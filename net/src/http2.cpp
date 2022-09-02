#include "http2.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <string>

#include <event2/buffer.h>
#include <nghttp2/nghttp2.h>

#include "util.h"

namespace ag {

static ag::Logger g_logger{"HTTP2"};

#define log_sess(s_, lvl_, fmt_, ...) lvl_##log(g_logger, "[id={}] " fmt_, (s_)->params.id, ##__VA_ARGS__)
#define log_sid(s_, sid_, lvl_, fmt_, ...) lvl_##log(g_logger, "[id={}-{}] " fmt_, (s_)->params.id, sid_, ##__VA_ARGS__)
#define log_frsid(s_, frm_, lvl_, fmt_, ...) log_sid(s_, (frm_)->hd.stream_id, lvl_, fmt_, ##__VA_ARGS__)

#define DATA_QUEUE_CHUNK_SIZE 4096
#define DATA_QUEUE_SIZE (10 * 1024 * 1024)

// taken from CoreLibs
static const uint32_t SESSION_LOCAL_WINDOW_SIZE = 8 * 1024 * 1024;

typedef struct {
    struct evbuffer *buf;
    bool has_eof : 1;
    bool scheduled : 1;
} DataSource;

static void on_end_headers(const nghttp2_frame *frame, HttpSession *session, HttpStream *stream);
static void on_end_stream(HttpSession *session, HttpStream *stream);
static DataSource *data_source_create();
static nghttp2_data_provider data_source_provider(void *source);
static ssize_t data_source_readcb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data);
static void data_source_free(DataSource *source);
static int data_source_add(HttpStream *stream, const uint8_t *data, size_t len, bool eof);
static int data_source_schedule_send(nghttp2_session *session, int32_t stream_id, DataSource *source);
static void stream_destroy(HttpStream *stream);

static inline void close_stream(HttpSession *session, khiter_t iter, HttpError error_code) {
    Http2Session *h2_session = session->h2;
    if (iter == kh_end(h2_session->streams)) {
        return;
    }

    HttpStream *stream = kh_value(h2_session->streams, iter);

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpStreamProcessedEvent event = {stream->id, error_code};
    callbacks->handler(callbacks->arg, HTTP_EVENT_STREAM_PROCESSED, &event);

    stream_destroy(stream);
    kh_del(h2_streams_ht, h2_session->streams, iter);
}

static int on_begin_frame_callback(nghttp2_session *ngsession, const nghttp2_frame_hd *hd, void *user_data) {
    auto *session = (HttpSession *) user_data;
    const auto *frame = (nghttp2_frame *) hd;
    log_frsid(session, frame, trace, "on_begin_frame_callback(ngsession={}, type={})", (void *) ngsession, hd->type);
    int r = 0;
    log_frsid(session, frame, trace, "on_begin_frame_callback() returned {}", r);
    return r;
}

static int on_begin_headers_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, void *user_data) {
    auto *session = (HttpSession *) user_data;
    log_frsid(session, frame, trace, "on_begin_headers_callback(ngsession={})", (void *) ngsession);
    Http2Session *h2_session = session->h2;
    HttpStream *stream;
    int r = 0;

    khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, (khint32_t) frame->hd.stream_id);
    bool found = (iter != kh_end(h2_session->streams));
    if (!found) {
        stream = http_stream_new(session, frame->hd.stream_id);
        iter = kh_put(h2_streams_ht, h2_session->streams, (khint32_t) frame->hd.stream_id, &r);
        kh_value(h2_session->streams, iter) = stream;
    } else {
        stream = kh_value(h2_session->streams, iter);
    }

    // Create headers structure and preallocate place for them.
    stream->headers = HttpHeaders{};
    stream->headers.version = HTTP_VER_2_0;
    stream->headers.fields.reserve((int) frame->headers.nvlen);

    log_frsid(session, frame, trace, "on_begin_headers_callback() returned {}", r);
    return r;
}

static int on_header_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, const uint8_t *name,
        size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data) {
    (void) flags;
    auto session = (HttpSession *) user_data;
    log_frsid(session, frame, trace, "on_header_callback(ngsession={}, name={}, value={})", (void *) ngsession,
            std::string_view{(char *) name, namelen}, std::string_view{(char *) value, valuelen});
    Http2Session *h2_session = session->h2;
    HttpStream *stream;
    HttpHeaders *headers;
    int r = 0;

    khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, frame->hd.stream_id);
    bool found = (iter != kh_end(h2_session->streams));

    if (found) {
        stream = kh_value(h2_session->streams, iter);
    } else {
        log_frsid(session, frame, err, "Stream table corrupted!");
        r = NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        goto finish;
    }

    headers = &stream->headers;

    headers->put_field(std::string{(char *) name, namelen}, std::string{(char *) value, valuelen});

finish:
    log_frsid(session, frame, trace, "on_header_callback() returned {}", r);
    return r;
}

static ssize_t on_send_callback(
        nghttp2_session *ngsession, const uint8_t *data, size_t length, int flags, void *user_data) {
    auto *session = (HttpSession *) user_data;
    log_sess(session, trace, "(ngsession={}, data={}, length={}, flags=0x{:x})", (void *) ngsession, (void *) data,
            length, flags);

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpOutputEvent event = {data, length};
    callbacks->handler(callbacks->arg, HTTP_EVENT_OUTPUT, &event);

    log_sess(session, trace, "returned length {}", length);
    return length;
}

static int on_frame_recv_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, void *user_data) {
    auto *session = (HttpSession *) user_data;
    log_frsid(session, frame, trace, "(type={}, ngsession={})", frame->hd.type, (void *) ngsession);
    Http2Session *h2_session = session->h2;
    HttpStream *stream = nullptr;
    int r = 0;
    bool found;
    khiter_t iter;

    int stream_id = frame->hd.stream_id;

    /**
     * Get stream
     */
    const char *frame_type = nullptr;
    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        frame_type = "HEADERS";
        // fall-through
    case NGHTTP2_DATA:
        if (frame_type == nullptr) {
            frame_type = "DATA";
        }
        // fall-through
    case NGHTTP2_RST_STREAM:
        if (frame_type == nullptr) {
            frame_type = "RST_STREAM";
        }
        // fall-through
    case NGHTTP2_PUSH_PROMISE:
        if (frame_type == nullptr) {
            frame_type = "PUSH_PROMISE";
        }
        iter = kh_get(h2_streams_ht, h2_session->streams, (khint32_t) stream_id);
        found = (iter != kh_end(h2_session->streams));
        if (found) {
            stream = kh_value(h2_session->streams, iter);
            stream->headers.version = HTTP_VER_2_0;
        } else if (frame->hd.type != NGHTTP2_RST_STREAM) {
            // https://tools.ietf.org/html/rfc7540#section-5.1
            // see description of "closed" state:
            // RST_STREAM frames can be received in this state
            // for a short period after a DATA or HEADERS frame containing an
            // END_STREAM flag is sent
            log_frsid(session, frame, dbg, "Stream not found in {}. This should not happen (frame type {})", __func__,
                    frame_type);
        }
        break;
    default:
        // do nothing
        break;
    }

    HttpSessionHandler *callbacks = &session->params.handler;
    /*
     * Documentation says that there is no ..._end_... callbacks, and this callback is fired after
     * all frametype-specific callbacks.
     * So if we need to do some finishing frametype-specific work, it must be done here.
     * Also, all CONTINUATION frames are automatically merged into previous by nghttp2,
     * and we don't need to process them separately.
     */
    switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
        if (stream != nullptr && (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) {
            on_end_headers(frame, session, stream);
        }
        // fall-through
    case NGHTTP2_DATA:
        if (stream != nullptr && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
            on_end_stream(session, stream);
        }
        break;
    case NGHTTP2_GOAWAY: {
        HttpGoawayEvent event = {frame->goaway.last_stream_id, (int) frame->goaway.error_code};
        callbacks->handler(callbacks->arg, HTTP_EVENT_GOAWAY, &event);
        break;
    }
    case NGHTTP2_PUSH_PROMISE:
        // Push promises are not supported at this time and silently dropped.
        if (stream != nullptr) {
            stream->headers = HttpHeaders{};
        }
        break;
    case NGHTTP2_WINDOW_UPDATE:
        log_frsid(session, frame, trace, "received window update: increment={}",
                frame->window_update.window_size_increment);

        if (stream_id != 0 && frame->window_update.window_size_increment > 0) {
            HttpSessionHandler *callbacks = &session->params.handler;
            HttpDataSentEvent event = {stream_id, 0};
            callbacks->handler(callbacks->arg, HTTP_EVENT_DATA_SENT, &event);
        }

        break;
    default:
        // do nothing
        break;
    }

    if (frame->hd.type == NGHTTP2_DATA || frame->hd.type == NGHTTP2_WINDOW_UPDATE) {
        log_frsid(session, frame, trace, "remote window size: session={} stream={}",
                nghttp2_session_get_remote_window_size(ngsession),
                nghttp2_session_get_stream_remote_window_size(ngsession, stream_id));
        log_frsid(session, frame, trace, "local window size: session={} stream={}",
                nghttp2_session_get_local_window_size(ngsession),
                nghttp2_session_get_stream_local_window_size(ngsession, stream_id));
    }

    // If nghttp2 generated auto-reply to incoming packet (SETTINGS ACK, PING ACK, frame error, etc.),
    // it would be send.
    if (nghttp2_session_want_write(ngsession)) {
        nghttp2_session_send(ngsession);
    }

    log_frsid(session, frame, trace, "returned {}", r);
    return r;
}

static int on_frame_send_callback(nghttp2_session *ngsession, const nghttp2_frame *frame, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    int r = 0;

    log_frsid(
            session, frame, trace, "on_frame_send_callback(type={}, ngsession={})", frame->hd.type, (void *) ngsession);

    if (frame->hd.type == NGHTTP2_WINDOW_UPDATE) {
        log_frsid(session, frame, trace, "sent window update: increment={}",
                (int) frame->window_update.window_size_increment);
    } else if (frame->hd.type == NGHTTP2_DATA) {
        log_frsid(session, frame, trace, "remote window size: session={} stream={}",
                (unsigned int) nghttp2_session_get_remote_window_size(ngsession),
                (unsigned int) nghttp2_session_get_stream_remote_window_size(ngsession, frame->hd.stream_id));
        log_frsid(session, frame, trace, "local window size: session={} stream={}",
                (unsigned int) nghttp2_session_get_local_window_size(ngsession),
                (unsigned int) nghttp2_session_get_stream_local_window_size(ngsession, frame->hd.stream_id));
    }

    log_frsid(session, frame, trace, "on_frame_send_callback() returned {}", r);
    return r;
}

static void on_end_stream(HttpSession *session, HttpStream *stream) {
    log_sid(session, stream->id, trace, "");

    HttpSessionHandler *callbacks = &session->params.handler;
    callbacks->handler(callbacks->arg, HTTP_EVENT_DATA_FINISHED, &stream->id);

    log_sid(session, stream->id, trace, "finished");
}

static void on_end_headers(const nghttp2_frame *frame, HttpSession *session, HttpStream *stream) {
    log_frsid(session, frame, trace, "");

    HttpHeaders *headers = &stream->headers;
    headers->has_body = !(frame->headers.hd.flags & NGHTTP2_FLAG_END_STREAM);

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpHeadersEvent event = {headers, frame->headers.hd.stream_id};
    callbacks->handler(callbacks->arg, HTTP_EVENT_HEADERS, &event);

    log_frsid(session, frame, trace, "finished");
}

static int h2_data_output(HttpStream *stream, const uint8_t *data, size_t length) {
    HttpSession *session = stream->session;
    HttpSessionHandler *callbacks = &session->params.handler;
    HttpDataEvent event = {stream->id, data, length, 0};
    callbacks->handler(callbacks->arg, HTTP_EVENT_DATA, &event);
    return event.result;
}

static int on_data_chunk_recv_callback(nghttp2_session *ngsession, uint8_t flags, int32_t stream_id,
        const uint8_t *data, size_t len, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    log_sid(session, stream_id, trace, "(ngsession={}, flags=0x{:x}, len={})", (void *) ngsession, flags, len);
    Http2Session *h2_session = session->h2;
    int r = 0;

    khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, (khint32_t) stream_id);
    bool found = (iter != kh_end(h2_session->streams));
    if (found) {
        HttpStream *stream = kh_value(h2_session->streams, iter);
        if (stream->id != stream_id) {
            log_sid(session, stream->id, err, "Stream table corrupted!");
            r = NGHTTP2_ERR_INVALID_STATE;
            goto finish;
        }

        if (!(stream->flags & STREAM_NEED_DECODE) || (stream->content_encoding == CONTENT_ENCODING_IDENTITY)) {
            r = h2_data_output(stream, data, len);
        } else if (0 != http_stream_decompress(stream, data, len, h2_data_output)) {
            http_stream_decompress_end(stream);
            r = HTTP_SESSION_DECOMPRESS_ERROR;
            goto finish;
        }
    } else {
        log_sid(session, stream_id, err, "Data before headers, this is incorrect");
        r = NGHTTP2_ERR_INVALID_STATE;
        goto finish;
    }

finish:
    // consuming session here is simpler than controlling it on the higher level, which is more
    // error prone and may lead to unrecoverable window leak out, but it leads to the higher data
    // bufferring rate
    int rr [[maybe_unused]] = nghttp2_session_consume_connection(ngsession, len);
    assert(rr == 0);

    log_sid(session, stream_id, trace, "returned {}", r);
    return r;
}

static int on_stream_close_callback(
        nghttp2_session *ngsession, int32_t stream_id, uint32_t error_code, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    log_sid(session, stream_id, trace, "(ngsession={}, error_code={})", (void *) ngsession, error_code);

    int r = 0;
    Http2Session *h2_session = session->h2;

    khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, (khint32_t) stream_id);
    bool found = (iter != kh_end(h2_session->streams));
    if (found) {
        HttpStream *stream = kh_value(h2_session->streams, iter);

        if (stream->id != stream_id) {
            stream_destroy(stream);
            kh_del(h2_streams_ht, h2_session->streams, iter);
            log_sid(session, stream_id, err, "ERROR: Stream table corrupted!");
            r = NGHTTP2_ERR_INVALID_STATE;
            goto finish;
        }

        // RST_STREAM
    } else {
        log_sid(session, stream_id, err, "ERROR: Stream table corrupted!");
        r = NGHTTP2_ERR_INVALID_STATE;
        goto finish;
    }

    close_stream(session, iter, (HttpError) error_code);

finish:
    log_sid(session, stream_id, trace, "returned {}", r);
    return r;
}

static int on_invalid_frame_recv_callback(
        nghttp2_session *ngsession, const nghttp2_frame *frame, int lib_error_code, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    log_frsid(session, frame, trace, "(ngsession={}, error_code={})", (void *) ngsession, lib_error_code);
    int r = 0;
    log_frsid(session, frame, trace, "returned {}", r);
    return r;
}

static int error_callback(nghttp2_session *ngsession, const char *msg, size_t len, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    int r = 0;
    log_sess(session, dbg, "nghttp2 error (ngsession={}): {}", (void *) ngsession, std::string_view{msg, len});
    return r;
}

Http2Session *http2_session_init(HttpSession *ctx) {
    Http2Session *session = nullptr;
    nghttp2_session *ngsession;
    nghttp2_session_callbacks *ngcallbacks;
    nghttp2_option *ngoption;

    // Session callbacks
    nghttp2_session_callbacks_new(&ngcallbacks);
    // Callbacks for events:
    // begin frame
    nghttp2_session_callbacks_set_on_begin_frame_callback(ngcallbacks, on_begin_frame_callback);
    // frame recv (end frame)
    nghttp2_session_callbacks_set_on_frame_recv_callback(ngcallbacks, on_frame_recv_callback);
    // frame sent
    nghttp2_session_callbacks_set_on_frame_send_callback(ngcallbacks, on_frame_send_callback);
    // invalid frame recv
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(ngcallbacks, on_invalid_frame_recv_callback);
    // data chunk recv
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ngcallbacks, on_data_chunk_recv_callback);
    // stream close
    nghttp2_session_callbacks_set_on_stream_close_callback(ngcallbacks, on_stream_close_callback);
    // begin headers
    nghttp2_session_callbacks_set_on_begin_headers_callback(ngcallbacks, on_begin_headers_callback);
    // header
    nghttp2_session_callbacks_set_on_header_callback(ngcallbacks, on_header_callback);

    // Delegate callbacks:
    // error logging callback
    nghttp2_session_callbacks_set_error_callback(ngcallbacks, error_callback);
    // output callback
    nghttp2_session_callbacks_set_send_callback(ngcallbacks, on_send_callback);

    // Session options
    nghttp2_option_new(&ngoption);
    // disable server push streams
    nghttp2_option_set_max_reserved_remote_streams(ngoption, 0);
    // turn on manual flow control
    nghttp2_option_set_no_auto_window_update(ngoption, 1);

    int status = nghttp2_session_client_new2(&ngsession, ngcallbacks, ctx, ngoption);
    nghttp2_session_callbacks_del(ngcallbacks);
    nghttp2_option_del(ngoption);

    if (status != 0) {
        goto finish;
    }

    session = (Http2Session *) calloc(1, sizeof(Http2Session));
    session->ngsession = ngsession;
    session->streams = kh_init(h2_streams_ht);

finish:
    return session;
}

int http2_session_input(HttpSession *session, const uint8_t *data, size_t len) {
    log_sess(session, trace, "(len={})", len);

    int r = nghttp2_session_mem_recv(session->h2->ngsession, data, len);
    if (r < 0) {
        log_sess(session, err, "nghttp2 error: {}", nghttp2_strerror(r));
    } else if (nghttp2_session_want_write(session->h2->ngsession)) {
        nghttp2_session_send(session->h2->ngsession);
    }

    log_sess(session, trace, "returned {}", r);
    return r;
}

int http2_session_close(HttpSession *session) {
    log_sess(session, trace, "");
    int r = 0;

    Http2Session *h2_session = session->h2;
    if (h2_session == nullptr) {
        return -1;
    }

    // Graceful shutdown
    nghttp2_session_terminate_session(h2_session->ngsession, NGHTTP2_NO_ERROR);
    nghttp2_session_send(h2_session->ngsession);
    nghttp2_session_del(h2_session->ngsession);

    log_sess(session, trace, "{} leftover streams", (int) kh_size(h2_session->streams));
    for (khiter_t iter = kh_begin(h2_session->streams); iter != kh_end(h2_session->streams); ++iter) {
        if (kh_exist(h2_session->streams, iter)) {
            stream_destroy(kh_value(h2_session->streams, iter));
        }
    }
    kh_destroy(h2_streams_ht, h2_session->streams);

    free(h2_session);

    session->h2 = nullptr;

    log_sess(session, trace, "returned {}", r);
    return r;
}

int http_session_send_settings(HttpSession *session) {
    log_sess(session, trace, "");

    nghttp2_session *ngsession = session->h2->ngsession;
    nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 65536 /* Chrome/Firefox constant */},
            {NGHTTP2_SETTINGS_ENABLE_PUSH, false},
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1000 /* Chrome constant */},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, (uint32_t) session->params.stream_window_size},
            {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 1 << 14 /* Firefox constant */},
    };

    int r = nghttp2_submit_settings(ngsession, 0, settings, sizeof(settings) / sizeof(settings[0]));
    if (r != 0) {
        goto finish;
    }

    // Set window size for connection after sending SETTINGS to remote server
    r = nghttp2_session_set_local_window_size(ngsession, NGHTTP2_FLAG_NONE, 0, SESSION_LOCAL_WINDOW_SIZE);
    if (r != 0) {
        goto finish;
    }

    r = nghttp2_session_send(ngsession);

finish:
    log_sess(session, trace, "returned {}", r);
    return r;
}

int http2_session_send_headers(HttpSession *session, int32_t stream_id, const HttpHeaders *headers, bool eof) {
    log_sid(session, stream_id, trace, "eof={}", (int) eof);

    std::vector<NameValue> nva = http_headers_to_nv_list(headers);
    std::vector<nghttp2_nv> ng_nva;
    ng_nva.reserve(nva.size());
    for (const auto &[name, value] : nva) {
        ng_nva.push_back(nghttp2_nv{
                .name = (uint8_t *)name.data(),
                .value = (uint8_t *)value.data(),
                .namelen = name.size(),
                .valuelen = value.size(),
        });
    }

    Http2Session *h2_session = session->h2;

    uint8_t flags = NGHTTP2_FLAG_END_HEADERS;
    if (eof) {
        flags |= NGHTTP2_FLAG_END_STREAM;
    }

    nghttp2_session *ngsession = h2_session->ngsession;
    if (!headers->method.empty()) {
        /* request, opening stream */
        khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, stream_id);
        bool found = (iter != kh_end(h2_session->streams));
        if (!found) {
            HttpStream *stream = http_stream_new(session, stream_id);
            int push_ret; // NOLINT(cppcoreguidelines-init-variables)
            iter = kh_put(h2_streams_ht, h2_session->streams, stream_id, &push_ret);
            kh_value(h2_session->streams, iter) = stream;
        }

        nghttp2_session_set_next_stream_id(ngsession, stream_id);
        nghttp2_submit_headers(ngsession, flags, -1, nullptr, ng_nva.data(), ng_nva.size(), nullptr);
    } else {
        nghttp2_submit_headers(ngsession, flags, stream_id, nullptr, ng_nva.data(), ng_nva.size(), nullptr);
    }
    int r = nghttp2_session_send(ngsession);
    if (r != 0) {
        goto finish;
    }

finish:
    log_sid(session, stream_id, trace, "returned {}", r);
    return r;
}

int http2_session_send_data(HttpSession *session, int32_t stream_id, const uint8_t *data, size_t len, bool eof) {
    log_sid(session, stream_id, trace, "eof={}", eof);

    Http2Session *h2_session = session->h2;
    nghttp2_session *ngsession = h2_session->ngsession;
    HttpStream *stream;
    int rv;

    khiter_t iter = kh_get(h2_streams_ht, h2_session->streams, (khint32_t) stream_id);
    bool found = (iter != kh_end(h2_session->streams));
    if (!found) {
        rv = NGHTTP2_ERR_INVALID_STREAM_STATE;
        goto finish;
    }

    stream = kh_value(h2_session->streams, iter);
    rv = data_source_add(stream, data, len, eof);
    if (rv != 0) {
        goto finish;
    }
    rv = data_source_schedule_send(ngsession, stream_id, (DataSource *) stream->data_source);
    if (rv != 0) {
        goto finish;
    }
    rv = nghttp2_session_send(ngsession);

finish:
    log_sid(session, stream_id, trace, "returned {}", rv);
    return rv;
}

int http_session_reset_stream(HttpSession *session, int32_t stream_id, int error_code) {
    log_sid(session, stream_id, trace, "error_code={}", error_code);
    nghttp2_session *ngsession = session->h2->ngsession;
    int r = nghttp2_submit_rst_stream(ngsession, NGHTTP2_FLAG_NONE, stream_id, error_code);
    if (r != 0) {
        goto finish;
    }
    r = nghttp2_session_send(ngsession);

finish:
    log_sid(session, stream_id, trace, "returned {}", r);
    return r;
}

int http_session_send_goaway(HttpSession *session, int last_stream_id, int error_code) {
    log_sess(session, trace, "error_code={}", error_code);
    nghttp2_session *ngsession = session->h2->ngsession;

    if (last_stream_id < 0) {
        last_stream_id = nghttp2_session_get_last_proc_stream_id(ngsession);
    }

    int r = nghttp2_session_terminate_session2(ngsession, last_stream_id, error_code);
    if (r != 0) {
        goto finish;
    }
    r = nghttp2_session_send(ngsession);

finish:
    log_sess(session, trace, "returned {}", r);
    return r;
}

int http_session_data_consume(HttpSession *session, int32_t stream_id, size_t length) {
    nghttp2_session *ngsession = session->h2->ngsession;
    // session was consumed in data chunk callback
    int r = nghttp2_session_consume_stream(ngsession, stream_id, length);
    if (r == 0) {
        r = nghttp2_session_send(ngsession);
    }

    log_sid(session, stream_id, trace, "remote window size: session={} stream={}",
            (int) nghttp2_session_get_remote_window_size(ngsession),
            (int) nghttp2_session_get_stream_remote_window_size(ngsession, stream_id));
    log_sid(session, stream_id, trace, "local window size: session={} stream={}",
            (int) nghttp2_session_get_local_window_size(ngsession),
            (int) nghttp2_session_get_stream_local_window_size(ngsession, stream_id));

    log_sid(session, stream_id, trace, "consumed:{} returned:{}", length, r);
    return r;
}

// @todo: figure out if we need some tricky algorithm for window size calculation
#if 0
static bool need_to_reduce_window(int current, size_t new) {
    return current > 0 && (int)new < (current * 8 / 10);
}

static size_t get_new_window_size(http_session_t *session, uint32_t stream_id, size_t requested_size) {
    uint64_t total_window_sizes = 0;
    const kh_h2_streams_ht_t *streams = session->h2->streams;
    for (khiter_t i = kh_begin(streams); i != kh_end(streams); ++i) {
        if (kh_exist(streams, i) && kh_key(streams, i) != stream_id) {
            total_window_sizes += kh_value(streams, i)->client_window_size;
        }
    }
    total_window_sizes += requested_size;
    ffint_setmax(total_window_sizes, 1);

    double coef = (double)SESSION_LOCAL_WINDOW_SIZE / total_window_sizes;
    if (coef < 1) {
        requested_size = (double)requested_size * coef;
    }

    // set new size in bounds [initial stream window size; session window size]
    requested_size = ffmin(SESSION_LOCAL_WINDOW_SIZE, requested_size);
    return ffmax(session->params.stream_window_size, requested_size);
}

int http_session_set_recv_window(http_session_t *session, int32_t stream_id, size_t size) {
    nghttp2_session *ngsession = session->h2->ngsession;

    int current_window = nghttp2_session_get_stream_local_window_size(ngsession, stream_id);
    size_t new_window = get_new_window_size(session, stream_id, size);
    log_sid(session, stream_id, trace, "Requested={} current={} new={}",
            size, current_window, new_window);

    kh_h2_streams_ht_t *streams = session->h2->streams;
    khiter_t i = kh_get(h2_streams_ht, streams, stream_id);
    if (i != kh_end(streams)) {
        kh_value(streams, i)->client_window_size = size;
    }

    int r = nghttp2_session_set_local_window_size(ngsession, NGHTTP2_FLAG_NONE, stream_id, new_window);
    if (r == 0 && size > 0 && need_to_reduce_window(current_window, new_window)) {
        log_sid(session, stream_id, dbg, "Reducing stream window sizes to initial value");
        nghttp2_settings_entry settings = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, session->params.stream_window_size };
        r = nghttp2_submit_settings(ngsession, NGHTTP2_FLAG_NONE, &settings, 1);
    }

    if (r == 0) {
        r = nghttp2_session_send(ngsession);
    }

    log_sid(session, stream_id, trace, "Remote window size: session={} stream={}",
            (int)nghttp2_session_get_remote_window_size(ngsession),
            (int)nghttp2_session_get_stream_remote_window_size(ngsession, stream_id));
    log_sid(session, stream_id, trace, "Local window size: session={} stream={}",
            (int)nghttp2_session_get_local_window_size(ngsession),
            (int)nghttp2_session_get_stream_local_window_size(ngsession, stream_id));

    return r;
}
#endif

int http_session_set_recv_window(HttpSession *session, int32_t stream_id, size_t size) {
    nghttp2_session *ngsession = session->h2->ngsession;

    static const int32_t MAX_STREAM_WINDOW_SIZE = 4 * 1024 * 1024;

    // don't reduce window, but don't let it be more than `MAX_STREAM_WINDOW_SIZE`
    int32_t current_window = nghttp2_session_get_stream_local_window_size(ngsession, stream_id);
    int32_t new_window = std::min(std::max(current_window, (int32_t) size), MAX_STREAM_WINDOW_SIZE);
    log_sid(session, stream_id, trace, "Requested={} current={} new={}", size, current_window, new_window);

    int r = nghttp2_session_set_local_window_size(ngsession, NGHTTP2_FLAG_NONE, stream_id, new_window);
    if (r == 0) {
        r = nghttp2_session_send(ngsession);
    }

    log_sid(session, stream_id, trace, "Remote window size: session={} stream={}",
            (int) nghttp2_session_get_remote_window_size(ngsession),
            (int) nghttp2_session_get_stream_remote_window_size(ngsession, stream_id));
    log_sid(session, stream_id, trace, "Local window size: session={} stream={}",
            (int) nghttp2_session_get_local_window_size(ngsession),
            (int) nghttp2_session_get_stream_local_window_size(ngsession, stream_id));

    return r;
}

static DataSource *data_source_create() {
    // Create non-pull data source
    DataSource *source = (DataSource *) calloc(1, sizeof(DataSource));
    source->buf = evbuffer_new();
    return source;
}

static nghttp2_data_provider data_source_provider(void *source) {
    nghttp2_data_provider provider = {};
    provider.source.ptr = source;
    provider.read_callback = data_source_readcb;
    return provider;
}

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

/**
 * Data source read callback. Called by nghttp2 when it is ready to send data.
 * Returns data if it is in output buffer or ERR_DEFERRED if buffer is empty and no EOF flag set.
 * If ERR_DEFERRED is set, nghttp2_session_resume_data() is called on next http2_data_provider_write() call.
 */
static ssize_t data_source_readcb(nghttp2_session *ngsession, int32_t stream_id, uint8_t *buf, size_t length,
        uint32_t *data_flags, nghttp2_data_source *source, void *user_data) {
    HttpSession *session = (HttpSession *) user_data;
    DataSource *ds = (DataSource *) source->ptr;

    // Pause and destroy data source if no work on current buffer.
    if (!ds->has_eof && 0 == evbuffer_get_length(ds->buf)) {
        log_sid(session, stream_id, trace, "no work on current buffer");
        return NGHTTP2_ERR_DEFERRED;
    }

    ssize_t n = evbuffer_remove(ds->buf, buf, length);
    log_sid(session, stream_id, trace, "{} bytes", n);
    if (n < 0) {
        return NGHTTP2_ERR_BUFFER_ERROR;
    }

    // If eof, set flag and destroy data source
    if (ds->has_eof && 0 == evbuffer_get_length(ds->buf)) {
        log_sid(session, stream_id, trace, "no data left in buffers -- set eof flag");
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpDataSentEvent event = {stream_id, (size_t) n};
    callbacks->handler(callbacks->arg, HTTP_EVENT_DATA_SENT, &event);

    log_sid(session, stream_id, trace, "remote window size: session={} stream={}",
            (unsigned int) nghttp2_session_get_remote_window_size(ngsession),
            (unsigned int) nghttp2_session_get_stream_remote_window_size(ngsession, stream_id));
    log_sid(session, stream_id, trace, "local window size: session={} stream={}",
            (unsigned int) nghttp2_session_get_local_window_size(ngsession),
            (unsigned int) nghttp2_session_get_stream_local_window_size(ngsession, stream_id));

    return event.length;
}

static int data_source_add(HttpStream *stream, const uint8_t *data, size_t len, bool eof) {
    DataSource *source = (DataSource *) stream->data_source;
    if (source == nullptr) {
        // Lazy init source
        source = data_source_create();
        stream->data_source = source;
    }
    source->has_eof |= eof;
    int rv = evbuffer_add(source->buf, data, len);
    return rv;
}

struct nghttp2_stream;
extern "C" {
int nghttp2_stream_check_deferred_item(struct nghttp2_stream *stream);
extern struct nghttp2_stream *nghttp2_session_get_stream(nghttp2_session *session, int32_t stream_id);
}

static int data_source_schedule_send(nghttp2_session *ngsession, int32_t stream_id, DataSource *source) {
    int rv = 0;
    if (source->scheduled) {
        // not deferred means that there is some unread data in the source, so
        // just add it there and it'll be read automatically later
        nghttp2_stream *stream = nghttp2_session_get_stream(ngsession, stream_id);
        if (stream == nullptr) {
            rv = NGHTTP2_ERR_INVALID_STREAM_STATE;
        } else if (nghttp2_stream_check_deferred_item(stream)) {
            rv = nghttp2_session_resume_data(ngsession, stream_id);
        }
    } else {
        nghttp2_data_provider provider = data_source_provider(source);
        rv = nghttp2_submit_data(ngsession, NGHTTP2_FLAG_END_STREAM, stream_id, &provider);
        source->scheduled = true;
    }
    return rv;
}

/**
 * Called from on-stream-close callback
 */
static void data_source_free(DataSource *source) {
    if (source == nullptr) {
        return;
    }
    evbuffer_free(source->buf);
    free(source);
}

static void stream_destroy(HttpStream *stream) {
    data_source_free((DataSource *) stream->data_source);
    http_stream_destroy(stream);
}

size_t http_session_available_to_write(HttpSession *session, int32_t stream_id) {
    int32_t r;

    if (stream_id != 0) {
        r = nghttp2_session_get_stream_remote_window_size(session->h2->ngsession, stream_id);
    } else {
        r = nghttp2_session_get_remote_window_size(session->h2->ngsession);
    }

    return (r > 0) ? r : 0;
}

size_t http_session_available_to_read(HttpSession *session, int32_t stream_id) {
    int32_t r;

    if (stream_id != 0) {
        r = nghttp2_session_get_stream_local_window_size(session->h2->ngsession, stream_id);
    } else {
        r = nghttp2_session_get_local_window_size(session->h2->ngsession);
    }

    return (r > 0) ? r : 0;
}

} // namespace ag
