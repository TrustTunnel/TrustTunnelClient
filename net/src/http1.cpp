#include "http1.h"

#include <cstring>

#include <magic_enum/magic_enum.hpp>
#include <zlib.h>

#include "common/utils.h"
#include "http_parser.h"
#include "http_stream.h"
#include "net/http_session.h"
#include "util.h"

namespace ag {

static ag::Logger g_logger{"HTTP1"};

#define log_sess(s_, lvl_, fmt_, ...) lvl_##log(g_logger, "[id={}] " fmt_, (uint64_t) (s_)->params.id, ##__VA_ARGS__)
#define log_sid(s_, sid_, lvl_, fmt_, ...)                                                                             \
    lvl_##log(g_logger, "[id={}-{}] " fmt_, (uint64_t) (s_)->params.id, (int) sid_, ##__VA_ARGS__)

enum {
    CLEN_CHUNKED = -2,
    CLEN_UNSET = -1,
};

/*
 * Session context structure
 */
typedef struct Http1Session {
    uint64_t id;                          // Connection id
    HttpError body_callback_error;        // Body callback error
    http_parser *parser;                  // Pointer to Node.js http_parser implementation
    const http_parser_settings *settings; // Pointer to parser settings
    size_t done;                          // Message construction is done
    bool in_field;     // We are currently in field (after retrieveing field name and before reteiving field value)
    HttpStream stream; // HTTP stream
    int clength;       // Content-length of HTTP message that currently being sent
                       // or CLEN_CHUNKED (set automatically if there is "Transfer-encoding" in output headers)
} Http1Session;

static void parser_reset(HttpSession *session, Http1Session *h1s);

/*
 *  Internal callbacks:
 */
static int on_message_begin(http_parser *parser) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    h1s->stream.headers.version = HTTP_VER_1_1;

    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t length) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    HttpHeaders *headers = &h1s->stream.headers;
    if (at != nullptr && length > 0) {
        headers->path.append(at, length);
    }

    return 0;
}

static int on_status(http_parser *parser, const char *at, size_t length) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    HttpHeaders *headers = &h1s->stream.headers;
    if (at != nullptr && length > 0) {
        headers->status_string.append(at, length);
    }
    headers->status_code = parser->status_code;

    return 0;
}

static int on_header_field(http_parser *parser, const char *at, size_t length) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "{}", std::string_view{at, length});

    Http1Session *h1s = session->h1;
    HttpHeaders *headers = &h1s->stream.headers;
    if (!h1s->in_field) {
        h1s->in_field = true;
        headers->fields.emplace_back();
    }

    headers->fields.back().name.append(at, length);

    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t length) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "{}", std::string_view{at, length});

    Http1Session *h1s = session->h1;
    h1s->in_field = false;
    h1s->stream.headers.fields.back().value.append(at, length);

    return 0;
}

static int on_headers_complete(http_parser *parser) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    HttpStream *stream = &h1s->stream;
    HttpHeaders *headers = &stream->headers;
    switch (parser->type) {
    case HTTP_REQUEST:
        headers->method = http_method_str((http_method) parser->method);
        break;
    default:
        break;
    }

    headers->has_body = (parser->flags & F_CHUNKED);
    if (parser->status_code == 100 || parser->status_code == 103) {
        headers->has_body = 0;
    } else {
        headers->has_body |= !(parser->flags & F_CONTENTLENGTH) || parser->content_length != 0;
    }

    headers->version = http_make_version(parser->http_major, parser->http_minor);

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpHeadersEvent event = {headers, stream->id};
    callbacks->handler(callbacks->arg, HTTP_EVENT_HEADERS, &event);

    // If server responds before request is sent, it is not HTTP/1.1
    // https://github.com/AdguardTeam/CoreLibs/issues/441
    bool pseudo_http =
            (stream->flags & STREAM_REQ_SENT) == 0 && headers->status_code != 100 && headers->status_code != 103;

    int skip = (stream->flags & STREAM_DONT_EXPECT_RESPONSE_BODY) ? 1 : 0;
    if (parser->upgrade || pseudo_http) {
        skip = -1;
        h1s->body_callback_error = HTTP_SESSION_UPGRADE;
    }

    log_sess(session, trace, "Returned {}, cb error {}", skip, magic_enum::enum_name(h1s->body_callback_error));
    return skip;
}

static int h1_data_output(HttpStream *stream, const uint8_t *data, size_t length) {
    HttpSession *session = stream->session;
    HttpSessionHandler *callbacks = &session->params.handler;
    HttpDataEvent event = {stream->id, data, length, 0};
    callbacks->handler(callbacks->arg, HTTP_EVENT_DATA, &event);
    return event.result;
}

static int on_body(http_parser *parser, const char *at, size_t length) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    HttpError r = HTTP_SESSION_OK;
    switch (parser->type) {
    case HTTP_REQUEST:
    case HTTP_RESPONSE:
        break;
    default:
        r = HTTP_SESSION_INVALID_ARGUMENT_ERROR;
        goto out;
    }

    if (!(h1s->stream.flags & STREAM_BODY_DATA_STARTED)) {
        if ((h1s->stream.flags & STREAM_NEED_DECODE) && 0 != http_stream_decompress_init(&h1s->stream)) {
            r = HTTP_SESSION_DECOMPRESS_ERROR;
            goto out;
        }
        h1s->stream.flags = (HttpStreamFlags) (h1s->stream.flags | STREAM_BODY_DATA_STARTED);
    }

    if (!(h1s->stream.flags & STREAM_NEED_DECODE) || h1s->stream.content_encoding == CONTENT_ENCODING_IDENTITY) {
        h1_data_output(&h1s->stream, (uint8_t *) at, length);
    } else if (0 != http_stream_decompress(&h1s->stream, (uint8_t *) at, length, h1_data_output)) {
        http_stream_decompress_end(&h1s->stream); /* result ignored */
        r = HTTP_SESSION_DECOMPRESS_ERROR;
        goto out;
    }

out:
    log_sess(session, trace, "Returned {}", magic_enum::enum_name(r));
    h1s->body_callback_error = r;
    return r;
}

static int on_message_complete(http_parser *parser) {
    auto *session = (HttpSession *) parser->data;
    log_sess(session, trace, "...");

    Http1Session *h1s = session->h1;
    HttpStream *stream = &h1s->stream;
    if (stream->headers.has_body) {
        HttpSessionHandler *callbacks = &session->params.handler;
        callbacks->handler(callbacks->arg, HTTP_EVENT_DATA_FINISHED, &stream->id);
    }

    HttpSessionHandler *callbacks = &session->params.handler;
    HttpStreamProcessedEvent event = {stream->id, 0};
    callbacks->handler(callbacks->arg, HTTP_EVENT_STREAM_PROCESSED, &event);

    parser_reset(session, h1s);

    log_sess(session, trace, "Returned {}", 0);
    return 0;
}

static int on_chunk_header(http_parser *) {
    // ignore
    return 0;
}

static int on_chunk_complete(http_parser *) {
    // ignore
    return 0;
}

static constexpr http_parser_settings g_parser_settings = {
        .on_message_begin = on_message_begin,
        .on_url = on_url,
        .on_status = on_status,
        .on_header_field = on_header_field,
        .on_header_value = on_header_value,
        .on_headers_complete = on_headers_complete,
        .on_body = on_body,
        .on_message_complete = on_message_complete,
        .on_chunk_header = on_chunk_header,
        .on_chunk_complete = on_chunk_complete,
};

/*
 *  API implementation
 */

Http1Session *http1_session_init(HttpSession *session) {
    auto *h1s = new Http1Session{};
    h1s->settings = &g_parser_settings;
    http_stream_reset_state(&h1s->stream);
    h1s->stream.id = 0;
    h1s->stream.session = session;

    static_assert(std::is_trivial_v<http_parser>);
    h1s->parser = (http_parser *) malloc(sizeof(http_parser));
    h1s->parser->data = session;
    parser_reset(session, h1s);

    return h1s;
}

static void parser_reset(HttpSession *session, Http1Session *h1s) {
    log_sess(session, trace, "...");

    if (h1s->stream.decompress_stream != nullptr) {
        http_stream_decompress_end(&h1s->stream);
    }

    http_stream_reset_state(&h1s->stream);
    h1s->stream.session = session;

    h1s->clength = CLEN_UNSET;

    /* Re-init parser before next message. */
    http_parser_init(h1s->parser, HTTP_BOTH);
}

int http1_session_input(HttpSession *session, const uint8_t *data, size_t length) {
    log_sess(session, trace, "Length={}", length);

    Http1Session *h1s = session->h1;
    h1s->done = 0;

    if (HTTP_PARSER_ERRNO(h1s->parser) != HPE_OK || h1s->parser->type == HTTP_BOTH) {
        http_parser_init(h1s->parser, HTTP_RESPONSE);
    }

    h1s->done = http_parser_execute(h1s->parser, h1s->settings, (char *) data, length);

    const char *error_msg = "";
    int r = 0;
    enum http_errno http_parser_errno = HTTP_PARSER_ERRNO(h1s->parser);
    switch (http_parser_errno) {
    case HPE_CB_headers_complete: // Upgrade, all attached data must be processed separately
        h1s->done += 1;           // Stopped HTTP parser at '\n' symbol, so increase by one.
        if (h1s->done == length) {
            r = HTTP_SESSION_UPGRADE;
            break;
        }
        // fallthrough
    case HPE_OK:
        r = (int) h1s->done;
        break;
    case HPE_CB_body:
        on_message_complete(h1s->parser);
        error_msg = h1s->stream.error_msg;
        r = h1s->body_callback_error;
        break;
    default:
        // If body data callback fails, then get saved error from structure, don't overwrite but report
        error_msg = http_errno_description(http_parser_errno);
        r = HTTP_SESSION_PARSE_ERROR;
        break;
    }

    log_sess(session, trace, "Returned {}: {}", r, error_msg);
    return r;
}

int http1_session_close(HttpSession *session) {
    log_sess(session, trace, "...");
    int r = 0;

    parser_reset(session, session->h1);
    free(session->h1->parser);
    session->h1->parser = nullptr;
    delete session->h1;
    session->h1 = nullptr;

    return r;
}

int http1_session_send_headers(HttpSession *session, int32_t stream_id, const HttpHeaders *headers) {
    log_sid(session, stream_id, trace, "...");
    int r = 0;

    std::optional<std::string_view> transfer_encoding = headers->get_field("Transfer-Encoding");
    std::optional<std::string_view> content_length = headers->get_field("Content-Length");
    std::optional<int32_t> clen;
    if (transfer_encoding.has_value() && case_equals(transfer_encoding.value(), "chunked")) {
        session->h1->clength = CLEN_CHUNKED;
    } else if (content_length.has_value() && (clen = ag::utils::to_integer<int32_t>(content_length.value()))) {
        session->h1->clength = *clen;
    } else {
        session->h1->clength = CLEN_UNSET;
    }

    std::string output = http_headers_to_http1_message(headers, false);
    HttpSessionHandler *callbacks = &session->params.handler;
    HttpOutputEvent event = {(uint8_t *) output.data(), output.size()};
    callbacks->handler(callbacks->arg, HTTP_EVENT_OUTPUT, &event);

    session->h1->stream.id = stream_id;
    if (headers->method == "HEAD") {
        session->h1->stream.flags = (HttpStreamFlags) (session->h1->stream.flags | STREAM_DONT_EXPECT_RESPONSE_BODY);
    }

    bool cant_have_body = headers->status_code / 100 == 1 /* 1xx e.g. Continue */
            || headers->status_code == 204                /* No Content */
            || headers->status_code == 205                /* Reset Content */
            || headers->status_code == 304;
    bool empty_msg = cant_have_body || session->h1->clength == 0 || session->h1->clength == CLEN_UNSET;
    if (empty_msg) {
        session->h1->stream.flags = (HttpStreamFlags) (session->h1->stream.flags | STREAM_REQ_SENT);
    }

    log_sid(session, stream_id, trace, "Returned {}", r);
    return r;
}

int http1_session_send_data(HttpSession *session, int32_t stream_id, const uint8_t *data, size_t len, bool eof) {
    log_sid(session, stream_id, trace, "Length={} eof={}", len, eof);

    int r = 0;

    bool append_eof = eof;
    if (len == 0) {
        append_eof = false; // because in this case main chunk is already EOF chunk
    }

    HttpSessionHandler *callbacks = &session->params.handler;
    bool chunked = (session->h1->clength == CLEN_CHUNKED);
    if (chunked) {
        char chunk_header[16];
        r = snprintf(chunk_header, 16, "%X\r\n", (int) len);
        HttpOutputEvent event = {(uint8_t *) chunk_header, (size_t) r};
        callbacks->handler(callbacks->arg, HTTP_EVENT_OUTPUT, &event);
    }

    HttpOutputEvent event = {data, len};
    callbacks->handler(callbacks->arg, HTTP_EVENT_OUTPUT, &event);

    if (chunked && append_eof) {
        static const char eof_chunk[] = "0\r\n\r\n";
        HttpOutputEvent event = {(uint8_t *) eof_chunk, strlen(eof_chunk)};
        callbacks->handler(callbacks->arg, HTTP_EVENT_OUTPUT, &event);
    }

    if (!chunked && session->h1->clength != CLEN_UNSET) {
        session->h1->clength = (session->h1->clength >= (int) len) ? session->h1->clength - (int) len : 0;
        eof = (session->h1->clength == 0);
    }

    log_sid(session, stream_id, trace, "Eof={}", eof);
    if (eof) {
        session->h1->stream.flags = (HttpStreamFlags) (session->h1->stream.flags | STREAM_REQ_SENT);
        log_sid(session, stream_id, trace, "Request sent set");
    }

    log_sid(session, stream_id, trace, "Returned={}", r);
    return r;
}

} // namespace ag
