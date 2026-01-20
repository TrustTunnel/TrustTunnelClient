#include "http_stream.h"

#include <cstdlib>
#include <cstring>

#include <brotli/decode.h>
#include <zlib.h>

#include "http2.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

static ag::Logger g_logger{"HTTP_STREAM"};

#define log_stream(s_, lvl_, fmt_, ...)                                                                                \
    lvl_##log(g_logger, "[id={}-{}] " fmt_, (s_)->session->params.id, (s_)->id, ##__VA_ARGS__)

#define ZLIB_DECOMPRESS_CHUNK_SIZE 8192

struct BrotliStream {
    BrotliDecoderState *state;
    size_t avail_in;
    const uint8_t *next_in;
    size_t avail_out;
    uint8_t *next_out;
    size_t total_out;
};

// NOLINTBEGIN(cppcoreguidelines-no-malloc,hicpp-no-malloc)
int http_stream_decompress_init(HttpStream *stream) {
    log_stream(stream, trace, "");
    // Get content encoding from HTTP headers
    stream->content_encoding = http_stream_get_content_encoding(&stream->headers);
    if (!(stream->flags & STREAM_NEED_DECODE) || (stream->content_encoding == CONTENT_ENCODING_IDENTITY)) {
        // Uncompressed
        stream->decompress_stream = nullptr;
        stream->decode_in_buffer = nullptr;
        stream->decode_out_buffer = nullptr;
        log_stream(stream, trace, "returned {}", 0);
        return 0;
    }

    // Allocate decode buffers
    stream->decode_in_buffer = (uint8_t *) calloc(ZLIB_DECOMPRESS_CHUNK_SIZE, 1);
    stream->decode_out_buffer = (uint8_t *) calloc(ZLIB_DECOMPRESS_CHUNK_SIZE, 1);

    // Initialize decompressor
    int r = 0;
    switch (stream->content_encoding) {
    case CONTENT_ENCODING_DEFLATE:
        stream->zlib_stream = (z_stream_s *) calloc(1, sizeof(z_stream));
        r = inflateInit(stream->zlib_stream);
        if (r != 0) {
            snprintf(stream->error_msg, sizeof(stream->error_msg), "%s", stream->zlib_stream->msg);
        }
        break;
    case CONTENT_ENCODING_GZIP:
        stream->zlib_stream = (z_stream_s *) calloc(1, sizeof(z_stream));
        r = inflateInit2(stream->zlib_stream, 16 + MAX_WBITS);
        if (r != 0) {
            snprintf(stream->error_msg, sizeof(stream->error_msg), "%s", stream->zlib_stream->msg);
        }
        break;
    case CONTENT_ENCODING_BROTLI:
        stream->brotli_stream = (BrotliStream *) calloc(1, sizeof(BrotliStream));
        stream->brotli_stream->state = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
        r = (stream->brotli_stream->state == nullptr);
        if (r != 0) {
            snprintf(stream->error_msg, sizeof(stream->error_msg), "Brotli decoder init error");
        }
        break;
    default:
        break;
    }

    log_stream(stream, trace, "returned {}", r);
    return r;
}
// NOLINTEND(cppcoreguidelines-no-malloc,hicpp-no-malloc)

HttpContentEncoding http_stream_get_content_encoding(const HttpHeaders *headers) {
    if (auto value = headers->get_field("Content-Encoding")) {
        if (case_equals(*value, "gzip") || case_equals(*value, "x-gzip")) {
            return CONTENT_ENCODING_GZIP;
        } else if (case_equals(*value, "deflate")) {
            return CONTENT_ENCODING_DEFLATE;
        } else if (case_equals(*value, "br")) {
            return CONTENT_ENCODING_BROTLI;
        }
    }
    return CONTENT_ENCODING_IDENTITY;
}

static int http_stream_decompress_zlib(
        HttpStream *h_stream, const uint8_t *data, size_t length, BodyDataOutputCallback data_output) {
    int result;
    int r = 0;
    z_stream *z_stream = h_stream->zlib_stream;

    // If we have a data in input buffer, append new data to it, otherwise process `data' as input buffer
    if (z_stream->avail_in > 0) {
        z_stream->next_in = (Bytef *) h_stream->decode_in_buffer;
        if (z_stream->avail_in + length > ZLIB_DECOMPRESS_CHUNK_SIZE) {
            result = Z_BUF_ERROR;
            goto error;
        }
        memcpy(h_stream->decode_in_buffer + z_stream->avail_in, data, length);
        z_stream->avail_in += (uInt) length;
    } else {
        z_stream->next_in = (Bytef *) data;
        z_stream->avail_in = (uInt) length;
    }

    uint32_t old_avail_in; // Check if we made a progress
    do {
        old_avail_in = z_stream->avail_in;
        z_stream->avail_out = ZLIB_DECOMPRESS_CHUNK_SIZE;
        z_stream->next_out = (Bytef *) h_stream->decode_out_buffer;
        result = inflate(z_stream, 0);
        size_t processed = ZLIB_DECOMPRESS_CHUNK_SIZE - z_stream->avail_out;
        if (processed > 0) {
            // Call callback function for each decompressed block
            data_output(h_stream, h_stream->decode_out_buffer, processed);
        }
        if (result != Z_OK) {
            goto error;
        }
    } while (z_stream->avail_in > 0 && old_avail_in != z_stream->avail_in);

    // Move unprocessed tail to the start of input buffer
    if (z_stream->avail_in) {
        memcpy(h_stream->decode_in_buffer, z_stream->next_in, z_stream->avail_in);
    }

    goto finish;

error:
    if (result != Z_STREAM_END) {
        if (z_stream->msg) {
            snprintf(h_stream->error_msg, sizeof(h_stream->error_msg), "%s", z_stream->msg);
        }
        fprintf(stderr, "Decompression error: %d\n", result);
        r = 1;
    }

finish:
    return r;
}

static int http_stream_decompress_brotli(
        HttpStream *h_stream, const uint8_t *data, size_t length, BodyDataOutputCallback data_output) {
    int result;
    int r = 0;
    BrotliStream *b_stream = h_stream->brotli_stream;

    // If we have a data in input buffer, append new data to it, otherwise process `data' as input buffer
    if (b_stream->avail_in > 0) {
        b_stream->next_in = h_stream->decode_in_buffer;
        if (b_stream->avail_in + length > ZLIB_DECOMPRESS_CHUNK_SIZE) {
            result = Z_BUF_ERROR;
            goto error;
        }
        memcpy(h_stream->decode_in_buffer + b_stream->avail_in, data, length);
        b_stream->avail_in += length;
    } else {
        b_stream->next_in = data;
        b_stream->avail_in = length;
    }

    size_t old_avail_in; // Check if we made a progress
    do {
        old_avail_in = b_stream->avail_in;
        b_stream->avail_out = ZLIB_DECOMPRESS_CHUNK_SIZE;
        b_stream->next_out = (Bytef *) h_stream->decode_out_buffer;
        result = BrotliDecoderDecompressStream(b_stream->state, &b_stream->avail_in, &b_stream->next_in,
                &b_stream->avail_out, &b_stream->next_out, &b_stream->total_out);
        size_t processed = ZLIB_DECOMPRESS_CHUNK_SIZE - b_stream->avail_out;
        if (processed > 0) {
            // Call callback function for each decompressed block
            data_output(h_stream, h_stream->decode_out_buffer, processed);
        }
        if (result == BROTLI_DECODER_RESULT_ERROR) {
            snprintf(h_stream->error_msg, sizeof(h_stream->error_msg), "%s",
                    BrotliDecoderErrorString(BrotliDecoderGetErrorCode(b_stream->state)));
            goto error;
        }
    } while (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT
            || (b_stream->avail_in > 0 && old_avail_in != b_stream->avail_in));

    // Move unprocessed tail to the start of input buffer
    if (b_stream->avail_in) {
        memcpy(h_stream->decode_in_buffer, b_stream->next_in, b_stream->avail_in);
    }

    goto finish;

error:
    fprintf(stderr, "Decompression error: %d\n", result);
    r = 1;

finish:
    return r;
}

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
/** Return TRUE if this is a ZLIB header. */
static bool is_zlib_hdr(const uint8_t *data) {
    return (data[0] & 0x0f) == 8 && (((data[0] & 0xf0) >> 4) <= 7 && (((uint32_t) data[0] << 8) + data[1]) % 31 == 0);
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

int http_stream_decompress(
        HttpStream *h_stream, const uint8_t *data, size_t length, BodyDataOutputCallback data_output) {
    log_stream(h_stream, trace, "(data={}, length={})", (void *) data, length);
    int r = 0;

    if (h_stream->decompress_stream == nullptr) {
        r = 1;
        // Compression stream was not initialized
        goto finish;
    }

    switch (h_stream->content_encoding) {
    case CONTENT_ENCODING_DEFLATE:
        if (h_stream->processed_bytes == 0 && length >= 2 && !is_zlib_hdr(data)) {
            /* Some servers incorrectly encode data with "Content-Encoding: deflate":
                the format they use is a raw 'deflate' data, while it must be a 'deflate' data
                wrapped inside 'zlib' header. */
            inflateEnd(h_stream->zlib_stream);
            memset(h_stream->zlib_stream, 0, sizeof(*h_stream->zlib_stream));
            r = inflateInit2(h_stream->zlib_stream, -MAX_WBITS);
            if (r != 0) {
                break;
            }
        }
        // fallthrough

    case CONTENT_ENCODING_GZIP:
        r = http_stream_decompress_zlib(h_stream, data, length, data_output);
        if (r == 0) {
            h_stream->processed_bytes += length;
        }
        break;
    case CONTENT_ENCODING_BROTLI:
        r = http_stream_decompress_brotli(h_stream, data, length, data_output);
        break;
    default:
        http_stream_decompress_end(h_stream);
        r = 1;
    }

finish:
    log_stream(h_stream, trace, "returned {}", r);
    return r;
}

int http_stream_decompress_end(HttpStream *stream) {
    int result = 0;
    switch (stream->content_encoding) {
    case CONTENT_ENCODING_DEFLATE:
    case CONTENT_ENCODING_GZIP:
        result = inflateEnd(stream->zlib_stream);
        break;
    case CONTENT_ENCODING_BROTLI:
        BrotliDecoderDestroyInstance(stream->brotli_stream->state);
        break;
    default:
        break;
    }

    // NOLINTBEGIN(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    free(stream->decompress_stream);
    stream->decompress_stream = nullptr;
    free(stream->decode_in_buffer);
    stream->decode_in_buffer = nullptr;
    free(stream->decode_out_buffer);
    stream->decode_out_buffer = nullptr;
    // NOLINTEND(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    return result;
}

void http_stream_reset_state(HttpStream *stream) {
    if (stream->decompress_stream != nullptr) {
        http_stream_decompress_end(stream);
    }

    stream->headers = HttpHeaders{};

    stream->content_encoding = CONTENT_ENCODING_IDENTITY;
    stream->flags = (HttpStreamFlags) 0;
    stream->processed_bytes = 0;
}

HttpStream *http_stream_new(HttpSession *session, int32_t id) {
    auto *stream = new HttpStream{};
    stream->id = id;
    stream->session = session;
    stream->processed_bytes = 0;
    return stream;
}

void http_stream_destroy(HttpStream *stream) {
    http_stream_reset_state(stream);
    delete stream;
}

} // namespace ag
