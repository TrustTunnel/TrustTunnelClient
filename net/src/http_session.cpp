#include "net/http_session.h"

#include <cassert>

#include "common/logger.h"
#include "http1.h"
#include "http2.h"

namespace ag {

static ag::Logger g_logger{"HTTP"};

#define log_sess(s_, lvl_, fmt_, ...) lvl_##log(g_logger, "[id={}] " fmt_, (s_)->params.id, ##__VA_ARGS__)

HttpSession *http_session_open(const HttpSessionParams *params) {
    static_assert(std::is_trivial_v<HttpSession>);
    auto *session = (HttpSession *) calloc(1, sizeof(HttpSession));
    if (session == nullptr) {
        return nullptr;
    }

    session->params = *params;

    log_sess(session, trace, "");

    switch (params->version) {
    case HTTP_VER_1_1:
        session->h1 = http1_session_init(session);
        break;
    case HTTP_VER_2_0:
        session->h2 = http2_session_init(session);
        break;
    case HTTP_VER_3_0:
        assert(0);
        return nullptr;
    }

    if (session->h1 == nullptr && session->h2 == nullptr) {
        log_sess(session, err, "failed to initialize session");
        http_session_close(session);
        return nullptr;
    }

    return session;
}

int http_session_input(HttpSession *session, const uint8_t *data, size_t length) {
    switch (session->params.version) {
    case HTTP_VER_1_1:
        return http1_session_input(session, data, length);
    case HTTP_VER_2_0:
        return http2_session_input(session, data, length);
    case HTTP_VER_3_0:
        assert(0);
        break;
    }
    return -1;
}

int http_session_close(HttpSession *session) {
    int r = 0;
    if (session != nullptr) {
        switch (session->params.version) {
        case HTTP_VER_1_1:
            r = http1_session_close(session);
            break;
        case HTTP_VER_2_0:
            r = http2_session_close(session);
            break;
        case HTTP_VER_3_0:
            assert(0);
            r = -1;
            break;
        }

        free(session);
    }
    return r;
}

int http_session_send_headers(HttpSession *session, int32_t stream_id, const HttpHeaders *headers, bool eof) {
    switch (session->params.version) {
    case HTTP_VER_1_1:
        return http1_session_send_headers(session, stream_id, headers);
    case HTTP_VER_2_0:
        return http2_session_send_headers(session, stream_id, headers, eof);
    case HTTP_VER_3_0:
        assert(0);
        break;
    }
    return -1;
}

int http_session_send_data(HttpSession *session, int32_t stream_id, const uint8_t *data, size_t len, bool eof) {
    switch (session->params.version) {
    case HTTP_VER_1_1:
        return http1_session_send_data(session, stream_id, data, len, eof);
    case HTTP_VER_2_0:
        return http2_session_send_data(session, stream_id, data, len, eof);
    case HTTP_VER_3_0:
        assert(0);
        break;
    }
    return -1;
}

} // namespace ag
