#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "net/http_header.h"
#include "net/http_session.h"

using namespace ag;

struct HandlerState {
    size_t output_bytes = 0;
    size_t sent_bytes = 0;
};

static void require(bool condition, int line) {
    if (!condition) {
        (void) std::fprintf(stderr, "test_http2 failed at line %d\n", line);
        std::abort();
    }
}

#define REQUIRE(condition) require((condition), __LINE__)

static void send_settings(HttpSession *session) {
    static constexpr std::array<uint8_t, 9> frame = {
            0x00,
            0x00,
            0x00,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
    };
    REQUIRE(http_session_input(session, frame.data(), frame.size()) == (int) frame.size());
}

static void http_handler(void *arg, HttpEventId what, void *data) {
    auto *state = (HandlerState *) arg;

    switch (what) {
    case HTTP_EVENT_OUTPUT: {
        const auto *event = (HttpOutputEvent *) data;
        state->output_bytes += event->length;
        break;
    }
    case HTTP_EVENT_DATA_SENT: {
        const auto *event = (HttpDataSentEvent *) data;
        state->sent_bytes += event->length;
        break;
    }
    default:
        break;
    }
}

static void send_window_update(HttpSession *session, uint32_t stream_id, uint32_t increment) {
    std::array<uint8_t, 13> frame = {
            0x00,
            0x00,
            0x04,
            0x08,
            0x00,
            uint8_t((stream_id >> 24) & 0x7f),
            uint8_t((stream_id >> 16) & 0xff),
            uint8_t((stream_id >> 8) & 0xff),
            uint8_t(stream_id & 0xff),
            uint8_t((increment >> 24) & 0x7f),
            uint8_t((increment >> 16) & 0xff),
            uint8_t((increment >> 8) & 0xff),
            uint8_t(increment & 0xff),
    };
    REQUIRE(http_session_input(session, frame.data(), frame.size()) == (int) frame.size());
}

int main() { // NOLINT(bugprone-exception-escape)
    HandlerState state;
    HttpSessionParams params = {
            .id = 1,
            .handler = {http_handler, &state},
            .stream_window_size = 128 * 1024,
            .version = HTTP_VER_2_0,
    };

    HttpSession *session = http_session_open(&params);
    REQUIRE(session != nullptr);

    REQUIRE(http_session_send_settings(session) == 0);
    send_settings(session);

    HttpHeaders headers{.version = HTTP_VER_2_0};
    headers.method = "CONNECT";
    headers.authority = "example.org:443";
    REQUIRE(http_session_send_headers(session, 1, &headers, false) == 0);

    size_t available = http_session_available_to_write(session, 1);
    REQUIRE(available > 0);

    std::vector<uint8_t> body(available, 0x42);
    REQUIRE(http_session_send_data(session, 1, body.data(), body.size(), false) == 0);
    REQUIRE(state.output_bytes > 0);
    REQUIRE(state.sent_bytes == available);
    REQUIRE(http_session_available_to_write(session, 1) == 0);

    send_window_update(session, 1, (uint32_t) available);
    REQUIRE(http_session_available_to_write(session, 1) == 0);

    send_window_update(session, 0, (uint32_t) available);
    REQUIRE(http_session_available_to_write(session, 1) == available);

    REQUIRE(http_session_close(session) == 0);
}
