// Regression test for the endpoint half of the idle-close fix (the destination half is covered
// by test_socks_idle_close.cpp): an idle EOF on the HTTP/2 endpoint socket must be handled by
// `Http2Upstream::net_handler()` even though libevent has already cleared EV_READ by the time
// the event is raised.
//
// Unlike `DirectUpstream`, whose reads can be re-enabled through `update_flow_control()` ->
// `tcp_socket_set_read_enabled()`, the endpoint socket's reads are enabled once at connect and
// never re-enabled, so this handler is the only place an idle endpoint EOF can be observed.

#ifdef _WIN32

// The test drives POSIX sockets directly; port it to a portable socket layer before enabling it here.
#include <gtest/gtest.h>

TEST(Http2UpstreamTest, SkippedOnWindows) {
    GTEST_SKIP() << "the test drives POSIX sockets directly";
}

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "http2_upstream.h"
#include "vpn/event_loop.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

using namespace ag;
using namespace std::chrono_literals;

// Create a listening socket bound to an arbitrary loopback port.
static int tcp_listen(uint16_t *out_port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    if (0 != ::bind(fd, (sockaddr *) &sa, sizeof(sa)) || 0 != ::listen(fd, 8)) {
        ::close(fd);
        return -1;
    }
    socklen_t len = sizeof(sa);
    getsockname(fd, (sockaddr *) &sa, &len);
    *out_port = ntohs(sa.sin_port);
    return fd;
}

namespace ag {

class Http2UpstreamTest : public ::testing::Test {
public:
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    vpn_client::Parameters parameters = {
            .ev_loop = this->ev_loop.get(),
    };
    std::unique_ptr<VpnClient> vpn;
    std::unique_ptr<Http2Upstream> upstream;
    TcpSocketPtr socket;
    uint16_t endpoint_port = 0;
    VpnError connect_error = {};
    std::thread worker;
    std::mutex guard;
    std::condition_variable cv;
    bool eof_seen = false;
    std::optional<ServerEvent> last_server_event;

    void SetUp() override {
        Logger::set_log_level(LOG_LEVEL_TRACE);

        this->vpn = std::make_unique<VpnClient>(this->parameters);
        this->upstream = std::make_unique<Http2Upstream>(
                VpnUpstreamProtocolConfig{}, 0, this->vpn.get(), ServerHandler{server_handler, this});

        this->worker = std::thread([loop = this->ev_loop.get()] {
            if (0 != vpn_event_loop_run(loop)) {
                abort();
            }
        });
    }

    void TearDown() override {
        vpn_event_loop_stop(this->ev_loop.get());
        if (this->worker.joinable()) {
            this->worker.join();
        }
        this->upstream.reset();
        this->socket.reset();
    }

    /**
     * Create a socket connected to the test endpoint and enable reading. Must run on the event
     * loop: `TcpSocket` state is not thread-safe, and the loop may process the connect completion
     * while `tcp_socket_connect()` is still on the stack.
     */
    void connect_socket(uint16_t port) {
        this->endpoint_port = port;
        bool dispatched = vpn_event_loop_dispatch_sync(
                this->ev_loop.get(),
                [](void *arg) {
                    auto *self = (Http2UpstreamTest *) arg;

                    TcpSocketParameters socket_parameters = {
                            .ev_loop = self->ev_loop.get(),
                            .handler = {socket_handler, self},
                            .timeout = Millis{},
                            .socket_manager = nullptr,
                            .read_threshold = 0,
                            .log_prefix = "test-endpoint",
                    };
                    self->socket.reset(tcp_socket_create(&socket_parameters));
                    if (self->socket == nullptr) {
                        self->connect_error = {-1, "Failed to create the test socket"};
                        return;
                    }

                    SocketAddress endpoint("127.0.0.1", self->endpoint_port);
                    TcpSocketConnectParameters connect_parameters = {.peer = &endpoint};
                    self->connect_error = tcp_socket_connect(self->socket.get(), &connect_parameters);
                    if (self->connect_error.code == 0) {
                        tcp_socket_set_read_enabled(self->socket.get(), true);
                    }
                },
                this);
        ASSERT_TRUE(dispatched);
        ASSERT_EQ(this->connect_error.code, 0) << this->connect_error.text;
    }

    /**
     * Inject the socket into the upstream and drive a readable event on the event loop, the way
     * the socket layer does when it raises one (normally the upstream's socket is created by
     * `open_session()`).
     */
    void drive_readable_event() {
        bool dispatched = vpn_event_loop_dispatch_sync(
                this->ev_loop.get(),
                [](void *arg) {
                    auto *self = (Http2UpstreamTest *) arg;
                    self->upstream->m_socket = std::move(self->socket);
                    Http2Upstream::net_handler(self->upstream.get(), TCP_SOCKET_EVENT_READABLE, nullptr);
                },
                this);
        ASSERT_TRUE(dispatched);
    }

    static void socket_handler(void *arg, TcpSocketEvent what, void *) {
        auto *self = (Http2UpstreamTest *) arg;
        if (what != TCP_SOCKET_EVENT_READABLE) {
            return;
        }
        if (std::holds_alternative<tcp_socket::Eof>(tcp_socket_peek(self->socket.get()))) {
            std::scoped_lock l(self->guard);
            self->eof_seen = true;
            self->cv.notify_all();
        }
    }

    static void server_handler(void *arg, ServerEvent what, void *) {
        auto *self = (Http2UpstreamTest *) arg;
        self->last_server_event = what;
    }
};

} // namespace ag

TEST_F(Http2UpstreamTest, IdleEndpointClose) {
    // A minimal "endpoint": accepts one connection and closes it immediately.
    uint16_t endpoint_port = 0;
    int listen_fd = tcp_listen(&endpoint_port);
    ASSERT_GE(listen_fd, 0);

    this->connect_socket(endpoint_port);

    int conn = -1;
    for (auto deadline = std::chrono::steady_clock::now() + 5s;
            conn < 0 && std::chrono::steady_clock::now() < deadline;) {
        pollfd p = {listen_fd, POLLIN, 0};
        if (0 < poll(&p, 1, 100)) {
            conn = ::accept(listen_fd, nullptr, nullptr);
        }
    }
    ASSERT_GE(conn, 0) << "the socket did not connect to the test endpoint";
    ::close(conn);
    ::close(listen_fd);

    {
        std::unique_lock l(this->guard);
        ASSERT_TRUE(this->cv.wait_for(l, 5s, [this] {
            return this->eof_seen;
        })) << "the socket did not report an idle EOF";
    }
    ASSERT_FALSE(tcp_socket_is_read_enabled(this->socket.get()))
            << "EV_READ should already be cleared when the EOF event is raised";

    this->drive_readable_event();

    EXPECT_EQ(this->last_server_event, SERVER_EVENT_SESSION_CLOSED)
            << "an idle endpoint EOF was not handled by the upstream";
}

#endif // _WIN32
