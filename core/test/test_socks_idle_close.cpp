// Regression test for CoreLibs#2048: a destination closing an *idle* connection must be
// propagated to the SOCKS5 client without waiting for new client data. Otherwise the client
// keeps reusing the zombie connection and requests written into it are lost.
//
// The EOF event is raised after libevent has already cleared EV_READ (`tcp_socket.cpp`
// `on_event()`), so consumers must not process it inside a loop gated by
// `tcp_socket_is_read_enabled()`.

#ifdef _WIN32

// The test drives POSIX sockets directly; port it to a portable socket layer before enabling it here.
#include <gtest/gtest.h>

TEST(SocksIdleCloseTest, SkippedOnWindows) {
    GTEST_SKIP() << "the test drives POSIX sockets directly";
}

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>
#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "net/network_manager.h"
#include "socks_listener.h"
#include "vpn/event_loop.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

using namespace ag;
using namespace std::chrono_literals;

static bool wait_readable(int fd, std::chrono::milliseconds timeout) {
    pollfd p = {fd, POLLIN, 0};
    return poll(&p, 1, (int) timeout.count()) > 0;
}

static constexpr ssize_t READ_TIMEOUT = -1;    // no data within the timeout
static constexpr ssize_t READ_CONN_ERROR = -2; // the connection is gone (reset, aborted)
static constexpr ssize_t READ_FAILED = -3;     // an unexpected read error

// Returns: > 0 bytes read, 0 on EOF, or one of the `READ_*` codes above.
static ssize_t read_some(int fd, void *buf, size_t size, std::chrono::milliseconds timeout) {
    if (!wait_readable(fd, timeout)) {
        return READ_TIMEOUT;
    }
    ssize_t r = ::read(fd, buf, size);
    if (r > 0) {
        return r;
    }
    if (r == 0) {
        return 0;
    }
    switch (errno) {
    case ECONNRESET:
    case ECONNABORTED:
    case ENOTCONN:
    case ETIMEDOUT:
        return READ_CONN_ERROR;
    default:
        return READ_FAILED;
    }
}

static bool read_exact(int fd, void *buf, size_t size, std::chrono::milliseconds timeout) {
    auto *p = (uint8_t *) buf;
    size_t got = 0;
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (got < size) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0 || !wait_readable(fd, left)) {
            return false;
        }
        ssize_t r = ::read(fd, p + got, size - got);
        if (r <= 0) {
            return false;
        }
        got += (size_t) r;
    }
    return true;
}

static bool write_all(int fd, const void *buf, size_t size) {
    auto *p = (const uint8_t *) buf;
    size_t sent = 0;
    while (sent < size) {
        ssize_t r = ::write(fd, p + sent, size - sent);
        if (r <= 0) {
            return false;
        }
        sent += (size_t) r;
    }
    return true;
}

static int tcp_connect(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_in sa = {};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (0 != ::connect(fd, (sockaddr *) &sa, sizeof(sa))) {
        ::close(fd);
        return -1;
    }
    return fd;
}

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

// SOCKS5: no-auth greeting + CONNECT to 127.0.0.1:<target_port>
static bool socks5_connect_to(int fd, uint16_t target_port) {
    uint8_t greeting[] = {0x05, 0x01, 0x00};
    if (!write_all(fd, greeting, sizeof(greeting))) {
        return false;
    }
    uint8_t auth_reply[2] = {};
    if (!read_exact(fd, auth_reply, sizeof(auth_reply), 5s) || auth_reply[0] != 0x05 || auth_reply[1] != 0x00) {
        return false;
    }

    uint8_t request[10] = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
    request[8] = (uint8_t) (target_port >> 8);
    request[9] = (uint8_t) (target_port & 0xff);
    if (!write_all(fd, request, sizeof(request))) {
        return false;
    }

    uint8_t reply[4] = {};
    if (!read_exact(fd, reply, sizeof(reply), 5s)) {
        return false;
    }
    if (reply[1] != 0x00) {
        return false;
    }
    size_t addr_len = (reply[3] == 0x01) ? 4 : (reply[3] == 0x04 ? 16 : 0);
    if (addr_len == 0) {
        return false;
    }
    uint8_t tail[16 + 2] = {};
    return read_exact(fd, tail, addr_len + 2, 5s);
}

// Test destination: accepts one connection, replies once, then closes it after idling.
class DestinationServer {
public:
    explicit DestinationServer(std::chrono::milliseconds idle_before_close)
            : m_idle_before_close(idle_before_close) {
    }

    ~DestinationServer() {
        stop();
    }

    bool start() {
        m_listen_fd = tcp_listen(&m_port);
        if (m_listen_fd < 0) {
            return false;
        }
        m_thread = std::thread([this] {
            run();
        });
        return true;
    }

    [[nodiscard]] uint16_t port() const {
        return m_port;
    }

    void wait_until_closed(std::chrono::milliseconds timeout = 10s) {
        std::unique_lock l(m_guard);
        m_closed_cv.wait_for(l, timeout, [this] {
            return m_closed;
        });
    }

    void stop() {
        m_stop = true;
        if (m_thread.joinable()) {
            m_thread.join();
        }
        if (m_listen_fd >= 0) {
            ::close(m_listen_fd);
            m_listen_fd = -1;
        }
    }

private:
    void run() {
        int conn = -1;
        while (!m_stop && conn < 0) {
            pollfd p = {m_listen_fd, POLLIN, 0};
            if (0 < poll(&p, 1, 100)) {
                conn = ::accept(m_listen_fd, nullptr, nullptr);
            }
        }
        if (conn < 0) {
            return;
        }

        uint8_t buf[4096];
        if (read_some(conn, buf, sizeof(buf), 5s) <= 0) {
            ::close(conn);
            mark_closed();
            return;
        }

        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        write_all(conn, response, strlen(response));

        std::this_thread::sleep_for(m_idle_before_close);

        // Half-close first, so that the peer sees an orderly EOF, then drain what the client sent
        // while we were idling: closing a socket with unread data would send a reset instead.
        ::shutdown(conn, SHUT_WR);
        auto drain_deadline = std::chrono::steady_clock::now() + 1s;
        uint8_t drain_buf[4096];
        while (std::chrono::steady_clock::now() < drain_deadline) {
            ssize_t r = read_some(conn, drain_buf, sizeof(drain_buf), 50ms);
            if (r == READ_TIMEOUT) {
                continue; // keep waiting for the client's remaining data until the deadline
            }
            if (r <= 0) {
                break; // EOF or a connection error: the peer is done
            }
        }

        ::close(conn);
        mark_closed();
    }

    void mark_closed() {
        {
            std::scoped_lock l(m_guard);
            m_closed = true;
        }
        m_closed_cv.notify_all();
    }

    std::chrono::milliseconds m_idle_before_close;
    int m_listen_fd = -1;
    uint16_t m_port = 0;
    std::thread m_thread;
    std::atomic<bool> m_stop{false};
    std::mutex m_guard;
    std::condition_variable m_closed_cv;
    bool m_closed = false;
};

enum class CloseResult {
    TIMEOUT,  // the connection is still open
    ORDERLY,  // closed gracefully: the client read an EOF
    RESET,    // terminated with a connection error (e.g. an incoming reset)
    IO_ERROR, // an unexpected read error
};

// Wait for the SOCKS5 connection to be closed, reading and discarding data.
static CloseResult wait_for_close(int fd, std::chrono::milliseconds timeout) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            return CloseResult::TIMEOUT;
        }
        uint8_t buf[4096];
        ssize_t r = read_some(fd, buf, sizeof(buf), left);
        if (r == 0) {
            return CloseResult::ORDERLY;
        }
        if (r == READ_CONN_ERROR) {
            return CloseResult::RESET;
        }
        if (r == READ_FAILED) {
            return CloseResult::IO_ERROR;
        }
    }
}

class SocksIdleCloseTest : public ::testing::Test {
public:
    ag::DeclPtr<ag::VpnEventLoop, &ag::vpn_event_loop_destroy> ev_loop{ag::vpn_event_loop_create()};
    ag::DeclPtr<ag::VpnNetworkManager, &ag::vpn_network_manager_destroy> network_manager{ag::vpn_network_manager_get()};
    ag::vpn_client::Parameters parameters = {
            .ev_loop = this->ev_loop.get(),
            .network_manager = this->network_manager.get(),
            .handler = {client_handler, this},
            .cert_verify_handler =
                    {
                            .func =
                                    [](auto...) {
                                        return 1;
                                    },
                    },
    };
    ag::VpnSettings settings = {
            .handler = {vpn_handler, this},
    };
    std::unique_ptr<ag::VpnClient> vpn;
    std::thread worker;
    uint16_t socks_port = 0;
    ag::VpnError listen_error = {};
    std::atomic<int> connect_requests{0};

    void SetUp() override {
        // The test writes into a connection that the proxy may close at any moment; a raw write()
        // would raise SIGPIPE, which the event loop blocks only on its own thread.
        signal(SIGPIPE, SIG_IGN);
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);

        this->vpn = std::make_unique<ag::VpnClient>(this->parameters);
        ag::VpnError error = this->vpn->init(&this->settings);
        ASSERT_EQ(error.code, ag::VPN_EC_NOERROR) << error.text;

        this->worker = std::thread([loop = this->ev_loop.get()] {
            if (0 != ag::vpn_event_loop_run(loop)) {
                abort();
            }
        });

        ASSERT_TRUE(this->run_sync_on_ev_loop([this] {
            ag::VpnSocksListenerConfig socks_config = {};
            socks_config.listen_address = ag::sockaddr_from_str("127.0.0.1:0");
            auto listener = std::make_unique<ag::SocksListener>(&socks_config);
            this->socks_listener = listener.get();

            ag::VpnListenerConfig listener_config = {};
            this->listen_error = this->vpn->listen(std::move(listener), &listener_config);
            if (this->listen_error.code == ag::VPN_EC_NOERROR) {
                this->socks_port = this->socks_listener->get_listen_address().port();
            }
        }));
        ASSERT_EQ(this->listen_error.code, ag::VPN_EC_NOERROR) << this->listen_error.text;
        ASSERT_NE(this->socks_port, 0);
    }

    void TearDown() override {
        if (this->vpn != nullptr) {
            if (this->worker.joinable()) {
                this->run_sync_on_ev_loop([this] {
                    this->vpn->disconnect();
                });
                ag::vpn_event_loop_stop(this->ev_loop.get());
                this->worker.join();
            }
            // The client listener is released in `finalize_disconnect()`, not in `deinit()`.
            this->vpn->finalize_disconnect();
            this->vpn->deinit();
        }
    }

    static void client_handler(void *arg, ag::vpn_client::Event what, void *data) {
        auto *self = (SocksIdleCloseTest *) arg;
        switch (what) {
        case ag::vpn_client::EVENT_CONNECT_REQUEST: {
            auto *event = (VpnConnectRequestEvent *) data;
            self->connect_requests.fetch_add(1);
            self->vpn->complete_connect_request(event->id, ag::VPN_CA_FORCE_BYPASS);
            break;
        }
        default:
            break;
        }
    }

    static void vpn_handler(void *, ag::VpnEvent, void *) {
    }

    bool run_sync_on_ev_loop(std::function<void()> f) {
        struct Context {
            std::function<void()> *f;
        } ctx = {&f};
        return ag::vpn_event_loop_dispatch_sync(
                this->ev_loop.get(),
                [](void *arg) {
                    auto *context = (Context *) arg;
                    (*context->f)();
                },
                &ctx);
    }

    ag::SocksListener *socks_listener = nullptr;
};

// The destination closes an idle connection: the close must reach the SOCKS5 client
// without any further client activity.
TEST_F(SocksIdleCloseTest, IdleDestinationClose) {
    DestinationServer destination(1000ms);
    ASSERT_TRUE(destination.start());

    int fd = tcp_connect(this->socks_port);
    ASSERT_GE(fd, 0) << "could not connect to the SOCKS5 listener";
    ASSERT_TRUE(socks5_connect_to(fd, destination.port())) << "SOCKS5 CONNECT failed";

    const char *request = "GET /one HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    ASSERT_TRUE(write_all(fd, request, strlen(request)));

    uint8_t buf[4096];
    ASSERT_GT(read_some(fd, buf, sizeof(buf), 5s), 0) << "no response to the first request";

    // Let the destination close the now idle connection and wait for the close to be propagated.
    destination.wait_until_closed();
    auto start = std::chrono::steady_clock::now();
    CloseResult result = wait_for_close(fd, 3s);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    ::close(fd);

    EXPECT_EQ(result, CloseResult::ORDERLY)
            << "the destination close was not propagated as an orderly EOF while the connection was idle (got "
            << magic_enum::enum_name(result) << " after " << elapsed.count() << " ms)";
}

// Control: on an active connection the close is propagated promptly.
TEST_F(SocksIdleCloseTest, ActiveDestinationClose) {
    DestinationServer destination(1000ms);
    ASSERT_TRUE(destination.start());

    int fd = tcp_connect(this->socks_port);
    ASSERT_GE(fd, 0);
    ASSERT_TRUE(socks5_connect_to(fd, destination.port()));

    const char *request = "GET /one HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    ASSERT_TRUE(write_all(fd, request, strlen(request)));
    uint8_t buf[4096];
    ASSERT_GT(read_some(fd, buf, sizeof(buf), 5s), 0) << "no response to the first request";

    // Keep the connection busy until the destination closes it. A write may fail when the proxy
    // closes the connection between the checks below; the read side still has to report the close.
    auto start = std::chrono::steady_clock::now();
    CloseResult result = CloseResult::TIMEOUT;
    while (std::chrono::steady_clock::now() - start < 5s) {
        if (!write_all(fd, request, strlen(request))) {
            break;
        }
        result = wait_for_close(fd, 200ms);
        if (result != CloseResult::TIMEOUT) {
            break;
        }
    }
    if (result == CloseResult::TIMEOUT) {
        result = wait_for_close(fd, 1s);
    }
    ::close(fd);

    // A reset is acceptable here: the test itself keeps writing into the connection while it is
    // being closed. Any other outcome means the close was not propagated (or an unexpected error).
    EXPECT_TRUE(result == CloseResult::ORDERLY || result == CloseResult::RESET)
            << "the destination close was not propagated on an active connection (got " << magic_enum::enum_name(result)
            << ")";
}

#endif // _WIN32
