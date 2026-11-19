// Regression test for BUG-2: the HTTP/3 upstream must feed the saved Retry with the
// network path that created the QUIC session, not one rebuilt from the upstream
// endpoint config. Without the fix, ngtcp2 drops the Retry and the server never sees
// a tokenized Initial.

#ifdef _WIN32

#include <gtest/gtest.h>

TEST(Http3UpstreamHandoffTest, SkippedOnWindows) {
    GTEST_SKIP() << "the test drives POSIX sockets and ngtcp2 directly";
}

#else

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/rand.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "http3_upstream.h"
#include "net/network_manager.h"
#include "net/quic_connector.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

using namespace std::chrono_literals;

namespace {

using namespace ag;

constexpr Millis CONNECT_TIMEOUT{2000};
constexpr auto SERVER_TIMEOUT = 5s;

// A minimal QUIC "server" that answers the first client Initial with a Retry packet.
// It does not terminate TLS and does not complete the handshake. Its only job is to
// make the client produce a Retry and to detect whether the client accepts it.
class RetryServer {
public:
    RetryServer()
            : m_fd(::socket(AF_INET, SOCK_DGRAM, 0)) {
        if (m_fd < 0) {
            return;
        }
        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        if (0 != ::bind(m_fd, (sockaddr *) &sin, sizeof(sin))) {
            ::close(m_fd);
            m_fd = -1;
            return;
        }
        socklen_t len = sizeof(sin);
        EXPECT_EQ(0, ::getsockname(m_fd, (sockaddr *) &sin, &len));
        m_port = ntohs(sin.sin_port);
    }

    ~RetryServer() {
        stop();
        if (m_fd >= 0) {
            ::close(m_fd);
        }
    }

    void start() {
        m_thread = std::thread([this] {
            this->run();
        });
    }

    void stop() {
        m_stop.store(true, std::memory_order_relaxed);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    [[nodiscard]] bool valid() const {
        return m_fd >= 0;
    }

    [[nodiscard]] uint16_t port() const {
        return m_port;
    }

    [[nodiscard]] SocketAddress address() const {
        return {"127.0.0.1", m_port};
    }

    bool wait_retry_accepted(std::chrono::milliseconds timeout) {
        std::unique_lock l(m_guard);
        return m_guard_cv.wait_for(l, timeout, [this] {
            return m_retry_accepted;
        });
    }

    [[nodiscard]] bool retry_accepted() const {
        std::scoped_lock l(m_guard);
        return m_retry_accepted;
    }

private:
    void run() {
        std::vector<uint8_t> buffer(NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE);
        bool retry_sent = false;
        ngtcp2_cid retry_scid = {};
        static constexpr uint8_t RETRY_TOKEN[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

        while (!m_stop.load(std::memory_order_relaxed)) {
            pollfd pfd = {.fd = m_fd, .events = POLLIN, .revents = 0};
            int poll_result = ::poll(&pfd, 1, 50);
            if (poll_result <= 0) {
                continue;
            }

            sockaddr_storage client_addr = {};
            socklen_t client_addr_len = sizeof(client_addr);
            ssize_t received =
                    ::recvfrom(m_fd, buffer.data(), buffer.size(), 0, (sockaddr *) &client_addr, &client_addr_len);
            if (received <= 0) {
                continue;
            }

            ngtcp2_pkt_hd hd = {};
            if (ngtcp2_accept(&hd, buffer.data(), (size_t) received) != 0) {
                continue;
            }

            if (!retry_sent) {
                retry_scid.datalen = 8;
                RAND_bytes(retry_scid.data, (int) retry_scid.datalen);

                std::vector<uint8_t> retry(NGTCP2_MAX_UDP_PAYLOAD_SIZE);
                ngtcp2_ssize retry_len = ngtcp2_crypto_write_retry(retry.data(), retry.size(), hd.version, &hd.scid,
                        &retry_scid, &hd.dcid, RETRY_TOKEN, sizeof(RETRY_TOKEN));
                if (retry_len < 0) {
                    continue;
                }
                retry.resize((size_t) retry_len);
                ::sendto(m_fd, retry.data(), retry.size(), 0, (sockaddr *) &client_addr, client_addr_len);
                retry_sent = true;
                continue;
            }

            // A retransmitted first Initial has no token. A second Initial generated after
            // Retry has the token and the server-chosen DCID.
            if (hd.tokenlen == sizeof(RETRY_TOKEN) && 0 == std::memcmp(hd.token, RETRY_TOKEN, sizeof(RETRY_TOKEN))
                    && hd.dcid.datalen == retry_scid.datalen
                    && 0 == std::memcmp(hd.dcid.data, retry_scid.data, retry_scid.datalen)) {
                std::scoped_lock l(m_guard);
                m_retry_accepted = true;
                m_guard_cv.notify_all();
                return;
            }
        }
    }

    int m_fd = -1;
    uint16_t m_port = 0;
    std::thread m_thread;
    std::atomic_bool m_stop{false};
    mutable std::mutex m_guard;
    std::condition_variable m_guard_cv;
    bool m_retry_accepted = false;
};

class Http3UpstreamHandoffTest : public ::testing::Test {
public:
    Http3UpstreamHandoffTest() {
        Logger::set_log_level(LOG_LEVEL_INFO);
    }

    void SetUp() override {
        ASSERT_TRUE(this->server.valid());
        this->server.start();
        this->network_manager.reset(vpn_network_manager_get());
    }

    void TearDown() override {
        if (this->upstream) {
            vpn_event_loop_dispatch_sync(
                    this->loop.get(),
                    [](void *arg) {
                        auto *self = (Http3UpstreamHandoffTest *) arg;
                        static_cast<ServerUpstream *>(self->upstream.get())->close_session();
                    },
                    this);
            this->upstream.reset();
        }
        this->vpn.reset();
        this->connector.reset();

        vpn_event_loop_stop(this->loop.get());
        if (this->loop_thread.joinable()) {
            this->loop_thread.join();
        }
        this->server.stop();
    }

    // Connect a QUIC connector to the Retry server and wait for the first server datagram.
    std::unique_ptr<QuicConnectorResult> connect_connector() {
        auto ssl_r = make_ssl(
                nullptr, nullptr, {QUIC_H3_ALPN_PROTOS, std::size(QUIC_H3_ALPN_PROTOS)}, "localhost", MSPT_NGTCP2);
        if (!std::holds_alternative<SslPtr>(ssl_r)) {
            ADD_FAILURE() << std::get<std::string>(ssl_r);
            return nullptr;
        }
        SslPtr ssl = std::move(std::get<SslPtr>(ssl_r));

        QuicConnectorParameters parameters{
                .ev_loop = this->loop.get(),
                .handler = {connector_handler, this},
                .socket_manager = this->network_manager->socket,
                .log_prefix = "handoff-test",
        };
        this->connector.reset(quic_connector_create(&parameters));
        if (!this->connector) {
            return nullptr;
        }

        SocketAddress peer = this->server.address();
        QuicConnectorConnectParameters connect_parameters{
                .peer = &peer,
                .ssl = ssl.release(),
                .timeout = CONNECT_TIMEOUT,
                .max_idle_timeout = Millis{30000},
                .quic_version = 0,
        };
        VpnError error = quic_connector_connect(this->connector.get(), &connect_parameters);
        if (error.code != 0) {
            ADD_FAILURE() << error.text;
            return nullptr;
        }

        this->loop_thread = std::thread([this] {
            if (0 != vpn_event_loop_run(this->loop.get())) {
                ADD_FAILURE() << "event loop failed";
            }
        });

        std::unique_lock l(this->guard);
        if (!this->cv.wait_for(l, SERVER_TIMEOUT, [this] {
                return this->connector_ready || this->connector_error.has_value();
            })) {
            ADD_FAILURE() << "the connector did not become ready";
            return nullptr;
        }
        if (this->connector_error.has_value()) {
            ADD_FAILURE() << this->connector_error->text;
            return nullptr;
        }
        return quic_connector_get_result(this->connector.get());
    }

    // Hand the connector state to an Http3Upstream whose endpoint address is deliberately wrong.
    void run_handoff(std::unique_ptr<QuicConnectorResult> result) {
        ASSERT_NE(nullptr, result);
        EXPECT_EQ(result->peer.str(), this->server.address().str());

        this->vpn = std::make_unique<VpnClient>(vpn_client::Parameters{
                .ev_loop = this->loop.get(),
                .network_manager = this->network_manager.get(),
                .handler = {vpn_handler, this},
        });

        SocketAddress wrong_address("127.0.0.2", 9);
        EXPECT_NE(wrong_address.str(), result->peer.str());
        this->vpn->upstream_config.endpoint->address = *wrong_address.c_storage();
        this->vpn->upstream_config.timeout = Millis{30000};
        this->vpn->upstream_config.health_check_timeout = Millis{30000};
        this->vpn->quic_connector = std::move(result);

        VpnUpstreamProtocolConfig protocol_config{.type = VPN_UP_HTTP3};
        this->upstream = std::make_unique<Http3Upstream>(0, protocol_config);
        ServerUpstream *upstream_base = this->upstream.get();
        ASSERT_TRUE(upstream_base->init(this->vpn.get(), ServerHandler{server_handler, this}));

        vpn_event_loop_dispatch_sync(
                this->loop.get(),
                [](void *arg) {
                    auto *self = (Http3UpstreamHandoffTest *) arg;
                    self->open_result = static_cast<ServerUpstream *>(self->upstream.get())->open_session();
                },
                this);
        EXPECT_TRUE(this->open_result);
    }

private:
    static void connector_handler(void *arg, QuicConnectorEvent id, void *data) {
        auto *self = (Http3UpstreamHandoffTest *) arg;
        std::scoped_lock l(self->guard);
        switch (id) {
        case QUIC_CONNECTOR_EVENT_READY:
            self->connector_ready = true;
            break;
        case QUIC_CONNECTOR_EVENT_ERROR:
            self->connector_error = *(VpnError *) data;
            break;
        case QUIC_CONNECTOR_EVENT_PROTECT:
            break;
        }
        self->cv.notify_all();
    }

    static void server_handler(void *arg, ServerEvent what, void *) {
        auto *self = (Http3UpstreamHandoffTest *) arg;
        if (what == SERVER_EVENT_ERROR) {
            std::scoped_lock l(self->guard);
            self->upstream_error = true;
        }
    }

    static void vpn_handler(void *, vpn_client::Event, void *) {
    }

protected:
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager;
    RetryServer server;
    std::thread loop_thread;
    DeclPtr<QuicConnector, &quic_connector_destroy> connector;
    std::unique_ptr<VpnClient> vpn;
    std::unique_ptr<Http3Upstream> upstream;
    bool open_result = false;

    std::mutex guard;
    std::condition_variable cv;
    bool connector_ready = false;
    std::optional<VpnError> connector_error;
    bool upstream_error = false;
};

TEST_F(Http3UpstreamHandoffTest, RetryUsesTheSessionNetworkPath) {
    std::unique_ptr<QuicConnectorResult> result = this->connect_connector();
    ASSERT_NE(nullptr, result);
    ASSERT_EQ(this->server.address().str(), result->peer.str());

    this->run_handoff(std::move(result));

    EXPECT_FALSE(this->upstream_error);
    EXPECT_TRUE(this->server.wait_retry_accepted(SERVER_TIMEOUT))
            << "the Retry was not accepted: the upstream did not use the session network path";
    EXPECT_TRUE(this->server.retry_accepted());
}

} // namespace

#endif // _WIN32
