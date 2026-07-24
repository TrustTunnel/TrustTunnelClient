#include <atomic>
#include <chrono>
#include <cstring>
#include <iterator>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

#include <event2/event.h>
#include <event2/util.h>
#include <gtest/gtest.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "net/network_manager.h"
#include "net/quic_connector.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

using namespace ag;

static constexpr Millis CONNECT_TIMEOUT{1000};
static constexpr Millis LOOP_EXIT_TIMEOUT{10 * CONNECT_TIMEOUT};

// A loopback UDP "server" which replies to every received datagram with a fixed payload.
// It cannot complete a QUIC handshake; it is only needed to trigger the connector's
// "first datagram from the server" condition.
class FakeUdpServer {
public:
    explicit FakeUdpServer(std::vector<uint8_t> reply)
            : m_fd(socket(AF_INET, SOCK_DGRAM, 0))
            , m_reply(std::move(reply)) {
        EXPECT_NE(m_fd, EVUTIL_INVALID_SOCKET);

        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        EXPECT_EQ(0, bind(m_fd, (sockaddr *) &sin, sizeof(sin)));

        socklen_t sin_len = sizeof(sin);
        EXPECT_EQ(0, getsockname(m_fd, (sockaddr *) &sin, &sin_len));
        m_port = ntohs(sin.sin_port);

        EXPECT_EQ(0, evutil_make_socket_nonblocking(m_fd));
    }

    ~FakeUdpServer() {
        stop();
        if (m_fd != EVUTIL_INVALID_SOCKET) {
            evutil_closesocket(m_fd);
        }
    }

    void start() {
        m_thread = std::thread([this] {
            while (!m_stop.load(std::memory_order_relaxed)) {
                uint8_t buf[UINT16_MAX];
                sockaddr_storage from{};
                socklen_t from_len = sizeof(from);
                ssize_t r = recvfrom(m_fd, (char *) buf, sizeof(buf), 0, (sockaddr *) &from, &from_len);
                if (r > 0) {
                    ++m_received;
                    sendto(m_fd, (const char *) m_reply.data(), (int) m_reply.size(), 0, (sockaddr *) &from, from_len);
                } else {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
        });
    }

    void stop() {
        m_stop.store(true, std::memory_order_relaxed);
        if (m_thread.joinable()) {
            m_thread.join();
        }
    }

    [[nodiscard]] uint16_t port() const {
        return m_port;
    }

    [[nodiscard]] size_t received_count() const {
        return m_received.load(std::memory_order_relaxed);
    }

private:
    evutil_socket_t m_fd = EVUTIL_INVALID_SOCKET;
    uint16_t m_port = 0;
    std::vector<uint8_t> m_reply;
    std::thread m_thread;
    std::atomic_bool m_stop{false};
    std::atomic_size_t m_received{0};
};

struct ConnectorCtx {
    VpnEventLoop *loop = nullptr;
    event_base *base = nullptr;
    DeclPtr<QuicConnector, &quic_connector_destroy> connector;
    std::unique_ptr<QuicConnectorResult> result;
    std::optional<VpnError> error;
};

class QuicConnectorTest : public testing::Test {
public:
    QuicConnectorTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};

    [[nodiscard]] ConnectorCtx make_ctx() const {
        return {
                .loop = this->loop.get(),
                .base = vpn_event_loop_get_base(this->loop.get()),
        };
    }

    void connect(ConnectorCtx &ctx, uint16_t port) const {
        auto ssl_r = make_ssl(
                nullptr, nullptr, {QUIC_H3_ALPN_PROTOS, std::size(QUIC_H3_ALPN_PROTOS)}, "localhost", MSPT_NGTCP2);
        ASSERT_TRUE(std::holds_alternative<SslPtr>(ssl_r)) << std::get<std::string>(ssl_r);
        SslPtr ssl = std::move(std::get<SslPtr>(ssl_r));

        QuicConnectorParameters parameters{
                .ev_loop = ctx.loop,
                .handler = {connector_handler, &ctx},
                .socket_manager = this->network_manager->socket,
                .log_prefix = "test",
        };
        ctx.connector.reset(quic_connector_create(&parameters));
        ASSERT_NE(ctx.connector.get(), nullptr);

        SocketAddress peer{sockaddr_from_str(AG_FMT("127.0.0.1:{}", port).c_str())};
        QuicConnectorConnectParameters connect_parameters{
                .peer = &peer,
                .ssl = ssl.release(),
                .timeout = CONNECT_TIMEOUT,
                .max_idle_timeout = Millis{30000},
                .quic_version = 0,
        };
        VpnError error = quic_connector_connect(ctx.connector.get(), &connect_parameters);
        ASSERT_EQ(error.code, 0) << error.text;
    }

    void run_event_loop() {
        vpn_event_loop_exit(loop.get(), LOOP_EXIT_TIMEOUT);
        vpn_event_loop_run(loop.get());
    }

private:
    static void connector_handler(void *arg, QuicConnectorEvent id, void *data) {
        auto *ctx = (ConnectorCtx *) arg;
        switch (id) {
        case QUIC_CONNECTOR_EVENT_READY:
            ctx->result = quic_connector_get_result(ctx->connector.get());
            event_base_loopbreak(ctx->base);
            break;
        case QUIC_CONNECTOR_EVENT_ERROR:
            ctx->error = *(VpnError *) data;
            event_base_loopbreak(ctx->base);
            break;
        case QUIC_CONNECTOR_EVENT_PROTECT:
            break;
        }
    }
};

// The connector must report readiness right after receiving the first datagram from the server,
// without feeding it into the TLS stack, and hand the datagram over in the result object.
TEST_F(QuicConnectorTest, ReadyOnFirstDatagram) {
    std::vector<uint8_t> payload(64);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = (uint8_t) (i + 1);
    }
    FakeUdpServer server{payload};
    server.start();

    ConnectorCtx ctx = make_ctx();
    connect(ctx, server.port());
    run_event_loop();

    if (ctx.error.has_value()) {
        FAIL() << "Connector reported error: " << ctx.error->text;
    }
    ASSERT_NE(ctx.result, nullptr);
    EXPECT_NE(ctx.result->fd, EVUTIL_INVALID_SOCKET);
    ASSERT_NE(ctx.result->client, nullptr);
    EXPECT_EQ(ctx.result->first_packet, payload);
    // The connection must be handed off half-open: the handshake is completed by the recipient
    EXPECT_EQ(0, SSL_is_init_finished(ctx.result->client->get_ssl()));
    // The connector must have sent the ClientHello to the server
    EXPECT_GT(server.received_count(), 0);
}

// The connector must report an error if the server does not respond in time.
TEST_F(QuicConnectorTest, TimeoutOnNoResponse) {
    FakeUdpServer black_hole{{}};
    // Do not start the server thread: nothing will reply to the connector's packets

    ConnectorCtx ctx = make_ctx();
    connect(ctx, black_hole.port());
    run_event_loop();

    EXPECT_EQ(ctx.result, nullptr);
    ASSERT_TRUE(ctx.error.has_value());
    EXPECT_EQ(ctx.error->code, utils::AG_ETIMEDOUT) << ctx.error->text;
}
