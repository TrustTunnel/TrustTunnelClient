#include "net/quic_connector.h"

#ifdef DISABLE_HTTP3

#include <cstdlib>

ag::QuicConnector *ag::quic_connector_create(const QuicConnectorParameters *) {
    abort();
}

void ag::quic_connector_destroy(QuicConnector *connector) {
    abort();
}

ag::VpnError ag::quic_connector_connect(QuicConnector *, const QuicConnectorConnectParameters *) {
    abort();
}

std::optional<ag::QuicConnectorResult> ag::quic_connector_get_result(QuicConnector *) {
    abort();
}

#else // DISABLE_HTTP3

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <event2/event.h>
#include <event2/util.h>
#include <magic_enum/magic_enum.hpp>

#include "common/http/http3.h"
#include "common/net_utils.h"
#include "net/udp_socket.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

#include <openssl/rand.h>
#include <openssl/ssl.h>

static void socket_handler(void *arg, ag::UdpSocketEvent what, void *data);
static void on_timer(evutil_socket_t, short, void *);
static void on_client_handshake_completed(void *arg);
static void on_client_output(void *arg, const ag::http::QuicNetworkPath &, ag::Uint8View chunk);
static void on_client_expiry_update(void *arg, ag::Nanos period);
static void on_client_close(void *arg, uint64_t error_code);
static void report_error(ag::QuicConnector *self, ag::VpnError error);
static void report_ready(ag::QuicConnector *self);

struct ag::QuicConnector {
    ag::DeclPtr<UdpSocket, &udp_socket_destroy> socket;
    std::unique_ptr<ag::http::Http3Client> client;
    ag::DeclPtr<event, &event_free> timer;
    SSL *ssl = nullptr; // Non-owning, valid until do_report
    QuicConnectorParameters parameters = {};
    SocketAddress peer; // server address, saved from connect() for path construction
    int64_t deadline_ns = 0;
    ag::TaskId report_task = -1;
    uint8_t server_payload[QUIC_MAX_UDP_PAYLOAD_SIZE]{};
    size_t server_payload_size = 0;
    std::optional<ag::VpnError> error;
    std::optional<ag::QuicConnectorResult> result;
};

ag::QuicConnector *ag::quic_connector_create(const ag::QuicConnectorParameters *parameters) {
    auto self = std::make_unique<QuicConnector>();
    self->parameters = *parameters;
    if (!self->parameters.ev_loop || !self->parameters.handler.handler || !self->parameters.socket_manager) {
        return nullptr;
    }
    return self.release();
}

void ag::quic_connector_destroy(ag::QuicConnector *connector) {
    if (connector) {
        if (connector->report_task != -1) {
            vpn_event_loop_cancel(connector->parameters.ev_loop, connector->report_task);
        }
    }
    delete connector;
}

ag::VpnError ag::quic_connector_connect(
        QuicConnector *connector, const ag::QuicConnectorConnectParameters *parameters) {
    ag::DeclPtr<SSL, &SSL_free> ssl{parameters->ssl};
    UdpSocketParameters sock_param{
            .ev_loop = connector->parameters.ev_loop,
            .handler = {.func = socket_handler, .arg = connector},
            .timeout = parameters->timeout,
            .peer = parameters->peer ? *parameters->peer : SocketAddress{},
            .socket_manager = connector->parameters.socket_manager,
    };
    connector->socket.reset(udp_socket_create(&sock_param));
    if (!connector->socket) {
        return {.code = -1, .text = "Failed to create a UDP socket"};
    }
    connector->peer = parameters->peer ? *parameters->peer : SocketAddress{};

    // Configure Http3Settings
    ag::http::Http3Settings settings{};
    settings.max_idle_timeout = ag::Micros{parameters->max_idle_timeout};
    // Other params (window size, max streams) use Http3Settings defaults

    // Set up callbacks for the ping phase
    ag::http::Http3Client::Callbacks callbacks{
        .arg = connector,
        .on_handshake_completed = on_client_handshake_completed,
        .on_response = nullptr,              // no requests during ping
        .on_body = nullptr,
        .on_stream_closed = nullptr,
        .on_close = on_client_close,
        .on_output = on_client_output,
        .on_expiry_update = on_client_expiry_update,
    };

    // Build QuicNetworkPath
    SocketAddress local = local_socket_address_from_fd(
            udp_socket_get_fd(connector->socket.get()));
    SocketAddress peer = parameters->peer ? *parameters->peer : SocketAddress{};
    ag::http::QuicNetworkPath path{
        .local = local.c_sockaddr(),
        .local_len = local.c_socklen(),
        .remote = peer.c_sockaddr(),
        .remote_len = peer.c_socklen(),
    };

    // Create Http3Client
    SSL *ssl_raw = ssl.get(); // save raw pointer before move
    auto result = ag::http::Http3Client::connect(settings, callbacks, path, std::move(ssl)); //TODO: settings???
    if (!result.has_value()) {
        connector->ssl = nullptr;
        return {.code = -1, .text = "Failed to create Http3Client"};
    }
    connector->client = std::move(result.value());
    connector->ssl = ssl_raw; // SSL now owned by Http3Client; keep non-owning pointer

    // Send Initial packet
    connector->client->flush();

    //quiche_config_verify_peer(config.get(), true);
    //quiche_config_set_application_protos(
    //        config.get(), (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL, strlen(QUICHE_H3_APPLICATION_PROTOCOL));
    //quiche_config_set_max_idle_timeout(config.get(), parameters->max_idle_timeout.count());
    //quiche_config_set_initial_max_data(config.get(), QUIC_CONNECTION_WINDOW_SIZE);
    //quiche_config_set_initial_max_stream_data_bidi_local(config.get(), QUIC_STREAM_WINDOW_SIZE);
    //quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), QUIC_STREAM_WINDOW_SIZE);
    //quiche_config_set_initial_max_stream_data_uni(config.get(), QUIC_STREAM_WINDOW_SIZE);
    //quiche_config_set_initial_max_streams_bidi(config.get(), QUIC_MAX_STREAMS_NUM);
    //quiche_config_set_initial_max_streams_uni(config.get(), QUIC_MAX_STREAMS_NUM);
    //quiche_config_set_max_recv_udp_payload_size(config.get(), QUIC_MAX_UDP_PAYLOAD_SIZE);
    //quiche_config_set_max_send_udp_payload_size(config.get(), QUIC_MAX_UDP_PAYLOAD_SIZE);
    //quiche_config_set_disable_active_migration(config.get(), true);
    //quiche_config_set_max_connection_window(config.get(), QUIC_CONNECTION_WINDOW_SIZE);
    //quiche_config_set_max_stream_window(config.get(), QUIC_STREAM_WINDOW_SIZE);
    //
    //uint8_t scid[QUIC_LOCAL_CONN_ID_LEN];
    //static_assert(std::size(scid) <= QUICHE_MAX_CONN_ID_LEN);
    //if (0 == RAND_bytes(scid, std::size(scid))) {
    //    return {.code = -1, .text = "Failed to generate connection ID"};
    //}

    connector->timer.reset(evtimer_new(vpn_event_loop_get_base(connector->parameters.ev_loop), on_timer, connector));
    if (!connector->timer) {
        return {.code = -1, .text = "Failed to create a timer"};
    }

    //connector->ssl = ssl.get();
    //SocketAddress local_address = local_socket_address_from_fd(udp_socket_get_fd(connector->socket.get()));
    //SocketAddress peer = parameters->peer ? *parameters->peer : SocketAddress{};
    //connector->conn.reset(quiche_conn_new_with_tls(scid, sizeof(scid), RUST_EMPTY, 0, local_address.c_sockaddr(),
    //        local_address.c_socklen(), peer.c_sockaddr(), peer.c_socklen(), config.get(), ssl.release(),
    //        /*is_server*/ false));
    //if (connector->conn == nullptr) {
    //    connector->ssl = nullptr;
    //    return {.code = -1, .text = "Failed to create a QUIC connection object"};
    //}

    int64_t now_ns = ag::get_time_monotonic_nanos();
    connector->deadline_ns = std::chrono::nanoseconds{parameters->timeout}.count() + now_ns;
    timeval tv = ag::ms_to_timeval(0);
    evtimer_add(connector->timer.get(), &tv);

    return {};
}

std::optional<ag::QuicConnectorResult> ag::quic_connector_get_result(ag::QuicConnector *connector) {
    return std::move(connector->result);
}

std::string ag::quic_connector_get_log_prefix(ag::QuicConnector *connector) {
    return connector->parameters.log_prefix;
}

void on_timer(evutil_socket_t, short, void *arg) {
    auto *self = (ag::QuicConnector *) arg;

    // Check deadline
    int64_t now_ns = ag::get_time_monotonic_nanos();
    if (now_ns >= self->deadline_ns) {
        report_error(self, {.code = ag::utils::AG_ETIMEDOUT, .text = "Timed out waiting for server response"});
        return;
    }

    // Forward to ngtcp2
    self->client->handle_expiry();
    // handle_expiry() may have completed handshake → do_report → socket.release()
    if (self->socket) {
        self->client->flush();
    }
}

/**
 * Called when handshake completes — connection is ready for handoff.
 */
static void on_client_handshake_completed(void *arg) {
    auto *self = (ag::QuicConnector *) arg;
    report_ready(self);
}

/**
 * Called when Http3Client wants to send a UDP packet.
 */
static void on_client_output(void *arg, const ag::http::QuicNetworkPath &, ag::Uint8View chunk) {
    auto *self = (ag::QuicConnector *) arg;
    if (!self->socket) {
        return; // socket already released via do_report
    }
    ag::VpnError error = ag::udp_socket_write(self->socket.get(), chunk.data(), chunk.size());
    if (error.code != 0) {
        report_error(self, error);
    }
}

/**
 * Called when the timer needs to be rescheduled.
 */
static void on_client_expiry_update(void *arg, ag::Nanos period) {
    auto *self = (ag::QuicConnector *) arg;
    int64_t now_ns = ag::get_time_monotonic_nanos();
    int64_t remaining_ns = self->deadline_ns - now_ns;
    if (remaining_ns <= 0) {
        report_error(self, {.code = ag::utils::AG_ETIMEDOUT, .text = "Timed out waiting for server response"});
        return;
    }
    // Take min of deadline and ngtcp2 period
    uint32_t timeout_ms = uint32_t(std::min(int64_t(period.count()), remaining_ns) / 1000000);
    timeval tv = ag::ms_to_timeval(timeout_ms);
    evtimer_add(self->timer.get(), &tv);
}

/**
 * Called when the connection is closed with an error.
 */
static void on_client_close(void *arg, uint64_t error_code) {
    auto *self = (ag::QuicConnector *) arg;
    report_error(self, {.code = (int) error_code, .text = "QUIC connection closed"});
}

void socket_handler(void *arg, ag::UdpSocketEvent what, void *data) {
    auto *self = (ag::QuicConnector *) arg;
    switch (what) {
    case ag::UDP_SOCKET_EVENT_PROTECT:
        self->parameters.handler.handler(self->parameters.handler.arg, ag::QUIC_CONNECTOR_EVENT_PROTECT, data);
        break;
    case ag::UDP_SOCKET_EVENT_READABLE: {
        ssize_t ret = ag::udp_socket_recv(self->socket.get(), self->server_payload, sizeof(self->server_payload));
        if (ret < 0) {
            int error = evutil_socket_geterror(ag::udp_socket_get_fd(self->socket.get()));
            report_error(self, {.code = error, .text = evutil_socket_error_to_string(error)});
            break;
        }
        self->server_payload_size = ret;

        // Feed response to ngtcp2 to continue handshake
        ag::SocketAddress local = ag::local_socket_address_from_fd(udp_socket_get_fd(self->socket.get()));
        ag::http::QuicNetworkPath path{
            .local = local.c_sockaddr(),
            .local_len = local.c_socklen(),
            .remote = self->peer.c_sockaddr(),
            .remote_len = self->peer.c_socklen(),
        };
        self->client->input(path, {self->server_payload, (size_t) ret});
        // input() may have completed handshake → do_report → socket.release()
        if (self->socket) {
            self->client->flush();
        }
        // Do not call report_ready here — wait for on_handshake_completed
        break;
    }
    case ag::UDP_SOCKET_EVENT_TIMEOUT:
        report_error(self, {.code = ag::utils::AG_ETIMEDOUT, .text = "UDP socket timed out"});
        break;
    }
}

static void do_report(ag::QuicConnector *self) {
    self->timer.reset();
    if (self->error.has_value()) {
        self->client.reset();
        self->socket.reset();
        self->parameters.handler.handler(self->parameters.handler.arg, ag::QUIC_CONNECTOR_EVENT_ERROR, &*self->error);
        return;
    }
    self->result.emplace(ag::QuicConnectorResult{
        .fd = ag::udp_socket_release_fd(self->socket.release()),
        .client = std::move(self->client),
    });
    self->parameters.handler.handler(self->parameters.handler.arg, ag::QUIC_CONNECTOR_EVENT_READY, nullptr);
}

void report_error(ag::QuicConnector *self, ag::VpnError error) {
    if (self->report_task != -1) {
        return;
    }
    self->error = error;
    self->report_task = ag::vpn_event_loop_submit(self->parameters.ev_loop,
            {
                    .arg = self,
                    .action =
                            [](void *arg, ag::TaskId) {
                                do_report((ag::QuicConnector *) arg);
                            },
            });
}

void report_ready(ag::QuicConnector *self) {
    if (self->report_task != -1) {
        return;
    }
    do_report(self);
}

#endif // DISABLE_HTTP3
