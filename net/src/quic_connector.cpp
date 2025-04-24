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
#include <quiche.h>

#include "common/net_utils.h"
#include "net/udp_socket.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

#include "vpn/platform.h"

#include <openssl/rand.h>
#include <openssl/ssl.h>

static void socket_handler(void *arg, ag::UdpSocketEvent what, void *data);
static void drive_connection(ag::QuicConnector *self);
static void on_timer(evutil_socket_t, short, void *);
static void report_error(ag::QuicConnector *self, ag::VpnError error);
static void report_ready(ag::QuicConnector *self);

struct ag::QuicConnector {
    ag::DeclPtr<UdpSocket, &udp_socket_destroy> socket;
    ag::DeclPtr<quiche_conn, &quiche_conn_free> conn;
    ag::DeclPtr<event, &event_free> timer;
    SSL *ssl = nullptr; // Non-owning, SSL owned by `conn`.
    QuicConnectorParameters parameters = {};
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
            .peer = sockaddr_to_storage(parameters->peer),
            .socket_manager = connector->parameters.socket_manager,
    };
    connector->socket.reset(udp_socket_create(&sock_param));
    if (!connector->socket) {
        return {.code = -1, .text = "Failed to create a UDP socket"};
    }

    ag::DeclPtr<quiche_config, &quiche_config_free> config{
            quiche_config_new((parameters->quic_version == 0) ? QUICHE_PROTOCOL_VERSION : parameters->quic_version)};
    if (config == nullptr) {
        return {.code = -1, .text = "Failed to create a QUIC config"};
    }

    quiche_config_verify_peer(config.get(), true);
    quiche_config_set_application_protos(
            config.get(), (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL, strlen(QUICHE_H3_APPLICATION_PROTOCOL));
    quiche_config_set_max_idle_timeout(config.get(), parameters->max_idle_timeout.count());
    quiche_config_set_initial_max_data(config.get(), QUIC_CONNECTION_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_bidi_local(config.get(), QUIC_STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), QUIC_STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_uni(config.get(), QUIC_STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_streams_bidi(config.get(), QUIC_MAX_STREAMS_NUM);
    quiche_config_set_initial_max_streams_uni(config.get(), QUIC_MAX_STREAMS_NUM);
    quiche_config_set_max_recv_udp_payload_size(config.get(), QUIC_MAX_UDP_PAYLOAD_SIZE);
    quiche_config_set_max_send_udp_payload_size(config.get(), QUIC_MAX_UDP_PAYLOAD_SIZE);
    quiche_config_set_disable_active_migration(config.get(), true);
    quiche_config_set_max_connection_window(config.get(), QUIC_CONNECTION_WINDOW_SIZE);
    quiche_config_set_max_stream_window(config.get(), QUIC_STREAM_WINDOW_SIZE);

    uint8_t scid[QUIC_LOCAL_CONN_ID_LEN];
    static_assert(std::size(scid) <= QUICHE_MAX_CONN_ID_LEN);
    if (0 == RAND_bytes(scid, std::size(scid))) {
        return {.code = -1, .text = "Failed to generate connection ID"};
    }

    connector->timer.reset(evtimer_new(vpn_event_loop_get_base(connector->parameters.ev_loop), on_timer, connector));
    if (!connector->timer) {
        return {.code = -1, .text = "Failed to create a timer"};
    }

    connector->ssl = ssl.get();
    sockaddr_storage local_address = local_sockaddr_from_fd(udp_socket_get_fd(connector->socket.get()));
    connector->conn.reset(quiche_conn_new_with_tls(scid, sizeof(scid), nullptr, 0, (sockaddr *) &local_address,
            sockaddr_get_size((sockaddr *) &local_address), parameters->peer, sockaddr_get_size(parameters->peer),
            config.get(), ssl.release(), /*is_server*/ false));
    if (connector->conn == nullptr) {
        connector->ssl = nullptr;
        return {.code = -1, .text = "Failed to create a QUIC connection object"};
    }

    int64_t now_ns = ag::get_time_monotonic_nanos();
    connector->deadline_ns = std::chrono::nanoseconds{parameters->timeout}.count() + now_ns;

    drive_connection(connector);

    return {};
}

std::optional<ag::QuicConnectorResult> ag::quic_connector_get_result(ag::QuicConnector *connector) {
    return std::move(connector->result);
}

void drive_connection(ag::QuicConnector *self) {
    int64_t now_ns = ag::get_time_monotonic_nanos();
    int64_t timeout_ns = self->deadline_ns - now_ns;
    if (timeout_ns <= 0) {
        report_error(self, {.code = ag::utils::AG_ETIMEDOUT, .text = "Timed out waiting for server response"});
        return;
    }

    for (;;) {
        uint8_t buf[ag::QUIC_MAX_UDP_PAYLOAD_SIZE];
        quiche_send_info info;
        ssize_t ret = quiche_conn_send(self->conn.get(), buf, sizeof(buf), &info);
        if (ret == QUICHE_ERR_DONE) {
            break;
        }
        if (ret < 0) {
            report_error(self, {.code = -1, .text = magic_enum::enum_name((quiche_error) ret).data()});
            return;
        }
        (void) info;
        ag::VpnError error = ag::udp_socket_write(self->socket.get(), buf, ret);
        if (error.code != 0) {
            report_error(self, error);
            return;
        }
    }

    uint64_t qtimeout_ns = quiche_conn_timeout_as_nanos(self->conn.get());
    uint32_t timeout_ms = uint32_t(std::min(uint64_t(timeout_ns), qtimeout_ns) / 1000);
    auto tv = ag::ms_to_timeval(timeout_ms);
    evtimer_add(self->timer.get(), &tv);
}

void on_timer(evutil_socket_t, short, void *arg) {
    auto *self = (ag::QuicConnector *) arg;
    quiche_conn_on_timeout(self->conn.get());
    drive_connection(self);
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
        report_ready(self);
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
        self->conn.reset();
        self->socket.reset();
        self->parameters.handler.handler(self->parameters.handler.arg, ag::QUIC_CONNECTOR_EVENT_ERROR, &*self->error);
        return;
    }
    self->result.emplace(ag::QuicConnectorResult{
            .fd = ag::udp_socket_release_fd(self->socket.release()),
            .conn = std::move(self->conn),
            .ssl = self->ssl,
            .data = {self->server_payload, self->server_payload_size},
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
