#include "socks_listener.h"

#include <cassert>

#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

namespace ag {

static constexpr Socks5ConnectResult TUNNEL_TO_SOCKS_CONNECT_RESULT[] = {
        /** CCR_PASS */ S5LCR_SUCCESS,
        /** CCR_DROP */ S5LCR_TIMEOUT,
        /** CCR_REJECT */ S5LCR_REJECT,
        /** CCR_UNREACH */ S5LCR_UNREACHABLE,
};

static TunnelAddress socks_to_client_address(const Socks5ConnectionAddress *addr) {
    switch (addr->type) {
    case S5CAT_SOCKADDR:
        return addr->ip;
    case S5CAT_DOMAIN_NAME:
        return NamePort{addr->domain.name, addr->domain.port};
    }
    return {};
}

static ClientListener::InitResult convert_socks5_listener_start_result(Socks5ListenerStartResult r) {
    switch (r) {
    case SOCKS5L_START_SUCCESS:
        return ClientListener::InitResult::SUCCESS;
    case SOCKS5L_START_ADDR_IN_USE:
        return ClientListener::InitResult::ADDR_IN_USE;
    case SOCKS5L_START_FAILURE:
        break;
    }
    return ClientListener::InitResult::FAILURE;
}

void SocksListener::socks_handler(void *arg, Socks5ListenerEvent what, void *data) {
    auto *client = (SocksListener *) arg;

    switch (what) {
    case SOCKS5L_EVENT_GENERATE_CONN_ID: {
        size_t id = client->vpn->listener_conn_id_generator.get();
        memcpy(data, &id, sizeof(id));
        break;
    }
    case SOCKS5L_EVENT_CONNECT_REQUEST: {
        const Socks5ConnectRequestEvent *socks_event = (Socks5ConnectRequestEvent *) data;

        TunnelAddress dst = socks_to_client_address(socks_event->dst);
        ClientConnectRequest event = {socks_event->id, socks_event->proto, socks_event->src, &dst};
        event.app_name = socks_event->app_name;
        client->handler.func(client->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);

        break;
    }
    case SOCKS5L_EVENT_CONNECTION_ACCEPTED: {
        client->handler.func(client->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, data);
        break;
    }
    case SOCKS5L_EVENT_READ: {
        auto *socks_event = (Socks5ReadEvent *) data;

        ClientRead event = {socks_event->id, socks_event->data, socks_event->length, 0};
        client->handler.func(client->handler.arg, CLIENT_EVENT_READ, &event);
        socks_event->result = event.result;

        break;
    }
    case SOCKS5L_EVENT_DATA_SENT: {
        const Socks5DataSentEvent *socks_event = (Socks5DataSentEvent *) data;

        ClientDataSentEvent event = {socks_event->id, socks_event->length};
        client->handler.func(client->handler.arg, CLIENT_EVENT_DATA_SENT, &event);

        break;
    }
    case SOCKS5L_EVENT_CONNECTION_CLOSED: {
        auto *socks_event = (Socks5ConnectionClosedEvent *) data;

        client->handler.func(client->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &socks_event->id);

        break;
    }
    case SOCKS5L_EVENT_PROTECT_SOCKET: {
        vpn_client::Handler *vpn_handler = &client->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
    }
}

static VpnSocksListenerConfig clone_config(const VpnSocksListenerConfig *config) {
    return VpnSocksListenerConfig{
            .listen_address = config->listen_address,
            .username = safe_strdup(config->username),
            .password = safe_strdup(config->password),
    };
}

static void destroy_cloned_config(VpnSocksListenerConfig *config) {
    free((void *) config->username);
    free((void *) config->password);
    *config = {};
}

SocksListener::SocksListener(const VpnSocksListenerConfig *config)
        : m_config(clone_config(config)) {
}

SocksListener::~SocksListener() {
    destroy_cloned_config(&m_config);
}

const sockaddr_storage &SocksListener::get_listen_address() const {
    return *socks5_listener_listen_address(m_socks5_listener);
}

ClientListener::InitResult SocksListener::init(VpnClient *vpn, ClientHandler handler) {
    if (auto result = this->ClientListener::init(vpn, handler); result != InitResult::SUCCESS) {
        return result;
    }

    Socks5ListenerConfig socks5_config = {
            .ev_loop = vpn->parameters.ev_loop,
            .listen_address = m_config.listen_address,
            .timeout = Millis{vpn->listener_config.timeout_ms},
            .socket_manager = vpn->parameters.network_manager->socket,
            .read_threshold = 0,
            .username = safe_to_string_view(m_config.username),
            .password = safe_to_string_view(m_config.password),
    };

    if (this->vpn->tmp_files_base_path.has_value()) {
        socks5_config.read_threshold = this->vpn->conn_memory_buffer_threshold;
    }

    Socks5ListenerHnadler event_handler = {socks_handler, this};
    m_socks5_listener = socks5_listener_create(&socks5_config, &event_handler);
    if (m_socks5_listener == nullptr) {
        errlog(m_log, "Failed to create SOCKS listener");
        this->deinit();
        return InitResult::FAILURE;
    }

    if (Socks5ListenerStartResult result = socks5_listener_start(m_socks5_listener); result != SOCKS5L_START_SUCCESS) {
        errlog(m_log, "Failed to start SOCKS listener");
        this->deinit();
        return convert_socks5_listener_start_result(result);
    }

    vpn->socks_listener_address = *socks5_listener_listen_address(m_socks5_listener);

    return InitResult::SUCCESS;
}

void SocksListener::deinit() {
    if (m_socks5_listener != nullptr) {
        socks5_listener_stop(m_socks5_listener);
        socks5_listener_destroy(load_and_null(m_socks5_listener));
    }

    m_deferred_tasks.clear();
}

void SocksListener::complete_connect_request(uint64_t id, ClientConnectResult result) {
    socks5_listener_complete_connect_request(m_socks5_listener, id, TUNNEL_TO_SOCKS_CONNECT_RESULT[result]);
}

void SocksListener::close_connection(uint64_t id, bool graceful, bool async) {
    if (!async) {
        socks5_listener_close_connection(m_socks5_listener, id, graceful);
    } else {
        struct CloseCtx {
            SocksListener *listener;
            uint64_t id;
            bool graceful;
        };

        m_deferred_tasks.emplace(event_loop::submit(vpn->parameters.ev_loop,
                {
                        new CloseCtx{this, id, graceful},
                        [](void *arg, TaskId task_id) {
                            auto *ctx = (CloseCtx *) arg;
                            ctx->listener->m_deferred_tasks.erase(event_loop::make_auto_id(task_id));
                            socks5_listener_close_connection(ctx->listener->m_socks5_listener, ctx->id, ctx->graceful);
                        },
                        [](void *arg) {
                            delete (CloseCtx *) arg;
                        },
                }));
    }
}

ssize_t SocksListener::send(uint64_t id, const uint8_t *data, size_t length) {
    int r = socks5_listener_send_data(m_socks5_listener, id, data, length);
    if (r == 0) {
        r = (int) length;
    }
    return r;
}

void SocksListener::consume(uint64_t id, size_t n) {
    // do nothing
}

TcpFlowCtrlInfo SocksListener::flow_control_info(uint64_t id) {
    return socks5_listener_flow_ctrl_info(m_socks5_listener, id);
}

void SocksListener::turn_read(uint64_t id, bool on) {
    socks5_listener_turn_read(m_socks5_listener, id, on);
}

} // namespace ag
