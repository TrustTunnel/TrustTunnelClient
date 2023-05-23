#include <algorithm>
#include <cassert>

#include "common/utils.h"
#include "memory_buffer.h"
#include "net/dns_utils.h"
#include "plain_dns_manager.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/wire_utils.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

#define log_manager(mngr_, lvl_, fmt_, ...) lvl_##log((mngr_)->m_log, "[{}] " fmt_, (mngr_)->id, ##__VA_ARGS__)
#define log_us_conn(mngr_, cid_, lvl_, fmt_, ...)                                                                      \
    lvl_##log((mngr_)->m_log, "[{}] [L:{}] " fmt_, (mngr_)->id, cid_, ##__VA_ARGS__)
#define log_cs_conn(mngr_, cid_, lvl_, fmt_, ...)                                                                      \
    lvl_##log((mngr_)->m_log, "[{}] [R:{}] " fmt_, (mngr_)->id, cid_, ##__VA_ARGS__)

struct ag::PlainDnsManager::ClientSideConnection {
    using UpstreamSideConnections =
            std::array<std::optional<uint64_t>, magic_enum::enum_count<PlainDnsMessageHandler::RoutingPolicy>()>;

    utils::TransportProtocol protocol;
    UpstreamSideConnections upstream_side_conns;
    bool library_request = false;
    VpnConnectAction connect_action = VPN_CA_DEFAULT;
    TcpFlowCtrlInfo flow_control_info = {};
    TunnelAddressPair original_addr;
    std::string app_name;

    ClientSideConnection() = delete;
    ClientSideConnection(const ClientSideConnection &) = delete;
    ClientSideConnection &operator=(const ClientSideConnection &) = delete;
    ClientSideConnection(ClientSideConnection &&) = default;
    ClientSideConnection &operator=(ClientSideConnection &&) = default;
    virtual ~ClientSideConnection() = default;

    [[nodiscard]] static std::unique_ptr<ClientSideConnection> make(
            utils::TransportProtocol protocol, TunnelAddressPair original_addr, std::string app_name);

    [[nodiscard]] constexpr int get_ipproto() const {
        switch (this->protocol) {
        case utils::TP_UDP:
            return IPPROTO_UDP;
        case utils::TP_TCP:
            return IPPROTO_TCP;
        }
    }

protected:
    ClientSideConnection(utils::TransportProtocol protocol, TunnelAddressPair original_addr, std::string app_name)
            : protocol(protocol)
            , original_addr(std::move(original_addr))
            , app_name(std::move(app_name)) {
    }
};

struct ag::PlainDnsManager::UdpClientSideConnection : public ClientSideConnection {
    size_t query_counter = 0;

private:
    friend struct ClientSideConnection;
    UdpClientSideConnection(TunnelAddressPair original_addr, std::string app_name)
            : ClientSideConnection(utils::TP_UDP, std::move(original_addr), std::move(app_name)) {
    }
};

struct ag::PlainDnsManager::TcpClientSideConnection : public ClientSideConnection {
    std::unique_ptr<ag::DataBuffer> packet_buffer = std::make_unique<MemoryBuffer>();

private:
    friend struct ClientSideConnection;
    TcpClientSideConnection(TunnelAddressPair original_addr, std::string app_name)
            : ClientSideConnection(utils::TP_TCP, std::move(original_addr), std::move(app_name)) {
    }
};

std::unique_ptr<ag::PlainDnsManager::ClientSideConnection> ag::PlainDnsManager::ClientSideConnection::make(
        utils::TransportProtocol protocol, TunnelAddressPair original_addr, std::string app_name) {
    switch (protocol) {
    case utils::TP_UDP:
        return std::unique_ptr<UdpClientSideConnection>(
                new UdpClientSideConnection(std::move(original_addr), std::move(app_name)));
    case utils::TP_TCP:
        return std::unique_ptr<TcpClientSideConnection>(
                new TcpClientSideConnection(std::move(original_addr), std::move(app_name)));
    }
}

struct ag::PlainDnsManager::UpstreamSideConnection {
    enum State {
        S_CONNECTING,
        S_CONNECTED,
        S_DROPPING,
    };

    State state = S_CONNECTING;
    PlainDnsMessageHandler::RoutingPolicy routing_policy = PlainDnsMessageHandler::RP_DEFAULT;
    uint64_t client_side_conn_id = NON_ID;
    bool readable = false;
    std::unique_ptr<DataBuffer> packet_buffer = std::make_unique<MemoryBuffer>();
    size_t unconsumed = 0;
};

ag::PlainDnsClientSideAdapter::PlainDnsClientSideAdapter(int id)
        : ServerUpstream(id) {
}

ag::PlainDnsClientSideAdapter::~PlainDnsClientSideAdapter() = default;

void ag::PlainDnsClientSideAdapter::close_connection(uint64_t conn_id, bool graceful, bool async) {
    close_client_side_connection(conn_id, graceful, async);
}

ssize_t ag::PlainDnsClientSideAdapter::send(uint64_t conn_id, const uint8_t *data, size_t length) {
    return send_outgoing_packet(conn_id, data, length);
}

void ag::PlainDnsClientSideAdapter::consume(uint64_t conn_id, size_t length) {
    consume_outgoing_flow(conn_id, length);
}

ag::VpnError ag::PlainDnsClientSideAdapter::do_health_check() {
    assert(0);
    return {-1, "Must not be called"};
}

ag::VpnConnectionStats ag::PlainDnsClientSideAdapter::get_connection_stats() const {
    assert(0);
    return {};
}

void ag::PlainDnsClientSideAdapter::on_icmp_request(ag::IcmpEchoRequestEvent &) {
    assert(0);
}

ag::PlainDnsServerSideAdapter::PlainDnsServerSideAdapter() = default;

ag::PlainDnsServerSideAdapter::~PlainDnsServerSideAdapter() = default;

void ag::PlainDnsServerSideAdapter::close_connection(uint64_t conn_id, bool graceful, bool async) {
    close_upstream_side_connection(conn_id, graceful, async);
}

ssize_t ag::PlainDnsServerSideAdapter::send(uint64_t conn_id, const uint8_t *data, size_t length) {
    return send_incoming_packet(conn_id, data, length);
}

void ag::PlainDnsServerSideAdapter::consume(uint64_t conn_id, size_t n) {
    consume_incoming_flow(conn_id, n);
}

ag::PlainDnsManager::PlainDnsManager(int upstream_id)
        : PlainDnsClientSideAdapter(upstream_id) {
}

ag::PlainDnsManager::~PlainDnsManager() = default;

std::optional<ag::PlainDnsMessageHandler::RoutingPolicy> ag::PlainDnsManager::get_routing_policy(
        uint64_t us_conn_id) const {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return std::nullopt;
    }

    return us_conn_iter->second->routing_policy;
}

void ag::PlainDnsManager::notify_library_request(uint64_t cs_conn_id) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return;
    }

    cs_conn_iter->second->library_request = true;
}

bool ag::PlainDnsManager::is_library_request(uint64_t us_conn_id) const {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return false;
    }

    uint64_t cs_conn_id = us_conn_iter->second->client_side_conn_id;
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return false;
    }

    return cs_conn_iter->second->library_request;
}

void ag::PlainDnsManager::notify_connect_action(uint64_t cs_conn_id, VpnConnectAction action) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return;
    }

    cs_conn_iter->second->connect_action = action;
}

bool ag::PlainDnsManager::init(VpnClient *vpn, ClientHandler upstream_side_handler, ServerHandler client_side_handler,
        const VpnDnsResolver *dns_resolver) {
    if (ClientListener::InitResult::SUCCESS != this->PlainDnsServerSideAdapter::init(vpn, upstream_side_handler)
            || !this->PlainDnsClientSideAdapter::init(vpn, client_side_handler)) {
        return false;
    }

    m_message_handler.init({
            .vpn = vpn,
            .dns_resolver = dns_resolver,
    });

    on_dns_updated(this);

    if (!m_system_dns_servers.empty() && m_system_dns_proxy == nullptr) {
        this->deinit();
        return false;
    }

    m_dns_change_subscription_id = dns_manager_subscribe_servers_change(
            vpn->parameters.network_manager->dns, vpn->parameters.ev_loop, on_dns_updated, this);
    if (!m_dns_change_subscription_id.has_value()) {
        log_manager(this, warn, "Failed to subscribe to DNS servers updates");
        this->deinit();
        return false;
    }

    return true;
}

bool ag::PlainDnsManager::init(VpnClient *vpn, ServerHandler handler) {
    return this->ServerUpstream::init(vpn, handler);
}

ag::ClientListener::InitResult ag::PlainDnsManager::init(VpnClient *vpn, ClientHandler handler) {
    return PlainDnsServerSideAdapter::init(vpn, handler);
}

void ag::PlainDnsManager::deinit() {
    if (std::optional dns_change_id = std::exchange(m_dns_change_subscription_id, std::nullopt);
            dns_change_id.has_value()) {
        dns_manager_unsubscribe_servers_change(
                this->ag::ServerUpstream::vpn->parameters.network_manager->dns, dns_change_id.value());
    }

    if (m_system_dns_proxy != nullptr) {
        m_system_dns_proxy->stop();
        m_system_dns_proxy.reset();
    }

    m_system_dns_servers.clear();
}

bool ag::PlainDnsManager::open_session(std::optional<Millis>) {
    this->ServerUpstream::handler.func(this->ServerUpstream::handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    return true;
}

void ag::PlainDnsManager::close_session() {
    log_manager(this, dbg, "...");

    while (!m_upstream_side_connections.empty()) {
        close_upstream_side_connection(m_upstream_side_connections.begin()->first, false, false);
    }

    log_manager(this, dbg, "Done");
}

uint64_t ag::PlainDnsManager::open_connection(const ag::TunnelAddressPair *addr, int proto, std::string_view app_name) {
    uint64_t conn_id = this->ServerUpstream::vpn->upstream_conn_id_generator.get();
    m_opening_connections.insert(conn_id);
    m_client_side_connections.emplace(conn_id,
            ClientSideConnection::make(ag::ipproto_to_transport_protocol(proto).value(), *addr, std::string(app_name)));
    if (!m_async_task.has_value()) {
        m_async_task = event_loop::submit(this->ServerUpstream::vpn->parameters.ev_loop, {this, on_async_task});
    }

    return conn_id;
}

void ag::PlainDnsManager::close_client_side_connection(uint64_t cs_conn_id, bool, bool async) {
    if (async) {
        m_closing_client_side_connections.insert(cs_conn_id);
        if (!m_async_task.has_value()) {
            m_async_task = event_loop::submit(this->ServerUpstream::vpn->parameters.ev_loop, {this, on_async_task});
        }
        return;
    }

    if (auto node = m_client_side_connections.extract(cs_conn_id); !node.empty()) {
        this->close_connection_sync(cs_conn_id, *node.mapped(), false);
    }
}

ssize_t ag::PlainDnsManager::send_outgoing_packet(uint64_t cs_conn_id, const uint8_t *data, size_t length) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return -1;
    }

    ClientSideConnection &cs_conn = *cs_conn_iter->second;
    switch (cs_conn.protocol) {
    case utils::TP_UDP: {
        ++((UdpClientSideConnection &) cs_conn).query_counter;
        Uint8View message = {data, length};
        return this->send_outgoing_query(cs_conn_id, cs_conn, m_message_handler.on_outgoing_message(message), message);
    }
    case utils::TP_TCP:
        return this->send_outgoing_tcp_packet(cs_conn_id, cs_conn, {data, length});
    }
}

void ag::PlainDnsManager::consume_outgoing_flow(uint64_t cs_conn_id, size_t length) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return;
    }

    ClientSideConnection &cs_conn = *cs_conn_iter->second;

    for (std::optional<uint64_t> us_conn_id : cs_conn.upstream_side_conns) {
        if (!us_conn_id.has_value()) {
            continue;
        }

        auto us_conn_iter = m_upstream_side_connections.find(us_conn_id.value());
        if (us_conn_iter == m_upstream_side_connections.end()) {
            log_us_conn(this, us_conn_id.value(), dbg, "Not found");
            continue;
        }

        UpstreamSideConnection &us_conn = *us_conn_iter->second;
        size_t to_consume = std::min(length, us_conn.unconsumed);
        us_conn.unconsumed -= to_consume;
        length -= to_consume;

        ClientDataSentEvent event = {
                .id = us_conn_id.value(),
                .length = to_consume,
        };
        this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_DATA_SENT, &event);
        // continue iteration even in case the length drops down to 0 to poll all the connections
    }
}

size_t ag::PlainDnsManager::available_to_send(uint64_t cs_conn_id) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return 0;
    }

    return cs_conn_iter->second->flow_control_info.send_buffer_size;
}

void ag::PlainDnsManager::update_flow_control(uint64_t cs_conn_id, ag::TcpFlowCtrlInfo info) {
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return;
    }

    ClientSideConnection &cs_conn = *cs_conn_iter->second;
    cs_conn.flow_control_info = info;

    if (info.send_buffer_size == 0) {
        return;
    }

    for (std::optional<uint64_t> us_conn_id : cs_conn.upstream_side_conns) {
        if (!us_conn_id.has_value()) {
            continue;
        }

        auto us_conn_iter = m_upstream_side_connections.find(us_conn_id.value());
        if (us_conn_iter == m_upstream_side_connections.end()) {
            log_us_conn(this, us_conn_id.value(), dbg, "Not found");
            continue;
        }

        // just poll the other side, so the tunnel will call for
        // `ClientListener::flow_control_info()` right after that
        ClientDataSentEvent event = {
                .id = us_conn_id.value(),
                .length = 0,
        };
        this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_DATA_SENT, &event);
    }
}

void ag::PlainDnsManager::complete_connect_request(uint64_t us_conn_id, ag::ClientConnectResult result) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        this->close_upstream_side_connection(us_conn_id, false, false);
        return;
    }

    UpstreamSideConnection &us_conn = *us_conn_iter->second;
    if (us_conn.state != UpstreamSideConnection::S_CONNECTING) {
        log_us_conn(this, us_conn_id, dbg, "Unexpected state: {}", magic_enum::enum_name(us_conn.state));
        this->close_upstream_side_connection(us_conn_id, false, false);
        return;
    }

    uint64_t cs_conn_id = us_conn.client_side_conn_id;
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        this->close_upstream_side_connection(us_conn_id, false, false);
        return;
    }

    std::optional<ServerError> error;
    switch (result) {
    case CCR_PASS:
        us_conn.state = UpstreamSideConnection::S_CONNECTED;
        this->ClientListener::handler.func(
                this->ClientListener::handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &us_conn_id);
        this->complete_read(us_conn_id);
        break;
    case CCR_DROP:
        us_conn.state = UpstreamSideConnection::S_DROPPING;
        log_us_conn(this, us_conn_id, dbg, "Switching to dropping state");
        if (us_conn.packet_buffer->size() > 0) {
            log_us_conn(this, us_conn_id, dbg, "Dropping buffered packets: {} bytes", us_conn.packet_buffer->size());
        }
        us_conn.packet_buffer.reset();
        break;
    case CCR_REJECT: {
        ServerError &event = error.emplace();
        event.id = cs_conn_id;
        event.error = {-1, "Upstream rejected connection"};
        break;
    }
    case CCR_UNREACH: {
        ServerError &event = error.emplace();
        event.id = cs_conn_id;
        event.error = {AG_EHOSTUNREACH, ag::sys::strerror(AG_EHOSTUNREACH)};
        break;
    }
    }

    if (error.has_value()) {
        this->ServerUpstream::handler.func(this->ServerUpstream::handler.arg, SERVER_EVENT_ERROR, &error.value());
    }
}

void ag::PlainDnsManager::close_upstream_side_connection(uint64_t us_conn_id, bool, bool async) {
    if (async) {
        m_closing_upstream_side_connections.insert(us_conn_id);
        if (!m_async_task.has_value()) {
            m_async_task = event_loop::submit(this->ServerUpstream::vpn->parameters.ev_loop, {this, on_async_task});
        }
        return;
    }

    if (auto node = m_upstream_side_connections.extract(us_conn_id); !node.empty()) {
        this->close_connection_sync(us_conn_id, *node.mapped(), false);
    } else {
        this->ClientListener::handler.func(
                this->ClientListener::handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &us_conn_id);
    }
}

ssize_t ag::PlainDnsManager::send_incoming_packet(uint64_t us_conn_id, const uint8_t *data, size_t length) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return -1;
    }

    UpstreamSideConnection &us_conn = *us_conn_iter->second;
    uint64_t cs_conn_id = us_conn.client_side_conn_id;
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return -1;
    }

    ClientSideConnection &cs_conn = *cs_conn_iter->second;
    m_message_handler.on_incoming_message({data, length}, cs_conn.library_request);

    if (cs_conn.protocol == utils::TP_UDP) {
        auto &udp_cs_conn = (UdpClientSideConnection &) cs_conn;
        if (udp_cs_conn.query_counter > 0) {
            --udp_cs_conn.query_counter;
        }
    }

    ServerReadEvent event = {
            .id = cs_conn_id,
            .data = data,
            .length = length,
    };
    this->ServerUpstream::handler.func(this->ServerUpstream::handler.arg, SERVER_EVENT_READ, &event);

    if (m_client_side_connections.contains(cs_conn_id) && cs_conn.protocol == utils::TP_UDP
            && ((UdpClientSideConnection &) cs_conn).query_counter == 0) {
        log_cs_conn(this, cs_conn_id, trace, "All queries are completed");
        this->close_client_side_connection(cs_conn_id, false, true);
    }

    return event.result;
}

void ag::PlainDnsManager::consume_incoming_flow(uint64_t us_conn_id, size_t n) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return;
    }

    ServerDataSentEvent event = {
            .id = us_conn_iter->second->client_side_conn_id,
            .length = n,
    };
    this->ServerUpstream::handler.func(this->ServerUpstream::handler.arg, SERVER_EVENT_DATA_SENT, &event);
}

ag::TcpFlowCtrlInfo ag::PlainDnsManager::flow_control_info(uint64_t us_conn_id) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return {};
    }

    const UpstreamSideConnection &us_conn = *us_conn_iter->second;
    uint64_t cs_conn_id = us_conn.client_side_conn_id;
    auto cs_conn_iter = m_client_side_connections.find(cs_conn_id);
    if (cs_conn_iter == m_client_side_connections.end()) {
        log_cs_conn(this, cs_conn_id, dbg, "Not found");
        return {};
    }

    return cs_conn_iter->second->flow_control_info;
}

void ag::PlainDnsManager::turn_read(uint64_t us_conn_id, bool on) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return;
    }

    UpstreamSideConnection &us_conn = *us_conn_iter->second;
    if (us_conn.readable == on) {
        return;
    }

    us_conn.readable = on;
    if (on && !m_async_task.has_value()) {
        m_async_task = event_loop::submit(this->ServerUpstream::vpn->parameters.ev_loop, {this, on_async_task});
    }
}

void ag::PlainDnsManager::on_async_task(void *arg, TaskId) {
    auto *self = (PlainDnsManager *) arg;
    log_manager(self, trace, "...");
    self->m_async_task.release();

    log_manager(self, trace, "Do postponed closes");
    for (uint64_t id : std::exchange(self->m_closing_client_side_connections, {})) {
        self->close_client_side_connection(id, false, false);
    }
    for (uint64_t id : std::exchange(self->m_closing_upstream_side_connections, {})) {
        self->close_upstream_side_connection(id, false, false);
    }
    log_manager(self, trace, "Closes done");

    log_manager(self, trace, "Do postponed openings");
    std::unordered_set<uint64_t> opening;
    std::swap(opening, self->m_opening_connections);
    for (uint64_t id : opening) {
        self->ServerUpstream::handler.func(self->ServerUpstream::handler.arg, SERVER_EVENT_CONNECTION_OPENED, &id);
    }
    log_manager(self, trace, "Openings done");

    log_manager(self, trace, "Read pending connections");
    std::vector<uint64_t> readable;
    for (const auto &[id, conn] : self->m_upstream_side_connections) {
        if (conn->state == UpstreamSideConnection::S_CONNECTED && conn->readable && conn->packet_buffer->size() > 0) {
            readable.push_back(id);
        }
    }
    for (uint64_t id : readable) {
        self->complete_read(id);
    }
    log_manager(self, trace, "Reads done");

    log_manager(self, trace, "Done");
}

void ag::PlainDnsManager::on_dns_updated(void *arg) {
    auto *self = (PlainDnsManager *) arg;

    static constexpr auto server_address_from_str = [](std::string_view str) {
        auto [host, port] = utils::split_host_port(str).value();
        // Strip scope-id via `SocketAddress`
        return sockaddr_to_storage(
                SocketAddress(host, utils::to_integer<uint16_t>(port).value_or(dns_utils::PLAIN_DNS_PORT_NUMBER))
                        .c_sockaddr());
    };

    SystemDnsServers servers =
            dns_manager_get_system_servers(self->ag::ServerUpstream::vpn->parameters.network_manager->dns);
    self->m_system_dns_servers.clear();
    self->m_system_dns_servers.reserve(servers.main.size() + servers.fallback.size());
    std::transform(servers.main.begin(), servers.main.end(),
            std::inserter(self->m_system_dns_servers, self->m_system_dns_servers.begin()), [](SystemDnsServer &s) {
                if (s.resolved_host.has_value()) {
                    return sockaddr_to_storage(s.resolved_host->c_sockaddr());
                }
                return server_address_from_str(s.address);
            });
    std::transform(servers.fallback.begin(), servers.fallback.end(),
            std::inserter(self->m_system_dns_servers, self->m_system_dns_servers.begin()), [](const std::string &s) {
                return server_address_from_str(s);
            });
    for (sockaddr_storage &a : self->m_system_dns_servers) {
        if (0 == sockaddr_get_port((sockaddr *) &a)) {
            sockaddr_set_port((sockaddr *) &a, dns_utils::PLAIN_DNS_PORT_NUMBER);
        }
    }

    if (self->m_system_dns_proxy != nullptr) {
        self->m_system_dns_proxy->stop();
        self->m_system_dns_proxy.reset();
    }

    if (!self->start_dns_proxy(std::move(servers))) {
        log_manager(self, err, "Failed to start DNS proxy");
    }
}

void ag::PlainDnsManager::complete_read(uint64_t us_conn_id) {
    auto us_conn_iter = m_upstream_side_connections.find(us_conn_id);
    if (us_conn_iter == m_upstream_side_connections.end()) {
        log_us_conn(this, us_conn_id, dbg, "Not found");
        return;
    }

    UpstreamSideConnection &us_conn = *us_conn_iter->second;
    if (us_conn.state != UpstreamSideConnection::S_CONNECTED) {
        return;
    }

    while (m_upstream_side_connections.contains(us_conn_id) && us_conn.readable && us_conn.packet_buffer->size() > 0) {
        BufferPeekResult result = us_conn.packet_buffer->peek();
        ClientRead event = {
                .id = us_conn_id,
                .data = result.data.data(),
                .length = result.data.length(),
        };
        this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_READ, &event);
        if (event.result < 0) {
            close_upstream_side_connection(us_conn_id, false, false);
            break;
        }
        if (event.result == 0) {
            us_conn.readable = false;
            break;
        }
        us_conn.packet_buffer->drain(event.result);
    }
}

void ag::PlainDnsManager::close_connection_sync( // NOLINT(misc-no-recursion)
        uint64_t cs_conn_id, ClientSideConnection &cs_conn, bool closed_by_opposite) {
    if (!closed_by_opposite) {
        for (std::optional<uint64_t> us_conn_id : cs_conn.upstream_side_conns) {
            if (!us_conn_id.has_value()) {
                continue;
            }
            if (auto node = m_upstream_side_connections.extract(us_conn_id.value()); !node.empty()) {
                this->close_connection_sync(us_conn_id.value(), *node.mapped(), true);
            }
        }
    }

    this->ServerUpstream::handler.func(this->ServerUpstream::handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &cs_conn_id);
}

void ag::PlainDnsManager::close_connection_sync( // NOLINT(misc-no-recursion)
        uint64_t us_conn_id, UpstreamSideConnection &us_conn, bool closed_by_opposite) {
    if (!closed_by_opposite) {
        if (auto cs_conn_iter = m_client_side_connections.find(us_conn.client_side_conn_id);
                cs_conn_iter != m_client_side_connections.end()) {
            ClientSideConnection &cs_conn = *cs_conn_iter->second;
            assert(us_conn_id == cs_conn.upstream_side_conns[us_conn.routing_policy]);
            cs_conn.upstream_side_conns[us_conn.routing_policy].reset();
            if (std::all_of(cs_conn.upstream_side_conns.begin(), cs_conn.upstream_side_conns.end(),
                        [](std::optional<uint64_t> x) {
                            return !x.has_value();
                        })) {
                this->close_connection_sync(us_conn.client_side_conn_id,
                        *m_client_side_connections.extract(us_conn.client_side_conn_id).mapped(), true);
            }
        }
    }

    this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &us_conn_id);
}

ssize_t ag::PlainDnsManager::send_outgoing_tcp_packet(
        uint64_t cs_conn_id, ClientSideConnection &cs_conn, Uint8View data) {
    auto &tcp_cs_conn = (TcpClientSideConnection &) cs_conn;

    size_t orig_data_length = data.length();
    std::vector<uint8_t> rebuilt_packet;
    if (tcp_cs_conn.packet_buffer->size() > 0) {
        rebuilt_packet.reserve(tcp_cs_conn.packet_buffer->size() + data.size());
        while (tcp_cs_conn.packet_buffer->size() > 0) {
            auto [_, chunk] = tcp_cs_conn.packet_buffer->peek();
            rebuilt_packet.insert(rebuilt_packet.end(), chunk.begin(), chunk.end());
            tcp_cs_conn.packet_buffer->drain(chunk.size());
        }
    }
    if (!rebuilt_packet.empty()) {
        rebuilt_packet.insert(rebuilt_packet.end(), data.begin(), data.end());
        data = {rebuilt_packet.data(), rebuilt_packet.size()};
    }

    wire_utils::Reader reader(data);
    while (!reader.get_buffer().empty()) {
        const uint8_t *packet_start = reader.get_buffer().data();

        std::optional<uint16_t> query_length = reader.get_u16();
        if (!query_length.has_value()) {
            tcp_cs_conn.packet_buffer->push(reader.get_buffer());
            break;
        }
        std::optional<U8View> query = reader.get_bytes(query_length.value());
        if (!query.has_value()) {
            tcp_cs_conn.packet_buffer->push(
                    {packet_start, sizeof(query_length.value()) + reader.get_buffer().length()});
            break;
        }

        PlainDnsMessageHandler::RoutingPolicy routing_policy = m_message_handler.on_outgoing_message(query.value());
        ssize_t r = this->send_outgoing_query(cs_conn_id, cs_conn, routing_policy,
                {packet_start, sizeof(query_length.value()) + query_length.value()});
        if (r < 0) {
            return r;
        }
    }

    return ssize_t(orig_data_length);
}

ssize_t ag::PlainDnsManager::send_outgoing_query(uint64_t cs_conn_id, ClientSideConnection &cs_conn,
        PlainDnsMessageHandler::RoutingPolicy routing_policy, Uint8View data) {
    log_cs_conn(this, cs_conn_id, dbg, "Routing policy: {}", magic_enum::enum_name(routing_policy));

    if (routing_policy == PlainDnsMessageHandler::RP_DROP) {
        log_cs_conn(this, cs_conn_id, dbg, "Drop due to policy");
        return ssize_t(data.length());
    }

    if (!cs_conn.library_request && cs_conn.connect_action != VPN_CA_DEFAULT) {
        // Queries on forcibly routed connections also get here.
        // In this case, the routing policy must be overwritten if it does not
        // already conform to the logic.
        PlainDnsMessageHandler::RoutingPolicy overwrite_policy = PlainDnsMessageHandler::vpn_action_to_routing_policy(
                this->ag::ClientListener::vpn->domain_filter.get_mode(), cs_conn.connect_action);
        if (overwrite_policy != routing_policy) {
            routing_policy = overwrite_policy;
            log_cs_conn(this, cs_conn_id, dbg, "Overwriting routing policy for query on forcibly routed connection: {}",
                    magic_enum::enum_name(routing_policy));
        }
    }

    if (std::optional us_conn_id = cs_conn.upstream_side_conns[routing_policy];
            !us_conn_id.has_value() || !m_upstream_side_connections.contains(us_conn_id.value())) {
        TunnelAddress dst;
        if (std::optional redirect_addr = get_redirect_address(cs_conn_id, cs_conn, routing_policy);
                redirect_addr.has_value()) {
            log_cs_conn(this, cs_conn_id, dbg, "Redirecting connection to {}",
                    sockaddr_to_str((sockaddr *) &redirect_addr.value()));
            dst.emplace<sockaddr_storage>(redirect_addr.value());
        } else {
            dst = cs_conn.original_addr.dst;
        }

        ClientConnectRequest request = {
                .id = this->ag::ClientListener::vpn->listener_conn_id_generator.get(),
                .protocol = cs_conn.get_ipproto(),
                .src = (sockaddr *) &cs_conn.original_addr.src,
                .dst = &dst,
                .app_name = cs_conn.app_name,
        };

        m_upstream_side_connections.emplace(request.id,
                new UpstreamSideConnection{
                        .routing_policy = routing_policy,
                        .client_side_conn_id = cs_conn_id,
                });
        cs_conn.upstream_side_conns[routing_policy] = request.id;

        this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &request);

        // the tunnel could have closed it immediately
        if (!m_upstream_side_connections.contains(request.id)) {
            return -1;
        }
    }

    uint64_t us_conn_id =
            cs_conn.upstream_side_conns[routing_policy].value(); // NOLINT(bugprone-unchecked-optional-access)
    UpstreamSideConnection &us_conn = *m_upstream_side_connections[us_conn_id];
    switch (us_conn.state) {
    case UpstreamSideConnection::S_CONNECTING: {
        us_conn.packet_buffer->push(data);
        return ssize_t(data.length());
    }
    case UpstreamSideConnection::S_CONNECTED: {
        if (us_conn.packet_buffer->size() > 0) {
            us_conn.packet_buffer->push(data);
            return ssize_t(data.length());
        }

        ClientRead event = {
                .id = us_conn_id,
                .data = data.data(),
                .length = data.length(),
        };
        this->ClientListener::handler.func(this->ClientListener::handler.arg, CLIENT_EVENT_READ, &event);

        if (cs_conn.protocol == utils::TP_TCP && event.result >= 0 && size_t(event.result) < data.length()) {
            data.remove_prefix(event.result);
            us_conn.packet_buffer->push(data);
        }

        return event.result;
    }
    case UpstreamSideConnection::S_DROPPING: {
        log_us_conn(this, us_conn_id, dbg, "Dropping due to state");
        return ssize_t(data.length());
    }
    }
}

bool ag::PlainDnsManager::start_dns_proxy(SystemDnsServers servers) {
    log_manager(this, dbg, "{}", servers);

    std::vector<DnsProxyAccessor::Upstream> upstreams;
    upstreams.reserve(servers.main.size());
    std::transform(servers.main.begin(), servers.main.end(), std::back_inserter(upstreams), [](SystemDnsServer &s) {
        return DnsProxyAccessor::Upstream{
                .address = std::move(s.address),
                .resolved_host = s.resolved_host,
        };
    });

    m_system_dns_proxy = std::make_unique<DnsProxyAccessor>(DnsProxyAccessor::Parameters{
            .upstreams = std::move(upstreams),
            .fallbacks = std::move(servers.fallback),
            .cert_verify_handler = this->ag::ServerUpstream::vpn->parameters.cert_verify_handler,
    });

    return m_system_dns_proxy->start();
}

std::optional<sockaddr_storage> ag::PlainDnsManager::get_redirect_address(uint64_t cs_conn_id,
        const ClientSideConnection &cs_conn, PlainDnsMessageHandler::RoutingPolicy routing_policy) const {
    const auto *dst = std::get_if<sockaddr_storage>(&cs_conn.original_addr.dst);
    if (dst == nullptr) {
        return std::nullopt;
    }

    bool routed_directly = false;
    switch (this->ag::ServerUpstream::vpn->domain_filter.get_mode()) {
    case VPN_MODE_GENERAL:
        routed_directly = routing_policy == PlainDnsMessageHandler::RP_EXCEPTIONAL
                || routing_policy == PlainDnsMessageHandler::RP_FORCE_BYPASS;
        break;
    case VPN_MODE_SELECTIVE:
        routed_directly = routing_policy == PlainDnsMessageHandler::RP_DEFAULT
                || routing_policy == PlainDnsMessageHandler::RP_FORCE_BYPASS;
        break;
    }

    constexpr auto contains_address = [](const std::vector<sockaddr_storage> &v, const sockaddr *a) {
        return v.end() != std::find_if(v.begin(), v.end(), [&](const sockaddr_storage &i) {
            return sockaddr_equals(a, (sockaddr *) &i);
        });
    };

    if (routed_directly && m_system_dns_proxy != nullptr) {
        log_cs_conn(this, cs_conn_id, dbg, "Redirecting query targeted default server to system DNS proxy");
        return m_system_dns_proxy->get_listen_address(cs_conn.protocol);
    }

    if (!routed_directly && routing_policy != PlainDnsMessageHandler::RP_THROUGH_DNS_PROXY
            && contains_address(m_system_dns_servers, (sockaddr *) dst)) {
        log_cs_conn(this, cs_conn_id, dbg, "Redirecting query routed through VPN endpoint to public DNS resolver");

        constexpr auto make_redirect_addr = [](const char *str) {
            sockaddr_storage a = sockaddr_from_str(str);
            sockaddr_set_port((sockaddr *) &a, dns_utils::PLAIN_DNS_PORT_NUMBER);
            return a;
        };
        static const sockaddr_storage IPV4_REDIRECT_ADDR = make_redirect_addr(AG_UNFILTERED_DNS_IPS_V4[0].data());
        static const sockaddr_storage IPV6_REDIRECT_ADDR = make_redirect_addr(AG_UNFILTERED_DNS_IPS_V6[0].data());

        return (dst->ss_family == AF_INET) ? IPV4_REDIRECT_ADDR : IPV6_REDIRECT_ADDR;
    }

    return std::nullopt;
}
