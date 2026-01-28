#include "dns_handler.h"

#include <algorithm>
#include <chrono>
#include <cassert>
#include <tuple>
#include <utility>

#include "common/logger.h"
#include "common/utils.h"
#include "net/dns_utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/wire_utils.h"
#include "vpn/utils.h"

static ag::Logger g_logger{"DNS_HANDLER"};

static constexpr auto DNS_CLIENT_TIMEOUT = ag::Secs{30};
static constexpr size_t CONN_MAX_BUFFERED = 128 * 1024;
static constexpr size_t MAX_UDP_QUEUE_SIZE = 10;
static constexpr size_t USER_DNS_FAILURE_RESTART_THRESHOLD = 3;
static constexpr auto USER_DNS_RESTART_MIN_INTERVAL = ag::Secs{30};

#define log_upstream(ups_, lvl_, fmt_, ...) lvl_##log(g_logger, "[upstream] " fmt_, ##__VA_ARGS__)
#define log_listener(ups_, lvl_, fmt_, ...) lvl_##log(g_logger, "[listener] " fmt_, ##__VA_ARGS__)
#define log_handler(ups_, lvl_, fmt_, ...) lvl_##log(g_logger, fmt_, ##__VA_ARGS__)

#ifdef NDEBUG
#define assert_use(x) ((void) (x))
#else
#define assert_use(x) assert(x)
#endif

struct ag::DnsHandlerServerUpstreamBase::ConnectionInfo {
    uint64_t upstream_conn_id;
    int proto;
    const TunnelAddressPair *addrs;
    std::string_view app_name;

    friend std::string format_as(const ConnectionInfo &info) {
        return AG_FMT("[R:{}] {} -> {} proto: {} app: {}", info.upstream_conn_id, info.addrs->src,
                tunnel_addr_to_str(&info.addrs->dst), info.proto, info.app_name);
    }
};

static void write_dns_message_to(std::vector<uint8_t> &out, ag::U8View message) {
    uint16_t size = message.size();
    size = htons(size);
    out.insert(out.end(), (uint8_t *) &size, (uint8_t *) &size + sizeof(size));
    out.insert(out.end(), message.data(), message.data() + ntohs(size));
}

void ag::DnsHandlerServerUpstreamBase::notify_vpn_resolver_connection(uint64_t upstream_conn_id) {
    auto it = m_connections.find(upstream_conn_id);
    if (it == m_connections.end()) {
        log_upstream(this, warn, "Connection R:{} does not exist", upstream_conn_id);
        return;
    }
    it->second.vpn_resolver_connection = true;
}

bool ag::DnsHandlerServerUpstreamBase::is_vpn_resolver_connection(uint64_t upstream_conn_id) {
    auto it = m_connections.find(upstream_conn_id);
    if (it == m_connections.end()) {
        log_upstream(this, warn, "Connection R:{} does not exist", upstream_conn_id);
        return false;
    }
    return it->second.vpn_resolver_connection;
}

ag::DnsHandlerServerUpstreamBase::DnsHandlerServerUpstreamBase(int id)
        : ServerUpstream(id) {
}

ag::DnsHandlerServerUpstreamBase::~DnsHandlerServerUpstreamBase() = default;

void ag::DnsHandlerServerUpstreamBase::deinit() {
}

void ag::DnsHandlerServerUpstreamBase::send_response(uint64_t upstream_conn_id, U8View message) {
    auto it = m_connections.find(upstream_conn_id);
    if (it == m_connections.end()) {
        log_upstream(this, dbg, "Connection R:{} does not exist", upstream_conn_id);
        return;
    }
    if (it->second.proto == IPPROTO_UDP) {
        if (it->second.read_enabled) {
            ServerReadEvent event{
                    .id = upstream_conn_id,
                    .data = message.data(),
                    .length = message.length(),
            };
            this->handler.func(this->handler.arg, SERVER_EVENT_READ, &event);
            if (event.result <= 0) {
                it = m_connections.find(upstream_conn_id);
                if (it == m_connections.end()) {
                    log_upstream(this, info, "Failed to send UDP: handler returned {}, connection R:{} is gone",
                            event.result, upstream_conn_id);
                } else {
                    log_upstream(this, info, "Failed to send UDP {} ({}) <- {}: handler returned {}",
                            it->second.addrs.src, it->second.app_name, tunnel_addr_to_str(&it->second.addrs.dst),
                            event.result);
                }
            } else {
                it = m_connections.find(upstream_conn_id);
                if (it != m_connections.end()) {
                    auto &conn = it->second;
                    if (--conn.unanswered_dns_requests == 0) {
                        log_upstream(this, dbg,
                                "[R:{}] All DNS requests answered for connection {} -> {} proto: {} app: {}",
                                upstream_conn_id, conn.addrs.src, tunnel_addr_to_str(&conn.addrs.dst), conn.proto,
                                conn.app_name);
                        close_connection(upstream_conn_id, /*graceful*/ false, /*async*/ false);
                    }
                }
            }
        } else {
            log_upstream(this, info, "Failed to send UDP {} ({}) <- {}: read disabled", it->second.addrs.src,
                    it->second.app_name, tunnel_addr_to_str(&it->second.addrs.dst));
        }
    } else {
        write_dns_message_to(it->second.rcv_buf, message);
        if (!raise_read(it->second)) {
            close_connection(upstream_conn_id, /*graceful*/ false, /*async*/ false);
        }
    }
}

bool ag::DnsHandlerServerUpstreamBase::open_session(std::optional<Millis> /*timeout*/) {
    return true;
}

void ag::DnsHandlerServerUpstreamBase::close_session() {
}

uint64_t ag::DnsHandlerServerUpstreamBase::open_connection(
        const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    if (addr->dstport() != dns_utils::PLAIN_DNS_PORT_NUMBER) {
        assert(0);
        return NON_ID;
    }
    uint64_t id = this->vpn->upstream_conn_id_generator.get();
    auto [it, placed] = m_connections.emplace(std::piecewise_construct, std::forward_as_tuple(id),
            std::forward_as_tuple(id, proto, *addr, std::string(app_name)));
    assert_use(placed);
    m_new_connections.push_back(id);
    if (!m_task.has_value()) {
        m_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
    }
    return it->second.id;
}

void ag::DnsHandlerServerUpstreamBase::close_connection(uint64_t upstream_conn_id, bool /*graceful*/, bool async) {
    if (std::erase_if(m_new_connections, [&](uint64_t id_) {
            return id_ == upstream_conn_id;
        })) {
        return;
    }

    auto it = m_connections.find(upstream_conn_id);
    if (it == m_connections.end()) {
        log_upstream(this, warn, "Connection R:{} does not exist", upstream_conn_id);
        return;
    }

    m_connections.erase(it);

    on_upstream_connection_closed(upstream_conn_id);

    if (!async) {
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &upstream_conn_id);
        return;
    }

    m_closed_connections.push_back(upstream_conn_id);
    if (!m_task.has_value()) {
        m_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
    }
}

ssize_t ag::DnsHandlerServerUpstreamBase::send(uint64_t upstream_conn_id, const uint8_t *data, size_t length) {
    auto it = m_connections.find(upstream_conn_id);
    if (it == m_connections.end()) {
        log_upstream(this, warn, "Connection R:{} does not exist", upstream_conn_id);
        return -1;
    }

    ConnectionInfo info{
            .upstream_conn_id = upstream_conn_id,
            .proto = it->second.proto,
            .addrs = &it->second.addrs,
            .app_name = it->second.app_name,
    };

    if (it->second.proto == IPPROTO_UDP) {
        ++it->second.unanswered_dns_requests;
        on_dns_request(info, {data, length});
        return length; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    }

    it->second.snd_buf.insert(it->second.snd_buf.end(), data, data + length);
    wire_utils::Reader reader{{it->second.snd_buf.begin(), it->second.snd_buf.end()}};
    int read = 0;
    for (;;) {
        auto msg_size = reader.get_u16();
        if (!msg_size.has_value()) {
            break;
        }
        auto msg = reader.get_bytes(*msg_size);
        if (!msg.has_value()) {
            break;
        }
        read += 2 + *msg_size;
        on_dns_request(info, *msg);
    }
    it->second.snd_buf.erase(it->second.snd_buf.begin(), it->second.snd_buf.begin() + read);

    return length; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
}

void ag::DnsHandlerServerUpstreamBase::consume(uint64_t /*upstream_conn_id*/, size_t /*length*/) {
    // No op
}

size_t ag::DnsHandlerServerUpstreamBase::available_to_send(uint64_t /*upstream_conn_id*/) {
    return SIZE_MAX;
}

void ag::DnsHandlerServerUpstreamBase::update_flow_control(uint64_t upstream_conn_id, TcpFlowCtrlInfo info) {
}

void ag::DnsHandlerServerUpstreamBase::do_health_check() {
    assert(0);
}

void ag::DnsHandlerServerUpstreamBase::cancel_health_check() {
    assert(0);
}

ag::VpnConnectionStats ag::DnsHandlerServerUpstreamBase::get_connection_stats() const {
    assert(0);
    return {};
}

void ag::DnsHandlerServerUpstreamBase::on_icmp_request(IcmpEchoRequestEvent & /*event*/) {
    assert(0);
}

ag::DnsHandlerServerUpstreamBase::Connection::Connection(
        uint64_t id, int proto, TunnelAddressPair addrs, std::string app_name)
        : id(id)
        , proto{proto}
        , addrs(std::move(addrs))
        , app_name(std::move(app_name))
        , read_enabled{true}
        , vpn_resolver_connection{false} {
}

void ag::DnsHandlerServerUpstreamBase::on_async_task(void *arg, TaskId /*task_id*/) {
    auto *self = (DnsHandlerServerUpstreamBase *) arg;
    self->m_task.release();

    std::vector<uint64_t> to_open;
    to_open.swap(self->m_new_connections);
    for (uint64_t id : to_open) {
        self->handler.func(self->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &id);
    }

    std::vector<uint64_t> to_close;
    to_close.swap(self->m_closed_connections);
    for (uint64_t id : to_close) {
        self->handler.func(self->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
    }
}

bool ag::DnsHandlerServerUpstreamBase::raise_read(Connection &conn) {
    if (!conn.read_enabled) {
        return true;
    }
    ServerReadEvent event{
            .id = conn.id,
            .data = conn.rcv_buf.data(),
            .length = conn.rcv_buf.size(),
    };
    this->handler.func(this->handler.arg, SERVER_EVENT_READ, &event);
    if (event.result < 0) {
        log_upstream(this, info, "Failed to send TCP data as upstream: handler returned {}", event.result);
        return false;
    }
    assert(size_t(event.result) <= conn.rcv_buf.size());
    conn.rcv_buf.erase(conn.rcv_buf.begin(), conn.rcv_buf.begin() + event.result);
    if (conn.rcv_buf.size() > CONN_MAX_BUFFERED) {
        log_upstream(this, warn, "Receive buffer for connection R:{} (({}) {} -> {}) is getting too long", conn.id,
                conn.app_name, conn.addrs.src, tunnel_addr_to_str(&conn.addrs.dst));
        return false;
    }
    return true;
}

ag::DnsHandlerClientListenerBase::DnsHandlerClientListenerBase() = default;

ag::DnsHandlerClientListenerBase::~DnsHandlerClientListenerBase() = default;

void ag::DnsHandlerClientListenerBase::deinit() {
}

uint64_t ag::DnsHandlerClientListenerBase::send_as_listener(
        const DnsHandlerServerUpstreamBase::ConnectionInfo &info, U8View message) {
    auto id_it = m_conn_id_by_upstream_conn_id.find(info.upstream_conn_id);
    if (id_it == m_conn_id_by_upstream_conn_id.end()) {
        uint64_t listener_conn_id = vpn->listener_conn_id_generator.get();

        auto [new_conn_it, placed] =
                m_connections.emplace(std::piecewise_construct, std::forward_as_tuple(listener_conn_id),
                        std::forward_as_tuple(listener_conn_id, info.upstream_conn_id, info.proto));
        assert_use(placed);
        m_conn_id_by_upstream_conn_id.emplace(info.upstream_conn_id, listener_conn_id);

        ClientConnectRequest event{
                .id = listener_conn_id,
                .protocol = info.proto,
                .src = &info.addrs->src,
                .dst = &info.addrs->dst,
        };
        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);

        if (new_conn_it->second.proto == IPPROTO_UDP) {
            new_conn_it->second.udp_pending.emplace_back(message.begin(), message.end());
        } else {
            write_dns_message_to(new_conn_it->second.snd_buf, message);
        }

        return new_conn_it->second.listener_conn_id;
    }

    auto it = m_connections.find(id_it->second);
    assert(it != m_connections.end());
    assert(it->second.proto == IPPROTO_UDP || it->second.proto == IPPROTO_TCP);

    if (it->second.proto == IPPROTO_UDP) {
        if (it->second.read_enabled) {
            ClientRead event{
                    .id = it->second.listener_conn_id,
                    .data = message.data(),
                    .length = message.length(),
            };
            this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
            if (event.result <= 0) {
                log_upstream(this, info, "Failed to send UDP {} ({}) -> {}: handler returned {}", info.addrs->src,
                        info.app_name, tunnel_addr_to_str(&info.addrs->dst), event.result);
            }
        } else if (it->second.udp_pending.size() < MAX_UDP_QUEUE_SIZE) {
            it->second.udp_pending.emplace_back(message.begin(), message.end());
        } else {
            log_upstream(this, info, "Failed to send UDP {} ({}) -> {}: read disabled", info.addrs->src, info.app_name,
                    tunnel_addr_to_str(&info.addrs->dst));
        }
    } else {
        write_dns_message_to(it->second.snd_buf, message);
        if (!raise_read(it->second)) {
            close_connection(it->second.listener_conn_id, /*graceful*/ false, /*async*/ true);
        }
    }

    return it->second.listener_conn_id;
}

void ag::DnsHandlerClientListenerBase::complete_connect_request(uint64_t id, ClientConnectResult result) {
    auto it = m_connections.find(id);
    if (it == m_connections.end()) {
        log_listener(this, warn, "Connection L:{} does not exist", id);
        return;
    }

    if (result != CCR_PASS) {
        log_listener(this, dbg, "Connection L:{} rejected: {}", id, magic_enum::enum_name(result));
        close_connection(id, /*graceful*/ false, /*async*/ false);
        return;
    }

    it->second.read_enabled = true;
    handler.func(handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &id);

    if (!raise_read(it->second)) {
        close_connection(id, /*graceful*/ false, /*async*/ false);
    }
}

void ag::DnsHandlerClientListenerBase::close_listener_connection_by_upstream_conn_id(uint64_t upstream_conn_id) {
    auto id_it = m_conn_id_by_upstream_conn_id.find(upstream_conn_id);
    if (id_it == m_conn_id_by_upstream_conn_id.end()) {
        // We might not have a connection as listener if we've never opened it.
        log_listener(this, dbg, "Connection for upstream connection R:{} does not exist", upstream_conn_id);
        return;
    }
    close_connection(id_it->second, /*graceful*/ false, /*async*/ false);
}

void ag::DnsHandlerClientListenerBase::close_connection(uint64_t listener_conn_id, bool /*graceful*/, bool async) {
    auto it = m_connections.find(listener_conn_id);
    if (it == m_connections.end()) {
        log_listener(this, warn, "Connection L:{} does not exist", listener_conn_id);
        return;
    }

    if (!async) {
        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &listener_conn_id);
        return;
    }

    m_closed_connections.push_back(listener_conn_id);
    if (!m_task.has_value()) {
        m_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
    }
}

ssize_t ag::DnsHandlerClientListenerBase::send(uint64_t listener_conn_id, const uint8_t *data, size_t length) {
    auto it = m_connections.find(listener_conn_id);
    if (it == m_connections.end()) {
        log_listener(this, warn, "Connection L:{} does not exist", listener_conn_id);
        return -1;
    }

    if (it->second.proto == IPPROTO_UDP) {
        on_dns_response(it->second.upstream_conn_id, {data, length});
        return length; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    }

    it->second.rcv_buf.insert(it->second.rcv_buf.end(), data, data + length);
    wire_utils::Reader reader{{it->second.rcv_buf.begin(), it->second.rcv_buf.end()}};
    int read = 0;
    for (;;) {
        auto msg_size = reader.get_u16();
        if (!msg_size.has_value()) {
            break;
        }
        auto msg = reader.get_bytes(*msg_size);
        if (!msg.has_value()) {
            break;
        }
        read += 2 + static_cast<int>(msg->size());
        on_dns_response(it->second.upstream_conn_id, *msg);
    }
    it->second.rcv_buf.erase(it->second.rcv_buf.begin(), it->second.rcv_buf.begin() + read);

    return length; // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
}

void ag::DnsHandlerClientListenerBase::consume(uint64_t /*listener_conn_id*/, size_t /*n*/) {
    // No op
}

ag::TcpFlowCtrlInfo ag::DnsHandlerClientListenerBase::flow_control_info(uint64_t /*listener_conn_id*/) {
    return TcpFlowCtrlInfo{DEFAULT_SEND_BUFFER_SIZE, DEFAULT_SEND_WINDOW_SIZE};
}

void ag::DnsHandlerClientListenerBase::turn_read(uint64_t id, bool read_enabled) {
    auto it = m_connections.find(id);
    if (it == m_connections.end()) {
        log_listener(this, warn, "Connection L:{} does not exist", id);
        return;
    }
    if (it->second.proto == IPPROTO_TCP && !it->second.read_enabled && read_enabled && !it->second.snd_buf.empty()) {
        m_connections_to_send.push_back(id);
        if (!m_task.has_value()) {
            m_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
        }
    }
    it->second.read_enabled = read_enabled;
}

ag::DnsHandlerClientListenerBase::Connection::Connection(
        uint64_t listener_conn_id, uint64_t upstream_conn_id, int proto)
        : listener_conn_id(listener_conn_id)
        , upstream_conn_id{upstream_conn_id}
        , proto{proto}
        , read_enabled{false} {
}

void ag::DnsHandlerClientListenerBase::on_async_task(void *arg, TaskId /*task_id*/) {
    auto *self = (DnsHandlerClientListenerBase *) arg;
    self->m_task.release();

    std::vector<uint64_t> to_close;
    to_close.swap(self->m_closed_connections);
    for (uint64_t id : to_close) {
        if (self->m_connections.contains(id)) {
            self->handler.func(self->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
        }
    }

    std::vector<uint64_t> to_send;
    to_send.swap(self->m_connections_to_send);
    for (uint64_t id : to_send) {
        if (auto it = self->m_connections.find(id); it != self->m_connections.end()) {
            if (!self->raise_read(it->second)) {
                self->close_connection(it->second.listener_conn_id, /*graceful*/ false, /*async*/ false);
            }
        }
    }
}

bool ag::DnsHandlerClientListenerBase::raise_read(Connection &conn) {
    if (!conn.read_enabled) {
        return true;
    }

    if (conn.proto == IPPROTO_UDP) {
        while (!conn.udp_pending.empty()) {
            auto &message = conn.udp_pending.front();
            ClientRead event{
                    .id = conn.listener_conn_id,
                    .data = message.data(),
                    .length = message.size(),
            };
            this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
            if (event.result <= 0) {
                log_listener(this, info, "Failed to send pending UDP messages: handler returned {}", event.result);
                conn.udp_pending.clear();
                break;
            }
            conn.udp_pending.pop_front();
        }
        return true;
    }

    if (conn.snd_buf.empty()) {
        return true;
    }

    ClientRead event{
            .id = conn.listener_conn_id,
            .data = conn.snd_buf.data(),
            .length = conn.snd_buf.size(),
    };
    this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
    if (event.result < 0) {
        log_listener(this, info, "Failed to send TCP data as client: handler returned {}", event.result);
        return false;
    }
    assert(size_t(event.result) <= conn.snd_buf.size());
    conn.snd_buf.erase(conn.snd_buf.begin(), conn.snd_buf.begin() + event.result);

    if (conn.snd_buf.size() > CONN_MAX_BUFFERED) {
        log_listener(this, warn, "Send buffer for connection L:{} is getting too long", conn.listener_conn_id);
        return false;
    }

    return true;
}

ag::DnsHandler::DnsHandler(int id, DnsHandlerParameters parameters)
        : DnsHandlerServerUpstreamBase(id)
        , m_parameters{std::move(parameters)} {
}

ag::DnsHandler::~DnsHandler() {
    shutdown();
}

bool ag::DnsHandler::initialize(VpnClient *vpn, ServerHandler upstream_handler, ClientHandler listener_handler) {
    if (!DnsHandlerServerUpstreamBase::init(vpn, upstream_handler)) {
        assert(0);
    }

    if (InitResult::SUCCESS != DnsHandlerClientListenerBase::init(vpn, listener_handler)) {
        assert(0);
    }

    if (m_parameters.cert_verify_handler.func == nullptr) {
        log_handler(this, err, "Cert verify handler is not set");
        return false;
    }

    if (!start_dns_proxy()) {
        shutdown();
        return false;
    }

    if (!start_system_dns_proxy()) {
        shutdown();
        return false;
    }

    m_dns_change_subscription_id = dns_manager_subscribe_servers_change(
            vpn->parameters.network_manager->dns, vpn->parameters.ev_loop, on_dns_change, this);
    return true;
}

bool ag::DnsHandler::update_parameters(DnsHandlerParameters parameters) {
    if (parameters.cert_verify_handler.func == nullptr) {
        log_handler(this, err, "Cert verify handler is not set");
        return false;
    }
    log_handler(this, dbg, "Restarting DNS proxy with new parameters");
    m_parameters = std::move(parameters);
    return start_dns_proxy();
}

bool ag::DnsHandler::start_dns_proxy() {
    m_user_dns_failure_count = 0;
    m_upstream_conn_id_by_client_id.clear();
    m_client.reset();
    if (m_dns_proxy) {
        m_dns_proxy->stop();
        m_dns_proxy.reset();
    }

    if (m_parameters.dns_upstreams.empty()) {
        log_handler(this, info, "User DNS servers empty");
        return true;
    }

    if (m_parameters.dns_proxy_listener_address.is_any() || !m_parameters.dns_proxy_listener_address.is_loopback()) {
        log_handler(this, warn, "DNS proxy listener address is invalid: {}", m_parameters.dns_proxy_listener_address);
        return false;
    }

    m_dns_proxy = std::make_unique<DnsProxyAccessor>(
            DnsProxyAccessor::Parameters{.upstreams = std::move(m_parameters.dns_upstreams),
                    .socks_listener_address = m_parameters.dns_proxy_listener_address,
                    .cert_verify_handler = m_parameters.cert_verify_handler,
#if defined(__APPLE__) && TARGET_OS_IPHONE
                    .qos_settings = {.qos_class = ServerUpstream::vpn->parameters.qos_settings.qos_class,
                            .relative_priority = ServerUpstream::vpn->parameters.qos_settings.relative_priority}
#endif // __APPLE__ && TARGET_OS_IPHONE
            });

    if (!m_dns_proxy->start()) {
        log_handler(this, err, "Failed to start DNS proxy");
        return false;
    }

    SocketAddress tcp_addr = m_dns_proxy->get_listen_address(utils::TP_TCP);
    SocketAddress udp_addr = m_dns_proxy->get_listen_address(utils::TP_UDP);
    log_handler(this, info, "DNS proxy listening on {}/TCP, {}/UDP", tcp_addr, udp_addr);

    m_client = std::make_unique<DnsClient>(DnsClientParameters{
            .ev_loop = ServerUpstream::vpn->parameters.ev_loop,
            .socket_manager = ServerUpstream::vpn->parameters.network_manager->socket,
            .handler = {.func = client_handler, .arg = this},
            .tcp_server_address = tcp_addr,
            .udp_server_address = udp_addr,
            .request_timeout = DNS_CLIENT_TIMEOUT,
            .tag = "user-dns-proxy",
    });

    if (!m_client->init()) {
        log_handler(this, err, "Failed to initialize DNS client");
        return false;
    }

    return true;
}

bool ag::DnsHandler::start_system_dns_proxy() {
    SystemDnsServers servers = dns_manager_get_system_servers(ServerUpstream::vpn->parameters.network_manager->dns);

    if (servers.main.empty()) {
        log_handler(this, info, "System DNS servers empty");
        servers = {};
        for (std::string_view address : AG_UNFILTERED_DNS_IPS_V4) {
            servers.main.emplace_back(SystemDnsServer{.address = std::string{address}});
        }
        for (std::string_view address : AG_UNFILTERED_DNS_IPS_V6) {
            servers.main.emplace_back(SystemDnsServer{.address = std::string{address}});
        }
    }

    SystemDnsServers servers_v6;
    for (auto it = servers.main.begin(); it != servers.main.end();) {
        SocketAddress address{it->address};
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        if ((it->resolved_host.has_value() && it->resolved_host->is_ipv6()) || (address.valid() && address.is_ipv6())) {
            servers_v6.main.emplace_back(std::move(*it));
            it = servers.main.erase(it);
            continue;
        }
        ++it;
    }
    using T = std::pair<std::vector<std::string> &, std::vector<std::string> &>;
    for (auto &[from, to] : {T{servers.bootstrap, servers_v6.bootstrap}, T{servers.fallback, servers_v6.fallback}}) {
        for (auto it = from.begin(); it != from.end();) {
            SocketAddress address{*it};
            if (address.valid() && address.is_ipv6()) {
                to.emplace_back(std::move(*it));
                it = from.erase(it);
                continue;
            }
            ++it;
        }
    }

    assert(!servers.main.empty() || !servers_v6.main.empty());

    using P = std::tuple<SystemDnsServers *, std::unique_ptr<DnsProxyAccessor> &, std::unique_ptr<DnsClient> &,
            std::string, std::unordered_map<uint16_t, uint64_t> &>;
    for (auto &[servers, proxy, client, tag, map] :
            {P{&servers, m_system_dns_proxy, m_system_client, "system-dns-proxy",
                     m_upstream_conn_id_by_system_client_id},
                    P{&servers_v6, m_system_dns_proxy_ipv6, m_system_client_ipv6, "system-dns-proxy-ipv6",
                            m_upstream_conn_id_by_system_client_ipv6_id}}) {
        client.reset();
        if (proxy) {
            proxy->stop();
            proxy.reset();
        }
        map.clear();

        if (servers->main.empty()) {
            continue;
        }
        std::vector<DnsProxyAccessor::Upstream> upstreams;
        for (auto &server : servers->main) {
            upstreams.emplace_back(DnsProxyAccessor::Upstream{
                    .address = std::move(server.address),
                    .resolved_host = server.resolved_host,
            });
        }
        proxy = std::make_unique<DnsProxyAccessor>(DnsProxyAccessor::Parameters{.upstreams = std::move(upstreams),
                .fallbacks = std::move(servers->fallback),
                .bootstraps = std::move(servers->bootstrap),
                .cert_verify_handler = m_parameters.cert_verify_handler,
#if defined(__APPLE__) && TARGET_OS_IPHONE
                .qos_settings = {.qos_class = ServerUpstream::vpn->parameters.qos_settings.qos_class,
                        .relative_priority = ServerUpstream::vpn->parameters.qos_settings.relative_priority}
#endif // __APPLE__ && TARGET_OS_IPHONE
        });

        if (!proxy->start()) {
            log_handler(this, err, "Failed to start system{} DNS proxy", servers == &servers_v6 ? " (IPv6)" : "");
            return false;
        }

        SocketAddress tcp_addr = proxy->get_listen_address(utils::TP_TCP);
        SocketAddress udp_addr = proxy->get_listen_address(utils::TP_UDP);
        log_handler(this, info, "System{} DNS proxy listening on {}/TCP, {}/UDP",
                servers == &servers_v6 ? " (IPv6)" : "", tcp_addr, udp_addr);

        client = std::make_unique<DnsClient>(DnsClientParameters{
                .ev_loop = ServerUpstream::vpn->parameters.ev_loop,
                .socket_manager = ServerUpstream::vpn->parameters.network_manager->socket,
                .handler = {.func = (servers == &servers_v6) ? system_client_ipv6_handler : system_client_handler,
                        .arg = this},
                .tcp_server_address = tcp_addr,
                .udp_server_address = udp_addr,
                .request_timeout = DNS_CLIENT_TIMEOUT,
                .tag = AG_FMT("system-dns-proxy{}", servers == &servers_v6 ? "-ipv6" : ""),
        });

        if (!client->init()) {
            log_handler(this, err, "Failed to initialize DNS client");
            return false;
        }
    }

    return true;
}

void ag::DnsHandler::handle_user_dns_proxy_failure() {
    if (m_parameters.dns_upstreams.empty()) {
        return;
    }

    m_user_dns_failure_count += 1;
    if (m_user_dns_failure_count < USER_DNS_FAILURE_RESTART_THRESHOLD) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    if (now - m_last_user_dns_restart < USER_DNS_RESTART_MIN_INTERVAL) {
        return;
    }

    m_last_user_dns_restart = now;
    m_user_dns_failure_count = 0;
    log_handler(this, warn, "Restarting user DNS proxy after {} consecutive failures",
            USER_DNS_FAILURE_RESTART_THRESHOLD);
    if (!start_dns_proxy()) {
        log_handler(this, err, "Failed to restart user DNS proxy after failures");
    }
}

void ag::DnsHandler::client_handler(void *arg, DnsClientEvent what, void *data) {
    auto *self = (DnsHandler *) arg;
    self->client_handler(self->m_upstream_conn_id_by_client_id, what, data);
}

void ag::DnsHandler::system_client_handler(void *arg, DnsClientEvent what, void *data) {
    auto *self = (DnsHandler *) arg;
    self->client_handler(self->m_upstream_conn_id_by_system_client_id, what, data);
}

void ag::DnsHandler::system_client_ipv6_handler(void *arg, DnsClientEvent what, void *data) {
    auto *self = (DnsHandler *) arg;
    self->client_handler(self->m_upstream_conn_id_by_system_client_ipv6_id, what, data);
}

void ag::DnsHandler::client_handler(std::unordered_map<uint16_t, uint64_t> &map, DnsClientEvent what, void *data) {
    switch (what) {
    case DNS_CLIENT_RESPONSE: {
        const bool is_user_proxy = (&map == &m_upstream_conn_id_by_client_id);
        auto *event = (DnsClientResponse *) data;
        auto node = map.extract(event->id);
        assert(!node.empty());
        if (!event->data.empty()) {
            if (is_user_proxy) {
                m_user_dns_failure_count = 0;
            }
            on_dns_response(node.mapped(), event->data);
        } else {
            log_handler(this, info, "{}DNS proxy request id={} failed",
                    &map == &m_upstream_conn_id_by_system_client_id                ? "System "
                            : &map == &m_upstream_conn_id_by_system_client_ipv6_id ? "System (IPv6) "
                                                                                   : "",
                    event->id);
            if (is_user_proxy) {
                handle_user_dns_proxy_failure();
            }
        }
        break;
    }
    case DNS_CLIENT_PROTECT:
        ServerUpstream::vpn->parameters.handler.func(
                ServerUpstream::vpn->parameters.handler.arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
}

void ag::DnsHandler::on_dns_change(void *arg) {
    auto *self = (DnsHandler *) arg;
    log_handler(self, info, "Restarting system DNS proxy");
    self->start_system_dns_proxy();
}

void ag::DnsHandler::on_network_change() {
    // System proxy has to be restarted with a new `outbound_interface`.
    // Assume `vpn_network_manager_set_outbound_interface` has been called before `vpn_notify_network_change`.
    log_handler(this, info, "Restarting DNS proxies after network change");
    start_system_dns_proxy();
    if (!m_parameters.dns_upstreams.empty() && !start_dns_proxy()) {
        log_handler(this, err, "Failed to restart user DNS proxy after network change");
    }
}

void ag::DnsHandler::on_upstream_connection_closed(uint64_t upstream_conn_id) {
    close_listener_connection_by_upstream_conn_id(upstream_conn_id);
}

void ag::DnsHandler::send_request(bool system_proxy, bool ipv6, bool tcp, uint64_t upstream_conn_id, U8View message) {
    auto &client = !system_proxy ? m_client : (ipv6 && m_system_client_ipv6) ? m_system_client_ipv6 : m_system_client;
    if (!client) {
        log_handler(this, dbg, "No DNS client, system: {}, ipv6: {}", system_proxy, ipv6);
        return;
    }
    auto request_id = client->send(message, tcp);
    if (!request_id.has_value()) {
        log_handler(this, info, "Dropping DNS request: failed to send to {}DNS proxy", system_proxy ? "system " : "");
        return;
    }
    auto &map = !system_proxy                ? m_upstream_conn_id_by_client_id
            : (ipv6 && m_system_client_ipv6) ? m_upstream_conn_id_by_system_client_ipv6_id
                                             : m_upstream_conn_id_by_system_client_id;
    auto [_, placed] = map.emplace(*request_id, upstream_conn_id);
    assert_use(placed);
}

void ag::DnsHandler::send_request_as_listener(const ConnectionInfo &info, U8View message) {
    uint64_t listener_conn_id = send_as_listener(info, message);
    log_handler(this, dbg, "[L:{}] {}", listener_conn_id, info);
}

void ag::DnsHandler::shutdown() {
    if (m_dns_change_subscription_id.has_value()) {
        dns_manager_unsubscribe_servers_change(
                ServerUpstream::vpn->parameters.network_manager->dns, *m_dns_change_subscription_id);
    }
    DnsHandlerServerUpstreamBase::deinit();
    DnsHandlerClientListenerBase::deinit();
    m_client.reset();
    m_system_client.reset();
    m_system_client_ipv6.reset();
    if (m_dns_proxy) {
        m_dns_proxy->stop();
        m_dns_proxy.reset();
    }
    if (m_system_dns_proxy) {
        m_system_dns_proxy->stop();
        m_system_dns_proxy.reset();
    }
    if (m_system_dns_proxy_ipv6) {
        m_system_dns_proxy_ipv6->stop();
        m_system_dns_proxy_ipv6.reset();
    }
}

void ag::DnsHandler::on_dns_request(const ConnectionInfo &info, U8View message) {
    auto decode_result = dns_utils::decode_packet(message);

    if (auto *error = std::get_if<dns_utils::Error>(&decode_result)) {
        log_handler(this, info, "{} dropping unparseable DNS request, error: {}", info, error->description);
        return;
    }

    // Note: now obsolete inverse queries (RFC 1035) will result in `dns_utils::InapplicablePacket`.
    // The DNS proxy doesn't support them.
    if (!std::holds_alternative<dns_utils::DecodedRequest>(decode_result)) {
        send_request_as_listener(info, message);
        return;
    }

    auto &request = std::get<dns_utils::DecodedRequest>(decode_result);
    bool ipv6 = std::holds_alternative<SocketAddress>(info.addrs->dst)
            && std::get<SocketAddress>(info.addrs->dst).is_ipv6();
    bool tcp = (info.proto == IPPROTO_TCP);

    if (!ServerUpstream::vpn->tunnel->endpoint_upstream_connected) {
        if (!ServerUpstream::vpn->kill_switch_on) {
            log_handler(this, dbg, "{} qname: {} -> system DNS proxy (not connected)", info, request.name);
            send_request(/*system proxy*/ true, ipv6, tcp, info.upstream_conn_id, message);
            return;
        }
        if (vpn_network_manager_check_app_request_domain(request.name.c_str())) {
            log_handler(this, dbg, "{} qname: {} -> system DNS proxy (not connected, app request)", info, request.name);
            send_request(/*system proxy*/ true, ipv6, tcp, info.upstream_conn_id, message);
            return;
        }
        log_handler(this, dbg, "{} qname: {} dropped: not connected, kill switch enabled", info, request.name);
        return;
    }

    DomainFilterMatchStatus status = ServerUpstream::vpn->domain_filter.match_domain(request.name);
    bool included = (ServerUpstream::vpn->exclusions_mode == VPN_MODE_GENERAL) ? (status == DFMS_DEFAULT)
                                                                               : (status == DFMS_EXCLUSION);

    if (included && m_client) {
        log_handler(this, dbg, "{} qname: {} -> DNS proxy", info, request.name);
        send_request(/*system proxy*/ false, ipv6, tcp, info.upstream_conn_id, message);
    } else if (!included) {
        log_handler(this, dbg, "{} qname: {} -> system DNS proxy", info, request.name);
        send_request(/*system proxy*/ true, ipv6, tcp, info.upstream_conn_id, message);
    } else {
        log_handler(this, dbg, "{} qname: {} -> {}", info, request.name, tunnel_addr_to_str(&info.addrs->dst));
        send_request_as_listener(info, message);
    }
}

void ag::DnsHandler::on_dns_response(uint64_t upstream_conn_id, U8View message) {
    dns_utils::LdnsBufferPtr pkt_buffer;
    auto decode_result = dns_utils::decode_packet(message);
    if (auto *response = std::get_if<dns_utils::DecodedReply>(&decode_result)) {
        if (std::ranges::any_of(response->names, [&](const std::string &name) {
                return DFMS_EXCLUSION == ServerUpstream::vpn->domain_filter.match_domain(name);
            })) {
            // Add exclusion suspects.
            for (const auto &addr : response->addresses) {
                ServerUpstream::vpn->domain_filter.add_exclusion_suspect(
                        SocketAddress({addr.ip.data(), addr.ip.size()}, 0),
                        is_vpn_resolver_connection(upstream_conn_id)
                                ? std::max(addr.ttl, Tunnel::EXCLUSIONS_RESOLVE_PERIOD)
                                : addr.ttl);
            }
            // Remove ECH parameters.
            if (dns_utils::remove_svcparam_echconfig(response->pkt.get())) {
                pkt_buffer = dns_utils::encode_pkt(response->pkt.get());
                if (pkt_buffer) {
                    message = {ldns_buffer_at(pkt_buffer.get(), 0), ldns_buffer_position(pkt_buffer.get())};
                }
            }
        }
    }
    send_response(upstream_conn_id, message);
}
