#include <utility>

#include <event2/util.h>
#include <magic_enum.hpp>

#include "common/defs.h"
#include "common/net_utils.h"
#include "direct_upstream.h"
#include "net/network_manager.h"
#include "net/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

#define log_upstream(ups_, lvl_, fmt_, ...) lvl_##log((ups_)->m_log, "[{}] " fmt_, (ups_)->id, ##__VA_ARGS__)
#define log_conn(ups_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((ups_)->m_log, "[{}] [R:{}] " fmt_, (ups_)->id, (uint64_t) (cid_), ##__VA_ARGS__)

namespace ag {

struct SocketContext {
    DirectUpstream *upstream = nullptr;
    uint64_t conn_id = NON_ID;
};

struct IcmpSocketContext {
    DirectUpstream *upstream = nullptr;
    sockaddr_storage peer = {};
    IcmpRequestKey key = {};
    uint16_t seqno = 0;

    [[nodiscard]] IcmpEchoReply make_reply_template() const {
        return {this->peer, this->key.id, this->seqno};
    }
};

struct IcmpRequestAttempt {
    TcpSocketPtr socket;
    std::unique_ptr<IcmpSocketContext> context;
};

struct DirectUpstream::IcmpRequestInfo {
    std::vector<IcmpRequestAttempt> tries;
};

static constexpr uint16_t ICMP_PING_EMULATION_PORT = 443;

DirectUpstream::DirectUpstream(int id)
        : ServerUpstream(id) {
}

DirectUpstream::~DirectUpstream() = default;

bool DirectUpstream::init(VpnClient *vpn, ServerHandler handler) {
    if (!this->ServerUpstream::init(vpn, handler)) {
        log_upstream(this, err, "Failed to initialize base upstream");
        deinit();
        return false;
    }

    return true;
}

void DirectUpstream::deinit() {
}

bool DirectUpstream::open_session(std::optional<Millis>) {
    this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    return true;
}

void DirectUpstream::close_session() {
    log_upstream(this, dbg, "...");

    while (!m_tcp_connections.empty()) {
        close_connection(m_tcp_connections.begin()->first, false, false);
    }

    while (!m_udp_connections.empty()) {
        close_connection(m_udp_connections.begin()->first, false, false);
    }

    m_icmp_requests.clear();

    log_upstream(this, dbg, "Done");
}

void DirectUpstream::tcp_socket_handler(void *arg, TcpSocketEvent what, void *data) {
    auto *ctx = (SocketContext *) arg;
    DirectUpstream *upstream = ctx->upstream;

    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED: {
        log_conn(upstream, ctx->conn_id, dbg, "Connected to remote host successfully");
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &ctx->conn_id);
        break;
    }
    case TCP_SOCKET_EVENT_READABLE: {
        uint64_t conn_id = ctx->conn_id;
        auto conn_iter = upstream->m_tcp_connections.find(conn_id);
        if (conn_iter == upstream->m_tcp_connections.end()) {
            log_conn(upstream, conn_id, warn, "Got read on nonexistent connection");
            break;
        }

        TcpSocket *socket = conn_iter->second.socket.get();

        constexpr size_t READ_BUDGET = 64;
        for (size_t i = 0; i < READ_BUDGET && tcp_socket_is_read_enabled(socket); ++i) {
            tcp_socket::PeekResult result = tcp_socket_peek(socket);
            if (std::holds_alternative<tcp_socket::NoData>(result)) {
                break;
            }

            if (std::holds_alternative<tcp_socket::Eof>(result)) {
                log_conn(upstream, conn_id, dbg, "Got EOF from remote host");
                upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &conn_id);
                upstream->m_tcp_connections.erase(conn_iter);
                break;
            }

            U8View chunk = std::get<tcp_socket::Chunk>(result);
            log_conn(upstream, conn_id, trace, "Got {} bytes from remote host", chunk.size());

            ServerReadEvent serv_event = {conn_id, chunk.data(), chunk.size()};
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_READ, &serv_event);

            if (!upstream->m_tcp_connections.contains(conn_id)) {
                break;
            }

            if (serv_event.result < 0) {
                upstream->close_connection(conn_id, false, false);
                break;
            }

            if (!tcp_socket_drain(socket, serv_event.result)) {
                log_conn(upstream, conn_id, dbg, "Couldn't drain data from socket buffer");
                upstream->close_connection(conn_id, false, false);
            }
        }

        break;
    }
    case TCP_SOCKET_EVENT_SENT: {
        const TcpSocketSentEvent *sock_event = (TcpSocketSentEvent *) data;

        ServerDataSentEvent serv_event = {ctx->conn_id, sock_event->bytes};
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_DATA_SENT, &serv_event);

        break;
    }
    case TCP_SOCKET_EVENT_ERROR: {
        const VpnError *sock_event = (VpnError *) data;

        log_conn(upstream, ctx->conn_id, dbg, "Error event on socket: {} ({})", sock_event->text, sock_event->code);

        ServerError serv_event = {ctx->conn_id, *sock_event};
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_ERROR, &serv_event);

        upstream->m_tcp_connections.erase(ctx->conn_id);

        break;
    }
    case TCP_SOCKET_EVENT_WRITE_FLUSH: {
        // do nothing
        break;
    }
    case TCP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
    }
}

void DirectUpstream::udp_socket_handler(void *arg, UdpSocketEvent what, void *data) {
    auto *ctx = (SocketContext *) arg;
    DirectUpstream *upstream = ctx->upstream;

    switch (what) {
    case UDP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
    case UDP_SOCKET_EVENT_TIMEOUT: {
        ServerError event = {
                ctx->conn_id, {ag::utils::AG_ETIMEDOUT, evutil_socket_error_to_string(ag::utils::AG_ETIMEDOUT)}};
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_ERROR, &event);
        upstream->m_udp_connections.erase(ctx->conn_id);
        break;
    }
    case UDP_SOCKET_EVENT_READABLE: {
        auto it = upstream->m_udp_connections.find(ctx->conn_id);
        if (it == upstream->m_udp_connections.end()) {
            log_conn(upstream, ctx->conn_id, dbg, "Read on closed connection");
            break;
        }

        constexpr size_t READ_BUDGET = 64;

        uint8_t buffer[UDP_MAX_DATAGRAM_SIZE];
        size_t attempts_made = 0;
        do {
            ssize_t r = udp_socket_recv(it->second.socket.get(), buffer, std::size(buffer));
            if (r <= 0) {
                int err = evutil_socket_geterror(udp_socket_get_fd(it->second.socket.get()));
                if (r != 0 && !AG_ERR_IS_EAGAIN(err)) {
                    log_conn(upstream, ctx->conn_id, dbg, "Failed to read data from socket: {} ({})",
                            evutil_socket_error_to_string(err), err);
                }
                break;
            }

            if (!it->second.read_enabled) {
                log_conn(upstream, ctx->conn_id, dbg, "Dropping packet as read disabled ({} bytes)", r);
                break;
            }

            ServerReadEvent event = {ctx->conn_id, buffer, size_t(r), 0};
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_READ, &event);
        } while (++attempts_made < READ_BUDGET && it->second.read_enabled);
        break;
    }
    }
}

uint64_t DirectUpstream::open_tcp_connection(const sockaddr_storage &peer) {
    uint64_t id = this->vpn->upstream_conn_id_generator.get();

    std::unique_ptr<SocketContext> ctx = std::make_unique<SocketContext>(SocketContext{this, id});

    TcpSocketParameters params = {
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {tcp_socket_handler, ctx.get()},
            .timeout = Millis{VPN_DEFAULT_TCP_TIMEOUT_MS},
            .socket_manager = this->vpn->parameters.network_manager->socket,
    };

    if (this->vpn->tmp_files_base_path.has_value()) {
        params.read_threshold = this->vpn->conn_memory_buffer_threshold;
    }

    TcpSocketPtr sock{tcp_socket_create(&params)};
    if (sock == nullptr) {
        log_upstream(this, dbg, "Failed to create socket");
        return NON_ID;
    }

    TcpSocketConnectParameters param = {
            .peer = (sockaddr *) &peer,
    };
    if (0 != tcp_socket_connect(sock.get(), &param).code) {
        return NON_ID;
    }

    TcpConnection *conn = &m_tcp_connections[id];
    conn->sock_ctx = std::move(ctx);
    conn->socket = std::move(sock);

    return id;
}

uint64_t DirectUpstream::open_udp_connection(const sockaddr_storage &peer) {
    uint64_t id = this->vpn->upstream_conn_id_generator.get();
    std::unique_ptr<SocketContext> ctx = std::make_unique<SocketContext>(SocketContext{this, id});

    UdpSocketParameters params = {
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {udp_socket_handler, ctx.get()},
            .timeout = Millis{VPN_DEFAULT_UDP_TIMEOUT_MS},
            .peer = peer,
            .socket_manager = this->vpn->parameters.network_manager->socket,
    };
    UdpSocketPtr socket{udp_socket_create(&params)};
    if (socket == nullptr) {
        log_upstream(this, err, "Failed to create socket");
        return NON_ID;
    }

    UdpConnection *conn = &m_udp_connections[id];
    conn->sock_ctx = std::move(ctx);
    conn->socket = std::move(socket);

    m_opening_connections.emplace(id);
    if (!m_async_task.has_value()) {
        m_async_task = event_loop::submit(this->vpn->parameters.ev_loop, {.arg = this, .action = on_async_task});
    }

    return id;
}

uint64_t DirectUpstream::open_connection(const TunnelAddressPair *addr, int proto, std::string_view) {
    uint64_t id = NON_ID;

    const auto *peer = std::get_if<sockaddr_storage>(&addr->dst);
    if (peer == nullptr) {
        log_upstream(this, dbg, "Destination peer is unresolved");
        return NON_ID;
    }

    switch (ipproto_to_transport_protocol(proto).value()) {
    case utils::TP_TCP:
        id = open_tcp_connection(*peer);
        break;
    case utils::TP_UDP:
        id = open_udp_connection(*peer);
        break;
    }

    return id;
}

void DirectUpstream::close_connection(uint64_t id, bool graceful, bool async) {
    m_opening_connections.erase(id);

    if (async) {
        m_closing_connections[id] = graceful;
        if (!m_async_task.has_value()) {
            m_async_task = event_loop::submit(this->vpn->parameters.ev_loop, {.arg = this, .action = on_async_task});
        }
        return;
    }

    log_conn(this, id, dbg, "Closing");
    m_closing_connections.erase(id);

    bool present = true;
    if (auto tcp_node = m_tcp_connections.extract(id); !tcp_node.empty()) {
        TcpConnection *conn = &tcp_node.mapped();
        if (!graceful && conn->socket != nullptr) {
            tcp_socket_set_rst(conn->socket.get());
        }
    } else if (auto udp_iter = m_udp_connections.find(id); udp_iter != m_udp_connections.end()) {
        m_udp_connections.erase(udp_iter);
    } else {
        present = false;
    }

    if (present) {
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
    }
}

ssize_t DirectUpstream::send(uint64_t id, const uint8_t *data, size_t length) {
    VpnError error = {};

    if (auto tcp_iter = m_tcp_connections.find(id); tcp_iter != m_tcp_connections.end()) {
        TcpConnection *conn = &tcp_iter->second;
        error = tcp_socket_write(conn->socket.get(), data, length);
    } else if (auto udp_iter = m_udp_connections.find(id); udp_iter != m_udp_connections.end()) {
        UdpConnection *conn = &udp_iter->second;
        error = udp_socket_write(conn->socket.get(), data, length);
    } else {
        log_conn(this, id, dbg, "Not found");
    }

    if (error.code == 0) {
        return ssize_t(length);
    }

    log_conn(this, id, dbg, "Failed to send data: {} ({})", safe_to_string_view(error.text), error.code);
    return -1;
}

void DirectUpstream::consume(uint64_t id, size_t length) {
    // do nothing
}

size_t DirectUpstream::available_to_send(uint64_t id) {
    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.cend()) {
        const TcpConnection *conn = &i->second;
        return tcp_socket_available_to_write(conn->socket.get());
    }

    if (auto i = m_udp_connections.find(id); i != m_udp_connections.end()) {
        return UDP_MAX_DATAGRAM_SIZE;
    }

    return 0;
}

void DirectUpstream::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
    auto i = m_tcp_connections.find(id);
    if (i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        tcp_socket_set_read_enabled(conn->socket.get(), info.send_buffer_size > 0);
        return;
    }

    auto j = m_udp_connections.find(id);
    if (j != m_udp_connections.end()) {
        UdpConnection *conn = &j->second;
        conn->read_enabled = info.send_buffer_size > 0;
    }
}

VpnError DirectUpstream::do_health_check() {
    assert(0);
    return {VPN_EC_ERROR, "Not implemented"};
}

VpnConnectionStats DirectUpstream::get_connection_stats() const {
    assert(0);
    return {};
}

void DirectUpstream::on_icmp_request(IcmpEchoRequestEvent &event) {
    auto ctx = std::make_unique<IcmpSocketContext>(IcmpSocketContext{
            .upstream = this,
            .peer = event.request.peer,
            .key = IcmpRequestKey::make(event.request),
            .seqno = event.request.seqno,
    });

    TcpSocketParameters params = {
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {icmp_socket_handler, ctx.get()},
            .timeout = Millis{VPN_DEFAULT_TCP_TIMEOUT_MS},
            .socket_manager = this->vpn->parameters.network_manager->socket,
    };

    TcpSocketPtr sock{tcp_socket_create(&params)};
    if (sock == nullptr) {
        event.result = -1;
        return;
    }

    sockaddr_storage peer = event.request.peer;
    sockaddr_set_port((sockaddr *) &peer, ICMP_PING_EMULATION_PORT);
    TcpSocketConnectParameters param = {
            .peer = (sockaddr *) &peer,
    };
    if (0 != tcp_socket_connect(sock.get(), &param).code) {
        event.result = -1;
        return;
    }

    auto &info = m_icmp_requests[ctx->key];
    if (info == nullptr) {
        info = std::make_unique<IcmpRequestInfo>();
    }

    info->tries.emplace_back(IcmpRequestAttempt{std::move(sock), std::move(ctx)});
}

void DirectUpstream::cancel_icmp_request(const IcmpRequestKey &key, uint16_t seqno) {
    auto request_it = m_icmp_requests.find(key);
    if (request_it == m_icmp_requests.end()) {
        log_upstream(this, trace, "Request is not found: id={} seqno={}", key.id, seqno);
        return;
    }

    auto &info = *request_it->second;
    auto try_it = std::find_if(info.tries.begin(), info.tries.end(), [seqno](const IcmpRequestAttempt &i) {
        return i.context->seqno == seqno;
    });
    if (try_it == info.tries.end()) {
        log_upstream(this, trace, "Request try is not found: id={} seqno={}", key.id, seqno);
        return;
    }

    info.tries.erase(try_it);
    if (info.tries.empty()) {
        m_icmp_requests.erase(request_it);
    }
}

static void update_reply_on_error_v4(IcmpEchoReply &reply, int code) {
    switch (code) {
    case AG_EHOSTUNREACH:
        reply.type = ICMP_MT_DESTINATION_UNREACHABLE;
        reply.code = ICMP_DUC_HOST_UNREACH;
        break;
    case AG_ENETUNREACH:
        reply.type = ICMP_MT_DESTINATION_UNREACHABLE;
        reply.code = ICMP_DUC_NET_UNREACH;
        break;
    case ag::utils::AG_ETIMEDOUT:
        reply.type = ICMP_MT_TIME_EXCEEDED;
        reply.code = ICMP_TEC_TTL;
        break;
    default:
        reply.type = ICMP_MT_DROP;
        break;
    }
}

static void update_reply_on_error_v6(IcmpEchoReply &reply, int code) {
    switch (code) {
    case AG_EHOSTUNREACH:
        reply.type = ICMPV6_MT_DESTINATION_UNREACHABLE;
        reply.code = ICMPV6_DUC_ADDRESS_UNREACH;
        break;
    case AG_ENETUNREACH:
        reply.type = ICMPV6_MT_DESTINATION_UNREACHABLE;
        reply.code = ICMPV6_DUC_NO_ROUTE;
        break;
    case ag::utils::AG_ETIMEDOUT:
        reply.type = ICMPV6_MT_TIME_EXCEEDED;
        reply.code = ICMPV6_TEC_HOP;
        break;
    default:
        reply.type = ICMP_MT_DROP;
        break;
    }
}

void DirectUpstream::icmp_socket_handler(void *arg, TcpSocketEvent what, void *data) {
    auto *ctx = (IcmpSocketContext *) arg;
    DirectUpstream *self = ctx->upstream;

    std::optional<IcmpEchoReply> reply;
    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED:
        reply = ctx->make_reply_template();
        reply->type = (ctx->peer.ss_family == AF_INET) ? uint8_t(ICMP_MT_ECHO_REPLY) : uint8_t(ICMPV6_MT_ECHO_REPLY);
        break;
    case TCP_SOCKET_EVENT_ERROR:
        reply = ctx->make_reply_template();
        if (const VpnError *error = (VpnError *) data; reply->peer.ss_family == AF_INET) {
            update_reply_on_error_v4(reply.value(), error->code);
        } else {
            update_reply_on_error_v6(reply.value(), error->code);
        }
        break;
    case TCP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &self->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
    case TCP_SOCKET_EVENT_READABLE:
    case TCP_SOCKET_EVENT_SENT:
    case TCP_SOCKET_EVENT_WRITE_FLUSH:
        log_upstream(self, dbg, "Unexpected event: {}", magic_enum::enum_name(what));
        reply = ctx->make_reply_template();
        if (reply->peer.ss_family == AF_INET) {
            update_reply_on_error_v4(reply.value(), ag::utils::AG_ECONNREFUSED);
        } else {
            update_reply_on_error_v6(reply.value(), ag::utils::AG_ECONNREFUSED);
        }
        assert(0);
        break;
    }

    if (reply.has_value()) {
        self->handler.func(self->handler.arg, SERVER_EVENT_ECHO_REPLY, &reply);
        self->cancel_icmp_request(ctx->key, ctx->seqno);
    }
}

void DirectUpstream::on_async_task(void *arg, TaskId) {
    auto *self = (DirectUpstream *) arg;
    self->m_async_task.release();

    for (auto [conn_id, graceful] : std::exchange(self->m_closing_connections, {})) {
        self->close_connection(conn_id, graceful, false);
    }

    for (uint64_t conn_id : std::exchange(self->m_opening_connections, {})) {
        self->handler.func(self->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &conn_id);
    }
}

} // namespace ag
