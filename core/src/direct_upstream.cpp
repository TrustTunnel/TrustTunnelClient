#include "direct_upstream.h"

#include <event2/util.h>

#include "common/net_utils.h"
#include "net/dns_manager.h"
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

bool DirectUpstream::init(VpnClient *vpn, SeverHandler handler) {
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
        close_connection(m_tcp_connections.begin()->first, false);
    }

    while (!m_udp_connections.empty()) {
        close_connection(m_udp_connections.begin()->first, false);
    }

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
    case TCP_SOCKET_EVENT_READ: {
        auto *sock_event = (TcpSocketReadEvent *) data;

        if (sock_event->length == 0) {
            log_conn(upstream, ctx->conn_id, dbg, "Got EOF from remote host");
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &ctx->conn_id);
            upstream->m_tcp_connections.erase(ctx->conn_id);
        } else {
            log_conn(upstream, ctx->conn_id, trace, "Got {} bytes from remote host", sock_event->length);

            ServerReadEvent serv_event = {ctx->conn_id, sock_event->data, sock_event->length, 0};
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_READ, &serv_event);

            if (serv_event.result >= 0) {
                sock_event->processed = serv_event.result;
            } else {
                upstream->close_connection(ctx->conn_id, false);
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
    case UDP_SOCKET_EVENT_READ: {
        auto *sock_event = (UdpSocketReadEvent *) data;

        auto it = upstream->m_udp_connections.find(ctx->conn_id);
        if (it == upstream->m_udp_connections.end()) {
            log_conn(upstream, ctx->conn_id, dbg, "Read on closed connection");
            sock_event->closed = true;
            break;
        }

        if (!it->second.read_enabled) {
            log_conn(upstream, ctx->conn_id, dbg, "Dropping packet as read disabled ({} bytes)", sock_event->length);
            break;
        }

        ServerReadEvent event = {ctx->conn_id, sock_event->data, sock_event->length, 0};
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_READ, &event);
        break;
    }
    }
}

uint64_t DirectUpstream::open_tcp_connection(const TunnelAddressPair *addr) {
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
        return NON_ID;
    }

    TcpSocketConnectParameters param = {};
    if (const sockaddr_storage *dst = std::get_if<sockaddr_storage>(&addr->dst); dst != nullptr) {
        param = {
                .connect_by = TCP_SOCKET_CB_ADDR,
                .by_addr = { .addr = (sockaddr *) dst },
        };
    } else if (const NamePort *dst = std::get_if<NamePort>(&addr->dst); dst != nullptr) {
        param = {
                .connect_by = TCP_SOCKET_CB_HOSTNAME,
                .by_name = {
                        .dns_base = this->vpn->parameters.dns_base,
                        .host = dst->name.c_str(),
                        .port = dst->port,
                },
        };
    } else {
        log_upstream(this, err, "Empty destination address");
        assert(0);
        return NON_ID;
    }

    if (0 != tcp_socket_connect(sock.get(), &param).code) {
        return NON_ID;
    }

    TcpConnection *conn = &m_tcp_connections[id];
    conn->sock_ctx = std::move(ctx);
    conn->socket = std::move(sock);

    return id;
}

uint64_t DirectUpstream::open_udp_connection(const TunnelAddressPair *addr) {
    uint64_t id = this->vpn->upstream_conn_id_generator.get();
    std::unique_ptr<SocketContext> ctx = std::make_unique<SocketContext>(SocketContext{this, id});

    UdpSocketParameters params = {this->vpn->parameters.ev_loop, {udp_socket_handler, ctx.get()},
            Millis{VPN_DEFAULT_UDP_TIMEOUT_MS}, *std::get_if<sockaddr_storage>(&addr->dst),
            this->vpn->parameters.network_manager->socket};
    UdpSocketPtr socket{udp_socket_create(&params)};
    if (socket == nullptr) {
        log_upstream(this, err, "Failed to create socket");
        return NON_ID;
    }

    UdpConnection *conn = &m_udp_connections[id];
    conn->sock_ctx = std::move(ctx);
    conn->socket = std::move(socket);
    conn->open_task_id = event_loop::submit(vpn->parameters.ev_loop,
            {
                    new SocketContext{this, id},
                    [](void *arg, TaskId) {
                        auto *ctx = (SocketContext *) arg;
                        DirectUpstream *upstream = ctx->upstream;
                        if (auto i = upstream->m_udp_connections.find(ctx->conn_id);
                                i != upstream->m_udp_connections.end()) {
                            upstream->handler.func(
                                    upstream->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &ctx->conn_id);
                            UdpConnection *conn = &i->second;
                            conn->open_task_id.release();
                        }
                    },
                    [](void *arg) {
                        delete (SocketContext *) arg;
                    },
            });

    return id;
}

uint64_t DirectUpstream::open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    (void) app_name;
    uint64_t id = NON_ID;

    if (proto == IPPROTO_TCP) {
        id = open_tcp_connection(addr);
    } else if (proto == IPPROTO_UDP) {
        id = open_udp_connection(addr);
    } else {
        log_upstream(this, err, "Unknown protocol: {}", proto);
        assert(0);
    }

    return id;
}

void DirectUpstream::close_connection(uint64_t id, bool graceful) {
    if (m_tcp_connections.count(id) == 0 && m_udp_connections.count(id) == 0) {
        // already raised in EOF event
        return;
    }

    log_conn(this, id, dbg, "Closing");

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        if (!graceful && conn->socket != nullptr) {
            tcp_socket_set_rst(conn->socket.get());
        }

        m_tcp_connections.erase(i);
    } else if (auto i = m_udp_connections.find(id); i != m_udp_connections.end()) {
        m_udp_connections.erase(i);
    }

    this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
}

void DirectUpstream::close_connection(uint64_t id, bool graceful, bool async) {
    if (!async) {
        close_connection(id, graceful);
        return;
    }

    struct CloseCtx {
        DirectUpstream *upstream;
        uint64_t id;
        bool graceful;
    };

    Connection *conn = nullptr;
    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        conn = &i->second;
    } else if (auto i = m_udp_connections.find(id); i != m_udp_connections.end()) {
        conn = &i->second;
    } else {
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
        return;
    }

    conn->close_task_id = event_loop::submit(vpn->parameters.ev_loop,
            {
                    new CloseCtx{this, id, graceful},
                    [](void *arg, TaskId) {
                        auto *ctx = (CloseCtx *) arg;
                        ctx->upstream->close_connection(ctx->id, ctx->graceful);
                    },
                    [](void *arg) {
                        delete (CloseCtx *) arg;
                    },
            });
}

ssize_t DirectUpstream::send(uint64_t id, const uint8_t *data, size_t length) {
    VpnError error = {};

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        error = tcp_socket_write(conn->socket.get(), data, length);
    } else if (auto i = m_udp_connections.find(id); i != m_udp_connections.end()) {
        UdpConnection *conn = &i->second;
        error = udp_socket_write(conn->socket.get(), data, length);
    } else {
        log_conn(this, id, dbg, "Not found");
    }

    if (error.code == 0) {
        return length;
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
            .connect_by = TCP_SOCKET_CB_ADDR,
            .by_addr = { .addr = (sockaddr *) &peer },
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
    case TCP_SOCKET_EVENT_READ:
    case TCP_SOCKET_EVENT_SENT:
    case TCP_SOCKET_EVENT_WRITE_FLUSH:
        log_upstream(self, dbg, "Unexpected event: {}", magic_enum::enum_name(what));
        assert(0);
        reply = ctx->make_reply_template();
        if (reply->peer.ss_family == AF_INET) {
            update_reply_on_error_v4(reply.value(), ag::utils::AG_ECONNREFUSED);
        } else {
            update_reply_on_error_v6(reply.value(), ag::utils::AG_ECONNREFUSED);
        }
        break;
    }

    if (reply.has_value()) {
        self->handler.func(self->handler.arg, SERVER_EVENT_ECHO_REPLY, &reply);
        self->cancel_icmp_request(ctx->key, ctx->seqno);
    }
}

} // namespace ag
