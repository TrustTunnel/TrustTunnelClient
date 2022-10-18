#include <net/socks5_listener.h>

#include <event2/listener.h>
#include <event2/util.h>
#include <khash.h>
#include <magic_enum.hpp>

#include "common/logger.h"
#include "common/net_utils.h"
#include "net/tcp_socket.h"
#include "net/utils.h"
#include "vpn/utils.h"

#include <cassert>

static const char *conn_proto_to_str(int p) {
    switch (p) {
    case IPPROTO_TCP:
        return "-TCP";
    case IPPROTO_UDP:
        return "-UDP";
    default:
        return "";
    }
}

static ag::Logger g_logger{"SOCKS5_LISTENER"};

#define STRICT_MODE 1
#define log_conn(listener_, id_, proto_, lvl_, fmt_, ...)                                                              \
    lvl_##log(g_logger, "[id={}{}] " fmt_, (uint32_t) (id_), conn_proto_to_str(proto_), ##__VA_ARGS__)

static const uint32_t SOCKS5_VER = 0x05;
static const uint32_t USERNAME_PASSWORD_VER = 0x01;

typedef enum {
    S5AM_NO_AUTHENTICATION_REQUIRED = 0x00,
    S5AM_GSSAPI = 0x01,
    S5AM_USERNAME_PASSWORD = 0x02,

    // same as corresponding method without _APPNAME, but the client will encode
    // the app name in a custom ATYP if one of these methods is chosen
    S5AM_NO_AUTHENTICATION_REQUIRED_APPNAME = 0x80,
    S5AM_USERNAME_PASSWORD_APPNAME = 0x82,

    S5AM_NO_ACCEPTABLE_METHODS = 0xff,
} Socks5AuthMethod;

typedef enum {
    S5CMD_CONNECT = 0x01,
    S5CMD_BIND = 0x02,
    S5CMD_UDP_ASSOCIATE = 0x03,
} Socks5Command;

typedef enum {
    S5AT_IPV4 = 0x01,       // a version-4 IP address, with a length of 4 octets
    S5AT_DOMAINNAME = 0x03, // a fully-qualified domain name, first octet of the address field
                            // contains the number of octets of name that follow
    S5AT_IPV6 = 0x04,       // a version-6 IP address, with a length of 16 octets

    // the first octet of the address field contains the number of octets in
    // the application name that follows, remaining octets are equivalent to
    // S5AT_IPV4, S5AT_DOMAINNAME, and S5AT_IPV6 respectively
    S5AT_IPV4_APPNAME = 0xf1,
    S5AT_DOMAINNAME_APPNAME = 0xf3,
    S5AT_IPV6_APPNAME = 0xf4,
} Socks5AddressType;

typedef enum {
    S5RS_SUCCEEDED,                         // succeeded
    S5RS_SOCKS_SERVER_FAILURE,              // general SOCKS server failure
    S5RS_CONNECTION_NOT_ALLOWED_BY_RULESET, // connection not allowed by ruleset
    S5RS_NETWORK_UNREACHABLE,               // Network unreachable
    S5RS_HOST_UNREACHABLE,                  // Host unreachable
    S5RS_CONNECTION_REFUSED,                // Connection refused
    S5RS_TTL_EXPIRED,                       // TTL expired
    S5RS_COMMAND_NOT_SUPPORTED,             // Command not supported
    S5RS_ADDRESS_TYPE_NOT_SUPPORTED,        // Address type not supported
} Socks5ReplyStatus;

static const Socks5ReplyStatus CONNECT_RESULT_TO_STATUS[] = {
        /** S5LCR_SUCCESS */ S5RS_SUCCEEDED,
        /** S5LCR_REJECT */ S5RS_CONNECTION_REFUSED,
        /** S5LCR_TIMEOUT */ S5RS_TTL_EXPIRED,
        /** S5LCR_UNREACHABLE */ S5RS_HOST_UNREACHABLE,
};

#pragma pack(push, 1)

typedef struct {
    uint8_t ver;       // set to X'05' for this version of the protocol
    uint8_t nmethods;  // number of method identifier octets
    uint8_t methods[]; // methods
} Socks5AuthRequest;

typedef struct {
    uint8_t ver;    // set to X'05' for this version of the protocol
    uint8_t method; // method
} Socks5AuthResponse;

typedef struct {
    uint8_t ver;           // set to X`01` for this version of the protocol
    uint8_t ulen;          // length of username
    const uint8_t *uname;  // username
    uint8_t plen;          // length of password
    const uint8_t *passwd; // password
} Socks5UsernamePasswordRequest;

typedef struct {
    uint8_t ver;    // set to X`01` for this version of the protocol
    uint8_t status; // set to X`00` for success, any other value for failure
} Socks5UsernamePasswordResponse;

typedef struct {
    uint8_t ver;        // set to X'05' for this version of the protocol
    uint8_t cmd;        // command id
    uint8_t rsv;        // reserved
    uint8_t atyp;       // address type of following address
    uint8_t dst_addr[]; // desired destination address
    // desired destination port in network octet order
} Socks5Request;

typedef struct {
    uint8_t ver;        // set to X'05' for this version of the protocol
    uint8_t rep;        // reply status
    uint8_t rsv;        // reserved
    uint8_t atyp;       // address type of following address
    uint8_t bnd_addr[]; // server bound address
    // server bound port in network octet order
} Socks5Reply;

typedef struct {
    uint16_t rsv;       // reserved
    uint8_t frag;       // current fragment number
    uint8_t atyp;       // address type of following addresses:
    uint8_t dst_addr[]; // desired destination address
    // desired destination port
    // user data
} Socks5UdpHeader;

#pragma pack(pop)

typedef enum {
    S5CONNS_IDLE,
    S5CONNS_WAITING_USERNAME_PASSWORD,
    S5CONNS_WAITING_REQUEST,
    S5CONNS_WAITING_CONNECT_RESULT,
    S5CONNS_WAITING_ACCEPT,
    S5CONNS_ESTABLISHED,
    S5CONNS_FAILED,
} ConnectionState;

typedef struct {
    struct sockaddr_storage src;
    ag::Socks5ConnectionAddress dst;
} AddressPair;

namespace ag {
static uint64_t socks_addr_hash(const ag::Socks5ConnectionAddress *addr);
static uint64_t socks_addr_pair_hash(const AddressPair *addr);
static bool socks_addr_equals(const ag::Socks5ConnectionAddress *lh, const ag::Socks5ConnectionAddress *rh);
static bool socks_addr_pair_equals(const AddressPair *lh, const AddressPair *rh);
} // namespace ag

struct Connection;
KHASH_MAP_INIT_INT(connections_by_id, Connection *);
KHASH_INIT(connections_by_addr, AddressPair *, Connection *, 1, ag::socks_addr_pair_hash, ag::socks_addr_pair_equals)

typedef struct {
    ag::Socks5Listener *listener;
    uint32_t id;
} SocketArg;

typedef struct {
    struct event *udp_event;
    Connection *tcp_conn;
    khash_t(connections_by_addr) * connections_by_addr;
    uint8_t *packet_buffer;
    SocketArg *event_arg;
} UdpRelay;

KHASH_MAP_INIT_INT(udp_relays_by_id, UdpRelay *);

typedef struct ag::Socks5Listener {
    khash_t(connections_by_id) * connections;
    khash_t(udp_relays_by_id) * udp_relays;
    struct evconnlistener *evconn_listener;
    ag::Socks5ListenerConfig config;
    ag::Socks5ListenerHnadler handler;
    std::string upbuffer;
} Socks5Listener;

typedef struct {
    bool readable;
    size_t sent_bytes_since_flush;
    std::vector<std::vector<uint8_t>> pending_udp_packets;
    UdpRelay *relay;
} UdpSpecific;

typedef struct {
    SocketArg *sock_arg;
} TcpSpecific;

struct Connection {
    ConnectionState state;
    uint64_t id;
    ag::TcpSocket *socket;
    AddressPair addr;
    int proto;
    std::string app_name;
    TcpSpecific tcp;
    UdpSpecific udp;
};

typedef struct {
    Socks5Listener *listener;
    uint64_t id;
} CompleteCtx;

extern "C" int evutil_sockaddr_is_loopback_(const struct sockaddr *sa);

namespace ag {

static void udp_event_handler(evutil_socket_t fd, short what, void *arg);
static void sock_handler(void *arg, TcpSocketEvent what, void *data);
static void on_accept(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *sa, int salen, void *data);
static void on_error(struct evconnlistener *evl, void *arg);
static void destroy_connection(Socks5Listener *listener, Connection *conn);
static void terminate_udp_association(Socks5Listener *listener, Connection *tcp_conn, VpnError error);
static bool is_udp_association_tcp_connection(const Socks5Listener *listener, const Connection *conn);

Socks5Listener *socks5_listener_create(const Socks5ListenerConfig *config, const Socks5ListenerHnadler *handler) {
    auto *listener = new Socks5Listener{};
    if (listener == nullptr) {
        return nullptr;
    }

    listener->connections = kh_init(connections_by_id);
    listener->udp_relays = kh_init(udp_relays_by_id);

    listener->config = *config;
    listener->upbuffer.append(config->username);
    listener->upbuffer.append(config->password);
    listener->config.username = {listener->upbuffer.data(), config->username.size()};
    listener->config.password = {listener->upbuffer.data() + config->username.size(), config->password.size()};

    listener->handler = *handler;

    if (listener->config.listen_address.ss_family == AF_UNSPEC) {
        uint32_t lo = htonl(INADDR_LOOPBACK);
        listener->config.listen_address = sockaddr_from_raw((uint8_t *) &lo, sizeof(lo), 0);
    }

    if (listener->config.username.empty() != listener->config.password.empty()) {
        errlog(g_logger, "Both or neither username and password must be set");
        socks5_listener_destroy(listener);
        return nullptr;
    }

    if (!evutil_sockaddr_is_loopback_((struct sockaddr *) &listener->config.listen_address)
            && listener->config.username.empty()) {
        errlog(g_logger, "Username must be set if listening on a non-loopback address");
        socks5_listener_destroy(listener);
        return nullptr;
    }

    return listener;
}

Socks5ListenerStartResult socks5_listener_start(Socks5Listener *listener) {
    if (listener->evconn_listener == nullptr) {
        sa_family_t family = listener->config.listen_address.ss_family;
        evutil_socket_t fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
        if (fd < 0) {
            errlog(g_logger, "Failed to create socket: {} ({})", strerror(errno), errno);
            return SOCKS5L_START_FAILURE;
        }

        if (0 != evutil_make_socket_nonblocking(fd)) {
            int err = evutil_socket_geterror(fd);
            errlog(g_logger, "Failed to make non-blocking: {} ({})", evutil_socket_error_to_string(err), err);
            evutil_closesocket(fd);
            return SOCKS5L_START_FAILURE;
        }

        if (evutil_make_listen_socket_reuseable(fd) != 0) {
            int err = evutil_socket_geterror(fd);
            errlog(g_logger, "Failed to make reusable: {} ({})", evutil_socket_error_to_string(err), err);
            evutil_closesocket(fd);
            return SOCKS5L_START_FAILURE;
        }

        if (family == AF_INET6 && 0 != make_fd_dual_stack(fd)) {
            int err = evutil_socket_geterror(fd);
            errlog(g_logger, "Failed to make socket dual-stack: {} ({})", evutil_socket_error_to_string(err), err);
            evutil_closesocket(fd);
            return SOCKS5L_START_FAILURE;
        }

        const struct sockaddr_storage *sa = &listener->config.listen_address;
        if (0 != bind(fd, (struct sockaddr *) sa, sockaddr_get_size((struct sockaddr *) sa))) {
            int err = evutil_socket_geterror(fd);
            errlog(g_logger, "Failed to bind socket: {} ({})", evutil_socket_error_to_string(err), err);
            Socks5ListenerStartResult error = SOCKS5L_START_FAILURE;
            if (err ==
#ifdef _WIN32
                    WSAEADDRINUSE
#else
                    EADDRINUSE
#endif
            ) {
                error = SOCKS5L_START_ADDR_IN_USE;
            }
            evutil_closesocket(fd);
            return error;
        }

        listener->evconn_listener = evconnlistener_new(
                vpn_event_loop_get_base(listener->config.ev_loop), on_accept, listener, LEV_OPT_CLOSE_ON_FREE, -1, fd);
        if (listener->evconn_listener == nullptr) {
            errlog(g_logger, "Failed to create evlistener");
            evutil_closesocket(fd);
            return SOCKS5L_START_FAILURE;
        }

        evconnlistener_set_error_cb(listener->evconn_listener, on_error);
    } else {
        if (0 != evconnlistener_enable(listener->evconn_listener)) {
            errlog(g_logger, "Failed to start listener");
            return SOCKS5L_START_FAILURE;
        }
    }

    if (sockaddr_get_port((struct sockaddr *) &listener->config.listen_address) == 0) {
        struct sockaddr_storage addr = local_sockaddr_from_fd(evconnlistener_get_fd(listener->evconn_listener));
        sockaddr_set_port(
                (struct sockaddr *) &listener->config.listen_address, sockaddr_get_port((struct sockaddr *) &addr));
    }

    infolog(g_logger, "Listening on {}", sockaddr_to_str((struct sockaddr *) &listener->config.listen_address));

    return SOCKS5L_START_SUCCESS;
}

void socks5_listener_stop(Socks5Listener *listener) {
    if (listener->evconn_listener != nullptr) {
        evconnlistener_disable(listener->evconn_listener);
    }

    for (khiter_t i = kh_begin(listener->udp_relays); i != kh_end(listener->udp_relays); ++i) {
        if (!kh_exist(listener->udp_relays, i)) {
            continue;
        }

        UdpRelay *relay = kh_value(listener->udp_relays, i);
        terminate_udp_association(listener, relay->tcp_conn, {});
        kh_del(udp_relays_by_id, listener->udp_relays, i);
    }

    khash_t(connections_by_id) *table = listener->connections;
    for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        Connection *conn = kh_value(table, it);
        Socks5ConnectionClosedEvent event = {.id = conn->id};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
        destroy_connection(listener, conn);
    }
}

void socks5_listener_destroy(Socks5Listener *listener) {
    if (listener != nullptr) {
        assert(0 == kh_size(listener->connections));
        assert(0 == kh_size(listener->udp_relays));
        kh_destroy(connections_by_id, listener->connections);
        kh_destroy(udp_relays_by_id, listener->udp_relays);
        if (listener->evconn_listener != nullptr) {
            evconnlistener_free(listener->evconn_listener);
        }
        delete listener;
    }
}

static Socks5AddressType socks_atyp_by_addr(const Socks5ConnectionAddress *addr) {
    Socks5AddressType type = S5AT_IPV4;

    switch (addr->type) {
    case S5CAT_SOCKADDR:
        type = (addr->ip.ss_family == AF_INET) ? S5AT_IPV4 : S5AT_IPV6;
        break;
    case S5CAT_DOMAIN_NAME:
        type = S5AT_DOMAINNAME;
        break;
    }

    return type;
}

static size_t socks_addr_size(const Socks5ConnectionAddress *addr) {
    switch (addr->type) {
    case S5CAT_SOCKADDR:
        return sockaddr_get_ip_size((sockaddr *) &addr->ip);
    case S5CAT_DOMAIN_NAME:
        return 1 + addr->domain.name.length();
    }
}

static void complete_tcp_connection(Socks5Listener *listener, Connection *conn, Socks5ConnectResult result) {
    const Socks5ConnectionAddress *dst = &conn->addr.dst;
    Socks5AddressType atyp = socks_atyp_by_addr(dst);

    std::vector<uint8_t> reply_data(sizeof(Socks5Reply) + socks_addr_size(dst) + sizeof(uint16_t));
    size_t reply_size = sizeof(Socks5Reply);
    switch (atyp) {
    case S5AT_IPV4:
        reply_size += 4;
        break;
    case S5AT_DOMAINNAME:
        reply_size += 1 + dst->domain.name.size();
        break;
    case S5AT_IPV6:
        reply_size += 16;
        break;
    default:
        assert(0);
        break;
    }
    reply_size += 2;

    Socks5Reply *reply = (Socks5Reply *) reply_data.data();
    reply->ver = SOCKS5_VER;
    reply->rep = CONNECT_RESULT_TO_STATUS[result];
    reply->rsv = 0;
    reply->atyp = atyp;

    size_t offset = 0;
    switch (atyp) {
    case S5AT_IPV4:
        memcpy(reply->bnd_addr, sockaddr_get_ip_ptr((struct sockaddr *) &dst->ip), 4);
        offset = 4;
        break;
    case S5AT_DOMAINNAME:
        reply->bnd_addr[0] = uint8_t(dst->domain.name.size());
        memcpy(&reply->bnd_addr[1], dst->domain.name.data(), dst->domain.name.size());
        offset = dst->domain.name.size() + 1;
        break;
    case S5AT_IPV6:
        memcpy(reply->bnd_addr, sockaddr_get_ip_ptr((struct sockaddr *) &dst->ip), 16);
        offset = 16;
        break;
    default:
        assert(0);
        break;
    }

    struct sockaddr_storage local_addr = local_sockaddr_from_fd(tcp_socket_get_fd(conn->socket));
    int port = htons(sockaddr_get_port((struct sockaddr *) &local_addr));
    memcpy(reply->bnd_addr + offset, &port, 2);

    log_conn(listener, conn->id, conn->proto, dbg, "Sending reply");
    VpnError error = tcp_socket_write(conn->socket, reply_data.data(), reply_size);
    if (error.code != 0) {
        log_conn(listener, conn->id, conn->proto, err, "Failed to send socks reply: {} ({})",
                safe_to_string_view(error.text), error.code);
        Socks5ConnectionClosedEvent event = {conn->id, error};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
        destroy_connection(listener, conn);
    }
}

static void send_pending_udp_data(void *arg, TaskId task_id) {
    CompleteCtx *ctx = (CompleteCtx *) arg;
    Socks5Listener *listener = ctx->listener;

    khiter_t i = kh_get(connections_by_id, listener->connections, ctx->id);
    if (i != kh_end(listener->connections)) {
        Connection *conn = kh_value(listener->connections, i);
        Socks5ReadEvent event = {};
        event.id = conn->id;
        for (const auto &pkt : conn->udp.pending_udp_packets) {
            event.data = pkt.data();
            event.length = pkt.size();
            listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_READ, &event);
            if (event.result < 0) {
                destroy_connection(listener, conn);
                break;
            }
        }
    }
}

static void complete_udp_connection(Socks5Listener *listener, Connection *conn, Socks5ConnectResult result) {
    if (result == S5LCR_SUCCESS) {
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_ACCEPTED, &conn->id);
        conn->state = S5CONNS_ESTABLISHED;

        auto *ctx = (CompleteCtx *) malloc(sizeof(CompleteCtx));
        ctx->listener = listener;
        ctx->id = conn->id;
        vpn_event_loop_submit(listener->config.ev_loop, {ctx, send_pending_udp_data, free});
    } else {
        Socks5ConnectionClosedEvent event = {conn->id, {}};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
        destroy_connection(listener, conn);
    }
}

void socks5_listener_complete_connect_request(Socks5Listener *listener, uint64_t id, Socks5ConnectResult result) {
    Connection *conn;

    khiter_t i = kh_get(connections_by_id, listener->connections, id);
    if (i != kh_end(listener->connections)) {
        conn = kh_value(listener->connections, i);
    } else {
        log_conn(listener, id, 0, dbg, "Connection was already closed or didn't exist");
        return;
    }

    if (conn->state == S5CONNS_FAILED) {
        // connection marked as failed isn't reported as closed immediately in case it's needed
        // to send some socks data to client
        return;
    }

    assert(conn->state == S5CONNS_WAITING_CONNECT_RESULT);
    if (result == S5LCR_SUCCESS) {
        conn->state = S5CONNS_WAITING_ACCEPT;
        log_conn(listener, conn->id, conn->proto, dbg, "Connection succeeded");
    } else {
        conn->state = S5CONNS_FAILED;
        log_conn(listener, conn->id, conn->proto, dbg, "Connection failed");
    }

    if (conn->proto == IPPROTO_TCP) {
        complete_tcp_connection(listener, conn, result);
    } else {
        complete_udp_connection(listener, conn, result);
    }
}

int socks5_listener_send_data(Socks5Listener *listener, uint64_t id, const uint8_t *data, size_t length) {
    Connection *conn;

    khiter_t i = kh_get(connections_by_id, listener->connections, id);
    if (i != kh_end(listener->connections)) {
        conn = kh_value(listener->connections, i);
    } else {
        log_conn(listener, id, 0, dbg, "Connection was already closed or didn't exist");
        return -1;
    }

    assert(conn->state == S5CONNS_ESTABLISHED);

    int r = 0;
    if (conn->proto == IPPROTO_TCP) {
        r = tcp_socket_write(conn->socket, data, length).code;
    } else {
        const Socks5ConnectionAddress *dst = &conn->addr.dst;
        Socks5AddressType atyp = socks_atyp_by_addr(dst);

        size_t reply_size = sizeof(Socks5UdpHeader);
        switch (atyp) {
        case S5AT_IPV4:
            reply_size += 4;
            break;
        case S5AT_IPV6:
            reply_size += 16;
            break;
        default:
            assert(0);
            break;
        }
        reply_size += 2;
        reply_size += length;

        uint8_t *reply_data = (uint8_t *) malloc(reply_size);

        Socks5UdpHeader *reply = (Socks5UdpHeader *) reply_data;
        reply->rsv = 0;
        reply->frag = 0;
        reply->atyp = atyp;

        size_t offset = 0;
        switch (atyp) {
        case S5AT_IPV4:
            memcpy(reply->dst_addr, sockaddr_get_ip_ptr((struct sockaddr *) &dst->ip), 4);
            offset = 4;
            break;
        case S5AT_IPV6:
            memcpy(reply->dst_addr, sockaddr_get_ip_ptr((struct sockaddr *) &dst->ip), 16);
            offset = 16;
            break;
        default:
            assert(0);
            break;
        }

        int port = htons(sockaddr_get_port((struct sockaddr *) &dst->ip));
        memcpy(reply->dst_addr + offset, &port, 2);
        offset += 2;

        memcpy(reply->dst_addr + offset, data, length);

        evutil_socket_t fd = event_get_fd(conn->udp.relay->udp_event);
        r = sendto(fd, (const char *) reply_data, reply_size, 0, (struct sockaddr *) &conn->addr.src,
                sockaddr_get_size((struct sockaddr *) &conn->addr.src));
        int err = evutil_socket_geterror(fd);
        if (err == 0 || AG_ERR_IS_EAGAIN(err)) {
            r = 0;
            conn->udp.sent_bytes_since_flush += length;
        } else {
            log_conn(listener, conn->id, IPPROTO_UDP, dbg, "Failed to sendto: {} ({})",
                    evutil_socket_error_to_string(err), err);
        }

        free(reply_data);
    }

    return r;
}

void socks5_listener_turn_read(const Socks5Listener *listener, uint64_t id, bool on) {
    khiter_t i = kh_get(connections_by_id, listener->connections, id);
    if (i != kh_end(listener->connections)) {
        Connection *conn = kh_value(listener->connections, i);
        if (conn->proto == IPPROTO_TCP) {
            tcp_socket_set_read_enabled(conn->socket, on);
        } else {
            conn->udp.readable = on;
        }
    } else {
        log_conn(listener, id, 0, dbg, "Connection was already closed or didn't exist");
    }
}

TcpFlowCtrlInfo socks5_listener_flow_ctrl_info(const Socks5Listener *listener, uint64_t id) {
    TcpFlowCtrlInfo r = {};

    khiter_t i = kh_get(connections_by_id, listener->connections, id);
    if (i != kh_end(listener->connections)) {
        Connection *conn = kh_value(listener->connections, i);
        if (conn->proto == IPPROTO_TCP) {
            r = tcp_socket_flow_control_info(conn->socket);
        } else {
            r = {UDP_MAX_DATAGRAM_SIZE, DEFAULT_SEND_WINDOW_SIZE};
        }
    } else {
        log_conn(listener, id, 0, dbg, "Connection was already closed or didn't exist");
    }

    return r;
}

void socks5_listener_close_connection(Socks5Listener *listener, uint64_t id, bool graceful) {
    khiter_t i = kh_get(connections_by_id, listener->connections, id);
    if (i != kh_end(listener->connections)) {
        Connection *conn = kh_value(listener->connections, i);
        if (!graceful && conn->proto == IPPROTO_TCP) {
            tcp_socket_set_rst(conn->socket);
        }

        Socks5ConnectionClosedEvent event = {conn->id, {}};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
        destroy_connection(listener, conn);
    } else {
        log_conn(listener, id, 0, dbg, "Connection was already closed or didn't exist");
    }
}

const struct sockaddr_storage *socks5_listener_listen_address(const Socks5Listener *listener) {
    return &listener->config.listen_address;
}

static void raise_connect_request(Socks5Listener *listener, const Connection *conn) {
    Socks5ConnectRequestEvent event = {};
    event.id = conn->id;
    event.proto = conn->proto;
    event.src = (struct sockaddr *) &conn->addr.src;
    event.dst = &conn->addr.dst;
    event.app_name = conn->app_name;

    listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECT_REQUEST, &event);
}

static size_t addr_length_from_request(Socks5AddressType type, const uint8_t *data) {
    switch (type) {
    case S5AT_IPV4:
        return 4;
    case S5AT_DOMAINNAME:
        return 1 + data[0];
    case S5AT_IPV6:
        return 16;
    case S5AT_IPV4_APPNAME:
        return 1 + data[0] + 4;
    case S5AT_DOMAINNAME_APPNAME:
        return 1 + data[0] + 1 + data[data[0]];
    case S5AT_IPV6_APPNAME:
        return 1 + data[0] + 16;
    }
    return 0;
}

// Return an application name encoded in a DST.ADDR field if `type` is appropriate, or an empty string otherwise
static std::string app_name_from_request(Socks5AddressType type, const uint8_t *data) {
    std::string str;
    if (type == S5AT_DOMAINNAME_APPNAME || type == S5AT_IPV4_APPNAME || type == S5AT_IPV6_APPNAME) {
        str.assign((char *) data + 1, data[0]);
    }
    return str;
}

static Socks5ConnectionAddress dst_addr_from_request(Socks5AddressType type, const uint8_t *data) {
    Socks5ConnectionAddress addr = {};

    if (type == S5AT_DOMAINNAME_APPNAME || type == S5AT_IPV4_APPNAME || type == S5AT_IPV6_APPNAME) {
        data += data[0] + 1;
        type = (Socks5AddressType) (type ^ 0xf0); // Remove the _APP part
    }

    size_t addr_len = addr_length_from_request(type, data);
    if (type == S5AT_DOMAINNAME) {
        addr.type = S5CAT_DOMAIN_NAME;
        addr.domain.name.assign((char *) &data[1], addr_len - 1);
        addr.domain.port = ntohs(*(uint16_t *) &data[addr_len]);
    } else {
        addr.type = S5CAT_SOCKADDR;
        addr.ip = sockaddr_from_raw(data, addr_len, *(uint16_t *) (data + addr_len));
    }

    return addr;
}

// Return number of bytes consumed, or 0 if need more data
static size_t read_username_password_request(size_t len, const uint8_t *data, Socks5UsernamePasswordRequest *request) {
    if (len < 2) {
        return 0;
    }
    uint8_t ver = data[0];
    uint8_t ulen = data[1];
    len -= 2, data += 2;
    if (len <= ulen) {
        return 0;
    }
    request->uname = data;
    uint8_t plen = data[ulen];
    len -= ulen + 1, data += ulen + 1;
    if (len < plen) {
        return 0;
    }
    request->passwd = data;
    request->ver = ver;
    request->ulen = ulen;
    request->plen = plen;
    return 3 + ulen + plen;
}

static bool socks_addr_equals(const Socks5ConnectionAddress *lh, const Socks5ConnectionAddress *rh) {
    if (lh->type != rh->type) {
        return false;
    }

    switch (lh->type) {
    case S5CAT_SOCKADDR:
        return 0 == memcmp(&lh->ip, &rh->ip, sizeof(lh->ip));
    case S5CAT_DOMAIN_NAME:
        return lh->domain.port == rh->domain.port && lh->domain.name == rh->domain.name;
    }

    return false;
}

static bool socks_addr_pair_equals(const AddressPair *lh, const AddressPair *rh) {
    return 0 == memcmp(&lh->src, &rh->src, sizeof(lh->src)) && socks_addr_equals(&lh->dst, &rh->dst);
}

static uint64_t socks_addr_hash(const Socks5ConnectionAddress *addr) {
    uint64_t hash = 0;

    switch (addr->type) {
    case S5CAT_SOCKADDR:
        hash = sockaddr_hash((struct sockaddr *) &addr->ip);
        break;
    case S5CAT_DOMAIN_NAME: {
        const std::string &domain = addr->domain.name;
        hash = hash_pair_combine(str_hash32(domain.data(), domain.size()), addr->domain.port);
        break;
    }
    }

    return hash;
}

static uint64_t socks_addr_pair_hash(const AddressPair *addr) {
    return hash_pair_combine(sockaddr_hash((struct sockaddr *) &addr->src), socks_addr_hash(&addr->dst));
}

static int handle_tcp_read(Socks5Listener *listener, Connection *conn, const uint8_t *data, size_t length) {
    Socks5ReadEvent event = {conn->id, data, length, 0};
    listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_READ, &event);
    return event.result;
}

static void pend_udp_packet(Connection *conn, const uint8_t *data, size_t length) {
    assert(conn->proto == IPPROTO_UDP);
    conn->udp.pending_udp_packets.emplace_back(data, data + length);
}

// Return number of processed bytes
static size_t handle_udp_read(Socks5Listener *listener, Connection *conn, const uint8_t *data, size_t length) {
    size_t n = length;

    switch (conn->state) {
    case S5CONNS_IDLE:
        conn->state = S5CONNS_WAITING_CONNECT_RESULT;
        raise_connect_request(listener, conn);
        pend_udp_packet(conn, data, length);
        break;
    case S5CONNS_WAITING_ACCEPT:
    case S5CONNS_WAITING_REQUEST:
    case S5CONNS_WAITING_USERNAME_PASSWORD:
        log_conn(listener, conn->id, conn->proto, dbg, "Got UDP packet in wrong state: {}", conn->state);
        assert(0);
        destroy_connection(listener, conn);
        break;
    case S5CONNS_WAITING_CONNECT_RESULT:
        pend_udp_packet(conn, data, length);
        break;
    case S5CONNS_ESTABLISHED: {
        if (!conn->udp.readable) {
            log_conn(listener, conn->id, conn->proto, dbg, "Connection isn't readable, dropping packet ({} bytes)", n);
            break;
        }

        Socks5ReadEvent event = {conn->id, data, length, 0};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_READ, &event);
        if (event.result == 0) {
            n = 0;
        }
        break;
    }
    case S5CONNS_FAILED:
        log_conn(listener, conn->id, conn->proto, dbg, "Connection is in {} state, dropping packet ({} bytes)",
                magic_enum::enum_name(conn->state), n);
        break;
    }

    return n;
}

static struct event *create_udp_event(Socks5Listener *listener, Connection *conn) {
    sa_family_t saf = listener->config.listen_address.ss_family;
    struct sockaddr_storage sa;
    SocketArg *arg;

    evutil_socket_t fd = socket(saf, SOCK_DGRAM, 0);
    if (fd < 0) {
        return nullptr;
    }

    struct event *event = nullptr;

    int r = evutil_make_socket_nonblocking(fd);
    if (r != 0) {
        int err = evutil_socket_geterror(fd);
        errlog(g_logger, "Failed to make socket for UDP traffic non-blocking: {} ({})",
                evutil_socket_error_to_string(err), err);
        goto fail;
    }

    if (evutil_make_listen_socket_reuseable(fd) != 0) {
        int err = evutil_socket_geterror(fd);
        errlog(g_logger, "Failed to make reusable: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    if (saf == AF_INET6) {
        r = make_fd_dual_stack(fd);
        if (r != 0) {
            int err = evutil_socket_geterror(fd);
            errlog(g_logger, "Failed to make socket for UDP traffic dual-stack: {} ({})",
                    evutil_socket_error_to_string(err), err);
            goto fail;
        }
    }

    sa = listener->config.listen_address;
    sockaddr_set_port((struct sockaddr *) &sa, 0);

    if (0 != bind(fd, (struct sockaddr *) &sa, sockaddr_get_size((struct sockaddr *) &sa))) {
        int err = evutil_socket_geterror(fd);
        errlog(g_logger, "Failed to bind socket for UDP traffic: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    arg = (SocketArg *) malloc(sizeof(SocketArg));
    arg->listener = listener;
    arg->id = conn->id;
    event = event_new(
            vpn_event_loop_get_base(listener->config.ev_loop), fd, EV_READ | EV_PERSIST, udp_event_handler, arg);
    if (event == nullptr) {
        errlog(g_logger, "Failed to create event for UDP traffic");
        goto fail;
    }

    if (0 != event_add(event, nullptr)) {
        errlog(g_logger, "Failed to add event for UDP traffic in event base");
        goto fail;
    }

    return event;

fail:
    evutil_closesocket(fd);
    if (event != nullptr) {
        event_free(event);
    }
    return nullptr;
}

static bool complete_udp_association(Socks5Listener *listener, Connection *conn) {
    struct event *udp_event = create_udp_event(listener, conn);
    struct sockaddr_storage bound_addr =
            (udp_event != nullptr) ? local_sockaddr_from_fd(event_get_fd(udp_event)) : sockaddr_storage{};

    Socks5AddressType atyp = socks_atyp_by_addr(&conn->addr.dst);
    if (bound_addr.ss_family == AF_INET) {
        atyp = S5AT_IPV4;
    } else if (bound_addr.ss_family == AF_INET6) {
        atyp = S5AT_IPV6;
    }

    constexpr size_t REPLY_BUFFER_SIZE = 32;
    uint8_t reply_data[REPLY_BUFFER_SIZE];
    size_t reply_size = sizeof(Socks5Reply);
    switch (atyp) {
    case S5AT_IPV4:
        reply_size += 4;
        break;
    case S5AT_IPV6:
        reply_size += 16;
        break;
    default:
        assert(0);
        break;
    }
    reply_size += 2;

    Socks5Reply *reply = (Socks5Reply *) reply_data;
    reply->ver = SOCKS5_VER;
    reply->rep = (udp_event != nullptr) ? S5LCR_SUCCESS : S5LCR_REJECT;
    reply->rsv = 0;
    reply->atyp = atyp;

    int port = htons(sockaddr_get_port((struct sockaddr *) &bound_addr));
    switch (bound_addr.ss_family) {
    case AF_UNSPEC:
        if (atyp == S5AT_IPV4) {
            uint32_t ip = htonl(INADDR_LOOPBACK);
            memcpy(reply->bnd_addr, &ip, 4);
        } else {
            memcpy(reply->bnd_addr, &in6addr_loopback, 16);
        }
        break;
    case AF_INET:
        memcpy(reply->bnd_addr, sockaddr_get_ip_ptr((struct sockaddr *) &bound_addr), 4);
        memcpy(reply->bnd_addr + 4, &port, 2);
        break;
    case AF_INET6:
        memcpy(reply->bnd_addr, sockaddr_get_ip_ptr((struct sockaddr *) &bound_addr), 16);
        memcpy(reply->bnd_addr + 16, &port, 2);
        break;
    }

    if (udp_event != nullptr) {
        assert(kh_end(listener->udp_relays) == kh_get(udp_relays_by_id, listener->udp_relays, conn->id));
        UdpRelay *relay = (UdpRelay *) calloc(1, sizeof(UdpRelay));
        relay->udp_event = udp_event;
        relay->tcp_conn = conn;
        relay->event_arg = (SocketArg *) event_get_callback_arg(udp_event);
        int r;
        khiter_t i = kh_put(udp_relays_by_id, listener->udp_relays, conn->id, &r);
        kh_value(listener->udp_relays, i) = relay;
    }

    log_conn(listener, conn->id, conn->proto, dbg, "Sending reply");
    VpnError error = tcp_socket_write(conn->socket, reply_data, reply_size);
    if (error.code != 0) {
        log_conn(listener, conn->id, conn->proto, err, "Failed to send socks reply: {} ({})",
                safe_to_string_view(error.text), error.code);
        terminate_udp_association(listener, conn, error);
    } else if (udp_event != nullptr) {
        tcp_socket_set_timeout(conn->socket, Millis::max());
        tcp_socket_set_read_enabled(conn->socket, true);
        log_conn(listener, conn->id, 0, dbg, "UDP association started on port {}...",
                sockaddr_get_port((struct sockaddr *) &bound_addr));
    }

    return error.code == 0 && udp_event != nullptr;
}

static int process_udp_header(Socks5Listener *listener, UdpRelay *relay, const uint8_t *data, size_t length,
        const struct sockaddr_storage *src, Connection **out_conn) {
    if (length < sizeof(Socks5UdpHeader)) {
        return 0;
    }

    const Socks5UdpHeader *req = (Socks5UdpHeader *) data;

    size_t addr_len = addr_length_from_request((Socks5AddressType) req->atyp, req->dst_addr);
    if (length < sizeof(Socks5UdpHeader) + addr_len + 2) {
        return 0;
    }

#if STRICT_MODE == 1
    if (req->rsv != 0) {
        dbglog(g_logger, "Got non-zero reserved bytes on UDP relaying connection");
        return -1;
    }
#endif

    if (req->frag != 0) {
        dbglog(g_logger, "UDP reassembling isn't supported");
        return -1;
    }

    switch (req->atyp) {
    case S5AT_IPV4:
    case S5AT_IPV6:
        break;
    case S5AT_DOMAINNAME:
    default:
        dbglog(g_logger, "Got unknown or unsupported address type: {}", (int) req->atyp);
        return false;
    }

    if (relay->connections_by_addr == nullptr) {
        relay->connections_by_addr = kh_init(connections_by_addr);
    }

    Connection *udp_conn = nullptr;

    AddressPair key = {};
    memcpy(&key.src, src, sizeof(*src));
    key.dst = dst_addr_from_request((Socks5AddressType) req->atyp, req->dst_addr);
    khiter_t i = kh_get(connections_by_addr, relay->connections_by_addr, &key);
    if (i == kh_end(relay->connections_by_addr)) {
        udp_conn = new Connection{};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_GENERATE_CONN_ID, &udp_conn->id);
        udp_conn->addr = key;
        udp_conn->proto = IPPROTO_UDP;
        udp_conn->udp.relay = relay;
        udp_conn->app_name = app_name_from_request((Socks5AddressType) req->atyp, req->dst_addr);

        int r;
        i = kh_put(connections_by_addr, relay->connections_by_addr, &udp_conn->addr, &r);
        if (r < 0) {
            dbglog(g_logger, "Failed to put UDP connection in address table");
            destroy_connection(listener, udp_conn);
            return -1;
        }

        kh_value(relay->connections_by_addr, i) = udp_conn;

        assert(kh_end(listener->connections) == kh_get(connections_by_id, listener->connections, udp_conn->id));

        i = kh_put(connections_by_id, listener->connections, udp_conn->id, &r);
        if (r < 0) {
            dbglog(g_logger, "Failed to put UDP connection in table");
            destroy_connection(listener, udp_conn);
            return -1;
        }

        kh_value(listener->connections, i) = udp_conn;

        log_conn(listener, udp_conn->id, udp_conn->proto, trace, "New UDP connection");
    } else {
        assert(kh_exist(relay->connections_by_addr, i));
        udp_conn = kh_value(relay->connections_by_addr, i);
    }

    *out_conn = udp_conn;
    return sizeof(Socks5UdpHeader) + addr_len + 2;
}

static void udp_event_handler(evutil_socket_t fd, short what, void *arg) {
    SocketArg *info = (SocketArg *) arg;
    Socks5Listener *listener = info->listener;

    khiter_t i = kh_get(connections_by_id, listener->connections, info->id);
    khiter_t j = kh_get(udp_relays_by_id, listener->udp_relays, info->id);
    if (i == kh_end(listener->connections) || j == kh_end(listener->udp_relays)) {
        assert(0);
        return;
    }

    Connection *tcp_conn = kh_value(listener->connections, i);
    UdpRelay *relay = kh_value(listener->udp_relays, j);

    if (what & EV_READ) {
        if (relay->packet_buffer == nullptr) {
            relay->packet_buffer = (uint8_t *) malloc(UDP_MAX_DATAGRAM_SIZE);
        }

        uint8_t *buffer = relay->packet_buffer;

        struct sockaddr_storage src = {};
        socklen_t src_len = sizeof(src);

        evutil_socket_t fd = event_get_fd(relay->udp_event);
        int r = recvfrom(fd, (char *) buffer, UDP_MAX_DATAGRAM_SIZE, MSG_PEEK, (struct sockaddr *) &src, &src_len);

        if (r > 0) {
            Connection *conn;
            int processed_bytes = process_udp_header(listener, relay, buffer, r, &src, &conn);
            if (processed_bytes <= 0
                    || 0 != handle_udp_read(listener, conn, buffer + processed_bytes, r - processed_bytes)) {
                // drain packet if it was sent successfully, or drop it if something went wrong;
                // if it was not sent, leave it in buffer and try later
                recvfrom(fd, (char *) buffer, UDP_MAX_DATAGRAM_SIZE, 0, (struct sockaddr *) &src, &src_len);
            }
        } else if (r < 0) {
            VpnError error = make_vpn_error_from_fd(fd);
            if (!AG_ERR_IS_EAGAIN(error.code)) {
                terminate_udp_association(listener, tcp_conn, error);
            }
        }
    } else if (what & EV_TIMEOUT) {
        terminate_udp_association(listener, tcp_conn, make_vpn_from_socket_error(ag::utils::AG_ETIMEDOUT));
    } else {
        dbglog(g_logger, "Unknown event {}", (int) what);
    }
}

static bool is_udp_association_tcp_connection(const Socks5Listener *listener, const Connection *conn) {
    return conn->proto == 0 && kh_end(listener->udp_relays) != kh_get(udp_relays_by_id, listener->udp_relays, conn->id);
}

static void terminate_udp_association(Socks5Listener *listener, Connection *tcp_conn, VpnError error) {
    assert(is_udp_association_tcp_connection(listener, tcp_conn));

    uint32_t tcp_id = tcp_conn->id;
    UdpRelay *udp_relay = kh_value(listener->udp_relays, kh_get(udp_relays_by_id, listener->udp_relays, tcp_id));

    Socks5ConnectionClosedEvent event = {0, error};

    if (udp_relay->connections_by_addr != nullptr) {
        khash_t(connections_by_addr) *table = udp_relay->connections_by_addr;
        for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
            if (!kh_exist(table, it)) {
                continue;
            }
            Connection *conn = kh_value(table, it);
            event.id = conn->id;
            listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
            destroy_connection(listener, conn);
        }
        kh_destroy(connections_by_addr, udp_relay->connections_by_addr);
    }

    if (udp_relay->udp_event != nullptr) {
        evutil_closesocket(event_get_fd(udp_relay->udp_event));
        event_free(udp_relay->udp_event);
        udp_relay->udp_event = nullptr;
    }

    kh_del(udp_relays_by_id, listener->udp_relays,
            kh_get(udp_relays_by_id, listener->udp_relays, udp_relay->tcp_conn->id));

    destroy_connection(listener, udp_relay->tcp_conn);
    udp_relay->tcp_conn = nullptr;

    free(udp_relay->packet_buffer);
    udp_relay->packet_buffer = nullptr;

    free(udp_relay->event_arg);
    free(udp_relay);

    if (error.code == 0) {
        log_conn(listener, tcp_id, 0, dbg, "UDP association terminated");
    } else {
        log_conn(listener, tcp_id, 0, dbg, "UDP association terminated with error: {} ({})",
                safe_to_string_view(error.text), error.code);
    }
}

static void sock_handler(void *arg, TcpSocketEvent what, void *data) {
    SocketArg *info = (SocketArg *) arg;
    Socks5Listener *listener = info->listener;

    if (what == TCP_SOCKET_EVENT_PROTECT) {
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_PROTECT_SOCKET, data);
        return;
    }

    khiter_t i = kh_get(connections_by_id, listener->connections, info->id);
    if (i == kh_end(listener->connections)) {
        free(arg);
        return;
    }

    Connection *conn = kh_value(listener->connections, i);

    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED: {
        // should not get here
        assert(0);
        break;
    }
    case TCP_SOCKET_EVENT_READ: {
        TcpSocketReadEvent *sock_event = (TcpSocketReadEvent *) data;

        if (is_udp_association_tcp_connection(listener, conn)) {
            VpnError error = {};
            if (sock_event->length != 0) {
                error = {-1, "Got some data on TCP socket of UDP assocation session"};
            }
            terminate_udp_association(listener, conn, error);
            break;
        }

        if (sock_event->length == 0) {
            goto close;
        }

        switch (conn->state) {
        case S5CONNS_IDLE: {
            if (sock_event->length < sizeof(Socks5AuthRequest)) {
                break;
            }

            log_conn(listener, conn->id, conn->proto, dbg, "Processing auth request...");

            VpnError error = {};
            Socks5AuthResponse resp = {SOCKS5_VER, 0};
            int chosen_method;
            int supported_method;

            const Socks5AuthRequest *req = (Socks5AuthRequest *) sock_event->data;
            if (req->ver != SOCKS5_VER) {
                log_conn(listener, conn->id, conn->proto, dbg, "Got wrong protocol version: {}", (int) req->ver);
                goto auth_failed;
            }

            if (sock_event->length < sizeof(Socks5AuthRequest) + req->nmethods) {
                // wait all methods
                break;
            }

            chosen_method = -1;
            supported_method =
                    !listener->config.username.empty() ? S5AM_USERNAME_PASSWORD : S5AM_NO_AUTHENTICATION_REQUIRED;
            for (size_t i = 0; i < req->nmethods; ++i) {
                int method = req->methods[i];
                if (method == supported_method) {
                    chosen_method = method;
                    continue; // Maybe next method will be more preferable
                }
                if (method == supported_method + 0x80) { // _APPNAME version is more preferable
                    chosen_method = method;
                    break;
                }
            }

            if (chosen_method < 0) {
                log_conn(listener, conn->id, conn->proto, dbg, "Haven't found any supported authentication method");
                goto auth_failed;
            }

            sock_event->processed = sizeof(Socks5AuthRequest) + req->nmethods;
            if (chosen_method == S5AM_USERNAME_PASSWORD || chosen_method == S5AM_USERNAME_PASSWORD_APPNAME) {
                conn->state = S5CONNS_WAITING_USERNAME_PASSWORD;
            } else {
                conn->state = S5CONNS_WAITING_REQUEST;
            }
            resp.method = chosen_method;

            log_conn(listener, conn->id, conn->proto, dbg, "Auth request processed, sending auth reply");

            goto send_resp;

        auth_failed:
            sock_event->processed = sock_event->length;
            conn->state = S5CONNS_FAILED;
            resp.method = S5AM_NO_ACCEPTABLE_METHODS;

        send_resp:
            error = tcp_socket_write(conn->socket, (uint8_t *) &resp, sizeof(resp));
            if (error.code != 0) {
                log_conn(listener, conn->id, conn->proto, err, "Failed to send socks authentication response: {} ({})",
                        safe_to_string_view(error.text), error.code);
                goto close;
            }

            break;
        }
        case S5CONNS_WAITING_USERNAME_PASSWORD: {
            Socks5UsernamePasswordResponse resp = {.ver = USERNAME_PASSWORD_VER, .status = 1}; // failure response
            Socks5UsernamePasswordRequest req = {0};
            size_t processed = read_username_password_request(sock_event->length, sock_event->data, &req);
            if (processed == 0) {
                break;
            }

            log_conn(listener, conn->id, conn->proto, dbg, "Processing username/password request...");

            if (req.ver != USERNAME_PASSWORD_VER) {
                log_conn(listener, conn->id, conn->proto, dbg, "Got wrong protocol version: {}", (int) req.ver);
                goto uname_passwd_failed;
            }
            sock_event->processed = processed;

            {
                std::string_view username = {(char *) req.uname, req.ulen};
                std::string_view password = {(char *) req.passwd, req.plen};
                if (listener->config.username == username && listener->config.password == password) {
                    resp.status = 0; // success response
                    conn->state = S5CONNS_WAITING_REQUEST;
                    log_conn(listener, conn->id, conn->proto, dbg, "Username/password match");
                    goto uname_passwd_send_resp;
                }
            }

        uname_passwd_failed:
            sock_event->processed = sock_event->length;
            conn->state = S5CONNS_FAILED;

            log_conn(listener, conn->id, conn->proto, dbg, "Username/password processing failed");

            VpnError error;
        uname_passwd_send_resp:
            error = tcp_socket_write(conn->socket, (uint8_t *) &resp, sizeof(resp));
            if (error.code != 0) {
                log_conn(listener, conn->id, conn->proto, err,
                        "Failed to send socks username/password response: {} ({})", safe_to_string_view(error.text),
                        error.code);
                goto close;
            }

            break;
        }
        case S5CONNS_WAITING_REQUEST: {
            if (sock_event->length < sizeof(Socks5Request)) {
                break;
            }

            log_conn(listener, conn->id, conn->proto, dbg, "Processing request...");

            size_t addr_len;
            Socks5ReplyStatus reply_status;

            const Socks5Request *req = (Socks5Request *) sock_event->data;
            if (req->ver != SOCKS5_VER) {
                log_conn(listener, conn->id, conn->proto, dbg, "Got wrong protocol version: {}", (int) req->ver);
                reply_status = S5RS_SOCKS_SERVER_FAILURE;
                goto invalid_request;
            }

            switch (req->cmd) {
            case S5CMD_CONNECT:
                conn->proto = IPPROTO_TCP;
                break;
            case S5CMD_UDP_ASSOCIATE:
                break;
            case S5CMD_BIND:
            default:
                log_conn(listener, conn->id, conn->proto, dbg, "Got unknown or unsupported command id: {}",
                        (int) req->cmd);
                reply_status = S5RS_COMMAND_NOT_SUPPORTED;
                goto invalid_request;
            }

#if STRICT_MODE == 1
            if (req->rsv != 0) {
                log_conn(listener, conn->id, conn->proto, dbg, "Got non-zero reserved bytes");
                reply_status = S5RS_SOCKS_SERVER_FAILURE;
                goto invalid_request;
            }
#endif

            switch (req->atyp) {
            case S5AT_IPV4:
            case S5AT_DOMAINNAME:
            case S5AT_IPV6:
            case S5AT_IPV4_APPNAME:
            case S5AT_DOMAINNAME_APPNAME:
            case S5AT_IPV6_APPNAME:
                break;
            default:
                log_conn(listener, conn->id, conn->proto, dbg, "Got unknown address type: {}", (int) req->atyp);
                reply_status = S5RS_ADDRESS_TYPE_NOT_SUPPORTED;
                goto invalid_request;
            }

            addr_len = addr_length_from_request((Socks5AddressType) req->atyp, req->dst_addr);
            if (sizeof(Socks5Request) + addr_len + 2 > sock_event->length) {
                // wait full address
                break;
            }

            conn->addr.dst = dst_addr_from_request((Socks5AddressType) req->atyp, req->dst_addr);
            conn->app_name = app_name_from_request((Socks5AddressType) req->atyp, req->dst_addr);

            sock_event->processed = sizeof(Socks5Request) + addr_len + 2;

            if (req->cmd == S5CMD_CONNECT) {
                conn->state = S5CONNS_WAITING_CONNECT_RESULT;
                conn->addr.src = remote_sockaddr_from_fd(tcp_socket_get_fd(conn->socket));
                raise_connect_request(listener, conn);
                tcp_socket_set_read_enabled(conn->socket, false);
                log_conn(listener, conn->id, conn->proto, dbg, "Request processed, waiting for connect result");
            } else {
                if (complete_udp_association(listener, conn)) {
                    conn->state = S5CONNS_ESTABLISHED;
                    log_conn(listener, conn->id, conn->proto, dbg, "Request processed, UDP relay set up");
                } else {
                    conn->state = S5CONNS_FAILED;
                }
            }

            break;

        invalid_request:
            sock_event->processed = sock_event->length;
            conn->state = S5CONNS_FAILED;

            addr_len = addr_length_from_request((Socks5AddressType) req->atyp, req->dst_addr);
            size_t reply_size = sizeof(Socks5Reply) + addr_len + 2;
            constexpr size_t REPLY_BUFFER_SIZE = 32;
            uint8_t reply_data[REPLY_BUFFER_SIZE];
            Socks5Reply *reply = (Socks5Reply *) reply_data;
            reply->ver = SOCKS5_VER;
            reply->rep = reply_status;
            reply->rsv = 0;
            reply->atyp = req->atyp;
            memcpy(reply->bnd_addr, req->dst_addr, addr_len);
            struct sockaddr_storage local_addr = local_sockaddr_from_fd(tcp_socket_get_fd(conn->socket));
            int port = htons(sockaddr_get_port((struct sockaddr *) &local_addr));
            memcpy(reply->bnd_addr + addr_len, &port, 2);

            VpnError error = tcp_socket_write(conn->socket, (uint8_t *) reply_data, reply_size);
            if (error.code != 0) {
                log_conn(listener, conn->id, conn->proto, err, "Failed to send socks response: {} ({})",
                        safe_to_string_view(error.text), error.code);
                goto close;
            }

            break;
        }
        case S5CONNS_WAITING_ACCEPT:
        case S5CONNS_WAITING_CONNECT_RESULT:
            log_conn(listener, conn->id, conn->proto, dbg, "Got data in wrong state: {}", conn->state);
            goto close;
        case S5CONNS_ESTABLISHED: {
            log_conn(listener, conn->id, conn->proto, trace, "Got {} bytes", sock_event->length);

            int r = handle_tcp_read(listener, conn, sock_event->data, sock_event->length);
            if (r < 0) {
                goto close;
            }
            sock_event->processed = r;
            break;
        }
        case S5CONNS_FAILED:
            // do nothing, just waiting for flush
            sock_event->processed = sock_event->length;
            break;
        }
        break;
    }
    case TCP_SOCKET_EVENT_ERROR: {
        const VpnError *sock_event = (VpnError *) data;

        if (is_udp_association_tcp_connection(listener, conn)) {
            dbglog(g_logger, "Error on TCP socket of UDP assocation session");
            terminate_udp_association(listener, conn, *sock_event);
            break;
        } else {
            Socks5ConnectionClosedEvent event = {conn->id, *sock_event};
            listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
        }

        goto close;
    }
    case TCP_SOCKET_EVENT_SENT: {
        const TcpSocketSentEvent *sock_event = (TcpSocketSentEvent *) data;

        tracelog(g_logger, "Sent {} bytes", sock_event->bytes);

        if (!is_udp_association_tcp_connection(listener, conn)) {
            switch (conn->state) {
            case S5CONNS_ESTABLISHED: {
                Socks5DataSentEvent event = {conn->id, sock_event->bytes};
                listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_DATA_SENT, &event);
                break;
            }
            default:
                // do nothing
                break;
            }
        }

        break;
    }
    case TCP_SOCKET_EVENT_WRITE_FLUSH: {
        tracelog(g_logger, "Write buffer flushed");

        if (is_udp_association_tcp_connection(listener, conn)) {
            switch (conn->state) {
            case S5CONNS_ESTABLISHED: {
                UdpRelay *relay =
                        kh_value(listener->udp_relays, kh_get(udp_relays_by_id, listener->udp_relays, conn->id));
                if (relay->connections_by_addr == nullptr) {
                    break;
                }

                khash_t(connections_by_addr) *table = relay->connections_by_addr;
                for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
                    if (!kh_exist(table, it)) {
                        continue;
                    }
                    Connection *udp_conn = kh_value(table, it);
                    UdpSpecific *udp = &udp_conn->udp;
                    if (udp_conn->state == S5CONNS_ESTABLISHED && udp->sent_bytes_since_flush > 0) {
                        Socks5DataSentEvent event = {.id = udp_conn->id, .length = udp->sent_bytes_since_flush};
                        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_DATA_SENT, &event);
                        udp->sent_bytes_since_flush = 0;
                    }
                }
                break;
            }
            case S5CONNS_FAILED:
                terminate_udp_association(listener, conn, {-1, ""});
                break;
            default:
                // do nothing
                break;
            }
        } else if (conn->proto == IPPROTO_TCP) {
            switch (conn->state) {
            case S5CONNS_WAITING_ACCEPT: {
                listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_ACCEPTED, &conn->id);
                conn->state = S5CONNS_ESTABLISHED;
                break;
            }
            case S5CONNS_FAILED:
                goto close;
            default:
                // do nothing
                break;
            }
        }

        break;
    }
    case TCP_SOCKET_EVENT_PROTECT: {
        // do nothing, already handled
        break;
    }
    }

    return;

close:
    assert(!is_udp_association_tcp_connection(listener, conn));
    if (conn->state >= S5CONNS_WAITING_CONNECT_RESULT) {
        Socks5ConnectionClosedEvent event = {conn->id, {}};
        listener->handler.func(listener->handler.arg, SOCKS5L_EVENT_CONNECTION_CLOSED, &event);
    }
    destroy_connection(listener, conn);
}

static void on_accept(
        struct evconnlistener *evlistener, evutil_socket_t fd, struct sockaddr *sa, int salen, void *data) {
    Socks5Listener *socks_listener = (Socks5Listener *) data;
    khint_t iter;

    if (g_logger.is_enabled(ag::LogLevel::LOG_LEVEL_DEBUG)) {
        char buf[SOCKADDR_STR_BUF_SIZE];
        sockaddr_to_str(sa, buf, sizeof(buf));
        dbglog(g_logger, "New connection from client {} fd {}", buf, fd);
    }

    Connection *conn = nullptr;

    SocketArg *arg = (SocketArg *) malloc(sizeof(SocketArg));
    arg->listener = socks_listener;
    socks_listener->handler.func(socks_listener->handler.arg, SOCKS5L_EVENT_GENERATE_CONN_ID, &arg->id);

    TcpSocketParameters sock_params = {
            .ev_loop = socks_listener->config.ev_loop,
            .handler = {sock_handler, arg},
            .timeout = socks_listener->config.timeout,
            .socket_manager = socks_listener->config.socket_manager,
            .read_threshold = socks_listener->config.read_threshold,
    };
    TcpSocket *socket = tcp_socket_create(&sock_params);
    if (socket == nullptr) {
        log_conn(socks_listener, arg->id, 0, err, "Failed to create socket");
        goto fail;
    }

    if (0 != tcp_socket_acquire_fd(socket, fd).code) {
        goto fail;
    }

    fd = -1; // will be closed in `tcp_socket_destroy`

    conn = new Connection{};
    if (conn == nullptr) {
        log_conn(socks_listener, arg->id, 0, err, "No memory to create connection");
        goto fail;
    }

    conn->id = arg->id;
    conn->socket = socket;
    conn->tcp.sock_arg = arg;

    // will be destroyed in `destroy_connection`
    socket = nullptr;
    arg = nullptr;

    int r;
    iter = kh_put(connections_by_id, socks_listener->connections, conn->id, &r);
    if (r < 0) {
        log_conn(socks_listener, arg->id, 0, err, "Failed to put connection in table");
        goto fail;
    }
    kh_value(socks_listener->connections, iter) = conn;

    log_conn(socks_listener, conn->id, 0, trace, "New incoming connection");

    tcp_socket_set_read_enabled(conn->socket, true);
    return;

fail:
    if (fd != -1) {
        evutil_closesocket(fd);
    }
    free(arg);
    if (socket != nullptr) {
        tcp_socket_destroy(socket);
    }
    destroy_connection(socks_listener, conn);
}

static void on_error(struct evconnlistener *evl, void *arg) {
    errlog(g_logger, "Connection accept error: {}", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

static void destroy_connection(Socks5Listener *listener, Connection *conn) {
    if (conn != nullptr) {
        khiter_t i = kh_get(connections_by_id, listener->connections, conn->id);
        kh_del(connections_by_id, listener->connections, i);

        if (conn->proto == IPPROTO_TCP || conn->proto == 0) {
            tcp_socket_destroy(conn->socket);
            free(conn->tcp.sock_arg);
        } else {
            UdpSpecific *udp = &conn->udp;
            if (udp->relay->connections_by_addr != nullptr) {
                i = kh_get(connections_by_addr, udp->relay->connections_by_addr, &conn->addr);
                kh_del(connections_by_addr, udp->relay->connections_by_addr, i);
            }
        }

        log_conn(listener, conn->id, conn->proto, trace, "Destroyed");

        delete conn;

        dbglog(g_logger, "Remaining connections: {}", (int) kh_size(listener->connections));
    }
}

} // namespace ag
