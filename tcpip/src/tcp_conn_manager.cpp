#include "vpn/platform.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <assert.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/util.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/netdb.h>
#include <lwip/timeouts.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "tcp_conn_manager.h"
#include "tcp_raw.h"
#include "tcpip/tcpip.h"
#include "tcpip_common.h"
#include "tcpip_util.h"

namespace ag {

#define FROM_START_OF_BUFFER nullptr

// Copied this constant from netinet/tcp.h, because header conflicts with LWIP
#define TCP_NODELAY 1 /* Turn off Nagle's algorithm. */

#define log_conn(conn_, lvl_, fmt_, ...)                                                                               \
    do {                                                                                                               \
        TcpipConnection *c = (TcpipConnection *) conn_;                                                                \
        lvl_##log(c->parent_ctx->tcp.log, "[id={}] " fmt_, ((TcpipConnection *) conn_)->id, ##__VA_ARGS__);            \
    } while (0)

#define tcp_conn_state_str(state)                                                                                      \
    (state == TCP_CONN_STATE_IDLE                               ? "idle"                                               \
                    : state == TCP_CONN_STATE_REQUESTED         ? "requested"                                          \
                    : state == TCP_CONN_STATE_CONFIRMED         ? "confirmed"                                          \
                    : state == TCP_CONN_STATE_HAVE_RESULT       ? "have-result"                                        \
                    : state == TCP_CONN_STATE_DROP              ? "drop"                                               \
                    : state == TCP_CONN_STATE_UNREACHABLE       ? "unreachable"                                        \
                    : state == TCP_CONN_STATE_ACCEPTED          ? "accepted"                                           \
                    : state == TCP_CONN_STATE_CLOSING_BY_CLIENT ? "closing-by-client"                                  \
                    : state == TCP_CONN_STATE_CLOSING_BY_SERVER ? "closing-by-server"                                  \
                                                                : "unknown")

static void process_forwarded_connection(TcpConnDescriptor *);
static void process_rejected_connection(TcpConnDescriptor *);
static void process_dropped_connection(TcpConnDescriptor *);
static void process_unreachable_connection(TcpConnDescriptor *);

static void tcp_refresh_connection_timeout(TcpConnDescriptor *connection) {
    int timeout;
    switch (connection->state) {
    case TCP_CONN_STATE_ACCEPTED:
        timeout = TCPIP_TCP_TIMEOUT_FOR_ESTABLISHED_S;
        break;
    case TCP_CONN_STATE_HAVE_RESULT:
        timeout = TCPIP_TCP_TIMEOUT_FOR_LOCAL_HANDSHAKE_S;
        break;
    case TCP_CONN_STATE_UNREACHABLE:
        timeout = TCPIP_TCP_TIMEOUT_FOR_UNREACHABLE_S;
        break;
    case TCP_CONN_STATE_DROP:
        timeout = TCPIP_TCP_TIMEOUT_FOR_DROPPED_S;
        break;
    default:
        timeout = TCPIP_DEFAULT_CONNECTION_TIMEOUT_S;
        break;
    }

    tcpip_refresh_connection_timeout_with_interval(connection->common.parent_ctx, &connection->common, timeout);
}

static void process_forwarded_connection(TcpConnDescriptor *connection) {
    TcpipCtx *ctx = connection->common.parent_ctx;

    connection->state = TCP_CONN_STATE_HAVE_RESULT;
    tcp_refresh_connection_timeout(connection);

    pbuf *buf = std::exchange(connection->buffer, nullptr);
    const err_t r = netif_input(buf, ctx->netif);
    if (r != ERR_OK) {
        pbuf_free(buf);
        log_conn(connection, err, "netif_input failed: {} ({})", lwip_strerr(r), r);
        tcp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id, false);
    }
}

void tcp_cm_sent_to_remote(TcpConnDescriptor *connection, size_t n) {
    if (connection->pcb != nullptr) {
        tcp_raw_slide_window(connection->pcb, n);
    }
    tcp_refresh_connection_timeout(connection);
}

static void process_and_close(TcpConnDescriptor *connection) {
    struct netif *netif = connection->common.parent_ctx->netif;
    pbuf *buf = std::exchange(connection->buffer, nullptr);
    const err_t r = netif_input(buf, netif);
    if (r != ERR_OK) {
        pbuf_free(buf);
        log_conn(connection, err, "netif_input failed: {} ({})", lwip_strerr(r), r);
    }
    tcp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id, false);
}

static void process_rejected_connection(TcpConnDescriptor *connection) {
    // mark connection to be rejected in tcp input
    connection->state = TCP_CONN_STATE_REJECTED;
    process_and_close(connection);
}

static void process_dropped_connection(TcpConnDescriptor *connection) {
    connection->state = TCP_CONN_STATE_DROP;
}

static void process_unreachable_connection(TcpConnDescriptor *connection) {
    connection->state = TCP_CONN_STATE_UNREACHABLE;
    process_and_close(connection);
}

bool tcp_cm_init(TcpipCtx *ctx) {

    ctx->tcp.connections.by_id = kh_init(connections_by_id);
    ctx->tcp.connections.by_addr = kh_init(connections_by_addr);

    err_t raw_init_result = tcp_raw_init(ctx);
    if (ERR_OK != raw_init_result) {
        errlog(ctx->tcp.log, "TCP raw initialization failed");
        tcp_cm_close(ctx);
        return false;
    }

    return true;
}

void tcp_cm_close(TcpipCtx *ctx) {
    tcp_raw_destroy(ctx);

    tcp_cm_clean_up(ctx);

    kh_destroy(connections_by_id, ctx->tcp.connections.by_id);
    ctx->tcp.connections.by_id = nullptr;
    kh_destroy(connections_by_addr, ctx->tcp.connections.by_addr);
    ctx->tcp.connections.by_addr = nullptr;

    dbglog(ctx->tcp.log, "Closed");
}

void tcp_cm_clean_up(TcpipCtx *ctx) {
    if (ctx->tcp.connections.by_id == nullptr) {
        return;
    }

    khash_t(connections_by_id) *table = ctx->tcp.connections.by_id;
    for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        auto *conn = (TcpConnDescriptor *) kh_value(table, it);
        tcp_cm_close_descriptor(ctx, conn->common.id, true);
    }
}

void tcp_cm_complete_connect_request(TcpipCtx *, TcpConnDescriptor *connection, TcpipAction action) {
    if (connection->state != TCP_CONN_STATE_REQUESTED) {
        log_conn(connection, warn, "Wrong TCP connection state: {}", tcp_conn_state_str(connection->state));
        assert(0);
        return;
    }
    connection->state = TCP_CONN_STATE_CONFIRMED;
    tcp_refresh_connection_timeout(connection);

    typedef struct {
        void (*handler)(TcpConnDescriptor *);
        const char *description;
    } CompleteConnectionEntry;

    static const CompleteConnectionEntry COMPLETE_CONNECTION_HANDLERS[] = {
            /** TCPIP_ACT_REJECT */ {process_rejected_connection, "rejecting"},
            /** TCPIP_ACT_BYPASS */ {process_forwarded_connection, "forwarding"},
            /** TCPIP_ACT_DROP */ {process_dropped_connection, "dropping"},
            /** TCPIP_ACT_REJECT_UNREACHABLE */ {process_unreachable_connection, "rejecting unreachable"},
    };

    log_conn(connection, dbg, "{} connection", COMPLETE_CONNECTION_HANDLERS[action].description);
    COMPLETE_CONNECTION_HANDLERS[action].handler(connection);
}

int tcp_cm_send_data(TcpConnDescriptor *connection, const uint8_t *data, size_t length) {
    if (connection->pcb == nullptr) {
        // not yet accepted
        return 0;
    }

    size_t available_to_send = tcp_cm_flow_ctrl_info(connection).send_buffer_size;
    size_t bytes_to_send = (available_to_send < length) ? available_to_send : length;

    log_conn(connection, trace, "Available to send = {}, requested to send = {}", available_to_send, length);
    // log_conn(connection, trace, "snd_wnd={} snd_scale={} SND_WND_SCALE={}",
    //         (int)connection->pcb->snd_wnd, (int)connection->pcb->snd_scale,
    //         (int)SND_WND_SCALE(connection->pcb, connection->pcb->snd_wnd));

    if (0 == bytes_to_send) {
        return 0;
    }

    err_t r = tcp_raw_send(connection->pcb, data, bytes_to_send);
    if (ERR_OK != r) {
        // send queue could be overflowed, let the caller try again later
        if (r == ERR_MEM) {
            return 0;
        }
        log_conn(connection, err, "Raw send failed: {} ({})", lwip_strerr(r), r);
        return -1;
    }

    // There is data to send
    r = tcp_output(connection->pcb);
    if (ERR_OK != r) {
        log_conn(connection, err, "Output failed - {} ({})", lwip_strerr(r), r);
        return -1;
    }

    tcp_refresh_connection_timeout(connection);

    return static_cast<int>(bytes_to_send);
}

void tcp_cm_data_sent_notify(TcpConnDescriptor *connection, size_t length) {
    TcpipCtx *ctx = connection->common.parent_ctx;
    TcpipHandler *callbacks = &ctx->parameters.handler;

    TcpipDataSentEvent event = {connection->common.id, length};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_DATA_SENT, &event);
}

void tcp_cm_close_descriptor(TcpipCtx *ctx, uint64_t id, bool graceful) {
    khiter_t i = kh_get(connections_by_id, ctx->tcp.connections.by_id, id);
    if (i == kh_end(ctx->tcp.connections.by_id)) {
        return;
    }

    auto *connection = (TcpConnDescriptor *) kh_value(ctx->tcp.connections.by_id, i);
    log_conn(connection, trace, "Closing connection {}", (void *) connection);

    tcp_raw_close(connection->pcb, graceful);
    connection->pcb = nullptr;

    if (nullptr != connection->buffer) {
        pbuf_free(connection->buffer);
        connection->buffer = nullptr;
    }

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_CLOSED, &connection->common.id);

    tcpip_remove_connection(&ctx->tcp.connections, &connection->common);

    log_conn(connection, trace, "Connection closed {}, {} active connections left", (void *) connection,
            kh_size(ctx->tcp.connections.by_id));

    free(connection); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
}

int tcp_cm_receive(TcpConnDescriptor *connection, size_t iovlen, const evbuffer_iovec *iov) {
    TcpipCtx *ctx = connection->common.parent_ctx;
    TcpipHandler *callbacks = &ctx->parameters.handler;

    TcpipReadEvent event = {connection->common.id, iovlen, iov, 0};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_READ, &event);

    return event.result;
}

TcpConnDescriptor *tcp_cm_create_descriptor(TcpipCtx *ctx, struct pbuf *buffer, const ip_addr_t *src_addr,
        u16_t src_port, const ip_addr_t *dst_addr, u16_t dst_port) {
    static_assert(std::is_trivial_v<TcpConnDescriptor>);
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    auto *connection = (TcpConnDescriptor *) calloc(1, sizeof(TcpConnDescriptor));
    if (nullptr == connection) {
        return nullptr;
    }

    TcpipConnection *common = &connection->common;

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_GENERATE_CONN_ID, &common->id);

    common->addr = {*src_addr, src_port, *dst_addr, dst_port};
    common->parent_ctx = ctx;

    connection->buffer = buffer;

    tcp_refresh_connection_timeout(connection);

    tcpip_put_connection(&ctx->tcp.connections, common);

    return connection;
}

void tcp_cm_request_connection(TcpipCtx *ctx, TcpConnDescriptor *connection) {
    TcpipConnection *common = &connection->common;
    if (ctx->tcp.log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
        char src_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r_pretty(&common->addr.src_ip, src_ip_str, sizeof(src_ip_str));
        char dst_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r_pretty(&common->addr.dst_ip, dst_ip_str, sizeof(dst_ip_str));
        log_conn(connection, trace, "New connection {}:{} -> {}:{}", src_ip_str, common->addr.src_port, dst_ip_str,
                common->addr.dst_port);
    }

    connection->state = TCP_CONN_STATE_REQUESTED;

    SocketAddress src = ip_addr_to_socket_address(&common->addr.src_ip, common->addr.src_port);
    SocketAddress dst = ip_addr_to_socket_address(&common->addr.dst_ip, common->addr.dst_port);

    TcpipConnectRequestEvent event = {
            common->id,
            IPPROTO_TCP,
            &src,
            &dst,
    };

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECT_REQUEST, &event);
}

void tcp_cm_timer_tick(TcpipCtx *ctx) {
    /*
     * Idle timeout for established TCP connections is disabled (set to 1 week)
     * TCP/IP stack should close TCP connections only if one of endpoints is disconnected.
     * https://github.com/AdguardTeam/AdguardForAndroid/issues/1547#issuecomment-344866651
     *
     * However, idle timeout for TCP connections that stale in HAVE_RESULT state in returned
     * If host resets such connections before first ack, handle becomes stale,
     * because for such connections connection event isn't provided to LWIP callbacks.
     * https://github.com/AdguardTeam/AdguardForAndroid/issues/1657#issuecomment-363490895
     *
     * For tunneled connections, there is 30 seconds timeout for connecting to remote host.
     */

    timeval now;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(ctx->parameters.event_loop), &now);

    khash_t(connections_by_id) *table = ctx->tcp.connections.by_id;
    for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        auto *conn = (TcpConnDescriptor *) kh_value(table, it);
        if (timercmp(&conn->common.conn_timeout, &now, <)) {
            log_conn(conn, dbg, "Connection has timed out in state {}", tcp_conn_state_str(conn->state));
            tcp_cm_close_descriptor(ctx, conn->common.id, false);
        }
    }
}

bool tcp_cm_accept(TcpConnDescriptor *connection, struct tcp_pcb *newpcb) {
    connection->state = TCP_CONN_STATE_ACCEPTED;
    connection->pcb = newpcb;
    tcp_refresh_connection_timeout(connection);

    TcpipHandler *callbacks = &connection->common.parent_ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_ACCEPTED, &connection->common.id);

    return true;
}

TcpFlowCtrlInfo tcp_cm_flow_ctrl_info(const TcpConnDescriptor *connection) {
    TcpFlowCtrlInfo r = {};
    if (connection->pcb != nullptr) {
        r = {
                .send_buffer_size = (tcp_sndqueuelen(connection->pcb) < TCP_SND_QUEUELEN)
                        ? tcp_raw_get_out_buf_space(connection->pcb)
                        : 0,
                .send_window_size = size_t(SND_WND_SCALE(connection->pcb, connection->pcb->snd_wnd)),
        };
    }
    return r;
}

} // namespace ag
