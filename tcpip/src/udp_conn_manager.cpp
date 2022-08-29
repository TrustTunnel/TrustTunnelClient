#include "udp_conn_manager.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/netdb.h>
#include <lwip/timeouts.h>

#include "common/logger.h"
#include "tcpip_common.h"
#include "tcpip_util.h"
#include "udp_raw.h"

namespace ag {

#define UDP_MAX_DATAGRAM_SIZE 65535
#define UDP_SND_QUEUE_LIMIT TCP_WND

#define log_conn(conn_, lvl_, fmt_, ...)                                                                               \
    do {                                                                                                               \
        TcpipConnection *c = (TcpipConnection *) conn_;                                                                \
        lvl_##log(c->parent_ctx->udp.log, "[id={}] " fmt_, ((TcpipConnection *) conn_)->id, ##__VA_ARGS__);            \
    } while (0)

#define udp_conn_state_str(state)                                                                                      \
    (state == UDP_CONN_STATE_IDLE                       ? "idle"                                                       \
                    : state == UDP_CONN_STATE_REQUESTED ? "requested"                                                  \
                    : state == UDP_CONN_STATE_CONFIRMED ? "confirmed"                                                  \
                    : state == UDP_CONN_STATE_REJECTED  ? "rejected"                                                   \
                                                        : "unknown")

static void process_rejected_connection(UdpConnDescriptor *);
static void process_forwarded_connection(UdpConnDescriptor *);

int udp_cm_send_data(UdpConnDescriptor *connection, const uint8_t *data, size_t length) {
    TcpipConnection *common = &connection->common;
    TcpipCtx *ctx = common->parent_ctx;
    tcpip_refresh_connection_timeout(ctx, common);

    err_t r = udp_raw_send(connection, &common->addr.dst_ip, common->addr.dst_port, data, length);
    if (ERR_OK != r) {
        log_conn(connection, err, "Failed to send data: {} ({})", lwip_strerr(r), r);
        udp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id);
        return -1;
    }

    update_input_statistics(common, length);

    TcpipHandler *callbacks = &ctx->parameters.handler;
    TcpipDataSentEvent event = {connection->common.id, length};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_DATA_SENT, &event);

    return length;
}

static void process_new_connection(UdpConnDescriptor *connection) {
    TcpipHandler *callbacks = &connection->common.parent_ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_ACCEPTED, &connection->common.id);

    struct netif *netif = connection->common.parent_ctx->netif;

    std::vector<DeclPtr<pbuf, &pbuf_free>> packets;
    packets.swap(connection->pending_packets);
    connection->pending_packets_bytes = 0;

    for (auto &packet : packets) {
        log_conn(connection, trace, "Sending queued packet");
        pbuf *buf = packet.release();
        const err_t r = netif_input(buf, netif);
        if (r != ERR_OK) {
            pbuf_free(buf);
            log_conn(connection, err, "netif_input failed: {} ({})", lwip_strerr(r), r);
            udp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id);
            break;
        }
    }
}

static void process_rejected_connection(UdpConnDescriptor *connection) {
    connection->state = UDP_CONN_STATE_REJECTED;
}

static void process_forwarded_connection(UdpConnDescriptor *connection) {
    process_new_connection(connection);
}

bool udp_cm_receive(TcpipCtx *ctx, const ip_addr_t *src_addr, u16_t src_port, const ip_addr_t *dst_addr, u16_t dst_port,
        size_t iovlen, const evbuffer_iovec *iov) {
    auto *connection = (UdpConnDescriptor *) tcpip_get_connection_by_ip(
            &ctx->udp.connections, src_addr, src_port, dst_addr, dst_port);
    if (connection == nullptr) {
        dbglog(ctx->udp.log, "No matching connection was found");
        return false;
    }

    TcpipHandler *callbacks = &ctx->parameters.handler;

    TcpipReadEvent event = {connection->common.id, iovlen, iov, 0};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_READ, &event);

    if (event.result >= 0) {
        update_output_statistics(&connection->common, event.result);
        tcpip_refresh_connection_timeout(ctx, &connection->common);
    }

    return event.result >= 0;
}

void udp_cm_complete_connect_request(TcpipCtx *ctx, UdpConnDescriptor *connection, TcpipAction action) {
    if (connection->state != UDP_CONN_STATE_REQUESTED) {
        log_conn(connection, warn, "Wrong UDP connection state: {}", udp_conn_state_str(connection->state));
        assert(0);
        return;
    }
    connection->state = UDP_CONN_STATE_CONFIRMED;
    tcpip_refresh_connection_timeout(ctx, &connection->common);

    typedef struct {
        void (*handler)(UdpConnDescriptor *);
        const char *description;
    } CompleteConnectionEntry;

    static const CompleteConnectionEntry COMPLETE_CONNECTION_HANDLERS[] = {
            [TCPIP_ACT_REJECT] = {process_rejected_connection, "rejecting"},
            [TCPIP_ACT_BYPASS] = {process_forwarded_connection, "forwarding"},
            [TCPIP_ACT_DROP] = {process_rejected_connection, "rejecting"},
            [TCPIP_ACT_REJECT_UNREACHABLE] = {process_rejected_connection, "rejecting"},
    };

    if ((size_t) action >= sizeof(COMPLETE_CONNECTION_HANDLERS) / sizeof(COMPLETE_CONNECTION_HANDLERS[0])) {
        log_conn(connection, err, "unknown action ({})... rejecting connection", action);
        process_rejected_connection(connection);
        return;
    }

    log_conn(connection, dbg, "{} connection", COMPLETE_CONNECTION_HANDLERS[action].description);
    COMPLETE_CONNECTION_HANDLERS[action].handler(connection);
}

bool udp_cm_init(TcpipCtx *ctx) {
    err_t raw_init_result = udp_raw_init(ctx);
    if (ERR_OK != raw_init_result) {
        errlog(ctx->udp.log, "UDP raw initialization has failed");
        udp_cm_close(ctx);
        return false;
    }

    ctx->udp.input_buffer = (uint8_t *) malloc(UDP_MAX_DATAGRAM_SIZE);
    if (nullptr == ctx->udp.input_buffer) {
        errlog(ctx->udp.log, "No memory for operation");
        udp_cm_close(ctx);
        return false;
    }

    ctx->udp.connections.by_id = kh_init(connections_by_id);
    ctx->udp.connections.by_addr = kh_init(connections_by_addr);

    return true;
}

void udp_cm_close(TcpipCtx *ctx) {
    udp_cm_clean_up(ctx);

    udp_raw_close(ctx);

    free(ctx->udp.input_buffer);

    kh_destroy(connections_by_id, ctx->udp.connections.by_id);
    ctx->udp.connections.by_id = nullptr;
    kh_destroy(connections_by_addr, ctx->udp.connections.by_addr);
    ctx->udp.connections.by_addr = nullptr;

    dbglog(ctx->udp.log, "Closed");
}

void udp_cm_clean_up(TcpipCtx *ctx) {
    if (ctx->udp.connections.by_id == nullptr) {
        return;
    }

    khash_t(connections_by_id) *table = ctx->udp.connections.by_id;
    for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        auto *conn = (UdpConnDescriptor *) kh_value(table, it);
        udp_cm_close_descriptor(ctx, conn->common.id);
    }
}

void udp_cm_close_descriptor(TcpipCtx *ctx, uint64_t id) {
    khiter_t i = kh_get(connections_by_id, ctx->udp.connections.by_id, id);
    if (i == kh_end(ctx->udp.connections.by_id)) {
        return;
    }

    auto *connection = (UdpConnDescriptor *) kh_value(ctx->udp.connections.by_id, i);
    log_conn(connection, dbg, "Closing connection {}", (void *) connection);

    notify_connection_statistics(&connection->common);

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_CLOSED, &connection->common.id);

    tcpip_remove_connection(&ctx->udp.connections, &connection->common);

    connection->pending_packets.clear();

    log_conn(connection, dbg, "Connection closed {}, {} active connections left", (void *) connection,
            kh_size(ctx->udp.connections.by_id));

    free(connection);
}

void udp_cm_enqueue_incoming_packet(UdpConnDescriptor *connection, struct pbuf *buffer, u16_t header_len) {
    // Restore IP header
    pbuf_header_force(buffer, header_len);

    if (connection->pending_packets_bytes + buffer->tot_len <= UDP_SND_QUEUE_LIMIT) {
        connection->pending_packets_bytes += buffer->tot_len;
        connection->pending_packets.emplace_back(buffer);
    } else {
        log_conn(connection, dbg, "Dropping packet ({} bytes) due to buffer overflow", (int) buffer->tot_len);
        pbuf_free(buffer);
    }
}

UdpConnDescriptor *udp_cm_create_descriptor(TcpipCtx *ctx, struct pbuf *buffer, u16_t header_len,
        const ip_addr_t *src_addr, u16_t src_port, const ip_addr_t *dst_addr, u16_t dst_port) {
    auto *connection = (UdpConnDescriptor *) calloc(1, sizeof(UdpConnDescriptor));
    if (nullptr == connection) {
        return nullptr;
    }

    TcpipConnection *common = &connection->common;

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_GENERATE_CONN_ID, &common->id);

    common->addr = (AddressPair){*src_addr, src_port, *dst_addr, dst_port};
    common->parent_ctx = ctx;

    tcpip_refresh_connection_timeout(ctx, common);
    tcpip_put_connection(&ctx->udp.connections, common);
    udp_cm_enqueue_incoming_packet(connection, buffer, header_len);

    return connection;
}

void udp_cm_request_connection(TcpipCtx *ctx, UdpConnDescriptor *connection) {
    TcpipConnection *common = &connection->common;
    if (ctx->udp.log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
        char src_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r_pretty(&common->addr.src_ip, src_ip_str, sizeof(src_ip_str));
        char dest_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r_pretty(&common->addr.dst_ip, dest_ip_str, sizeof(dest_ip_str));
        log_conn(connection, trace, "New connection request {}:{} -> {}:{}", src_ip_str, common->addr.src_port,
                dest_ip_str, common->addr.dst_port);
    }

    connection->state = UDP_CONN_STATE_REQUESTED;

    struct sockaddr_storage src = ip_addr_to_sockaddr(&common->addr.src_ip, common->addr.src_port);
    struct sockaddr_storage dst = ip_addr_to_sockaddr(&common->addr.dst_ip, common->addr.dst_port);

    TcpipConnectRequestEvent event = {
            common->id,
            IPPROTO_UDP,
            (struct sockaddr *) &src,
            (struct sockaddr *) &dst,
    };

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECT_REQUEST, &event);
}

void udp_cm_timer_tick(TcpipCtx *ctx) {
    struct timeval now;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(ctx->parameters.event_loop), &now);

    khash_t(connections_by_id) *table = ctx->udp.connections.by_id;
    for (khiter_t it = kh_begin(table); it != kh_end(table); ++it) {
        if (!kh_exist(table, it)) {
            continue;
        }
        auto *conn = (UdpConnDescriptor *) kh_value(table, it);
        if (timercmp(&conn->common.conn_timeout, &now, <)) {
            log_conn(conn, dbg, "Connection has timed out");
            udp_cm_close_descriptor(ctx, conn->common.id);
        }
    }
}

TcpFlowCtrlInfo udp_cm_flow_ctrl_info(const UdpConnDescriptor *connection) {
    return (TcpFlowCtrlInfo){
            // MTU — (Max IP Header Size) — (UDP Header Size)
            connection->common.parent_ctx->parameters.mtu_size - 60 - 8,
            DEFAULT_SEND_WINDOW_SIZE,
    };
}

} // namespace ag
