#include "vpn/platform.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <assert.h>
#include <cstdlib>
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
#include "tcpip_common.h"
#include "tcpip_util.h"
#include "udp_conn_manager.h"
#include "udp_raw.h"

namespace ag {

#define UDP_MAX_DATAGRAM_SIZE 65535
#define UDP_SND_QUEUE_LIMIT TCP_WND
constexpr auto MAX_IP_HEADER_SIZE = 60;
constexpr auto UDP_HEADER_SIZE = 8;

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
    tcpip_refresh_connection_timeout_with_interval(ctx, common, TCPIP_UDP_TIMEOUT_S);

    err_t r = udp_raw_send(connection, &common->addr.dst_ip, common->addr.dst_port, data, length);
    if (ERR_OK != r) {
        log_conn(connection, err, "Failed to send data: {} ({})", lwip_strerr(r), r);
        udp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id);
        return -1;
    }

    TcpipHandler *callbacks = &ctx->parameters.handler;
    TcpipDataSentEvent event = {connection->common.id, length};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_DATA_SENT, &event);

    return static_cast<int>(length);
}

static void process_new_connection(UdpConnDescriptor *connection) {
    TcpipHandler *callbacks = &connection->common.parent_ctx->parameters.handler;
    TcpipCtx *ctx = connection->common.parent_ctx;
    uint64_t id = connection->common.id;
    const Logger &log = connection->common.parent_ctx->udp.log;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_ACCEPTED, &connection->common.id);

    struct netif *netif = connection->common.parent_ctx->netif;

    std::vector<DeclPtr<pbuf, &pbuf_free>> packets;
    packets.swap(connection->pending_packets);
    connection->pending_packets_bytes = 0;

    for (auto it = packets.begin(); it != packets.end(); ++it) {
        if (it != packets.begin()) {
            if (tcpip_get_connection_by_id(&ctx->udp.connections, id) == nullptr) {
                // connection was closed while processing pending packets
                dbglog(log, "[id={}] Connection was closed while processing pending packets", id);
                return;
            }
        }
        auto &packet = *it;
        log_conn(connection, trace, "Sending queued packet");
        pbuf *buf = packet.release();
        const err_t r = netif_input(buf, netif);
        if (r != ERR_OK) {
            pbuf_free(buf);
            log_conn(connection, err, "netif_input failed: {} ({})", lwip_strerr(r), r);
            udp_cm_close_descriptor(ctx, id);
            return;
        }
    }
}

static void process_rejected_connection(UdpConnDescriptor *connection) {
    connection->state = UDP_CONN_STATE_REJECTED;
}

static void process_unreachable_connection(UdpConnDescriptor *connection) {
    connection->state = UDP_CONN_STATE_UNREACHABLE;
    if (!connection->pending_packets.empty()) {
        struct netif *netif = connection->common.parent_ctx->netif;
        struct pbuf *buf = connection->pending_packets.back().release();
        connection->pending_packets.pop_back();
        if (err_t r = netif_input(buf, netif); r != ERR_OK) {
            pbuf_free(buf);
            log_conn(connection, err, "netif_input failed: {} ({})", lwip_strerr(r), r);
        }
        udp_cm_close_descriptor(connection->common.parent_ctx, connection->common.id);
    }
}

static void process_forwarded_connection(UdpConnDescriptor *connection) {
    process_new_connection(connection);
}

void udp_cm_receive(TcpipCtx *ctx, const ip_addr_t *src_addr, u16_t src_port, const ip_addr_t *dst_addr, u16_t dst_port,
        size_t iovlen, const evbuffer_iovec *iov) {
    auto *connection = (UdpConnDescriptor *) tcpip_get_connection_by_ip(
            &ctx->udp.connections, src_addr, src_port, dst_addr, dst_port);
    if (connection == nullptr) {
        dbglog(ctx->udp.log, "No matching connection was found");
        return;
    }

    TcpipHandler *callbacks = &ctx->parameters.handler;

    TcpipReadEvent event = {connection->common.id, iovlen, iov, 0};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_READ, &event);

    if (event.result >= 0) {
        tcpip_refresh_connection_timeout_with_interval(ctx, &connection->common, TCPIP_UDP_TIMEOUT_S);
    } else {
        udp_cm_close_descriptor(ctx, event.id);
    }
}

void udp_cm_complete_connect_request(TcpipCtx *ctx, UdpConnDescriptor *connection, TcpipAction action) {
    if (connection->state != UDP_CONN_STATE_REQUESTED) {
        log_conn(connection, warn, "Wrong UDP connection state: {}", udp_conn_state_str(connection->state));
        assert(0);
        return;
    }
    connection->state = UDP_CONN_STATE_CONFIRMED;
    tcpip_refresh_connection_timeout_with_interval(ctx, &connection->common, TCPIP_UDP_TIMEOUT_S);

    typedef struct {
        void (*handler)(UdpConnDescriptor *);
        const char *description;
    } CompleteConnectionEntry;

    static const CompleteConnectionEntry COMPLETE_CONNECTION_HANDLERS[] = {
            /** TCPIP_ACT_REJECT */ {process_rejected_connection, "rejecting"},
            /** TCPIP_ACT_BYPASS */ {process_forwarded_connection, "forwarding"},
            /** TCPIP_ACT_DROP */ {process_rejected_connection, "rejecting"},
            /** TCPIP_ACT_REJECT_UNREACHABLE */ {process_unreachable_connection, "rejecting (unreachable)"},
    };

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

    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
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

    free(ctx->udp.input_buffer); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)

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
    log_conn(connection, trace, "Closing connection {}", (void *) connection);

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_CONNECTION_CLOSED, &connection->common.id);

    tcpip_remove_connection(&ctx->udp.connections, &connection->common);

    connection->pending_packets.clear();

    log_conn(connection, trace, "Connection closed {}, {} active connections left", (void *) connection,
            kh_size(ctx->udp.connections.by_id));

    delete connection;
}

void udp_cm_enqueue_incoming_packet(UdpConnDescriptor *connection, struct pbuf *buffer, u16_t header_len) {
    // Restore IP header
    pbuf_header_force(buffer, static_cast<s16_t>(header_len));

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
    auto *connection = new UdpConnDescriptor{};
    if (nullptr == connection) {
        return nullptr;
    }

    TcpipConnection *common = &connection->common;

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_GENERATE_CONN_ID, &common->id);

    common->addr = {*src_addr, src_port, *dst_addr, dst_port};
    common->parent_ctx = ctx;

    tcpip_refresh_connection_timeout_with_interval(ctx, common, TCPIP_UDP_TIMEOUT_S);
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

    SocketAddress src = ip_addr_to_socket_address(&common->addr.src_ip, common->addr.src_port);
    SocketAddress dst = ip_addr_to_socket_address(&common->addr.dst_ip, common->addr.dst_port);

    TcpipConnectRequestEvent event = {
            common->id,
            IPPROTO_UDP,
            &src,
            &dst,
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
    return {
            // MTU — (Max IP Header Size) — (UDP Header Size)
            .send_buffer_size =
                    connection->common.parent_ctx->parameters.mtu_size - MAX_IP_HEADER_SIZE - UDP_HEADER_SIZE,
            .send_window_size = DEFAULT_SEND_WINDOW_SIZE,
    };
}

} // namespace ag
