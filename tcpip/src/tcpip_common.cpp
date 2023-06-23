#include "vpn/platform.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <span>
#include <vector>

#include <common/utils.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>
#include <lwip/netdb.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>

#include "libevent_lwip.h"
#include "tcp_conn_manager.h"
#include "tcpip/tcpip.h"
#include "tcpip_common.h"
#include "tcpip_util.h"
#include "udp_conn_manager.h"
#include "vpn/utils.h"

namespace ag {

#define TIMER_PERIOD_S (TCPIP_DEFAULT_CONNECTION_TIMEOUT_S / 10)

/**
 * Read at most this much packets from TUN fd
 * before deferring until the next event loop iteration.
 */
static constexpr size_t TUN_READ_BUDGET = 64;

static constexpr int DEFAULT_PACKET_POOL_SIZE = 25;
static constexpr const char *NETIF_NAME = "tn";
static constexpr TimerTickNotifyFn TIMER_TICK_NOTIFIERS[] = {
        tcp_cm_timer_tick,
        udp_cm_timer_tick,
};

static void dump_packet_to_pcap(TcpipCtx *ctx, const uint8_t *data, size_t len);
static void dump_packet_iovec_to_pcap(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks);
static void open_pcap_file(TcpipCtx *ctx, const char *pcap_filename);
static void process_input_packet(TcpipCtx *ctx, VpnPacket *packet);
#ifdef __MACH__
static err_t tun_output_to_utun_fd(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks, int family);
#endif /* __MACH__ */
#ifndef _WIN32
static err_t tun_output_to_fd(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks);
#endif
static err_t tun_output_to_callback(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks, int family);

static err_t tun_output(const struct netif *netif, const struct pbuf *packet_buffer, int family) {
    auto *ctx = (TcpipCtx *) netif->state;

    size_t chain_length = pbuf_clen(packet_buffer);
    std::vector<evbuffer_iovec> chunks;
    chunks.reserve(chain_length);

    size_t idx = 0;
    for (const struct pbuf *iter = packet_buffer; (idx < chain_length) && (iter != nullptr); idx++, iter = iter->next) {
        chunks.push_back({
                .iov_base = iter->payload,
                .iov_len = iter->len,
        });
    }

    tracelog(ctx->logger, "TUN output: {} bytes", (int) packet_buffer->tot_len);

    err_t err;
    if (ctx->parameters.tun_fd != -1) {
#ifdef __MACH__
        err = tun_output_to_utun_fd(ctx, {chunks.data(), chunks.size()}, family);
#elif !defined _WIN32
        err = tun_output_to_fd(ctx, {chunks.data(), chunks.size()});
#else
        err = ERR_ARG;
#endif
    } else {
        err = tun_output_to_callback(ctx, {chunks.data(), chunks.size()}, family);
    }

    if (err == ERR_OK && ctx->pcap_fd != -1) {
        dump_packet_iovec_to_pcap(ctx, {chunks.data(), chunks.size()});
    }

    return err;
}

static err_t tun_output_to_callback(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks, int family) {
    TcpipTunOutputEvent info = {family, {chunks.size(), chunks.data()}};

    TcpipHandler *callbacks = &ctx->parameters.handler;
    callbacks->handler(callbacks->arg, TCPIP_EVENT_TUN_OUTPUT, &info);

    return ERR_OK;
}

#ifndef _WIN32
static err_t tun_output_to_fd(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks) {
    err_t err = ERR_OK;

    /* Write packet to TUN */
    ssize_t written = writev(ctx->parameters.tun_fd, chunks.data(), chunks.size());
    if (-1 == written) {
        if (errno == EWOULDBLOCK) {
            err = ERR_MEM;
        } else {
            err = ERR_ABRT;
        }
    }

    return err;
}
#endif // !defined _WIN32

#ifdef __MACH__
struct UtunHdr {
    int family;
};

static err_t tun_output_to_utun_fd(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks, int family) {
    std::vector<evbuffer_iovec> new_chunks;
    new_chunks.reserve(chunks.size() + 1);
    struct UtunHdr hdr = {.family = (int) htonl(family)};
    new_chunks.push_back({.iov_base = &hdr, .iov_len = sizeof(hdr)});
    for (const evbuffer_iovec &chunk : chunks) {
        new_chunks.push_back(chunk);
    }
    return tun_output_to_fd(ctx, {new_chunks.data(), new_chunks.size()});
}
#endif /* __MACH__ */

static err_t tun_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ip4) {
    return tun_output(netif, p, AF_INET);
}

static err_t tun_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ip6) {
    return tun_output(netif, p, AF_INET6);
}

static err_t netif_init_cb(struct netif *netif) {
    const auto *ctx = (TcpipCtx *) netif->state;

    netif->name[0] = NETIF_NAME[0];
    netif->name[1] = NETIF_NAME[1];
    netif->output = tun_output_ipv4;
    netif->output_ip6 = tun_output_ipv6;
    netif->flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    netif->mtu = ctx->parameters.mtu_size;

    return ERR_OK;
}

enum TunReadStatus {
    TRS_OK,     // data was read from tun device and sent to netif driver
    TRS_DROP,   // read data was malformed, so another read is required
    TRS_STOP    // no more data can be read from tun device
};

/**
 * Read data from tun device and send it to netif driver.
 * If packet is VpnPacket was sent to netif driver, its destructor will be called on the driver's side,
 * else call VpnPacket's destructor manually to avoid leak.
 * @param ctx context holder for tcp/ip stack
 * @param packet container for reading data from tun device
 * @return see TunReadStatus fields description
 */
#ifdef __MACH__
static TunReadStatus process_data_from_utun(TcpipCtx *ctx, VpnPacket *packet) {
    UtunHdr hdr{};

    static constexpr int HDR_SIZE = sizeof(hdr);
    evbuffer_iovec iov[] = {
            {.iov_base = &hdr, .iov_len = HDR_SIZE}, {.iov_base = packet->data, .iov_len = ctx->parameters.mtu_size}};
    ssize_t bytes_read = readv(ctx->parameters.tun_fd, iov, std::size(iov));
    if (bytes_read <= 0) {
        if (EWOULDBLOCK != errno) {
            errlog(ctx->logger, "data from UTUN: read failed (errno={})", strerror(errno));
        }
        return TRS_STOP;
    }
    if (bytes_read < HDR_SIZE) {
        errlog(ctx->logger, "data from UTUN: read less than header size bytes");
        return TRS_DROP;
    }

    tracelog(ctx->logger, "data from UTUN: {} bytes", bytes_read);
    packet->size = bytes_read - HDR_SIZE;
    process_input_packet(ctx, packet);
    return TRS_OK;
}
#else  /* __MACH__ */
static TunReadStatus process_data_from_tun(TcpipCtx *ctx, VpnPacket *packet) {

    ssize_t bytes_read = read(ctx->parameters.tun_fd, packet->data, ctx->parameters.mtu_size);
    if (bytes_read <= 0) {
        if (EWOULDBLOCK != errno) {
            errlog(ctx->logger, "data from TUN: read failed (errno={})", strerror(errno));
        }
        return TRS_STOP;
    }
    packet->size = bytes_read;
    tracelog(ctx->logger, "data from TUN: {} bytes", bytes_read);

    process_input_packet(ctx, packet);
    return TRS_OK;
}
#endif /* else of __MACH__ */

struct ZeroCopyPBuf {
    pbuf_custom p;
    VpnPacket v;
};

static void zerocopy_pbuf_free(struct pbuf *buf) {
    auto *buf_custom = (ZeroCopyPBuf *) buf;
    if (buf_custom->v.destructor) {
        buf_custom->v.destructor(buf_custom->v.destructor_arg, buf_custom->v.data);
    }
    delete buf_custom;
}

static pbuf *zerocopy_pbuf_create(VpnPacket *packet) {
    auto *buf_custom = new ZeroCopyPBuf{};
    buf_custom->p.custom_free_function = zerocopy_pbuf_free;
    buf_custom->v = *packet;

    pbuf *buffer = pbuf_alloced_custom(PBUF_RAW, buf_custom->v.size, PBUF_REF, &buf_custom->p,
            buf_custom->v.data, u16_t(buf_custom->v.size));
    if (buffer == nullptr) {
        delete buf_custom;
        return nullptr;
    }
    return buffer;
}

static void process_input_packet(TcpipCtx *ctx, VpnPacket *packet) {
    // Dump to PCap
    if (ctx->pcap_fd != -1) {
        dump_packet_to_pcap(ctx, packet->data, packet->size);
    }

    pbuf *buffer = zerocopy_pbuf_create(packet);
    err_t result = netif_input(buffer, ctx->netif);

    if (ERR_OK != result) {
        pbuf_free(buffer);
        errlog(ctx->logger, "data from TUN: netif_input failed ({})", result);
    }
}

static void tun_event_callback(evutil_socket_t fd, short ev_flag, void *arg) {
    auto *ctx = (TcpipCtx *) arg;
    if (nullptr == ctx) {
        return;
    }

    tracelog(ctx->logger, "tun event: socket {} - events: {}{}{}{}", (int) fd, (ev_flag & EV_TIMEOUT) ? " timeout" : "",
            (ev_flag & EV_READ) ? " read" : "", (ev_flag & EV_WRITE) ? " write" : "",
            (ev_flag & EV_SIGNAL) ? " signal" : "");

    for (size_t i = 0; i < TUN_READ_BUDGET; ++i) {
        TunReadStatus status{};
        VpnPacket packet = ctx->pool->get_packet();
#ifdef __MACH__
        status = process_data_from_utun(ctx, &packet);
#else
        status = process_data_from_tun(ctx, &packet);
#endif
        if (status != TRS_OK && packet.destructor) {
            packet.destructor(packet.destructor_arg, packet.data);
        }
        if (status == TRS_STOP) {
            break;
        }
    }
}

static void timer_callback(evutil_socket_t, short, void *arg) {
    for (auto fn : TIMER_TICK_NOTIFIERS) {
        fn((TcpipCtx *) arg);
    }
}

static bool configure_events(TcpipCtx *ctx) {
    struct event_base *ev_base = vpn_event_loop_get_base(ctx->parameters.event_loop);
    if (nullptr == ev_base) {
        errlog(ctx->logger, "configure: no event base provided");
        return false;
    }

    if (ctx->parameters.tun_fd != -1) {
        ctx->tun_event = event_new(ev_base, ctx->parameters.tun_fd, EV_READ | EV_PERSIST, tun_event_callback, ctx);
        if (nullptr == ctx->tun_event) {
            errlog(ctx->logger, "configure: failed to create TUN event");
            return false;
        }

        int add_result = event_add(ctx->tun_event, EVENT_WITHOUT_TIMEOUT);
        if (-1 == add_result) {
            errlog(ctx->logger, "configure: failed to add TUN event");
            return false;
        }
    } else {
        ctx->tun_event = nullptr;
    }

    ctx->timer_event = event_new(ev_base, EVENT_WITHOUT_FD, EV_PERSIST, timer_callback, ctx);
    if (nullptr == ctx->timer_event) {
        errlog(ctx->logger, "init: failed to create event");
        event_free(ctx->tun_event);
        return false;
    }

    static constexpr struct timeval TV = {.tv_sec = TIMER_PERIOD_S, .tv_usec = 0};
    int add_result = event_add(ctx->timer_event, &TV);
    if (-1 == add_result) {
        errlog(ctx->logger, "configure: failed to add TUN event");
        event_free(ctx->tun_event);
        event_free(ctx->timer_event);
        return false;
    }

    tracelog(ctx->logger, "configure: OK");
    return true;
}

static void release_resources(TcpipCtx *ctx) {
    delete ctx->pool;

    if (ctx->parameters.tun_fd != -1) {
        close(ctx->parameters.tun_fd);
    }
    if (ctx->pcap_fd != -1) {
        close(ctx->pcap_fd);
    }

    free(ctx->tun_input_buffer);

    free(ctx);
}

static void clean_up_events(TcpipCtx *ctx) {
    if (nullptr != ctx->tun_event) {
        event_free(ctx->tun_event);
        ctx->tun_event = nullptr;
    }

    if (ctx->timer_event != nullptr) {
        event_free(ctx->timer_event);
    }
}

TcpipCtx *tcpip_init_internal(const TcpipParameters *params) {
    auto *ctx = (TcpipCtx *) calloc(1, sizeof(TcpipCtx));
    if (nullptr == ctx) {
        errlog(ctx->logger, "init: no memory for operation");
        return nullptr;
    }

    ctx->parameters = *params;
    ctx->parameters.mtu_size = (0 == ctx->parameters.mtu_size) ? DEFAULT_MTU_SIZE : ctx->parameters.mtu_size;
    if (ctx->parameters.tun_fd != -1) {
        ctx->pool = new VpnPacketPool(DEFAULT_PACKET_POOL_SIZE, ctx->parameters.mtu_size);
    }
    if (!configure_events(ctx)) {
        errlog(ctx->logger, "init: failed to create events");
        goto error;
    }

    ctx->tun_input_buffer = (uint8_t *) malloc(ctx->parameters.mtu_size);
    ctx->netif = (netif *) calloc(1, sizeof(struct netif));
    if ((nullptr == ctx->tun_input_buffer) || (nullptr == ctx->netif)) {
        errlog(ctx->logger, "init: no memory for operation");
        goto error;
    }

    if (libevent_lwip_init(ctx) != ERR_OK) {
        errlog(ctx->logger, "lwip init failed");
        goto error;
    }

    netif_add_noaddr(ctx->netif, ctx, &netif_init_cb, netif_input);
    netif_set_default(ctx->netif);
    netif_set_up(ctx->netif);

    if (!tcp_cm_init(ctx) || !udp_cm_init(ctx) || !icmp_rm_init(ctx)) {
        goto error;
    }

    open_pcap_file(ctx, params->pcap_filename);

    return ctx;

error:
    tcpip_close_internal(ctx);
    return nullptr;
}

static void release_lwip_resources(TcpipCtx *ctx) {
    netif_remove(ctx->netif);
    free(ctx->netif);
    libevent_lwip_free();
}

void tcpip_close_internal(TcpipCtx *ctx) {
    tcp_cm_close(ctx);
    udp_cm_close(ctx);
    icmp_rm_close(ctx);

    release_lwip_resources(ctx);
    clean_up_events(ctx);
    release_resources(ctx);
}

void tcpip_refresh_connection_timeout(TcpipCtx *ctx, TcpipConnection *connection) {
    tcpip_refresh_connection_timeout_with_interval(ctx, connection, TCPIP_DEFAULT_CONNECTION_TIMEOUT_S);
}

void tcpip_refresh_connection_timeout_with_interval(TcpipCtx *ctx, TcpipConnection *connection, time_t seconds) {
    timeval current_time{};
    event_base_gettimeofday_cached(vpn_event_loop_get_base(ctx->parameters.event_loop), &current_time);

    timeval timeout_interval{};
    timeout_interval.tv_sec = seconds ? seconds : TCPIP_DEFAULT_CONNECTION_TIMEOUT_S;
    timeout_interval.tv_usec = 0;

    evutil_timeradd(&current_time, &timeout_interval, &connection->conn_timeout);
}

static void dump_packet_to_pcap(TcpipCtx *ctx, const uint8_t *data, size_t len) {
    struct timeval tv;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(ctx->parameters.event_loop), &tv);
    if (pcap_write_packet(ctx->pcap_fd, &tv, data, len) < 0) {
        dbglog(ctx->logger, "pcap: failed to write packet to file");
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
    }
}

static void dump_packet_iovec_to_pcap(TcpipCtx *ctx, std::span<evbuffer_iovec> chunks) {
    struct timeval tv;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(ctx->parameters.event_loop), &tv);
    if (pcap_write_packet_iovec(ctx->pcap_fd, &tv, chunks.data(), chunks.size()) < 0) {
        dbglog(ctx->logger, "pcap: failed to write packet to file");
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
    }
}

static void open_pcap_file(TcpipCtx *ctx, const char *pcap_filename) {
    if (pcap_filename == nullptr) {
        ctx->pcap_fd = -1;
        return;
    }

#ifdef _WIN32
    int flags = O_WRONLY | O_CREAT | O_TRUNC | O_BINARY;
    ctx->pcap_fd = _wopen(ag::utils::to_wstring(pcap_filename).c_str(), flags, 0664);
#else
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    ctx->pcap_fd = open(pcap_filename, flags, 0664);
#endif
    if (ctx->pcap_fd == -1) {
        errlog(ctx->logger, "pcap: can't open output file: {}", strerror(errno));
        return;
    }

    if (pcap_write_header(ctx->pcap_fd) < 0) {
        errlog(ctx->logger, "pcap: failed to write file header: {}", strerror(errno));
        close(ctx->pcap_fd);
        ctx->pcap_fd = -1;
        return;
    }

    infolog(ctx->logger, "started pcap capture");
}

void tcpip_process_input_packets(TcpipCtx *ctx, VpnPackets *packets) {
    tracelog(ctx->logger, "TUN: processing {} input packets", packets->size);

    for (size_t i = 0; i < packets->size; ++i) {
        tracelog(ctx->logger, "TUN: packet length {}", packets->data[i].size);
        process_input_packet(ctx, &packets->data[i]);
    }

    tracelog(ctx->logger, "TUN: processed {} input packets", packets->size);
}

void notify_connection_statistics(TcpipConnection *connection) {
#if ENABLE_STATISTICS
    tcpip_ctx_t *ctx = connection->parent_ctx;
    tcpip_callbacks_t *callbacks = &ctx->parameters.callbacks;

    tcpip_stat_event_t event = {
            connection->id,
            connection->sent_to_server,
            connection->received_from_server,
    };
    callbacks->handler(callbacks->arg, TCPIP_EVENT_STAT_NOTIFY, &event);

    connection->last_sent_to_server = connection->sent_to_server;
    connection->last_received_from_server = connection->received_from_server;
#endif
}

void update_output_statistics(TcpipConnection *connection, const size_t bytes_number) {
#if ENABLE_STATISTICS
    tcpip_ctx_t *ctx = connection->parent_ctx;
    uint16_t mtu_size = ctx->parameters.mtu_size;
    connection->sent_to_server += bytes_number + get_approx_headers_size(bytes_number, IP_PROTO_TCP, mtu_size);

    if (stat_should_be_notified(ctx->parameters.event_base, &connection->next_stat_update,
                connection->sent_to_server - connection->last_sent_to_server)) {
        notify_connection_statistics(connection);
    }
#endif
}

void update_input_statistics(TcpipConnection *connection, size_t bytes_number) {
#if ENABLE_STATISTICS
    tcpip_ctx_t *ctx = connection->parent_ctx;
    uint16_t mtu_size = ctx->parameters.mtu_size;
    connection->received_from_server += bytes_number + get_approx_headers_size(bytes_number, IP_PROTO_UDP, mtu_size);

    if (stat_should_be_notified(ctx->parameters.event_base, &connection->next_stat_update,
                connection->received_from_server - connection->last_received_from_server)) {
        notify_connection_statistics(connection);
    }
#endif
}

TcpipConnection *tcpip_get_connection_by_id(const ConnectionTables *tables, uint64_t id) {
    TcpipConnection *conn = nullptr;

    khiter_t iter = kh_get(connections_by_id, tables->by_id, id);
    if (iter != kh_end(tables->by_id)) {
        conn = kh_value(tables->by_id, iter);
    }

    return conn;
}

uint64_t lwip_ip_addr_hash(const ip_addr_t *addr) {
    sa_family_t family; // NOLINT(cppcoreguidelines-init-variables)
    const void *ip;     // NOLINT(cppcoreguidelines-init-variables)
    if (IP_IS_V4(addr)) {
        family = AF_INET;
        ip = &ip_2_ip4(addr)->addr;
    } else {
        family = AF_INET6;
        ip = ip_2_ip6(addr)->addr;
    }
    return ip_addr_hash(family, ip);
}

uint64_t addr_pair_hash(const AddressPair *addr) {
    uint64_t src_hash = hash_pair_combine(lwip_ip_addr_hash(&addr->src_ip), addr->src_port);
    uint64_t dst_hash = hash_pair_combine(lwip_ip_addr_hash(&addr->dst_ip), addr->dst_port);
    return hash_pair_combine(src_hash, dst_hash);
}

bool addr_pair_equals(const AddressPair *lh, const AddressPair *rh) {
    return lh->src_port == rh->src_port && lh->dst_port == rh->dst_port && ip_addr_cmp(&lh->src_ip, &rh->src_ip)
            && ip_addr_cmp(&lh->dst_ip, &rh->dst_ip);
}

TcpipConnection *tcpip_get_connection_by_ip(const ConnectionTables *tables, const ip_addr_t *src_addr,
        uint16_t src_port, const ip_addr_t *dst_addr, uint16_t dst_port) {
    TcpipConnection *conn = nullptr;

    AddressPair key = {*src_addr, src_port, *dst_addr, dst_port};

    khiter_t iter = kh_get(connections_by_addr, tables->by_addr, &key);
    if (iter != kh_end(tables->by_addr)) {
        conn = kh_value(tables->by_addr, iter);
    }

    return conn;
}

int tcpip_put_connection(ConnectionTables *tables, TcpipConnection *connection) {
    int r;
    khiter_t iter = kh_put(connections_by_id, tables->by_id, connection->id, &r);
    if (r < 0) {
        return 0;
    }
    kh_value(tables->by_id, iter) = connection;

    iter = kh_put(connections_by_addr, tables->by_addr, &connection->addr, &r);
    if (r < 0) {
        kh_del(connections_by_id, tables->by_id, connection->id);
        return 0;
    }
    kh_value(tables->by_addr, iter) = connection;

    return 1;
}

void tcpip_remove_connection(ConnectionTables *tables, TcpipConnection *connection) {
    khiter_t iter = kh_get(connections_by_id, tables->by_id, connection->id);
    if (iter != kh_end(tables->by_id)) {
        kh_del(connections_by_id, tables->by_id, iter);
    }

    iter = kh_get(connections_by_addr, tables->by_addr, &connection->addr);
    if (iter != kh_end(tables->by_addr)) {
        kh_del(connections_by_addr, tables->by_addr, iter);
    }
}

} // namespace ag
