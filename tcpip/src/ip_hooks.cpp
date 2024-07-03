#include "vpn/platform.h"

#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/tcp.h>
#include <lwip/udp.h>

#include "ip_hooks.h"
#include "net/utils.h"
#include "tcpip_common.h"

using namespace ag;

static inline int process_tcp(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr, const ip_addr_t *dst_addr);
static inline int process_udp(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr, const ip_addr_t *dst_addr);
static inline int process_icmp(TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr,
        const ip_addr_t *dst_addr, u16_t ttl);
static inline int process_icmp6(TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr,
        const ip_addr_t *dst_addr, u16_t ttl);

#define PASS_PACKET_TO_LWIP(p, header_len) (pbuf_header_force(p, header_len), false)
#define DROP_PACKET(p) (pbuf_free(p), true)
#define PACKET_IS_DEFERRED (true)

int ip4_input_hook(struct pbuf *p, struct netif *inp) {
    if (IP_HLEN > p->len) {
        return PASS_PACKET_TO_LWIP(p, 0);
    }
    auto *ctx = (TcpipCtx *) inp->state;
    struct ip_hdr *iphdr;
    ip_addr_t src_addr;
    // Identify the IP header
    iphdr = (struct ip_hdr *) p->payload;
    if (ip4_addr_isany_val(iphdr->dest) || ip4_addr_isany_val(iphdr->src)) {
        return DROP_PACKET(p);
    }
    // Get source and dest address (dest address is set to interface)
    ip_addr_copy_from_ip4(src_addr, iphdr->src);
    ip_addr_copy_from_ip4(inp->ip_addr, iphdr->dest);
    // Obtain IP header length in number of 32-bit words
    u16_t header_len = IPH_HL(iphdr);
    // Calculate IP header length in bytes
    header_len *= 4;
    if ((header_len > p->len) || (header_len < IP_HLEN)) {
        return PASS_PACKET_TO_LWIP(p, 0);
    }
    pbuf_header_force(p, -(s16_t) header_len);
    // Process payload
    switch (IPH_PROTO(iphdr)) {
    case IP_PROTO_TCP:
        return process_tcp(ctx, p, header_len, &src_addr, &inp->ip_addr);
    case IP_PROTO_UDP:
        return process_udp(ctx, p, header_len, &src_addr, &inp->ip_addr);
    case IP_PROTO_ICMP:
        return process_icmp(ctx, p, header_len, &src_addr, &inp->ip_addr, IPH_TTL(iphdr));
    default:
        return DROP_PACKET(p);
    }
}

int ip6_input_hook(struct pbuf *p, struct netif *inp) {
    if (IP6_HLEN > p->len) {
        return PASS_PACKET_TO_LWIP(p, 0);
    }
    auto *ctx = (TcpipCtx *) inp->state;
    struct ip6_hdr *ip6hdr;
    ip_addr_t src_addr;
    u16_t hlen;
    // Identify the IP header
    ip6hdr = (struct ip6_hdr *) p->payload;
    if (ip6_addr_isany_val(ip6hdr->dest) || ip6_addr_isany_val(ip6hdr->src)) {
        return DROP_PACKET(p);
    }
    // Get source and dest address (dest address is set to interface)
    ip_addr_copy_from_ip6(src_addr, ip6hdr->src);
    ip_addr_copy_from_ip6(inp->ip6_addr[1], ip6hdr->dest);
    inp->ip6_addr_state[1] = IP6_ADDR_PREFERRED;
    // Save next header type
    u8_t nexth = IP6H_NEXTH(ip6hdr);
    u16_t header_len = IP6_HLEN;
    pbuf_header_force(p, -IP6_HLEN);
    // Skip options headers
    while (nexth != IP6_NEXTH_NONE) {
        switch (nexth) {
        case IP6_NEXTH_HOPBYHOP:
        case IP6_NEXTH_DESTOPTS:
        case IP6_NEXTH_ROUTING:
        case IP6_NEXTH_FRAGMENT:
            if (p->len == 0) {
                return PASS_PACKET_TO_LWIP(p, header_len);
            }
            // Get next header type
            nexth = *((u8_t *) p->payload);
            // Get the header length
            hlen = 8 * (1 + *((u8_t *) p->payload + 1));
            if (hlen < p->len) {
                return PASS_PACKET_TO_LWIP(p, header_len);
            }
            header_len += hlen;
            pbuf_header_force(p, -(s16_t) hlen);
            break;
        default:
            goto options_done;
        }
    }
options_done:
    // Process payload
    switch (nexth) {
    case IP6_NEXTH_TCP:
        return process_tcp(ctx, p, header_len, &src_addr, &inp->ip6_addr[1]);
    case IP6_NEXTH_UDP:
        return process_udp(ctx, p, header_len, &src_addr, &inp->ip6_addr[1]);
    case IP6_NEXTH_ICMP6:
    case IP6_NEXTH_NONE:
        return process_icmp6(ctx, p, header_len, &src_addr, &inp->ip6_addr[1], IP6H_HOPLIM(ip6hdr));
    default:
        return DROP_PACKET(p);
    }
}

static inline int forward_existing_tcp_entry(TcpConnDescriptor *entry, struct tcp_pcb_listen *pcb, struct pbuf *buffer,
        u16_t header_len, u16_t destination_port) {
    entry->buffer = nullptr;
    pcb->local_port = destination_port;
    return PASS_PACKET_TO_LWIP(buffer, header_len);
}

static inline int process_new_tcp_connection(TcpipCtx *ctx, struct pbuf *buffer, u16_t header_len,
        const ip_addr_t *source_addr, u16_t source_port, const ip_addr_t *destination_addr, u16_t destination_port) {
    pbuf_header_force(buffer, header_len);

    TcpConnDescriptor *entry =
            tcp_cm_create_descriptor(ctx, buffer, source_addr, source_port, destination_addr, destination_port);
    if (nullptr == entry) {
        return DROP_PACKET(buffer);
    }

    tcp_cm_request_connection(ctx, entry);
    return PACKET_IS_DEFERRED;
}

static void icmp6_dest_unreach_hook(
        struct pbuf *p, enum icmp6_dur_code c, const ip_addr_t *src_addr, struct netif *netif) {
    // Since LWIP 2.1.0 icmp6_dest_unreach takes params from current state, not from packet.
    // But we are in IP hook and state is not set yet.
    // https://github.com/AdguardTeam/CoreLibs/issues/584
    ip_current_netif() = netif;
    ip6_addr_copy(*ip6_current_src_addr(), *ip_2_ip6(src_addr));
    icmp6_dest_unreach(p, c);
    ip6_addr_set_zero(ip6_current_src_addr());
    ip_current_netif() = nullptr;
}

static inline int process_tcp(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr, const ip_addr_t *dst_addr) {
    if (p->len < TCP_HLEN) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    auto *hdr = (tcp_hdr *) p->payload;
    uint32_t tcp_flags = TCPH_FLAGS(hdr);
    if (!(tcp_flags & (TCP_SYN | TCP_RST))) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    u16_t src_port = ntohs(hdr->src);
    u16_t dst_port = ntohs(hdr->dest);
    auto *entry = (TcpConnDescriptor *) tcpip_get_connection_by_ip(
            &ctx->tcp.connections, src_addr, src_port, dst_addr, dst_port);

    if (tcp_flags & TCP_RST) {
        if (entry != nullptr && entry->state == TCP_CONN_STATE_HAVE_RESULT) {
            tcp_cm_close_descriptor(ctx, entry->common.id, false);
        }
        return PASS_PACKET_TO_LWIP(p, header_len);
    }

    if (entry != nullptr) {
        switch (entry->state) {
        case TCP_CONN_STATE_UNREACHABLE:
            pbuf_header_force(p, header_len);
            if (IP_IS_V4(src_addr)) {
                icmp_dest_unreach(p, ICMP_DUR_NET);
            } else {
                icmp6_dest_unreach_hook(p, ICMP6_DUR_NO_ROUTE, src_addr, ctx->netif);
            }
            return DROP_PACKET(p);
        case TCP_CONN_STATE_HAVE_RESULT:
            return forward_existing_tcp_entry(
                    entry, (struct tcp_pcb_listen *) ctx->tcp.tun_pcb, p, header_len, dst_port);
        case TCP_CONN_STATE_REJECTED:
            return forward_existing_tcp_entry(entry, (struct tcp_pcb_listen *) ctx->tcp.tun_pcb, p, header_len, -1);
        default:
            // if not yet confirmed by application, drop syn packets
            return DROP_PACKET(p);
        }
    } else {
        return process_new_tcp_connection(ctx, p, header_len, src_addr, src_port, dst_addr, dst_port);
    }
}

static inline int forward_existing_udp_entry(
        UdpConnDescriptor *, struct udp_pcb *pcb, struct pbuf *buffer, u16_t header_len, u16_t destination_port) {
    pcb->local_port = destination_port;
    return PASS_PACKET_TO_LWIP(buffer, header_len);
}

static inline int process_new_udp_connection(TcpipCtx *ctx, UdpConnDescriptor *entry, struct pbuf *buffer,
        u16_t header_len, const ip_addr_t *source_addr, u16_t source_port, const ip_addr_t *destination_addr,
        u16_t destination_port) {
    if (nullptr == entry) {
        entry = udp_cm_create_descriptor(
                ctx, buffer, header_len, source_addr, source_port, destination_addr, destination_port);
        if (nullptr == entry) {
            return DROP_PACKET(buffer);
        }
    } else {
        udp_cm_enqueue_incoming_packet(entry, buffer, header_len);
    }

    udp_cm_request_connection(ctx, entry);
    return PACKET_IS_DEFERRED;
}

static inline int process_udp(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src_addr, const ip_addr_t *dst_addr) {
    if (p->len < UDP_HLEN) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }

    auto *hdr = (udp_hdr *) p->payload;
    u16_t src_port = ntohs(hdr->src);
    u16_t dst_port = ntohs(hdr->dest);

    auto *entry = (UdpConnDescriptor *) tcpip_get_connection_by_ip(
            &ctx->udp.connections, src_addr, src_port, dst_addr, dst_port);

    if (nullptr != entry) {
        switch (entry->state) {
        case UDP_CONN_STATE_REJECTED:
            return DROP_PACKET(p);
        case UDP_CONN_STATE_REQUESTED:
            // requested, but not yet confirmed
            udp_cm_enqueue_incoming_packet(entry, p, header_len);
            return PACKET_IS_DEFERRED;
        default:
            return forward_existing_udp_entry(entry, ctx->udp.tun_pcb, p, header_len, dst_port);
        }
    } else {
        return process_new_udp_connection(ctx, entry, p, header_len, src_addr, src_port, dst_addr, dst_port);
    }
}

static int finalize_icmp_request(TcpipCtx *ctx, IcmpRequestDescriptor *request, struct pbuf *buffer, u16_t header_len) {
    // It was set to the original destination address in `ip4_input_hook`, but in case the message
    // is not an echo reply the source address may not be the same as the original destination
    ip4_addr_copy(*ip_2_ip4(&ctx->netif->ip_addr), *ip_2_ip4(&request->reply_src));

    switch (request->reply_type) {
    case ICMP_MT_ECHO_REPLY:
        return PASS_PACKET_TO_LWIP(buffer, header_len);
    case ICMP_MT_DESTINATION_UNREACHABLE:
        pbuf_header_force(buffer, header_len);
        icmp_dest_unreach(buffer, (icmp_dur_type) request->reply_code);
        return DROP_PACKET(buffer);
    case ICMP_MT_TIME_EXCEEDED:
        pbuf_header_force(buffer, header_len);
        icmp_time_exceeded(buffer, (icmp_te_type) request->reply_code);
        return DROP_PACKET(buffer);
    default:
        return DROP_PACKET(buffer);
    }
}

// Since LWIP 2.1.0 icmp6_dest_unreach takes params from current state, not from packet.
// But we are in IP hook and state is not set yet.
// https://github.com/AdguardTeam/CoreLibs/issues/584
static void icmp6_err_message_hook_enter(const ip_addr_t *src_addr, struct netif *netif) {
    ip_current_netif() = netif;
    ip6_addr_copy(*ip6_current_src_addr(), *ip_2_ip6(src_addr));
}

static void icmp6_err_message_hook_exit() {
    ip6_addr_set_zero(ip6_current_src_addr());
    ip_current_netif() = nullptr;
}

static int finalize_icmpv6_request(TcpipCtx *ctx, IcmpRequestDescriptor *request, struct pbuf *buffer, u16_t header_len) {
    // It was set to the original destination address in `ip6_input_hook`, but in case the message
    // is not an echo reply the source address may not be the same as the original destination
    ip6_addr_copy(*ip_2_ip6(&ctx->netif->ip6_addr[1]), *ip_2_ip6(&request->reply_src));

    switch (request->reply_type) {
    case ICMPV6_MT_DESTINATION_UNREACHABLE:
        icmp6_err_message_hook_enter(&request->src, ctx->netif);
        pbuf_header_force(buffer, header_len);
        icmp6_dest_unreach(buffer, (icmp6_dur_code) request->reply_code);
        icmp6_err_message_hook_exit();
        return DROP_PACKET(buffer);
    case ICMPV6_MT_TIME_EXCEEDED:
        icmp6_err_message_hook_enter(&request->src, ctx->netif);
        pbuf_header_force(buffer, header_len);
        icmp6_time_exceeded(buffer, (icmp6_te_code) request->reply_code);
        icmp6_err_message_hook_exit();
        return DROP_PACKET(buffer);
    case ICMPV6_MT_ECHO_REPLY:
        return PASS_PACKET_TO_LWIP(buffer, header_len);
    default:
        return DROP_PACKET(buffer);
    }
}

static int forward_existing_icmp_entry(
        TcpipCtx *ctx, IcmpRequestDescriptor *request, struct pbuf *buffer, u16_t header_len) {

    int r = IP_IS_V4(&request->src) ? finalize_icmp_request(ctx, request, buffer, header_len)
                                    : finalize_icmpv6_request(ctx, request, buffer, header_len);

    request->buffer = nullptr;
    icmp_rm_close_descriptor(ctx, request);

    return r;
}

static inline int process_new_icmp_request(TcpipCtx *ctx, struct pbuf *buffer, u16_t header_len, const ip_addr_t *src,
        const ip_addr_t *dst, u16_t id, u16_t seqno, u16_t ttl) {
    pbuf_header_force(buffer, (s16_t) header_len);

    IcmpRequestDescriptor *request = icmp_rm_create_descriptor(ctx, src, dst, id, seqno, ttl, buffer);
    if (request == nullptr) {
        return DROP_PACKET(buffer);
    }

    if (0 != icmp_rm_start_request(ctx, request)) {
        request->buffer = nullptr;
        icmp_rm_close_descriptor(ctx, request);
        return DROP_PACKET(buffer);
    }

    return PACKET_IS_DEFERRED;
}

static inline int process_icmp_req(TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src,
        const ip_addr_t *dst, uint16_t id, uint16_t seqno, u16_t ttl) {
    IcmpRequestDescriptor *request = icmp_rm_find_descriptor(ctx, id, seqno);
    if (request != nullptr) {
        return forward_existing_icmp_entry(ctx, request, p, header_len);
    }
    return process_new_icmp_request(ctx, p, header_len, src, dst, id, seqno, ttl);
}

static inline int process_icmp(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src, const ip_addr_t *dst, u16_t ttl) {
    if (p->tot_len < sizeof(struct icmp_echo_hdr)) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    auto *iecho = (icmp_echo_hdr *) p->payload;
    if (iecho->type != ICMP_ECHO) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    return process_icmp_req(ctx, p, header_len, src, dst, iecho->id, iecho->seqno, ttl);
}

static inline int process_icmp6(
        TcpipCtx *ctx, struct pbuf *p, u16_t header_len, const ip_addr_t *src, const ip_addr_t *dst, u16_t ttl) {
    if (p->tot_len < sizeof(struct icmp6_echo_hdr)) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    auto *iecho = (icmp6_echo_hdr *) p->payload;
    if (iecho->type != ICMP6_TYPE_EREQ) {
        return PASS_PACKET_TO_LWIP(p, header_len);
    }
    return process_icmp_req(ctx, p, header_len, src, dst, iecho->id, iecho->seqno, ttl);
}
