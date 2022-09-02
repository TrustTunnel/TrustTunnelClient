#include "tcpip_util.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <string.h>

#include <event2/event.h>
#include <event2/util.h>
#include <lwip/ip.h>
#include <lwip/prot/tcp.h>
#include <lwip/udp.h>

#include "pcap_savefile.h"
#include "tcpip/tcpip.h"

namespace ag {

struct sockaddr_storage ip_addr_to_sockaddr(const ip_addr_t *addr, uint16_t port) {
    struct sockaddr_storage sockaddr = {};
    if (IP_IS_V4(addr)) {
        auto *sin = (struct sockaddr_in *) &sockaddr;
        sin->sin_addr.s_addr = ip_2_ip4(addr)->addr;
        sin->sin_port = htons(port);
        sin->sin_family = AF_INET;
#ifdef SIN6_LEN
        sin->sin_len = sizeof(struct sockaddr_in);
#endif
    } else if (IP_IS_V6(addr)) {
        auto *sin = (struct sockaddr_in6 *) &sockaddr;
        memcpy(sin->sin6_addr.s6_addr, ip_2_ip6(addr)->addr, sizeof(ip6_addr_t));
        sin->sin6_port = htons(port);
        sin->sin6_family = AF_INET6;
#ifdef SIN6_LEN
        sin->sin6_len = sizeof(struct sockaddr_in6);
#endif
    }

    return sockaddr;
}

void sockaddr_to_ip_addr(
        const struct sockaddr_storage *sock_addr, ev_socklen_t sock_addr_len, ip_addr_t *out_addr, uint16_t *out_port) {
    if (sock_addr->ss_family == AF_INET) {
        if (sock_addr_len < (ev_socklen_t) sizeof(struct sockaddr_in)) {
            goto fail;
        }
        const auto *sockaddr = (sockaddr_in *) sock_addr;
        ip_2_ip4(out_addr)->addr = sockaddr->sin_addr.s_addr;
        out_addr->type = IPADDR_TYPE_V4;
        *out_port = ntohs(sockaddr->sin_port);
        return;
    }
    if (sock_addr->ss_family == AF_INET6) {
        if (sock_addr_len < (ev_socklen_t) sizeof(struct sockaddr_in6)) {
            goto fail;
        }
        const auto *sockaddr = (sockaddr_in6 *) sock_addr;
        memcpy(ip_2_ip6(out_addr)->addr, sockaddr->sin6_addr.s6_addr, sizeof(ip6_addr_t));
        out_addr->type = IPADDR_TYPE_V6;
        *out_port = ntohs(sockaddr->sin6_port);
        return;
    }
fail:
    *out_addr = IPADDR_ANY_TYPE_INIT;
}

void ipaddr_ntoa_r_pretty(const ip_addr_t *addr, char *buf, int buflen) {
    if (IP_IS_V4(addr)) {
        inet_ntop(AF_INET, &ip_2_ip4(addr)->addr, buf, (ev_socklen_t) buflen);
    } else if (IP_IS_V6(addr)) {
        inet_ntop(AF_INET6, &ip_2_ip6(addr)->addr, buf, (ev_socklen_t) buflen);
    } else {
        inet_ntop(AF_INET6, &IP6_ADDR_ANY6->addr, buf, (ev_socklen_t) buflen);
    }
}

bool stat_should_be_notified(struct event_base *event_base, struct timeval *next_update, size_t bytes_transfered) {
#if ENABLE_STATISTICS
    struct timeval current_time;
    event_base_gettimeofday_cached(event_base, &current_time);

    bool is_time_threshold_reached = timercmp(&current_time, next_update, >);
    bool is_byte_threshold_reached = TCPIP_STAT_NOTIFY_BYTE_THRESHOLD <= bytes_transfered;

    if (is_byte_threshold_reached && is_time_threshold_reached) {
        static const struct timeval notify_interval = {.tv_sec = (time_t) TCPIP_STAT_NOTIFY_PERIOD_MS / 1000,
                .tv_usec = (suseconds_t) (TCPIP_STAT_NOTIFY_PERIOD_MS % 1000) * 1000};
        timeradd(&current_time, &notify_interval, next_update);
        return true;
    }
#endif

    return false;
}

int pcap_write_header(int fd) {
    const struct pcap_file_header pcap_header = {.magic = 0xa1b2c3d4,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = MAX_SUPPORTED_MTU,
            .linktype = LINKTYPE_RAW};
    return write(fd, &pcap_header, sizeof(pcap_header));
}

int pcap_write_packet(int fd, struct timeval *tv, const void *data, size_t len) {
    evbuffer_iovec iov = {.iov_base = (void *) data, .iov_len = len};
    return pcap_write_packet_iovec(fd, tv, &iov, 1);
}

static inline int writev_file(int fd, const evbuffer_iovec *iov, int iov_cnt) {
#ifdef _WIN32
    int r = 0;
    for (int i = 0; i < iov_cnt; i++) {
        r = write(fd, iov[i].iov_base, iov[i].iov_len);
    }
    return r;
#else
    return writev(fd, iov, iov_cnt);
#endif
}

int pcap_write_packet_iovec(int fd, struct timeval *tv, const evbuffer_iovec *iov, int iov_cnt) {
    struct pcap_sf_pkthdr rec = {.ts = {.tv_sec = (int32_t) tv->tv_sec, .tv_usec = (int32_t) tv->tv_usec}, .caplen = 0};

    std::vector<evbuffer_iovec> iovec_pcap;
    iovec_pcap.reserve(iov_cnt + 1);
    iovec_pcap.push_back({
            .iov_base = (void *) &rec,
            .iov_len = sizeof(rec),
    });

    for (int i = 0; i < iov_cnt; i++) {
        iovec_pcap.push_back(iov[i]);
        rec.caplen += iov[i].iov_len;
    }
    rec.len = rec.caplen;

    return writev_file(fd, iovec_pcap.data(), iovec_pcap.size());
}

size_t get_approx_headers_size(size_t bytes_transfered, uint8_t proto_id, uint16_t mtu_size) {
    size_t headers_num = (bytes_transfered + mtu_size - 1) / mtu_size;
    size_t network_header_length = IP_HLEN;
    size_t transport_header_length = (IP_PROTO_TCP == proto_id) ? TCP_HLEN : UDP_HLEN;
    size_t headers_size = (headers_num * (network_header_length + transport_header_length));

    return headers_size;
}

} // namespace ag
