#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <algorithm>
#include <iterator>
#include <vector>

#include <event2/buffer.h>
#include <event2/util.h>
#include <lwip/inet_chksum.h>
#include <lwip/ip_addr.h>

#include "common/socket_address.h"
#include "tcpip/tcpip.h"
#include "tcpip_util.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

using namespace ag;

#define ASSERT(x)                                                                                                      \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "FAILED: %s", #x);                                                                         \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)

void test_socket_address_to_ip_addr() {
    // Test IPv4
    {
        // Set
        struct sockaddr_in in4;
        in4.sin_family = AF_INET;
        ASSERT(inet_pton(AF_INET, "192.0.2.1", &in4.sin_addr) > 0);
        in4.sin_port = htons(12344);

        // Convert
        ip_addr_t ip4;
        uint16_t ip4_port;
        socket_address_to_ip_addr(SocketAddress((const sockaddr *) &in4), &ip4, &ip4_port);

        // Check
        ip_addr_t ip4_check;
        ASSERT(ipaddr_aton("192.0.2.1", &ip4_check));
        ASSERT(ip_addr_cmp(&ip4, &ip4_check));
        ASSERT(ip4_port == 12344);
    }

    // Test IPv6
    {
        // Set
        struct sockaddr_in6 in6;
        in6.sin6_family = AF_INET6;
        ASSERT(inet_pton(AF_INET6, "2001:db8:2017::1", &in6.sin6_addr) > 0);
        in6.sin6_port = htons(12346);

        // Convert
        ip_addr_t ip6;
        uint16_t ip6_port;
        socket_address_to_ip_addr(SocketAddress((const struct sockaddr *) &in6), &ip6, &ip6_port);

        // Check
        ip_addr_t ip6_check;
        ASSERT(ipaddr_aton("2001:db8:2017::1", &ip6_check));
        ASSERT(ip_addr_cmp(&ip6, &ip6_check));
        ASSERT(ip6_port == 12346);
    }
}

void test_ip_addr_to_socket_address() {
    // Test IPv4
    {
        // Set
        ip_addr_t ip4;
        constexpr uint16_t ip4_port = 12334;
        ASSERT(ipaddr_aton("192.0.2.2", &ip4));

        // Convert
        SocketAddress in4 = ip_addr_to_socket_address(&ip4, ip4_port);
        socklen_t in4_len = in4.c_socklen();

        // Check
        ASSERT(in4.is_ipv4());
        ASSERT(in4_len == sizeof(struct sockaddr_in));
        struct sockaddr_in *pin = (struct sockaddr_in *) &in4;
        ASSERT(pin->sin_port == PP_HTONS(12334));
        struct in_addr sin_addr_check;
        ASSERT(inet_pton(AF_INET, "192.0.2.2", &sin_addr_check) > 0);
        ASSERT(!memcmp(&pin->sin_addr, &sin_addr_check, sizeof(struct in_addr)));
    }

    // Test IPv6
    {
        // Set
        ip_addr_t ip6;
        constexpr uint16_t ip6_port = 12335;
        ASSERT(ipaddr_aton("2001:db8:2017::2", &ip6));

        // Convert
        SocketAddress in6 = ip_addr_to_socket_address(&ip6, ip6_port);
        socklen_t in6_len = in6.c_socklen();

        // Check
        ASSERT(in6.is_ipv6());
        ASSERT(in6_len == sizeof(struct sockaddr_in6));
        struct sockaddr_in6 *pin6 = (struct sockaddr_in6 *) &in6;
        ASSERT(pin6->sin6_port == PP_HTONS(12335));
        struct in6_addr sin6_addr_check;
        ASSERT(inet_pton(AF_INET6, "2001:db8:2017::2", &sin6_addr_check) > 0);
        ASSERT(!memcmp(&pin6->sin6_addr, &sin6_addr_check, sizeof(struct in6_addr)));
    }
}

void test_tun_read_status() {
    // Data read, errno irrelevant
    ASSERT(TRS_OK == tun_read_status(1, EBADF));
    ASSERT(TRS_OK == tun_read_status(1500, 0));

    // Transient
    ASSERT(TRS_STOP == tun_read_status(-1, EWOULDBLOCK));
    ASSERT(TRS_STOP == tun_read_status(-1, EAGAIN));
    ASSERT(TRS_STOP == tun_read_status(-1, EINTR));

    // Will not clear
    ASSERT(TRS_FATAL == tun_read_status(-1, EBADF));
#ifdef EBADFD
    ASSERT(TRS_FATAL == tun_read_status(-1, EBADFD));
#endif
    ASSERT(TRS_FATAL == tun_read_status(-1, EIO));
    ASSERT(TRS_FATAL == tun_read_status(-1, ENXIO));

    // End of file, errno not consulted
    ASSERT(TRS_FATAL == tun_read_status(0, 0));
    ASSERT(TRS_FATAL == tun_read_status(0, EWOULDBLOCK));
}

struct UdpDatagramTest {
    TcpipCtx *stack = nullptr;
    std::vector<std::vector<uint8_t>> messages;
};

static void udp_test_handler(void *arg, TcpipEvent event, void *message) {
    auto *state = static_cast<UdpDatagramTest *>(arg);
    switch (event) {
    case TCPIP_EVENT_GENERATE_CONN_ID:
        *static_cast<uint64_t *>(message) = 1;
        break;
    case TCPIP_EVENT_CONNECT_REQUEST: {
        const auto *request = static_cast<TcpipConnectRequestEvent *>(message);
        ASSERT(request->proto == IPPROTO_UDP);
        tcpip_complete_connect_request(state->stack, request->id, TCPIP_ACT_BYPASS);
        break;
    }
    case TCPIP_EVENT_READ: {
        auto *read = static_cast<TcpipReadEvent *>(message);
        for (size_t index = 0; index < read->iovlen; ++index) {
            const auto &chunk = read->iov[index];
            const auto *data = static_cast<const uint8_t *>(chunk.iov_base);
            state->messages.emplace_back(data, data + chunk.iov_len);
            read->result += static_cast<int>(chunk.iov_len);
        }
        break;
    }
    default:
        break;
    }
}

static void put_network_u16(uint8_t *bytes, uint16_t value) {
    bytes[0] = static_cast<uint8_t>(value >> 8);
    bytes[1] = static_cast<uint8_t>(value);
}

static void test_udp_datagram_boundary(uint32_t mtu, size_t payload_length) {
    constexpr size_t IPV4_HEADER_SIZE = 20;
    constexpr size_t UDP_HEADER_SIZE = 8;
    constexpr uint8_t SOURCE[] = {192, 0, 2, 1};
    constexpr uint8_t DESTINATION[] = {198, 51, 100, 1};

    UdpDatagramTest state;
    VpnEventLoop *loop = vpn_event_loop_create();
    ASSERT(loop != nullptr);
    TcpipParameters parameters{
            .tun_fd = -1, .event_loop = loop, .mtu_size = mtu, .handler = {udp_test_handler, &state}};
    state.stack = tcpip_open(&parameters);
    ASSERT(state.stack != nullptr);

    std::vector<uint8_t> datagram(UDP_HEADER_SIZE + payload_length);
    put_network_u16(datagram.data(), 43210);
    put_network_u16(datagram.data() + 2, 27000);
    put_network_u16(datagram.data() + 4, static_cast<uint16_t>(datagram.size()));
    for (size_t offset = UDP_HEADER_SIZE; offset < datagram.size(); ++offset) {
        datagram[offset] = static_cast<uint8_t>(offset * 31);
    }

    const size_t fragment_size = (mtu - IPV4_HEADER_SIZE) & ~size_t{7};
    const size_t stride = datagram.size() + IPV4_HEADER_SIZE <= mtu ? datagram.size() : fragment_size;
    std::vector<std::vector<uint8_t>> fragments;
    for (size_t offset = 0; offset < datagram.size(); offset += stride) {
        const size_t length = std::min(stride, datagram.size() - offset);
        const bool more_fragments = offset + length < datagram.size();
        auto &fragment = fragments.emplace_back(IPV4_HEADER_SIZE + length);
        fragment[0] = 0x45;
        put_network_u16(fragment.data() + 2, static_cast<uint16_t>(fragment.size()));
        put_network_u16(fragment.data() + 4, 173);
        put_network_u16(fragment.data() + 6, static_cast<uint16_t>(offset / 8 | (more_fragments ? 0x2000 : 0)));
        fragment[8] = 64;
        fragment[9] = IPPROTO_UDP;
        std::copy(std::begin(SOURCE), std::end(SOURCE), fragment.data() + 12);
        std::copy(std::begin(DESTINATION), std::end(DESTINATION), fragment.data() + 16);
        const uint16_t checksum = inet_chksum(fragment.data(), IPV4_HEADER_SIZE);
        memcpy(fragment.data() + 10, &checksum, sizeof(checksum));
        std::copy_n(datagram.data() + offset, length, fragment.data() + IPV4_HEADER_SIZE);
    }

    std::vector<VpnPacket> input;
    for (auto &fragment : fragments) {
        input.push_back({.data = fragment.data(), .size = fragment.size()});
    }
    VpnPackets packets{.data = input.data(), .size = static_cast<uint32_t>(input.size())};
    tcpip_tun_input(state.stack, &packets);
    tcpip_close(state.stack);
    vpn_event_loop_destroy(loop);

    if (state.messages.size() != 1) {
        fprintf(stderr, "UDP payload of %zu bytes at MTU %u produced %zu chunks\n", payload_length, mtu,
                state.messages.size());
    }
    ASSERT(state.messages.size() == 1);
    const std::vector<uint8_t> expected(datagram.begin() + UDP_HEADER_SIZE, datagram.end());
    ASSERT(state.messages[0] == expected);
}

int main() {
    test_socket_address_to_ip_addr();
    test_ip_addr_to_socket_address();
    test_tun_read_status();
    test_udp_datagram_boundary(1350, 1322);
    test_udp_datagram_boundary(1350, 1323);
    test_udp_datagram_boundary(1350, 4096);
    test_udp_datagram_boundary(1500, 1472);
    test_udp_datagram_boundary(1500, 1473);
}
