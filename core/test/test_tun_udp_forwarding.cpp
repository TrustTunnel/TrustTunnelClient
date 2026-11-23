#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "common/defs.h"
#include "tun_device_listener.h"
#include "vpn/event_loop.h"

using namespace ag;

static constexpr size_t IPV4_HEADER_SIZE = 20;
static constexpr size_t UDP_HEADER_SIZE = 8;

struct TunUdpForwarding {
    ClientListener *listener;
    std::vector<std::vector<uint8_t>> received;
};

static void handle_client_event(void *arg, ClientEvent event, void *data) {
    auto &state = *static_cast<TunUdpForwarding *>(arg);
    switch (event) {
    case CLIENT_EVENT_CONNECT_REQUEST: {
        const auto &request = *static_cast<ClientConnectRequest *>(data);
        EXPECT_EQ(request.protocol, IPPROTO_UDP);
        state.listener->turn_read(request.id, true);
        state.listener->complete_connect_request(request.id, CCR_PASS);
        break;
    }
    case CLIENT_EVENT_READ: {
        auto &read = *static_cast<ClientRead *>(data);
        state.received.emplace_back(read.data, read.data + read.length);
        read.result = static_cast<int>(read.length);
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

static uint16_t ipv4_header_checksum(const std::vector<uint8_t> &packet) {
    uint32_t sum = 0;
    for (size_t offset = 0; offset < IPV4_HEADER_SIZE; offset += 2) {
        sum += (uint32_t{packet[offset]} << 8) | packet[offset + 1];
    }
    while (sum > UINT16_MAX) {
        sum = (sum & UINT16_MAX) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

static std::vector<std::vector<uint8_t>> make_ipv4_fragments(const std::vector<uint8_t> &datagram, uint32_t mtu) {
    constexpr std::array<uint8_t, 4> SOURCE{192, 0, 2, 1};
    constexpr std::array<uint8_t, 4> DESTINATION{198, 51, 100, 1};
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
        std::copy(SOURCE.begin(), SOURCE.end(), fragment.data() + 12);
        std::copy(DESTINATION.begin(), DESTINATION.end(), fragment.data() + 16);
        put_network_u16(fragment.data() + 10, ipv4_header_checksum(fragment));
        std::copy_n(datagram.data() + offset, length, fragment.data() + IPV4_HEADER_SIZE);
    }
    return fragments;
}

struct DatagramCase {
    uint32_t mtu;
    size_t payload_length;
};

class TunUdpForwardingTest : public testing::TestWithParam<DatagramCase> {};

TEST_P(TunUdpForwardingTest, ForwardsOneCompleteDatagram) {
    const auto [mtu, payload_length] = GetParam();
    SCOPED_TRACE(::testing::Message() << "MTU " << mtu << ", UDP payload " << payload_length);
    std::vector<uint8_t> datagram(UDP_HEADER_SIZE + payload_length);
    put_network_u16(datagram.data(), 43210);
    put_network_u16(datagram.data() + 2, 27000);
    put_network_u16(datagram.data() + 4, static_cast<uint16_t>(datagram.size()));
    for (size_t offset = UDP_HEADER_SIZE; offset < datagram.size(); ++offset) {
        datagram[offset] = static_cast<uint8_t>(offset * 31);
    }
    auto fragments = make_ipv4_fragments(datagram, mtu);
    std::vector<VpnPacket> input;
    for (auto &fragment : fragments) {
        input.push_back({.data = fragment.data(), .size = fragment.size()});
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    ASSERT_NE(loop.get(), nullptr);
    VpnClient vpn({.ev_loop = loop.get()});
    const VpnTunListenerConfig config{.fd = -1, .mtu_size = mtu};
    TunListener tun(&config);
    ClientListener &listener = tun;
    TunUdpForwarding state{.listener = &listener, .received = {}};
    ASSERT_EQ(listener.init(&vpn, {handle_client_event, &state}), ClientListener::InitResult::SUCCESS);
    EXPECT_EQ(listener.process_client_packets({.data = input.data(), .size = static_cast<uint32_t>(input.size())}), 0);
    listener.deinit();

    ASSERT_EQ(state.received.size(), 1);
    const std::vector<uint8_t> expected(datagram.begin() + UDP_HEADER_SIZE, datagram.end());
    EXPECT_EQ(state.received.front(), expected);
}

INSTANTIATE_TEST_SUITE_P(FragmentationBoundary, TunUdpForwardingTest,
        testing::Values(DatagramCase{1350, 1322}, DatagramCase{1350, 1323}, DatagramCase{1350, 4096},
                DatagramCase{1500, 1472}, DatagramCase{1500, 1473}),
        [](const testing::TestParamInfo<DatagramCase> &info) {
            return "Mtu" + std::to_string(info.param.mtu) + "Payload" + std::to_string(info.param.payload_length);
        });
