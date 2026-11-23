#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <lwip/mem.h>
#include <lwip/pbuf.h>
#include <lwip/prot/ip6.h>

#include "common/defs.h"
#include "tun_device_listener.h"
#include "vpn/event_loop.h"

using namespace ag;

static constexpr size_t IPV4_HEADER_SIZE = 20;
static constexpr size_t IPV6_OPTIONS_HEADER_SIZE = 8;
static constexpr size_t UDP_HEADER_SIZE = 8;

static thread_local std::optional<size_t> g_fail_lwip_allocation_size;

extern "C" void *tun_udp_real_mem_malloc(mem_size_t size);

extern "C" void *mem_malloc(mem_size_t size) {
    if (g_fail_lwip_allocation_size == size) {
        g_fail_lwip_allocation_size.reset();
        return nullptr;
    }
    return tun_udp_real_mem_malloc(size);
}

struct TunUdpForwarding {
    ClientListener *listener;
    std::vector<std::vector<uint8_t>> received;
    size_t connections = 0;
};

static void handle_client_event(void *arg, ClientEvent event, void *data) {
    auto &state = *static_cast<TunUdpForwarding *>(arg);
    switch (event) {
    case CLIENT_EVENT_CONNECT_REQUEST: {
        const auto &request = *static_cast<ClientConnectRequest *>(data);
        EXPECT_EQ(request.protocol, IPPROTO_UDP);
        ++state.connections;
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

struct InputFragment {
    std::vector<uint8_t> bytes;
    size_t releases = 0;
};

static std::vector<uint8_t> make_payload(size_t length, uint8_t seed) {
    std::vector<uint8_t> payload(length);
    for (size_t offset = 0; offset < length; ++offset) {
        payload[offset] = static_cast<uint8_t>(offset * 31 + seed);
    }
    return payload;
}

static std::vector<InputFragment> make_ipv4_fragments(
        const std::vector<uint8_t> &payload, uint32_t mtu, uint16_t identification) {
    constexpr std::array<uint8_t, 4> SOURCE{192, 0, 2, 1};
    constexpr std::array<uint8_t, 4> DESTINATION{198, 51, 100, 1};
    std::vector<uint8_t> datagram(UDP_HEADER_SIZE + payload.size());
    put_network_u16(datagram.data(), 43210);
    put_network_u16(datagram.data() + 2, 27000);
    put_network_u16(datagram.data() + 4, static_cast<uint16_t>(datagram.size()));
    std::copy(payload.begin(), payload.end(), datagram.begin() + UDP_HEADER_SIZE);

    const size_t fragment_size = (mtu - IPV4_HEADER_SIZE) & ~size_t{7};
    const size_t stride = datagram.size() + IPV4_HEADER_SIZE <= mtu ? datagram.size() : fragment_size;
    std::vector<InputFragment> fragments;
    for (size_t offset = 0; offset < datagram.size(); offset += stride) {
        const size_t length = std::min(stride, datagram.size() - offset);
        const bool more_fragments = offset + length < datagram.size();
        auto &fragment = fragments.emplace_back(std::vector<uint8_t>(IPV4_HEADER_SIZE + length)).bytes;
        fragment[0] = 0x45;
        put_network_u16(fragment.data() + 2, static_cast<uint16_t>(fragment.size()));
        put_network_u16(fragment.data() + 4, identification);
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

static uint32_t checksum_words(std::span<const uint8_t> bytes) {
    uint32_t sum = 0;
    for (size_t offset = 0; offset < bytes.size(); offset += 2) {
        sum += uint32_t{bytes[offset]} << 8;
        if (offset + 1 < bytes.size()) {
            sum += bytes[offset + 1];
        }
    }
    return sum;
}

struct Ipv6Options {
    bool before_fragment;
    bool after_fragment;
};

static std::vector<InputFragment> make_ipv6_fragments(
        const std::vector<uint8_t> &payload, uint32_t mtu, Ipv6Options options) {
    constexpr std::array<uint8_t, 16> SOURCE{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    constexpr std::array<uint8_t, 16> DESTINATION{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    const size_t before_size = options.before_fragment ? IPV6_OPTIONS_HEADER_SIZE : 0;
    const size_t after_size = options.after_fragment ? IPV6_OPTIONS_HEADER_SIZE : 0;
    const size_t fragment_header_offset = IP6_HLEN + before_size;
    const size_t fragment_data_offset = fragment_header_offset + IP6_FRAG_HLEN;
    const size_t fragment_capacity = (mtu - fragment_data_offset) & ~size_t{7};

    std::vector<uint8_t> fragmentable(after_size + UDP_HEADER_SIZE + payload.size());
    if (options.after_fragment) {
        fragmentable[0] = IP6_NEXTH_UDP;
    }
    const std::span udp = std::span(fragmentable).subspan(after_size);
    put_network_u16(udp.data(), 43210);
    put_network_u16(udp.data() + 2, 27000);
    put_network_u16(udp.data() + 4, static_cast<uint16_t>(udp.size()));
    std::copy(payload.begin(), payload.end(), udp.begin() + UDP_HEADER_SIZE);
    uint32_t sum = checksum_words(SOURCE) + checksum_words(DESTINATION) + static_cast<uint32_t>(udp.size())
            + IP6_NEXTH_UDP + checksum_words(udp);
    while (sum > UINT16_MAX) {
        sum = (sum & UINT16_MAX) + (sum >> 16);
    }
    const auto checksum = static_cast<uint16_t>(~sum);
    put_network_u16(udp.data() + 6, checksum != 0 ? checksum : UINT16_MAX);

    std::vector<InputFragment> fragments;
    for (size_t offset = 0; offset < fragmentable.size(); offset += fragment_capacity) {
        const size_t length = std::min(fragment_capacity, fragmentable.size() - offset);
        const bool more_fragments = offset + length < fragmentable.size();
        auto &fragment = fragments.emplace_back(std::vector<uint8_t>(fragment_data_offset + length)).bytes;
        fragment[0] = 0x60;
        put_network_u16(fragment.data() + 4, static_cast<uint16_t>(fragment.size() - IP6_HLEN));
        fragment[6] = options.before_fragment ? IP6_NEXTH_DESTOPTS : IP6_NEXTH_FRAGMENT;
        fragment[7] = 64;
        std::copy(SOURCE.begin(), SOURCE.end(), fragment.data() + 8);
        std::copy(DESTINATION.begin(), DESTINATION.end(), fragment.data() + 24);
        if (options.before_fragment) {
            fragment[IP6_HLEN] = IP6_NEXTH_FRAGMENT;
        }
        fragment[fragment_header_offset] = options.after_fragment ? IP6_NEXTH_DESTOPTS : IP6_NEXTH_UDP;
        put_network_u16(
                fragment.data() + fragment_header_offset + 2, static_cast<uint16_t>(offset | (more_fragments ? 1 : 0)));
        put_network_u16(fragment.data() + fragment_header_offset + 6, 173);
        std::copy_n(fragmentable.data() + offset, length, fragment.data() + fragment_data_offset);
    }
    return fragments;
}

static int forward_fragments(TunUdpForwarding &state, std::vector<InputFragment> &fragments) {
    std::vector<VpnPacket> input;
    for (auto &fragment : fragments) {
        input.push_back({
                .data = fragment.bytes.data(),
                .size = fragment.bytes.size(),
                .destructor =
                        [](void *arg, uint8_t *) {
                            ++static_cast<InputFragment *>(arg)->releases;
                        },
                .destructor_arg = &fragment,
        });
    }
    return state.listener->process_client_packets({.data = input.data(), .size = static_cast<uint32_t>(input.size())});
}

static void expect_released_once(const std::vector<InputFragment> &fragments) {
    for (size_t index = 0; index < fragments.size(); ++index) {
        EXPECT_EQ(fragments[index].releases, 1u) << "Input fragment " << index;
    }
}

static void with_udp_listener(uint32_t mtu, auto test) {
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    ASSERT_NE(loop.get(), nullptr);
    VpnClient vpn({.ev_loop = loop.get()});
    const VpnTunListenerConfig config{.fd = -1, .mtu_size = mtu};
    TunListener tun(&config);
    ClientListener &listener = tun;
    TunUdpForwarding state{.listener = &listener, .received = {}};
    ASSERT_EQ(listener.init(&vpn, {handle_client_event, &state}), ClientListener::InitResult::SUCCESS);
    test(state);
    listener.deinit();
}

struct DatagramCase {
    uint32_t mtu;
    size_t payload_length;
};

class TunUdpForwardingTest : public testing::TestWithParam<DatagramCase> {};

TEST_P(TunUdpForwardingTest, ForwardsOneCompleteDatagram) {
    const auto [mtu, payload_length] = GetParam();
    SCOPED_TRACE(::testing::Message() << "MTU " << mtu << ", UDP payload " << payload_length);
    const auto payload = make_payload(payload_length, 19);
    auto fragments = make_ipv4_fragments(payload, mtu, 173);
    with_udp_listener(mtu, [&](TunUdpForwarding &state) {
        EXPECT_EQ(forward_fragments(state, fragments), 0);
        EXPECT_EQ(state.received, std::vector<std::vector<uint8_t>>{payload});
        expect_released_once(fragments);
    });
}

TEST(TunUdpForwardingRegressionTest, KeepsConsecutiveDatagramsSeparateOnOneFlow) {
    constexpr uint32_t MTU = 1350;
    const auto large_payload = make_payload(4096, 29);
    const auto small_payload = make_payload(37, 61);
    auto large = make_ipv4_fragments(large_payload, MTU, 173);
    auto small = make_ipv4_fragments(small_payload, MTU, 174);
    ASSERT_GT(large.size(), 1u);
    ASSERT_EQ(small.size(), 1u);

    with_udp_listener(MTU, [&](TunUdpForwarding &state) {
        EXPECT_EQ(forward_fragments(state, large), 0);
        EXPECT_EQ(forward_fragments(state, small), 0);
        const std::vector expected{large_payload, small_payload};
        EXPECT_EQ(state.received, expected);
        EXPECT_EQ(state.connections, 1u);
        expect_released_once(large);
        expect_released_once(small);
    });
}

TEST(TunUdpForwardingRegressionTest, DropsWholeDatagramOnCoalesceAllocationFailure) {
    constexpr uint32_t MTU = 1350;
    const auto dropped_payload = make_payload(4096, 73);
    const auto next_payload = make_payload(2048, 107);
    auto dropped = make_ipv4_fragments(dropped_payload, MTU, 173);
    auto next = make_ipv4_fragments(next_payload, MTU, 174);
    ASSERT_GT(dropped.size(), 1u);
    ASSERT_GT(next.size(), 1u);

    with_udp_listener(MTU, [&](TunUdpForwarding &state) {
        g_fail_lwip_allocation_size =
                LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf)) + LWIP_MEM_ALIGN_SIZE(dropped_payload.size());
        const int result = forward_fragments(state, dropped);
        EXPECT_FALSE(std::exchange(g_fail_lwip_allocation_size, std::nullopt).has_value());
        EXPECT_EQ(result, 0);
        EXPECT_TRUE(state.received.empty());
        expect_released_once(dropped);

        EXPECT_EQ(forward_fragments(state, next), 0);
        EXPECT_EQ(state.received, std::vector<std::vector<uint8_t>>{next_payload});
        EXPECT_EQ(state.connections, 1u);
        expect_released_once(next);
    });
}

class TunUdpForwardingIpv6Test : public testing::TestWithParam<Ipv6Options> {};

TEST_P(TunUdpForwardingIpv6Test, ForwardsOneCompleteDatagram) {
    constexpr uint32_t MTU = 1350;
    const auto options = GetParam();
    const auto payload = make_payload(4097, 29);
    auto fragments = make_ipv6_fragments(payload, MTU, options);
    ASSERT_GT(fragments.size(), 1u);

    with_udp_listener(MTU, [&](TunUdpForwarding &state) {
        EXPECT_EQ(forward_fragments(state, fragments), 0);
        ASSERT_EQ(state.received.size(), 1u);
        EXPECT_TRUE(state.received.front() == payload);
        EXPECT_EQ(state.connections, 1u);
        expect_released_once(fragments);
    });
}

INSTANTIATE_TEST_SUITE_P(Reassembled, TunUdpForwardingIpv6Test,
        testing::Values(
                Ipv6Options{false, false}, Ipv6Options{true, false}, Ipv6Options{false, true}, Ipv6Options{true, true}),
        [](const testing::TestParamInfo<Ipv6Options> &info) -> std::string {
            if (info.param.before_fragment && info.param.after_fragment) {
                return "OptionsBeforeAndAfter";
            }
            if (info.param.before_fragment) {
                return "OptionsBefore";
            }
            return info.param.after_fragment ? "OptionsAfter" : "NoOptions";
        });

INSTANTIATE_TEST_SUITE_P(FragmentationBoundary, TunUdpForwardingTest,
        testing::Values(DatagramCase{1350, 1322}, DatagramCase{1350, 1323}, DatagramCase{1350, 4096},
                DatagramCase{1500, 1472}, DatagramCase{1500, 1473}),
        [](const testing::TestParamInfo<DatagramCase> &info) {
            return "Mtu" + std::to_string(info.param.mtu) + "Payload" + std::to_string(info.param.payload_length);
        });
