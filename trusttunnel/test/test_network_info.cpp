#include <gtest/gtest.h>

#include "vpn/trusttunnel/network_info.h"

using namespace ag;

static VpnAddressArray make_dns_servers(const char **servers, uint32_t size) {
    return VpnAddressArray{.data = servers, .size = size};
}

TEST(VpnNetworkInfo, BareAddressesGetNaturalPrefixes) {
    static const char *DNS[] = {"94.140.14.14", "2a10:50c0::ad1:ff"};
    VpnNetworkInfo info = build_network_info("tt0", "172.16.219.2", "fd01::2", 1350, make_dns_servers(DNS, 2));
    EXPECT_EQ(info.iface_name, "tt0");
    EXPECT_EQ(info.ipv4_address, "172.16.219.2");
    EXPECT_EQ(info.ipv4_prefix, 32u);
    EXPECT_EQ(info.ipv6_address, "fd01::2");
    EXPECT_EQ(info.ipv6_prefix, 128u);
    EXPECT_EQ(info.mtu, 1350u);
    ASSERT_EQ(info.dns_servers.size(), 2u);
    EXPECT_EQ(info.dns_servers[0], "94.140.14.14");
    EXPECT_EQ(info.dns_servers[1], "2a10:50c0::ad1:ff");
}

TEST(VpnNetworkInfo, ExplicitPrefixesArePreserved) {
    VpnNetworkInfo info = build_network_info("tun123", "10.5.0.1/24", "fdfd:29::1/64", 9000, VpnAddressArray{});
    EXPECT_EQ(info.iface_name, "tun123");
    EXPECT_EQ(info.ipv4_address, "10.5.0.1");
    EXPECT_EQ(info.ipv4_prefix, 24u);
    EXPECT_EQ(info.ipv6_address, "fdfd:29::1");
    EXPECT_EQ(info.ipv6_prefix, 64u);
    EXPECT_EQ(info.mtu, 9000u);
}

TEST(VpnNetworkInfo, MissingIpv6YieldsZeroPrefix) {
    VpnNetworkInfo info = build_network_info("tt0", "172.16.219.2", "", 1350, VpnAddressArray{});
    EXPECT_EQ(info.ipv4_prefix, 32u);
    EXPECT_TRUE(info.ipv6_address.empty());
    EXPECT_EQ(info.ipv6_prefix, 0u);
}

TEST(VpnNetworkInfo, UnparsableAddressIsKeptWithZeroPrefix) {
    VpnNetworkInfo info = build_network_info("tt0", "not-an-address", "", 1350, VpnAddressArray{});
    EXPECT_EQ(info.ipv4_address, "not-an-address");
    EXPECT_EQ(info.ipv4_prefix, 0u);
}
