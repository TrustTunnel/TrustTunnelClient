#include <chrono>

#include <gtest/gtest.h>

#include "vpn/utils.h"

using namespace ag;

TEST(ResolveEndpointAddress, Ipv4WithPort) {
    auto result = resolve_endpoint_address("1.2.3.4:443");
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].sa_family, AF_INET);
    SocketAddress addr(result[0]);
    ASSERT_EQ(addr.port(), 443);
}

TEST(ResolveEndpointAddress, Ipv6WithPort) {
    auto result = resolve_endpoint_address("[::1]:443");
    ASSERT_EQ(result.size(), 1);
    ASSERT_EQ(result[0].sa_family, AF_INET6);
    SocketAddress addr(result[0]);
    ASSERT_EQ(addr.port(), 443);
}

TEST(ResolveEndpointAddress, Ipv4WithoutPort) {
    auto result = resolve_endpoint_address("1.2.3.4");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, Ipv6WithoutPort) {
    auto result = resolve_endpoint_address("[::1]");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, LocalhostWithPort) {
    auto result = resolve_endpoint_address("localhost:443");
    if (result.empty()) {
        GTEST_SKIP() << "localhost does not resolve on this system";
    }
    for (const auto &addr : result) {
        ASSERT_TRUE(addr.sa_family == AF_INET || addr.sa_family == AF_INET6);
        SocketAddress sa(addr);
        ASSERT_EQ(sa.port(), 443);
    }
}

TEST(ResolveEndpointAddress, InvalidHostname) {
    auto result = resolve_endpoint_address("this.hostname.does.not.exist.invalid:443");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, EmptyString) {
    auto result = resolve_endpoint_address("");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, EmptyHostWithPort) {
    auto result = resolve_endpoint_address(":443");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, NullPtr) {
    auto result = resolve_endpoint_address(nullptr);
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddress, HostnameWithoutPort) {
    auto result = resolve_endpoint_address("localhost");
    ASSERT_TRUE(result.empty());
}

TEST(ResolveEndpointAddresses, PreservesOrderAndPerSlotResults) {
    auto results = resolve_endpoint_addresses({
            "1.2.3.4:443",                              // numeric, resolves to one address
            "1.2.3.4",                                  // missing port, empty slot
            "[::1]:8443",                               // numeric IPv6
            "",                                         // empty string, empty slot
            "this.hostname.does.not.exist.invalid:443", // unresolvable, empty slot
    });
    ASSERT_EQ(results.size(), 5);

    ASSERT_EQ(results[0].size(), 1);
    ASSERT_EQ(results[0][0].sa_family, AF_INET);
    ASSERT_EQ(SocketAddress(results[0][0]).port(), 443);

    ASSERT_TRUE(results[1].empty());

    ASSERT_EQ(results[2].size(), 1);
    ASSERT_EQ(results[2][0].sa_family, AF_INET6);
    ASSERT_EQ(SocketAddress(results[2][0]).port(), 8443);

    ASSERT_TRUE(results[3].empty());
    ASSERT_TRUE(results[4].empty());
}

TEST(ResolveEndpointAddresses, Empty) {
    auto results = resolve_endpoint_addresses({});
    ASSERT_TRUE(results.empty());
}
