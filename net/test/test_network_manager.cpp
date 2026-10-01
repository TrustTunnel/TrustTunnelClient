#include <gtest/gtest.h>

#include "net/network_manager.h"

TEST(NetworkManagerTest, TunnelActiveState) {
    EXPECT_FALSE(ag::vpn_network_manager_get_tunnel_active());

    auto token = ag::vpn_network_manager_acquire_tunnel_activity();
    EXPECT_NE(ag::VPN_TUNNEL_ACTIVITY_TOKEN_INVALID, token);
    EXPECT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_release_tunnel_activity(token);
    EXPECT_FALSE(ag::vpn_network_manager_get_tunnel_active());
}

TEST(NetworkManagerTest, TunnelActiveUntilLastOwnerReleasesIt) {
    EXPECT_FALSE(ag::vpn_network_manager_get_tunnel_active());

    auto first = ag::vpn_network_manager_acquire_tunnel_activity();
    auto second = ag::vpn_network_manager_acquire_tunnel_activity();
    EXPECT_NE(first, second);
    EXPECT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_release_tunnel_activity(first);
    EXPECT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_release_tunnel_activity(first);
    EXPECT_TRUE(ag::vpn_network_manager_get_tunnel_active());

    ag::vpn_network_manager_release_tunnel_activity(second);
    EXPECT_FALSE(ag::vpn_network_manager_get_tunnel_active());
}
