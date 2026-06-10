#include <gtest/gtest.h>

#include <memory>

#include "vpn_packet_pool.h"

using namespace ag;

TEST(VpnPacketPool, Functional) {
    constexpr size_t pool_capacity = 20;
    auto pool = std::make_unique<VpnPacketPool>(pool_capacity, DEFAULT_MTU_SIZE);
    std::vector<VpnPacket> packets;
    VpnPacket packet = pool->get_packet();

    ASSERT_EQ(pool->get_size(), 19);
    pool->return_packet_data(packet.data);
    ASSERT_EQ(pool->get_size(), 20);

    for (size_t i = 0; i < pool_capacity; ++i) {
        packets.push_back(pool->get_packet());
    }
    ASSERT_EQ(pool->get_size(), 0);
    for (auto i = 0; i < 5; ++i) {
        packets.push_back(pool->get_packet());
    }

    // ensure that we didn't increase size of data blocks
    for (auto &p : packets) {
        pool->return_packet_data(p.data);
    }
    ASSERT_EQ(pool->get_size(), pool_capacity);
}
