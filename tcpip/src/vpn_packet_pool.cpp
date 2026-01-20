#include "vpn_packet_pool.h"

namespace ag {

struct VpnPacketPool::VpnPacketPoolState {
    VpnPacketPool *pool;
    std::atomic_size_t refcounter;
    std::atomic_bool is_alive;

    void retain() {
        refcounter.fetch_add(1, std::memory_order_relaxed);
    }

    void release() {
        if (refcounter.fetch_sub(1, std::memory_order_relaxed) == 1) {
            delete this;
        }
    }
};

VpnPacketPool::VpnPacketPool(size_t size, uint32_t mtu)
        : m_capacity(size)
        , m_mtu(mtu)
        , m_state(new VpnPacketPoolState{this, 1, true}) {
    for (size_t i = 0; i < size; ++i) {
        m_packets.emplace_back(new uint8_t[m_mtu]);
    }
}

VpnPacketPool::~VpnPacketPool() {
    m_state->is_alive.store(false, std::memory_order_release);
    m_state->release();
}

VpnPacket VpnPacketPool::get_packet() {
    m_state->retain();

    auto destructor = [](void *arg, uint8_t *data) {
        auto *state = static_cast<VpnPacketPoolState *>(arg);
        if (state->is_alive.load(std::memory_order_acquire)) {
            state->pool->return_packet_data(data);
        } else {
            delete[] data;
            state->release();
        }
    };

    uint8_t *data = nullptr;
    if (m_packets.empty()) {
        data = new uint8_t[m_mtu];
    } else {
        data = m_packets.front().release();
        m_packets.pop_front();
    }

    return VpnPacket{
            .data = data, .size = static_cast<size_t>(m_mtu), .destructor = destructor, .destructor_arg = m_state};
}

void VpnPacketPool::return_packet_data(uint8_t *packet) {
    std::unique_ptr<uint8_t[]> data{packet};
    if (m_packets.size() < m_capacity) {
        m_packets.emplace_back(std::move(data));
    }

    m_state->release();
}

size_t VpnPacketPool::get_size() {
    return m_packets.size();
}

} // namespace ag
