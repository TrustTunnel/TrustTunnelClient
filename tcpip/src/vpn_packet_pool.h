#pragma once

#include <list>
#include <memory>

#include "tcpip/tcpip.h"
#include "vpn/utils.h"

namespace ag {

class VpnPacketPool {
public:
    /**
     * Init list with pointers to data blocks
     * @param size number of blocks
     * @param mtu size of one block
     */
    VpnPacketPool(size_t size, uint32_t mtu);

    ~VpnPacketPool();

    /**
     * Return VpnPacket with pointer to data from pool.
     * If there are no unused data block, create the new one.
     */
    VpnPacket get_packet();

    /**
     * Take ownership of allocated data back
     * @param packet pointer to data block
     */
    void return_packet_data(uint8_t *packet);

    /**
     * Return number of unused allocated blocks
     */
    size_t get_size();

private:
    struct VpnPacketPoolState;

    size_t m_capacity;
    uint32_t m_mtu;
    std::list<std::unique_ptr<uint8_t[]>> m_packets;
    VpnPacketPoolState *m_state;
};

} // namespace ag
