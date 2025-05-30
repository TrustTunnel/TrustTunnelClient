#pragma once

#include <cstdint>

#include <lwip/pbuf.h>

#include "tcpip_connection.h"

namespace ag {

/**
 * Enumeration of states of UDP connection
 */
enum UdpConnState {
    UDP_CONN_STATE_IDLE,
    UDP_CONN_STATE_REQUESTED,
    UDP_CONN_STATE_CONFIRMED,
    UDP_CONN_STATE_REJECTED,
    UDP_CONN_STATE_UNREACHABLE,
};

/**
 * This struct is used to store the essential parameters of UDP connection
 */
struct UdpConnDescriptor {
    TcpipConnection common;
    UdpConnState state;                                     /**< Connection state */
    std::vector<DeclPtr<pbuf, &pbuf_free>> pending_packets; /**< Pending input packets */
    size_t pending_packets_bytes;                           /**< Total bytes number of pending packets */
};

} // namespace ag
