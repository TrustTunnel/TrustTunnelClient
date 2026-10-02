#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "lwipopts.h" // Include before LWIP headers

#include <lwip/prot/udp.h>

#include "common/logger.h"
#include "tcpip/tcpip.h"
#include "udp_connection.h"

namespace ag {

typedef struct UdpCtx {
    struct udp_pcb *tun_pcb;      /**< TUN UDP control block */
    uint8_t *input_buffer;        /**< Buffer used to receive data from remote host */
    ConnectionTables connections; /**< List of connections */
    ag::Logger log{"TCPIP.UDPMNGR"};
} UdpCtx;

/**
 * Handles received data from TCP/IP stack
 */
void udp_cm_receive(TcpipCtx *ctx, const ip_addr_t *src_addr, u16_t src_port, const ip_addr_t *dst_addr, u16_t dst_port,
        size_t iovlen, const struct evbuffer_iovec *iov);

/**
 * Initializes UDP connection manager
 *
 * @param ctx initialized earlier TCP context instance
 *
 * @return     true  if one was initialized successfully
 *             false otherwise
 */
bool udp_cm_init(TcpipCtx *ctx);

/**
 * Closes UDP connection manager
 *
 * @param ctx initialized earlier TCP context instance
 */
void udp_cm_close(TcpipCtx *ctx);

/**
 * Handles action which should be applied to connection
 *
 * @param ctx context of connection returned by `tcpip_open`
 * @param connection the connection descriptor
 * @param action action id (@see tcpip_action_t)
 */
void udp_cm_complete_connect_request(TcpipCtx *ctx, UdpConnDescriptor *connection, TcpipAction action);

/**
 * Moves an already-established connection to the unreachable state so that the
 * following packets from the client are answered with ICMP/ICMPv6
 * destination-unreachable messages (see `ip_hooks`). The connection is kept for
 * a short timeout and then closed by the timer.
 *
 * @param ctx context of connection returned by `tcpip_open`
 * @param connection the connection descriptor
 */
void udp_cm_reject_unreachable(TcpipCtx *ctx, UdpConnDescriptor *connection);

/**
 * Cleans up resources after running loop has been stopped
 *
 * @param ctx initialized earlier TCP/IP context instance
 */
void udp_cm_clean_up(TcpipCtx *ctx);

/**
 * Removes descriptor from the list and frees allocated memory for it
 *
 * @param id connection id
 */
void udp_cm_close_descriptor(TcpipCtx *ctx, uint64_t id);

/**
 * Places incoming packet in queue of pending packets of connection
 *
 * @param descriptor the connection descriptor
 * @param buffer buffer which contains the packet
 * @param header_len IP header length
 */
void udp_cm_enqueue_incoming_packet(UdpConnDescriptor *descriptor, struct pbuf *buffer, u16_t header_len);

/**
 * Creates and initializes new UDP connection descriptor
 *
 * @param ctx initialized earlier TCP/IP context instance
 * @param buffer buffer with received packet
 * @param header_len IP header length packet buffer
 * @param src_addr source ip address
 * @param source_port source port number
 * @param dst_addr destination ip address
 * @param destination_port destination port number
 *
 * @return     successfully created descriptor, or
 *             NULL if something went wrong
 */
UdpConnDescriptor *udp_cm_create_descriptor(TcpipCtx *ctx, struct pbuf *buffer, u16_t header_len,
        const ip_addr_t *src_addr, u16_t source_port, const ip_addr_t *dst_addr, u16_t destination_port);

/**
 * Performs a request for next higher layer for new UDP connection
 *
 * @param ctx initialized earlier TCP/IP context instance
 * @param descriptor UDP connection descriptor
 */
void udp_cm_request_connection(TcpipCtx *ctx, UdpConnDescriptor *descriptor);

/**
 * Notifies UDP connection manager of timer tick event
 *
 * @param ctx initialized earlier TCP/IP context instance
 */
void udp_cm_timer_tick(TcpipCtx *ctx);

/**
 * Sends data to TCP/IP stack
 *
 * @param conn connection descriptor
 * @param data received data
 * @param length size of received data
 */
int udp_cm_send_data(UdpConnDescriptor *conn, const uint8_t *data, size_t length);

/**
 * Get flow control info for connection
 * @param conn connection descriptor
 */
TcpFlowCtrlInfo udp_cm_flow_ctrl_info(const UdpConnDescriptor *conn);

} // namespace ag
