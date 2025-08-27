#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/util.h>
#include <lwip/ip_addr.h>

#include "common/socket_address.h"

namespace ag {

/**
 * Convert ip_addr_t and port to `SocketAddress`
 *
 * @param addr ip_addr_t instance
 * @param port Port
 * @param out_sock_addr SocketAddress
 */
SocketAddress ip_addr_to_socket_address(const ip_addr_t *addr, uint16_t port);

/**
 * Makes ip_addr_t and port from SocketAddress
 * @param sock_addr SocketAddress
 * @param out_addr ip_addr_t instance
 * @param out_port port
 */
void socket_address_to_ip_addr(const SocketAddress &sock_addr, ip_addr_t *out_addr, uint16_t *out_port);

/**
 * IP addr to string conversion, prettier than LWIP variant
 * @param addr IP address
 * @param buf Output buffer
 * @param buflen Output buffer length
 */
void ipaddr_ntoa_r_pretty(const ip_addr_t *addr, char *buf, int buflen);

/**
 * Says whether statistics should be raised to higher layer at the moment
 *
 * @param event_base libevent event base
 * @param prev_update timeval with previous update
 * @param bytes_transfered bytes transfered
 *
 * @return     true  if statistics should be raised,
 *             false otherwise
 */
bool stat_should_be_notified(struct event_base *event_base, struct timeval *prev_update, size_t bytes_transfered);

/**
 * Writes pcap file header
 * @param fd File descriptor
 * @return 0 on success
 */
int pcap_write_header(int fd);

/**
 * Writes packet to pcap file
 * @param event_base Event base
 * @param fd File descriptor
 * @param iovec I/O vectors array
 * @param iov_cnt I/O vectors count
 * @return 0 on success
 */
int pcap_write_packet(int fd, struct timeval *tv, const void *data, size_t len);

/**
 * Writes packet to pcap file
 * @param fd File descriptor
 * @param iovec I/O vectors array
 * @param iov_cnt I/O vectors count
 * @return 0 on success
 */
int pcap_write_packet_iovec(int fd, struct timeval *tv, const struct evbuffer_iovec *iov, int iov_cnt);

/**
 * Calculates approximate size of headers sent with useful payload
 *
 * @param bytes_transfered size of useful data sent
 * @param proto_id id of the transport protocol (UDP or TCP)
 * @param mtu_size size of maximum transfer unit for stack
 *
 * @return size of sent headers
 */
size_t get_approx_headers_size(size_t bytes_transfered, uint8_t proto_id, uint16_t mtu_size);

} // namespace ag
