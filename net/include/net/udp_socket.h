#pragma once

#include <cstdint>

#include "common/defs.h"
#include "net/socket_manager.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

struct UdpSocket;

typedef enum {
    UDP_SOCKET_EVENT_PROTECT,  /**< Raised when socket needs to be protected (raised with `SocketProtectEvent`) */
    UDP_SOCKET_EVENT_READABLE, /**< Raised whenever socket has some data to read from (raised with `null`) */
    UDP_SOCKET_EVENT_TIMEOUT,  /**< Raised if there was no activity on socket for specified time (raised with `null`) */
} UdpSocketEvent;

typedef struct {
    void (*func)(void *arg, UdpSocketEvent what, void *data);
    void *arg;
} UdpSocketCallbacks;

typedef struct {
    VpnEventLoop *ev_loop; // event loop for operation
    UdpSocketCallbacks handler;
    Millis timeout;                // socket timeout, set 0 to disable
    sockaddr_storage peer;         // destination peer (must be set)
    SocketManager *socket_manager; // socket manager
} UdpSocketParameters;

/**
 * Create a UDP socket
 * @param parameters the socket parameters
 * @return null if failed, some socket otherwise
 */
UdpSocket *udp_socket_create(const UdpSocketParameters *parameters);

/**
 * Destroy a UDP socket
 * @param socket the socket to destroy
 */
void udp_socket_destroy(UdpSocket *socket);

/**
 * Send data via a UDP socket
 * @param socket the socket
 * @param data the data to send
 * @param length the data length
 * @return 0 in case of success, non-zero value otherwise
 */
VpnError udp_socket_write(UdpSocket *socket, const uint8_t *data, size_t length);

/**
 * Get underlying descriptor
 */
evutil_socket_t udp_socket_get_fd(const UdpSocket *socket);

/**
 * Dissociate `socket` with its file descriptor and return
 * the file descriptor while destroying the socket.
 */
evutil_socket_t udp_socket_release_fd(UdpSocket *socket);

/**
 * Create a UDP socket that wraps an existing datagram socket file descriptor.
 */
UdpSocket *udp_socket_acquire_fd(const UdpSocketParameters *parameters, evutil_socket_t fd);

/**
 * Read from the underlying fd.
 * @return the number of bytes received, or a negative number if an error occurred.
 */
ssize_t udp_socket_recv(UdpSocket *socket, uint8_t *buffer, size_t cap);

/**
 * Set the socket timeout. 0 disables timeout.
 */
void udp_socket_set_timeout(UdpSocket *socket, Millis timeout);

/**
 * Get peer of the socket
 * @param socket the UDP socket
 * @return peer as sockaddr_storage
 */
sockaddr_storage *udp_socket_get_peer(UdpSocket *socket);

} // namespace ag
