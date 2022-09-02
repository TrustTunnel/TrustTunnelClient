#pragma once

#include <cstdint>

#include "common/defs.h"
#include "net/socket_manager.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

typedef struct UdpSocket UdpSocket;

typedef enum {
    UDP_SOCKET_EVENT_PROTECT, /**< Raised when socket needs to be protected (raised with `socket_protect_event_t`) */
    UDP_SOCKET_EVENT_READ,    /**< Raised whenever socket has some data to read from (raised with
                                 `tcp_socket_read_event_t`) */
    UDP_SOCKET_EVENT_TIMEOUT, /**< Raised if there was no activity on socket for specified time (raised with `null`) */
} UdpSocketEvent;

typedef struct {
    const uint8_t *data; // buffer with data
    size_t length;       // data length
    bool closed;         // set by event handler when socket is closed to prevent reading from the closed descriptor
} UdpSocketReadEvent;

typedef struct {
    void (*func)(void *arg, UdpSocketEvent what, void *data);
    void *arg;
} UdpSocketCallbacks;

typedef struct {
    VpnEventLoop *ev_loop; // event loop for operation
    UdpSocketCallbacks handler;
    Millis timeout;                // operation time out value
    struct sockaddr_storage peer;  // destination peer (must be set)
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
 * Read from the underlying fd and raise `UDP_SOCKET_EVENT_READ` zero or more times synchronously
 * until `read` returns a retriable error or, if `cap` is non-zero, the total number of bytes read exceeds `cap`.
 * @return `true` if socket was closed during draining.
 */
bool udp_socket_drain(UdpSocket *socket, size_t cap);

} // namespace ag
