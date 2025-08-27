#pragma once

#include <cstdint>
#include <cstdlib>
#include <variant>

#include "vpn/platform.h" // Unbreak Windows builddows

#include <openssl/ssl.h>

#include "common/defs.h"
#include "common/logger.h"
#include "common/socket_address.h"
#include "net/socket_manager.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

struct TcpSocket;

typedef enum {
    /**< Raised on `tcp_socket_connect` result is ready (raised with null) */
    TCP_SOCKET_EVENT_CONNECTED,
    /**< Raised whenever socket has some data from connected peer (raised with null) */
    TCP_SOCKET_EVENT_READABLE,
    /**< Raised whenever socket sent some data in network (raised with `TcpSocketSentEvent`) */
    TCP_SOCKET_EVENT_SENT,
    /**< Raised if some error happened on socket (raised with `VpnError`) */
    TCP_SOCKET_EVENT_ERROR,
    /**< Raised on written data is sent (raised with null) */
    TCP_SOCKET_EVENT_WRITE_FLUSH,
    /**< Raised when socket needs to be protected (raised with `SocketProtectEvent`) */
    TCP_SOCKET_EVENT_PROTECT,
} TcpSocketEvent;

typedef struct {
    size_t bytes; // number of bytes sent
} TcpSocketSentEvent;

typedef struct {
    void (*handler)(void *arg, TcpSocketEvent id, void *data);
    void *arg;
} TcpSocketHandler;

typedef struct {
    VpnEventLoop *ev_loop;         // event loop
    TcpSocketHandler handler;      // socket events handler
    Millis timeout;                // operations timeout
    SocketManager *socket_manager; // socket manager
    size_t read_threshold;  // reaching this read buffer size causes stop reads from network (if 0, takes no effect)
    std::string log_prefix; // prefix to the main log message
#ifdef _WIN32
    bool record_estats; // if true, extended statistics will be enabled for the socket
#endif                  // _WIN32
} TcpSocketParameters;

typedef struct {
    const SocketAddress *peer; // should be null if `tcp_socket_acquire_fd` was called before
    SSL *ssl;                  // SSL context in case of the traffic needs to be encrypted
    bool anti_dpi;             // Enable anti-DPI protection
    bool pause_tls;            // Pause the TLS handshake and raise `TCP_SOCKET_EVENT_CONNECTED` after receiving the
                               // first bytes from server. Continue the handshake by calling `tcp_socket_connect_continue`.
                               // `TCP_SOCKET_EVENT_CONNECTED` will be raised one more time when the handshake is complete.
} TcpSocketConnectParameters;

/**
 * Create new socket
 * @param parameters socket parameters
 * @return null if failed, some socket otherwise
 */
TcpSocket *tcp_socket_create(const TcpSocketParameters *parameters);

/**
 * Destroy socket
 * @param socket socket
 */
void tcp_socket_destroy(TcpSocket *socket);

/**
 * Configure whether RST should be sent on socket close
 */
void tcp_socket_set_rst(TcpSocket *socket, bool rst);

/**
 * Connect to peer
 *
 * The socket can be instructed to pause the TLS handshake by setting `TcpSocketConnectParameters::pause_tls`.
 * A `TCP_SOCKET_EVENT_CONNECTED` will be raised upon receiving the first bytes from the server, but before
 * proceeding with the handshake. The handshake can then be resumed by calling `tcp_socket_connect_continue`.
 * A `TCP_SOCKET_EVENT_CONNECTED` will be raised again on successful handshake completion. This way, a half-open
 * connection can be handed off from the locations pinger to the upstream to save some network round trips.
 *
 * @param socket socket
 * @param param see `tcp_socket_connect_param_t`
 * @return 0 code error in case of success, non-zero otherwise
 */
VpnError tcp_socket_connect(TcpSocket *socket, const TcpSocketConnectParameters *param);

/**
 * If there is a paused TLS handshake, replace socket parameters with `params` and continue
 * the handshake, otherwise, return an error.
 *
 * Windows note: the value of `params->record_estats` is ignored, the state of the extended
 * statistics remains as it was at socket creation.
 *
 * @return 0 code error in case of success, non-zero otherwise
 */
VpnError tcp_socket_connect_continue(TcpSocket *socket, const TcpSocketParameters *params);

/**
 * Wrap fd in socket entity (fd will be closed with socket in `tcp_socket_destroy`).
 * This is typically used on already connected sockets, so socket protect is not called.
 * @param socket socket
 * @param fd file descriptor
 * @return 0 in case of success, non-zero otherwise (in this case user should close socket himself)
 */
VpnError tcp_socket_acquire_fd(TcpSocket *socket, evutil_socket_t fd);

/**
 * Enable/disable read events on socket
 * @param socket socket
 * @param flag true -> enable / false -> disable
 */
void tcp_socket_set_read_enabled(TcpSocket *socket, bool flag);

/**
 * Check whether read is enabled on the socket
 */
bool tcp_socket_is_read_enabled(TcpSocket *socket);

/**
 * Get free space in write buffer
 * @param socket socket
 */
size_t tcp_socket_available_to_write(const TcpSocket *socket);

/**
 * Send data via socket
 * @param socket socket
 * @param data data to send
 * @param length data length
 * @return 0 in case of success, non-zero value otherwise
 */
VpnError tcp_socket_write(TcpSocket *socket, const uint8_t *data, size_t length);

/**
 * Get underlying descriptor
 * @param socket socket
 * @return descriptor, -1 if there is no underlying descriptor
 */
evutil_socket_t tcp_socket_get_fd(const TcpSocket *socket);

/**
 * Return a non-owning pointer to the socket's SSL object,
 * or `nullptr` if there is none.
 */
SSL *tcp_socket_get_ssl(TcpSocket *socket);

/**
 * Set timeout value for operations
 * @param socket socket
 * @param x timeout, 0 for no timeout
 */
void tcp_socket_set_timeout(TcpSocket *socket, Millis x);

/**
 * Make socket to support both ipv4 and ipv6 connections
 * @param fd file descriptor
 * @return 0 in case of success, non-zero value otherwise
 */
int make_fd_dual_stack(evutil_socket_t fd);

/**
 * Get flow control information for underlying socket
 */
TcpFlowCtrlInfo tcp_socket_flow_control_info(const TcpSocket *socket);

/**
 * Get statistics for underlying socket
 */
VpnConnectionStats tcp_socket_get_stats(const TcpSocket *socket);

/**
 * Get NID of the group function used for key exchange
 */
int tcp_socket_get_kex_group_nid(const TcpSocket *socket);

namespace tcp_socket {

/** Retrieved data chunk */
using Chunk = U8View;

/** No more data will be read from the socket */
struct Eof {};

/** The buffer is currently empty. Try after the next readable event. */
using NoData = std::monostate;

using PeekResult = std::variant<NoData, Chunk, Eof>;

} // namespace tcp_socket

/**
 * Get data chunk from the socket buffer without moving the read pointer.
 * The caller is responsible for draining the portion of data it does not
 * need anymore.
 *
 * To read out all the buffered data it may require to run a `peek()`-`drain()`
 * loop until `peek()` returns not `Chunk`.
 */
tcp_socket::PeekResult tcp_socket_peek(TcpSocket *socket);

/**
 * Move the read pointer of the socket buffer.
 * @return true if successful
 */
bool tcp_socket_drain(TcpSocket *socket, size_t n);

/**
 * Get the selected ALPN protocol
 * @return nullptr if no alpn is selected
 */
std::string_view tcp_socket_get_selected_alpn(TcpSocket *socket);

/**
 * Get socket id
 */
int tcp_socket_get_id(const TcpSocket *socket);

} // namespace ag
