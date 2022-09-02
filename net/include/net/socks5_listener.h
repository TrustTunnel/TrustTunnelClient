#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "common/defs.h"
#include "common/logger.h"
#include "net/socket_manager.h"
#include "net/tcp_socket.h"
#include "vpn/event_loop.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

typedef enum {
    SOCKS5L_START_SUCCESS = 0,
    SOCKS5L_START_ADDR_IN_USE,
    SOCKS5L_START_FAILURE,
} Socks5ListenerStartResult;

typedef enum {
    SOCKS5L_EVENT_GENERATE_CONN_ID, /**< Called before registering a new incoming connection (raised with a pointer to
                                       buffer to store the ID) */
    SOCKS5L_EVENT_CONNECT_REQUEST,  /** Called when new incoming connection is appeared (raised with
                                       `socks5l_connect_request_event_t`) */
    SOCKS5L_EVENT_CONNECTION_ACCEPTED, /** Called when passed connection is accepted (raised with connection id) */
    SOCKS5L_EVENT_READ, /**< Called when some data needs to be sent via connection (raised with `socks5l_read_event_t`)
                         */
    SOCKS5L_EVENT_DATA_SENT, /**< Called when some data was sent to client (raised with `socks5l_data_sent_event_t`) */
    SOCKS5L_EVENT_CONNECTION_CLOSED, /**< Called when connection is closed by client (raised with
                                        `socks5l_connection_closed_event_t`) */
    SOCKS5L_EVENT_PROTECT_SOCKET, /**< Called when socket needs to be protected (raised with `socket_protect_event_t`)
                                   */
} Socks5ListenerEvent;

typedef enum {
    S5CAT_SOCKADDR,    /**< either ipv4 or ipv6 address + port */
    S5CAT_DOMAIN_NAME, /**< domain name + port */
} Socks5ConnectionAddressType;

typedef struct {
    Socks5ConnectionAddressType type;
    struct sockaddr_storage ip;
    struct {
        std::string name;
        uint16_t port;
    } domain;
} Socks5ConnectionAddress;

typedef struct {
    uint64_t id;                        /**< connection identifier */
    int proto;                          /**< connection protocol */
    const struct sockaddr *src;         /**< source address of connection */
    const Socks5ConnectionAddress *dst; /**< destination address */
    std::string_view app_name;          /**< name of application that initiated this request */
} Socks5ConnectRequestEvent;

typedef struct {
    uint64_t id;         /**< connection identifier */
    const uint8_t *data; /**< data buffer */
    size_t length;       /**< data length */
    int result;          /**< FILLED BY HANDLER: operation result (0 in case of success, non-zero otherwise) */
} Socks5ReadEvent;

typedef struct {
    uint64_t id;   /**< connection identifier */
    size_t length; /**< sent bytes number */
} Socks5DataSentEvent;

typedef struct {
    uint64_t id;    /**< connection identifier */
    VpnError error; /**< error if connection closed unexpectedly */
} Socks5ConnectionClosedEvent;

typedef struct Socks5Listener Socks5Listener;

typedef struct {
    void (*func)(void *arg, Socks5ListenerEvent what, void *data);
    void *arg;
} Socks5ListenerHnadler;

typedef enum {
    S5LCR_SUCCESS,
    S5LCR_REJECT,
    S5LCR_TIMEOUT,
    S5LCR_UNREACHABLE,
} Socks5ConnectResult;

typedef struct {
    /** Event loop */
    VpnEventLoop *ev_loop;
    /**
     * Address to listen on for SOCKS5 traffic (if not set, `127.0.0.1` will be used).
     * Recognized formats are:
     *    - [IPv6Address]:port
     *    - [IPv6Address]
     *    - IPv6Address
     *    - IPv4Address:port
     *    - IPv4Address
     * If port is 0 or not specified, it will be chosen automatically.
     */
    struct sockaddr_storage listen_address;
    /** IO operations timeout */
    Millis timeout;
    /** Socket manager */
    SocketManager *socket_manager;
    /** Reaching this read buffer size causes stop reads from network (if 0, takes no effect) */
    size_t read_threshold;
    /**
     * If set, require this username to connect.
     * Must be set if `listen_address` is not a loopback address or if `password` is set.
     */
    std::string_view username;
    /**
     * If set, require this password to connect.
     * Must be set if `username` is set.
     */
    std::string_view password;
} Socks5ListenerConfig;

/**
 * Create socks5 listener
 * @param config configuration
 * @param handler event handler
 * @return listener
 */
Socks5Listener *socks5_listener_create(const Socks5ListenerConfig *config, const Socks5ListenerHnadler *handler);

/**
 * Start socks5 listener
 * @param listener listener instance
 */
Socks5ListenerStartResult socks5_listener_start(Socks5Listener *listener);

/**
 * Stop socks5 listener
 * @param listener listener instance
 */
void socks5_listener_stop(Socks5Listener *listener);

/**
 * Destroy socks5 listener
 * @param listener listener instance
 */
void socks5_listener_destroy(Socks5Listener *listener);

/**
 * Complete connect request raised with `SOCKS5L_EVENT_CONNECT_REQUEST`
 * @param listener listener
 * @param id connection id
 * @param result connect result
 */
void socks5_listener_complete_connect_request(Socks5Listener *listener, uint64_t id, Socks5ConnectResult result);

/**
 * Send data via connection
 * @param listener listener
 * @param id connection id
 * @param data data to send
 * @param length data length
 * @return 0 on success, non-zero value otherwise
 */
int socks5_listener_send_data(Socks5Listener *listener, uint64_t id, const uint8_t *data, size_t length);

/**
 * Close connection
 * @note: `SOCKS5L_EVENT_CONNECTION_CLOSED` event will be fired synchronously
 *
 * @param listener listener
 * @param id connection id
 * @param graceful whether connection should be closed gracefully
 */
void socks5_listener_close_connection(Socks5Listener *listener, uint64_t id, bool graceful);

/**
 * Get flow control for connection
 * @param listener listener
 * @param id connection id
 */
TcpFlowCtrlInfo socks5_listener_flow_ctrl_info(const Socks5Listener *listener, uint64_t id);

/**
 * Enable/disable read events on connection
 * @param listener listener
 * @param id connection id
 * @param on if true, enable
 */
void socks5_listener_turn_read(const Socks5Listener *listener, uint64_t id, bool on);

/**
 * Get the address is being listened for SOCKS requests
 */
const struct sockaddr_storage *socks5_listener_listen_address(const Socks5Listener *listener);

} // namespace ag
