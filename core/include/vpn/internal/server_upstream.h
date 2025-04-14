#pragma once

#include <cstdint>
#include <optional>

#include "common/defs.h"
#include "net/utils.h"
#include "vpn/internal/icmp_manager.h"
#include "vpn/internal/utils.h"
#include "vpn/vpn.h"

namespace ag {

class VpnClient;

enum ServerEvent {
    SERVER_EVENT_SESSION_OPENED, /**< Called when session with server is successfully established (raised with null) */
    SERVER_EVENT_SESSION_CLOSED, /**< Called when session with server is gracefully closed by server (raised with null)
                                  */
    SERVER_EVENT_CONNECTION_OPENED, /**< Called when connection to peer is successfully opened (raised with connection
                                       id) */
    SERVER_EVENT_CONNECTION_CLOSED, /**< Called when connection is gracefully closed by peer (raised with connection id)
                                     */
    SERVER_EVENT_READ, /**< Called when some data needs to be sent via connection (raised with `ServerReadEvent`) */
    SERVER_EVENT_DATA_SENT, /**< Called when some data was sent to client (raised with `ServerDataSentEvent`) */
    SERVER_EVENT_HEALTH_CHECK_RESULT,   /**< Called when a health check result has failed (raised with `VpnError`) */
    SERVER_EVENT_GET_AVAILABLE_TO_SEND, /**< Called when the upstream wants to know available size for sending (raised
                                           with `ServerAvailableToSendEvent`) */
    SERVER_EVENT_ERROR,      /**< Called when some error happened on server side (raised with `ServerError`) */
    SERVER_EVENT_ECHO_REPLY, /**< Called when ICMP echo reply is received (raised with `icmp_echo_reply_t`) */
};

struct ServerReadEvent {
    uint64_t id;         /**< connection id */
    const uint8_t *data; /**< data from server */
    size_t length;       /**< data length */
    int result;          /**< (filled by handler) operation result */
};

struct ServerDataSentEvent {
    uint64_t id;   /**< connection id */
    size_t length; /**< sent bytes number (if 0, then connection polls for send resuming) */
};

struct ServerAvailableToSendEvent {
    uint64_t id;   /**< connection id */
    size_t length; /**< (filled by handler) number of available to send bytes */
};

struct ServerError {
    uint64_t id; /**< connection id (if `NON_ID`, then event relates to the whole session, no a connection) */
    VpnError error;
};

struct ServerHandler {
    /**
     * Event handling function
     * @param arg user argument
     * @param what see `ServerEvent`
     * @param data event data (see `ServerEvent`)
     */
    void (*func)(void *arg, ServerEvent what, void *data) = nullptr;
    /** User argument */
    void *arg = nullptr;
};

/**
 * Server communication interface which encapsulates server-side connections management
 */
class ServerUpstream {
public:
    const std::optional<VpnUpstreamProtocolConfig> PROTOCOL_CONFIG;
    VpnClient *vpn = nullptr;
    ServerHandler handler = {};
    int id;
    IpVersionSet ip_version_availability;

    explicit ServerUpstream(int id, std::optional<VpnUpstreamProtocolConfig> protocol_config = std::nullopt)
            : PROTOCOL_CONFIG(protocol_config)
            , id(id) {
        ip_version_availability.set();
    }
    virtual ~ServerUpstream() = default;

    ServerUpstream(const ServerUpstream &) = delete;
    ServerUpstream &operator=(const ServerUpstream &) = delete;

    ServerUpstream(ServerUpstream &&) noexcept = delete;
    ServerUpstream &operator=(ServerUpstream &&) noexcept = delete;

    /**
     * Initialize server upstream (MUST be called if overridden)
     * @param vpn vpn instance
     * @param handler server events handler
     * @return true if initialized successfully, false otherwise
     */
    virtual bool init(VpnClient *vpn, ServerHandler handler) {
        this->vpn = vpn;
        this->handler = handler;
        return true;
    }

    /**
     * Deinitialize server upstream
     */
    virtual void deinit() = 0;

    /**
     * Open session with server. Result will be raised asynchronously with
     * `SERVER_EVENT_SESSION_OPENED` in case of success, or with `SERVER_EVENT_ERROR` in case of
     * error.
     * @param timeout timeout of operation (if `nullopt`, the value from upstream settings will be used)
     * @return true if operation started successfully, false otherwise
     */
    virtual bool open_session(std::optional<Millis> timeout = std::nullopt) = 0;

    /**
     * Close session with server
     */
    virtual void close_session() = 0;

    /**
     * Create connection to peer. Result will be raised asynchronously with
     * `SERVER_EVENT_CONNECTION_OPENED` in case of success, or with `SERVER_EVENT_ERROR` in case of
     * error.
     * @param addr source and destination address pair
     * @param proto connection protocol
     * @param app_name name of the application that initiated this connection (optional)
     * @return connection id in case of success, NON_ID in case of error
     */
    virtual uint64_t open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) = 0;

    /**
     * Close connection to peer
     * @param id connection id
     * @param graceful true if connection should be closed in a graceful way
     * @param async true if connection should be closed with a context switch
     */
    virtual void close_connection(uint64_t id, bool graceful, bool async) = 0;

    /**
     * Send data through connection
     * @param id connection id
     * @param data data to send
     * @param length data length
     * @return number of consumed bytes (< 0 in case of error)
     */
    virtual ssize_t send(uint64_t id, const uint8_t *data, size_t length) = 0;

    /**
     * Notify server of client sent some data
     * @param id connection id
     * @param n number of sent bytes
     */
    virtual void consume(uint64_t id, size_t length) = 0;

    /**
     * Get free space in write buffer
     * @param id connection id
     */
    virtual size_t available_to_send(uint64_t id) = 0;

    /**
     * Enable/disable read operations
     * @param id connection id
     * @param info flow control info
     */
    virtual void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) = 0;

    /**
     * Perform a connection health check. If the connection is healthy,
     * nothing is reported. If the connection is determined to be unhealthy,
     * a `SERVER_EVENT_HEALTH_CHECK_RESULT` is raised with an error description.
     */
    virtual void do_health_check() = 0;

    /**
     * Cancel an in-progress connection health check. No result will be reported.
     * If no connection health check is currently in progress, do nothing.
     */
    virtual void cancel_health_check() = 0;

    /**
     * Get statistics of the connection to endpoint
     */
    [[nodiscard]] virtual VpnConnectionStats get_connection_stats() const = 0;

    /**
     * Process an ICMP echo request received from client
     */
    virtual void on_icmp_request(IcmpEchoRequestEvent &event) = 0;

    /**
     * Get the connection protocol
     */
    [[nodiscard]] VpnUpstreamProtocol get_protocol() const {
        return this->PROTOCOL_CONFIG->type;
    }

    /**
     * Get endpoints group function used for key exchange
     */
    virtual int kex_group_nid() const {
        return NID_undef;
    }

    /**
     * Handle a system sleep event. The system is going to sleep after this function returns.
     */
    virtual void handle_sleep() {
        // Default no-op
    }

    /**
     * Handle a system wake up event.
     */
    virtual void handle_wake() {
        // Default no-op
    }

    /**
     * Update IP protocol versions availability
     */
    void update_ip_availability(IpVersionSet x) {
        this->ip_version_availability = x;
    }
};

} // namespace ag
