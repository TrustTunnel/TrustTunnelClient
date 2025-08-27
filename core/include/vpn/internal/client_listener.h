#pragma once

#include <cassert>
#include <cstdint>

#include "vpn/internal/utils.h"
#include "vpn/platform.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {

class VpnClient;

enum ClientEvent {
    CLIENT_EVENT_CONNECT_REQUEST,     /**< Called when new incoming connection is appeared (raised with
                                         `ClientConnectRequest`) */
    CLIENT_EVENT_CONNECTION_ACCEPTED, /**< Called when passed connection is accepted (raised with connection id) */
    CLIENT_EVENT_CONNECTION_CLOSED,   /**< Called when connection is closed by client (raised with connection id) */
    CLIENT_EVENT_READ,      /**< Called when some data needs to be sent via connection (raised with `ClientRead`) */
    CLIENT_EVENT_DATA_SENT, /**< Called when some data was sent to client (raised with `ClientDataSentEvent`) */
    CLIENT_EVENT_OUTPUT, /**< Called when some data from server is ready to be sent to client application (raised with
                            `VpnClientOutputEvent`) */
    CLIENT_EVENT_ICMP_ECHO_REQUEST, /**< Called when ICMP echo request is received (raised with
                                       `icmp_echo_request_event_t`) */
};

enum ClientConnectResult {
    CCR_PASS,    // connected successfully
    CCR_DROP,    // connection to destination peer timed out
    CCR_REJECT,  // destination peer rejected connection
    CCR_UNREACH, // destination peer is unreachable
};

struct ClientConnectRequest {
    uint64_t id;               /**< connection identifier */
    int protocol;              /**< protocol */
    const SocketAddress *src;  /**< source address */
    const TunnelAddress *dst;  /**< destination address */
    std::string_view app_name; /**< name of application that initiated this request */
};

struct ClientRead {
    uint64_t id;         /**< connection identifier */
    const uint8_t *data; /**< data buffer */
    size_t length;       /**< data length */
    /**
     * Operation result. Filled by caller.
     * Negative value means error.
     * For a TCP connection may be less than `length`, in that case the listener should slide
     * buffer and try to raise the rest data if read is still enabled, or, if read is disabled,
     * try it after the other side enables read.
     * For a UDP connection may be equal to `length` in case packet was sent successfully, or
     * 0 in case the other side can't send anymore at the moment. In the latter case, the listener
     * may retry later or drop the packet.
     */
    int result;
};

struct ClientDataSentEvent {
    uint64_t id;   /**< connection identifier */
    size_t length; /**< sent bytes number (if 0, then connection polls for send resuming) */
};

struct ClientHandler {
    /**
     * Event handling function
     * @param arg user argument
     * @param what see `ClientEvent`
     * @param data event data (see `ClientEvent`)
     */
    void (*func)(void *arg, ClientEvent what, void *data) = nullptr;
    /** User argument */
    void *arg = nullptr;
};

/**
 * Client communication interface which encapsulates client-side connections management
 */
class ClientListener {
public:
    enum class InitResult {
        SUCCESS,
        ADDR_IN_USE,
        FAILURE,
    };

    VpnClient *vpn = nullptr;
    ClientHandler handler = {};

    ClientListener() = default;
    virtual ~ClientListener() = default;

    ClientListener(const ClientListener &) = delete;
    ClientListener &operator=(const ClientListener &) = delete;

    ClientListener(ClientListener &&) noexcept = delete;
    ClientListener &operator=(ClientListener &&) noexcept = delete;

    /**
     * Initialize client listener (MUST be called if overridden)
     * If initialization is unsuccessful, the object is left in the same state it was in before calling init()
     * @param vpn vpn instance
     * @param handler client events handler
     * @return true if initialized successfully, false otherwise
     */
    virtual InitResult init(VpnClient *vpn, ClientHandler handler) {
        this->vpn = vpn;
        this->handler = handler;
        return InitResult::SUCCESS;
    }

    /**
     * Deinitialize client listener
     * The object is returned to the state it was in before calling init()
     */
    virtual void deinit() = 0;

    /**
     * Complete request for connection raised with `CLIENT_EVENT_CONNECT_REQUEST`
     * @param id connection id
     * @param result connect result
     */
    virtual void complete_connect_request(uint64_t id, ClientConnectResult result) = 0;

    /**
     * Close connection
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
     * Notify client of server sent some data
     * @param id connection id
     * @param n number of sent bytes
     */
    virtual void consume(uint64_t id, size_t n) = 0;

    /**
     * Get flow control info for connection
     * @param id connection id
     */
    virtual TcpFlowCtrlInfo flow_control_info(uint64_t id) = 0;

    /**
     * Enable/disable read operations
     * @param id connection id
     * @param on true -> enable / false -> disable
     */
    virtual void turn_read(uint64_t id, bool on) = 0;

    /**
     * Pass data packets received from a client application to the client listener in case it
     * doesn't listen for incoming data by itself
     * @param packets packets
     * @return 0 on success, non-zero value otherwise
     */
    virtual int process_client_packets(VpnPackets packets) {
        (void) packets;
        assert(0);
        return -1;
    }

    /**
     * Process an ICMP reply
     */
    virtual void process_icmp_reply(const IcmpEchoReply &reply) {
    }
};

} // namespace ag
