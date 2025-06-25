#pragma once

#include <span>

#include "net/utils.h"
#include "vpn/event_loop.h"
#include "net/network_manager.h"

namespace ag {

struct Ping;

enum PingStatus {
    PING_OK,           // pinged successfully
    PING_FINISHED,     // all addresses were pinged
    PING_SOCKET_ERROR, // failed to establish connection
    PING_TIMEDOUT,     // connection timed out
};

struct PingResult {
    Ping *ping;                    // ping pointer (don't delete from callback unless PING_FINISHED is reported)
    PingStatus status;             // ping status
    int socket_error;              // has sense if `status` == `PING_SOCKET_ERROR`
    const VpnEndpoint *endpoint;   // pinged endpoint
    int ms;                        // RTT value
    const sockaddr *relay_address; // if the endpoint was pinged through a relay, the relay's address
    bool is_quic;                  // Whether the established connection is QUIC
    void *conn_state;              // Connection object, non-NULL if connection hand-off is enabled
};

struct PingInfo {
    const char *id = ""; ///< An ID string for correlating log messages

    VpnEventLoop *loop = nullptr;           ///< Event loop
    VpnNetworkManager *network_manager = nullptr;
    std::span<const VpnEndpoint> endpoints; ///< List of endpoints to ping

    /// Each connection attempt timeout. Note that there might be several connection attempts.
    /// If 0, `DEFAULT_PING_TIMEOUT_MS` will be assigned.
    uint32_t timeout_ms = 0;

    /// The list of the network interfaces to ping the endpoint through.
    /// If empty, the operation will use the default one.
    std::span<const uint32_t> interfaces_to_query;

    /// The number of times each endpoint's RTT must be measured. If 0, `DEFAULT_PING_ROUNDS` will be assigned.
    /// The best result (lowest RTT) will be reported.
    uint32_t nrounds = 0;

    bool use_quic = false; ///< Use QUIC version negotiation instead of TCP handshake
    bool anti_dpi = false; ///< Enable anti-DPI measures
    bool handoff = false;  ///< Enable connection hand-off.

    /// The list of relay addresses to try if an endpoint is unresponsive on its normal address.
    std::span<const sockaddr_storage> relay_addresses;

    /// If not zero, ping through this relay address in parallel with normal pings.
    sockaddr_storage relay_address_parallel;

    /// QUIC parameters. Set 0 to use defaults.
    uint32_t quic_max_idle_timeout_ms = 0;
    uint32_t quic_version = 0;
};

struct PingHandler {
    void (*func)(void *arg, const PingResult *result);
    void *arg;
};

/**
 * Ping the given addresses.
 * The handler will be called once for each address with the result of pinging that address,
 * and then one final time with the status equal to `PING_FINISHED`.
 */
Ping *ping_start(const PingInfo *info, PingHandler handler);

/**
 * Cancel pinging.
 * @param ping the ping to be cancelled.
 */
void ping_destroy(Ping *ping);

/**
 * Return the id of the specified ping.
 */
const char *ping_get_id(const Ping *ping);

} // namespace ag
