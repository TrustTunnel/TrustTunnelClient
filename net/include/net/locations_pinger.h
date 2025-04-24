#pragma once

#include "net/utils.h"
#include "vpn/event_loop.h"
#include "net/network_manager.h"

namespace ag {

/**
 * Locations pinger is intended to help to select an optimal endpoint for a location.
 * To achieve this it does the following:
 *     1) measures round-trip time for each endpoint in a location
 *     2) selects a suitable endpoint from the successfully pinged ones using
 *        the following criteria:
 *             a) IPv6 addresses prevail over IPv4 ones
 *             b) An address specified earlier in the list prevails over the latter ones
 *        - note, that low RTT value does not make endpoint to be selected
 */

struct LocationsPinger;

typedef struct {
    // Each connection attempt timeout (if 0, `DEFAULT_PING_TIMEOUT_MS` will be assigned).
    // Note that there will be several connection attempts, the exact number of which depends
    // on multiple factors, such as the number of rounds, the number of relay addresses,
    // whether fall back from QUIC to TLS happened, etc.
    uint32_t timeout_ms;
    AG_ARRAY_OF(const VpnLocation) locations; // list of locations to ping
    // The number of times each endpoint in a location is pinged (if <= 0, `DEFAULT_PING_ROUNDS` is used).
    // The best ping result out of all rounds will be used.
    uint32_t rounds;
#ifdef __MACH__
    bool query_all_interfaces; // Query all interfaces to calculate pings. Supported only on Apple platforms.
#endif
    // Use QUIC instead of TLS to ping the endpoints.
    // If a ping fails, the pinger will fall back to TLS for that endpoint.
    bool use_quic;
    bool anti_dpi;                          // Enable anti-DPI measures.
    bool handoff;                           // For internal use. Applications should set this parameter to `false`.
                                            // If `true`, pass the connection state with the ping result.
    const sockaddr *relay_address_parallel; // Ping through this relay in parallel with normal pings.
    uint32_t quic_max_idle_timeout_ms;      // QUIC connection max idle timeout. Set `0` to use the default.
    uint32_t quic_version;                  // QUIC version. Set `0` to use the default.
} LocationsPingerInfo;

typedef struct {
    const char *id; // location id
    int ping_ms;    // selected endpoint's ping (negative if none of the location endpoints successfully pinged)
    const VpnEndpoint *endpoint;   // selected endpoint
    const sockaddr *relay_address; // if the selected endpoint was pinged through a relay, the relay's address
    bool is_quic;                  // Whether the established connection is QUIC
    void *conn_state;              // For internal use. Applications should ignore this field.
                                   // If `handoff` is `true`, this is the connection state object.
} LocationsPingerResult;

struct LocationsPingerResultExtra : public LocationsPingerResult {
    /**
     * An IP version is considered unavailable in case pinging all the addresses
     * of the corresponding family failed with the unavailable status.
     */
    IpVersionSet ip_availability;
};

typedef struct {
    /**
     * Ping result handler
     * @param arg User argument
     * @param result Contains ping result or nullptr if pinging was finished
     */
    void (*func)(void *arg, const LocationsPingerResult *result);
    void *arg; // user argument
} LocationsPingerHandler;

/**
 * Ping locations.
 * @param info pinger info
 * @param handler pinger handler
 * @param ev_loop event loop for operation
 * @param network_manager network manager
 * @return pinger context
 */
LocationsPinger *locations_pinger_start(
        const LocationsPingerInfo *info, LocationsPingerHandler handler, VpnEventLoop *ev_loop, VpnNetworkManager *network_manager);

/**
 * Stop pinging
 * @param pinger the pinger
 */
void locations_pinger_stop(LocationsPinger *pinger);

/**
 * Destroy pinging
 */
void locations_pinger_destroy(LocationsPinger *pinger);

} // namespace ag
