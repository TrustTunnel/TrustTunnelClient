#pragma once

#include "net/utils.h"
#include "vpn/event_loop.h"

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
    uint32_t timeout_ms;                // ping operation timeout (if 0, `DEFAULT_PING_TIMEOUT_MS` will be assigned)
    AG_ARRAY_OF(VpnLocation) locations; // list of locations to ping
    // maximum number of times each endpoint in each location is pinged (if <= 0, `DEFAULT_PING_ROUNDS` is used)
    uint32_t rounds;
#ifdef __MACH__
    // query all interfaces to calculate pings. Supported only on Apple platforms.
    bool query_all_interfaces;
#endif /* __MACH__ */
} LocationsPingerInfo;

typedef struct {
    const char *id; // location id
    int ping_ms;    // selected endpoint's ping (negative if none of the location endpoints successfully pinged)
    const VpnEndpoint *endpoint; // selected endpoint
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
 * Ping given locations
 * @param info pinger info
 * @param handler pinger handler
 * @param ev_loop event loop for operation
 * @return pinger context
 */
LocationsPinger *locations_pinger_start(
        const LocationsPingerInfo *info, LocationsPingerHandler handler, VpnEventLoop *ev_loop);

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
