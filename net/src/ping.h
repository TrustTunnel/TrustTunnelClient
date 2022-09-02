#pragma once

#include <string_view>

#include "vpn/event_loop.h"

namespace ag {

struct Ping;

enum PingStatus {
    PING_OK,           // pinged successfully
    PING_FINISHED,     // all addresses were pinged
    PING_SOCKET_ERROR, // failed to establish connection
    PING_TIMEDOUT,     // connection timed out
};

struct PingResult {
    Ping *ping;                  // ping pointer (don't delete from callback unless PING_FINISHED is reported)
    PingStatus status;           // ping status
    const struct sockaddr *addr; // pinged address
    int ms;                      // RTT value
};

struct PingInfo {
    VpnEventLoop *loop;                             ///< Event loop
    std::basic_string_view<sockaddr_storage> addrs; ///< List of addresses to ping

    /// The maximum amount of time the whole pinging process is allowed to take.
    /// The effective timeout before we report that a connection to an address
    /// has timed out will be `timeout_ms / nrounds`.
    /// If 0, `DEFAULT_PING_TIMEOUT_MS` will be assigned.
    uint32_t timeout_ms;

    /// Start a separate connection for each available network interface.
    /// Supported only on Apple platforms. The same pinged address will
    /// be reported multiple times, once per interface.
    bool query_all_interfaces;

    uint32_t nrounds; ///< Number of pinging rounds. If 0, `DEFAULT_PING_ROUNDS` will be assigned.
};

struct PingHandler {
    void (*func)(void *arg, const PingResult *result);
    void *arg;
};

/**
 * Ping the given addresses.
 * Each address will be pinged at most `info.nrounds` times (less if `info.timeout_ms`
 * expires or an error occurs) and the handler will be called once for each address.
 * After that, the handler is called one final time with status equal to `PING_FINISHED`.
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
int ping_get_id(const Ping *ping);

} // namespace ag
