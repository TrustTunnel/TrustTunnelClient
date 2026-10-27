#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * C API of the TrustTunnel Linux client library.
 *
 * The library owns the VPN client lifecycle (modelled after the CLI client) and reports
 * events through the callbacks provided at creation time. The callbacks are invoked from
 * the library's threads, so a single-threaded consumer (e.g. a D-Bus event loop) must
 * not run any non-trivial work inside them. The recommended pattern is: the callbacks
 * only enqueue a message and the consumer wakes its own loop through the library
 * event fd (see `trusttunnel_event_fd()`), then drains the pending events on the loop
 * thread with `trusttunnel_drain()`, which invokes the callbacks again on the loop
 * thread.
 */

/** Opaque VPN client instance. */
typedef struct trusttunnel_s trusttunnel_t;

/** VPN session state. The values mirror `ag::VpnSessionState` 1:1. */
typedef enum trusttunnel_vpn_state {
    TRUSTTUNNEL_VPN_DISCONNECTED = 0,
    TRUSTTUNNEL_VPN_CONNECTING = 1,
    TRUSTTUNNEL_VPN_CONNECTED = 2,
    TRUSTTUNNEL_VPN_WAITING_RECOVERY = 3,
    TRUSTTUNNEL_VPN_RECOVERING = 4,
    TRUSTTUNNEL_VPN_WAITING_FOR_NETWORK = 5,
} trusttunnel_vpn_state_t;

/** Error codes returned by `trusttunnel_start()` and `trusttunnel_stop()`. */
typedef enum trusttunnel_vpn_error {
    TRUSTTUNNEL_VPN_SUCCESS = 0,
    TRUSTTUNNEL_VPN_ALREADY_RUNNING = 1,
    TRUSTTUNNEL_VPN_INVALID_CONFIG = 2,
} trusttunnel_vpn_error_t;

/**
 * Tunnel device parameters reported once they are final.
 * All pointers are owned by the library and are only valid for the duration of
 * the callback invocation.
 */
typedef struct trusttunnel_network_info {
    /** Actual TUN interface name (kernel-assigned names are resolved). */
    const char *iface_name;
    /** IPv4 address of the interface without the prefix length, empty string if none. */
    const char *ipv4_address;
    /** IPv4 prefix length: 32 for a bare address, 0 if there is no address. */
    uint32_t ipv4_prefix;
    /** IPv6 address of the interface without the prefix length, empty string if none. */
    const char *ipv6_address;
    /** IPv6 prefix length: 128 for a bare address, 0 if there is no address. */
    uint32_t ipv6_prefix;
    /** MTU of the interface. */
    uint32_t mtu;
    /** NULL-terminated array of DNS servers used by the tunnel. */
    const char *const *dns_servers;
    /** Number of entries in `dns_servers`. */
    size_t dns_servers_count;
} trusttunnel_network_info_t;

/**
 * Called each time the VPN session state changes.
 * Runs on a library thread, see the threading notes in the file comment.
 */
typedef void (*trusttunnel_on_state_changed_t)(void *arg, trusttunnel_vpn_state_t state);

/**
 * Called with a connection telemetry record (JSON).
 * Runs on a library thread, see the threading notes in the file comment.
 */
typedef void (*trusttunnel_on_connection_info_t)(void *arg, const char *json);

/**
 * Called once the tunnel device is initialized and its network parameters are final.
 * Runs on a library thread, see the threading notes in the file comment.
 */
typedef void (*trusttunnel_on_network_ready_t)(void *arg, const trusttunnel_network_info_t *info);

/** Callbacks and their arguments. All fields are optional (NULL callbacks are ignored). */
typedef struct trusttunnel_callbacks {
    void *state_changed_arg;
    trusttunnel_on_state_changed_t on_state_changed;
    void *connection_info_arg;
    trusttunnel_on_connection_info_t on_connection_info;
    void *network_ready_arg;
    trusttunnel_on_network_ready_t on_network_ready;
} trusttunnel_callbacks_t;

/**
 * Create a VPN client instance. Does not start a connection.
 * @param callbacks Callbacks invoked for client events (see the threading notes above).
 *                  Copied by the library; the pointers passed inside remain owned by
 *                  the caller and must stay valid until `trusttunnel_destroy()`.
 * @return On success, a pointer to the new instance. On error, a null pointer.
 */
trusttunnel_t *trusttunnel_create(const trusttunnel_callbacks_t *callbacks);

/**
 * Start (connect) a VPN client with the provided TOML configuration
 * (same format as the CLI client's `trusttunnel_client.toml`).
 * The configuration is parsed synchronously; on success the client transitions to
 * the CONNECTING state (reported through the state callback) and the connection
 * runs on a library thread.
 * @return `TRUSTTUNNEL_VPN_SUCCESS`, or an error code (`TRUSTTUNNEL_VPN_ALREADY_RUNNING`,
 *         `TRUSTTUNNEL_VPN_INVALID_CONFIG`).
 */
trusttunnel_vpn_error_t trusttunnel_start(trusttunnel_t *vpn, const char *toml_config);

/**
 * Request a stop of the active session. Does not block: the final DISCONNECTED state
 * is reported through the state callback once the client has been torn down.
 * @return `TRUSTTUNNEL_VPN_SUCCESS`, or an error code.
 */
trusttunnel_vpn_error_t trusttunnel_stop(trusttunnel_t *vpn);

/** Last known VPN state. Reflects enqueued transitions immediately. */
trusttunnel_vpn_state_t trusttunnel_get_state(trusttunnel_t *vpn);

/**
 * The event fd that becomes readable whenever new client events are pending.
 * Intended for integration with the consumer's event loop (epoll/sd-event):
 * when the fd is readable, call `trusttunnel_drain()`.
 * @return The fd, or -1 if `vpn` is null. The fd is owned by the library.
 */
int trusttunnel_event_fd(trusttunnel_t *vpn);

/**
 * Drain pending client events, invoking the corresponding callbacks. Must be called
 * on the consumer's loop thread whenever `trusttunnel_event_fd()` is readable.
 */
void trusttunnel_drain(trusttunnel_t *vpn);

/**
 * Stop the active session (if any) and free the instance. Blocks until the client
 * thread has been torn down, so call it outside of callback/event-loop contexts.
 */
void trusttunnel_destroy(trusttunnel_t *vpn);

#ifdef __cplusplus
} // extern "C"
#endif
