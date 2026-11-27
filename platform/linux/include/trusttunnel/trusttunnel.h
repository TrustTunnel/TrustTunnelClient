#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define TT_LINUX_EXPORT __attribute__((visibility("default")))
#else
#define TT_LINUX_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct trusttunnel_s trusttunnel_t;

/** See `ag::VpnSessionState`. */
typedef void (*on_state_changed_t)(void *arg, int state);

/**
 * Called with a connection telemetry record serialized as JSON.
 * The string is owned by the library and is valid only for the duration of the callback invocation.
 */
typedef void (*on_connection_info_t)(void *arg, const char *json);

/**
 * Start (connect) a VPN client.
 *
 * The call returns immediately; the connection is established asynchronously. State transitions,
 * including failures, are reported through `state_changed_cb`.
 *
 * The client runs in a single process-wide manager: only one VPN session may exist at a time, and
 * starting a new one requires stopping the previous one. If the client disconnects on its own (for
 * example because the endpoint is unreachable), call `trusttunnel_stop()` before the next
 * `trusttunnel_start()`, otherwise the new call reports that the VPN has already been started.
 *
 * A `trusttunnel_stop()` issued while a `trusttunnel_start()` is still connecting does not abort the
 * connection attempt: it is queued and executed after the attempt finishes.
 *
 * Starting the client has process-wide side effects: the global log level is set from the
 * configuration, the post-quantum group setting is applied globally, and the shared network-manager
 * state is used. Plan for one VPN session per process.
 *
 * The callbacks and their arguments must remain valid throughout the lifetime of the client.
 *
 * @param toml_config VPN client parameters in TOML format (the CLI client configuration).
 * @param fall_into_recovery If true, failures during initial connection establishment enter the
 *                           recovery algorithm (`VPN_CRP_FALL_INTO_RECOVERY`) instead of retrying
 *                           a fixed number of times (`VPN_CRP_SEVERAL_ATTEMPTS`).
 * @param state_changed_cb A function which will be called each time the VPN client's state changes.
 * @param state_changed_cb_arg An argument passed to each invocation of the state change function.
 */
TT_LINUX_EXPORT void trusttunnel_start(const char *toml_config, bool fall_into_recovery,
        on_state_changed_t state_changed_cb, void *state_changed_cb_arg);

/**
 * Stop (disconnect) the VPN client started by `trusttunnel_start()` and free all associated resources.
 * Does nothing if no client is running.
 */
TT_LINUX_EXPORT void trusttunnel_stop(void);

/**
 * Start (connect) a VPN client and return an instance handle.
 *
 * Blocks until the connection is initiated. On success the caller owns the returned instance and
 * must release it with `trusttunnel_stop_ex()`. A null pointer is returned when the configuration
 * is invalid or the client cannot be created; a later connection failure is reported through
 * `state_changed_cb`.
 *
 * The callbacks and their arguments passed to this function must remain valid throughout the
 * lifetime of the VPN client.
 *
 * @param toml_config VPN client parameters in TOML format (the CLI client configuration).
 * @param fall_into_recovery If true, failures during initial connection establishment enter the
 *                           recovery algorithm (`VPN_CRP_FALL_INTO_RECOVERY`) instead of retrying
 *                           a fixed number of times (`VPN_CRP_SEVERAL_ATTEMPTS`).
 * @param state_changed_cb A function which will be called each time the VPN client's state changes.
 * @param state_changed_cb_arg An argument passed to each invocation of the state change function.
 * @param connection_info_cb A function called each time a connection is made through the VPN.
 * @param connection_info_cb_arg An argument passed to each invocation of the connection info function.
 * @return On success, a pointer to the started VPN client instance. On error, a null pointer.
 */
TT_LINUX_EXPORT trusttunnel_t *trusttunnel_start_ex(const char *toml_config, bool fall_into_recovery,
        on_state_changed_t state_changed_cb, void *state_changed_cb_arg, on_connection_info_t connection_info_cb,
        void *connection_info_cb_arg);

/**
 * Stop (disconnect) the given VPN client and free all associated resources.
 * @param vpn The instance returned by `trusttunnel_start_ex()`, or NULL.
 */
TT_LINUX_EXPORT void trusttunnel_stop_ex(trusttunnel_t *vpn);

/**
 * Callbacks are invoked from the library's internal threads. The caller must not run non-trivial
 * work inside them and must not call the library's functions without a context switch.
 */

#ifdef __cplusplus
} // extern "C"
#endif
