#pragma once

#include <stddef.h>
#include <stdint.h>

#include "vpn/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpn_easy_s vpn_easy_t;

/** See `ag::VpnSessionState`. */
typedef void (*on_state_changed_t)(void *arg, int state);

/** See `ag::VpnConnectionInfoEvent`. */
typedef void (*on_connection_info_t)(void *arg, void *connection_info);

/** Callback for receiving connection info as a JSON string. Used by `vpn_easy_read_all_connection_info`
    and `vpn_easy_service_start`. */
typedef void (*on_connection_info_json_t)(void *arg, const char *json);

/**
 * Start (connect) a VPN client.
 * @param toml_config VPN client parameters in TOML format.
 * @param state_changed_cb A function which will be called each time the VPN client's state changes.
 *                         Must be valid throughout the VPN client lifetime.
 * @param state_changed_cb_arg An argument passed to each invocation of the state change function.
 *                             Must be valid throught the VPN client lifetime.
 * @return On success, a pointer to the started VPN client instance. On error, a null pointer.
 */
WIN_EXPORT void vpn_easy_start(
        const char *toml_config, on_state_changed_t state_changed_cb, void *state_changed_cb_arg);

/**
 * Stop (disconnect) a VPN client and free all associated resources.
 */
WIN_EXPORT void vpn_easy_stop();

/**
 * Start (connect) a VPN client. The callbacks and their arguments passed to this function
 * must remain valid throughout the lifetime of the VPN client.
 * @param toml_config VPN client parameters in TOML format.
 * @param state_changed_cb A function which will be called each time the VPN client's state changes.
 * @param state_changed_cb_arg An argument passed to each invocation of the state change function.
 * @param connection_info_cb A function called each time a connection is made through the VPN.
 * @param connection_info_cb_arg An argument passed to each invocation of the connection info function.
 * @return On success, a pointer to the started VPN client instance. On error, a null pointer.
 */
vpn_easy_t *vpn_easy_start_ex(const char *toml_config, on_state_changed_t state_changed_cb, void *state_changed_cb_arg,
        on_connection_info_t connection_info_cb, void *connection_info_cb_arg);

/** Stop (disconnect) a VPN client and free all associated resources. */
void vpn_easy_stop_ex(vpn_easy_t *vpn);

/**
 * Read all persisted connection info records from a PersistentRingBuffer file
 * and deliver them to the provided callback.
 *
 * If the file does not exist or is empty, the callback is not invoked and
 * the function returns normally. If the file is corrupted, it is cleared
 * and the function returns normally.
 *
 * @param ring_buffer_path Path to the PersistentRingBuffer file (UTF-8).
 * @param connection_info_cb A function called for each record. The `json`
 *                           parameter is a null-terminated UTF-8 JSON string
 *                           valid only for the duration of the callback.
 * @param connection_info_cb_arg An argument passed to each invocation.
 */
WIN_EXPORT void vpn_easy_read_all_connection_info(
        const char *ring_buffer_path, on_connection_info_json_t connection_info_cb, void *connection_info_cb_arg);

#ifdef __cplusplus
}; // extern "C"
#endif
