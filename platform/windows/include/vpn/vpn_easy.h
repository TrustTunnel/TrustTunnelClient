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

#ifdef __cplusplus
}; // extern "C"
#endif
