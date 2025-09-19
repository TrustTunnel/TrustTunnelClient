#pragma once

#include <stddef.h>
#include <stdint.h>

#include "vpn/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vpn_easy_s vpn_easy_t;
typedef void (*on_state_changed_t)(void *arg, int new_state_description);

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

#ifdef __cplusplus
}; // extern "C"
#endif
