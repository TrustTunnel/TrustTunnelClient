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

/** Callback invoked once per exported log file with its absolute path (native wide encoding). */
typedef void (*on_log_path_t)(void *arg, const wchar_t *path);

/**
 * Initialize file logging for the client process.
 *
 * Installs a rotating file logger that writes the client log family into `logs_dir` (created if
 * absent) and becomes the global log sink. `logs_dir` is remembered so that `vpn_easy_log_export()`
 * and `vpn_easy_log_clear()` can also reach the service log family, which the service process
 * writes into the same directory.
 *
 * Call once, early, before anything logs. Subsequent calls are ignored.
 * @param logs_dir The absolute path to the directory that holds the client and service log families.
 */
WIN_EXPORT void vpn_easy_log_init(const wchar_t *logs_dir);

/**
 * Copy the client and service log families into `dest_dir` (created if absent) and invoke `path_cb`
 * once per copied file. Missing files are skipped. No-op if logging was not initialized.
 * @param dest_dir The absolute path to the directory to copy the log files into. The caller owns it.
 * @param path_cb A function called once per copied file with its absolute path (native wide encoding).
 * @param path_cb_arg An argument passed to each invocation of `path_cb`.
 */
WIN_EXPORT void vpn_easy_log_export(const wchar_t *dest_dir, on_log_path_t path_cb, void *path_cb_arg);

/**
 * Clear the client and service log families. Resets the client's own file directly and asks the
 * running service to clear its family over the pipe, falling back to clearing the service files
 * directly when the service is not connected. No-op if logging was not initialized.
 */
WIN_EXPORT void vpn_easy_log_clear(void);

#ifdef __cplusplus
}; // extern "C"
#endif
