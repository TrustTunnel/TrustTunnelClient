#pragma once

#include <stdint.h>

#include "trusttunnel/trusttunnel.h"
#include "vpn/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Communication with the service is done by sending messages of the form:
 * ```
 * struct Message {
 *     uint32_t type;
 *     uint32_t length; // The length of the `data` field.
 *     uint8_t data[0]; // `length` bytes of data.
 * };
 * ```
 * over the named pipe configured at service creation time (see `trusttunnel_service_install()`).
 * The format of the `data` field is given by the message type. Integers are in network byte order.
 */
typedef enum {
    /**
     * A request to start (connect) the VPN client. The data field must contain the VPN client configuration
     * in TOML format (encoded in UTF-8 as per TOML specification).
     *
     * Ignored if the client is already connecting or connected: changing the configuration requires
     * an explicit `TRUSTTUNNEL_SVC_MSG_STOP` first.
     */
    TRUSTTUNNEL_SVC_MSG_START = 0,

    /**
     * A request to stop (disconnect) the VPN client. The length field must be zero, the data field empty.
     * If the client is already stopped, this message is ignored.
     */
    TRUSTTUNNEL_SVC_MSG_STOP,

    /**
     * Sent by the service when the VPN client state changes. `length` is always `4` in network byte order, `data`
     * is an `int32_t` in network byte order, one of the `ag::VpnSessionState` values.
     *
     * The service client should wait for this message after sending a start/stop request.
     */
    TRUSTTUNNEL_SVC_MSG_STATE_CHANGED,

    /**
     * Sent by the service to notify the client of a new connection through the VPN tunnel. The data field
     * is a JSON document describing the connection, as returned by `ag::ConnectionInfo::to_json()`.
     */
    TRUSTTUNNEL_SVC_MSG_CONNECTION_INFO,

    /**
     * A request to send the current VPN state. `length` must be zero, the data
     * field empty. The service will respond with a `TRUSTTUNNEL_SVC_MSG_STATE_CHANGED` message
     * containing the current VPN state value.
     */
    TRUSTTUNNEL_SVC_MSG_QUERY_STATE,

    /** Ask the service to clear its own log files. `length` must be zero, the data field empty.
     *  Fire-and-forget: the service clears its `service` log family and sends no response. */
    TRUSTTUNNEL_SVC_MSG_CLEAR_LOGS,
} TrusttunnelServiceMessageType;

typedef enum {
    /** Access denied. Check if the calling process is running as administrator. */
    TRUSTTUNNEL_SVC_ERR_ACCESS = 1,

    /** Service already exists. Uninstall it with `trusttunnel_service_uninstall()` first. */
    TRUSTTUNNEL_SVC_ERR_SERVICE_EXISTS,

    /** No service with the given name exists. */
    TRUSTTUNNEL_SVC_ERR_NO_SUCH_SERVICE,

    /** An operation on the service took too long. */
    TRUSTTUNNEL_SVC_ERR_TIMED_OUT,

    /** Encountered an unexpected error. Probably as a result of API misusage. The log may contain more details. */
    TRUSTTUNNEL_SVC_ERR_OTHER,
} TrusttunnelServiceError;

/** Callback for receiving connection info as a JSON string.
 *  Used by `trusttunnel_service_attach()` and `trusttunnel_service_read_all_connection_info()`. */
typedef void (*on_connection_info_json_t)(void *arg, const char *json);

/**
 * Create and start a VPN service. This function requires administrator privileges. The service is configured
 * to start manually (on demand). After startup, the service is listening on a named pipe `pipe_name`,
 * and can be controlled by connecting and sending messages on that pipe. The protocol details are given by the
 * description of `TrusttunnelServiceMessageType` enumeration. Anyone can read/write from/to the pipe.
 * @param image_path The absolute path to the `trusttunnel_service` executable.
 * @param logs_dir The absolute path to the directory where the service writes its rotating `service.log`
 *                 family. Created if absent.
 * @param pipe_name The name for the named pipe used to communicate with the service.
 *                  A string of at most 256 characters of the form: "\\.\pipe\<pipename>", where "<pipename>"
 *                  can include any character except the backslash.
 * @param name The service name. At most 256 characters.
 * @param display_name The display name to be used by user interface programs to identify the service.
 *                     At most 256 characters.
 * @param description A comment that explains the purpose of the service.
 * @param ring_buffer_path The absolute path to the persistent ring buffer file for connection info storage.
 * @return Zero on success, one of `TrusttunnelServiceError` constants on failure.
 */
WIN_EXPORT int32_t trusttunnel_service_install(const wchar_t *image_path, const wchar_t *logs_dir,
        const wchar_t *pipe_name, const wchar_t *name, const wchar_t *display_name, const wchar_t *description,
        const wchar_t *ring_buffer_path);

/**
 * Stop and delete the VPN service named `name`. This function requires administrator privileges. The service is
 * requested to stop and marked for deletion. It will be deleted when it has stopped and all handles to it have
 * been closed. If it doesn't stop for some reason, it will be deleted when the system is restarted.
 * @param name The service name that was passed to `trusttunnel_service_install()`.
 * @return Zero on success, one of `TrusttunnelServiceError` constants on failure.
 */
WIN_EXPORT int32_t trusttunnel_service_uninstall(const wchar_t *name);

/**
 * Start the VPN client, using the service and the callbacks bound by `trusttunnel_service_attach()`.
 *
 * This will start the Windows service if it's not already running, connect to the running service
 * through the named pipe and instruct it to start the VPN client with the provided configuration.
 * An existing pipe connection is reused. The service ignores the request if the VPN is already
 * running: changing the configuration requires an explicit `trusttunnel_service_stop()` first.
 *
 * @param toml_config The VPN client configuration in TOML format (encoded in UTF-8 as per TOML specification).
 * @return Zero on success, one of `TrusttunnelServiceError` constants on failure.
 */
WIN_EXPORT int32_t trusttunnel_service_start(const char *toml_config);

/**
 * Stop the VPN client.
 *
 * The request is sent to the service and this function returns without waiting: completion is
 * reported as a `VPN_SS_DISCONNECTED` state change. The Windows service is left running so that a
 * subsequent `trusttunnel_service_start()` does not have to start it again; use
 * `trusttunnel_service_uninstall()` to stop the service itself.
 *
 * @return Zero on success, one of `TrusttunnelServiceError` constants on failure.
 */
WIN_EXPORT int32_t trusttunnel_service_stop();

/**
 * Connect to a running VPN service to monitor its state. Does not start the VPN.
 * The service must already be running (typically started by a previous call to
 * `trusttunnel_service_start()`). If the service is not running, returns
 * `TRUSTTUNNEL_SVC_ERR_NO_SUCH_SERVICE`.
 *
 * Must be called before `trusttunnel_service_start()`: it binds the service name, the pipe name and
 * the callbacks, and that binding is kept even when the service turns out not to be running.
 *
 * After a successful call, state changes are delivered to `state_changed_cb` and
 * connection info events to `connection_info_cb`. The callbacks (and their `_arg`
 * parameters) must remain valid until `trusttunnel_service_detach()` is called.
 *
 * @param service_name The service name passed to `trusttunnel_service_install()`.
 * @param pipe_name The pipe name passed to `trusttunnel_service_install()`.
 * @param state_changed_cb State change callback.
 * @param state_changed_cb_arg Argument for state change callback.
 * @param connection_info_cb Connection info callback. May be NULL.
 * @param connection_info_cb_arg Argument for connection info callback.
 * @return Zero on success, one of `TrusttunnelServiceError` constants on failure.
 */
WIN_EXPORT int32_t trusttunnel_service_attach(const wchar_t *service_name, const wchar_t *pipe_name,
        on_state_changed_t state_changed_cb, void *state_changed_cb_arg, on_connection_info_json_t connection_info_cb,
        void *connection_info_cb_arg);

/**
 * Detach from the VPN service. Tears down the pipe connection and stops the IO thread.
 * After this call, state change and connection info callbacks will no longer be invoked.
 * No-op if not currently attached.
 */
WIN_EXPORT void trusttunnel_service_detach();

/**
 * Read all persisted connection info records from a PersistentRingBuffer file
 * and deliver them to the provided callback.
 *
 * If the file does not exist or is empty, the callback is not invoked and
 * the function returns normally. If the file is corrupted, it is cleared
 * and the function returns normally.
 *
 * @param ring_buffer_path Path to the PersistentRingBuffer file.
 * @param connection_info_cb A function called for each record. The `json`
 *                           parameter is a null-terminated UTF-8 JSON string
 *                           valid only for the duration of the callback.
 * @param connection_info_cb_arg An argument passed to each invocation.
 */
WIN_EXPORT void trusttunnel_service_read_all_connection_info(
        const wchar_t *ring_buffer_path, on_connection_info_json_t connection_info_cb, void *connection_info_cb_arg);

#ifdef __cplusplus
}; // extern "C"
#endif
