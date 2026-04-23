#pragma once

#include <stdint.h>

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
 * over the named pipe configured at service creation time (see `vpn_easy_service_install()`).
 * The format of the `data` field is given by the message type. Integers are in network byte order.
 */
typedef enum {
    /**
     * A request to start (connect) the VPN client. The data field must contain the VPN client configuration
     * in TOML format (encoded in UTF-8 as per TOML specification).
     *
     * If the client is already connecting or connected, it is requested to stop
     * first and then start with the new configuration.
     *
     * If the client fails to start for whatever reason, the service will send a state change
     * message with the state `VPN_SS_DISCONNECTED`.
     */
    VPN_EASY_SVC_MSG_START = 0,

    /**
     * A request to stop (disconnect) the VPN client. The length field must be zero, the data field empty.
     * If the client is already stopped, this message is ignored.
     */
    VPN_EASY_SVC_MSG_STOP,

    /**
     * Sent by the service when the VPN client state changes. `length` is always `4` in network byte order, `data`
     * is an `int32_t` in network byte order, one of the `ag::VpnSessionState` values.
     *
     * The service client should wait for this message after sending a start/stop request.
     */
    VPN_EASY_SVC_MSG_STATE_CHANGED,

    /**
     * Sent by the service to notify the client of a new connection through the VPN tunnel. The data field
     * is a JSON document describing the connection, as returned by `ag::ConnectionInfo::to_json()`.
     */
    VPN_EASY_SVC_MSG_CONNECTION_INFO,

    /**
     * A request to convey the last known state of the VPN client. The length field must be zero, the data field empty.
     * The service will respond with a state change message. This is useful when a client has just connected to the
     * service and wants to know the current state of the VPN client.
     */
    VPN_EASY_SVC_MSG_GET_LAST_STATE,
} VpnEasyServiceMessageType;

typedef enum {
    /** Access denied. Check if the calling process is running as administrator. */
    VPN_EASY_SVC_ERR_ACCESS = 1,

    /** Service already exists. Uninstall it with `vpn_easy_service_uninstall()` first. */
    VPN_EASY_SVC_ERR_SERVICE_EXISTS,

    /** Encountered an unexpected error. Probably as a result of API misusage. The log may contain more details. */
    VPN_EASY_SVC_ERR_OTHER,
} VpnEasyServiceError;

/**
 * Create and start a VPN service. This function requires administrator privileges. The service is configured
 * to start automatically at system startup. After startup, the service is listening on a named pipe `pipe_name`,
 * and can be controlled by connecting and sending messages on that pipe. The protocol details are given by the
 * description of `VpnEasyServiceMessageType` enumeration. Anyone can read/write from/to the pipe.
 * @param image_path The absolute path to the `vpn_easy_service` executable.
 * @param logfile_path The absolute path to the service's log file. Will be created if doesn't exist.
 * @param name The service name. At most 256 characters.
 * @param pipe_name The name for the named pipe used to communicate with the service.
 *                  A string of at most 256 characters of the form: "\\.\pipe\<pipename>", where "<pipename>"
 *                  can include any character except the backslash.
 * @param display_name The display name to be used by user interface programs to identify the service.
 *                     At most 256 characters.
 * @param description A comment that explains the purpose of the service.
 * @return Zero on success, one of `VpnEasyServiceError` constants on failure.
 */
WIN_EXPORT int32_t vpn_easy_service_install(const wchar_t *image_path, const wchar_t *logfile_path,
        const wchar_t *pipe_name, const wchar_t *name, const wchar_t *display_name, const wchar_t *description);

/**
 * Stop and delete the VPN service named `name`. This function requires administrator privileges. The service is
 * requested to stop and marked for deletion. It will be deleted when it has stopped and all handles to it have
 * been closed. If it doesn't stop for some reason, it will be deleted when the system is restarted.
 * @param name The service name that was passed to `vpn_easy_service_install()`.
 * @return Zero on success, one of `VpnEasyServiceError` constants on failure.
 */
WIN_EXPORT int32_t vpn_easy_service_uninstall(const wchar_t *name);

#ifdef __cplusplus
}; // extern "C"
#endif
