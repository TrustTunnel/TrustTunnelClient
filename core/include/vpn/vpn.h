#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vpn/platform.h" // Unbreak Windows build

#include <event2/buffer.h>
#include <openssl/x509.h>

#include "common/logger.h"
#include "net/os_tunnel.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"
#include "tcpip/tcpip.h"

namespace ag {

enum {
    VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS = 30 * 1000, // for VPN endpoint connection
    VPN_DEFAULT_TCP_TIMEOUT_MS = TCPIP_TCP_TIMEOUT_FOR_ESTABLISHED_S * 1000, // for bypassed server-side and client-side TCP connections
    VPN_DEFAULT_UDP_TIMEOUT_MS = TCPIP_UDP_TIMEOUT_S * 1000, // for bypassed and redirected server-side and client-side UDP connections
    VPN_DEFAULT_MAX_CONN_BUFFER_FILE_SIZE = 4 * 1024 * 1024,
    VPN_DEFAULT_CONN_MEMORY_BUFFER_THRESHOLD = DEFAULT_CONNECTION_MEMORY_BUFFER_SIZE,
    VPN_DEFAULT_ENDPOINT_PINGING_PERIOD_MS = 60 * 1000,
    VPN_DEFAULT_RECOVERY_LOCATION_UPDATE_PERIOD_MS = 70 * 1000,
    VPN_DEFAULT_INITIAL_RECOVERY_INTERVAL_MS = 1 * 1000,
    VPN_DEFAULT_CONNECT_ATTEMPTS_NUM = 5,
    VPN_DEFAULT_FALLBACK_CONNECT_DELAY_MS = 1 * 1000,
    VPN_DEFAULT_POSTPONEMENT_WINDOW_MS =
            3 * 1000, // how long after recovery starts connections are postponed instead of bypassed
};

static const float VPN_DEFAULT_RECOVERY_BACKOFF_RATE = 1.3f;

typedef enum {
    VPN_EC_NOERROR, // Depending on context may mean successful operation status (if returned from `vpn_connect`)
                    // or an endpoint session is closed without any error (if raised with `VPN_EVENT_STATE_CHANGED`)
    VPN_EC_ERROR,   // General code for the errors not described below
    VPN_EC_INVALID_SETTINGS,     // Settings passed for an operation are invalid
    VPN_EC_ADDR_IN_USE,          // Operation failed because the specified address was in use
    VPN_EC_INVALID_STATE,        // VPN client instance is in invalid state for the requested operation
    VPN_EC_AUTH_REQUIRED,        // Authorization error (in case user credentials are invalid or expired)
    VPN_EC_LOCATION_UNAVAILABLE, // None of the endpoints in a location are available
    VPN_EC_EVENT_LOOP_FAILURE,   // Failed to start the IO event loop, or it unexpectedly terminated
    VPN_EC_INITIAL_CONNECT_FAILED,  // No connection attempts left after initial connect() call
} VpnErrorCode;

typedef struct Vpn Vpn;
typedef void VpnListener;

/**
 * TUN device handler configuration
 */
typedef struct {
    /**
     * File descriptor of TUN device. If -1, the client handler expects that
     * `tunnel` is specified. If `tunnel` is NULL, it is expected that an application will
     * provide data packet from a client application via `vpn_process_client_packet` and send
     * data from a server in `VPN_EVENT_CLIENT_OUTPUT` handler. Otherwise it listens the descriptor
     * by itself.
     */
    evutil_socket_t fd;
    /**
     * For non-fd mode, if specified, then `VPN_EVENT_CLIENT_OUTPUT is not needed - it will be automatically passed to this tunnel.
     */
    VpnOsTunnel *tunnel;
    /** Maximum transfer unit for TCP protocol (if 0, `DEFAULT_MTU_SIZE` will be used) */
    uint32_t mtu_size;
    /** Pcap file name */
    const char *pcap_filename;
} VpnTunListenerConfig;

/**
 * SOCKS listener configuration
 */
typedef struct {
    /**
     * Address to listen on for SOCKS5 traffic (if not set, `127.0.0.1` will be used).
     * Recognized formats are:
     *    - [IPv6Address]:port
     *    - [IPv6Address]
     *    - IPv6Address
     *    - IPv4Address:port
     *    - IPv4Address
     * If port is 0 or not specified, it will be chosen automatically.
     */
    struct sockaddr_storage listen_address;
    /**
     * If set, require this username to connect.
     * Must be set if `listen_address` is not a loopback address or if `password` is set.
     */
    const char *username;
    /**
     * If set, require this password to connect.
     * Must be set if `username` is set.
     */
    const char *password;
} VpnSocksListenerConfig;

/**
 * Common settings for all types of listeners.
 */
typedef struct {
    /** Socket operations timeout (if 0, `VPN_DEFAULT_TCP_TIMEOUT_MS` will be used) */
    uint32_t timeout_ms;
    /**
     * Optional.
     * If configured, the library will intercept and route plain DNS queries to the DNS resolvers.
     * One of the following kinds:
     *     8.8.8.8:53 -- plain DNS
     *     tcp://8.8.8.8:53 -- plain DNS over TCP
     *     tls://1.1.1.1 -- DNS-over-TLS
     *     https://dns.adguard.com/dns-query -- DNS-over-HTTPS
     *     sdns://... -- DNS stamp (see https://dnscrypt.info/stamps-specifications)
     *     quic://dns.adguard.com:8853 -- DNS-over-QUIC
     */
    AG_ARRAY_OF(const char *) dns_upstreams;
} VpnListenerConfig;

/**
 * Communication protocols between a VPN client and an endpoint
 */
typedef enum {
    VPN_UP_HTTP2,
    VPN_UP_HTTP3,
} VpnUpstreamProtocol;

typedef struct {
    /** Number of parallel HTTP2 sessions. If 0, default value will be assigned. */
    uint32_t connections_num;
} VpnHttp2UpstreamConfig;

typedef struct {
    /** QUIC protocol version. If 0, default version will be used */
    uint32_t quic_version;
} VpnHttp3UpstreamConfig;

typedef struct {
    /**
     * If a session with selected endpoint is lost, the library tries to recover it using exponential
     * backoff intervals between attempts. This field defines the rate of increasing of the interval.
     * If less then 1, `VPN_DEFAULT_RECOVERY_BACKOFF_RATE` will be assigned.
     */
    float backoff_rate;
    /**
     * In case session recovery takes too long the library re-select an endpoint by pinging
     * the location. This field defines the period between updates.
     * If 0, `VPN_DEFAULT_RECOVERY_LOCATION_UPDATE_PERIOD_MS` will be assigned.
     */
    uint32_t location_update_period_ms;
} VpnUpstreamSessionRecoverySettings;

typedef struct {
    /** VPN endpoint communication protocol */
    VpnUpstreamProtocol type;
    union {
        VpnHttp2UpstreamConfig http2;
        VpnHttp3UpstreamConfig http3;
    };
} VpnUpstreamProtocolConfig;

typedef struct {
    /** By default falling back is disabled */
    bool enabled;
    /**
     * The delay period after which the library begins to connect using the fallback protocol.
     * The connection procedure by the main protocol does not stop in this case.
     * The connection to the endpoint will eventually be through the protocol that established
     * it faster.
     * If 0, the default value (`VPN_DEFAULT_FALLBACK_CONNECT_DELAY_MS`) will be assigned.
     */
    uint32_t connect_delay_ms;
    /** Fall back upstream protocol configuration */
    VpnUpstreamProtocolConfig protocol;
} VpnUpstreamFallbackConfig;

/**
 * VPN client's server-side interface configuration
 */
typedef struct {
    /** Protocol-specific configuration */
    VpnUpstreamProtocolConfig protocol;
    /**
     * A location to connect to. An endpoint is selected by the location ping algorithm,
     * see `locations_pinger_t` for details.
     */
    VpnLocation location;
    /**
     * Time out value for VPN endpoints addresses ping operation.
     * If 0, `DEFAULT_PING_TIMEOUT_MS` will be assigned.
     */
    uint32_t location_ping_timeout_ms;
    /**
     * Socket operations timeout. If 0, `VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS` will be assigned.
     * Used for IO operations and server session establishing during `vpn_connect`.
     */
    uint32_t timeout_ms;
    /**
     * The library periodically pings a VPN endpoint. This is needed for an endpoint to increase its
     * confidence in the connected client legitimacy, and for the library to update connectivity
     * status.
     * This field contains the period value of the pinging.
     * If 0, `VPN_DEFAULT_ENDPOINT_PINGING_PERIOD_MS` will be assigned.
     */
    uint32_t endpoint_pinging_period_ms;
    /** Username for authorization */
    const char *username;
    /** Password for authorization */
    const char *password;
    /** Session recovery settings */
    VpnUpstreamSessionRecoverySettings recovery;
    /** Fall back configuration */
    VpnUpstreamFallbackConfig fallback;
    /** Enable anti-dpi measures */
    bool anti_dpi;
} VpnUpstreamConfig;

/**
 * VPN client application events identifiers
 */
typedef enum {
    VPN_EVENT_PROTECT_SOCKET,     /** Raised when socket needs to be protected (raised with `SocketProtectEvent`) */
    VPN_EVENT_VERIFY_CERTIFICATE, /** Raised when VPN needs to verify certificate (raised with
                                     `VpnVerifyCertificateEvent`) */
    VPN_EVENT_STATE_CHANGED, /** Raised when VPN endpoint session state is changed (raised with `VpnStateChangedEvent`)
                              */
    VPN_EVENT_CLIENT_OUTPUT, /** Raised when some data from server is ready to be sent to client application (raised
                                with `VpnClientOutputEvent`) */
    VPN_EVENT_CONNECT_REQUEST,           /** Raised when new incoming connection is appeared (raised with
                                            `VpnConnectRequestEvent`) */
    VPN_EVENT_ENDPOINT_CONNECTION_STATS, /** Raised when requested (with `vpn_request_endpoint_connection_stats`)
                                            connection statistics is ready (raised with
                                            `VpnEndpointConnectionStatsEvent`) */
    VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE,  /** Raised if a health check on the configured DNS upstream is failed (raised
                                            with `VpnDnsUpstreamUnavailableEvent`) */
    VPN_EVENT_TUNNEL_CONNECTION_STATS,   /** Notifies of connection statistics updates (raised with
                                            `VpnTunnelConnectionStatsEvent` and only for connections routed through
                                            a VPN endpoint) */
    VPN_EVENT_TUNNEL_CONNECTION_CLOSED,  /** Raised when a connection is closed (raised with
                                            `VpnTunnelConnectionClosedEvent`) */
} VpnEvent;

typedef struct {
    X509_STORE_CTX *ctx; // SSL context to verify
    int result;          // FILLED BY HANDLER: operation result (0 in case of success)
} VpnVerifyCertificateEvent;

typedef enum {
    /**
     * Idle state. VPN client is disconnected and waiting for call to `vpn_connect`.
     */
    VPN_SS_DISCONNECTED,
    /**
     * VPN client is connecting to an endpoint after call to `vpn_connect`.
     * If the connection fails, returns to `VPN_SS_DISCONNECTED` state,
     * otherwise to `VPN_SS_CONNECTED` state.
     */
    VPN_SS_CONNECTING,
    /**
     * VPN client is connected to an endpoint.
     * If connection to an endpoint is lost with a fatal error, state changes to `VPN_SS_DISCONNECTED`.
     * Otherwise, if the connection is lost with a non-fatal error, state changes to `VPN_SS_WAITING_RECOVERY`.
     */
    VPN_SS_CONNECTED,
    /**
     * VPN client is waiting for the next connection recovery attempt.
     * If connection to an endpoint is lost with a fatal error, state changes to `VPN_SS_DISCONNECTED`.
     * If the connection recovery is initiated successfully, state changes to `VPN_SS_RECOVERING`.
     * Otherwise, stays in this state and waits for the next attempt.
     */
    VPN_SS_WAITING_RECOVERY,
    /**
     * VPN client is re-connecting to an endpoint.
     * If connection to an endpoint is lost with a fatal error, state changes to `VPN_SS_DISCONNECTED`.
     * If the connection recovery succeeds, state changes to `VPN_SS_CONNECTED`.
     * Otherwise, returns to `VPN_SS_WAITING_RECOVERY` and waits for the next attempt.
     */
    VPN_SS_RECOVERING,
} VpnSessionState;

typedef struct {
    ag::VpnError error;       // error caused disconnect
    uint32_t time_to_next_ms; // time to next recovery attempt
} VpnWaitingRecoveryInfo;

typedef struct {
    const VpnEndpoint *endpoint;          // the endpoint to which the library is connected
    const struct sockaddr *relay_address; // if connected through a relay, the relay's address
    VpnUpstreamProtocol protocol;         // the protocol used for this connection
} VpnConnectedInfo;

typedef struct {
    const char *location_id; // identifier of the location the VPN client is connected to
    VpnSessionState state;   // connection state
    union {
        VpnWaitingRecoveryInfo waiting_recovery_info; // valid if `state` is `VPN_SS_WAITING_RECOVERY`
        VpnConnectedInfo connected_info;              // valid if `state` is `VPN_SS_CONNECTED`
        ag::VpnError error;                           // valid for any other state
    };
} VpnStateChangedEvent;

typedef struct {
    int family; // ip family
    struct {
        size_t chunks_num;          // message vector size
        const struct iovec *chunks; // message vector
    } packet;                       // note, that it's a single packet which should be sent in one piece
} VpnClientOutputEvent;

typedef enum {
    VPN_AT_ADDR, // address contains socket address
    VPN_AT_HOST, // address contains host name + port
} VpnAddressType;

typedef struct {
    ag::VpnStr name;
    uint32_t port;
} VpnHostPort;

typedef struct {
    VpnAddressType type;
    union {
        struct sockaddr_storage addr;
        VpnHostPort host;
    };
} VpnAddress;

typedef struct {
    uint64_t id;                // connection id
    int proto;                  // connection protocol
    const struct sockaddr *src; // source address of connection
    const VpnAddress *dst;      // destination address of connection
    const char *app_name;       // application that initiated the request
} VpnConnectRequestEvent;

typedef struct {
    ag::VpnError error;           // some error in case the statistics could not be collected
    VpnUpstreamProtocol protocol; // endpoint connection protocol
    ag::VpnConnectionStats stats; // endpoint connection statistics
} VpnEndpointConnectionStatsEvent;

typedef struct {
} VpnDnsUpstreamUnavailableEvent;

typedef struct {
    uint64_t id;       // Connection id, corresponds to the one raised in `VpnConnectRequestEvent`
    uint64_t upload;   // Number of uploaded bytes since the last notification
    uint64_t download; // Number of downloaded bytes since the last notification
} VpnTunnelConnectionStatsEvent;

typedef struct {
    uint64_t id; // Connection id, corresponds to the one raised in `VpnConnectRequestEvent`
} VpnTunnelConnectionClosedEvent;

typedef struct {
    void (*func)(void *arg, VpnEvent what, void *data);
    void *arg;
} VpnHandler;

/**
 * VPN client user-side connections actions
 */
typedef enum {
    /**
     * Route this connection according to the VPN mode (`VpnMode`) and exclusions
     * (`VpnSettings.exclusions`)
     */
    VPN_CA_DEFAULT,
    /**
     * Route this connection to the destination host directly _unconditionally_
     */
    VPN_CA_FORCE_BYPASS,
    /**
     * Route this connection through the VPN endpoint _unconditionally_
     */
    VPN_CA_FORCE_REDIRECT,
} VpnConnectAction;

/**
 * Defines how client's traffic goes to the target host
 */
typedef enum {
    /**
     * Route through a VPN endpoint all connections except ones which destinations are in exclusions
     */
    VPN_MODE_GENERAL,
    /**
     * Route through a VPN endpoint only the connections which destinations are in exclusions
     */
    VPN_MODE_SELECTIVE,
} VpnMode;

/**
 * List of VPN client settings
 */
typedef struct {
    VpnHandler handler;
    /** The VPN mode (see `VpnMode`) */
    VpnMode mode;
    /**
     * Whitespace-separated list of the domains and addresses which should be routed in a special
     * manner
     *
     * Supported syntax:
     *
     *  `entry1[ entry2]...`
     *
     *      - the list consists of entries which are separated by whitespaces
     *      - each entry contains:
     *          - domain name
     *              - if starts with "*.", any subdomain of the domain will be matched including
     *                www-subdomain, but not the domain itself (e.g., `*.example.com` will match
     *                `sub.example.com`, `sub.sub.example.com`, `www.example.com`, but not `example.com`)
     *              - if starts with "www." or it's just a domain name, the domain itself and its
     *                www-subdomain will be matched (e.g. `example.com` and `www.example.com` will
     *                match `example.com` `www.example.com`, but not `sub.example.com`)
     *          - ip address
     *              - recognized formats are:
     *                  - [IPv6Address]:port
     *                  - [IPv6Address]
     *                  - IPv6Address
     *                  - IPv4Address:port
     *                  - IPv4Address
     *              - if port is not specified, any port will be matched
     *          - CIDR range
     *              - recognized formats are:
     *                  - IPv4Address/mask
     *                  - IPv6Address/mask
     *
     *  examples:
     *      - example.org 1.2.3.4
     *      - 1.1.1.1:1 [feed::beef] www.example.com
     *      - [deaf::beef]:12 *.example.com
     */
    ag::VpnStr exclusions;
    /**
     * Path to directory where some temporary files (like connection buffers) will be stored.
     * If null, temporary files won't be used at all.
     */
    const char *tmp_files_base_path;
    /**
     * Connection in-memory buffer size exceeding which causes storing incoming data in a file.
     * If `tmp_files_base_path` is null, takes no effect. Otherwise, if equals 0,
     * `VPN_DEFAULT_CONN_MEMORY_BUFFER_THRESHOLD` will be used.
     */
    int conn_memory_buffer_threshold;
    /**
     * Maximum size of file of a connection data buffer.
     * If `tmp_files_base_path` is null, takes no effect. Otherwise, if equals 0,
     * `VPN_DEFAULT_MAX_CONN_BUFFER_FILE_SIZE` will be used.
     */
    int max_conn_buffer_file_size;
    /**
     * When disabled, all connection requests are routed directly to target hosts in case session
     * to VPN endpoint is lost and the library fails to recover it. This helps not to break
     * an Internet connection if user has poor connectivity to an endpoint.
     *
     * When enabled, incoming connection requests which should be routed through
     * an endpoint will not be routed directly in that case.
     */
    bool killswitch_enabled;
} VpnSettings;

/**
 * Information about a connection to complete its request
 */
typedef struct {
    uint64_t id;             // connection id
    VpnConnectAction action; // what to do with the connection (see `VpnConnectAction`)
    const char *appname;     // name of the application which initiated connection
    int uid;                 // the application id
} VpnConnectionInfo;

/**
 * Defines the behavior in case of the VPN endpoint connection failure during
 * the connection establishing procedure
 */
typedef enum {
    /// Try to establish the connection for the configured number of times.
    /// Go to the `VPN_SS_DISCONNECTED` state in case of all of them failed.
    VPN_CRP_SEVERAL_ATTEMPTS,
    /// In case of failure go to the `VPN_SS_WAITING_RECOVERY` state and fall
    /// into the connection recovery algorithm, just like if the client would
    /// lose the connection while were connected
    VPN_CRP_FALL_INTO_RECOVERY,
} VpnConnectRetyPolicy;

typedef struct {
    /// Defines the failure handling algorithm
    VpnConnectRetyPolicy policy;
    union {
        /// Valid for `VPN_CRP_SEVERAL_ATTEMPTS`.
        /// Number of the connection attempts
        /// (if <= 0, `VPN_DEFAULT_CONNECT_ATTEMPTS_NUM` will be used).
        int attempts_num;
    };
} VpnConnectRetryInfo;

typedef struct {
    /// VPN upstream configuration
    VpnUpstreamConfig upstream_config;
    /// Defines the failure handling algorithm
    VpnConnectRetryInfo retry_info;
} VpnConnectParameters;

extern "C" {

/**
 * Open VPN client
 * @param settings VPN client settings
 * @return null if failed, some instance otherwise
 */
WIN_EXPORT Vpn *vpn_open(const VpnSettings *settings);

/**
 * Proceed connection to a VPN server and check if communication with the server is possible
 * @param vpn VPN client
 * @param parameters VPN connect parameters
 * @return `VpnError` filled with `VpnErrorCode`
 */
WIN_EXPORT ag::VpnError vpn_connect(Vpn *vpn, const VpnConnectParameters *parameters);

/**
 * Forcibly initiate the next session recovery attempt. Do nothing if the VPN client is not between
 * recovery attempts (e.g., not in `VPN_SS_WAITING_RECOVERY` state).
 * @param vpn VPN client
 */
WIN_EXPORT void vpn_force_reconnect(Vpn *vpn);

/**
 * Start listening for client connections.
 * MUST be called after `vpn_connect`.
 * Please note that it may not be acceptable to run several instances simultaneously for some
 * listener configurations. It's up to an application to ensure that only a single instance is
 * listening at the moment or several listening instances have the compatible configurations.
 * @param vpn VPN client
 * @param listener The specific listener to listen with.
 *                 See `vpn_create_tun_listener()`, `vpn_create_socks_listener()`.
 *                 This function always takes ownership of the listener, regardless of the return value.
 * @param config The config common to all listener types.
 */
WIN_EXPORT ag::VpnError vpn_listen(Vpn *vpn, VpnListener *listener, const VpnListenerConfig *config);

/**
 * Stop VPN client.
 * MUST be called if either `vpn_connect` or `vpn_listen` was called previously.
 * MUST NOT be called in event handlers without a context switch (i.e., it's not safe to call
 * `vpn_stop` directly, for example, in disconnected event handler).
 * @param vpn VPN client
 */
WIN_EXPORT void vpn_stop(Vpn *vpn);

/**
 * Close VPN client
 * @param vpn VPN client
 */
WIN_EXPORT void vpn_close(Vpn *vpn);

/**
 * Return the address that the SOCKS listener is bound to.
 * The returned address is valid only if this function is called
 * after `vpn_listen()` has completed successfully with a result
 * of `vpn_create_socks_listener()` as an argument.
 */
WIN_EXPORT sockaddr_storage vpn_get_socks_listener_address(Vpn *vpn);

/**
 * Clone common listener config.
 * @return cloned config (must be freed by caller via `vpn_listener_config_destroy()`)
 */
WIN_EXPORT VpnListenerConfig vpn_listener_config_clone(const VpnListenerConfig *config);

/** Destroy cloned common listener config. */
WIN_EXPORT void vpn_listener_config_destroy(VpnListenerConfig *config);

/**
 * Pass data packets received from a client application to the client listener in case it
 * doesn't listen for incoming data by itself
 * @param vpn VPN client
 * @param packets packets
 */
void vpn_process_client_packets(Vpn *vpn, VpnPackets packets);

/**
 * Complete connect request according to action.
 * MAY be called from `VPN_EVENT_CONNECT_REQUEST` handler without a context switch.
 * @param vpn VPN client
 * @param info connection info
 */
WIN_EXPORT void vpn_complete_connect_request(Vpn *vpn, const VpnConnectionInfo *info);

/**
 * Update the VPN exclusion settings. This also resets all client connections without restarting vpn client.
 * @param vpn VPN client
 * @param mode the VPN mode
 * @param exclusions the exclusions list (see `VpnSettings.exclusions`)
 */
WIN_EXPORT void vpn_update_exclusions(Vpn *vpn, VpnMode mode, ag::VpnStr exclusions);

/**
 * Reset all connection with given application UID
 * @param vpn VPN client
 * @param uid an application UID. Use -1 to reset all connections.
 */
WIN_EXPORT void vpn_reset_connections(Vpn *vpn, int uid);

/**
 * Notify the instance of a network change.
 * @param vpn VPN client
 * @param network_loss_suspected true if it's possible that the network through which the library
 *                               was connected to an endpoint was lost
 */
void vpn_notify_network_change(Vpn *vpn, bool network_loss_suspected);

/**
 * Request the instance for an endpoint connection statistics.
 * The statistics is raised with `VPN_EVENT_ENDPOINT_CONNECTION_STATS` event.
 */
WIN_EXPORT void vpn_request_endpoint_connection_stats(Vpn *vpn);

/**
 * Notify the instance that the system is going to sleep.
 * The completion handler will be called when the instance is ready for sleeping.
 * The completion handler will always be called, even if the the instance is destroyed
 * after receiving the notification.
 * @param vpn VPN client
 * @param completion_handler ready callback, must NOT be NULL
 * @param arg ready callback argument
 */
void vpn_notify_sleep(Vpn *vpn, void (*completion_handler)(void *arg), void *arg);

/**
 * Notify the instance that the system has just waked up from sleep.
 * @param vpn VPN client
 */
void vpn_notify_wake(Vpn *vpn);

typedef enum {
    VPN_EVS_OK,        // an entry is valid
    VPN_EVS_MALFORMED, // an entry is not valid
} VpnExclusionValidationStatus;

/**
 * Check if a string is a valid exclusion
 * @param text string to check
 * @return see `VpnExclusionValidationStatus`
 */
WIN_EXPORT VpnExclusionValidationStatus vpn_validate_exclusion(const char *text);

typedef enum {
    VPN_DUVS_OK,        // an upstream is valid
    VPN_DUVS_MALFORMED, // an upstream is not valid
} VpnDnsUpstreamValidationStatus;

/**
 * Check if a string as a valid DNS resolver address
 * @param address the DNS resolver address (see `VpnListenerConfig#dns_upstream`'s description for details)
 * @return see `VpnDnsUpstreamValidationStatus`
 */
WIN_EXPORT VpnDnsUpstreamValidationStatus vpn_validate_dns_upstream(const char *address);

/**
 * Return the event loop that the VPN instance is running in.
 * If the event loop has not been started yet or has already been stopped, return NULL.
 */
WIN_EXPORT ag::VpnEventLoop *vpn_get_event_loop(Vpn *vpn);

/**
 * Disqualify the endpoint from connection procedure.
 * In case it is the currently connected one, disconnect and start recovery procedure.
 */
WIN_EXPORT void vpn_abandon_endpoint(Vpn *vpn, const VpnEndpoint *endpoint);

/** Create a TUN interface listener. */
WIN_EXPORT VpnListener *vpn_create_tun_listener(Vpn *vpn, const VpnTunListenerConfig *config);

/** Create a SOCKS listener. */
WIN_EXPORT VpnListener *vpn_create_socks_listener(Vpn *vpn, const VpnSocksListenerConfig *config);

} // extern "C"
} // namespace ag
