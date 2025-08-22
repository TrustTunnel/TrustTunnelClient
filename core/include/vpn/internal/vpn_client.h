#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <string>

#ifdef __APPLE__
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#include "vpn/internal/qos_settings.h"
#endif // TARGET_OS_IPHONE

#endif // __APPLE__

#include "common/defs.h"
#include "common/logger.h"
#include "net/locations_pinger.h"
#include "net/network_manager.h"
#include "net/utils.h"
#include "net/tcp_socket.h"
#include "net/quic_connector.h"
#include "vpn/event_loop.h"
#include "vpn/fsm.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/data_buffer.h"
#include "vpn/internal/dns_proxy_accessor.h"
#include "vpn/internal/domain_filter.h"
#include "vpn/internal/domain_lookuper.h"
#include "vpn/internal/endpoint_connector.h"
#include "vpn/internal/id_generator.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/tunnel.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_dns_resolver.h"
#include "vpn/vpn.h"

namespace ag {
namespace vpn_client {

enum Event {
    EVENT_PROTECT_SOCKET,     /** Raised when socket needs to be protected (raised with `SocketProtectEvent`) */
    EVENT_VERIFY_CERTIFICATE, /** Raised when VPN needs to verify certificate (raised with
                                 `VpnVerifyCertificateEvent`) */
    EVENT_CONNECTED,          /** Raised when VPN client connected to endpoint gracefully (raised with null) */
    EVENT_DISCONNECTED,       /** Raised when VPN client disconnected from endpoint gracefully (raised with null) */
    EVENT_OUTPUT,          /** Raised when some data from server is ready to be sent to client application (raised with
                              `VpnClientOutputEvent`) */
    EVENT_CONNECT_REQUEST, /** Raised when new incoming connection is appeared (raised with
                              `VpnConnectRequestEvent`) */
    EVENT_ERROR,           /** Raised when something went wrong (raised with `VpnError`) */
    EVENT_DNS_UPSTREAM_UNAVAILABLE, /** Raised if a health check on the configured DNS upstream is failed (raised with
                                       null) */
    EVENT_CONNECTION_STATS,  /** Notifies of connection statistics updates (raised with `VpnTunnelConnectionStatsEvent`
                                and  only for connections routed through a VPN endpoint) */
    EVENT_CONNECTION_CLOSED, /** Raised when a connection is closed (raised with `VpnTunnelConnectionClosedEvent`) */
    EVENT_CONNECTION_INFO,   /** Notifies that connection info is ready (raised with `VpnConnectionInfoEvent`) */
};

struct Handler {
    void (*func)(void *arg, Event what, void *data);
    void *arg;
};

struct Parameters {
    VpnEventLoop *ev_loop = nullptr;
    VpnNetworkManager *network_manager = nullptr;
    Handler handler = {};
    CertVerifyHandler cert_verify_handler = {};
#if defined(__APPLE__) && TARGET_OS_IPHONE
    /// QoS class and relative priority for threads on iOS platform
    VpnQosSettings qos_settings;
#endif // __APPLE__ && TARGET_OS_IPHONE
};

struct EndpointConnectionConfig {
    VpnUpstreamProtocolConfig main_protocol;
    VpnUpstreamFallbackConfig fallback;
    AutoVpnEndpoint endpoint;
    std::chrono::milliseconds timeout{VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS};
    std::chrono::milliseconds health_check_timeout{VPN_DEFAULT_HEALTH_CHECK_TIMEOUT_MS};
    std::string username;
    std::string password;
    IpVersionSet ip_availability;
    bool anti_dpi = false;
};

static constexpr const char *LOG_NAME = "VPNCLIENT";

} // namespace vpn_client

class VpnClient {
public:
    VpnClient() = delete;
    VpnClient(const VpnClient &) = delete;
    VpnClient(VpnClient &&) = delete;
    VpnClient &operator=(const VpnClient &) = delete;
    VpnClient &operator=(VpnClient &&) = delete;

    explicit VpnClient(vpn_client::Parameters parameters);

    ~VpnClient();

    VpnError init(const VpnSettings *settings);

    VpnError connect(vpn_client::EndpointConnectionConfig config, std::optional<Millis> timeout = std::nullopt);

    VpnError listen(std::unique_ptr<ClientListener> listener, const VpnListenerConfig *config);

    void disconnect();

    void finalize_disconnect();

    void deinit();

    void process_client_packets(VpnPackets packets);

    std::optional<VpnConnectAction> finalize_connect_action(ConnectRequestResult request_result) const;

    void complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action);

    void reject_connect_request(uint64_t id);

    void update_exclusions(VpnMode mode, std::string_view exclusions);

    void reset_connections(int uid);

    void reset_connection(uint64_t id);

    void update_parameters(vpn_client::Parameters parameters);

    void do_health_check();

    bool do_dns_upstream_health_check();

    void handle_sleep();

    void handle_wake();

    VpnConnectionStats get_connection_stats() const;

    [[nodiscard]] std::unique_ptr<DataBuffer> make_buffer(uint64_t id) const;

    [[nodiscard]] bool may_send_icmp_request() const;

    [[nodiscard]] static int next_upstream_id();

    [[nodiscard]] static std::string_view dns_health_check_domain();

    [[nodiscard]] bool drop_non_app_initiated_dns_queries() const;

    void update_bypass_ip_availability();

    bool is_reachable(const ag::SocketAddress &address) const;

    void on_network_change();

    Fsm fsm;
    std::unique_ptr<Tunnel> tunnel = std::make_unique<Tunnel>(); // tunnel connections manager
    vpn_client::Parameters parameters = {};
    VpnListenerConfig listener_config = {};                    // common listener configuration
    vpn_client::EndpointConnectionConfig upstream_config = {}; // upstream configuration
    bool kill_switch_on = false;
    std::shared_ptr<ServerUpstream> endpoint_upstream;  // upstream for connections routed through vpn
    std::shared_ptr<ServerUpstream> bypass_upstream;    // upstream for bypassed connections
    std::shared_ptr<ClientListener> client_listener;    // client listener
    std::shared_ptr<ClientListener> dns_proxy_listener; // client listener
    IdGenerator listener_conn_id_generator{};           // connection id generator for client-side connections
    IdGenerator upstream_conn_id_generator{};           // connection id generator for server-side connections
    std::optional<VpnDnsResolveId> dns_health_check_id; // ID of the resolve for a DNS upstream health check
    DomainFilter domain_filter;                         // decides if connection should be bypassed over VPN
    std::set<event_loop::AutoTaskId> deferred_tasks;
    std::unique_ptr<EndpointConnector> endpoint_connector; // connects to endpoint using given upstream(s)
    std::optional<std::string> tmp_files_base_path;        // directory where some temporary files will be stored
    std::optional<std::string> ssl_session_storage_path;   // directory where SSL sessions will be cached
    size_t conn_memory_buffer_threshold =
            0; // connection in-memory buffer size exceeding which causes storing incoming data in a file
    size_t max_conn_buffer_file_size = 0; // maximum size of file of a connection data buffer
    ag::Logger log{vpn_client::LOG_NAME}; // logger
    int id = 0;
    std::optional<VpnError> pending_error;
    sockaddr_storage socks_listener_address{}; // The address the SOCKS listener is bound to
    bool bypass_upstream_session_opened = false;
    bool in_disconnect = false;
    VpnMode exclusions_mode = VPN_MODE_GENERAL;

    // One of these is handed off from the pinger. An upstream can then snatch it up.
    ag::DeclPtr<QuicConnector, &quic_connector_destroy> quic_connector;
    ag::DeclPtr<TcpSocket, &tcp_socket_destroy> tcp_socket;
};

} // namespace ag
