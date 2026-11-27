#pragma once

#include <functional>
#include <memory>
#include <string>

#include "net/os_tunnel.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"

namespace ag::trusttunnel_linux {

/**
 * Owns a TrustTunnel client session and bridges it to the adapter callbacks.
 *
 * The lifecycle mirrors the CLI client: the configured post-quantum setting is applied, then the
 * network monitor is started, the system DNS servers are registered, and finally the client
 * connects. `stop()` performs the reverse teardown in the order that proved stable on Linux: the
 * network monitor stops first, then the client disconnects and releases its resources.
 */
class VpnController {
public:
    struct Callbacks {
        /// Called each time the VPN session state changes
        std::function<void(int state)> on_state_changed;
        /// Called with a JSON connection telemetry record
        std::function<void(const std::string &json)> on_connection_info;
    };

    explicit VpnController(Callbacks callbacks);
    ~VpnController();

    VpnController(const VpnController &) = delete;
    VpnController &operator=(const VpnController &) = delete;

    /**
     * Establish a connection.
     * Resolves the endpoints and initiates the connection; the result of the attempt is reported
     * asynchronously through the state-changed callback. On failure the controller is left stopped.
     * @param config The client configuration; consumed by the call
     * @param fall_into_recovery Failure handling during initial connection establishment,
     *                           see `TrustTunnelClient::ConnectOptions`
     * @return true if the connection was initiated, false otherwise
     */
    bool start(TrustTunnelConfig &&config, bool fall_into_recovery);

    /**
     * Tear the session down: stop the network monitor, disconnect the client and release it.
     */
    void stop();

private:
    /// Bind an outgoing endpoint socket to the current outbound interface to avoid a route loop
    void protect_socket(SocketProtectEvent *event);
    /// Verify the endpoint certificate against the system trust store
    void verify_certificate(VpnVerifyCertificateEvent *event);
    /// Assemble the callbacks handed over to the client; `protect_sockets` is true for a managed TUN
    /// listener, where sockets must be bound to the outbound interface
    VpnCallbacks make_client_callbacks(bool protect_sockets);

    Callbacks m_callbacks;
    std::unique_ptr<TrustTunnelClient> m_client;
    std::unique_ptr<AutoNetworkMonitor> m_monitor;
};

} // namespace ag::trusttunnel_linux
