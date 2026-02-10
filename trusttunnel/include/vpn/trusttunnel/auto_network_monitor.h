#pragma once

#include <memory>

#include <common/network_monitor.h>

#include "vpn/trusttunnel/client.h"

namespace ag {
/**
 * Automatic network monitoring.
 *
 * Monitors the active network interface and network availability, calls
 * `TrustTunnelClient::notify_network_change` and `vpn_network_manager_set_outbound_interface` respectively.
 * Respects the forced network interface returned by `TrustTunnelClient::get_bound_if`.
 */
class AutoNetworkMonitor {
public:
    explicit AutoNetworkMonitor(std::weak_ptr<TrustTunnelClient> client);
    ~AutoNetworkMonitor();

    bool start();
    void stop();

private:
    std::weak_ptr<TrustTunnelClient> m_client;
    std::unique_ptr<ag::utils::NetworkMonitor> m_network_monitor;
    UniquePtr<VpnEventLoop, &vpn_event_loop_destroy> m_network_monitor_loop = nullptr;
    std::thread m_network_monitor_loop_thread;
};
} // namespace ag
