#pragma once

#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <common/network_monitor.h>

#include "vpn/vpn.h"

namespace ag {
/**
 * Automatic network monitoring.
 *
 * Monitors the active network interface and network availability, calls
 * `vpn_network_manager_set_outbound_interface` and `on_network_change` respectively.
 * `on_network_change` is called from the monitor thread.
 * Respects the forced network interface if `bound_if` is not empty.
 */
class AutoNetworkMonitor {
public:
    AutoNetworkMonitor(std::function<void(VpnNetworkState)> on_network_change, std::string bound_if);
    ~AutoNetworkMonitor();

    bool start();
    void stop();

private:
    std::function<void(VpnNetworkState)> m_on_network_change;
    std::string m_bound_if;
    std::unique_ptr<ag::utils::NetworkMonitor> m_network_monitor;
    UniquePtr<VpnEventLoop, &vpn_event_loop_destroy> m_network_monitor_loop = nullptr;
    std::thread m_network_monitor_loop_thread;
};
} // namespace ag
