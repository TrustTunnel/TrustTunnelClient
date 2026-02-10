#ifdef __APPLE__
#include <net/if.h>
#include <netinet/in.h>
#endif // __APPLE__

#ifdef __linux__
// clang-format off
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
// clang-format on
#endif // __linux__

#ifdef _WIN32
#include <WinSock2.h>
#endif // _WIN32

#include "net/network_manager.h"
#include "vpn/trusttunnel/auto_network_monitor.h"

namespace ag {

AutoNetworkMonitor::AutoNetworkMonitor(std::weak_ptr<TrustTunnelClient> client)
        : m_client(std::move(client)) {
}

AutoNetworkMonitor::~AutoNetworkMonitor() {
    stop();
}

static bool update_interface(std::string_view if_name) {
    uint32_t if_index = if_nametoindex(if_name.data());
    if (if_index != 0) {
        vpn_network_manager_set_outbound_interface(if_index);
        return true;
    }
    return false;
}

bool AutoNetworkMonitor::start() {
    m_network_monitor_loop.reset(vpn_event_loop_create());
    m_network_monitor_loop_thread = std::thread([this]() {
        vpn_event_loop_run(m_network_monitor_loop.get());
    });

    auto client = m_client.lock();
    std::string_view bound_if = client->get_bound_if();
    bool is_bound_if_override = !bound_if.empty();

    m_network_monitor = ag::utils::create_network_monitor(
            [this, is_bound_if_override](const std::string &if_name, bool is_connected) {
                if (!is_bound_if_override) {
                    update_interface(if_name);
                }
                if (auto client = m_client.lock()) {
                    client->notify_network_change(is_connected ? ag::VPN_NS_CONNECTED : ag::VPN_NS_NOT_CONNECTED);
                }
            });

    if (is_bound_if_override && !update_interface(bound_if)) {
        return false;
    }

    event_loop::dispatch_sync(m_network_monitor_loop.get(), [this, is_bound_if_override]() {
        m_network_monitor->start(vpn_event_loop_get_base(m_network_monitor_loop.get()));
        if (!is_bound_if_override) {
            auto if_name = m_network_monitor->get_default_interface();
            update_interface(if_name);
        }
    });

    return true;
}

void AutoNetworkMonitor::stop() {
    if (m_network_monitor_loop) {
        event_loop::dispatch_sync(m_network_monitor_loop.get(), [this]() {
            m_network_monitor->stop();
        });
        vpn_event_loop_stop(m_network_monitor_loop.get());
        if (m_network_monitor_loop_thread.joinable()) {
            m_network_monitor_loop_thread.join();
        }
    }
}

} // namespace ag
