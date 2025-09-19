// TODO (ayakushin): move this to native_libs_common
#pragma once

#include <functional>
#include <string>

#include "common/logger.h"
#include "vpn/event_loop.h"

#ifdef __APPLE__
#include <Network/Network.h>
#include <Network/path.h>
#include <Network/path_monitor.h>
#include <dispatch/dispatch.h>
#endif // __APPLE__

#ifdef __linux__
#include <thread>
#endif // __linux__

namespace ag {

class NetworkMonitor {
public:
    explicit NetworkMonitor(std::function<void(const std::string &if_name, bool is_connected)> cmd_handler);

    NetworkMonitor(const NetworkMonitor &c) = delete;
    NetworkMonitor(NetworkMonitor &&c) = delete;
    NetworkMonitor &operator=(const NetworkMonitor &c) = delete;
    NetworkMonitor &operator=(NetworkMonitor &&c) = delete;

    virtual void start(VpnEventLoop *loop) = 0;
    virtual void stop() = 0;

    virtual std::string get_default_interface() = 0;
    [[nodiscard]] virtual bool is_running() const = 0;

    virtual ~NetworkMonitor() = default;

protected:
    std::function<void(const std::string &if_name, bool is_connected)> m_cmd_handler = nullptr;
};

/**
 * @class NetworkMonitorImpl
 * Monitors network changes.
 */
class NetworkMonitorImpl : public NetworkMonitor {
public:
    /**
     * Constructs a NetworkMonitorImpl object with the specified command handler.
     * @param cmd_handler A function to handle network status changes
     */
    explicit NetworkMonitorImpl(std::function<void(const std::string &if_name, bool is_connected)> cmd_handler);

    NetworkMonitorImpl(const NetworkMonitorImpl &c) = delete;
    NetworkMonitorImpl(NetworkMonitorImpl &&c) = delete;
    NetworkMonitorImpl &operator=(const NetworkMonitorImpl &c) = delete;
    NetworkMonitorImpl &operator=(NetworkMonitorImpl &&c) = delete;

    /**
     * Starts monitoring the network status in the specified event loop.
     * @param loop A pointer to the event loop
     */
    void start(VpnEventLoop *loop) override;
    /**
     * Stops monitoring the network status.
     */
    void stop() override;

    /**
     * Gets the default network interface name.
     * @return A string representing the default network interface name
     */
    std::string get_default_interface() override;
    /**
     * Checks if the network monitor is currently running.
     * @return A boolean indicating if the network monitor is running
     */
    [[nodiscard]] bool is_running() const override;

    ~NetworkMonitorImpl() override;

protected:
    const ag::Logger m_logger{"NETWORK_MONITORING"};

    std::string m_if_name;
#ifdef __APPLE__
    nw_path_monitor_t m_nw_path_monitor = nullptr;
    dispatch_queue_t m_dispatch_queue = nullptr;
    nw_path_t m_current_path = nullptr;
    bool m_first_update_done= false;
#endif // __APPLE__

#ifdef __linux__
    std::thread *m_monitor_thread = nullptr;
    event *m_monitor_event = nullptr;
    evutil_socket_t m_monitor_sock_fd = -1;

    bool create_socket();
    void close_socket();
#endif // __linux__

    void changed_handler();
    void handle_network_change(const std::string &new_if_name, bool is_satisfied);
};

}  // namespace ag