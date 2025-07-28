#pragma once

#include <atomic>
#include <memory>
#include <thread>

#include "common/logger.h"
#include "config.h"
#include "net/os_tunnel.h"
#include "net/utils.h"
#include "vpn/vpn.h"

#ifdef __APPLE__
#include "net/mac_dns_settings_manager.h"
#endif // __APPLE__

#ifdef _WIN32
static constexpr std::string_view WINTUN_DLL_NAME = "wintun";
#endif

namespace ag {

struct VpnCallbacks {
    std::function<void(SocketProtectEvent *)> protect_handler;
    std::function<void(VpnVerifyCertificateEvent *)> verify_handler;
    std::function<void(VpnStateChangedEvent *)> state_changed_handler;
};

class VpnStandaloneClient {
private:
    class FileHandler {
    public:
        explicit FileHandler(std::string_view filename)
                : m_filename(filename)
                , m_file(std::fopen(filename.data(), "w")) {
        }
        ~FileHandler() {
            std::fclose(m_file);
        }
        FILE *get_file() {
            return m_file;
        }

    private:
        std::string m_filename;
        FILE *m_file;
    };

public:
    // Helper class that cleans up the listener resources on destruction
    // (e.g. closes tun fd). `release()` method should be called to create the
    // `VpnListener` and pass it to VpnListen where the resources will be handled internally
    class ListenerHelper {
    public:
        explicit ListenerHelper(std::variant<VpnTunListenerConfig, VpnSocksListenerConfig> listener_config)
            : m_listener_config(listener_config) {}

        VpnListener *release() {
            auto listener_config = std::exchange(m_listener_config, std::nullopt);
            if (!listener_config.has_value()) {
                return nullptr;
            }
            if (auto *config = std::get_if<VpnTunListenerConfig>(&listener_config.value())) {
                return vpn_create_tun_listener(nullptr, config);
            }
            if (auto *config = std::get_if<VpnSocksListenerConfig>(&listener_config.value())) {
                return vpn_create_socks_listener(nullptr, config);
            }
            return nullptr;
        }

        ListenerHelper(const ListenerHelper &) = delete;
        ListenerHelper &operator=(const ListenerHelper &) = delete;
        ListenerHelper(ListenerHelper &&other) {
            other = std::move(*this);
        }
        ListenerHelper &operator=(ListenerHelper &&other) {
            other.m_listener_config = std::exchange(this->m_listener_config, std::nullopt);
            return *this;
        }

        ~ListenerHelper() {
            if (!m_listener_config.has_value()) {
                return;
            }

            // Cleanup
            if (auto *config = std::get_if<VpnTunListenerConfig>(&m_listener_config.value())) {
                close(config->fd);
            }
        }

    private:
        std::optional<std::variant<VpnTunListenerConfig, VpnSocksListenerConfig>> m_listener_config;
    };

    enum ConnectResultError {};

    VpnStandaloneClient(VpnStandaloneConfig &&config, VpnCallbacks &&callbacks);

    VpnStandaloneClient(const VpnStandaloneClient &c) = delete;
    VpnStandaloneClient(VpnStandaloneClient &&c) = delete;
    VpnStandaloneClient &operator=(const VpnStandaloneClient &c) = delete;
    VpnStandaloneClient &operator=(VpnStandaloneClient &&c) = delete;

    Error<ConnectResultError> connect(std::chrono::milliseconds timeout, ListenerHelper &&listener);
    Error<ConnectResultError> set_system_dns();

    int disconnect();

    void notify_network_change(VpnNetworkState state);

    void notify_sleep();
    void notify_wake();

    ~VpnStandaloneClient();

private:
    Error<ConnectResultError> connect_impl(ListenerHelper &&listener);
    Error<ConnectResultError> vpn_runner(ListenerHelper &&listener);
    Error<ConnectResultError> connect_to_server();

    void vpn_protect_socket(SocketProtectEvent *event);
    int set_outbound_interface();

    static void static_vpn_handler(void *arg, VpnEvent what, void *data);
    void vpn_handler(void *, VpnEvent what, void *data);

    std::mutex m_guard;
    std::condition_variable m_connect_waiter;
    VpnSessionState m_connect_result = VPN_SS_DISCONNECTED;
    const ag::Logger m_logger{"STANDALONE_CLIENT"};
    std::atomic<Vpn *> m_vpn = nullptr;
    VpnStandaloneConfig m_config;
    std::thread m_loop_thread;
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_extra_loop = nullptr;
    std::optional<FileHandler> m_logfile_handler;
    std::optional<Logger::LogToFile> m_logtofile;
    std::chrono::milliseconds m_connect_timeout {};
    VpnCallbacks m_callbacks;
};

template <>
struct ErrorCodeToString<VpnStandaloneClient::ConnectResultError> {
    std::string operator()(VpnStandaloneClient::ConnectResultError) {
        return {};
    }
};

} // namespace ag
