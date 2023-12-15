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
    enum ConnectResultError {};

    explicit VpnStandaloneClient(VpnStandaloneConfig &&config);

    VpnStandaloneClient(const VpnStandaloneClient &c) = delete;
    VpnStandaloneClient(VpnStandaloneClient &&c) = delete;
    VpnStandaloneClient &operator=(const VpnStandaloneClient &c) = delete;
    VpnStandaloneClient &operator=(VpnStandaloneClient &&c) = delete;

    Error<ConnectResultError> connect(std::chrono::milliseconds timeout);

    int disconnect();

    void notify_network_change(VpnNetworkState state);

    ~VpnStandaloneClient();

private:
    Error<ConnectResultError> connect_impl();
    Error<ConnectResultError> vpn_runner();
    Error<ConnectResultError> dns_runner();
    Error<ConnectResultError> connect_to_server();

    void vpn_protect_socket(SocketProtectEvent *event);
    int set_outbound_interface();

    VpnListener *make_tun_listener();
    VpnListener *make_socks_listener();

    static void static_vpn_handler(void *arg, VpnEvent what, void *data);
    void vpn_handler(void *, VpnEvent what, void *data);

    std::mutex m_guard;
    std::condition_variable m_connect_waiter;
    const ag::Logger m_logger{"STANDALONE_CLIENT"};
    std::atomic<Vpn *> m_vpn = nullptr;
    VpnStandaloneConfig m_config;
    std::thread m_loop_thread;
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_extra_loop = nullptr;
    std::unique_ptr<ag::VpnOsTunnel> m_tunnel = nullptr;
    std::optional<FileHandler> m_logfile_handler;
    std::optional<Logger::LogToFile> m_logtofile;
    std::chrono::milliseconds m_connect_timeout;
#ifdef __APPLE__
    std::unique_ptr<VpnMacDnsSettingsManager> m_dns_manager;
#endif // __APPLE__
#ifdef _WIN32
    HMODULE m_wintun;
#endif
};

template <>
struct ErrorCodeToString<VpnStandaloneClient::ConnectResultError> {
    std::string operator()(VpnStandaloneClient::ConnectResultError) {
        return {};
    }
};

} // namespace ag
