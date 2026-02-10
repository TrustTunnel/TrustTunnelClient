#pragma once

#include <atomic>
#include <memory>
#include <thread>

#include "common/autofd.h"
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
    std::function<void(VpnClientOutputEvent *)> client_output_handler;
    std::function<void(VpnConnectionInfoEvent *)> connection_info_handler;
};

class TrustTunnelClient {
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

    TrustTunnelClient(TrustTunnelConfig &&config, VpnCallbacks &&callbacks);

    TrustTunnelClient(const TrustTunnelClient &c) = delete;
    TrustTunnelClient(TrustTunnelClient &&c) = delete;
    TrustTunnelClient &operator=(const TrustTunnelClient &c) = delete;
    TrustTunnelClient &operator=(TrustTunnelClient &&c) = delete;

    struct AutoSetup {};
    struct UseTunnelFd {
        AutoFd fd;
    };
    struct UseProcessPackets {};

    using ListenerSettings = std::variant<AutoSetup, UseTunnelFd, UseProcessPackets>;

    /**
     * Establish VPN connection
     * @param timeout Timeout for endpoint connection establishment
     * @param listener_settings If set to `AutoSetup`, automatically create a tunnel or socks based on config.
     *                          If set to `UseTunnelFd`, use provided fd for packet processing.
     *                          If set to `UseProcessPackets`, use `processClientPackets` and `VPN_EVENT_CLIENT_OUTPUT`
     *                              to process packets.
     */
    Error<ConnectResultError> connect(ListenerSettings listener_settings);
    Error<ConnectResultError> set_system_dns();

    int disconnect();

    void notify_network_change(VpnNetworkState state);

    void notify_sleep();
    void notify_wake();

    bool process_client_packets(VpnPackets packets);

    std::string_view get_bound_if() const;

    ~TrustTunnelClient();

private:
    Error<ConnectResultError> connect_impl(ListenerSettings listener_settings);
    Error<ConnectResultError> vpn_runner(ListenerSettings listener_settings);
    Error<ConnectResultError> connect_to_server();

    VpnListener *make_tun_listener(ListenerSettings listener_settings);
    VpnListener *make_socks_listener(ListenerSettings listener_settings);

    static void static_vpn_handler(void *arg, VpnEvent what, void *data);
    void vpn_handler(void *, VpnEvent what, void *data);

    VpnSessionState m_connect_result = VPN_SS_DISCONNECTED;
    const ag::Logger m_logger{"TRUSTTUNNEL_CLIENT"};
    std::atomic<Vpn *> m_vpn = nullptr;
    TrustTunnelConfig m_config;
    std::thread m_loop_thread;
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_extra_loop = nullptr;
    std::unique_ptr<ag::VpnOsTunnel> m_tunnel = nullptr;
    std::optional<FileHandler> m_logfile_handler;
    std::optional<Logger::LogToFile> m_logtofile;
    VpnCallbacks m_callbacks;
#ifdef _WIN32
    HMODULE m_wintun;
#endif
};

template <>
struct ErrorCodeToString<TrustTunnelClient::ConnectResultError> {
    std::string operator()(TrustTunnelClient::ConnectResultError) {
        return {};
    }
};

} // namespace ag
