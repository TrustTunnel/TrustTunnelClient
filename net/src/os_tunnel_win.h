#pragma once

#include <list>

#include <wintun.h>

#include "net/os_tunnel.h"
#include "vpn/utils.h"

#include "wfp_firewall.h"

namespace ag {

class VpnWinTunnel : public ag::VpnOsTunnel {
public:
    VpnError init(const VpnOsTunnelSettings *settings, const VpnWinTunnelSettings *win_settings) override;
    void start_recv_packets(void (*read_callback)(void *arg), void *read_callback_arg) override;
    void stop_recv_packets() override;
    void send_packet(std::span<const evbuffer_iovec> chunks) override;
    std::optional<VpnPacket> recv_packet() override;
    void deinit() override;
    /** Return EVUTIL_INVALID_SOCKET */
    evutil_socket_t get_fd() override;
    std::string get_name() override;
    bool get_system_dns_setup_success() const override;

    VpnWinTunnel() = default;
    ~VpnWinTunnel() override;

    VpnWinTunnel(const VpnWinTunnel &) = delete;
    VpnWinTunnel &operator=(const VpnWinTunnel &) = delete;

    VpnWinTunnel(VpnWinTunnel &&) = delete;
    VpnWinTunnel &operator=(VpnWinTunnel &&) = delete;

private:
    void init_win_settings(const VpnWinTunnelSettings *win_settings) {
        m_win_settings.reset(vpn_win_tunnel_settings_clone(win_settings));
    }
    bool setup_mtu();
    bool setup_dns();
    bool setup_routes();
    DeclPtr<VpnWinTunnelSettings, &vpn_win_tunnel_settings_destroy> m_win_settings;

    WINTUN_ADAPTER_HANDLE m_wintun_adapter{nullptr};
    WINTUN_SESSION_HANDLE m_wintun_session{nullptr};
    HANDLE m_wintun_quit_event{nullptr};
    std::unique_ptr<std::thread> m_recv_thread_handle{};

    WfpFirewall m_firewall;
};

} // namespace ag
