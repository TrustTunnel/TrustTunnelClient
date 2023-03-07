#pragma once

#include <wintun.h>

#include "net/os_tunnel.h"

#include "wfp_firewall.h"

namespace ag {

class VpnWinTunnel : public ag::VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init(const VpnOsTunnelSettings *settings, const VpnWinTunnelSettings *win_settings) override;
    /** Start receiving packets */
    void start_recv_packets(void (*read_callback)(void *arg, const VpnPackets *packets), void *read_callback_arg) override;
    /** Stop receiving packets */
    void stop_recv_packets() override;
    /** Send packet */
    void send_packet(std::span<const evbuffer_iovec> chunks) override;
    /** Stop and deinit tunnel */
    void deinit() override;
    /** Return EVUTIL_INVALID_SOCKET */
    evutil_socket_t get_fd();

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
