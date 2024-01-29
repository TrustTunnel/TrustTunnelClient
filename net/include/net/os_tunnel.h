#pragma once

#include <memory>
#include <span>
#include <string>
#include <vector>

#include <event2/buffer.h>

#include <common/cidr_range.h>
#include <common/error.h>
#include <vpn/utils.h>

#ifdef _WIN32
#include <BaseTsd.h>
#endif

#ifdef __APPLE__
#include "net/mac_dns_settings_manager.h"
#endif

#ifdef __cplusplus
namespace ag {
extern "C" {
#endif

typedef AG_ARRAY_OF(const char *) VpnAddressArray;

struct VpnOsTunnelSettings {
    /** IPv4 address for interface */
    const char *ipv4_address;
    /** IPv6 address for the interface. Specify NULL if you don't need IPv6 */
    const char *ipv6_address;
    /** Included routes **/
    VpnAddressArray included_routes;
    /** Excluded routes **/
    VpnAddressArray excluded_routes;
    /** MTU of the interface */
    int mtu;
    /** DNS servers addresses */
    VpnAddressArray dns_servers;
};

#ifdef _WIN32
struct VpnWinTunnelSettings {
    /** Adapter name */
    const char *adapter_name;
    /** Library module to handle tunnel */
    HMODULE wintun_lib;
    /** Block all inbound/outbound IPv6 traffic */
    bool block_ipv6;
};
#endif

WIN_EXPORT VpnOsTunnelSettings *vpn_os_tunnel_settings_clone(const VpnOsTunnelSettings *settings);
WIN_EXPORT void vpn_os_tunnel_settings_destroy(VpnOsTunnelSettings *settings);

#ifdef _WIN32
WIN_EXPORT VpnWinTunnelSettings *vpn_win_tunnel_settings_clone(const VpnWinTunnelSettings *settings);
WIN_EXPORT void vpn_win_tunnel_settings_destroy(VpnWinTunnelSettings *settings);
#endif

/* Exported functions for Win32 CAPI */
/**
 * Default settings for all tunnels
 */
WIN_EXPORT const VpnOsTunnelSettings *vpn_os_tunnel_settings_defaults();

#ifdef _WIN32
/**
 * Additional default settings for Win tunnel. For common settings, see `vpn_os_tunnel_settings_defaults()`.
 */
WIN_EXPORT const VpnWinTunnelSettings *vpn_win_tunnel_settings_defaults();

/**
 * Create Wintun tunnel
 * @param settings Tunnel settings (common). See `vpn_os_tunnel_settings_defaults()` for recommended defaults.
 * @param win_settings Win tunnel settings. See `vpn_win_tunnel_settings_defaults()` for recommended defaults.
 * @return Newly created tunnel or NULL
 */
WIN_EXPORT void *vpn_win_tunnel_create(VpnOsTunnelSettings *settings, VpnWinTunnelSettings *win_settings);
/**
 * Destroy Wintun tunnel
 */
WIN_EXPORT void vpn_win_tunnel_destroy(void *win_tunnel);
/**
 * This function must be used in ping_handler and vpn_handler when tunnel is on.
 * Does nothing if `vpn_network_manager_set_outbound_interface()` was not previously called,
 * or it was called with 0.
 */
WIN_EXPORT bool vpn_win_socket_protect(evutil_socket_t fd, const sockaddr *addr);

#endif

#ifdef __cplusplus
} // extern "C"

class VpnOsTunnel {
public:
#ifdef _WIN32
    /** Initialize tunnel with windows adapter settings */
    virtual VpnError init(const VpnOsTunnelSettings *settings, const VpnWinTunnelSettings *win_settings) = 0;
#else
    /** Initialize tunnel */
    virtual VpnError init(const VpnOsTunnelSettings *settings) = 0;
#endif

    /** Stop and deinit tunnel */
    virtual void deinit() = 0;

    /** Get file descriptor */
    virtual evutil_socket_t get_fd() = 0;

#ifdef _WIN32

    /** Start receiving packets */
    virtual void start_recv_packets(
            void (*read_callback)(void *arg, const VpnPackets *packets), void *read_callback_arg) = 0;

    /** Stop receiving packets */
    virtual void stop_recv_packets() = 0;

    /** Send packet */
    virtual void send_packet(std::span<const evbuffer_iovec> chunks) = 0;

#endif // _WIN32

    VpnOsTunnel() = default;
    virtual ~VpnOsTunnel() = default;

    VpnOsTunnel(const VpnOsTunnel &) = delete;
    VpnOsTunnel &operator=(const VpnOsTunnel &) = delete;

    VpnOsTunnel(VpnOsTunnel &&) = delete;
    VpnOsTunnel &operator=(VpnOsTunnel &&) = delete;

protected:
    void init_settings(const VpnOsTunnelSettings *settings) {
        m_settings.reset(vpn_os_tunnel_settings_clone(settings));
    }
    DeclPtr<VpnOsTunnelSettings, &vpn_os_tunnel_settings_destroy> m_settings;
    // Interface index
    uint32_t m_if_index = 0;
};

#ifdef __linux__
class VpnLinuxTunnel : public VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init(const VpnOsTunnelSettings *settings) override;
    /** Get file descriptor */
    evutil_socket_t get_fd() override;
    /** Stop and deinit tunnel */
    void deinit() override;
    ~VpnLinuxTunnel() override = default;

private:
    evutil_socket_t tun_open();
    void setup_if();
    void setup_dns();
    void setup_routes();

    evutil_socket_t m_tun_fd{-1};
    std::string m_tun_name{};
};
#elif __APPLE__ && !TARGET_OS_IPHONE
class VpnMacTunnel : public VpnOsTunnel {
public:
    /** Initialize tunnel */
    VpnError init(const VpnOsTunnelSettings *settings) override;
    /** Get file descriptor */
    evutil_socket_t get_fd() override;
    /** Stop and deinit tunnel */
    void deinit() override;
    ~VpnMacTunnel() override = default;

protected:
    evutil_socket_t tun_open();
    void setup_if();
    void setup_dns();
    void setup_routes();

private:
    evutil_socket_t m_tun_fd{-1};
    std::string m_tun_name{};
#ifdef __APPLE__
    std::unique_ptr<VpnMacDnsSettingsManager> m_dns_manager;
#endif // __APPLE__
};
#endif

/** Return tunnel object for current OS */
std::unique_ptr<ag::VpnOsTunnel> make_vpn_tunnel();

namespace tunnel_utils {
enum ExecError {
    AE_POPEN,
    AE_PCLOSE,
    AE_CMD_FAILURE,
};

/** Execute command in shell and return output as string */
Result<std::string, ExecError> exec_with_output(const char *cmd);

/**
 * Needed because using `__func__` (which is used in `tracelog()`) inside variadic
 * template function causes a compiler error inside fmtlib's headers
 */
void sys_cmd(const std::string &cmd);
template <typename... Ts>
void fsystem(std::string_view fmt, Ts &&...args) {
    sys_cmd(fmt::vformat(fmt, fmt::make_format_args(args...)));
}
template <typename... Ts>
Result<std::string, ExecError> fsystem_with_output(std::string_view fmt, Ts &&...args) {
    return exec_with_output(fmt::vformat(fmt, fmt::make_format_args(args...)).c_str());
}
void get_setup_dns(std::string &dns_list_v4, std::string &dns_list_v6, ag::VpnAddressArray &dns_servers);
void get_setup_routes(std::vector<ag::CidrRange> &ipv4_routes, std::vector<ag::CidrRange> &ipv6_routes,
        ag::VpnAddressArray &included_routes, ag::VpnAddressArray &excluded_routes);
void split_default_route(std::vector<ag::CidrRange> &routes, ag::CidrRange route);
ag::CidrRange get_address_for_index(const char *ipv4_address, uint32_t index);
} // namespace tunnel_utils

template <>
struct ErrorCodeToString<tunnel_utils::ExecError> {
    std::string operator()(tunnel_utils::ExecError code) {
        // clang-format off
        switch (code) {
        case tunnel_utils::AE_POPEN: return "popen()";
        case tunnel_utils::AE_PCLOSE: return "pclose()";
        case tunnel_utils::AE_CMD_FAILURE: return "Command failure";
        }
        // clang-format on
    }
};

} // namespace ag

#endif
