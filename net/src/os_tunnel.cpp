#include <vector>

#include "net/os_tunnel.h"
#include "net/utils.h"
#include "common/utils.h"

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif

#ifdef _WIN32
#include "os_tunnel_win.h"
#endif

static ag::Logger g_logger("OS_TUNNEL");

static constexpr std::string_view DEFAULT_IPV4_ROUTE = "0.0.0.0/0";
static constexpr std::string_view DEFAULT_IPV6_ROUTE = "::/0";
static constexpr std::string_view DEFAULT_IPV6_ROUTE_UNICAST = "2000::/3";

void ag::tunnel_utils::split_default_route(std::vector<ag::CidrRange> &routes, ag::CidrRange route) {
    for (size_t idx = 0; idx < routes.size(); ++idx) {
        if (routes[idx] == route) {
            routes.erase(routes.begin() + idx);

            auto split = route.split();
            routes.push_back(split.value().first);
            routes.push_back(split.value().second);
        }
    }
}

void ag::tunnel_utils::get_setup_dns(
        std::string &dns_list_v4, std::string &dns_list_v6, ag::VpnAddressArray &dns_servers) {
    auto *dns_iter = dns_servers.data;
    auto *dns_end = dns_servers.data + dns_servers.size;
    std::vector<std::string> dns_v4;
    std::vector<std::string> dns_v6;
    for (; dns_iter != dns_end; dns_iter++) {
        if (ag::utils::is_valid_ip4(*dns_iter)) {
            dns_v4.emplace_back(*dns_iter);
        } else if (ag::utils::is_valid_ip6(*dns_iter)) {
            dns_v6.emplace_back(*dns_iter);
        }
    }

    dns_list_v4 = ag::utils::join(dns_v4.begin(), dns_v4.end(), ",");
    dns_list_v6 = ag::utils::join(dns_v6.begin(), dns_v6.end(), ",");
}

void ag::tunnel_utils::get_setup_routes(std::vector<ag::CidrRange> &ipv4_routes,
        std::vector<ag::CidrRange> &ipv6_routes, ag::VpnAddressArray &included_routes, ag::VpnAddressArray &excluded_routes) {
    for (size_t i = 0; i < included_routes.size; i++) {
        std::string_view route(included_routes.data[i]);
        if (route.find(':') == std::string::npos) {
            ipv4_routes.emplace_back(route);
        } else {
            if (route == DEFAULT_IPV6_ROUTE) {
                ipv6_routes.emplace_back(DEFAULT_IPV6_ROUTE_UNICAST);
            } else {
                ipv6_routes.emplace_back(route);
            }
        }
    }
    for (size_t i = 0; i < excluded_routes.size; i++) {
        std::string_view excluded_route(excluded_routes.data[i]);
        if (excluded_route.find(':') == std::string::npos) {
            ipv4_routes = ag::CidrRange::exclude(ipv4_routes, ag::CidrRange(excluded_route));
        } else {
            ipv6_routes = ag::CidrRange::exclude(ipv6_routes, ag::CidrRange(excluded_route));
        }
    }

    split_default_route(ipv4_routes, ag::CidrRange(DEFAULT_IPV4_ROUTE));
    split_default_route(ipv6_routes, ag::CidrRange(DEFAULT_IPV6_ROUTE_UNICAST));
}

#ifndef _WIN32
static std::string prompt() {
    return (geteuid() == 0) ? "#" : "$";
}
#else
static std::string prompt() {
    // Must check user name
    char username[256];
    DWORD username_len = sizeof(username);
    if (GetUserNameA(username, &username_len)) {
        return AG_FMT("{}@> ", username);
    } else {
        return "> ";
    }
}
#endif

#ifndef _WIN32
void ag::tunnel_utils::sys_cmd(std::string cmd) {
    dbglog(g_logger, "{} {}", prompt(), cmd);
    auto result = ag::exec_with_output(cmd);
    if (result.has_value()) {
        auto &output = result.value().output;
        if (!output.empty()) {
            dbglog(g_logger, "{}", ag::utils::rtrim(result.value().output));
        }
        if (result.value().status != 0) {
            dbglog(g_logger, "Exit code: {}", result.value().status);
        }
        return;
    }
    dbglog(g_logger, "{}", result.error()->str());
}

ag::Result<std::string, ag::tunnel_utils::ExecError> ag::tunnel_utils::sys_cmd_with_output(std::string cmd) {
    dbglog(g_logger, "{} {}", prompt(), cmd);
    auto result = ag::exec_with_output(cmd);
    if (result.has_value()) {
        auto &output = result.value().output;
        if (!output.empty()) {
            dbglog(g_logger, "{}", ag::utils::rtrim(result.value().output));
        }
        if (result.value().status != 0) {
            dbglog(g_logger, "Exit code: {}", result.value().status);
            return make_error(ag::tunnel_utils::ExecError::AE_CMD_FAILURE, AG_FMT("Command failed: Non-zero exit code: {}", result.value().status));
        }
        return output;
    }
    dbglog(g_logger, "{}", result.error()->str());
    switch (result.error()->value()) {
        case ag::EE_POPEN:
            return make_error(ag::tunnel_utils::ExecError::AE_POPEN, AG_FMT("popen() failed: {}", result.error()->str()));
        case ag::EE_PCLOSE:
            return make_error(ag::tunnel_utils::ExecError::AE_PCLOSE, AG_FMT("pclose() failed: {}", result.error()->str()));
    }
}
#endif // defined _WIN32

// This function is called to convert the interface address string from the settings.
// There used to be some sort of auto-correction of an invalid argument, using the interface index, now we
// simply check for nullptr and convert to CidrRange. An invalid setting will lead to an error down the line.
ag::CidrRange ag::tunnel_utils::get_address_for_index(const char *address, uint32_t /*index*/) {
    CidrRange range{safe_to_string_view(address)};
    if (!range.valid()) {
        return range;
    }
    const Uint8Vector &addr = range.get_address();
    return {as_u8v(addr), addr.size() * 8};
}

ag::VpnOsTunnelSettings *ag::vpn_os_tunnel_settings_clone(const ag::VpnOsTunnelSettings *settings) {
    ag::VpnOsTunnelSettings *dst = new VpnOsTunnelSettings{};
    dst->ipv4_address = safe_strdup(settings->ipv4_address);
    dst->ipv6_address = safe_strdup(settings->ipv6_address);
    dst->included_routes.size = settings->included_routes.size;
    dst->included_routes.data = new const char *[settings->included_routes.size] {};
    for (size_t i = 0; i != dst->included_routes.size; i++) {
        dst->included_routes.data[i] = safe_strdup(settings->included_routes.data[i]);
    }
    dst->excluded_routes.size = settings->excluded_routes.size;
    dst->excluded_routes.data = new const char *[settings->excluded_routes.size] {};
    for (size_t i = 0; i != dst->excluded_routes.size; i++) {
        dst->excluded_routes.data[i] = safe_strdup(settings->excluded_routes.data[i]);
    }
    dst->mtu = settings->mtu;
    dst->dns_servers.size = settings->dns_servers.size;
    dst->dns_servers.data = new const char *[settings->dns_servers.size] {};
    for (size_t i = 0; i != dst->dns_servers.size; i++) {
        dst->dns_servers.data[i] = safe_strdup(settings->dns_servers.data[i]);
    }
    return dst;
}

void ag::vpn_os_tunnel_settings_destroy(ag::VpnOsTunnelSettings *settings) {
    if (settings == nullptr) {
        return;
    }
    free((void *) settings->ipv4_address);
    free((void *) settings->ipv6_address);
    for (size_t i = 0; i != settings->included_routes.size; i++) {
        free((void *) settings->included_routes.data[i]);
    }
    delete[] settings->included_routes.data;
    for (size_t i = 0; i != settings->excluded_routes.size; i++) {
        free((void *) settings->excluded_routes.data[i]);
    }
    delete[] settings->excluded_routes.data;
    for (size_t i = 0; i != settings->dns_servers.size; i++) {
        free((void *) settings->dns_servers.data[i]);
    }
    delete[] settings->dns_servers.data;
    delete settings;
}

const ag::VpnOsTunnelSettings *ag::vpn_os_tunnel_settings_defaults() {
    static const char *included_routes[] = {"0.0.0.0/0", "2000::/3"};
    static const char *excluded_routes[] = {"10.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3"};
    static const char *dns_servers[] = {AG_UNFILTERED_DNS_IPS_V4[0].data(), AG_UNFILTERED_DNS_IPS_V4[1].data()};
    static const VpnOsTunnelSettings settings{
            .ipv4_address = "172.16.219.2",
            .ipv6_address = "fd01::2",
            .included_routes = {.data = included_routes, .size = std::size(included_routes)},
            .excluded_routes = {.data = excluded_routes, .size = std::size(excluded_routes)},
            .mtu = 9000,
            .dns_servers = {.data = dns_servers, .size = std::size(dns_servers)},
    };
    return &settings;
}

#ifdef _WIN32

const ag::VpnWinTunnelSettings *ag::vpn_win_tunnel_settings_defaults() {
    static const ag::VpnWinTunnelSettings win_settings = {
            .adapter_name = "Adguard VpnLibs test tunnel",
            .tunnel_type = "wintun",
            .wintun_lib = nullptr,
            .block_ipv6 = false,
            .block_inbound = false,
            .zerocopy = false,
    };
    return &win_settings;
}

ag::VpnWinTunnelSettings *ag::vpn_win_tunnel_settings_clone(const ag::VpnWinTunnelSettings *settings) {
    auto *dst = new VpnWinTunnelSettings{};
    *dst = *settings;
    dst->adapter_name = safe_strdup(settings->adapter_name);
    dst->tunnel_type = safe_strdup(settings->tunnel_type);
    return dst;
}

void ag::vpn_win_tunnel_settings_destroy(ag::VpnWinTunnelSettings *settings) {
    if (settings == nullptr) {
        return;
    }
    free((char *) settings->adapter_name);
    free((char *) settings->tunnel_type);
    delete settings;
}

#endif // _WIN32

std::unique_ptr<ag::VpnOsTunnel> ag::make_vpn_tunnel() {
#ifdef _WIN32
    std::unique_ptr<ag::VpnWinTunnel> tunnel{new ag::VpnWinTunnel{}};
    return tunnel;
#elif __APPLE__ && !TARGET_OS_IPHONE
    std::unique_ptr<ag::VpnMacTunnel> tunnel{new ag::VpnMacTunnel{}};
    return tunnel;
#elif __linux__ && !ANDROID
    std::unique_ptr<ag::VpnLinuxTunnel> tunnel{new ag::VpnLinuxTunnel{}};
    return tunnel;
#else
    return nullptr;
#endif
}
