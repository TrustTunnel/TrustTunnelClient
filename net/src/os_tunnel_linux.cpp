#include "net/os_tunnel.h"

#include <net/if.h> // should be included before linux/if.h

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

static const ag::Logger logger("OS_TUNNEL_LINUX");

static constexpr auto TABLE_ID = 880;

void ag::tunnel_utils::sys_cmd(const std::string &cmd) {
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = exec_with_output(cmd.c_str());
    if (result.has_value()) {
        dbglog(logger, "{}", result.value());
    } else {
        dbglog(logger, "{}", result.error()->str());
    }
}

ag::VpnError ag::VpnLinuxTunnel::init(const ag::VpnOsTunnelSettings *settings) {
    init_settings(settings);
    if (tun_open() == -1) {
        return {-1, "Failed to init tunnel"};
    }
    setup_if();
    setup_dns();
    setup_routes(TABLE_ID);

    return {};
}

void ag::VpnLinuxTunnel::deinit() {
    close(m_tun_fd);
    teardown_routes(TABLE_ID);
}

evutil_socket_t ag::VpnLinuxTunnel::get_fd() {
    return m_tun_fd;
}

std::string ag::VpnLinuxTunnel::get_name() {
    return m_tun_name;
}

evutil_socket_t ag::VpnLinuxTunnel::tun_open() {
    evutil_socket_t fd = open("/dev/net/tun", O_RDWR);

    if (fd == -1) {
        errlog(logger, "Failed to open /dev/net/tun: {}", strerror(errno));
        return -1;
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        evutil_closesocket(fd);
        errlog(logger, "ioctl TUNSETIFF failed: {}", strerror(errno));
        return -1;
    }
    m_tun_fd = fd;
    m_tun_name = ifr.ifr_name;
    m_if_index = if_nametoindex(ifr.ifr_name);

    infolog(logger, "Device {} opened", ifr.ifr_name);
    return fd;
}

void ag::VpnLinuxTunnel::setup_if() {
    ag::tunnel_utils::fsystem("ip addr add {} dev {}",
            tunnel_utils::get_address_for_index(m_settings->ipv4_address, m_if_index).to_string(), m_tun_name);
    ag::tunnel_utils::fsystem("ip -6 addr add {} dev {}",
            tunnel_utils::get_address_for_index(m_settings->ipv6_address, m_if_index).to_string(), m_tun_name);
    ag::tunnel_utils::fsystem("ip link set dev {} mtu {} up", m_tun_name, m_settings->mtu);
}

bool ag::VpnLinuxTunnel::check_sport_rule_support() {
    auto result = ag::tunnel_utils::fsystem_with_output("ip rule show sport 65535");
    if (!result.has_value()) {
        dbglog(logger, "sport rule not supported: {}", result.error()->str());
        return false;
    }
    return true;
}

void ag::VpnLinuxTunnel::setup_routes(int16_t table_id) {
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    m_sport_supported = check_sport_rule_support();
    std::string table_name = m_sport_supported ? std::to_string(table_id) : "main";

    for (auto &route : ipv4_routes) {
        ag::tunnel_utils::fsystem("ip ro add {} dev {} table {}", route.to_string(), m_tun_name, table_name);
    }
    for (auto &route : ipv6_routes) {
        ag::tunnel_utils::fsystem("ip -6 ro add {} dev {} table {}", route.to_string(), m_tun_name, table_name);
    }

    if (m_sport_supported) {
        if (!ipv4_routes.empty()) {
            ag::tunnel_utils::fsystem("ip rule add prio 30800 sport 1-1024 lookup main");
            ag::tunnel_utils::fsystem("ip rule add prio 30801 lookup {}", table_id);
        }
        if (!ipv6_routes.empty()) {
            ag::tunnel_utils::fsystem("ip -6 rule add prio 30800 sport 1-1024 lookup main");
            ag::tunnel_utils::fsystem("ip -6 rule add prio 30801 lookup {}", table_id);
        }
    }
}

void ag::VpnLinuxTunnel::setup_dns() {
    if (m_settings->dns_servers.size == 0) {
        return;
    }
    std::vector<std::string_view> dns_servers{
            m_settings->dns_servers.data, m_settings->dns_servers.data + m_settings->dns_servers.size};
    ag::tunnel_utils::fsystem("resolvectl dns {} {}", m_tun_name, fmt::join(dns_servers, " "));
    ag::tunnel_utils::fsystem("resolvectl domain {} '~.'", m_tun_name);
}

void ag::VpnLinuxTunnel::teardown_routes(int16_t table_id) {
    if (m_sport_supported) {
        // It is safe to leave these rules but it is better to remove them.
        ag::tunnel_utils::fsystem("ip rule del prio 30801 lookup {}", table_id);
        ag::tunnel_utils::fsystem("ip rule del prio 30800 sport 1-1024 lookup main");
        ag::tunnel_utils::fsystem("ip -6 rule del prio 30801 lookup {}", table_id);
        ag::tunnel_utils::fsystem("ip -6 rule del prio 30800 sport 1-1024 lookup main");
    }
}
