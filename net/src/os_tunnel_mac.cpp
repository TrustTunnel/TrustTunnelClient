#include "net/os_tunnel.h"

#include <net/if.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>

static const ag::Logger logger("OS_TUNNEL_MAC");

void ag::tunnel_utils::sys_cmd(std::string cmd) {
    cmd += " 2>&1";
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = exec_with_output(cmd.c_str());
    if (result.has_value()) {
        dbglog(logger, "{}", result.value());
    } else {
        dbglog(logger, "{}", result.error()->str());
    }
}

static bool sys_cmd(std::string cmd) {
    cmd += " 2>&1";
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = ag::tunnel_utils::exec_with_output(cmd.c_str());
    if (result.has_value()) {
        dbglog(logger, "{}", result.value());
        if (result.value().empty()) {
            return true;
        }
    } else {
        dbglog(logger, "{}", result.error()->str());
    }
    return false;
}

ag::VpnError ag::VpnMacTunnel::init(const ag::VpnOsTunnelSettings *settings) {
    init_settings(settings);
    if (tun_open() == -1) {
        return {-1, "Failed to init tunnel"};
    }
    setup_if();
    setup_dns();
    if (!setup_routes()) {
        return {-1, "Unable to setup routes for mactun session"};
    }

    return {};
}

void ag::VpnMacTunnel::deinit() {
    close(m_tun_fd);
    m_system_dns_setup_success = false;
}

std::string ag::VpnMacTunnel::get_name() {
    return m_tun_name;
}

evutil_socket_t ag::VpnMacTunnel::get_fd() {
    return m_tun_fd;
}

bool ag::VpnMacTunnel::get_system_dns_setup_success() const {
    return m_system_dns_setup_success;
}

evutil_socket_t ag::VpnMacTunnel::tun_open() {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0) {
        errlog(logger, "Failed to create socket: {}", strerror(errno));
        return -1;
    }

    struct ctl_info info{
        .ctl_name = UTUN_CONTROL_NAME
    };

    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        close(fd);
        errlog(logger, "IOCTL system call failed: {}", strerror(errno));
        return -1;
    }

    struct sockaddr_ctl addr {};
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0;

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(fd);
        errlog(logger, "Failed to connect: {}", strerror(errno));
        return -1;
    }

    socklen_t addr_len = sizeof(struct sockaddr_ctl);
    if (getpeername(fd, (sockaddr *) &addr, &addr_len) != 0) {
        close(fd);
        errlog(logger, "Failed to get tun number: {}", strerror(errno));
        return -1;
    }

    m_tun_fd = fd;
    m_tun_name = AG_FMT("utun{}", addr.sc_unit - 1);
    m_if_index = if_nametoindex(m_tun_name.c_str());

    infolog(logger, "Device {} opened", m_tun_name);
    return fd;
}

void ag::VpnMacTunnel::setup_if() {
    ag::tunnel_utils::fsystem("set -x\n");
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} mtu {} up", m_tun_name, m_settings->mtu);
    auto ipv4_address = tunnel_utils::get_address_for_index(m_settings->ipv4_address, m_if_index);
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} inet add {} 127.1.1.1 netmask {}\n", m_tun_name,
            ipv4_address.get_address_as_string(), fmt::join(ipv4_address.get_mask(), "."));
    auto ipv6_address = tunnel_utils::get_address_for_index(m_settings->ipv6_address, m_if_index);
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} inet6 add {} fe80::1 prefixlen {}\n", m_tun_name,
            ipv6_address.get_address_as_string(), ipv6_address.get_prefix_len());
}

bool ag::VpnMacTunnel::setup_routes() {
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    for (auto &route : ipv4_routes) {
        if (!sys_cmd(AG_FMT("route add {} -iface {}", route.to_string(), m_tun_name))) {
            auto splitted = route.split();
            if (!splitted
                    || !sys_cmd(AG_FMT("route add {} -iface {}", splitted->first.to_string(), m_tun_name))
                    || !sys_cmd(AG_FMT("route add {} -iface {}", splitted->second.to_string(), m_tun_name))) {
                return false;
            }
        }
    }
    for (auto &route : ipv6_routes) {
        if (!sys_cmd(AG_FMT("route add -inet6 {} -iface {}", route.to_string(), m_tun_name))) {
            auto splitted = route.split();
            if (!splitted
                    || !sys_cmd(AG_FMT("route add -inet6 {} -iface {}", splitted->first.to_string(), m_tun_name))
                    || !sys_cmd(AG_FMT("route add -inet6 {} -iface {}", splitted->second.to_string(), m_tun_name))) {
                return false;
            }
        }
    }
    return true;
}

[[clang::optnone]]
void ag::VpnMacTunnel::setup_dns() {
    m_system_dns_setup_success = false;
    std::vector<std::string_view> dns_servers{m_settings->dns_servers.data, m_settings->dns_servers.data + m_settings->dns_servers.size};
    m_dns_manager = VpnMacDnsSettingsManager::create(dns_servers);
    m_system_dns_setup_success = (m_dns_manager != nullptr);
}
