#include "net/os_tunnel.h"

#include <net/if.h>
#include <net/if_utun.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>

static const ag::Logger logger("OS_TUNNEL_MAC");

void ag::tunnel_utils::sys_cmd(const std::string &cmd) {
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = exec_with_output(cmd.c_str());
    if (result.has_value()) {
        dbglog(logger, "{}", result.value());
    } else {
        dbglog(logger, "{}", result.error()->str());
    }
}

ag::VpnError ag::VpnMacTunnel::init(const ag::VpnOsTunnelSettings *settings) {
    init_settings(settings);
    bool success_tun_open = false;
    for (uint8_t i = 0; i < 255; i++) {
        if (int fd = tun_open(i); fd != -1) {
            m_tun_fd = fd;
            m_tun_name = AG_FMT("utun{}", i);
            m_if_index = if_nametoindex(m_tun_name.c_str());
            success_tun_open = true;
            break;
        }
    }
    if (!success_tun_open) {
        return {-1, "Failed to init tunnel"};
    }
    setup_if();
    setup_routes();

    return {};
}

void ag::VpnMacTunnel::deinit() {
    close(m_tun_fd);
}

evutil_socket_t ag::VpnMacTunnel::get_fd() {
    return m_tun_fd;
}

evutil_socket_t ag::VpnMacTunnel::tun_open(uint32_t num) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    if (fd < 0) {
        errlog(logger, "Failed to create socket: {}", strerror(errno));
        return -1;
    }

    struct ctl_info info {};
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, std::max(std::size(info.ctl_name), strlen(UTUN_CONTROL_NAME)));

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
    addr.sc_unit = num + 1;

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        errlog(logger, "Failed to connect: {}", strerror(errno));
        return -1;
    }

    infolog(logger, "Device {} opened", info.ctl_name);
    return fd;
}

void ag::VpnMacTunnel::setup_if() {
    ag::tunnel_utils::fsystem("set -x\n");
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} mtu {} up", m_tun_name, m_settings->mtu);
    auto ipv4_address = tunnel_utils::get_address_for_index(m_settings->ipv4_address, m_if_index);
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} inet add {} {} prefixlen {}\n", m_tun_name,
            ipv4_address.get_address_as_string(), ipv4_address.get_address_as_string(), ipv4_address.get_prefix_len());
    auto ipv6_address = tunnel_utils::get_address_for_index(m_settings->ipv6_address, m_if_index);
    ag::tunnel_utils::fsystem("/sbin/ifconfig {} inet6 add {} prefixlen {}\n", m_tun_name,
            ipv6_address.get_address_as_string(), ipv6_address.get_prefix_len());
}

void ag::VpnMacTunnel::setup_routes() {
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    for (auto &route : ipv4_routes) {
        ag::tunnel_utils::fsystem("route add {} -iface {}", route.to_string(), m_tun_name);
    }
    for (auto &route : ipv6_routes) {
        ag::tunnel_utils::fsystem("route add -inet6 {} -iface {}", route.to_string(), m_tun_name);
    }
}
