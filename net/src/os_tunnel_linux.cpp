#include "common/utils.h"
#include "net/os_tunnel.h"
#include "vpn/utils.h"

#include <cstring>
#include <net/if.h> // should be included before linux/if.h

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

static const ag::Logger logger("OS_TUNNEL_LINUX");

static constexpr auto TABLE_ID = 880;
static constexpr std::string_view PRIVILEGED_PORTS = "1-1024";
static constexpr std::string_view VNC_PORTS = "5900-5920";

static bool sys_cmd_bool(std::string cmd) {
    cmd += " 2>&1";
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = ag::exec_with_output(cmd);
    if (result.has_value()) {
        auto &output = result.value().output;
        if (!output.empty()) {
            dbglog(logger, "{}", ag::utils::rtrim(result.value().output));
        }
        if (result.value().status != 0) {
            dbglog(logger, "Exit code: {}", result.value().status);
        }
        return output.empty();
    }
    dbglog(logger, "{}", result.error()->str());
    return false;
}

static bool sys_cmd_netns(const std::string &netns, std::string cmd) {
    if (!netns.empty()) {
        cmd = AG_FMT("ip netns exec {} {}", ag::utils::escape_argument_for_shell(netns), cmd);
    }
    return sys_cmd_bool(cmd);
}

static void sys_cmd_netns_ignore_errors(const std::string &netns, std::string cmd) {
    if (!netns.empty()) {
        cmd = AG_FMT("ip netns exec {} {}", ag::utils::escape_argument_for_shell(netns), cmd);
    }
    cmd += " 2>&1";
    dbglog(logger, "{} {}", (geteuid() == 0) ? '#' : '$', cmd);
    auto result = ag::exec_with_output(cmd);
    if (result.has_value()) {
        auto &output = result.value().output;
        if (!output.empty()) {
            dbglog(logger, "{}", ag::utils::rtrim(result.value().output));
        }
        if (result.value().status != 0) {
            dbglog(logger, "Exit code: {} (ignored)", result.value().status);
        }
    } else {
        dbglog(logger, "{} (ignored)", result.error()->str());
    }
}

static ag::Result<std::string, ag::tunnel_utils::ExecError> sys_cmd_with_output_netns(
        const std::string &netns, std::string cmd) {
    if (!netns.empty()) {
        cmd = AG_FMT("ip netns exec {} {}", ag::utils::escape_argument_for_shell(netns), cmd);
    }
    return ag::tunnel_utils::sys_cmd_with_output(cmd);
}

ag::VpnError ag::VpnLinuxTunnel::init(const ag::VpnOsTunnelSettings *settings, std::optional<std::string> netns) {
    init_settings(settings);
    m_netns = netns.value_or("");
    bool managed_routing = m_settings->included_routes.size > 0;
    infolog(logger, "TUN mode: {}{}{}", m_settings->use_existing ? "attach" : "create",
            (m_settings->device_name && m_settings->device_name[0] != '\0')
                    ? AG_FMT(" name={}", m_settings->device_name)
                    : "",
            managed_routing ? "" : " (routes unmanaged)");
    if (tun_open() == -1) {
        return {-1, "Failed to init tunnel"};
    }
    setup_if();

    if (managed_routing) {
        m_sport_supported = check_sport_rule_support();
        if (m_settings->use_existing && !m_sport_supported) {
            errlog(logger,
                    "Managed routing for an existing TUN device requires sport rule support; "
                    "set included_routes = [] to leave routing external");
            return {-1, "Managed routing for an existing TUN device requires sport rule support"};
        }
        teardown_routes(TABLE_ID); // Remove stale rules from previous sessions
        if (!setup_routes(TABLE_ID)) {
            return {-1, "Unable to setup routes for linuxtun session"};
        }
    } else {
        infolog(logger, "Empty included_routes: skipping route and ip rule management");
    }
    setup_dns();

    return {};
}

void ag::VpnLinuxTunnel::deinit() {
    close(m_tun_fd);
    if (m_settings->included_routes.size > 0) {
        teardown_routes(TABLE_ID);
    }
    m_system_dns_setup_success = false;
}

evutil_socket_t ag::VpnLinuxTunnel::get_fd() {
    return m_tun_fd;
}

std::string ag::VpnLinuxTunnel::get_name() {
    return m_tun_name;
}

bool ag::VpnLinuxTunnel::get_system_dns_setup_success() const {
    return m_system_dns_setup_success;
}

evutil_socket_t ag::VpnLinuxTunnel::tun_open() {
    const char *requested_name = m_settings->device_name;
    const bool has_name = (requested_name != nullptr && requested_name[0] != '\0');
    const bool use_existing = m_settings->use_existing;

    if (use_existing && !has_name) {
        errlog(logger, "use_existing requires device_name");
        return -1;
    }

    if (use_existing && if_nametoindex(requested_name) == 0) {
        errlog(logger, "Device {} does not exist (use_existing = true)", requested_name);
        return -1;
    }

    if (!use_existing && has_name && if_nametoindex(requested_name) != 0) {
        errlog(logger, "Device {} already exists; refusing to create", requested_name);
        return -1;
    }

    evutil_socket_t fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
        errlog(logger, "Failed to open /dev/net/tun: {}", strerror(errno));
        return -1;
    }

    struct ifreq ifr = {};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (has_name) {
        // Copy bounded by IFNAMSIZ - 1; kernel enforces max 15 chars.
        std::strncpy(ifr.ifr_name, requested_name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        evutil_closesocket(fd);
        errlog(logger, "ioctl TUNSETIFF failed: {}", strerror(errno));
        return -1;
    }
    m_tun_fd = fd;
    m_tun_name = ifr.ifr_name;
    m_if_index = if_nametoindex(ifr.ifr_name);

    infolog(logger, "Device {} {} (use_existing = {})", ifr.ifr_name, use_existing ? "attached" : "opened",
            use_existing);
    return fd;
}

void ag::VpnLinuxTunnel::setup_if() {
    // Move interface to network namespace if specified
    if (!m_netns.empty()) {
        if (!sys_cmd_bool(
                    AG_FMT("ip link set {} netns {}", m_tun_name, ag::utils::escape_argument_for_shell(m_netns)))) {
            errlog(logger, "Failed to move tunnel interface to network namespace {}", m_netns);
            return;
        }
        infolog(logger, "Moved tunnel interface {} to network namespace {}", m_tun_name, m_netns);
    }

    if (!m_settings->use_existing) {
        // Set the interface address (in netns if specified)
        if (!sys_cmd_netns(m_netns,
                    AG_FMT("ip addr add {} dev {}",
                            tunnel_utils::get_address_for_index(m_settings->ipv4_address, m_if_index).to_string(),
                            m_tun_name))) {
            errlog(logger, "Failed to set IPv4 address");
            return;
        }

        auto result = sys_cmd_with_output_netns(m_netns,
                AG_FMT("ip -6 addr add {} dev {}",
                        tunnel_utils::get_address_for_index(m_settings->ipv6_address, m_if_index).to_string(),
                        m_tun_name));
        if (result.has_error()) {
            warnlog(logger, "Failed to set IPv6 address: {}", result.error()->str());
        } else {
            m_ipv6_available = true;
        }
    } else {
        // In attach mode the operator owns the interface addresses; just
        // detect IPv6 availability from the existing device state.
        auto result = sys_cmd_with_output_netns(m_netns, AG_FMT("ip -6 addr show dev {}", m_tun_name));
        m_ipv6_available = result.has_value() && !result.value().empty();
    }

    // Bring the interface up (in netns if specified)
    if (!sys_cmd_netns(m_netns, AG_FMT("ip link set dev {} mtu {} up", m_tun_name, m_settings->mtu))) {
        errlog(logger, "Failed to bring up tunnel interface");
        return;
    }
}

bool ag::VpnLinuxTunnel::check_sport_rule_support() {
    // Check IPv4 sport rule support
    auto result = ag::tunnel_utils::fsystem_with_output("ip rule show sport 65535");
    if (!result.has_value()) {
        dbglog(logger, "IPv4 sport rule not supported: {}", result.error()->str());
        return false;
    }

    // If IPv6 is available, also check IPv6 sport rule support
    if (m_ipv6_available) {
        auto result_v6 = ag::tunnel_utils::fsystem_with_output("ip -6 rule show sport 65535");
        if (!result_v6.has_value()) {
            dbglog(logger, "IPv6 sport rule not supported: {}", result_v6.error()->str());
            return false;
        }
    }

    return true;
}

bool ag::VpnLinuxTunnel::setup_routes(int16_t table_id) {
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    std::string table_name = m_sport_supported ? std::to_string(table_id) : "main";

    if (!m_ipv6_available) {
        ipv6_routes.clear();
    }

    for (auto &route : ipv4_routes) {
        if (!sys_cmd_netns(
                    m_netns, AG_FMT("ip ro add {} dev {} table {}", route.to_string(), m_tun_name, table_name))) {
            auto splitted = route.split();
            if (!splitted
                    || !sys_cmd_netns(m_netns,
                            AG_FMT("ip ro add {} dev {} table {}", splitted->first.to_string(), m_tun_name, table_name))
                    || !sys_cmd_netns(m_netns,
                            AG_FMT("ip ro add {} dev {} table {}", splitted->second.to_string(), m_tun_name,
                                    table_name))) {
                return false;
            }
        }
    }
    for (auto &route : ipv6_routes) {
        if (!sys_cmd_netns(
                    m_netns, AG_FMT("ip -6 ro add {} dev {} table {}", route.to_string(), m_tun_name, table_name))) {
            auto splitted = route.split();
            if (!splitted
                    || !sys_cmd_netns(m_netns,
                            AG_FMT("ip -6 ro add {} dev {} table {}", splitted->first.to_string(), m_tun_name,
                                    table_name))
                    || !sys_cmd_netns(m_netns,
                            AG_FMT("ip -6 ro add {} dev {} table {}", splitted->second.to_string(), m_tun_name,
                                    table_name))) {
                return false;
            }
        }
    }

    // Apply routing rules (in netns if specified)
    if (m_sport_supported) {
        if (!ipv4_routes.empty()) {
            if (!sys_cmd_netns(m_netns, AG_FMT("ip rule add prio 30800 sport {} lookup main", PRIVILEGED_PORTS))
                    || !sys_cmd_netns(m_netns, AG_FMT("ip rule add prio 30800 sport {} lookup main", VNC_PORTS))
                    || !sys_cmd_netns(m_netns, AG_FMT("ip rule add prio 30801 lookup {}", table_id))) {
                return false;
            }
        }
        if (!ipv6_routes.empty()) {
            if (!sys_cmd_netns(m_netns, AG_FMT("ip -6 rule add prio 30800 sport {} lookup main", PRIVILEGED_PORTS))
                    || !sys_cmd_netns(m_netns, AG_FMT("ip -6 rule add prio 30800 sport {} lookup main", VNC_PORTS))
                    || !sys_cmd_netns(m_netns, AG_FMT("ip -6 rule add prio 30801 lookup {}", table_id))) {
                return false;
            }
        }
    }
    return true;
}

void ag::VpnLinuxTunnel::setup_dns() {
    m_system_dns_setup_success = false;
    if (m_settings->dns_servers.size == 0) {
        m_system_dns_setup_success = true;
        return;
    }

    std::vector<std::string_view> dns_servers{
            m_settings->dns_servers.data, m_settings->dns_servers.data + m_settings->dns_servers.size};

    std::vector<std::string> escaped_servers;
    for (const auto &dns_server : dns_servers) {
        escaped_servers.push_back(ag::utils::escape_argument_for_shell(dns_server));
    }

    m_system_dns_setup_success = false;
    constexpr int TRIES = 5;
    for (int i = 0; i < TRIES; i++) {
        auto result = sys_cmd_with_output_netns(
                m_netns, AG_FMT("resolvectl dns {} {}", m_tun_name, fmt::join(escaped_servers, " ")));
        if (result.has_error()) {
            warnlog(logger, "System DNS servers are not set");
            return;
        }
        result = sys_cmd_with_output_netns(m_netns, AG_FMT("resolvectl dns {}", m_tun_name));
        if (result.has_error()) {
            warnlog(logger, "Can't get the list of system DNS servers set");
            return;
        }
        auto output = result.value();
        bool found = std::find_if(dns_servers.begin(), dns_servers.end(), [&output](auto &&server) {
            return output.find(server) != output.npos;
        }) != dns_servers.end();
        if (found) {
            result = sys_cmd_with_output_netns(m_netns, AG_FMT("resolvectl domain {} '~.'", m_tun_name));
            if (result.has_error()) {
                warnlog(logger, "Can't enable DNS leak protection settings on the interface");
                return;
            }
            m_system_dns_setup_success = result.has_value();
            infolog(logger, "System DNS servers are successfully set");
            return;
        }
        if (i == TRIES - 1) {
            warnlog(logger, "System DNS servers are not set after {} tries", TRIES);
            return;
        }
        warnlog(logger, "System DNS servers are set but not applied, retrying");
        std::this_thread::sleep_for(Secs{1});
    }
}

void ag::VpnLinuxTunnel::teardown_routes(int16_t table_id) {
    // Flush all routes from the project-owned table (stale routes may remain
    // when the TUN device is externally created and survives client shutdown).
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip route flush table {}", table_id));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip -6 route flush table {}", table_id));

    // Try to remove rules regardless of m_sport_supported (may exist from previous session)
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip rule del prio 30801 lookup {}", table_id));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip rule del prio 30800 sport {} lookup main", PRIVILEGED_PORTS));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip rule del prio 30800 sport {} lookup main", VNC_PORTS));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip -6 rule del prio 30801 lookup {}", table_id));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip -6 rule del prio 30800 sport {} lookup main", PRIVILEGED_PORTS));
    sys_cmd_netns_ignore_errors(m_netns, AG_FMT("ip -6 rule del prio 30800 sport {} lookup main", VNC_PORTS));
}
