#include "common/utils.h"
#include "net/os_tunnel.h"
#include "vpn/utils.h"

#include <cstring>
#include <net/if.h> // should be included before linux/if.h

#include <linux/if.h>
#include <linux/if_tun.h>
#include <magic_enum/magic_enum.hpp>
#include <sys/ioctl.h>
#include <unistd.h>

static const ag::Logger logger("OS_TUNNEL_LINUX");

static constexpr auto TABLE_ID = 880;
static constexpr std::string_view PRIVILEGED_PORTS = "1-1024";
static constexpr std::string_view VNC_PORTS = "5900-5920";
static constexpr std::string_view RESOLV_CONF_PATH = "/etc/resolv.conf";
static constexpr std::string_view RESOLV_CONF_BACKUP_PATH = "/etc/resolv.conf.trusttunnel.bak";

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

static std::string escaped_server_args(const ag::VpnAddressArray &servers) {
    std::vector<std::string> escaped;
    escaped.reserve(servers.size);
    for (size_t i = 0; i < servers.size; ++i) {
        escaped.push_back(ag::utils::escape_argument_for_shell(servers.data[i]));
    }
    return AG_FMT("{}", fmt::join(escaped, " "));
}

static std::vector<std::string> dns_config_lines(const ag::VpnAddressArray &servers) {
    std::vector<std::string> lines{"# Managed by TrustTunnel"};
    lines.reserve(1 + servers.size);
    for (size_t i = 0; i < servers.size; ++i) {
        lines.push_back(AG_FMT("nameserver {}", servers.data[i]));
    }
    return lines;
}

static std::string escaped_dns_config_args(const ag::VpnAddressArray &servers) {
    std::vector<std::string> escaped;
    std::vector<std::string> lines = dns_config_lines(servers);
    escaped.reserve(lines.size());
    for (const auto &line : lines) {
        escaped.push_back(ag::utils::escape_argument_for_shell(line));
    }
    return AG_FMT("{}", fmt::join(escaped, " "));
}

std::string ag::tunnel_utils::make_resolvectl_dns_cmd(std::string_view iface, const VpnAddressArray &servers) {
    return AG_FMT("resolvectl dns {} {}", ag::utils::escape_argument_for_shell(iface), escaped_server_args(servers));
}

std::string ag::tunnel_utils::make_resolvconf_register_cmd(
        std::string_view exe, std::string_view iface, const VpnAddressArray &servers) {
    return AG_FMT("printf '%s\\n' {} | {} -a {}", escaped_dns_config_args(servers),
            ag::utils::escape_argument_for_shell(exe), ag::utils::escape_argument_for_shell(iface));
}

std::string ag::tunnel_utils::make_resolv_conf_write_cmd(std::string_view path, const VpnAddressArray &servers) {
    return AG_FMT(
            "printf '%s\\n' {} > {}", escaped_dns_config_args(servers), ag::utils::escape_argument_for_shell(path));
}

static bool resolvectl_available(const std::string &netns) {
    // Redirect the output: only the exit code matters here, and `resolvectl
    // status` is verbose.
    if (sys_cmd_with_output_netns(netns, "command -v resolvectl > /dev/null 2>&1").has_error()) {
        return false;
    }
    // resolvectl may be installed while systemd-resolved is not running.
    if (sys_cmd_with_output_netns(netns, "resolvectl status > /dev/null 2>&1").has_error()) {
        dbglog(logger, "systemd-resolved is not running");
        return false;
    }
    return true;
}

static std::optional<std::string> find_resolvconf(const std::string &netns) {
    auto probe = sys_cmd_with_output_netns(netns, "command -v resolvconf");
    if (probe.has_value()) {
        std::string path{ag::utils::rtrim(probe.value())};
        if (!path.empty()) {
            return path;
        }
    }
    // Distributions may keep resolvconf in /sbin or /usr/sbin, which are often
    // absent from the PATH of a system service.
    for (std::string_view candidate : {"/sbin/resolvconf", "/usr/sbin/resolvconf"}) {
        if (::access(std::string(candidate).c_str(), X_OK) == 0) {
            return std::string{candidate};
        }
    }
    return std::nullopt;
}

static bool setup_dns_systemd_resolved(
        const std::string &netns, std::string_view iface, const ag::VpnAddressArray &servers) {
    if (!resolvectl_available(netns)) {
        dbglog(logger, "Skipping systemd-resolved backend");
        return false;
    }

    std::vector<std::string_view> dns_servers{servers.data, servers.data + servers.size};

    constexpr int TRIES = 5;
    for (int i = 0; i < TRIES; i++) {
        auto result = sys_cmd_with_output_netns(netns, ag::tunnel_utils::make_resolvectl_dns_cmd(iface, servers));
        if (result.has_error()) {
            warnlog(logger, "Failed to set system DNS servers via systemd-resolved: {}", result.error()->str());
            return false;
        }
        result = sys_cmd_with_output_netns(
                netns, AG_FMT("resolvectl dns {}", ag::utils::escape_argument_for_shell(iface)));
        if (result.has_error()) {
            warnlog(logger, "Can't get the list of system DNS servers set");
            return false;
        }
        const std::string &output = result.value();
        bool found = std::find_if(dns_servers.begin(), dns_servers.end(), [&output](auto &&server) {
            return output.find(server) != output.npos;
        }) != dns_servers.end();
        if (found) {
            result = sys_cmd_with_output_netns(
                    netns, AG_FMT("resolvectl domain {} '~.'", ag::utils::escape_argument_for_shell(iface)));
            if (result.has_error()) {
                warnlog(logger, "Can't enable DNS leak protection settings on the interface");
                return false;
            }
            return true;
        }
        if (i == TRIES - 1) {
            warnlog(logger, "System DNS servers are not set after {} tries", TRIES);
            return false;
        }
        warnlog(logger, "System DNS servers are set but not applied, retrying");
        std::this_thread::sleep_for(ag::Secs{1});
    }
    return false;
}

static bool setup_dns_resolvconf(const std::string &netns, std::string_view iface, const ag::VpnAddressArray &servers) {
    auto exe = find_resolvconf(netns);
    if (!exe.has_value()) {
        dbglog(logger, "Skipping resolvconf backend: binary not found");
        return false;
    }
    auto result =
            sys_cmd_with_output_netns(netns, ag::tunnel_utils::make_resolvconf_register_cmd(*exe, iface, servers));
    if (result.has_error()) {
        warnlog(logger, "Failed to set system DNS servers via resolvconf: {}", result.error()->str());
        return false;
    }
    return true;
}

static bool setup_dns_resolv_conf_file(const std::string &netns, const ag::VpnAddressArray &servers) {
    // Perform all file operations through the shell so that they respect the
    // per-netns /etc/resolv.conf bind mounts (see ip-netns(8)).
    if (sys_cmd_with_output_netns(netns, AG_FMT("test -e {}", RESOLV_CONF_BACKUP_PATH)).has_value()) {
        warnlog(logger, "Found a leftover {} from a previous run, restoring it first", RESOLV_CONF_BACKUP_PATH);
        sys_cmd_netns_ignore_errors(netns, AG_FMT("mv -f {} {}", RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_PATH));
    }
    bool had_resolv_conf = sys_cmd_with_output_netns(netns, AG_FMT("test -e {}", RESOLV_CONF_PATH)).has_value();
    if (had_resolv_conf
            && sys_cmd_with_output_netns(netns, AG_FMT("mv -f {} {}", RESOLV_CONF_PATH, RESOLV_CONF_BACKUP_PATH))
                    .has_error()) {
        warnlog(logger, "Failed to back up {}", RESOLV_CONF_PATH);
        return false;
    }
    auto result =
            sys_cmd_with_output_netns(netns, ag::tunnel_utils::make_resolv_conf_write_cmd(RESOLV_CONF_PATH, servers));
    if (result.has_error()) {
        warnlog(logger, "Failed to write {}: {}", RESOLV_CONF_PATH, result.error()->str());
        sys_cmd_netns_ignore_errors(netns, AG_FMT("mv -f {} {}", RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_PATH));
        return false;
    }
    return true;
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
    mark_tunnel_active();

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
    teardown_dns();
    if (m_settings->included_routes.size > 0) {
        teardown_routes(TABLE_ID);
    }
    m_system_dns_setup_success = false;
    clear_tunnel_active();
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
    m_dns_backend = DnsBackend::NONE;
    const ag::VpnAddressArray &servers = m_settings->dns_servers;
    if (servers.size == 0) {
        m_system_dns_setup_success = true;
        return;
    }

    if (setup_dns_systemd_resolved(m_netns, m_tun_name, servers)) {
        m_dns_backend = DnsBackend::SYSTEMD_RESOLVED;
    } else if (setup_dns_resolvconf(m_netns, m_tun_name, servers)) {
        m_dns_backend = DnsBackend::RESOLVCONF;
    } else if (setup_dns_resolv_conf_file(m_netns, servers)) {
        m_dns_backend = DnsBackend::RESOLV_CONF_FILE;
    } else {
        warnlog(logger, "System DNS servers are not set: no working system DNS mechanism found");
        return;
    }

    m_system_dns_setup_success = true;
    infolog(logger, "System DNS servers are successfully set (backend: {})", magic_enum::enum_name(m_dns_backend));
}

void ag::VpnLinuxTunnel::teardown_dns() {
    switch (m_dns_backend) {
    case DnsBackend::NONE:
        return;
    case DnsBackend::SYSTEMD_RESOLVED:
        // Per-link settings usually vanish together with the interface, but an
        // explicit revert also covers devices that outlive the client
        // (use_existing mode).
        sys_cmd_netns_ignore_errors(
                m_netns, AG_FMT("resolvectl revert {}", ag::utils::escape_argument_for_shell(m_tun_name)));
        break;
    case DnsBackend::RESOLVCONF: {
        auto exe = find_resolvconf(m_netns);
        if (exe.has_value()) {
            sys_cmd_netns_ignore_errors(m_netns,
                    AG_FMT("{} -d {}", ag::utils::escape_argument_for_shell(*exe),
                            ag::utils::escape_argument_for_shell(m_tun_name)));
        }
        break;
    }
    case DnsBackend::RESOLV_CONF_FILE:
        // Restore the original file (or symlink) saved before the overwrite.
        sys_cmd_netns_ignore_errors(m_netns, AG_FMT("mv -f {} {}", RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_PATH));
        break;
    }
    m_dns_backend = DnsBackend::NONE;
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

void *ag::vpn_linux_tunnel_create(ag::VpnOsTunnelSettings *settings) {
    if (settings == nullptr) {
        return nullptr;
    }

    auto *tunnel = new ag::VpnLinuxTunnel{};
    auto res = tunnel->init(settings, std::nullopt);
    if (res.code != 0) {
        dbglog(logger, "Error initializing tunnel: {}", res.text ? res.text : "(null)");
        tunnel->deinit();
        delete tunnel;
        return nullptr;
    }

    return tunnel;
}

void ag::vpn_linux_tunnel_destroy(void *linux_tunnel) {
    auto *tunnel = (ag::VpnLinuxTunnel *) linux_tunnel;
    if (tunnel == nullptr) {
        return;
    }

    tunnel->deinit();
    delete tunnel;
}

int ag::vpn_linux_tunnel_get_fd(void *linux_tunnel) {
    if (linux_tunnel == nullptr) {
        return -1;
    }
    auto *tunnel = (ag::VpnLinuxTunnel *) linux_tunnel;
    return tunnel->get_fd();
}
