#include <gtest/gtest.h>

#include "net/os_tunnel.h"

using namespace ag;
using namespace ag::tunnel_utils;

static VpnAddressArray make_dns_servers(const char **servers, uint32_t size) {
    return VpnAddressArray{.data = servers, .size = size};
}

TEST(OsTunnelLinuxDns, ResolvectlDnsCommand) {
    static const char *SERVERS[] = {"1.1.1.1", "8.8.8.8"};
    ASSERT_EQ("resolvectl dns 'tt0' '1.1.1.1' '8.8.8.8'", make_resolvectl_dns_cmd("tt0", make_dns_servers(SERVERS, 2)));
}

TEST(OsTunnelLinuxDns, ResolvconfRegisterCommand) {
    static const char *SERVERS[] = {"1.1.1.1", "8.8.8.8"};
    ASSERT_EQ("printf '%s\\n' '# Managed by TrustTunnel' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' "
              "| '/sbin/resolvconf' -a 'tt0'",
            make_resolvconf_register_cmd("/sbin/resolvconf", "tt0", make_dns_servers(SERVERS, 2)));
}

TEST(OsTunnelLinuxDns, ResolvConfWriteCommand) {
    static const char *SERVERS[] = {"94.140.14.14", "2a10:50c0::ad1:ff"};
    ASSERT_EQ("printf '%s\\n' '# Managed by TrustTunnel' 'nameserver 94.140.14.14' 'nameserver 2a10:50c0::ad1:ff' "
              "> '/etc/resolv.conf'",
            make_resolv_conf_write_cmd("/etc/resolv.conf", make_dns_servers(SERVERS, 2)));
}

TEST(OsTunnelLinuxDns, EscapesShellMetacharacters) {
    static const char *SERVERS[] = {"1.1.1.1'; rm -rf /"};
    ASSERT_EQ("resolvectl dns 'tt0' '1.1.1.1'\\''; rm -rf /'",
            make_resolvectl_dns_cmd("tt0", make_dns_servers(SERVERS, 1)));
    ASSERT_EQ("printf '%s\\n' '# Managed by TrustTunnel' 'nameserver 1.1.1.1'\\''; rm -rf /' > '/etc/resolv.conf'",
            make_resolv_conf_write_cmd("/etc/resolv.conf", make_dns_servers(SERVERS, 1)));
}
