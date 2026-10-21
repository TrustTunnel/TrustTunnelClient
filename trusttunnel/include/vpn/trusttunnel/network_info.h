#pragma once

#include "net/os_tunnel.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ag {

/**
 * Network parameters of an initialized TUN device, reported to the
 * `network_ready_handler` callback as soon as the tunnel is ready.
 */
struct VpnNetworkInfo {
    /// Actual TUN interface name (kernel-assigned names are resolved)
    std::string iface_name;
    /// IPv4 address of the interface without the prefix length, empty if none
    std::string ipv4_address;
    /// IPv4 prefix length: 32 for a bare address, 0 if there is no address
    uint32_t ipv4_prefix = 0;
    /// IPv6 address of the interface without the prefix length, empty if none
    std::string ipv6_address;
    /// IPv6 prefix length: 128 for a bare address, 0 if there is no address
    uint32_t ipv6_prefix = 0;
    /// MTU of the interface
    uint32_t mtu = 0;
    /// DNS servers used by the tunnel
    std::vector<std::string> dns_servers;
};

/**
 * Assemble the network info of an initialized tunnel.
 * A bare IP address yields its natural prefix length (32 for IPv4, 128 for
 * IPv6), an explicit `a.b.c.d/nn` yields `nn`, and a missing address yields an
 * empty string with a zero prefix. An unparsable address is kept as is with a
 * zero prefix.
 */
VpnNetworkInfo build_network_info(std::string_view iface_name, std::string_view ipv4_address,
        std::string_view ipv6_address, uint32_t mtu, const VpnAddressArray &dns_servers);

} // namespace ag
