#pragma once

#include "trusttunnel/trusttunnel.h"

#include <string>
#include <vector>

#include "vpn/trusttunnel/network_info.h"

namespace ag::trusttunnel_linux {

/**
 * Convert the C++ network info into the C API structure.
 * `dns_storage` and `dns_ptrs` must outlive the use of the returned structure:
 * the `dns_servers` pointers reference `dns_storage`. The array is
 * NULL-terminated as documented in trusttunnel.h, while `dns_servers_count`
 * holds the number of actual servers.
 */
inline trusttunnel_network_info_t make_c_network_info(
        const VpnNetworkInfo &info, std::vector<std::string> &dns_storage, std::vector<const char *> &dns_ptrs) {
    dns_storage.assign(info.dns_servers.begin(), info.dns_servers.end());
    dns_ptrs.reserve(dns_storage.size() + 1);
    for (const std::string &server : dns_storage) {
        dns_ptrs.push_back(server.c_str());
    }
    dns_ptrs.push_back(nullptr);

    trusttunnel_network_info_t network_info{};
    network_info.iface_name = info.iface_name.c_str();
    network_info.ipv4_address = info.ipv4_address.c_str();
    network_info.ipv4_prefix = info.ipv4_prefix;
    network_info.ipv6_address = info.ipv6_address.c_str();
    network_info.ipv6_prefix = info.ipv6_prefix;
    network_info.mtu = info.mtu;
    network_info.dns_servers = dns_ptrs.data();
    network_info.dns_servers_count = dns_storage.size();
    return network_info;
}

} // namespace ag::trusttunnel_linux
