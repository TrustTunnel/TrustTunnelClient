#include <common/cidr_range.h>

#include "vpn/trusttunnel/network_info.h"

namespace ag {

VpnNetworkInfo build_network_info(std::string_view iface_name, std::string_view ipv4_address,
        std::string_view ipv6_address, uint32_t mtu, const VpnAddressArray &dns_servers) {
    auto split_address = [](std::string_view address, std::string &out_address, uint32_t &out_prefix) {
        if (address.empty()) {
            out_address.clear();
            out_prefix = 0;
            return;
        }
        CidrRange range{address};
        if (range.valid()) {
            // Report the address as configured: CidrRange would normalize it
            // to the network address, which is not what the platform should
            // assign to the interface.
            size_t slash = address.find('/');
            out_address = std::string{address.substr(0, slash)};
            out_prefix = uint32_t(range.get_prefix_len());
        } else {
            out_address = std::string{address};
            out_prefix = 0;
        }
    };

    VpnNetworkInfo info;
    info.iface_name = std::string{iface_name};
    split_address(ipv4_address, info.ipv4_address, info.ipv4_prefix);
    split_address(ipv6_address, info.ipv6_address, info.ipv6_prefix);
    info.mtu = mtu;
    info.dns_servers.reserve(dns_servers.size);
    for (uint32_t i = 0; dns_servers.data != nullptr && i < dns_servers.size; ++i) {
        if (dns_servers.data[i] != nullptr) {
            info.dns_servers.emplace_back(dns_servers.data[i]);
        }
    }
    return info;
}

} // namespace ag
