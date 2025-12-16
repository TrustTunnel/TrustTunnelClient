#pragma once

#include <memory>
#include <span>
#include <string_view>

#include "common/cidr_range.h"
#include "common/error.h"
#include "vpn/utils.h"

namespace ag {

enum WfpFirewallErrorCode {
    FE_NOT_INITIALIZED,
    FE_WFP_ERROR,
    FE_WINAPI_ERROR,
};

template <>
struct ErrorCodeToString<WfpFirewallErrorCode> {
    std::string operator()(WfpFirewallErrorCode e) {
        switch (e) {
        case FE_NOT_INITIALIZED:
            return "The firewall failed to initialize";
        case FE_WFP_ERROR:
            return "A WFP function call failed";
        case FE_WINAPI_ERROR:
            return "A Windows API function call failed";
        }
    }
};

using WfpFirewallError = Error<WfpFirewallErrorCode>;

/** WFP-based firewall. */
class WfpFirewall {
public:
    WfpFirewall();
    ~WfpFirewall();

    WfpFirewall(const WfpFirewall &) = delete;
    WfpFirewall &operator=(const WfpFirewall &) = delete;

    WfpFirewall(WfpFirewall &&) = default;
    WfpFirewall &operator=(WfpFirewall &&) = default;

    /** Block DNS traffic to/from all addresses except `allowed_v4` and `allowed_v6`. */
    WfpFirewallError restrict_dns_to(std::span<const CidrRange> allowed_v4, std::span<const CidrRange> allowed_v6);

    /** Block all inbound/outbound IPv6 traffic. */
    WfpFirewallError block_ipv6();

    /**
     * Block untunneled traffic, i.e. traffic to/from `incl4`/`incl6` and not from/to `tunnadr4`/`tunaddr6`.
     * `tunaddr4` and `tunaddr6` are the tun interface's IPv4 and IPv6 addresses.
     * `incl4` and `incl6` are included (i.e. routed through the tunnel) prefixes.
     * Traffic to/from loopback is never blocked.
     */
    WfpFirewallError block_untunneled(const CidrRange &tunaddr4, const CidrRange &tunaddr6,
            std::span<const CidrRange> incl4, std::span<const CidrRange> incl6, std::span<const uint16_t> excl_ports);

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ag
