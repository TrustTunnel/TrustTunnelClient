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

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace ag
