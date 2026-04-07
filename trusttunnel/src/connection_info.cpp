#include <common/time_utils.h>
#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>

#include "vpn/trusttunnel/connection_info.h"

namespace ag {

std::string ConnectionInfo::to_json(VpnConnectionInfoEvent *info, bool include_current_time) {
    static const std::map<VpnFinalConnectionAction, std::string_view> ACTION_MAP = {
            {VPN_FCA_BYPASS, "bypass"},
            {VPN_FCA_TUNNEL, "tunnel"},
            {VPN_FCA_REJECT, "reject"},
    };

    nlohmann::json json;
    json["proto"] = info->proto == IPPROTO_TCP ? "TCP" : "UDP";
    if (info->src) {
        json["src"] = SocketAddress(*info->src).str();
    }
    if (info->dst) {
        json["dst"] = SocketAddress(*info->dst).str();
    }
    if (info->domain) {
        json["domain"] = info->domain;
    }

    if (auto action = ACTION_MAP.find(info->action); action != ACTION_MAP.end()) {
        json["action"] = action->second;
    } else {
        json["action"] = "unknown";
    }

    if (include_current_time) {
        json["date"] = format_gmtime(ag::SystemClock::now(), "%Y-%m-%dT%H:%M:%S.%fZ");
    }

    return json.dump(-1, ' ', false, nlohmann::detail::error_handler_t::replace);
}

} // namespace ag
