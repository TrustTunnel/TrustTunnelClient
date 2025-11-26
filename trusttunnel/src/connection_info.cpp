#include "vpn/trusttunnel/connection_info.h"

#include <nlohmann/json.hpp>
#include <magic_enum/magic_enum.hpp>

namespace ag {

std::string ConnectionInfo::to_json(VpnConnectionInfoEvent *info) {
    static const std::map<VpnFinalConnectionAction, std::string_view> ACTION_MAP = {
        { VPN_FCA_BYPASS, "bypass" },
        { VPN_FCA_TUNNEL, "tunnel" },
        { VPN_FCA_REJECT, "reject" },
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

    return json.dump();
}

} // namespace ag
