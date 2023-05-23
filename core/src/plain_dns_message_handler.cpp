#include "plain_dns_message_handler.h"
#include "net/dns_utils.h"
#include "net/network_manager.h"
#include "vpn/internal/tunnel.h"

#define log_handler(p_, lvl_, fmt_, ...) lvl_##log((p_)->m_log, fmt_, ##__VA_ARGS__)

namespace ag {

void PlainDnsMessageHandler::init(const Parameters &p) {
    m_parameters = p;
}

PlainDnsMessageHandler::RoutingPolicy PlainDnsMessageHandler::on_outgoing_message(U8View data) const {
    dns_utils::DecodeResult r = dns_utils::decode_packet(data);
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_handler(this, dbg, "Failed to parse reply: {}", e->description);
        return (m_parameters.vpn->dns_proxy == nullptr) ? RP_DEFAULT : RP_THROUGH_DNS_PROXY;
    }

    const auto *request = std::get_if<dns_utils::DecodedRequest>(&r);
    if (request == nullptr) {
        log_handler(this, dbg, "Packet holds inapplicable request");
        return (m_parameters.vpn->dns_proxy == nullptr) ? RP_DEFAULT : RP_THROUGH_DNS_PROXY;
    }

    log_handler(this, dbg, "Domain name: {}", request->name);

    if (m_parameters.vpn->drop_non_app_initiated_dns_queries()) {
        if (!vpn_network_manager_check_app_request_domain(request->name.c_str())) {
            log_handler(this, dbg, "Drop non-app-initiated DNS query");
            return RP_DROP;
        }

        // `drop_non_app_initiated_dns_queries()` returning true means that we are not
        // connected to an endpoint, so all our own application initiated DNS queries
        // should be routed to the target host directly, otherwise they would be dropped
        return RP_FORCE_BYPASS;
    }

    if (m_parameters.vpn->dns_health_check_id.has_value() && request->name == VpnClient::dns_health_check_domain()
            && m_parameters.vpn->dns_health_check_id
                    == m_parameters.dns_resolver->lookup_resolve_id(request->id, request->name)) {
        log_handler(this, dbg, "DNS health check request");
        return RP_THROUGH_DNS_PROXY;
    }

    switch (m_parameters.vpn->domain_filter.match_domain(request->name)) {
    case DFMS_SUSPECT_EXCLUSION:
        assert(0);
        [[fallthrough]];
    case DFMS_DEFAULT:
        switch (m_parameters.vpn->domain_filter.get_mode()) {
        case VPN_MODE_GENERAL:
            return (m_parameters.vpn->dns_proxy == nullptr) ? RP_DEFAULT : RP_THROUGH_DNS_PROXY;
        case VPN_MODE_SELECTIVE:
            return RP_DEFAULT;
        }
    case DFMS_EXCLUSION:
        switch (m_parameters.vpn->domain_filter.get_mode()) {
        case VPN_MODE_GENERAL:
            return RP_EXCEPTIONAL;
        case VPN_MODE_SELECTIVE:
            return (m_parameters.vpn->dns_proxy == nullptr) ? RP_EXCEPTIONAL : RP_THROUGH_DNS_PROXY;
        }
    }
}

void PlainDnsMessageHandler::on_incoming_message(U8View data, bool library_request) {
    dns_utils::DecodeResult r = dns_utils::decode_packet(data);
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_handler(this, dbg, "Failed to parse reply: {}", e->description);
        return;
    }

    const auto *answer = std::get_if<dns_utils::DecodedReply>(&r);
    if (answer == nullptr) {
        return;
    }

    bool found_exclusion = false;
    for (const std::string &name : answer->names) {
        found_exclusion = DFMS_EXCLUSION == m_parameters.vpn->domain_filter.match_domain(name);
        if (found_exclusion) {
            log_handler(this, dbg, "Domain name ({}) is excluded, adding its addresses as suspects", name);
            break;
        }
    }

    if (found_exclusion) {
        for (const dns_utils::AnswerAddress &addr : answer->addresses) {
            m_parameters.vpn->domain_filter.add_exclusion_suspect(sockaddr_from_raw(addr.ip.data(), addr.ip.size(), 0),
                    library_request ? std::max(addr.ttl, Tunnel::EXCLUSIONS_RESOLVE_PERIOD) : addr.ttl);
        }
    }
}

PlainDnsMessageHandler::RoutingPolicy PlainDnsMessageHandler::vpn_action_to_routing_policy(
        VpnMode mode, VpnConnectAction action) {
    constexpr RoutingPolicy TABLE[magic_enum::enum_count<VpnMode>()][magic_enum::enum_count<VpnConnectAction>()] = {
            /** VPN_MODE_GENERAL */
            {
                    /** VPN_CA_DEFAULT */ RP_DEFAULT,
                    /** VPN_CA_FORCE_BYPASS */ RP_EXCEPTIONAL,
                    /** VPN_CA_FORCE_REDIRECT */ RP_DEFAULT,
            },
            /** VPN_MODE_SELECTIVE */
            {
                    /** VPN_CA_DEFAULT */ RP_DEFAULT,
                    /** VPN_CA_FORCE_BYPASS */ RP_DEFAULT,
                    /** VPN_CA_FORCE_REDIRECT */ RP_EXCEPTIONAL,
            },
    };

    return TABLE[mode][action]; // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
}

} // namespace ag
