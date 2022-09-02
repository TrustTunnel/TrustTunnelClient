#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>

#include <event2/event.h>
#include <khash.h>

#include "common/logger.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/dns_sniffer.h"
#include "vpn/internal/icmp_manager.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_connection.h"
#include "vpn/internal/vpn_dns_resolver.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {

KHASH_MAP_INIT_INT64(connections_by_id, VpnConnection *);

struct VpnConnections {
    khash_t(connections_by_id) *by_client_id = nullptr;
    khash_t(connections_by_id) *by_server_id = nullptr;
};

struct DnsResolveWaiter {
    uint64_t conn_client_id = NON_ID;
    bool failures[magic_enum::enum_count<dns_utils::RecordType>()] = {};
};

struct Tunnel {
    static constexpr std::chrono::seconds EXCLUSIONS_RESOLVE_PERIOD{60 * 60};

    VpnConnections connections = {};
    VpnClient *vpn = nullptr;
    IcmpManager icmp_manager;
    ag::Logger log{"TUNNEL"};
    int id;
    bool endpoint_upstream_connected = false;
    std::unique_ptr<VpnDnsResolver> dns_resolver;
    std::unordered_map<VpnDnsResolveId, DnsResolveWaiter> dns_resolve_waiters;
    event_loop::AutoTaskId repeat_exclusions_resolve_task;
    std::unique_ptr<ServerUpstream> fake_upstream;
    DnsSniffer dns_sniffer;

    Tunnel();
    ~Tunnel();

    Tunnel(const Tunnel &) = delete;
    Tunnel &operator=(const Tunnel &) = delete;

    Tunnel(Tunnel &&) noexcept = delete;
    Tunnel &operator=(Tunnel &&) noexcept = delete;

    bool init(VpnClient *vpn);

    void deinit();

    void upstream_handler(ServerUpstream *upstream, ServerEvent what, void *data);
    void listener_handler(ClientListener *listener, ClientEvent what, void *data);

    void complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action);
    void reset_connections(int uid);
    void reset_connection(uint64_t client_id);
    void on_before_endpoint_disconnect(ServerUpstream *upstream);
    void on_after_endpoint_disconnect(ServerUpstream *upstream);
    void on_exclusions_updated();

    /**
     * @param request_result The connection request result
     * @param only_app_initiated_dns If true and the connection is not forcibly redirected (`VPN_CA_FORCE_REDIRECT`),
     *                               all the non-app-initiated DNS queries
     * (`vpn_network_manager_check_app_request_domain`) will be dropped on this connection
     * @return Some value if connection should definitely be routed to some upstream.
     *         Otherwise, if upstream can be changed in the future (e.g. if the destination address
     *         is ip, we can realize that the connection should not have been routed to the
     *         VPN endpoint, but to the host directly), none is returned.
     */
    std::optional<VpnConnectAction> finalize_connect_action(
            ConnectRequestResult &request_result, bool only_app_initiated_dns) const;

    static void on_icmp_reply_ready(void *arg, const IcmpEchoReply &reply);
};

} // namespace ag
