#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <unordered_map>

#include <event2/event.h>
#include <khash.h>

#include "common/cache.h"
#include "common/logger.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/icmp_manager.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_connection.h"
#include "vpn/internal/vpn_dns_resolver.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {

class DnsHandler;
class ConnectionStatisticsMonitor;

KHASH_MAP_INIT_INT64(connections_by_id, VpnConnection *);

struct VpnConnections {
    khash_t(connections_by_id) *by_client_id = nullptr;
    khash_t(connections_by_id) *by_server_id = nullptr;
};

struct DnsResolveWaiter {
    uint64_t conn_client_id = NON_ID;
};

struct Tunnel {
    static constexpr std::chrono::seconds EXCLUSIONS_RESOLVE_PERIOD{60 * 60};

    VpnConnections connections = {};
    VpnClient *vpn = nullptr;
    IcmpManager icmp_manager;
    ag::Logger log{"TUNNEL"};
    int id;
    bool endpoint_upstream_connected = false;

    /**
     * This flag is set by `handle_sleep()` and reset by `handle_wake()`.
     * While this flag is set, no health checks are issued.
     */
    bool sleeping = false;

    /**
     * The time at which the most recent health check was issued,
     * as reported by `event_base_gettimeofday_cached()`.
     *
     * A health check is always issued by `handle_wake()` (after resetting the `sleeping` flag),
     * regardless of this value. Otherwise, a health check is issued after opening a connection
     * or sending data on the endpoint upstream if and only if the time since `last_health_check_at`
     * is greater than or equal to `ag::VpnUpstreamConfig::timeout_ms` and the `sleeping` flag is not set.
     */
    timeval last_health_check_at = {};

    std::shared_ptr<VpnDnsResolver> dns_resolver;
    std::unordered_map<VpnDnsResolveId, DnsResolveWaiter> dns_resolve_waiters;
    event_loop::AutoTaskId repeat_exclusions_resolve_task;
    std::shared_ptr<ServerUpstream> fake_upstream;
    std::shared_ptr<DnsHandler> dns_handler;
    std::unique_ptr<ConnectionStatisticsMonitor> statistics_monitor;
    std::shared_ptr<WithMtx<LruTimeoutCache<TunnelAddressPair, DomainLookuperResult>>> udp_close_wait_hostname_cache;

    Tunnel();
    ~Tunnel();

    Tunnel(const Tunnel &) = delete;
    Tunnel &operator=(const Tunnel &) = delete;

    Tunnel(Tunnel &&) noexcept = delete;
    Tunnel &operator=(Tunnel &&) noexcept = delete;

    bool init(VpnClient *vpn);

    void deinit();

    void upstream_handler(const std::shared_ptr<ServerUpstream> &upstream, ServerEvent what, void *data);
    void listener_handler(const std::shared_ptr<ClientListener> &listener, ClientEvent what, void *data);

    void complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action);
    void reset_connections(int uid);
    void reset_connections(ClientListener *listener);
    void reset_connection(uint64_t client_id);
    void on_before_endpoint_disconnect(ServerUpstream *upstream);
    void on_after_endpoint_disconnect(ServerUpstream *upstream);
    void on_exclusions_updated();

    /**
     * Return `true` if connection request `client_id` should be completed immediately
     * (i.e. should not be postponed until recovery ends).
     */
    bool should_complete_immediately(uint64_t client_id) const;

    /**
     * @param request_result The connection request result
     * @return Some value if connection should definitely be routed to some upstream.
     *         Otherwise, if upstream can be changed in the future (e.g. if the destination address
     *         is ip, we can realize that the connection should not have been routed to the
     *         VPN endpoint, but to the host directly), none is returned.
     */
    std::optional<VpnConnectAction> finalize_connect_action(ConnectRequestResult request_result) const;

    static void on_icmp_reply_ready(void *arg, const IcmpEchoReply &reply);

    bool update_dns_handler_parameters();

    void on_network_change();

    /**
     * If a health check can be issued at this time or `force` is `true`,
     * issue a health check on `upstream`. Otherwise, do nothing.
     *
     * If `sleeping` is `true`, a health check will not be issued, regardless of `force`.
     */
    void do_health_check(const std::shared_ptr<ServerUpstream> &upstream, bool force = false);

    /** Must be called before the system goes to sleep. */
    void handle_sleep();

    /** Must be called after the system has woken from sleep. */
    void handle_wake();
};

} // namespace ag
