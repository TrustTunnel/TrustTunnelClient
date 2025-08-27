#pragma once

#include <array>
#include <bitset>
#include <map>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <magic_enum/magic_enum.hpp>

#include "common/clock.h"
#include "common/defs.h"
#include "common/logger.h"
#include "common/socket_address.h"
#include "net/dns_manager.h"
#include "net/dns_utils.h"
#include "vpn/event_loop.h"
#include "vpn/internal/client_listener.h"
#include "vpn/utils.h"

namespace ag {

using VpnDnsResolveId = uint32_t;

enum VpnDnsResolverQueue {
    /// Contains items whose resolving can be delayed
    VDRQ_BACKGROUND,
    /// Contains items that should be resolved as soon as possible
    VDRQ_FOREGROUND,
};

/// Successfully resolved
struct VpnDnsResolverSuccess {
    /// Always non-empty
    std::vector<SocketAddress> addresses;
};

/// Failed to resolve a domain for some reason
struct VpnDnsResolverFailure {};

using VpnDnsResolverResult = std::variant<VpnDnsResolverSuccess, VpnDnsResolverFailure>;

/**
 * This class is intended to make plain DNS requests through VPN endpoint to resolve
 * the provided domains.
 */
class VpnDnsResolver : public ClientListener {
public:
    /// Prevent UDP stream flooding
    static constexpr size_t MAX_PARALLEL_BACKGROUND_RESOLVES = 32;
    /// Default query timeout
    static constexpr Secs DEFAULT_QUERY_TIMEOUT{5};
    /// Query timeout
    static inline Millis g_query_timeout = DEFAULT_QUERY_TIMEOUT;

    using RecordTypeSet = std::bitset<magic_enum::enum_count<dns_utils::RecordType>()>;
    using QueueTypeSet = std::bitset<magic_enum::enum_count<VpnDnsResolverQueue>()>;

    struct ResultHandler {
        /// Will be raised for each of the record type passed to `resolve()`
        void (*func)(void *arg, VpnDnsResolveId id, VpnDnsResolverResult result);
        void *arg;
    };

    VpnDnsResolver();
    ~VpnDnsResolver() override = default;

    VpnDnsResolver(const VpnDnsResolver &) = delete;
    VpnDnsResolver &operator=(const VpnDnsResolver &) = delete;
    VpnDnsResolver(VpnDnsResolver &&) = delete;
    VpnDnsResolver &operator=(VpnDnsResolver &&) = delete;

    ClientListener::InitResult init(VpnClient *vpn, ClientHandler handler) override;
    void deinit() override;

    /**
     * Set the timeout value that is applied to each query
     */
    static void set_query_timeout(Millis v);

    /**
     * Start the domain name resolving procedure
     * @param name the name to be resolved
     * @param record_types record types to resolve
     * @param result_handler the handler which is called after a result is ready
     * @return some ID if started successfully
     */
    std::optional<VpnDnsResolveId> resolve(VpnDnsResolverQueue queue, std::string name,
            RecordTypeSet record_types = 1 << dns_utils::RT_A | 1 << dns_utils::RT_AAAA,
            ResultHandler result_handler = {});

    /**
     * Lookup for the resolve ID
     * @param query_id the DNS query ID
     * @param name the domain name contained in the query
     * @return Some ID if found
     */
    [[nodiscard]] std::optional<VpnDnsResolveId> lookup_resolve_id(uint16_t query_id, std::string_view name) const;

    /**
     * Stop the specified resolving procedure silently
     */
    void cancel(VpnDnsResolveId id);

    /**
     * Stop all running resolving procedures on the queues.
     * The `ResultHandler` callbacks of the cancelled queries are raised with errors.
     * @param queues Bitset of queues to stop to resolve.
     */
    void stop_resolving_queues(QueueTypeSet queues);

    /**
     * Stop all running resolving procedures.
     * The `ResultHandler` callbacks of the cancelled queries are raised with errors.
     * The `CLIENT_EVENT_CONNECTION_CLOSED` events for the fictive connections are raised as well.
     */
    void stop_resolving();

private:
    struct Resolve {
        std::string name;
        RecordTypeSet record_types;
        ResultHandler handler = {};
        std::vector<SocketAddress> resolved_addresses;
        std::array<std::optional<uint16_t>, magic_enum::enum_count<dns_utils::RecordType>()> queries;
    };

    struct ResolveState {
        struct Query {
            VpnDnsResolveId id;
            dns_utils::RecordType record_type;
            std::string name;
            VpnDnsResolverQueue queue_kind;
        };

        uint64_t connection_id = NON_ID;
        bool connection_accepted = false;
        std::unordered_map<uint16_t, Query> queries;
        // The whole fake connection timeout
        event_loop::AutoTaskId connection_timeout_task;
        event_loop::AutoTaskId periodic_queries_check_task;
        std::multimap<SteadyClock::time_point, uint16_t> deadlines;
    };

    using Queue = std::unordered_set<VpnDnsResolveId>;

    VpnDnsResolveId next_id = 0;
    std::unordered_map<VpnDnsResolveId, Resolve> resolutions;
    std::array<Queue, magic_enum::enum_count<VpnDnsResolverQueue>()> queues;
    ResolveState state;
    event_loop::AutoTaskId deferred_accept_task;
    event_loop::AutoTaskId deferred_close_task;
    event_loop::AutoTaskId deferred_resolve_task;
    std::optional<DnsChangeSubscriptionId> m_dns_change_subscription_id;
    TunnelAddress m_resolver_address;
    uint16_t next_connection_port = 1;
    ag::Logger log{"VPN_DNS_RESOLVER"};

    void complete_connect_request(uint64_t id, ClientConnectResult result) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t n) override;
    TcpFlowCtrlInfo flow_control_info(uint64_t id) override;
    void turn_read(uint64_t id, bool on) override;
    int process_client_packets(VpnPackets packets) override;

    void accept_connection();
    [[nodiscard]] std::optional<std::pair<uint16_t, std::vector<uint8_t>>> make_request(
            dns_utils::RecordType record_type, std::string_view name) const;
    void resolve_pending_domains();
    void resolve_queue(VpnDnsResolverQueue queue);
    SocketAddress make_source_address();
    static void raise_result(ResultHandler h, VpnDnsResolveId id, VpnDnsResolverResult result);

    static void on_connection_timeout(void *arg, TaskId);
    static void on_periodic_queries_check(void *arg, TaskId);
    static void on_dns_updated(void *arg);
};

} // namespace ag
