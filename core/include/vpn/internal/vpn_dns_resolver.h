#pragma once

#include <array>
#include <bitset>
#include <map>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include <magic_enum.hpp>

#include "common/logger.h"
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
    sockaddr_storage addr;
};

/// Failed to resolve a domain for some reason
struct VpnDnsResolverFailure {
    dns_utils::RecordType record_type;
};

using VpnDnsResolverResult = std::variant<VpnDnsResolverSuccess, VpnDnsResolverFailure>;

/**
 * This class is intended to make plain DNS requests through VPN endpoint to resolve
 * the provided domains.
 */
class VpnDnsResolver : public ClientListener {
public:
    /// Prevent UDP stream flooding
    static constexpr size_t MAX_PARALLEL_BACKGROUND_RESOLVES = 32;

    using RecordTypeSet = std::bitset<magic_enum::enum_count<dns_utils::RecordType>()>;

    struct ResultHandler {
        /// Will be raised for each of the record type passed to `resolve()`
        void (*func)(void *arg, VpnDnsResolveId id, VpnDnsResolverResult result);
        void *arg;
    };

    VpnDnsResolver() = default;
    ~VpnDnsResolver() override = default;

    VpnDnsResolver(const VpnDnsResolver &) = delete;
    VpnDnsResolver &operator=(const VpnDnsResolver &) = delete;
    VpnDnsResolver(VpnDnsResolver &&) = delete;
    VpnDnsResolver &operator=(VpnDnsResolver &&) = delete;

    void deinit() override;

    /**
     * Set the IPV6 availability
     */
    void set_ipv6_availability(bool available);

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
     * Stop the specified resolving procedure silently
     */
    void cancel(VpnDnsResolveId id);

    /**
     * Stop all running resolving procedures.
     * May raise some callbacks.
     */
    void stop_resolving();

private:
    struct Resolve {
        std::string name;
        RecordTypeSet record_types;
        ResultHandler handler = {};
    };

    struct BootstrapState {
        struct Connection {
            std::array<std::optional<uint16_t>, 2> queries;
        };

        std::unordered_map<uint64_t, Connection> connections;
        event_loop::AutoTaskId timeout_task;
    };

    struct ResolveState {
        struct Query {
            VpnDnsResolveId id;
            dns_utils::RecordType record_type;
            ResultHandler result_handler;
        };

        uint64_t connection_id = NON_ID;
        bool is_open = false;
        std::unordered_map<uint16_t, Query> queries;
        event_loop::AutoTaskId timeout_task;
    };

    using State = std::variant<std::monostate, BootstrapState, ResolveState>;
    using Queue = std::map<VpnDnsResolveId, Resolve>;

    bool m_ipv6_available = false;
    std::optional<sockaddr_storage> m_dns_resolver_address;
    VpnDnsResolveId next_id = 0;
    std::array<Queue, magic_enum::enum_count<VpnDnsResolverQueue>()> queues;
    State state;
    std::vector<uint64_t> accepting_connections;
    event_loop::AutoTaskId deferred_accept_task;
    std::vector<uint64_t> closing_connections;
    event_loop::AutoTaskId deferred_close_task;
    event_loop::AutoTaskId deferred_resolve_task;
    uint16_t next_connection_port = 1;
    bool stopping = false;
    ag::Logger log{"VPN_DNS_RESOLVER"};

    void complete_connect_request(uint64_t id, ClientConnectResult result) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t n) override;
    TcpFlowCtrlInfo flow_control_info(uint64_t id) override;
    void turn_read(uint64_t id, bool on) override;
    int process_client_packets(VpnPackets packets) override;

    void accept_pending_connection(uint64_t);
    std::optional<std::pair<uint16_t, std::vector<uint8_t>>> make_request(bool is_aaaa, std::string_view name) const;
    std::optional<uint16_t> send_request(bool is_aaaa, uint64_t conn_id, std::string_view name);
    std::array<std::optional<uint16_t>, 2> send_request(
            uint64_t conn_id, std::string_view name, RecordTypeSet record_types);
    void resolve_pending_domains();
    void resolve_queue(VpnDnsResolverQueue queue);
    sockaddr_storage make_source_address();
    static void raise_result(ResultHandler h, VpnDnsResolveId id, VpnDnsResolverResult result);

    static void on_bootstrap_timeout(void *arg, TaskId);
    static void on_resolve_timeout(void *arg, TaskId);
};

} // namespace ag
