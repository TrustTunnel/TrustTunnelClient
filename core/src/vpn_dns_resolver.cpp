#include <algorithm>
#include <bitset>
#include <limits>

#include "net/dns_utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_dns_resolver.h"

#define log_resolver(r_, lvl_, fmt_, ...) lvl_##log((r_)->log, fmt_, ##__VA_ARGS__)
#define log_conn(r_, cid_, lvl_, fmt_, ...) lvl_##log((r_)->log, "[L:{}] " fmt_, (cid_), ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

static const sockaddr_storage BOOTSTRAP_ADDRESSES[] = {
        sockaddr_from_str("94.140.14.140:53"),
        sockaddr_from_str("94.140.14.141:53"),
        sockaddr_from_str("1.1.1.1:53"),
        sockaddr_from_str("8.8.8.8:53"),
};

static const sockaddr_storage CUSTOM_SRC_IP = sockaddr_from_str("127.0.0.11");
static constexpr std::string_view CUSTOM_APP_NAME = "__vpn_dns_resolver__";
static constexpr std::string_view RESOLVER_DOMAIN = "dns-unfiltered.adguard.com";
/// Manually resolved `RESOLVER_DOMAIN`
static const sockaddr_storage DEFAULT_RESOLVER_ADDRESS = sockaddr_from_str("94.140.14.140:53");
static constexpr size_t RESOLVE_CAPACITIES[magic_enum::enum_count<VpnDnsResolverQueue>()] = {
        /** VDRQ_BACKGROUND */ VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES,
        /** VDRQ_FOREGROUND */ std::numeric_limits<size_t>::max(),
};

void VpnDnsResolver::set_ipv6_availability(bool available) {
    m_ipv6_available = available;
}

std::optional<VpnDnsResolveId> VpnDnsResolver::resolve(
        VpnDnsResolverQueue queue, std::string name, RecordTypeSet record_types, ResultHandler result_handler) {
    log_resolver(this, trace, "{}", name);
    VpnDnsResolveId id = this->next_id++;
    this->queues[queue].emplace(id, Resolve{std::move(name), record_types, result_handler});

    if (std::holds_alternative<BootstrapState>(this->state)) {
        return id;
    }

    if (std::holds_alternative<ResolveState>(this->state)) {
        if (!this->deferred_resolve_task.has_value()) {
            this->deferred_resolve_task =
                    event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                                   auto *self = (VpnDnsResolver *) arg;
                                                                   self->deferred_resolve_task.release();
                                                                   self->resolve_pending_domains();
                                                               }});
        }
        return id;
    }

    if (!std::holds_alternative<std::monostate>(this->state)) {
        log_resolver(this, warn, "Invalid resolver state: {}", this->state.index());
        assert(0);
        return std::nullopt;
    }

    uint64_t connection_ids[std::size(BOOTSTRAP_ADDRESSES)];
    std::generate(
            std::begin(connection_ids), std::end(connection_ids), [gen = &this->vpn->listener_conn_id_generator]() {
                return gen->get();
            });

    auto &bootstrap = this->state.emplace<BootstrapState>();
    bootstrap.connections.reserve(std::size(BOOTSTRAP_ADDRESSES));
    std::transform(std::begin(connection_ids), std::end(connection_ids),
            std::inserter(bootstrap.connections, bootstrap.connections.begin()), [](uint64_t id) {
                return std::make_pair(id, BootstrapState::Connection{});
            });

    TunnelAddress dst;
    sockaddr_storage src = this->make_source_address();
    ClientConnectRequest event = {
            0,
            IPPROTO_UDP,
            (sockaddr *) &src,
            &dst,
            CUSTOM_APP_NAME,
    };
    for (size_t i = 0; i < std::size(BOOTSTRAP_ADDRESSES); ++i) {
        dst = BOOTSTRAP_ADDRESSES[i];
        event.id = connection_ids[i];
        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);
    }

    if (std::holds_alternative<BootstrapState>(this->state)) {
        bootstrap.timeout_task = event_loop::schedule(this->vpn->parameters.ev_loop, {this, on_bootstrap_timeout},
                this->vpn->upstream_config.timeout);
    }

    return id;
}

void VpnDnsResolver::cancel(VpnDnsResolveId id) {
    for (Queue &q : this->queues) {
        if (q.erase(id) != 0) {
            return;
        }
    }

    auto *resolve = std::get_if<ResolveState>(&this->state);
    if (resolve == nullptr) {
        return;
    }

    auto on_the_wire_it = std::find_if(resolve->queries.begin(), resolve->queries.end(), [id](const auto &i) {
        return i.second.id == id;
    });
    if (on_the_wire_it != resolve->queries.end()) {
        resolve->queries.erase(on_the_wire_it);
    }
}

void VpnDnsResolver::stop_resolving() {
    this->stopping = true;

    std::vector<uint64_t> connections;
    if (auto *bootstrap = std::get_if<BootstrapState>(&this->state); bootstrap != nullptr) {
        connections.reserve(bootstrap->connections.size());
        std::transform(bootstrap->connections.begin(), bootstrap->connections.end(), std::back_inserter(connections),
                [](const auto &i) {
                    return i.first;
                });
    } else if (auto *resolve = std::get_if<ResolveState>(&this->state); resolve != nullptr) {
        connections.push_back(resolve->connection_id);
    }

    for (uint64_t id : connections) {
        this->close_connection(id, false, false);
    }

    this->deinit();
    this->stopping = false;
}

void VpnDnsResolver::deinit() {
    m_dns_resolver_address.reset();
    this->queues = {};
    this->state = std::monostate{};
    this->accepting_connections.clear();
    this->deferred_accept_task.reset();
    this->closing_connections.clear();
    this->deferred_close_task.reset();
    this->deferred_resolve_task.reset();
}

void VpnDnsResolver::complete_connect_request(uint64_t id, ClientConnectResult result) {
    if (std::holds_alternative<std::monostate>(this->state)
            || this->closing_connections.end()
                    != std::find(this->closing_connections.begin(), this->closing_connections.end(), id)) {
        return;
    }

    if (result != CCR_PASS) {
        log_conn(this, id, dbg, "Failed to make connection: {}", magic_enum::enum_name(result));
        this->close_connection(id, false, true);
        return;
    }

    this->accepting_connections.push_back(id);
    if (!this->deferred_accept_task.has_value()) {
        this->deferred_accept_task =
                event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                               auto *self = (VpnDnsResolver *) arg;
                                                               self->deferred_accept_task.release();
                                                               std::vector<uint64_t> connections;
                                                               connections.swap(self->accepting_connections);
                                                               for (uint64_t id : connections) {
                                                                   self->accept_pending_connection(id);
                                                               }
                                                           }});
    }
}

void VpnDnsResolver::accept_pending_connection(uint64_t id) {
    if (auto *bootstrap = std::get_if<BootstrapState>(&this->state); bootstrap != nullptr) {
        auto it = bootstrap->connections.find(id);
        if (it == bootstrap->connections.end()) {
            log_conn(this, id, dbg, "Not found among bootstrap connections");
            this->close_connection(id, false, false);
            assert(0);
            return;
        }

        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &id);
        if (!std::holds_alternative<BootstrapState>(this->state)
                || bootstrap->connections.end() == (it = bootstrap->connections.find(id))) {
            return;
        }

        BootstrapState::Connection &conn = it->second;
        conn.queries = this->send_request(id, RESOLVER_DOMAIN, 1 << dns_utils::RT_A | 1 << dns_utils::RT_AAAA);
        if (std::all_of(conn.queries.begin(), conn.queries.end(), [](const auto &i) {
                return !i.has_value();
            })) {
            this->close_connection(id, true, false);
        }

        return;
    }

    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &id);
    auto *resolve = std::get_if<ResolveState>(&this->state);
    if (resolve == nullptr) {
        return;
    }

    if (resolve->is_open) {
        log_conn(this, resolve->connection_id, dbg, "Resolving connection is already open");
        this->close_connection(id, false, false);
        assert(0);
        return;
    }

    if (resolve->connection_id != id) {
        log_conn(this, resolve->connection_id, dbg, "Unexpected resolving connection ID: {}", resolve->connection_id,
                id);
        this->close_connection(id, false, false);
        assert(0);
        return;
    }

    resolve->is_open = true;
    this->resolve_pending_domains();
}

void VpnDnsResolver::close_connection(uint64_t id, bool graceful, bool async) {
    if (auto it = std::find(this->accepting_connections.begin(), this->accepting_connections.end(), id);
            it != this->accepting_connections.end()) {
        this->accepting_connections.erase(it);
    }

    if (async) {
        this->closing_connections.push_back(id);
        if (!this->deferred_close_task.has_value()) {
            this->deferred_close_task =
                    event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                                   auto *self = (VpnDnsResolver *) arg;
                                                                   self->deferred_close_task.release();
                                                                   std::vector<uint64_t> connections;
                                                                   connections.swap(self->closing_connections);
                                                                   for (uint64_t id : connections) {
                                                                       self->close_connection(id, true, false);
                                                                   }
                                                               }});
        }
        return;
    }

    if (auto it = std::find(this->closing_connections.begin(), this->closing_connections.end(), id);
            it != this->closing_connections.end()) {
        this->closing_connections.erase(it);
    }

    if (auto *bootstrap = std::get_if<BootstrapState>(&this->state); bootstrap != nullptr) {
        bootstrap->connections.erase(id);
        if (!bootstrap->connections.empty()) {
            goto raise_event;
        }

        if (!m_dns_resolver_address.has_value()) {
            log_resolver(this, dbg, "Failed to bootstrap the resolver, falling back to the default address: {}",
                    sockaddr_to_str((sockaddr *) &DEFAULT_RESOLVER_ADDRESS));
            m_dns_resolver_address = DEFAULT_RESOLVER_ADDRESS;
        }

        this->state.emplace<ResolveState>();
        assert(!this->deferred_resolve_task.has_value());
        this->deferred_resolve_task =
                event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                               auto *self = (VpnDnsResolver *) arg;
                                                               self->deferred_resolve_task.release();
                                                               self->resolve_pending_domains();
                                                           }});
    } else if (auto *resolve = std::get_if<ResolveState>(&this->state);
               resolve != nullptr && resolve->connection_id == id) {
        log_resolver(this, dbg, "Resolve connection has been closed");

        if (!this->stopping) {
            while (!resolve->queries.empty()) {
                ResolveState::Query q = resolve->queries.begin()->second;
                resolve->queries.erase(resolve->queries.begin());
                raise_result(q.result_handler, q.id, VpnDnsResolverFailure{q.record_type});
            }

            for (Queue &queue : this->queues) {
                while (!queue.empty()) {
                    auto [entry_id, entry] = std::move(*queue.begin());
                    queue.erase(queue.begin());
                    for (size_t i = 0; i < entry.record_types.size(); ++i) {
                        if (entry.record_types.test(i)) {
                            raise_result(entry.handler, entry_id, VpnDnsResolverFailure{dns_utils::RecordType(i)});
                        }
                    }
                }
            }
        }

        this->state = std::monostate{};
    }

raise_event:
    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
}

ssize_t VpnDnsResolver::send(uint64_t id, const uint8_t *data, size_t length) {
    log_conn(this, id, dbg, "{}", length);
    if (std::holds_alternative<std::monostate>(this->state)) {
        log_conn(this, id, dbg, "Invalid state: idle");
        return -1;
    }

    dns_utils::DecodeResult r = dns_utils::decode_packet({data, length});
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_conn(this, id, dbg, "Failed to parse reply: {}", e->description);
        return -1;
    }

    if (auto *bootstrap = std::get_if<BootstrapState>(&this->state); bootstrap != nullptr) {
        auto it = bootstrap->connections.find(id);
        if (bootstrap->connections.end() == it) {
            log_conn(this, id, dbg, "Not found");
            return -1;
        }

        uint16_t reply_id; // NOLINT(cppcoreguidelines-init-variables)
        BootstrapState::Connection &conn = it->second;
        if (const auto *inapplicable_reply = std::get_if<dns_utils::InapplicablePacket>(&r);
                inapplicable_reply != nullptr) {
            log_conn(this, id, trace, "Packet holds inapplicable reply");
            reply_id = inapplicable_reply->id;
        } else {
            const auto &reply = std::get<dns_utils::DecodedReply>(r);
            reply_id = reply.id;
            if (!reply.addresses.empty()) {
                m_dns_resolver_address =
                        sockaddr_from_raw(reply.addresses[0].ip.data(), reply.addresses[0].ip.size(), htons(53));
                log_conn(this, id, dbg, "Got resolver address: {}",
                        sockaddr_to_str((sockaddr *) &m_dns_resolver_address.value()));
            } else {
                log_conn(this, id, trace, "Dropping reply without any address");
            }
        }

        if (reply_id == conn.queries[0]) {
            conn.queries[0].reset();
        } else {
            assert(reply_id == conn.queries[1]);
            conn.queries[1].reset();
        }

        if (m_dns_resolver_address.has_value()) {
            std::vector<uint64_t> bootstrap_connections(bootstrap->connections.size());
            std::transform(bootstrap->connections.begin(), bootstrap->connections.end(), bootstrap_connections.begin(),
                    [](const auto &i) -> uint64_t {
                        return i.first;
                    });
            for (uint64_t bc_id : bootstrap_connections) { // NOLINT(clang-analyzer-core.uninitialized.Assign)
                this->close_connection(bc_id, true, false);
            }
        } else if (std::all_of(conn.queries.begin(), conn.queries.end(), [](const auto &i) {
                       return !i.has_value();
                   })) {
            this->close_connection(id, true, false);
        }
        return (ssize_t) length;
    }

    auto &resolve = std::get<ResolveState>(this->state);
    if (resolve.connection_id != id) {
        log_conn(this, id, dbg, "Wrong connection ID");
        assert(0);
        return -1;
    }

    VpnDnsResolverResult result = VpnDnsResolverFailure{};
    uint16_t reply_id; // NOLINT(cppcoreguidelines-init-variables)
    if (const auto *inapplicable_packet = std::get_if<dns_utils::InapplicablePacket>(&r);
            inapplicable_packet != nullptr) {
        log_conn(this, id, trace, "Packet holds inapplicable packet");
        reply_id = inapplicable_packet->id;
    } else if (const auto *request = std::get_if<dns_utils::DecodedRequest>(&r); request != nullptr) {
        log_conn(this, id, trace, "Packet holds DNS request");
        reply_id = request->id;
    } else {
        const auto &reply = std::get<dns_utils::DecodedReply>(r);
        reply_id = reply.id;
        if (!reply.addresses.empty()) {
            result = VpnDnsResolverSuccess{
                    .addr = sockaddr_from_raw(reply.addresses[0].ip.data(), reply.addresses[0].ip.size(), 0)};
        } else {
            log_conn(this, id, dbg, "Resolved address list is empty");
        }
        // @note: resolved addresses are passed to filter via the DNS sniffer in the tunnel
    }

    if (auto it = resolve.queries.find(reply_id); it != resolve.queries.end()) {
        if (auto *failure = std::get_if<VpnDnsResolverFailure>(&result); failure != nullptr) {
            failure->record_type = it->second.record_type;
        }

        ResolveState::Query q = it->second;
        resolve.queries.erase(it);
        raise_result(q.result_handler, q.id, result);
    }

    this->resolve_pending_domains();

    return (ssize_t) length;
}

void VpnDnsResolver::consume(uint64_t, size_t) {
}

TcpFlowCtrlInfo VpnDnsResolver::flow_control_info(uint64_t id) {
    if (std::holds_alternative<std::monostate>(this->state)) {
        return {};
    }

    if (auto *bootstrap = std::get_if<BootstrapState>(&this->state); bootstrap != nullptr) {
        return (bootstrap->connections.count(id) != 0) ? TcpFlowCtrlInfo{UDP_MAX_DATAGRAM_SIZE, UDP_MAX_DATAGRAM_SIZE}
                                                       : TcpFlowCtrlInfo{};
    }

    auto &resolve = std::get<ResolveState>(this->state);
    return (resolve.connection_id == id) ? TcpFlowCtrlInfo{UDP_MAX_DATAGRAM_SIZE, UDP_MAX_DATAGRAM_SIZE}
                                         : TcpFlowCtrlInfo{};
}

void VpnDnsResolver::turn_read(uint64_t, bool) {
}

int VpnDnsResolver::process_client_packets(VpnPackets) {
    assert(0);
    return -1;
}

std::optional<std::pair<uint16_t, std::vector<uint8_t>>> VpnDnsResolver::make_request(
        bool is_aaaa, std::string_view name) const {
    dns_utils::EncodeResult r = dns_utils::encode_request({is_aaaa ? dns_utils::RT_AAAA : dns_utils::RT_A, name});
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_resolver(this, dbg, "Failed to encode packet: {}", e->description);
        return std::nullopt;
    }

    auto &req = std::get<dns_utils::EncodedRequest>(r);
    return {{req.id, std::move(req.data)}};
}

std::optional<uint16_t> VpnDnsResolver::send_request(bool is_aaaa, uint64_t conn_id, std::string_view name) {
    auto req = this->make_request(is_aaaa, name);
    if (!req.has_value()) {
        return std::nullopt;
    }

    auto &[query_id, data] = req.value();
    ClientRead event = {conn_id, data.data(), data.size()};
    this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
    if (event.result != (int) data.size()) {
        log_conn(this, conn_id, dbg, "Failed to send request: {}", event.result);
        return std::nullopt;
    }

    return query_id;
}

std::array<std::optional<uint16_t>, 2> VpnDnsResolver::send_request(
        uint64_t conn_id, std::string_view name, RecordTypeSet record_types) {
    return {
            record_types.test(dns_utils::RT_A) ? this->send_request(false, conn_id, name) : std::nullopt,
            (m_ipv6_available && record_types.test(dns_utils::RT_AAAA)) ? this->send_request(true, conn_id, name)
                                                                        : std::nullopt,
    };
}

void VpnDnsResolver::resolve_pending_domains() {
    if (!std::holds_alternative<ResolveState>(this->state)) {
        log_resolver(this, dbg, "Invalid state: {}", this->state.index());
        assert(0);
        return;
    }

    if (std::all_of(this->queues.begin(), this->queues.end(), [](const Queue &q) {
            return q.empty();
        })) {
        // nothing to do
        return;
    }

    auto *resolve = std::get_if<ResolveState>(&this->state);
    resolve->timeout_task = event_loop::schedule(this->vpn->parameters.ev_loop, {this, on_resolve_timeout},
            this->vpn->upstream_config.timeout);

    if (!resolve->is_open) {
        resolve->connection_id = this->vpn->listener_conn_id_generator.get();
        sockaddr_storage src = this->make_source_address();
        TunnelAddress dst = m_dns_resolver_address.value();
        ClientConnectRequest event = {
                resolve->connection_id,
                IPPROTO_UDP,
                (sockaddr *) &src,
                &dst,
                CUSTOM_APP_NAME,
        };
        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);
        return;
    }

    for (VpnDnsResolverQueue q : magic_enum::enum_values<VpnDnsResolverQueue>()) {
        this->resolve_queue(q);
    }
}

void VpnDnsResolver::resolve_queue(VpnDnsResolverQueue queue_type) {
    auto &resolve_state = std::get<ResolveState>(this->state);
    Queue &queue = this->queues[queue_type];

    while (resolve_state.queries.size() < RESOLVE_CAPACITIES[queue_type] && !queue.empty()) {
        auto [entry_id, entry] = std::move(*queue.begin());
        queue.erase(queue.begin());

        auto ids = this->send_request(resolve_state.connection_id, entry.name, entry.record_types);
        static_assert(ids.size() == decltype(entry.record_types){}.size());
        for (size_t i = 0; i < ids.size(); ++i) {
            const auto &id = ids[i];
            if (id.has_value()) {
                resolve_state.queries.emplace(id.value(),
                        ResolveState::Query{
                                .id = entry_id,
                                .record_type = dns_utils::RecordType(i),
                                .result_handler = entry.handler,
                        });
            } else if (entry.record_types.test(i)) {
                raise_result(entry.handler, entry_id, VpnDnsResolverFailure{dns_utils::RecordType(i)});
            }
        }
    }
}

sockaddr_storage VpnDnsResolver::make_source_address() {
    sockaddr_storage addr = CUSTOM_SRC_IP;
    sockaddr_set_port((sockaddr *) &addr, this->next_connection_port++);
    return addr;
}

void VpnDnsResolver::raise_result(ResultHandler h, VpnDnsResolveId id, VpnDnsResolverResult result) {
    if (h.func != nullptr) {
        h.func(h.arg, id, result);
    }
}

void VpnDnsResolver::on_bootstrap_timeout(void *arg, TaskId) {
    auto *self = (VpnDnsResolver *) arg;
    log_resolver(self, dbg, "...");

    auto *bootstrap = std::get_if<BootstrapState>(&self->state);
    if (bootstrap == nullptr) {
        log_resolver(self, dbg, "Invalid state: {}", self->state.index());
        assert(0);
        return;
    }

    bootstrap->timeout_task.release();

    std::vector<uint64_t> bootstrap_connections(bootstrap->connections.size());
    std::transform(bootstrap->connections.begin(), bootstrap->connections.end(), bootstrap_connections.begin(),
            [](const auto &i) -> uint64_t {
                return i.first;
            });
    for (uint64_t bc_id : bootstrap_connections) { // NOLINT(clang-analyzer-core.uninitialized.Assign)
        self->close_connection(bc_id, true, false);
    }
}

void VpnDnsResolver::on_resolve_timeout(void *arg, TaskId) {
    auto *self = (VpnDnsResolver *) arg;
    log_resolver(self, dbg, "...");

    auto *resolve = std::get_if<ResolveState>(&self->state);
    if (resolve == nullptr) {
        log_resolver(self, dbg, "Invalid state: {}", self->state.index());
        assert(0);
        return;
    }

    resolve->timeout_task.release();
    self->close_connection(resolve->connection_id, true, false);
}

} // namespace ag
