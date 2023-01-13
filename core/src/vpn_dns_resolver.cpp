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

static const sockaddr_storage CUSTOM_SRC_IP = sockaddr_from_str("127.0.0.11");
static constexpr std::string_view CUSTOM_APP_NAME = "__vpn_dns_resolver__";
static const sockaddr_storage RESOLVER_ADDRESS =
        sockaddr_from_str(AG_FMT("{}:53", AG_UNFILTERED_DNS_IPS_V4[0]).c_str());
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
    if (!this->deferred_resolve_task.has_value()) {
        this->deferred_resolve_task = event_loop::submit(this->vpn->parameters.ev_loop,
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *self = (VpnDnsResolver *) arg;
                                    self->deferred_resolve_task.release();
                                    self->resolve_pending_domains();
                                },
                });
    }
    return id;
}

void VpnDnsResolver::cancel(VpnDnsResolveId id) {
    for (Queue &q : this->queues) {
        if (q.erase(id) != 0) {
            return;
        }
    }
    auto on_the_wire_it = std::find_if(this->state.queries.begin(), this->state.queries.end(), [id](const auto &i) {
        return i.second.id == id;
    });
    if (on_the_wire_it != this->state.queries.end()) {
        this->state.queries.erase(on_the_wire_it);
    }
}

void VpnDnsResolver::stop_resolving_queues(QueueTypeSet stopping_queues) {
    for (VpnDnsResolverQueue q : magic_enum::enum_values<VpnDnsResolverQueue>()) {
        if (!stopping_queues.test(q)) {
            continue;
        }

        for (auto &[entry_id, entry] : std::exchange(this->queues[q], {})) {
            for (size_t i = 0; i < entry.record_types.size(); ++i) {
                if (entry.record_types.test(i)) {
                    raise_result(entry.handler, entry_id, VpnDnsResolverFailure{dns_utils::RecordType(i)});
                }
            }
        }
    }

    std::vector<ResolveState::Query> cancelled_queries;
    cancelled_queries.reserve(this->state.queries.size());
    for (auto it = this->state.queries.begin(); it != this->state.queries.end();) {
        if (stopping_queues.test(it->second.queue_kind)) {
            cancelled_queries.emplace_back(std::move(it->second));
            it = this->state.queries.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto &q : cancelled_queries) {
        raise_result(q.result_handler, q.id, VpnDnsResolverFailure{q.record_type});
    }
}

void VpnDnsResolver::stop_resolving() {
    this->stop_resolving_queues(QueueTypeSet{}.set());
    if (this->state.connection_id != NON_ID) {
        this->close_connection(this->state.connection_id, false, false);
    }
    this->deinit();
}

void VpnDnsResolver::deinit() {
    this->queues = {};
    this->state = ResolveState{};
    this->accepting_connections.clear();
    this->deferred_accept_task.reset();
    this->closing_connections.clear();
    this->deferred_close_task.reset();
    this->deferred_resolve_task.reset();
}

void VpnDnsResolver::complete_connect_request(uint64_t id, ClientConnectResult result) {
    if (result != CCR_PASS) {
        log_conn(this, id, dbg, "Failed to make connection: {}", magic_enum::enum_name(result));
        this->close_connection(id, false, true);
        return;
    }

    this->accepting_connections.push_back(id);
    if (!this->deferred_accept_task.has_value()) {
        this->deferred_accept_task = event_loop::submit(this->vpn->parameters.ev_loop,
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *self = (VpnDnsResolver *) arg;
                                    self->deferred_accept_task.release();
                                    std::vector<uint64_t> connections;
                                    connections.swap(self->accepting_connections);
                                    for (uint64_t id : connections) {
                                        self->accept_pending_connection(id);
                                    }
                                },
                });
    }
}

void VpnDnsResolver::accept_pending_connection(uint64_t id) {
    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &id);

    if (this->state.is_open) {
        log_conn(this, this->state.connection_id, dbg, "Resolving connection is already open");
        this->close_connection(id, false, false);
        assert(0);
        return;
    }

    if (this->state.connection_id != id) {
        log_conn(this, this->state.connection_id, dbg, "Unexpected resolving connection ID: {}", this->state.connection_id,
                id);
        this->close_connection(id, false, false);
        assert(0);
        return;
    }

    this->state.is_open = true;
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
            this->deferred_close_task = event_loop::submit(this->vpn->parameters.ev_loop,
                    {
                            .arg = this,
                            .action =
                                    [](void *arg, TaskId) {
                                        auto *self = (VpnDnsResolver *) arg;
                                        self->deferred_close_task.release();
                                        std::vector<uint64_t> connections;
                                        connections.swap(self->closing_connections);
                                        for (uint64_t id : connections) {
                                            self->close_connection(id, true, false);
                                        }
                                    },
                    });
        }
        return;
    }

    if (auto it = std::find(this->closing_connections.begin(), this->closing_connections.end(), id);
            it != this->closing_connections.end()) {
        this->closing_connections.erase(it);
    }

    log_resolver(this, dbg, "Resolve connection has been closed");

    for (auto &[_, q] : std::exchange(this->state.queries, {})) {
        raise_result(q.result_handler, q.id, VpnDnsResolverFailure{q.record_type});
    }

    for (const Queue &queue : std::exchange(this->queues, {})) {
        for (auto &[entry_id, entry] : queue) {
            for (size_t i = 0; i < entry.record_types.size(); ++i) {
                if (entry.record_types.test(i)) {
                    raise_result(entry.handler, entry_id, VpnDnsResolverFailure{dns_utils::RecordType(i)});
                }
            }
        }
    }

    this->state = ResolveState{};
    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
}

ssize_t VpnDnsResolver::send(uint64_t id, const uint8_t *data, size_t length) {
    log_conn(this, id, dbg, "{}", length);

    dns_utils::DecodeResult r = dns_utils::decode_packet({data, length});
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_conn(this, id, dbg, "Failed to parse reply: {}", e->description);
        return -1;
    }

    if (this->state.connection_id != id) {
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

    if (auto it = this->state.queries.find(reply_id); it != this->state.queries.end()) {
        if (auto *failure = std::get_if<VpnDnsResolverFailure>(&result); failure != nullptr) {
            failure->record_type = it->second.record_type;
        }

        ResolveState::Query q = it->second;
        this->state.queries.erase(it);
        raise_result(q.result_handler, q.id, result);
    }

    this->resolve_pending_domains();

    return (ssize_t) length;
}

void VpnDnsResolver::consume(uint64_t, size_t) {
}

TcpFlowCtrlInfo VpnDnsResolver::flow_control_info(uint64_t id) {
    return (this->state.connection_id == id) ? TcpFlowCtrlInfo{UDP_MAX_DATAGRAM_SIZE, UDP_MAX_DATAGRAM_SIZE}
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
    if (std::all_of(this->queues.begin(), this->queues.end(), [](const Queue &q) {
            return q.empty();
        })) {
        // nothing to do
        return;
    }

    this->state.timeout_task = event_loop::schedule(
            this->vpn->parameters.ev_loop, {this, on_resolve_timeout}, this->vpn->upstream_config.timeout);

    if (!this->state.is_open) {
        this->state.connection_id = this->vpn->listener_conn_id_generator.get();
        sockaddr_storage src = this->make_source_address();
        TunnelAddress dst = RESOLVER_ADDRESS;
        ClientConnectRequest event = {
                this->state.connection_id,
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
    Queue &queue = this->queues[queue_type];

    while (this->state.queries.size() < RESOLVE_CAPACITIES[queue_type] && !queue.empty()) {
        auto [entry_id, entry] = std::move(*queue.begin());
        queue.erase(queue.begin());

        auto ids = this->send_request(this->state.connection_id, entry.name, entry.record_types);
        static_assert(ids.size() == decltype(entry.record_types){}.size());
        for (size_t i = 0; i < ids.size(); ++i) {
            const auto &id = ids[i];
            if (id.has_value()) {
                this->state.queries.emplace(id.value(),
                        ResolveState::Query{
                                .id = entry_id,
                                .record_type = dns_utils::RecordType(i),
                                .result_handler = entry.handler,
                                .queue_kind = queue_type,
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

void VpnDnsResolver::on_resolve_timeout(void *arg, TaskId) {
    auto *self = (VpnDnsResolver *) arg;
    log_resolver(self, dbg, "...");
    self->state.timeout_task.release();
    self->close_connection(self->state.connection_id, true, false);
}

} // namespace ag
