#include <algorithm>
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
static const TunnelAddress FALLBACK_RESOLVER_ADDRESS =
        sockaddr_from_str(AG_FMT("{}:53", AG_UNFILTERED_DNS_IPS_V4[0]).c_str());
static constexpr size_t RESOLVE_CAPACITIES[magic_enum::enum_count<VpnDnsResolverQueue>()] = {
        /** VDRQ_BACKGROUND */ VpnDnsResolver::MAX_PARALLEL_BACKGROUND_RESOLVES,
        /** VDRQ_FOREGROUND */ std::numeric_limits<size_t>::max(),
};

VpnDnsResolver::VpnDnsResolver()
        : m_resolver_address(FALLBACK_RESOLVER_ADDRESS) {
}

std::optional<VpnDnsResolveId> VpnDnsResolver::resolve(
        VpnDnsResolverQueue queue, std::string name, RecordTypeSet record_types, ResultHandler result_handler) {
    log_resolver(this, trace, "{}", name);
    VpnDnsResolveId id = this->next_id++;
    this->resolutions.emplace(id, Resolve{std::move(name), record_types, result_handler});
    this->queues[queue].insert(id);
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

std::optional<VpnDnsResolveId> VpnDnsResolver::lookup_resolve_id(uint16_t query_id, std::string_view name) const {
    auto iter = this->state.queries.find(query_id);
    if (iter == this->state.queries.end()) {
        log_resolver(this, dbg, "Not found: query={}", query_id);
        return std::nullopt;
    }

    const ResolveState::Query &query = iter->second;
    if (query.name != name) {
        log_resolver(this, dbg, "Unexpected name: query={}, name={}, expected={}", query_id, query.name, name);
        return std::nullopt;
    }

    return query.id;
}

void VpnDnsResolver::cancel(VpnDnsResolveId id) {
    auto node = this->resolutions.extract(id);
    if (!node.empty()) {
        for (std::optional q : node.mapped().queries) {
            if (q.has_value()) {
                this->state.queries.erase(q.value());
            }
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

        for (VpnDnsResolveId entry_id : std::exchange(this->queues[q], {})) {
            auto node = this->resolutions.extract(entry_id);
            if (!node.empty()) {
                raise_result(node.mapped().handler, entry_id, VpnDnsResolverFailure{});
                for (std::optional query : node.mapped().queries) {
                    if (query.has_value()) {
                        this->state.queries.erase(query.value());
                    }
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
        auto node = this->resolutions.extract(q.id);
        if (!node.empty()) {
            raise_result(node.mapped().handler, q.id, VpnDnsResolverFailure{});
        }
    }
}

void VpnDnsResolver::stop_resolving() {
    this->stop_resolving_queues(QueueTypeSet{}.set());
    if (this->state.connection_id != NON_ID) {
        this->close_connection(this->state.connection_id, false, false);
    }
    this->deinit();
}

ClientListener::InitResult VpnDnsResolver::init(VpnClient *vpn, ClientHandler handler) {
    if (ClientListener::InitResult x = ClientListener::init(vpn, handler); x != ClientListener::InitResult::SUCCESS) {
        return x;
    }

    on_dns_updated(this);

    m_dns_change_subscription_id = dns_manager_subscribe_servers_change(
            vpn->parameters.network_manager->dns, vpn->parameters.ev_loop, on_dns_updated, this);
    if (!m_dns_change_subscription_id.has_value()) {
        log_resolver(this, warn, "Failed to subscribe to DNS servers updates");
        this->deinit();
        return ClientListener::InitResult::FAILURE;
    }

    return ClientListener::InitResult::SUCCESS;
}

void VpnDnsResolver::deinit() {
    if (std::optional dns_change_id = std::exchange(m_dns_change_subscription_id, std::nullopt);
            dns_change_id.has_value()) {
        dns_manager_unsubscribe_servers_change(this->vpn->parameters.network_manager->dns, dns_change_id.value());
    }

    this->queues = {};
    this->state = ResolveState{};
    this->deferred_accept_task.reset();
    this->deferred_close_task.reset();
    this->deferred_resolve_task.reset();
}

void VpnDnsResolver::set_query_timeout(Millis v) {
    g_query_timeout = v;
}

void VpnDnsResolver::complete_connect_request(uint64_t id, ClientConnectResult result) {
    if (id != this->state.connection_id) {
        log_conn(this, id, warn, "Unexpected connection ID: {} (expected={})", id, this->state.connection_id);
        return;
    }

    if (result != CCR_PASS) {
        log_conn(this, id, dbg, "Failed to make connection: {}", magic_enum::enum_name(result));
        this->close_connection(id, false, true);
        return;
    }

    if (!this->deferred_accept_task.has_value()) {
        this->deferred_accept_task = event_loop::submit(this->vpn->parameters.ev_loop,
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *self = (VpnDnsResolver *) arg;
                                    self->deferred_accept_task.release();
                                    self->accept_connection();
                                },
                });
    }
}

void VpnDnsResolver::accept_connection() {
    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, &this->state.connection_id);
    this->resolve_pending_domains();
}

void VpnDnsResolver::close_connection(uint64_t id, bool graceful, bool async) {
    if (id != this->state.connection_id) {
        log_conn(this, id, warn, "Unexpected connection ID: {} (expected={})", id, this->state.connection_id);
        return;
    }

    if (async) {
        if (!this->deferred_close_task.has_value()) {
            this->deferred_close_task = event_loop::submit(this->vpn->parameters.ev_loop,
                    {
                            .arg = this,
                            .action =
                                    [](void *arg, TaskId) {
                                        auto *self = (VpnDnsResolver *) arg;
                                        self->deferred_close_task.release();
                                        self->close_connection(self->state.connection_id, true, false);
                                    },
                    });
        }
        return;
    }

    log_resolver(this, dbg, "Resolve connection has been closed");

    for (auto &[rid, r] : std::exchange(this->resolutions, {})) {
        VpnDnsResolverResult result = VpnDnsResolverFailure{};
        if (!r.resolved_addresses.empty()) {
            result = VpnDnsResolverSuccess{
                    .addresses = std::move(r.resolved_addresses),
            };
        }
        raise_result(r.handler, rid, std::move(result));
    }

    this->queues = {};
    this->state = ResolveState{};
    this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
}

ssize_t VpnDnsResolver::send(uint64_t id, const uint8_t *data, size_t length) {
    log_conn(this, id, dbg, "{}", length);

    this->state.connection_timeout_task = event_loop::schedule(
            this->vpn->parameters.ev_loop, {this, on_connection_timeout}, this->vpn->upstream_config.timeout);

    dns_utils::DecodeResult r = dns_utils::decode_packet({data, length});
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_conn(this, id, dbg, "Failed to parse reply: {}", e->description);
        return -1;
    }

    if (this->state.connection_id != id) {
        log_conn(this, id, dbg, "Wrong connection ID");
        return -1;
    }

    std::vector<sockaddr_storage> resolved_addresses;
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
        resolved_addresses.reserve(reply.addresses.size());
        std::transform(reply.addresses.begin(), reply.addresses.end(), std::back_inserter(resolved_addresses),
                [](const dns_utils::AnswerAddress &a) {
                    return sockaddr_from_raw(a.ip.data(), a.ip.size(), 0);
                });
        // @note: resolved addresses are passed to filter via the DNS sniffer in the tunnel
    }

    auto query_node = this->state.queries.extract(reply_id);
    if (query_node.empty()) {
        log_conn(this, id, dbg, "Query not found: id={}", reply_id);
        return ssize_t(length);
    }

    const ResolveState::Query &query = query_node.mapped();
    auto res_it = this->resolutions.find(query.id);
    if (res_it == this->resolutions.end()) {
        log_conn(this, id, dbg, "Resolution entry not found: query id={}, resolution id={}, name={}", reply_id,
                query.id, query.name);
        return ssize_t(length);
    }

    bool done;
    {
        Resolve &res = res_it->second;
        res.record_types.reset(query.record_type);
        res.resolved_addresses.insert(
                res.resolved_addresses.end(), resolved_addresses.begin(), resolved_addresses.end());
        done = res.record_types.none();
    }
    if (done) {
        auto res_node = this->resolutions.extract(res_it);
        VpnDnsResolverResult result = VpnDnsResolverFailure{};
        if (!res_node.mapped().resolved_addresses.empty()) {
            result = VpnDnsResolverSuccess{
                    .addresses = std::move(res_node.mapped().resolved_addresses),
            };
        }
        raise_result(res_node.mapped().handler, query.id, std::move(result));
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
        dns_utils::RecordType record_type, std::string_view name) const {
    dns_utils::EncodeResult r = dns_utils::encode_request({record_type, name});
    if (const auto *e = std::get_if<dns_utils::Error>(&r); e != nullptr) {
        log_resolver(this, dbg, "Failed to encode packet: {}", e->description);
        return std::nullopt;
    }

    auto &req = std::get<dns_utils::EncodedRequest>(r);
    return {{req.id, std::move(req.data)}};
}

void VpnDnsResolver::resolve_pending_domains() {
    if (std::all_of(this->queues.begin(), this->queues.end(), [](const Queue &q) {
            return q.empty();
        })) {
        // nothing to do
        return;
    }

    if (this->state.connection_id == NON_ID) {
        this->state.connection_id = this->vpn->listener_conn_id_generator.get();
        sockaddr_storage src = this->make_source_address();
        ClientConnectRequest event = {
                this->state.connection_id,
                IPPROTO_UDP,
                (sockaddr *) &src,
                &m_resolver_address,
                CUSTOM_APP_NAME,
        };
        this->handler.func(this->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);
    } else {
        for (VpnDnsResolverQueue q : magic_enum::enum_values<VpnDnsResolverQueue>()) {
            this->resolve_queue(q);
        }
    }

    this->state.connection_timeout_task = event_loop::schedule(
            this->vpn->parameters.ev_loop, {this, on_connection_timeout}, this->vpn->upstream_config.timeout);
    if (!this->state.periodic_queries_check_task.has_value()) {
        this->state.periodic_queries_check_task =
                event_loop::schedule(this->vpn->parameters.ev_loop, {this, on_periodic_queries_check}, g_query_timeout);
    }
}

void VpnDnsResolver::resolve_queue(VpnDnsResolverQueue queue_type) {
    Queue &queue = this->queues[queue_type];

    while (this->state.queries.size() < RESOLVE_CAPACITIES[queue_type] && !queue.empty()) {
        VpnDnsResolveId entry_id = queue.extract(queue.begin()).value();

        auto res_it = this->resolutions.find(entry_id);
        if (res_it == this->resolutions.end()) {
            log_resolver(this, dbg, "Resolution entry not found: id={}", entry_id);
            continue;
        }

        SteadyClock::time_point now = SteadyClock::now();
        Resolve &entry = res_it->second;
        for (dns_utils::RecordType record_type : magic_enum::enum_values<dns_utils::RecordType>()) {
            if (!entry.record_types.test(record_type)) {
                continue;
            }

            auto req = this->make_request(record_type, entry.name);
            if (!req.has_value()) {
                continue;
            }

            auto &[query_id, data] = req.value();
            auto query_it = this->state.queries
                                    .emplace(query_id,
                                            ResolveState::Query{
                                                    .id = entry_id,
                                                    .record_type = record_type,
                                                    .name = entry.name,
                                                    .queue_kind = queue_type,
                                            })
                                    .first;

            ClientRead event = {this->state.connection_id, data.data(), data.size()};
            this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
            if (event.result != (int) data.size()) {
                log_conn(this, this->state.connection_id, dbg, "Failed to send request: {}", event.result);
                this->state.queries.erase(query_it);
                continue;
            }

            entry.record_types.set(record_type);
            entry.queries[record_type] = query_id;

            this->state.deadlines.emplace(now, query_id);

            log_resolver(this, dbg,
                    "Sent query for resolution: query id={}, resolution id={}, name={}, rtype={}, queue={}", query_id,
                    entry_id, entry.name, magic_enum::enum_name(record_type), magic_enum::enum_name(queue_type));
        }
        if (entry.record_types.none()) {
            ResultHandler handler = this->resolutions.extract(res_it).mapped().handler;
            raise_result(handler, entry_id, VpnDnsResolverFailure{});
            continue;
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

void VpnDnsResolver::on_connection_timeout(void *arg, TaskId) {
    auto *self = (VpnDnsResolver *) arg;
    log_resolver(self, dbg, "...");
    self->state.connection_timeout_task.release();
    self->close_connection(self->state.connection_id, true, false);
}

void VpnDnsResolver::on_periodic_queries_check(void *arg, TaskId) {
    auto *self = (VpnDnsResolver *) arg;
    log_resolver(self, dbg, "...");

    self->state.periodic_queries_check_task.release();

    SteadyClock::time_point now = SteadyClock::now();
    auto first_nonexpired = self->state.deadlines.upper_bound(now);
    for (auto it = self->state.deadlines.begin(); it != first_nonexpired; ++it) {
        auto node = self->state.queries.extract(it->second);
        log_resolver(self, dbg, "Query expired: id={}", it->second);
        if (node.empty()) {
            continue;
        }

        ResolveState::Query &query = node.mapped();
        auto res_it = self->resolutions.find(query.id);
        if (res_it == self->resolutions.end()) {
            log_resolver(self, dbg, "Resolution entry not found: resolution id={}, query id={}", query.id, it->second);
            continue;
        }

        bool done;
        {
            Resolve &res = res_it->second;
            res.record_types.reset(query.record_type);
            done = res.record_types.none();
        }
        if (done) {
            auto res_node = self->resolutions.extract(res_it);
            VpnDnsResolverResult result = VpnDnsResolverFailure{};
            if (!res_node.mapped().resolved_addresses.empty()) {
                result = VpnDnsResolverSuccess{
                        .addresses = std::move(res_node.mapped().resolved_addresses),
                };
            }
            raise_result(res_node.mapped().handler, query.id, std::move(result));
        }
    }

    self->state.deadlines.erase(self->state.deadlines.begin(), first_nonexpired);
    self->resolve_pending_domains();
}

void VpnDnsResolver::on_dns_updated(void *arg) {
    auto *self = (VpnDnsResolver *) arg;

    static constexpr auto server_address_from_str = [](std::string_view str) {
        auto [host, port] = utils::split_host_port(str).value();
        return sockaddr_to_storage(
                SocketAddress(host, utils::to_integer<uint16_t>(port).value_or(dns_utils::PLAIN_DNS_PORT_NUMBER))
                        .c_sockaddr());
    };

    std::optional<sockaddr_storage> selected_address;

    SystemDnsServers servers = dns_manager_get_system_servers(self->vpn->parameters.network_manager->dns);
    for (const SystemDnsServer &x : servers.main) {
        sockaddr_storage address = server_address_from_str(x.address);
        if (address.ss_family == AF_UNSPEC) {
            continue;
        }
        selected_address = address;
        break;
    }

    if (selected_address.has_value()) {
        self->m_resolver_address = selected_address.value();
        log_resolver(self, dbg, "Chosen resolver from main system servers: {}",
                tunnel_addr_to_str(&self->m_resolver_address));
        return;
    }

    for (std::string_view x : servers.fallback) {
        sockaddr_storage address = server_address_from_str(x);
        if (address.ss_family == AF_UNSPEC) {
            continue;
        }
        selected_address = address;
        break;
    }

    if (selected_address.has_value()) {
        self->m_resolver_address = selected_address.value();
        log_resolver(self, dbg, "Chosen resolver from fallback system servers: {}",
                tunnel_addr_to_str(&self->m_resolver_address));
    } else {
        self->m_resolver_address = FALLBACK_RESOLVER_ADDRESS;
        log_resolver(self, dbg, "Couldn't choose resolver from system servers, using fallback: {}",
                tunnel_addr_to_str(&self->m_resolver_address));
    }
}

} // namespace ag
