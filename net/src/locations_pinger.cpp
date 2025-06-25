#include "net/locations_pinger.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <list>
#include <memory>
#include <unordered_map>
#include <utility>
#include <vector>

#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "net/network_manager.h"
#include "net/quic_connector.h"
#include "net/tcp_socket.h"
#include "net/utils.h"
#include "ping.h"
#include "vpn/utils.h"

#define log_location(pinger_, id_, lvl_, fmt_, ...) lvl_##log((pinger_)->logger, "[{}] " fmt_, (id_), ##__VA_ARGS__)

namespace ag {

struct PingedEndpoint {
    AutoVpnEndpoint endpoint;
    int ping_ms = 0;
    sockaddr_storage relay_address{};
    bool is_quic = false;
    void *conn_state = nullptr;

    PingedEndpoint(AutoVpnEndpoint endpoint, int ping_ms, const sockaddr *relay_address, bool is_quic, void *conn_state)
            : endpoint{std::move(endpoint)}
            , ping_ms{ping_ms}
            , is_quic{is_quic}
            , conn_state{conn_state} {
        if (relay_address) {
            this->relay_address = sockaddr_to_storage(relay_address);
        }
    }
};

struct LocationsCtx {
    explicit LocationsCtx(AutoVpnLocation i)
            : info(std::move(i)) {
    }

    LocationsCtx(LocationsCtx &&other) noexcept = default;
    LocationsCtx &operator=(LocationsCtx &&other) noexcept = default;

    LocationsCtx(const LocationsCtx &) = delete;
    LocationsCtx &operator=(const LocationsCtx &) = delete;

    ~LocationsCtx() = default;

    AutoVpnLocation info;
    std::vector<PingedEndpoint> pinged_ipv6;
    std::vector<PingedEndpoint> pinged_ipv4;
    size_t ipv4_unavailable_errors_cnt = 0;
    size_t ipv6_unavailable_errors_cnt = 0;
};

struct LocationsPinger {
    LocationsPingerHandler handler = {};
    std::list<LocationsCtx> pending_locations;
    std::unordered_map<Ping *, LocationsCtx> locations;
    VpnEventLoop *loop;
    VpnNetworkManager *network_manager;
    ag::Logger logger{"LOCATIONS_PINGER"};
    bool query_all_interfaces;
    std::vector<uint32_t> interfaces;
    event_loop::AutoTaskId task_id;
    uint32_t timeout_ms;
    uint32_t rounds;
    bool use_quic;
    bool anti_dpi;
    bool handoff;
    sockaddr_storage relay_address_parallel{};
    uint32_t quic_max_idle_timeout_ms;
    uint32_t quic_version;
};

struct FinalizeLocationInfo {
    LocationsCtx location_ctx;
    bool is_last_location = false;
};

typedef size_t (*PingerSort)(const LocationsCtx *location, const sockaddr *a, int ping_ms);

static size_t get_addr_priority(const LocationsCtx *location, const sockaddr *a, int /*ping_ms*/) {
    auto *i = std::find_if(location->info->endpoints.data,
            location->info->endpoints.data + location->info->endpoints.size, [a](const VpnEndpoint &i) -> bool {
                return sockaddr_equals(a, (sockaddr *) &i.address);
            });
    return location->info->endpoints.size - std::distance(location->info->endpoints.data, i);
}

static size_t get_smallest_ping_priority(const LocationsCtx *, const sockaddr *, int ping_ms) {
    return -(ping_ms + 1);
}

static const PingedEndpoint *select_endpoint_from_list(
        const LocationsCtx *location, const std::vector<PingedEndpoint> &addresses, PingerSort priority_func) {
    const PingedEndpoint *selected = nullptr;
    size_t selected_priority = 0;

    for (const PingedEndpoint &i : addresses) {
        size_t i_priority = priority_func(location, (sockaddr *) &i.endpoint->address, i.ping_ms);
        if (selected == nullptr || selected_priority < i_priority) {
            selected = &i;
            selected_priority = i_priority;
        }
    }

    return selected;
}

static const PingedEndpoint *select_endpoint(const LocationsCtx *location, PingerSort sorter) {
    const PingedEndpoint *selected = select_endpoint_from_list(location, location->pinged_ipv6, sorter);
    if (selected == nullptr) {
        selected = select_endpoint_from_list(location, location->pinged_ipv4, sorter);
    }

    return selected;
}

static constexpr size_t count_of_ip_version(const VpnEndpoints &endpoints, IpVersion v) {
    int family = ip_version_to_sa_family(v);
    return std::count_if(endpoints.data, endpoints.data + endpoints.size, [family](const VpnEndpoint &e) {
        return e.address.ss_family == family;
    });
}

static void destroy_conn_state(PingedEndpoint &endpoint) {
    if (endpoint.is_quic) {
        quic_connector_destroy((QuicConnector *) endpoint.conn_state);
    } else {
        tcp_socket_destroy((TcpSocket *) endpoint.conn_state);
    }
    endpoint.conn_state = nullptr;
}

static void finalize_location(LocationsPinger *pinger, FinalizeLocationInfo info) {
    const LocationsCtx *location = &info.location_ctx;
    const PingedEndpoint *selected =
            select_endpoint(location, pinger->query_all_interfaces ? &get_smallest_ping_priority : &get_addr_priority);

    for (auto *v : {&info.location_ctx.pinged_ipv4, &info.location_ctx.pinged_ipv6}) {
        for (PingedEndpoint &endpoint : *v) {
            if (std::addressof(endpoint) != selected) {
                destroy_conn_state(endpoint);
            }
        }
    }

    LocationsPingerResultExtra result = {
            .ip_availability =
                    [&] {
                        IpVersionSet ret;
                        size_t ipv4_num = count_of_ip_version(location->info->endpoints, IPV4);
                        ret.set(IPV4, ipv4_num == 0 || location->ipv4_unavailable_errors_cnt != ipv4_num);
                        size_t ipv6_num = count_of_ip_version(location->info->endpoints, IPV6);
                        ret.set(IPV6, ipv6_num == 0 || location->ipv6_unavailable_errors_cnt != ipv6_num);
                        return ret;
                    }(),
    };
    result.id = location->info->id;
    if (selected != nullptr) {
        result.is_quic = selected->is_quic;
        result.conn_state = selected->conn_state;
        result.ping_ms = selected->ping_ms;
        for (size_t i = 0; i < location->info->endpoints.size; ++i) {
            VpnEndpoint *ep = &location->info->endpoints.data[i];
            if (vpn_endpoint_equals(ep, selected->endpoint.get())) {
                result.endpoint = ep;
                break;
            }
        }
        assert(result.endpoint != nullptr);
        if (selected->relay_address.ss_family) {
            result.relay_address = (sockaddr *) &selected->relay_address;
        }
        log_location(pinger, location->info->id, dbg, "Selected endpoint: {} ({}){}{} ({} ms)", result.endpoint->name,
                sockaddr_to_str((sockaddr *) &result.endpoint->address), result.relay_address ? " through relay " : "",
                result.relay_address ? sockaddr_to_str(result.relay_address) : "", result.ping_ms);
    } else {
        log_location(pinger, location->info->id, dbg, "None of the endpoints has been pinged successfully");
        result.ping_ms = -1;
    }

    LocationsPingerHandler handler = pinger->handler;
    handler.func(handler.arg, &result);
    if (info.is_last_location) {
        handler.func(handler.arg, nullptr);
    }
}

static std::optional<FinalizeLocationInfo> process_ping_result(LocationsPinger *pinger, const PingResult *result) {
    auto i = pinger->locations.find(result->ping);
    if (i == pinger->locations.end()) {
        return std::nullopt;
    }

    LocationsCtx *l = &i->second;

    switch (result->status) {
    case PING_OK: {
        std::vector<PingedEndpoint> &dst =
                (result->endpoint->address.ss_family == AF_INET6) ? l->pinged_ipv6 : l->pinged_ipv4;
        // This might not be the first result for this address
        auto it = std::find_if(dst.begin(), dst.end(), [&](const PingedEndpoint &a) {
            return vpn_endpoint_equals(a.endpoint.get(), result->endpoint);
        });
        if (it == dst.end()) { // Add new result
            dst.emplace_back(vpn_endpoint_clone(result->endpoint), result->ms, result->relay_address, result->is_quic,
                    result->conn_state);
        } else {
            if (!pinger->query_all_interfaces) {
                log_location(pinger, ping_get_id(result->ping), warn,
                        "Duplicate result for address {}. Please check that location doesn't contain duplicate IPs.",
                        sockaddr_to_str((sockaddr *) &result->endpoint->address));
            }
            it->ping_ms = std::min(result->ms, it->ping_ms);
            destroy_conn_state(*it);
            it->is_quic = result->is_quic;
            it->conn_state = result->conn_state;
        }
        break;
    }
    case PING_FINISHED: {
        auto node = pinger->locations.extract(i);
        ping_destroy(node.key());
        return {{std::move(node.mapped()), pinger->locations.empty() && pinger->pending_locations.empty()}};
    }
    case PING_SOCKET_ERROR:
        if (result->socket_error == AG_EHOSTUNREACH || result->socket_error == AG_ENETUNREACH) {
            if (result->endpoint->address.ss_family == AF_INET) {
                l->ipv4_unavailable_errors_cnt += 1;
            } else {
                l->ipv6_unavailable_errors_cnt += 1;
            }
        }
        [[fallthrough]];
    case PING_TIMEDOUT:
        log_location(pinger, ping_get_id(result->ping), dbg, "Failed to ping endpoint {} ({}) - error code {}",
                result->endpoint->name, sockaddr_to_str((sockaddr *) &result->endpoint->address),
                magic_enum::enum_name(result->status));
        break;
    }

    return std::nullopt;
}

static void ping_handler(void *arg, const PingResult *result) {
    auto *pinger = (LocationsPinger *) arg;

    if (auto finalize_info = process_ping_result(pinger, result); finalize_info.has_value()) {
        finalize_location(pinger, std::move(finalize_info.value()));
    }
}

// Force libevent to poll/select between starting pings. Starting many connections in one flight
// takes a large amount of time on some systems and stalls the event loop.
static void start_location_ping(LocationsPinger *pinger) {
    assert(!pinger->pending_locations.empty());
    auto i = pinger->pending_locations.begin();

    log_location(pinger, i->info->id, dbg, "Starting location ping");
    PingInfo ping_info = {i->info->id, pinger->loop, pinger->network_manager, {i->info->endpoints.data, i->info->endpoints.size},
            pinger->timeout_ms, {pinger->interfaces.data(), pinger->interfaces.size()}, pinger->rounds,
            pinger->use_quic, pinger->anti_dpi, pinger->handoff,
            {i->info->relay_addresses.data, i->info->relay_addresses.size}, pinger->relay_address_parallel,
            pinger->quic_max_idle_timeout_ms, pinger->quic_version};
    Ping *ping = ping_start(&ping_info, {ping_handler, pinger});
    if (!ping) {
        FinalizeLocationInfo info{std::move(*i), pinger->pending_locations.size() == 1 && pinger->locations.empty()};
        finalize_location(pinger, std::move(info));
    } else {
        pinger->locations.emplace(ping, std::move(*i));
    }
    pinger->pending_locations.pop_front();

    if (!pinger->pending_locations.empty()) {
        pinger->task_id = event_loop::schedule(pinger->loop,
                {
                        .arg = pinger,
                        .action =
                                [](void *arg, TaskId) {
                                    start_location_ping((LocationsPinger *) arg);
                                },
                },
                Millis{1} /*ms (force libevent to poll/select*/);
    }
}

LocationsPinger *locations_pinger_start(
        const LocationsPingerInfo *info, LocationsPingerHandler handler, VpnEventLoop *ev_loop, VpnNetworkManager *network_manager) {
    auto *pinger = new LocationsPinger{};

    pinger->handler = handler;
    pinger->locations.reserve(info->locations.size);
    pinger->loop = ev_loop;
    pinger->network_manager = network_manager;
#ifdef __MACH__
    pinger->query_all_interfaces = info->query_all_interfaces;
    if (info->query_all_interfaces) {
        pinger->interfaces = collect_operable_network_interfaces();
    } else
#endif
    {
        pinger->interfaces.push_back(vpn_network_manager_get_outbound_interface());
    }

    pinger->timeout_ms = info->timeout_ms;
    pinger->rounds = info->rounds;
    pinger->use_quic = info->use_quic;
    pinger->anti_dpi = info->anti_dpi;
    pinger->handoff = info->handoff;
    pinger->quic_max_idle_timeout_ms = info->quic_max_idle_timeout_ms;
    pinger->quic_version = info->quic_version;
    if (info->relay_address_parallel) {
        pinger->relay_address_parallel = sockaddr_to_storage(info->relay_address_parallel);
    }

    for (size_t i = 0; i < info->locations.size; ++i) {
        const VpnLocation *l = &info->locations.data[i];
        pinger->pending_locations.emplace_back(vpn_location_clone(l));
    }

    if (!pinger->pending_locations.empty()) {
        pinger->task_id = event_loop::schedule(pinger->loop,
                {
                        .arg = pinger,
                        .action =
                                [](void *arg, TaskId) {
                                    start_location_ping((LocationsPinger *) arg);
                                },
                },
                Millis{1} /*ms (force libevent to poll/select*/);
    } else {
        pinger->task_id = event_loop::submit(pinger->loop,
                {
                        .arg = pinger,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *pinger = (LocationsPinger *) arg;
                                    LocationsPingerHandler handler = pinger->handler;
                                    handler.func(handler.arg, nullptr);
                                },
                });
    }

    return pinger;
}

void locations_pinger_stop(LocationsPinger *pinger) {
    for (auto &i : pinger->locations) {
        ping_destroy(i.first);
    }
    pinger->locations.clear();
    pinger->pending_locations.clear();
    pinger->task_id.reset();
}

void locations_pinger_destroy(LocationsPinger *pinger) {
    locations_pinger_stop(pinger);
    delete pinger;
}

} // namespace ag
