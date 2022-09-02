#include "net/locations_pinger.h"

#include <algorithm>
#include <cassert>
#include <iterator>
#include <list>
#include <unordered_map>
#include <vector>

#include <magic_enum.hpp>

#include "common/logger.h"
#include "ping.h"
#include "vpn/utils.h"

#define log_location(pinger_, id_, lvl_, fmt_, ...) lvl_##log((pinger_)->logger, "[{}] " fmt_, (id_), ##__VA_ARGS__)

namespace ag {

struct PingedAddress {
    int ping_ms = 0;
    sockaddr_storage addr = {};
};

struct LocationsCtx {
    explicit LocationsCtx(const VpnLocation &i) {
        vpn_location_clone(&this->info, &i);
    }

    LocationsCtx(LocationsCtx &&other) noexcept {
        *this = std::move(other);
    }

    LocationsCtx &operator=(LocationsCtx &&other) noexcept {
        std::swap(this->info, other.info);
        this->pinged_ipv6 = std::move(other.pinged_ipv6);
        this->pinged_ipv4 = std::move(other.pinged_ipv4);
        return *this;
    }

    LocationsCtx(const LocationsCtx &) = delete;
    LocationsCtx &operator=(const LocationsCtx &) = delete;

    ~LocationsCtx() {
        vpn_location_destroy(&this->info);
    }

    VpnLocation info = {};
    std::vector<PingedAddress> pinged_ipv6;
    std::vector<PingedAddress> pinged_ipv4;
};

struct LocationsPinger {
    LocationsPingerHandler handler = {};
    std::list<LocationsCtx> pending_locations;
    std::unordered_map<Ping *, LocationsCtx> locations;
    VpnEventLoop *loop;
    ag::Logger logger{"LOCATIONS_PINGER"};
    bool query_all_interfaces;
    event_loop::AutoTaskId task_id;
    uint32_t timeout_ms;
    uint32_t rounds;
};

struct FinalizeLocationInfo {
    LocationsCtx location_ctx;
    bool is_last_location = false;
};

typedef size_t (*PingerSort)(const LocationsCtx *location, const sockaddr *a, int ping_ms);

static size_t get_addr_priority(const LocationsCtx *location, const sockaddr *a, int /*ping_ms*/) {
    auto *i = std::find_if(location->info.endpoints.data, location->info.endpoints.data + location->info.endpoints.size,
            [a](const VpnEndpoint &i) -> bool {
                return sockaddr_equals(a, (sockaddr *) &i.address);
            });
    return location->info.endpoints.size - std::distance(location->info.endpoints.data, i);
}

static size_t get_smallest_ping_priority(const LocationsCtx *, const sockaddr *, int ping_ms) {
    return -(ping_ms + 1);
}

static const PingedAddress *select_endpoint_from_list(
        const LocationsCtx *location, const std::vector<PingedAddress> &addresses, PingerSort priority_func) {
    const PingedAddress *selected = nullptr;
    size_t selected_priority = 0;

    for (const PingedAddress &i : addresses) {
        size_t i_priority = priority_func(location, (sockaddr *) &i.addr, i.ping_ms);
        if (selected == nullptr || selected_priority < i_priority) {
            selected = &i;
            selected_priority = i_priority;
        }
    }

    return selected;
}

static const PingedAddress *select_endpoint(const LocationsCtx *location, PingerSort sorter) {
    const PingedAddress *selected = select_endpoint_from_list(location, location->pinged_ipv6, sorter);
    if (selected == nullptr) {
        selected = select_endpoint_from_list(location, location->pinged_ipv4, sorter);
    }

    return selected;
}

static void finalize_location(LocationsPinger *pinger, const FinalizeLocationInfo &info) {
    const LocationsCtx *location = &info.location_ctx;
    const PingedAddress *selected =
            select_endpoint(location, pinger->query_all_interfaces ? &get_smallest_ping_priority : &get_addr_priority);

    LocationsPingerResult result = {};
    result.id = location->info.id;
    if (selected != nullptr) {
        result.ping_ms = selected->ping_ms;
        for (size_t i = 0; i < location->info.endpoints.size; ++i) {
            VpnEndpoint *ep = &location->info.endpoints.data[i];
            if (sockaddr_equals((sockaddr *) &ep->address, (sockaddr *) &selected->addr)) {
                result.endpoint = ep;
                break;
            }
        }
        assert(result.endpoint != nullptr);
        log_location(pinger, location->info.id, dbg, "Selected endpoint: '{}' {} ({}ms)", result.endpoint->name,
                sockaddr_to_str((sockaddr *) &result.endpoint->address), result.ping_ms);
    } else {
        log_location(pinger, location->info.id, dbg, "None of the addresses has been pinged successfully");
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
        std::vector<PingedAddress> &dst = (result->addr->sa_family == AF_INET6) ? l->pinged_ipv6 : l->pinged_ipv4;
        // This might not be the first result for this address
        auto it = std::find_if(dst.begin(), dst.end(), [&](const PingedAddress &a) {
            return sockaddr_equals((struct sockaddr *) &a.addr, result->addr);
        });
        if (it == dst.end()) { // Add new result
            dst.emplace_back(PingedAddress{result->ms, sockaddr_to_storage(result->addr)});
        } else {
            if (!pinger->query_all_interfaces) {
                log_location(pinger, ping_get_id(result->ping), warn,
                        "Duplicate result for address {}. Please check that location doesn't contain duplicate IPs.",
                        sockaddr_to_str(result->addr));
            }
            it->ping_ms = std::min(result->ms, it->ping_ms);
        }
        break;
    }
    case PING_FINISHED: {
        auto node = pinger->locations.extract(i);
        ping_destroy(node.key());
        return {{std::move(node.mapped()), pinger->locations.empty()}};
    }
    case PING_SOCKET_ERROR:
    case PING_TIMEDOUT:
        log_location(pinger, ping_get_id(result->ping), dbg, "Failed to ping endpoint {} - error code {}",
                sockaddr_to_str(result->addr), magic_enum::enum_name(result->status));
        break;
    }

    return std::nullopt;
}

static void ping_handler(void *arg, const PingResult *result) {
    auto *pinger = (LocationsPinger *) arg;

    if (auto finalize_info = process_ping_result(pinger, result); finalize_info.has_value()) {
        finalize_location(pinger, finalize_info.value());
    }
}

// Force libevent to poll/select between starting pings. Starting many connections in one flight
// takes a large amount of time on some systems and stalls the event loop.
static void start_location_ping(LocationsPinger *pinger) {
    assert(!pinger->pending_locations.empty());
    auto i = pinger->pending_locations.begin();

    log_location(pinger, i->info.id, dbg, "Starting location ping");
    std::vector<sockaddr_storage> addresses;
    addresses.reserve(i->info.endpoints.size);
    std::transform(i->info.endpoints.data, i->info.endpoints.data + i->info.endpoints.size,
            std::back_inserter(addresses), [](const VpnEndpoint &endpoint) {
                return endpoint.address;
            });
    PingInfo ping_info = {pinger->loop, {addresses.data(), addresses.size()}, pinger->timeout_ms,
            pinger->query_all_interfaces, pinger->rounds};
    Ping *ping = ping_start(&ping_info, {ping_handler, pinger});
    pinger->locations.emplace(ping, std::move(*i));
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
        const LocationsPingerInfo *info, LocationsPingerHandler handler, VpnEventLoop *ev_loop) {
    auto *pinger = new LocationsPinger{};

    pinger->handler = handler;
    pinger->locations.reserve(info->locations.size);
    pinger->loop = ev_loop;
#ifdef __MACH__
    pinger->query_all_interfaces = info->query_all_interfaces;
#endif /* __MACH__ */
    pinger->timeout_ms = info->timeout_ms;
    pinger->rounds = info->rounds;

    for (size_t i = 0; i < info->locations.size; ++i) {
        const VpnLocation *l = &info->locations.data[i];
        pinger->pending_locations.emplace_back(*l);
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
