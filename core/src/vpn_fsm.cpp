#include <algorithm>

#include "vpn/event_loop.h"
#include "vpn/utils.h"
#include "vpn_fsm.h"
#include "vpn_manager.h"

using namespace std::chrono;
using namespace ag::vpn_fsm;

namespace ag {

static bool need_to_ping(const void *ctx, void *data);
static bool is_fatal_error(const void *ctx, void *data);
static bool need_to_ping_on_recovery(const void *ctx, void *data);
static bool fall_into_recovery(const void *ctx, void *data);
static bool no_connect_attempts(const void *ctx, void *data);
static bool last_active_endpoint(const void *ctx, void *data);
static bool network_loss_suspected(const void *ctx, void *data);

static void run_ping(void *ctx, void *data);
static void connect_client(void *ctx, void *data);
static void complete_connect(void *ctx, void *data);
static void retry_connect(void *ctx, void *data);
static void prepare_for_recovery(void *ctx, void *data);
static void reconnect_client(void *ctx, void *data);
static void finalize_recovery(void *ctx, void *data);
static void do_disconnect(void *ctx, void *data);
static void do_health_check(void *ctx, void *data);
static void start_listening(void *ctx, void *data);
static void on_wrong_connect_state(void *ctx, void *data);
static void on_wrong_listen_state(void *ctx, void *data);
static void on_network_loss(void *ctx, void *data);
static void abandon_endpoint(void *ctx, void *data);

static void raise_state(void *ctx, void *data);

static bool can_complete(const void *ctx, void *data);
static bool is_kill_switch_on(const void *ctx, void *data);
static bool should_postpone(const void *ctx, void *data);

static void complete_request(void *ctx, void *data);
static void postpone_request(void *ctx, void *data);
static void reject_request(void *ctx, void *data);
static void bypass_until_connected(void *ctx, void *data);

// clang-format off
static constexpr FsmTransitionEntry TRANSITION_TABLE[] = {
        {VPN_SS_DISCONNECTED,     CE_DO_CONNECT,          need_to_ping,             run_ping,               VPN_SS_CONNECTING,       raise_state},
        {VPN_SS_DISCONNECTED,     CE_DO_CONNECT,          Fsm::OTHERWISE,           connect_client,         VPN_SS_CONNECTING,       raise_state},
        {VPN_SS_DISCONNECTED,     CE_CLIENT_DISCONNECTED, Fsm::ANYWAY,              Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_SHUTDOWN,            Fsm::ANYWAY,              do_disconnect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_START_LISTENING,     Fsm::ANYWAY,              on_wrong_listen_state,  Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_CONNECTING,       CE_RETRY_CONNECT,       need_to_ping,             run_ping,               VPN_SS_CONNECTING,       Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_RETRY_CONNECT,       Fsm::OTHERWISE,           connect_client,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_READY,          Fsm::ANYWAY,              connect_client,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           last_active_endpoint,     complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           Fsm::OTHERWISE,           retry_connect,          VPN_SS_CONNECTING,       Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_CLIENT_READY,        Fsm::ANYWAY,              complete_connect,       VPN_SS_CONNECTED,        raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, last_active_endpoint,     complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           retry_connect,          VPN_SS_CONNECTING,       Fsm::DO_NOTHING},

        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           do_health_check,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTED,        CE_ABANDON_ENDPOINT,    Fsm::ANYWAY,              abandon_endpoint,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      need_to_ping_on_recovery, run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           connect_client,         VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         need_to_ping_on_recovery, run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         Fsm::OTHERWISE,           connect_client,         VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           do_disconnect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_RECOVERING,       CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_READY,          Fsm::ANYWAY,              reconnect_client,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_FAIL,           Fsm::ANYWAY,              prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_RECOVERING,       CE_CLIENT_READY,        Fsm::ANYWAY,              finalize_recovery,      VPN_SS_CONNECTED,        raise_state},

        {Fsm::ANY_SOURCE_STATE,   CE_CLIENT_DISCONNECTED, is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_SHUTDOWN,            Fsm::ANYWAY,              do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_DO_CONNECT,          Fsm::ANYWAY,              on_wrong_connect_state, VPN_SS_DISCONNECTED,     raise_state},
        {Fsm::ANY_SOURCE_STATE,   CE_START_LISTENING,     Fsm::ANYWAY,              start_listening,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    can_complete,             complete_request,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    should_postpone,          postpone_request,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    is_kill_switch_on,        reject_request,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {Fsm::ANY_SOURCE_STATE,   CE_COMPLETE_REQUEST,    Fsm::OTHERWISE,           bypass_until_connected, Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
};
// clang-format on

FsmTransitionTable vpn_fsm::get_transition_table() {
    return {std::begin(TRANSITION_TABLE), std::end(TRANSITION_TABLE)};
}

static void postponement_window_timer_cb(evutil_socket_t, short, void *arg);

static void initiate_recovery(Vpn *vpn) {
    time_point now = steady_clock::now();
    Millis elapsed{};
    if (vpn->recovery.start_ts != time_point<steady_clock>{}) {
        elapsed = std::max(duration_cast<Millis>(now - vpn->recovery.attempt_start_ts), Millis{});
    } else {
        vpn->recovery.start_ts = now;
        vpn->postponement_window_timer.reset(
                evtimer_new(vpn_event_loop_get_base(vpn->ev_loop.get()), postponement_window_timer_cb, vpn));
        timeval tv = ms_to_timeval(VPN_DEFAULT_POSTPONEMENT_WINDOW_MS);
        evtimer_add(vpn->postponement_window_timer.get(), &tv);
    }

    // try to recover immediately if a previous attempt has taken the whole period
    Millis time_to_next{};
    if (vpn->recovery.attempt_interval >= elapsed) {
        time_to_next = vpn->recovery.attempt_interval - elapsed;
    }

    log_vpn(vpn, dbg, "Time to next recovery: {}", time_to_next);

    vpn->submit(
            [vpn]() {
                log_vpn(vpn, dbg, "Recovering session...");
                vpn->recovery.attempt_start_ts = steady_clock::now();
                vpn->fsm.perform_transition(vpn_fsm::CE_DO_RECOVERY, nullptr);
            },
            time_to_next);

    vpn->recovery.attempt_interval = Millis{Millis::rep(float(vpn->recovery.attempt_interval.count()) * vpn->upstream_config.recovery.backoff_rate)};
    time_point next_attempt_ts = now + time_to_next;
    if (next_attempt_ts - vpn->recovery.start_ts >= Millis{vpn->upstream_config.recovery.location_update_period_ms}) {
        log_vpn(vpn, dbg, "Resetting recovery state due to the recovery took too long");
        vpn->recovery = {};
        vpn->register_selected_endpoint_fail();
    }

    vpn->recovery.to_next = time_to_next;
}

static void pinger_handler(void *arg, const LocationsPingerResult *result) {
    if (result == nullptr) {
        // ignore ping finished event
        return;
    }

    Vpn *vpn = (Vpn *) arg;

    const VpnEndpoint *endpoint = nullptr;
    if (result->endpoint != nullptr) {
        for (size_t i = 0; i < vpn->upstream_config.location.endpoints.size; ++i) {
            endpoint = &vpn->upstream_config.location.endpoints.data[i];
            if (vpn_endpoint_equals(result->endpoint, endpoint)) {
                break;
            }
        }
    }

    vpn->selected_endpoint_info = {endpoint};
    if (endpoint != nullptr) {
        log_vpn(vpn, dbg, "Using endpoint '{}' {} (ping={}ms)", endpoint->name,
                sockaddr_to_str((sockaddr *) &endpoint->address), result->ping_ms);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_READY, nullptr);
    } else {
        VpnError error = {VPN_EC_LOCATION_UNAVAILABLE, "None of the endpoints were pinged successfully"};
        log_vpn(vpn, warn, "{}", error.text);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_FAIL, &error);
    }
}

static bool are_there_active_endpoints(const Vpn *vpn) {
    return vpn->inactive_endpoints.size() < vpn->upstream_config.location.endpoints.size;
}

template <typename It, typename Pred, typename Free>
static It remove_if(It begin, It end, Pred &&pred, Free &&free) {
    begin = std::find_if(begin, end, std::forward<Pred>(pred));
    if (begin != end) {
        It it = begin;
        while (++it != end) {
            if (!std::forward<Pred>(pred)(*it)) {
                std::forward<Free>(free)(*begin);
                *begin = *it;
                *it = {};
                ++begin;
            }
        }
    }
    return begin;
}

static VpnLocation filter_out_inactive_endpoints(const Vpn *vpn, const VpnLocation &src) {
    VpnLocation dst;
    vpn_location_clone(&dst, &src);

    assert(src.endpoints.size >= vpn->inactive_endpoints.size());
    size_t available_endpoints_num = src.endpoints.size - vpn->inactive_endpoints.size();
    if (available_endpoints_num > 0) {
        for (const VpnEndpoint *inactive_endpoint : vpn->inactive_endpoints) {
            VpnEndpoint *end = dst.endpoints.data + dst.endpoints.size;
            VpnEndpoint *begin = remove_if(
                    dst.endpoints.data, end,
                    [inactive_endpoint](const VpnEndpoint &endpoint) {
                        return vpn_endpoint_equals(&endpoint, inactive_endpoint);
                    },
                    [](VpnEndpoint &endpoint) {
                        vpn_endpoint_destroy(&endpoint);
                    });
            dst.endpoints.size -= (end - begin);
            for (; begin != end; ++begin) {
                vpn_endpoint_destroy(begin);
            }
        }
    } else {
        log_vpn(vpn, dbg, "All endpoints are marked inactive, re-ping them all in case some were resurrected");
    }

    return dst;
}

static bool is_fatal_error_code(int code) {
    return code == VPN_EC_AUTH_REQUIRED;
}

static void run_client_connect(Vpn *vpn, std::optional<Millis> timeout = std::nullopt) {
    VpnError error = vpn->client.connect(vpn->make_client_upstream_config(), timeout);
    if (error.code == VPN_EC_NOERROR) {
        vpn->client_state = vpn_manager::CLIS_CONNECTING;
        vpn->pending_error.reset();
    } else {
        log_vpn(vpn, dbg, "Failed to connect: {} ({})", safe_to_string_view(error.text), error.code);
        vpn->pending_error = error;
        vpn->submit([vpn] {
            vpn->fsm.perform_transition(CE_CLIENT_DISCONNECTED, nullptr);
        });
    }
}

static bool need_to_ping(const void *ctx, void *) {
    const Vpn *vpn = (Vpn *) ctx;
    const auto *endpoints = &vpn->upstream_config.location.endpoints;
    // special case: a single endpoint is specified without resolved address
    return !(endpoints->size == 1 && endpoints->data[0].address.ss_family == AF_UNSPEC);
}

static bool need_to_ping_on_recovery(const void *ctx, void *data) {
    if (!need_to_ping(ctx, data)) {
        return false;
    }

    const Vpn *vpn = (Vpn *) ctx;
    if (vpn->selected_endpoint_info.endpoint == nullptr) {
        // we lost endpoint for some reason, need to refresh the location
        return true;
    }

    time_point now = steady_clock::now();
    return now - vpn->recovery.start_ts >= Millis{vpn->upstream_config.recovery.location_update_period_ms};
}

static bool fall_into_recovery(const void *ctx, void *data) {
    const auto *vpn = (Vpn *) ctx;
    return std::holds_alternative<vpn_manager::ConnectFallIntoRecovery>(vpn->connect_retry_info);
}

static bool no_connect_attempts(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    const auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info);
    return several_attempts != nullptr && several_attempts->attempts_left == 0;
}

static bool last_active_endpoint(const void *ctx, void *) {
    const Vpn *vpn = (Vpn *) ctx;
    return vpn->upstream_config.location.endpoints.size <= vpn->inactive_endpoints.size() + 1;
}

static bool network_loss_suspected(const void *, void *data) {
    bool network_loss_suspected = *(bool *) data;
    return network_loss_suspected;
}

static bool is_fatal_error(const void *ctx, void *data) {
    const VpnError *error = (VpnError *) data;
    const Vpn *vpn = (Vpn *) ctx;
    return (error != nullptr && is_fatal_error_code(error->code))
            || is_fatal_error_code(vpn->pending_error.value_or(VpnError{}).code);
}

static void run_ping(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->stop_pinging();

    VpnLocation filtered_location = filter_out_inactive_endpoints(vpn, vpn->upstream_config.location);

    LocationsPingerInfo pinger_info = {vpn->upstream_config.location_ping_timeout_ms, {&filtered_location, 1}, 1};
    vpn->pinger.reset(locations_pinger_start(&pinger_info, {pinger_handler, vpn}, vpn->ev_loop.get()));

    vpn_location_destroy(&filtered_location);

    vpn->pending_error.reset();

    log_vpn(vpn, trace, "Done");
}

static void connect_client(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    run_client_connect(vpn);

    log_vpn(vpn, trace, "Done");
}

static void complete_connect(void *ctx, void *data) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    const VpnError *error = (VpnError *) data;
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->disconnect();
        vpn->pending_error = *error;
    }

    vpn->recovery = {};
    vpn->inactive_endpoints.clear();

    log_vpn(vpn, trace, "Done");
}

static void retry_connect(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    // mark current endpoint inactive without retries like in connected case
    vpn->mark_selected_endpoint_inactive();

    if (auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info)) {
        several_attempts->attempts_left -= 1;
    } else {
        assert(0);
    }

    vpn->disconnect();

    vpn->submit([vpn] {
        vpn->fsm.perform_transition(CE_RETRY_CONNECT, nullptr);
    });

    log_vpn(vpn, trace, "Done");
}

static void prepare_for_recovery(void *ctx, void *data) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect();
    initiate_recovery(vpn);

    const VpnError *error = (VpnError *) data;
    if (!are_there_active_endpoints(vpn)) {
        vpn->pending_error = {VPN_EC_LOCATION_UNAVAILABLE, "Got errors on each endpoint of location"};
        log_vpn(vpn, dbg, "No active endpoints left");
    } else if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->pending_error = *error;
    }

    log_vpn(vpn, trace, "Done");
}

static void reconnect_client(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect_client();

    run_client_connect(vpn, std::min(vpn->recovery.attempt_interval, Millis{vpn->upstream_config.timeout_ms}));

    log_vpn(vpn, trace, "Done");
}

static void finalize_recovery(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->recovery = {};
    vpn->stop_pinging();
    vpn->inactive_endpoints.clear();
    vpn->selected_endpoint_info.recoveries_num = 0;
    vpn->postponement_window_timer.reset();
    vpn->complete_postponed_requests();
    vpn->reset_bypassed_connections();

    log_vpn(vpn, trace, "Done");
}

static void do_disconnect(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect();

    log_vpn(vpn, trace, "Done");
}

static void do_health_check(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    switch (vpn->client_state) {
    case vpn_manager::CLIS_DISCONNECTED:
    case vpn_manager::CLIS_CONNECTING:
        log_vpn(vpn, dbg, "Ignoring due to current client state: {}", magic_enum::enum_name(vpn->client_state));
        break;
    case vpn_manager::CLIS_CONNECTED:
        vpn->client.do_health_check();
        break;
    }

    log_vpn(vpn, trace, "Done");
}

static void start_listening(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    auto *args = (StartListeningArgs *) data;

    log_vpn(vpn, info, "...");
    const VpnLocation &location = vpn->upstream_config.location;
    bool ipv6_available = std::any_of(location.endpoints.data, location.endpoints.data + location.endpoints.size,
            [](const VpnEndpoint &e) -> bool {
                return e.address.ss_family == AF_INET6;
            });
    VpnError error = vpn->client.listen(std::move(args->listener), args->config, ipv6_available);
    if (error.code != VPN_EC_NOERROR) {
        log_vpn(vpn, err, "Client run failed: {} ({})", safe_to_string_view(error.text), error.code);
        vpn->submit([vpn, error] {
            vpn->pending_error = error;
            vpn->fsm.perform_transition(CE_SHUTDOWN, nullptr);
        });
    } else {
        log_vpn(vpn, info, "Client has been successfully prepared to run");
    }
}

static void on_wrong_connect_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;

    vpn->disconnect();

    vpn->pending_error = {VPN_EC_INVALID_STATE, "Invalid state for connecting"};
    log_vpn(vpn, err, "{}: {}", vpn->pending_error->text,
            magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));
}

static void on_wrong_listen_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, err, "Invalid state for listenning: {}",
            magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));
}

static void on_network_loss(void *ctx, void *data) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect_client();

    bool network_loss_suspected = *(bool *) data;
    if (network_loss_suspected) {
        vpn->inactive_endpoints.clear();
    }

    run_ping(ctx, nullptr);

    log_vpn(vpn, trace, "Done");
}

static void raise_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    auto state = (VpnSessionState) vpn->fsm.get_state();
    VpnStateChangedEvent event = {vpn->upstream_config.location.id, state};

    log_vpn(vpn, info, "{}", magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));

    switch (state) {
    case VPN_SS_WAITING_RECOVERY:
        event.waiting_recovery_info = {vpn->pending_error.value_or(VpnError{}), uint32_t(vpn->recovery.to_next.count())};
        break;
    case VPN_SS_CONNECTED:
        assert(vpn->selected_endpoint_info.endpoint != nullptr);
        event.connected_info = {vpn->selected_endpoint_info.endpoint, vpn->client.endpoint_upstream->get_protocol()};
        break;
    case VPN_SS_DISCONNECTED:
    case VPN_SS_CONNECTING:
    case VPN_SS_RECOVERING:
        event.error = vpn->pending_error.value_or(VpnError{});
        break;
    }

    vpn->handler.func(vpn->handler.arg, VPN_EVENT_STATE_CHANGED, (void *) &event);
}

void abandon_endpoint(void *ctx, void *) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->mark_selected_endpoint_inactive();
    vpn->disconnect_client();

    log_vpn(vpn, trace, "Done");
}

static bool can_complete(const void *ctx, void *data) {
    auto *result = (ConnectRequestResult *) data;
    if (result->action == VPN_CA_FORCE_BYPASS) {
        return true;
    }
    const auto *vpn = (Vpn *) ctx;
    int state = vpn->fsm.get_state();
    return state == VPN_SS_CONNECTED || state == VPN_SS_CONNECTING || state == VPN_SS_DISCONNECTED;
}

static bool is_kill_switch_on(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    return vpn->client.kill_switch_on;
}

static void complete_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *result = (ConnectRequestResult *) data;
    vpn->client.complete_connect_request(result->id, result->action);

    log_vpn(vpn, trace, "Done");
}

static void reject_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;

    auto *result = (ConnectRequestResult *) data;
    log_vpn(vpn, dbg, "Rejecting connection [L:{}]: not ready to route through endpoint", result->id);
    vpn->client.reject_connect_request(result->id);

    log_vpn(vpn, trace, "Done");
}

static void bypass_until_connected(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *result = (ConnectRequestResult *) data;
    vpn->bypassed_connection_ids.emplace_back(result->id);
    vpn->client.complete_connect_request(result->id, VPN_CA_FORCE_BYPASS);

    log_vpn(vpn, trace, "Done");
}

static bool should_postpone(const void *ctx, void *) {
    auto *vpn = (Vpn *) ctx;
    return vpn->postponement_window_timer != nullptr;
}

static void postpone_request(void *ctx, void *data) {
    auto *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    auto *request = (ConnectRequestResult *) data;
    vpn->postponed_requests.emplace_back(std::move(*request));

    log_vpn(vpn, trace, "Done");
}

static void postponement_window_timer_cb(int, short, void *arg) {
    auto *vpn = (Vpn *) arg;
    log_vpn(vpn, trace, "...");

    vpn->postponement_window_timer.reset();
    for (auto &request : vpn->postponed_requests) {
        if (vpn->client.kill_switch_on) {
            vpn->client.reject_connect_request(request.id);
        } else {
            vpn->client.complete_connect_request(request.id, VPN_CA_FORCE_BYPASS);
            vpn->bypassed_connection_ids.emplace_back(request.id);
        }
    }
    vpn->postponed_requests.clear();

    log_vpn(vpn, trace, "Done");
}

} // namespace ag
