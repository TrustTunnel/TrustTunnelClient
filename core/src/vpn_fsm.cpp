#include <algorithm>

#include "vpn/event_loop.h"
#include "vpn/utils.h"
#include "vpn_fsm.h"
#include "vpn_manager.h"

using namespace std::chrono;
using namespace ag::vpn_fsm;

namespace ag {

static bool is_fatal_error(const void *ctx, void *data);
static bool need_to_ping_on_recovery(const void *ctx, void *data);
static bool fall_into_recovery(const void *ctx, void *data);
static bool no_connect_attempts(const void *ctx, void *data);
static bool network_loss_suspected(const void *ctx, void *data);

static void run_ping(void *ctx, void *data);
static void connect_client(void *ctx, void *data);
static void complete_connect(void *ctx, void *data);
static void retry_connect(void *ctx, void *data);
static void prepare_for_recovery(void *ctx, void *data);
static void reconnect_client(void *ctx, void *data);
static void finalize_recovery(void *ctx, void *data);
static void do_disconnect(void *ctx, void *data);
static void on_network_change_no_loss(void *ctx, void *data);
static void do_health_check(void *ctx, void *data);
static void start_listening(void *ctx, void *data);
static void on_wrong_connect_state(void *ctx, void *data);
static void on_wrong_listen_state(void *ctx, void *data);
static void on_network_loss(void *ctx, void *data);

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
        {VPN_SS_DISCONNECTED,     CE_DO_CONNECT,          Fsm::ANYWAY,              run_ping,               VPN_SS_CONNECTING,       raise_state},
        {VPN_SS_DISCONNECTED,     CE_CLIENT_DISCONNECTED, Fsm::ANYWAY,              Fsm::DO_NOTHING,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_SHUTDOWN,            Fsm::ANYWAY,              do_disconnect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_DISCONNECTED,     CE_START_LISTENING,     Fsm::ANYWAY,              on_wrong_listen_state,  Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_CONNECTING,       CE_RETRY_CONNECT,       Fsm::ANYWAY,              run_ping,               Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_READY,          Fsm::ANYWAY,              connect_client,         Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_PING_FAIL,           Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_CLIENT_READY,        Fsm::ANYWAY,              complete_connect,       VPN_SS_CONNECTED,        raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, fall_into_recovery,       prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, no_connect_attempts,      complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_CONNECTING,       CE_ABANDON_ENDPOINT,    is_fatal_error,           complete_connect,       VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTING,       CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           retry_connect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},

        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_CONNECTED,        CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           on_network_change_no_loss, Fsm::SAME_TARGET_STATE, Fsm::DO_NOTHING},
        {VPN_SS_CONNECTED,        CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_CONNECTED,        CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},

        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_NETWORK_CHANGE,      Fsm::OTHERWISE,           run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         need_to_ping_on_recovery, run_ping,               VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_DO_RECOVERY,         Fsm::OTHERWISE,           connect_client,         VPN_SS_RECOVERING,       raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_WAITING_RECOVERY, CE_CLIENT_DISCONNECTED, Fsm::OTHERWISE,           do_disconnect,          Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_WAITING_RECOVERY, CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},

        {VPN_SS_RECOVERING,       CE_NETWORK_CHANGE,      network_loss_suspected,   on_network_loss,        Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_READY,          Fsm::ANYWAY,              reconnect_client,       Fsm::SAME_TARGET_STATE,  Fsm::DO_NOTHING},
        {VPN_SS_RECOVERING,       CE_PING_FAIL,           is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_RECOVERING,       CE_PING_FAIL,           Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},
        {VPN_SS_RECOVERING,       CE_CLIENT_READY,        Fsm::ANYWAY,              finalize_recovery,      VPN_SS_CONNECTED,        raise_state},
        {VPN_SS_RECOVERING,       CE_ABANDON_ENDPOINT,    is_fatal_error,           do_disconnect,          VPN_SS_DISCONNECTED,     raise_state},
        {VPN_SS_RECOVERING,       CE_ABANDON_ENDPOINT,    Fsm::OTHERWISE,           prepare_for_recovery,   VPN_SS_WAITING_RECOVERY, raise_state},

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

    vpn->recovery.attempt_interval =
            std::chrono::round<Millis>(vpn->recovery.attempt_interval * vpn->upstream_config->recovery.backoff_rate);
    time_point next_attempt_ts = now + time_to_next;
    if (next_attempt_ts - vpn->recovery.start_ts >= Millis{vpn->upstream_config->recovery.location_update_period_ms}) {
        log_vpn(vpn, dbg, "Resetting recovery state due to the recovery took too long");
        vpn->recovery = {};
    }

    vpn->recovery.to_next = time_to_next;
}

static void pinger_handler(void *arg, const LocationsPingerResult *result) {
    if (result == nullptr) {
        // ignore ping finished event
        return;
    }

    auto *vpn = (Vpn *) arg;
    assert(!vpn->selected_endpoint.has_value());
    vpn->selected_endpoint.reset();
    bool failure_induces_location_unavailable = std::exchange(vpn->ping_failure_induces_location_unavailable, false);
    if (result->ping_ms < 0) {
        VpnError error = failure_induces_location_unavailable
                ? VpnError{VPN_EC_LOCATION_UNAVAILABLE, "None of the endpoints were pinged successfully"}
                : VpnError{VPN_EC_ERROR, "Failed to ping location"};
        log_vpn(vpn, warn, "{}", error.text);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_FAIL, &error);
        return;
    }

    VpnEndpoint *endpoints_end =
            vpn->upstream_config->location.endpoints.data + vpn->upstream_config->location.endpoints.size;
    if (std::none_of(vpn->upstream_config->location.endpoints.data, endpoints_end,
                [seek = result->endpoint](const VpnEndpoint &iter) {
                    return vpn_endpoint_equals(seek, &iter);
                })) {
        vpn->ping_failure_induces_location_unavailable = failure_induces_location_unavailable;
        VpnError error = {VPN_EC_ERROR, "Best available endpoint isn't found in location"};
        log_vpn(vpn, warn, "{}: {}", error.text, *result->endpoint);
        vpn->fsm.perform_transition(vpn_fsm::CE_PING_FAIL, &error);
        return;
    }

    vpn->selected_endpoint.emplace(vpn_endpoint_clone(result->endpoint),
            result->relay_address ? std::make_optional(sockaddr_to_storage(result->relay_address)) : std::nullopt);
    log_vpn(vpn, dbg, "Using endpoint: {} (relay address={}) (ping={}ms)", *vpn->selected_endpoint->endpoint,
            vpn->selected_endpoint->relay_address.has_value()
                    ? sockaddr_to_str((sockaddr *) &*vpn->selected_endpoint->relay_address).c_str()
                    : "none",
            result->ping_ms);

    const auto *extra_result = (LocationsPingerResultExtra *) result;
    vpn->client.update_bypass_ip_availability(extra_result->ip_availability);

    vpn->fsm.perform_transition(vpn_fsm::CE_PING_READY, nullptr);
}

static bool is_fatal_error_code(int code) {
    return code == VPN_EC_AUTH_REQUIRED || code == VPN_EC_LOCATION_UNAVAILABLE;
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

static bool need_to_ping_on_recovery(const void *ctx, void *) {
    const Vpn *vpn = (Vpn *) ctx;
    if (!vpn->selected_endpoint.has_value()) {
        // we lost endpoint for some reason, need to refresh the location
        return true;
    }
    if (vpn->network_changed_before_recovery) {
        return true;
    }

    time_point now = steady_clock::now();
    return now - vpn->recovery.start_ts >= Millis{vpn->upstream_config->recovery.location_update_period_ms};
}

static bool fall_into_recovery(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    return std::holds_alternative<vpn_manager::ConnectFallIntoRecovery>(vpn->connect_retry_info);
}

static bool no_connect_attempts(const void *ctx, void *) {
    const auto *vpn = (Vpn *) ctx;
    const auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info);
    return several_attempts != nullptr && several_attempts->attempts_left == 0;
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

    LocationsPingerInfo pinger_info = {
            .timeout_ms = vpn->upstream_config->location_ping_timeout_ms,
            .locations = {&vpn->upstream_config->location, 1},
            .rounds = 1,
            .use_quic = vpn->upstream_config->protocol.type == VPN_UP_HTTP3,
            .anti_dpi = vpn->upstream_config->anti_dpi,
    };
    vpn->pinger.reset(locations_pinger_start(&pinger_info, {pinger_handler, vpn}, vpn->ev_loop.get()));

    vpn->pending_error.reset();
    vpn->selected_endpoint.reset();

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
    if (vpn->pending_error.has_value() && !is_fatal_error(ctx, data) && no_connect_attempts(ctx, nullptr)) {
        vpn->pending_error = {VPN_EC_INITIAL_CONNECT_FAILED, "Number of connection attempts exceeded"};
    }

    vpn->recovery = {};

    log_vpn(vpn, trace, "Done");
}

static void retry_connect(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

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
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->pending_error = *error;
    }

    log_vpn(vpn, trace, "Done");
}

static void reconnect_client(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect_client();

    run_client_connect(vpn, std::min(vpn->recovery.attempt_interval, Millis{vpn->upstream_config->timeout_ms}));

    log_vpn(vpn, trace, "Done");
}

static void finalize_recovery(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->recovery = {};
    vpn->stop_pinging();
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

static void on_network_change_no_loss(void *ctx, void *arg) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");
    vpn->network_changed_before_recovery = true;
    do_health_check(ctx, arg);
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
    VpnError error = vpn->client.listen(std::move(args->listener), args->config);
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

static void on_network_loss(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    log_vpn(vpn, trace, "...");

    vpn->disconnect_client();
    run_ping(ctx, nullptr);

    log_vpn(vpn, trace, "Done");
}

static void raise_state(void *ctx, void *) {
    Vpn *vpn = (Vpn *) ctx;
    auto state = (VpnSessionState) vpn->fsm.get_state();
    VpnStateChangedEvent event = {vpn->upstream_config->location.id, state};

    log_vpn(vpn, info, "{}", magic_enum::enum_name((VpnSessionState) vpn->fsm.get_state()));

    switch (state) {
    case VPN_SS_WAITING_RECOVERY:
        event.waiting_recovery_info = {
                .error = std::exchange(vpn->pending_error, std::nullopt).value_or(VpnError{}),
                .time_to_next_ms = uint32_t(vpn->recovery.to_next.count()),
        };
        break;
    case VPN_SS_CONNECTED:
        event.connected_info = {
                .endpoint = vpn->selected_endpoint.value().endpoint.get(), // NOLINT(bugprone-unchecked-optional-access)
                .protocol = vpn->client.endpoint_upstream->get_protocol(),
        };
        break;
    case VPN_SS_DISCONNECTED:
    case VPN_SS_CONNECTING:
    case VPN_SS_RECOVERING:
        event.error = std::exchange(vpn->pending_error, std::nullopt).value_or(VpnError{});
        vpn->network_changed_before_recovery = false;
        break;
    }

    vpn->handler.func(vpn->handler.arg, VPN_EVENT_STATE_CHANGED, (void *) &event);
}

static bool can_complete(const void *ctx, void *data) {
    auto *result = (ConnectRequestResult *) data;
    if (result->action == VPN_CA_FORCE_BYPASS) {
        return true;
    }
    const auto *vpn = (Vpn *) ctx;
    auto state = VpnSessionState(vpn->fsm.get_state());
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

static void postponement_window_timer_cb(evutil_socket_t, short, void *arg) {
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
