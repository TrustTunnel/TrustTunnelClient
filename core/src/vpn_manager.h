#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <variant>
#include <vector>

#include "common/defs.h"
#include "common/logger.h"
#include "common/move_only_function.h"
#include "common/utils.h"
#include "net/locations_pinger.h"
#include "net/network_manager.h"
#include "net/tls.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/fsm.h"
#include "vpn/internal/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/platform.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {
namespace vpn_manager {

enum ClientConnectionState {
    CLIS_DISCONNECTED,
    CLIS_CONNECTING,
    CLIS_CONNECTED,
};

struct RecoveryInfo {
    std::chrono::time_point<std::chrono::steady_clock> start_ts;             // session recovery start timestamp
    std::chrono::time_point<std::chrono::steady_clock> attempt_start_ts;     // last recovery attempt start timestamp
    Millis attempt_interval{ag::VPN_DEFAULT_INITIAL_RECOVERY_INTERVAL_MS}; // last interval between recovery attempts
    Millis to_next{};                                                        // left to next attempt
};

struct SelectedEndpointInfo {
    const VpnEndpoint *endpoint = nullptr; // pointer to endpoint in `upstream_config.location`
};

static constexpr const char *LOG_NAME = "VPNCORE";

struct ConnectSeveralAttempts {
    size_t attempts_left = ag::VPN_DEFAULT_CONNECT_ATTEMPTS_NUM;
};

struct ConnectFallIntoRecovery {};

using ConnectRetryInfo = std::variant<
        // VPN_CRP_SEVERAL_ATTEMPTS
        ConnectSeveralAttempts,
        // VPN_CRP_FALL_INTO_RECOVERY
        ConnectFallIntoRecovery>;

} // namespace vpn_manager

struct SelectedEndpoint {
    AutoVpnEndpoint endpoint;
    std::optional<AutoVpnRelay> relay;

    SelectedEndpoint(AutoVpnEndpoint endpoint, std::optional<AutoVpnRelay> relay)
            : endpoint{std::move(endpoint)}
            , relay{std::move(relay)} {
    }
};

struct Vpn {
    Vpn(const Vpn &) = delete;
    Vpn(Vpn &&) = delete;
    Vpn &operator=(const Vpn &) = delete;
    Vpn &operator=(Vpn &&) = delete;

    Vpn();
    ~Vpn();

    void update_upstream_config(AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> config);
    vpn_client::Parameters make_client_parameters() const;
    vpn_client::EndpointConnectionConfig make_client_upstream_config() const;
    void disconnect_client();
    void stop_pinging();
    void disconnect();
    bool run_event_loop();
    void submit(ag::MoveOnlyFunction<void()> &&func, std::optional<Millis> defer = std::nullopt);
    void complete_postponed_requests();
    void reset_bypassed_connections();

    Fsm fsm;
    std::optional<VpnError> pending_error;
    std::thread executor_thread;
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    vpn_manager::RecoveryInfo recovery = {};
    VpnHandler handler = {};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> upstream_config;
    /** The endpoint the client is connected or trying to connect to */
    std::optional<SelectedEndpoint> selected_endpoint;
    bool network_changed_before_recovery = false;
    bool connected_once = false;

    DeclPtr<LocationsPinger, &locations_pinger_destroy> pinger;
    bool ping_failure_induces_location_unavailable = false;

    vpn_manager::ClientConnectionState client_state = vpn_manager::CLIS_DISCONNECTED;
    VpnClient client;

    vpn_manager::ConnectRetryInfo connect_retry_info;

    // Ids of connections bypassed during recovery
    std::vector<uint64_t> bypassed_connection_ids;

    // Completed connect requests whose processing is postponed until VPN is connected
    std::vector<ConnectRequestResult> postponed_requests;

    // This timer counts down the time during which connect requests can be postponed.
    // It is started when recovery starts and reset when recovery is done.
    // If it expires before recovery is done, all postponed connect requests are bypassed.
    DeclPtr<event, &event_free> postponement_window_timer;

    mutable std::mutex stop_guard;

    event_loop::AutoTaskId update_exclusions_task; // Guarded by stop_guard

    ag::Logger log{vpn_manager::LOG_NAME};
    int id;
};

struct StartListeningArgs {
    std::unique_ptr<ClientListener> listener;
    const VpnListenerConfig *config;
};

#define log_vpn(vpn_, lvl_, fmt_, ...) lvl_##log((vpn_)->log, "[{}] " fmt_, (vpn_)->id, ##__VA_ARGS__)

} // namespace ag
