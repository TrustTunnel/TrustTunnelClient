#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <variant>
#include <vector>

#include <event2/dns.h>

#include "common/defs.h"
#include "common/logger.h"
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
    uint32_t recoveries_num = 0;           // the number of recovery attempts to the endpoint
};

static constexpr const char *LOG_NAME = "VPNCORE";
// the number of recovery attempts before marking an endpoint inactive
static constexpr size_t INACTIVE_ENDPOINT_RECOVERIES_NUM = 1;

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

struct Vpn {
    Vpn(const Vpn &) = delete;
    Vpn(Vpn &&) = delete;
    Vpn &operator=(const Vpn &) = delete;
    Vpn &operator=(Vpn &&) = delete;

    Vpn();
    ~Vpn();

    void update_upstream_config(const VpnUpstreamConfig *config);
    vpn_client::Parameters make_client_parameters() const;
    vpn_client::EndpointConnectionConfig make_client_upstream_config() const;
    void disconnect_client();
    void stop_pinging();
    void disconnect();
    bool run_event_loop();
    void submit(std::function<void()> &&func, std::optional<Millis> defer = std::nullopt);
    /**
     * Get endpoint to connect to
     * @return the selected one if some, the first active from the location list otherwise
     */
    const VpnEndpoint *get_endpoint() const;
    /**
     * Increment failures counter and mark the selected endpoint inactive
     * if it's reached the threshold
     */
    void register_selected_endpoint_fail();
    /**
     * Mark the selected endpoint inactive unconditionally
     */
    void mark_selected_endpoint_inactive();
    void complete_postponed_requests();
    void reset_bypassed_connections();

    Fsm fsm;
    std::optional<VpnError> pending_error;
    std::thread executor_thread;
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    vpn_manager::RecoveryInfo recovery = {};
    VpnHandler handler = {};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    evdns_base *dns_base = dns_manager_create_base(this->network_manager->dns,
            vpn_event_loop_get_base(this->ev_loop.get())); // DNS base used for resolving hosts in bypassing upstream
    VpnUpstreamConfig upstream_config = {};
    vpn_manager::SelectedEndpointInfo selected_endpoint_info = {}; // the most suitable endpoint

    DeclPtr<LocationsPinger, &locations_pinger_destroy> pinger;

    vpn_manager::ClientConnectionState client_state = vpn_manager::CLIS_DISCONNECTED;
    VpnClient client;

    // An endpoint becomes inactive in case it was disconnected for any reason.
    // If all endpoints were marked inactive, the library re-pings them all in case some of them were resurrected.
    // This list is reset on successful recovery and on `vpn_stop` call.
    std::vector<const VpnEndpoint *> inactive_endpoints; // pointers to endpoints in `upstream_config.location`

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
