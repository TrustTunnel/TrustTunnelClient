#include <atomic>
#include <condition_variable>

#include "socks_listener.h"
#include "tun_device_listener.h"
#include "vpn/internal/domain_filter.h"
#include "vpn/internal/utils.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"
#include "vpn_fsm.h"
#include "vpn_manager.h"

#undef gettid
#include "dns/upstream/upstream_utils.h"

/** This dummy variable is preventing the linker from excluding modules from dll */
int g_exp_init_adguard_vpncore [[maybe_unused]] = 0;

namespace ag {

using namespace std::chrono;

static std::atomic_int g_next_id = 0;

static int ssl_verify_callback(const char *host_name, const sockaddr *host_ip, X509_STORE_CTX *ctx, void *arg);
static void client_handler(void *arg, vpn_client::Event what, void *data);
static void shutdown_cb(Vpn *vpn);
static const char *check_address(const sockaddr_storage *addr);

static constexpr auto STATE_NAMES = make_enum_names_array<VpnSessionState>();
static constexpr auto EVENT_NAMES = make_enum_names_array<vpn_fsm::ConnectEvent>();

static FsmParameters make_fsm_params(Vpn *vpn) {
    return {VPN_SS_DISCONNECTED, vpn_fsm::get_transition_table(), vpn, vpn_manager::LOG_NAME, STATE_NAMES.data(),
            EVENT_NAMES.data()};
}

Vpn::Vpn()
        : fsm(make_fsm_params(this))
        , client(make_client_parameters())
        , id(g_next_id++) {
}

Vpn::~Vpn() {
    vpn_upstream_config_destroy(&this->upstream_config);
}

void Vpn::update_upstream_config(const VpnUpstreamConfig *config) {
    vpn_upstream_config_destroy(&this->upstream_config);
    this->upstream_config = vpn_upstream_config_clone(config);

    if (!this->upstream_config.fallback.enabled && this->upstream_config.protocol.type == VPN_UP_HTTP3) {
        log_vpn(this, info, "Setting forcibly HTTP/2 as fallback protocol");
        this->upstream_config.fallback.enabled = true;
        this->upstream_config.fallback.protocol.type = VPN_UP_HTTP2;
    }

    if (this->upstream_config.location_ping_timeout_ms == 0) {
        this->upstream_config.location_ping_timeout_ms = DEFAULT_PING_TIMEOUT_MS;
    }
    if (this->upstream_config.timeout_ms == 0) {
        this->upstream_config.timeout_ms = VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS;
    }
    if (this->upstream_config.endpoint_pinging_period_ms == 0) {
        this->upstream_config.endpoint_pinging_period_ms = VPN_DEFAULT_ENDPOINT_PINGING_PERIOD_MS;
    }
    if (this->upstream_config.recovery.backoff_rate < 1) {
        this->upstream_config.recovery.backoff_rate = VPN_DEFAULT_RECOVERY_BACKOFF_RATE;
    }
    if (this->upstream_config.recovery.location_update_period_ms == 0) {
        this->upstream_config.recovery.location_update_period_ms = VPN_DEFAULT_RECOVERY_LOCATION_UPDATE_PERIOD_MS;
    }
    if (VpnUpstreamFallbackConfig &fallback = this->upstream_config.fallback; fallback.enabled) {
        if (fallback.connect_delay_ms == 0) {
            fallback.connect_delay_ms = VPN_DEFAULT_FALLBACK_CONNECT_DELAY_MS;
        }
    }
}

vpn_client::Parameters Vpn::make_client_parameters() const {
    return {
            this->ev_loop.get(),
            this->dns_base,
            this->network_manager.get(),
            {client_handler, (void *) this},
            {ssl_verify_callback, (void *) this},
    };
}

vpn_client::EndpointConnectionConfig Vpn::make_client_upstream_config() const {
    return {
            this->upstream_config.protocol,
            this->upstream_config.fallback,
            this->get_endpoint(),
            milliseconds(this->upstream_config.timeout_ms),
            this->upstream_config.username,
            this->upstream_config.password,
            milliseconds(this->upstream_config.endpoint_pinging_period_ms),
    };
}

void Vpn::disconnect_client() {
    switch (this->client_state) {
    case vpn_manager::CLIS_DISCONNECTED:
        // do nothing
        break;
    case vpn_manager::CLIS_CONNECTED:
    case vpn_manager::CLIS_CONNECTING:
        this->client.disconnect();
        this->client_state = vpn_manager::CLIS_DISCONNECTED;
        break;
    }
}

void Vpn::stop_pinging() {
    if (this->pinger != nullptr) {
        locations_pinger_stop(this->pinger.get());
        this->pinger.reset();
    }
}

void Vpn::disconnect() {
    this->stop_pinging();
    this->disconnect_client();
}

bool Vpn::run_event_loop() {
    log_vpn(this, info, "Starting event loop...");

    if (this->ev_loop == nullptr) {
        this->ev_loop.reset(vpn_event_loop_create());

        if (this->ev_loop == nullptr) {
            log_vpn(this, err, "Failed to create event loop");
            return false;
        }

        this->dns_base =
                dns_manager_create_base(this->network_manager->dns, vpn_event_loop_get_base(this->ev_loop.get()));
    }

    this->executor_thread = std::thread([this]() {
        int ret = vpn_event_loop_run(this->ev_loop.get());
        if (ret != 0) {
            log_vpn(this, err, "Event loop run returned {}, shutting down", ret);
            this->pending_error = {.code = VPN_EC_EVENT_LOOP_FAILURE, .text = "Event loop run error"};
            shutdown_cb(this);
        }
    });

    if (!vpn_event_loop_dispatch_sync(this->ev_loop.get(), nullptr, nullptr)) {
        log_vpn(this, err, "Event loop did not start");
        assert(0);
        vpn_event_loop_stop(this->ev_loop.get());
        if (this->executor_thread.joinable()) {
            this->executor_thread.join();
        }
        return false;
    }

    log_vpn(this, info, "Event loop has been started");

    return true;
}

void Vpn::submit(std::function<void()> &&func, std::optional<Millis> defer) {
    VpnEventLoopTask task = {
            new std::function(std::move(func)),
            [](void *arg, TaskId task_id) {
                std::function<void()> *func = (std::function<void()> *) arg;
                (*func)();
            },
            [](void *arg) {
                delete (std::function<void()> *) arg;
            },
    };

    if (!defer.has_value()) {
        vpn_event_loop_submit(this->ev_loop.get(), task);
    } else {
        vpn_event_loop_schedule(this->ev_loop.get(), task, defer.value());
    }
}

const VpnEndpoint *Vpn::get_endpoint() const {
    if (this->selected_endpoint_info.endpoint != nullptr) {
        return this->selected_endpoint_info.endpoint;
    }

    // find first active
    for (size_t i = 0; i < this->upstream_config.location.endpoints.size; ++i) {
        const VpnEndpoint *endpoint = &this->upstream_config.location.endpoints.data[i];
        auto it = std::find(this->inactive_endpoints.begin(), this->inactive_endpoints.end(), endpoint);
        if (it == this->inactive_endpoints.end()) {
            return endpoint;
        }
    }

    // if none, just return the first one
    return &this->upstream_config.location.endpoints.data[0];
}

void Vpn::register_selected_endpoint_fail() {
    if (this->selected_endpoint_info.endpoint == nullptr) {
        return;
    }

    ++this->selected_endpoint_info.recoveries_num;
    if (this->selected_endpoint_info.recoveries_num >= vpn_manager::INACTIVE_ENDPOINT_RECOVERIES_NUM) {
        this->mark_selected_endpoint_inactive();
    }
}

void Vpn::mark_selected_endpoint_inactive() {
    if (this->selected_endpoint_info.endpoint == nullptr) {
        return;
    }

    const VpnEndpoint *endpoint = this->selected_endpoint_info.endpoint;
    this->selected_endpoint_info = {};

    auto it = std::find(this->inactive_endpoints.begin(), this->inactive_endpoints.end(), endpoint);
    if (it != this->inactive_endpoints.end()) {
        return;
    }

    this->inactive_endpoints.push_back(endpoint);
    log_vpn(this, info, "Adding endpoint to the list of inactive: '{}' {} (list size={})", endpoint->name,
            sockaddr_to_str((sockaddr *) &endpoint->address), this->inactive_endpoints.size());
}

void Vpn::complete_postponed_requests() {
    log_vpn(this, trace, "...");
    for (auto &request : this->postponed_requests) {
        this->client.complete_connect_request(request.id, request.action);
    }
    this->postponed_requests.clear();
    log_vpn(this, trace, "Done");
}

void Vpn::reset_bypassed_connections() {
    log_vpn(this, trace, "...");
    for (uint64_t id : this->bypassed_connection_ids) {
        this->client.reset_connection(id);
    }
    this->bypassed_connection_ids.clear();
    log_vpn(this, trace, "Done");
}

Vpn *vpn_open(const VpnSettings *settings) {
    DeclPtr<Vpn, &vpn_close> vpn{new Vpn{}};
    log_vpn(vpn, info, "...");

    if (vpn->ev_loop == nullptr) {
        log_vpn(vpn, err, "Failed to create event loop");
        return nullptr;
    }

    vpn->handler = settings->handler;

    VpnError error = vpn->client.init(settings);
    if (error.code == VPN_EC_NOERROR) {
        log_vpn(vpn, info, "Done");
    } else {
        log_vpn(vpn, err, "Failed: {} ({})", safe_to_string_view(error.text), error.code);
        vpn.reset();
    }

    return vpn.release();
}

static VpnError validate_upstream_config(const Vpn *vpn, const VpnUpstreamConfig *config) {
    if (config->location.endpoints.size == 0) {
        return {VPN_EC_INVALID_SETTINGS, "At least one endpoint must be specified"};
    }

    if (config->username == nullptr || config->password == nullptr) {
        return {VPN_EC_INVALID_SETTINGS, "Both username and password must be specified"};
    }

    for (size_t i = 0; i < config->location.endpoints.size; ++i) {
        const VpnEndpoint *i_ep = &config->location.endpoints.data[i];
        if (i_ep->name == nullptr) {
            log_vpn(vpn, err, "Invalid endpoint's address='{}'", sockaddr_to_str((sockaddr *) &i_ep->address));
            return {VPN_EC_INVALID_SETTINGS, "Names must be specified for each endpoint"};
        }

        if (config->location.endpoints.size > 1 && i_ep->address.ss_family == AF_UNSPEC) {
            log_vpn(vpn, err, "Invalid endpoint's name='{}'", i_ep->name);
            return {VPN_EC_INVALID_SETTINGS, "In case of multiple endpoints addresses must be specified for each one"};
        }

        if (const char *error_message = check_address(&i_ep->address); error_message != nullptr) {
            log_vpn(vpn, err, "Invalid endpoint address {} ({}): {}", sockaddr_to_str((sockaddr *) &i_ep->address),
                    i_ep->name, error_message);
            return {VPN_EC_INVALID_SETTINGS, "Invalid endpoint address"};
        }
    }

    return {};
}

VpnError vpn_connect(Vpn *vpn, const VpnConnectParameters *parameters) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    VpnError error = validate_upstream_config(vpn, &parameters->upstream_config);
    if (error.code != VPN_EC_NOERROR) {
        log_vpn(vpn, err, "Upstream configuration validation failed: {}", error.text);
        return error;
    }

    if (vpn->executor_thread.joinable()) {
        error = {VPN_EC_ERROR, "VPN client worker is already running"};
        log_vpn(vpn, err, "{}", error.text);
        return error;
    }

    if (!vpn->run_event_loop()) {
        error = {VPN_EC_EVENT_LOOP_FAILURE, "Failed to start event loop for operation"};
        log_vpn(vpn, err, "{}", error.text);
        return error;
    }

    vpn_manager::ConnectRetryInfo retry_info;
    switch (parameters->retry_info.policy) {
    case VPN_CRP_SEVERAL_ATTEMPTS:
        retry_info = vpn_manager::ConnectSeveralAttempts{
                .attempts_left = (parameters->retry_info.attempts_num <= 0)
                        ? VPN_DEFAULT_CONNECT_ATTEMPTS_NUM
                        : size_t(parameters->retry_info.attempts_num),
        };
        break;
    case VPN_CRP_FALL_INTO_RECOVERY:
        retry_info = vpn_manager::ConnectFallIntoRecovery{};
        break;
    }

    vpn->submit([vpn, cfg = vpn_upstream_config_clone(&parameters->upstream_config),
                        retry_info = std::move(retry_info)]() mutable {
        vpn->client.update_parameters(vpn->make_client_parameters());
        vpn->update_upstream_config(&cfg);
        vpn->connect_retry_info = std::move(retry_info);
        if (auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info);
                several_attempts != nullptr) {
            several_attempts->attempts_left -= 1;
        }
        vpn->fsm.perform_transition(vpn_fsm::CE_DO_CONNECT, nullptr);
        vpn_upstream_config_destroy(&cfg);
    });

    log_vpn(vpn, info, "Done");

    return error;
}

void vpn_force_reconnect(Vpn *vpn) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn]() {
        vpn->fsm.perform_transition(vpn_fsm::CE_DO_RECOVERY, nullptr);
    });

    log_vpn(vpn, info, "Done");
}

VpnError vpn_listen(Vpn *vpn, VpnListener *listener_, const VpnListenerConfig *config) {
    log_vpn(vpn, info, "...");

    if (!listener_) {
        return VpnError{.code = VPN_EC_INVALID_SETTINGS, .text = "Listener is NULL"};
    }
    if (!config) {
        return VpnError{.code = VPN_EC_INVALID_SETTINGS, .text = "Listener config is NULL"};
    }

    std::unique_ptr<ClientListener> listener((ClientListener *) listener_);

    std::unique_lock l(vpn->stop_guard);

    if (!vpn->executor_thread.joinable()) {
        VpnError error = {VPN_EC_ERROR, "VPN client worker is not running"};
        log_vpn(vpn, err, "{}", error.text);
        return error;
    }

    event_loop::dispatch_sync(vpn->ev_loop.get(), [&]() mutable {
        StartListeningArgs args{.listener = std::move(listener), .config = config};
        vpn->fsm.perform_transition(vpn_fsm::CE_START_LISTENING, &args);
    });

    log_vpn(vpn, info, "Done");

    return {};
}

void vpn_stop(Vpn *vpn) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    if (vpn->ev_loop != nullptr) {
        vpn->submit([vpn]() {
            shutdown_cb(vpn);
        });
        log_vpn(vpn, info, "Stopping event loop...");
        vpn_event_loop_stop(vpn->ev_loop.get());
        log_vpn(vpn, info, "Event loop has been stopped");
    }

    if (vpn->executor_thread.joinable()) {
        vpn->executor_thread.join();
    }

    vpn->fsm.reset();
    vpn->pending_error.reset();
    vpn->client_state = vpn_manager::CLIS_DISCONNECTED;
    vpn->client.finalize_disconnect();
    dns_manager_delete_base(vpn->network_manager->dns, load_and_null(vpn->dns_base));
    socket_manager_complete_all(vpn->network_manager->socket);
    vpn->stop_pinging();
    vpn->postponement_window_timer.reset();
    vpn->ev_loop.reset();

    vpn->recovery = {};
    vpn->selected_endpoint_info = {};
    vpn->inactive_endpoints.clear();

    vpn->update_exclusions_task.release(); // The event loop is stopped, no need to reset()

    vpn->postponed_requests.clear();
    vpn->bypassed_connection_ids.clear();

    log_vpn(vpn, info, "Done");
}

void vpn_close(Vpn *vpn) {
    if (vpn == NULL) {
        return;
    }

    log_vpn(vpn, info, "...");
    vpn->client.deinit();

    log_vpn(vpn, info, "Done");
    delete vpn;
}

VpnListenerConfig vpn_get_listener_config(const Vpn *vpn) {
    std::unique_lock l(vpn->stop_guard);
    return vpn_listener_config_clone(&vpn->client.listener_config);
}

VpnListenerConfig vpn_listener_config_clone(const VpnListenerConfig *config) {
    return VpnListenerConfig{
            .timeout_ms = config->timeout_ms,
            .dns_upstream = safe_strdup(config->dns_upstream),
    };
}

void vpn_listener_config_destroy(VpnListenerConfig *config) {
    free((char *) config->dns_upstream);
    *config = {};
}

static void vpn_complete_connect_request_task(Vpn *vpn, ConnectRequestResult result) {
    log_vpn(vpn, dbg, "{}", result.to_string());

    result.action = vpn->client.finalize_connect_action(
            result, vpn->client.kill_switch_on && vpn->fsm.get_state() != VPN_SS_CONNECTED);

    vpn->fsm.perform_transition(vpn_fsm::CE_COMPLETE_REQUEST, &result);
}

void vpn_complete_connect_request(Vpn *vpn, const VpnConnectionInfo *info) {
    std::unique_lock l(vpn->stop_guard);

    if (vpn->ev_loop == nullptr) {
        log_vpn(vpn, warn, "Can't complete request {} since event loop doesn't exist", info->id);
        return;
    }

    ConnectRequestResult result = {
            info->id,
            info->action,
            (info->appname != nullptr) ? info->appname : "",
            info->uid,
    };

    vpn->submit([vpn, result = std::move(result)]() mutable {
        vpn_complete_connect_request_task(vpn, std::move(result));
    });
}

void vpn_update_exclusions(Vpn *vpn, VpnMode mode, VpnStr exclusions) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    struct Ctx {
        Vpn *vpn;
        VpnMode mode;
        std::string exclusions;
    };

    auto *ctx = new Ctx{
            .vpn = vpn,
            .mode = mode,
            .exclusions = {exclusions.data, exclusions.size},
    };

    vpn->update_exclusions_task = event_loop::submit(vpn->ev_loop.get(),
            {
                    .arg = ctx,
                    .action =
                            [](void *arg, TaskId task_id) {
                                auto *ctx = (Ctx *) arg;
                                ctx->vpn->client.reset_connections(-1);
                                ctx->vpn->client.update_exclusions(ctx->mode, ctx->exclusions);
                            },
                    .finalize =
                            [](void *arg) {
                                delete (Ctx *) arg;
                            },
            });

    log_vpn(vpn, info, "Done");
}

void vpn_reset_connections(Vpn *vpn, int uid) {
    log_vpn(vpn, info, "UID={}", uid);

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn, uid]() {
        vpn->client.reset_connections(uid);
    });

    log_vpn(vpn, info, "Done");
}

void vpn_notify_network_change(Vpn *vpn, bool network_loss_suspected) {
    log_vpn(vpn, info, "Loss suspected={}", network_loss_suspected);

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn, network_loss_suspected]() {
        vpn->fsm.perform_transition(vpn_fsm::CE_NETWORK_CHANGE, (void *) &network_loss_suspected);
    });

    log_vpn(vpn, info, "Done");
}

void vpn_request_endpoint_connection_stats(Vpn *vpn) {
    log_vpn(vpn, dbg, "...");

    std::unique_lock l(vpn->stop_guard);

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        VpnEndpointConnectionStatsEvent event = {{VPN_EC_ERROR, "Event loop is stopped"}};
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_ENDPOINT_CONNECTION_STATS, &event);
    }

    vpn->submit([vpn]() {
        VpnEndpointConnectionStatsEvent event = {};
        VpnSessionState state = (VpnSessionState) vpn->fsm.get_state();
        if (state == VPN_SS_CONNECTED) {
            event.protocol = vpn->client.endpoint_upstream->get_protocol();
            event.stats = vpn->client.get_connection_stats();
        } else {
            event.error = {VPN_EC_INVALID_STATE, "Invalid state"};
            log_vpn(vpn, dbg, "Can't get endpoint connection statistics in unsuitable state: {}",
                    magic_enum::enum_name(state));
        }
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_ENDPOINT_CONNECTION_STATS, &event);
    });

    log_vpn(vpn, dbg, "Done");
}

void vpn_notify_sleep(Vpn *vpn, void (*completion_handler)(void *), void *arg) {
    log_vpn(vpn, dbg, "...");

    std::unique_lock l(vpn->stop_guard);

    struct vpn_notify_sleep_ctx_t {
        void (*handler)(void *);
        void *handler_arg;
        Vpn *vpn;
    };

    // Completion handler MUST be called even if the task doesn't run
    vpn_event_loop_submit(vpn->ev_loop.get(),
            {
                    .arg = new vpn_notify_sleep_ctx_t{.handler = completion_handler, .handler_arg = arg, .vpn = vpn},
                    .action =
                            [](void *arg, TaskId id) {
                                auto *ctx = (vpn_notify_sleep_ctx_t *) arg;
                                ctx->vpn->client.handle_sleep();
                            },
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (vpn_notify_sleep_ctx_t *) arg;
                                assert(ctx->handler);
                                ctx->handler(ctx->handler_arg);
                                delete ctx;
                            },
            });

    log_vpn(vpn, dbg, "Done");
}

void vpn_notify_wake(Vpn *vpn) {
    log_vpn(vpn, dbg, "...");
    std::unique_lock l(vpn->stop_guard);
    vpn->submit([vpn] {
        vpn->client.handle_wake();
    });
    log_vpn(vpn, dbg, "Done");
}

VpnExclusionValidationStatus vpn_validate_exclusion(const char *text) {
    switch (DomainFilter::validate_entry(text)) {
    case DFVS_OK:
        return VPN_EVS_OK;
    case DFVS_MALFORMED:
        return VPN_EVS_MALFORMED;
    }

    return VPN_EVS_OK;
}

VpnDnsUpstreamValidationStatus vpn_validate_dns_upstream(const char *address) {
    dns::UpstreamOptions opts = {
            .address = address,
            .bootstrap = {"1.1.1.1"},
    };
    std::optional err = dns::test_upstream(opts, true, nullptr, true);
    if (err.has_value()) {
        ag::Logger log{__func__};
        dbglog(log, "{}", *err);
        return VPN_DUVS_MALFORMED;
    }

    return VPN_DUVS_OK;
}

std::vector<VpnPacket> c_packets_to_vector(const VpnPackets &packets) {
    return std::vector<VpnPacket>{packets.data, packets.data + packets.size};
}

VpnPackets to_c_packets(std::vector<VpnPacket> &packets) {
    return VpnPackets{packets.data(), (uint32_t) packets.size()};
}

void vpn_process_client_packets(Vpn *vpn, VpnPackets packets) {
    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn, packets_vector = c_packets_to_vector(packets)]() mutable {
        VpnPackets packets = to_c_packets(packets_vector);
        vpn->client.process_client_packets(packets);
    });
}

static int ssl_verify_callback(const char *host_name, const sockaddr *host_ip, X509_STORE_CTX *ctx, void *arg) {
    const Vpn *vpn = (Vpn *) arg;

    X509 *cert = X509_STORE_CTX_get0_cert(ctx);
    if ((host_name != nullptr || (host_ip != nullptr && host_ip->sa_family != AF_UNSPEC))
            && (host_name == nullptr || !tls_verify_cert_host_name(cert, host_name))
            && (host_ip == nullptr || host_ip->sa_family == AF_UNSPEC
                    || !tls_verify_cert_ip(cert, sockaddr_to_str(host_ip).c_str()))) {
        log_vpn(vpn, err, "Server host name or IP doesn't match certificate");
        return 0;
    }

    int result = 0;
    VpnVerifyCertificateEvent event = {ctx, 0};
    vpn->handler.func(vpn->handler.arg, VPN_EVENT_VERIFY_CERTIFICATE, &event);
    if (event.result == 0) {
        result = 1;
    } else {
        log_vpn(vpn, err, "Failed to verify certificate");
    }

    return result;
}

static void client_handler(void *arg, vpn_client::Event what, void *data) {
    Vpn *vpn = (Vpn *) arg;

    switch (what) {
    case vpn_client::EVENT_PROTECT_SOCKET:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_PROTECT_SOCKET, data);
        break;
    case vpn_client::EVENT_VERIFY_CERTIFICATE:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_VERIFY_CERTIFICATE, data);
        break;
    case vpn_client::EVENT_CONNECTED:
        vpn->client_state = vpn_manager::CLIS_CONNECTED;
        vpn->fsm.perform_transition(vpn_fsm::CE_CLIENT_READY, nullptr);
        break;
    case vpn_client::EVENT_OUTPUT:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_CLIENT_OUTPUT, data);
        break;
    case vpn_client::EVENT_CONNECT_REQUEST:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_CONNECT_REQUEST, data);
        break;
    case vpn_client::EVENT_ERROR:
    case vpn_client::EVENT_DISCONNECTED:
        vpn->client_state = vpn_manager::CLIS_DISCONNECTED;
        vpn->fsm.perform_transition(vpn_fsm::CE_CLIENT_DISCONNECTED, data);
        break;
    case vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE, data);
        break;
    }
}

static void shutdown_cb(Vpn *vpn) {
    vpn->fsm.perform_transition(vpn_fsm::CE_SHUTDOWN, nullptr);
}

static const char *check_address(const sockaddr_storage *addr) {
    switch (addr->ss_family) {
    case AF_INET: {
        const sockaddr_in *v4 = (sockaddr_in *) addr;
        return (v4->sin_port > 0) ? nullptr : "Port must be specified";
    }
    case AF_INET6: {
        const sockaddr_in6 *v6 = (sockaddr_in6 *) addr;
        return (v6->sin6_port > 0) ? nullptr : "Port must be specified";
    }
    case AF_UNSPEC:
        return nullptr;
    default:
        return "Unknown family";
    }
}

VpnEventLoop *vpn_get_event_loop(Vpn *vpn) {
    std::unique_lock l(vpn->stop_guard);
    return vpn->ev_loop.get();
}

void vpn_abandon_current_endpoint(Vpn *vpn) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn]() {
        vpn->fsm.perform_transition(vpn_fsm::CE_ABANDON_ENDPOINT, nullptr);
    });

    log_vpn(vpn, info, "Done");
}

VpnListener *vpn_create_tun_listener(Vpn *, const VpnTunListenerConfig *config) {
    return std::make_unique<TunListener>(config).release();
}

VpnListener *vpn_create_socks_listener(Vpn *, const VpnSocksListenerConfig *config) {
    return std::make_unique<SocksListener>(config).release();
}

sockaddr_storage vpn_get_socks_listener_address(Vpn *vpn) {
    sockaddr_storage ret{};
    std::scoped_lock l(vpn->stop_guard);
    event_loop::dispatch_sync(vpn->ev_loop.get(), [&]() mutable {
        ret = vpn->client.socks_listener_address;
    });
    return ret;
}

} // namespace ag
