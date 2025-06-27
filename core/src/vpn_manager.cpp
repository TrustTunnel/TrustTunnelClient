#include <algorithm>
#include <atomic>
#include <chrono>

#include <magic_enum/magic_enum.hpp>

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

struct ProfilingVpnHandlerCtx {
    VpnHandler handler;
    Vpn *vpn;
};

static int ssl_verify_callback(const char *host_name, const sockaddr *host_ip, const CertVerifyCtx &ctx, void *arg);
static void client_handler(void *arg, vpn_client::Event what, void *data);
static void shutdown_cb(Vpn *vpn);
static const char *check_address(const sockaddr_storage *addr);
static void profiling_vpn_handler(void *arg, VpnEvent what, void *data);

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

Vpn::~Vpn() = default;

void Vpn::update_upstream_config(AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> config) {
    this->upstream_config = std::move(config);

    if (!this->upstream_config->fallback.enabled && this->upstream_config->protocol.type == VPN_UP_HTTP3) {
        log_vpn(this, info, "Forcibly setting HTTP/2 as fallback protocol");
        this->upstream_config->fallback.enabled = true;
        this->upstream_config->fallback.protocol.type = VPN_UP_HTTP2;
    }

    if (this->upstream_config->location_ping_timeout_ms == 0) {
        this->upstream_config->location_ping_timeout_ms = DEFAULT_PING_TIMEOUT_MS;
    }
    if (this->upstream_config->timeout_ms == 0) {
        this->upstream_config->timeout_ms = VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS;
    }
    if (this->upstream_config->health_check_timeout_ms == 0) {
        this->upstream_config->health_check_timeout_ms = VPN_DEFAULT_HEALTH_CHECK_TIMEOUT_MS;
    }
    this->upstream_config->health_check_timeout_ms =
            std::min(this->upstream_config->health_check_timeout_ms, this->upstream_config->timeout_ms);
    if (this->upstream_config->recovery.backoff_rate < 1) {
        this->upstream_config->recovery.backoff_rate = VPN_DEFAULT_RECOVERY_BACKOFF_RATE;
    }
    if (this->upstream_config->recovery.location_update_period_ms == 0) {
        this->upstream_config->recovery.location_update_period_ms = VPN_DEFAULT_RECOVERY_LOCATION_UPDATE_PERIOD_MS;
    }
    if (VpnUpstreamFallbackConfig &fallback = this->upstream_config->fallback; fallback.enabled) {
        if (fallback.connect_delay_ms == 0) {
            fallback.connect_delay_ms = VPN_DEFAULT_FALLBACK_CONNECT_DELAY_MS;
        }
    }
}

vpn_client::Parameters Vpn::make_client_parameters() const {
    return {
            this->ev_loop.get(),
            this->network_manager.get(),
            {client_handler, (void *) this},
            {ssl_verify_callback, (void *) this},
    };
}

vpn_client::EndpointConnectionConfig Vpn::make_client_upstream_config() const {
    AutoVpnEndpoint endpoint = vpn_endpoint_clone(this->selected_endpoint.value().endpoint.get()); // NOLINT(bugprone-unchecked-optional-access)
    if (this->selected_endpoint->relay.has_value()) {
        AutoVpnRelay relay = vpn_relay_clone(this->selected_endpoint->relay.value().get());
        endpoint->address = relay->address;
        std::swap(endpoint->additional_data.data, relay->additional_data.data);
        std::swap(endpoint->additional_data.size, relay->additional_data.size);
    }
    return {
            .main_protocol = this->upstream_config->protocol,
            .fallback = this->upstream_config->fallback,
            .endpoint = std::move(endpoint),
            .timeout = Millis{this->upstream_config->timeout_ms},
            .health_check_timeout = Millis{this->upstream_config->health_check_timeout_ms},
            .username = this->upstream_config->username,
            .password = this->upstream_config->password,
            .ip_availability =
                    [this] {
                        const VpnEndpoints &endpoints = this->upstream_config->location.endpoints;
                        // IPv4 is considered always available on an endpoint
                        IpVersionSet ret = IpVersionSet{}.set(IPV4);
                        ret.set(IPV6,
                                std::any_of(endpoints.data, endpoints.data + endpoints.size,
                                        [](const VpnEndpoint &e) -> bool {
                                            return e.address.ss_family == AF_INET6;
                                        }));
                        return ret;
                    }(),
            .anti_dpi = this->upstream_config->anti_dpi,
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
    this->ping_failure_induces_location_unavailable = false;
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
        vpn_event_loop_stop(this->ev_loop.get());
        if (this->executor_thread.joinable()) {
            this->executor_thread.join();
        }
        assert(0);
        return false;
    }

    log_vpn(this, info, "Event loop has been started");

    return true;
}

void Vpn::submit(std::function<void()> &&func, std::optional<Millis> defer) {
    VpnEventLoopTask task = {
            new std::function(std::move(func)),
            [](void *arg, TaskId) {
                auto *func = (std::function<void()> *) arg;
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

    if (vpn_handler_profiling_enabled()) {
        vpn->handler.func = &profiling_vpn_handler;
        vpn->handler.arg = new ProfilingVpnHandlerCtx{.handler = settings->handler, .vpn = vpn.get()};
    } else {
        vpn->handler = settings->handler;
    }

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
            log_vpn(vpn, err, "No hostname for endpoint '{}'", sockaddr_to_str((sockaddr *) &i_ep->address));
            return {VPN_EC_INVALID_SETTINGS, "Names must be specified for each endpoint"};
        }

        if (config->location.endpoints.size > 1 && i_ep->address.ss_family == AF_UNSPEC) {
            log_vpn(vpn, err, "No address for endpoint '{}'", i_ep->name);
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

    vpn->submit([vpn,
                        cfg = std::make_shared<decltype(vpn->upstream_config)>(
                                vpn_upstream_config_clone(&parameters->upstream_config)),
                        retry_info = std::move(retry_info)]() mutable {
        vpn->client.update_parameters(vpn->make_client_parameters());
        vpn->update_upstream_config(std::move(*cfg));
        vpn->connect_retry_info = std::move(retry_info);
        if (auto *several_attempts = std::get_if<vpn_manager::ConnectSeveralAttempts>(&vpn->connect_retry_info);
                several_attempts != nullptr) {
            several_attempts->attempts_left -= 1;
        }
        vpn->fsm.perform_transition(vpn_fsm::CE_DO_CONNECT, nullptr);
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

void vpn_force_disconnect(Vpn *vpn, bool fatal_connectivity_error) {
    log_vpn(vpn, info, "...");

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn, fatal_connectivity_error]() {
        if (fatal_connectivity_error) {
            vpn->pending_error = {.code = VPN_EC_FATAL_CONNECTIVITY_ERROR, .text = "Fatal connectivity error occurred"};
        }
        shutdown_cb(vpn);
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
    socket_manager_complete_all(vpn->network_manager->socket);
    vpn->stop_pinging();
    vpn->postponement_window_timer.reset();
    vpn->ev_loop.reset();

    vpn->recovery = {};
    vpn->selected_endpoint.reset();

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

    if (vpn->handler.func == &profiling_vpn_handler) {
        delete (ProfilingVpnHandlerCtx *) vpn->handler.arg;
    }

    log_vpn(vpn, info, "Done");
    delete vpn;
}

VpnListenerConfig vpn_get_listener_config(const Vpn *vpn) {
    std::unique_lock l(vpn->stop_guard);
    return vpn_listener_config_clone(&vpn->client.listener_config);
}

VpnListenerConfig vpn_listener_config_clone(const VpnListenerConfig *config) {
    VpnListenerConfig out = *config;

    out.dns_upstreams.data = new const char *[config->dns_upstreams.size];
    out.dns_upstreams.size = config->dns_upstreams.size;
    for (size_t i = 0; i < out.dns_upstreams.size; ++i) {
        out.dns_upstreams.data[i] = safe_strdup(config->dns_upstreams.data[i]);
    }

    return out;
}

void vpn_listener_config_destroy(VpnListenerConfig *config) {
    for (size_t i = 0; i < config->dns_upstreams.size; ++i) {
        free((char *) config->dns_upstreams.data[i]);
    }
    delete[] config->dns_upstreams.data;

    *config = {};
}

static void vpn_complete_connect_request_task(Vpn *vpn, ConnectRequestResult result) {
    log_vpn(vpn, dbg, "{}", result.to_string());

    result.action = vpn->client.finalize_connect_action(std::move(result));

    vpn->fsm.perform_transition(vpn_fsm::CE_COMPLETE_REQUEST, &result);
}

void vpn_complete_connect_request(Vpn *vpn, const VpnConnectionInfo *info) {
    std::unique_lock l(vpn->stop_guard);

    if (vpn->ev_loop.get() == nullptr) {
        log_vpn(vpn, warn, "Can't complete request {} since event loop is not active", info->id);
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

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        log_vpn(vpn, warn, "Can't update exclusions since event loop is not active");
        return;
    }

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
                            [](void *arg, TaskId) {
                                auto *ctx = (Ctx *) arg;
                                ctx->vpn->update_exclusions_task.release();
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

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        log_vpn(vpn, warn, "Can't reset connections since event loop is not active");
        return;
    }

    vpn->submit([vpn, uid]() {
        vpn->client.reset_connections(uid);
    });

    log_vpn(vpn, info, "Done");
}

void vpn_notify_network_change(Vpn *vpn, VpnNetworkState state) {
    log_vpn(vpn, info, "state={}", magic_enum::enum_name(state));

    std::unique_lock l(vpn->stop_guard);

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        log_vpn(vpn, warn, "Can't notify network change since event loop is not active");
        return;
    }

    vpn->submit([vpn, state] {
        vpn->client.on_network_change();
        vpn->network_changed_before_recovery = true;
        vpn->fsm.perform_transition(vpn_fsm::CE_NETWORK_CHANGE, (void *) &state);
    });

    log_vpn(vpn, info, "Done");
}

void vpn_request_endpoint_connection_stats(Vpn *vpn) {
    log_vpn(vpn, dbg, "...");

    std::unique_lock l(vpn->stop_guard);

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        VpnEndpointConnectionStatsEvent event = {{VPN_EC_ERROR, "Event loop is stopped"}};
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_ENDPOINT_CONNECTION_STATS, &event);
        return;
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
    log_vpn(vpn, info, "System is going to sleep");

    std::unique_lock l(vpn->stop_guard);

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        log_vpn(vpn, warn, "Can't notify sleep since event loop is not active");
        return;
    }

    // Completion handler MUST be called even if the task doesn't run
    std::shared_ptr<void> complete(
        nullptr, [=](void *) {
            completion_handler(arg);
        }
    );

    event_loop::submit(vpn->ev_loop.get(), [vpn, complete]{
        vpn->client.handle_sleep();
        event_loop::submit(vpn->ev_loop.get(), [complete] {
        }).release();
    }).release();

    l.unlock();
    // completion handler may be ran here unlocked
}

void vpn_notify_wake(Vpn *vpn) {
    log_vpn(vpn, info, "System has woken up");
    std::unique_lock l(vpn->stop_guard);

    if (!vpn_event_loop_is_active(vpn->ev_loop.get())) {
        log_vpn(vpn, warn, "Can't notify wake since event loop is not active");
        return;
    }

    event_base_update_cache_time(vpn_event_loop_get_base(vpn->ev_loop.get()));

    vpn->submit([vpn] {
        vpn->client.handle_wake();
    });
}

VpnExclusionValidationStatus vpn_validate_exclusion(const char *text) {
    switch (DomainFilter::validate_entry(text)) {
    case DFVS_OK_ADDR:
    case DFVS_OK_CIDR:
    case DFVS_OK_DOMAIN:
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
    Error<dns::UpstreamUtilsError> err = dns::test_upstream(opts, {}, true, nullptr, true);
    if (err != nullptr) {
        ag::Logger log{__func__};
        dbglog(log, "{}", err->str());
        return VPN_DUVS_MALFORMED;
    }

    return VPN_DUVS_OK;
}

bool vpn_process_client_packets(Vpn *vpn, VpnPackets packets) {
    std::unique_lock l(vpn->stop_guard);

    auto packets_holder = std::make_shared<VpnPacketsHolder>(packets);

    if (!vpn->ev_loop) {
        return false;
    }

    vpn->submit([vpn, packets_holder = std::move(packets_holder)]() mutable {
        auto packets = packets_holder->release();
        vpn->client.process_client_packets({packets.data(), (uint32_t) packets.size()});
    });

    return true;
}

static int ssl_verify_callback(const char *host_name, const sockaddr *host_ip, const CertVerifyCtx &ctx, void *arg) {
    const Vpn *vpn = (Vpn *) arg;

    int result = 0;
    VpnVerifyCertificateEvent event = {ctx.cert, ctx.chain, 0};
    vpn->handler.func(vpn->handler.arg, VPN_EVENT_VERIFY_CERTIFICATE, &event);
    if (event.result == 0) {
        result = 1;
    } else if (event.result == VPN_SKIP_VERIFICATION_FLAG) {
        result = 1;
        return result;
    } else {
        log_vpn(vpn, err, "Failed to verify certificate");
#ifdef OPENSSL_IS_BORINGSSL
        if (ctx.ssl) {
            SSL_send_fatal_alert(ctx.ssl, SSL_AD_UNKNOWN_CA);
        }
#endif
    }

    if ((host_name != nullptr || (host_ip != nullptr && host_ip->sa_family != AF_UNSPEC))
            && (host_name == nullptr || !tls_verify_cert_host_name(ctx.cert, host_name))
            && (host_ip == nullptr || host_ip->sa_family == AF_UNSPEC
                    || !tls_verify_cert_ip(ctx.cert, sockaddr_to_str(host_ip).c_str()))) {
        log_vpn(vpn, err, "Server host name or IP doesn't match certificate");
#ifdef OPENSSL_IS_BORINGSSL
        if (ctx.ssl) {
            SSL_send_fatal_alert(ctx.ssl, SSL_AD_CERTIFICATE_UNKNOWN);
        }
#endif
        return 0;
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
    case vpn_client::EVENT_CONNECTION_STATS:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_TUNNEL_CONNECTION_STATS, data);
        break;
    case vpn_client::EVENT_CONNECTION_CLOSED:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_TUNNEL_CONNECTION_CLOSED, data);
        break;
    case vpn_client::EVENT_CONNECTION_INFO:
        vpn->handler.func(vpn->handler.arg, VPN_EVENT_CONNECTION_INFO, data);
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

void vpn_abandon_endpoint(Vpn *vpn, const VpnEndpoint *endpoint) {
    log_vpn(vpn, info, "{}", *endpoint);

    std::unique_lock l(vpn->stop_guard);

    vpn->submit([vpn, endpoint = std::make_shared<AutoVpnEndpoint>(vpn_endpoint_clone(endpoint))]() mutable {
        bool is_selected_endpoint = vpn->selected_endpoint.has_value()
                && vpn_endpoint_equals(vpn->selected_endpoint->endpoint.get(), endpoint->get());
        if (is_selected_endpoint) {
            vpn->selected_endpoint.reset();
        }

        VpnEndpoint *endpoints_end =
                vpn->upstream_config->location.endpoints.data + vpn->upstream_config->location.endpoints.size;
        VpnEndpoint *abandoned = swap_remove_if(vpn->upstream_config->location.endpoints.data, endpoints_end,
                [seek = endpoint->get()](const VpnEndpoint &iter) {
                    return vpn_endpoint_equals(seek, &iter);
                });
        if (abandoned == endpoints_end) {
            log_vpn(vpn, dbg, "Abandoning endpoint is not found in upstream location");
        }

        vpn->upstream_config->location.endpoints.size -= std::distance(abandoned, endpoints_end);
        while (abandoned != endpoints_end) {
            vpn_endpoint_destroy(abandoned++);
        }

        endpoints_end = vpn->upstream_config->location.endpoints.data + vpn->upstream_config->location.endpoints.size;
        if (int abandoned_family = endpoint->get()->address.ss_family;
                std::none_of(vpn->upstream_config->location.endpoints.data, endpoints_end,
                        [abandoned_family](const VpnEndpoint &iter) {
                            return abandoned_family == iter.address.ss_family;
                        })) {
            vpn->pending_error = (vpn->upstream_config->location.endpoints.size == 0)
                    ? VpnError{VPN_EC_LOCATION_UNAVAILABLE, "Exhausted all endpoints of location"}
                    : ((abandoned_family == AF_INET)
                                      ? VpnError{VPN_EC_LOCATION_UNAVAILABLE, "Exhausted IPv4 endpoints of location"}
                                      : VpnError{VPN_EC_LOCATION_UNAVAILABLE, "Exhausted IPv6 endpoints of location"});
            log_vpn(vpn, info, "{}", vpn->pending_error->text);
            vpn_endpoints_destroy(&vpn->upstream_config->location.endpoints);
        } else if (!is_selected_endpoint) {
            assert(vpn->upstream_config->location.endpoints.size > 0);
            return;
        } else {
            vpn->pending_error = {VPN_EC_ERROR, "Current endpoint is abandoned"};
            log_vpn(vpn, dbg, "{}", vpn->pending_error->text);
            vpn->ping_failure_induces_location_unavailable = true;
        }
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

void profiling_vpn_handler(void *arg, VpnEvent what, void *data) {
    auto *ctx = (ProfilingVpnHandlerCtx *) arg;
    if (what == VPN_EVENT_CLIENT_OUTPUT) {
        ctx->handler.func(ctx->handler.arg, what, data);
        return;
    }
    auto start = high_resolution_clock::now();
    ctx->handler.func(ctx->handler.arg, what, data);
    auto end = high_resolution_clock::now();
    int64_t dt = duration_cast<nanoseconds>(end - start).count();
    if (int64_t threshold = vpn_handler_profiling_threshold_ns(); dt > threshold) {
        log_vpn(ctx->vpn, warn, "Handler for {} ran for {} ms, threshold: {} ms", magic_enum::enum_name(what),
                dt / 1'000'000.0, threshold / 1'000'000.0);
    }
}

} // namespace ag
