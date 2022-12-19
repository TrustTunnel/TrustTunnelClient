#include <atomic>
#include <cassert>
#include <chrono>

#include <event2/util.h>

#include "direct_upstream.h"
#include "fallbackable_upstream_connector.h"
#include "http2_upstream.h"
#include "http3_upstream.h"
#include "memfile_buffer.h"
#include "memory_buffer.h"
#include "single_upstream_connector.h"
#include "socks_listener.h"
#include "upstream_multiplexer.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/tunnel.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/platform.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

#define log_client(cli_, lvl_, fmt_, ...) lvl_##log((cli_)->log, "[{}] " fmt_, (cli_)->id, ##__VA_ARGS__)

namespace ag {

static std::atomic_int g_next_id = 0;
static constexpr std::string_view DNS_PROXY_CHECK_DOMAIN = "ipv4only.arpa";

using namespace std::chrono;

namespace vpn_client {

enum State {
    S_DISCONNECTED,
    S_CONNECTING,
    S_CONNECTED,
    S_DISCONNECTING,
};

enum SessionEvent {
    E_RUN_CONNECT,
    E_DISCONNECT,
    E_DEFERRED_DISCONNECT,
    E_RUN_PREPARATION_FAIL,
    E_SESSION_OPENED,
    E_SESSION_CLOSED,
    E_SESSION_ERROR,
    E_HEALTH_CHECK_READY,
};

static constexpr auto STATE_NAMES = make_enum_names_array<State>();
static constexpr auto EVENT_NAMES = make_enum_names_array<SessionEvent>();

static bool is_successful(const void *ctx, void *data);

static void run_connect(void *ctx, void *data);
static void schedule_health_check(void *ctx, void *data);
static void raise_connected(void *ctx, void *data);
static void raise_disconnected(void *ctx, void *data);
static void run_disconnect(void *ctx, void *data);
static void submit_disconnect(void *ctx, void *data);

// clang-format off
static constexpr FsmTransitionEntry TRANSITION_TABLE[] = {
        {S_DISCONNECTED,        E_RUN_CONNECT,          Fsm::ANYWAY,    run_connect,           S_CONNECTING,           Fsm::DO_NOTHING},
        {S_DISCONNECTED,        E_SESSION_CLOSED,       Fsm::ANYWAY,    Fsm::DO_NOTHING,       S_DISCONNECTED,         raise_disconnected},
        {S_DISCONNECTED,        E_DISCONNECT,           Fsm::ANYWAY,    Fsm::DO_NOTHING,       S_DISCONNECTED,         Fsm::DO_NOTHING},

        {S_CONNECTING,          E_SESSION_OPENED,       Fsm::ANYWAY,    schedule_health_check, S_CONNECTED,            raise_connected},
        {S_CONNECTING,          E_SESSION_CLOSED,       Fsm::ANYWAY,    Fsm::DO_NOTHING,       S_DISCONNECTED,         raise_disconnected},

        {S_CONNECTED,           E_SESSION_CLOSED,       Fsm::ANYWAY,    Fsm::DO_NOTHING,       S_DISCONNECTED,         raise_disconnected},
        {S_CONNECTED,           E_SESSION_ERROR,        Fsm::ANYWAY,    submit_disconnect,     S_DISCONNECTING,        Fsm::DO_NOTHING},
        {S_CONNECTED,           E_RUN_PREPARATION_FAIL, Fsm::ANYWAY,    submit_disconnect,     S_DISCONNECTING,        Fsm::DO_NOTHING},
        {S_CONNECTED,           E_HEALTH_CHECK_READY,   is_successful,  schedule_health_check, Fsm::SAME_TARGET_STATE, Fsm::DO_NOTHING},
        {S_CONNECTED,           E_HEALTH_CHECK_READY,   Fsm::OTHERWISE, submit_disconnect,     S_DISCONNECTING,        Fsm::DO_NOTHING},

        {S_DISCONNECTING,       E_SESSION_CLOSED,       Fsm::ANYWAY,    Fsm::DO_NOTHING,       S_DISCONNECTED,         raise_disconnected},
        {S_DISCONNECTING,       E_DISCONNECT,           Fsm::ANYWAY,    Fsm::DO_NOTHING,       Fsm::SAME_TARGET_STATE, Fsm::DO_NOTHING},
        {S_DISCONNECTING,       E_DEFERRED_DISCONNECT,  Fsm::ANYWAY,    run_disconnect,        S_DISCONNECTED,         raise_disconnected},

        {Fsm::ANY_SOURCE_STATE, E_DISCONNECT,           Fsm::ANYWAY,    run_disconnect,        S_DISCONNECTED,         Fsm::DO_NOTHING},
};
// clang-format on

} // namespace vpn_client

static VpnError start_dns_proxy(VpnClient *self);

static void release_deferred_task(VpnClient *self, TaskId task) {
    if (auto n = self->deferred_tasks.extract(event_loop::make_auto_id(task)); !n.empty()) {
        n.value().release();
    }
}

static void endpoint_connector_finalizer(void *arg, TaskId task_id) {
    auto *self = (VpnClient *) arg;
    release_deferred_task(self, task_id);
    self->endpoint_connector.reset();

    if (self->pending_error.has_value()) {
        self->fsm.perform_transition(vpn_client::E_SESSION_CLOSED, nullptr);
        return;
    }

    self->tunnel->upstream_handler(self->endpoint_upstream.get(), SERVER_EVENT_SESSION_OPENED, nullptr);
    self->fsm.perform_transition(vpn_client::E_SESSION_OPENED, nullptr);

    // reconnect or `listen` was called before connection procedure completion
    if (self->client_listener != nullptr) {
        self->tunnel->on_exclusions_updated();
        if (self->dns_proxy != nullptr && !self->do_dns_upstream_health_check()) {
            log_client(self, dbg, "Failed to start DNS upstream health check");
            VpnDnsUpstreamUnavailableEvent event = {
                    .upstream = self->listener_config.dns_upstream,
            };
            self->parameters.handler.func(
                    self->parameters.handler.arg, vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, &event);
        }
    }
}

static void endpoint_connector_handler(void *arg, EndpointConnectorResult result) {
    auto *self = (VpnClient *) arg;

    self->pending_error.reset();
    if (const auto *e = std::get_if<VpnError>(&result); e != nullptr) {
        self->pending_error = *e;
    } else {
        self->endpoint_upstream = std::move(std::get<std::unique_ptr<ServerUpstream>>(result));
        if (self->listener_config.dns_upstream != nullptr && self->dns_proxy == nullptr) {
            VpnError error = start_dns_proxy(self);
            if (error.code != VPN_EC_NOERROR) {
                self->pending_error = error;
            }
        }
    }

    self->deferred_tasks.emplace(event_loop::submit(self->parameters.ev_loop,
            {
                    .arg = self,
                    .action = endpoint_connector_finalizer,
            }));
}

static void vpn_upstream_handler(void *arg, ServerEvent what, void *data) {
    auto *vpn = (VpnClient *) arg;
    assert(vpn->endpoint_connector == nullptr);

    bool is_disconnected =
            what == SERVER_EVENT_SESSION_CLOSED || (what == SERVER_EVENT_ERROR && ((ServerError *) data)->id == NON_ID);
    if (is_disconnected) {
        vpn->tunnel->on_before_endpoint_disconnect(vpn->endpoint_upstream.get());
    }

    vpn->tunnel->upstream_handler(vpn->endpoint_upstream.get(), what, data);

    switch (what) {
    case SERVER_EVENT_SESSION_OPENED: {
        assert(0);
        break;
    }
    case SERVER_EVENT_SESSION_CLOSED: {
        log_client(vpn, dbg, "Server session is closed");
        vpn->fsm.perform_transition(vpn_client::E_SESSION_CLOSED, nullptr);
        break;
    }
    case SERVER_EVENT_HEALTH_CHECK_RESULT: {
        const VpnError *error = (VpnError *) data;
        if (error == nullptr || error->code == VPN_EC_NOERROR) {
            log_client(vpn, dbg, "Health check succeeded");
        } else {
            log_client(vpn, dbg, "Health check error: {} ({})", error->text, error->code);
        }
        vpn->fsm.perform_transition(vpn_client::E_HEALTH_CHECK_READY, data);
        break;
    }
    case SERVER_EVENT_ERROR: {
        const ServerError *event = (ServerError *) data;
        if (event->id != NON_ID) {
            break;
        }

        log_client(vpn, dbg, "Server session terminated with error: {} ({})", safe_to_string_view(event->error.text),
                event->error.code);
        vpn->fsm.perform_transition(vpn_client::E_SESSION_ERROR, (void *) &event->error);
        break;
    }
    case SERVER_EVENT_CONNECTION_OPENED:
    case SERVER_EVENT_CONNECTION_CLOSED:
    case SERVER_EVENT_READ:
    case SERVER_EVENT_DATA_SENT:
    case SERVER_EVENT_GET_AVAILABLE_TO_SEND:
    case SERVER_EVENT_ECHO_REPLY:
        // do nothing
        break;
    }

    if (is_disconnected) {
        vpn->tunnel->on_after_endpoint_disconnect(vpn->endpoint_upstream.get());
    }
}

static void direct_upstream_handler(void *arg, ServerEvent what, void *data) {
    auto *vpn = (VpnClient *) arg;
    vpn->tunnel->upstream_handler(vpn->bypass_upstream.get(), what, data);
}

static void listener_handler(void *arg, ClientEvent what, void *data) {
    auto *vpn = (VpnClient *) arg;
    vpn->tunnel->listener_handler(vpn->client_listener.get(), what, data);
}

static void dns_proxy_listener_handler(void *arg, ClientEvent what, void *data) {
    auto *vpn = (VpnClient *) arg;
    vpn->tunnel->listener_handler(vpn->dns_proxy_listener.get(), what, data);
}

static void dns_resolver_handler(void *arg, VpnDnsResolveId, VpnDnsResolverResult result) {
    auto *self = (VpnClient *) arg;

    if (std::holds_alternative<VpnDnsResolverSuccess>(result)) {
        log_client(self, dbg, "DNS resolver health check succeeded");
    } else if (self->fsm.get_state() != vpn_client::S_CONNECTED) {
        log_client(self, dbg, "Ignoring DNS resolver health check failure due to state: {}",
                magic_enum::enum_name<>(vpn_client::State(self->fsm.get_state())));
    } else if (self->in_disconnect) {
        log_client(self, dbg, "Ignoring DNS resolver health check failure while disconnecting by next level");
    } else {
        log_client(self, dbg, "DNS resolver health check failed");
        VpnDnsUpstreamUnavailableEvent event = {
                .upstream = self->listener_config.dns_upstream,
        };
        self->parameters.handler.func(self->parameters.handler.arg, vpn_client::EVENT_DNS_UPSTREAM_UNAVAILABLE, &event);
    }
}

static FsmParameters make_fsm_params(VpnClient *vpn) {
    return {vpn_client::S_DISCONNECTED,
            FsmTransitionTable{std::begin(vpn_client::TRANSITION_TABLE), std::end(vpn_client::TRANSITION_TABLE)}, vpn,
            vpn_client::LOG_NAME, vpn_client::STATE_NAMES.data(), vpn_client::EVENT_NAMES.data()};
}

VpnClient::VpnClient(vpn_client::Parameters parameters)
        : fsm(make_fsm_params(this))
        , parameters(parameters)
        , id(g_next_id++) {
}

VpnError VpnClient::init(const VpnSettings *settings) {
    log_client(this, dbg, "...");

    this->kill_switch_on = settings->killswitch_enabled;
    update_exclusions(settings->mode, {settings->exclusions.data, settings->exclusions.size});

    if (settings->tmp_files_base_path != nullptr) {
        this->tmp_files_base_path = settings->tmp_files_base_path;
        if (this->tmp_files_base_path->back() == '/') {
            this->tmp_files_base_path->pop_back();
        }

        this->conn_memory_buffer_threshold = settings->conn_memory_buffer_threshold;
        if (settings->conn_memory_buffer_threshold == 0) {
            this->conn_memory_buffer_threshold = VPN_DEFAULT_CONN_MEMORY_BUFFER_THRESHOLD;
        }
        this->max_conn_buffer_file_size = settings->max_conn_buffer_file_size;
        if (settings->max_conn_buffer_file_size == 0) {
            this->max_conn_buffer_file_size = VPN_DEFAULT_MAX_CONN_BUFFER_FILE_SIZE;
        }
    }

    VpnError error = {};

    if (!this->tunnel->init(this)) {
        error = {VPN_EC_INVALID_SETTINGS, "Failed to initialize connection tunnelling module"};
        goto fail;
    }

    this->bypass_upstream = std::make_unique<DirectUpstream>(next_upstream_id());
    if (!this->bypass_upstream->init(this, {&direct_upstream_handler, this})) {
        error = {VPN_EC_INVALID_SETTINGS, "Failed to initialize an upstream for bypassed connections"};
        goto fail;
    }

    log_client(this, dbg, "Done");
    goto exit;

fail:
    log_client(this, err, "Failed: {} ({})", safe_to_string_view(error.text), error.code);

exit:
    return error;
}

static VpnError client_connect(VpnClient *vpn, std::optional<Millis> timeout) {
    log_client(vpn, dbg, "...");

    vpn->fsm.perform_transition(vpn_client::E_RUN_CONNECT, &timeout);

    if (!vpn->pending_error.has_value()) {
        log_client(vpn, dbg, "Started");
    } else {
        log_client(vpn, dbg, "Failed: {} ({})", vpn->pending_error->text, vpn->pending_error->code);
    }

    return std::exchange(vpn->pending_error, std::nullopt).value_or(VpnError{});
}

static void submit_health_check(VpnClient *vpn, milliseconds postpone) {
    vpn->deferred_tasks.emplace(event_loop::schedule(vpn->parameters.ev_loop,
            {
                    vpn,
                    [](void *arg, TaskId task_id) {
                        auto *vpn = (VpnClient *) arg;
                        release_deferred_task(vpn, task_id);

                        if (vpn->fsm.get_state() != vpn_client::S_CONNECTED) {
                            log_client(vpn, dbg, "Ignore submitted health check due to state: {}",
                                    magic_enum::enum_name((vpn_client::State) vpn->fsm.get_state()));
                            return;
                        }

                        VpnError error = vpn->endpoint_upstream->do_health_check();
                        if (error.code != VPN_EC_NOERROR) {
                            vpn->fsm.perform_transition(vpn_client::E_HEALTH_CHECK_READY, &error);
                        }
                    },
            },
            postpone));
}

static std::unique_ptr<ServerUpstream> make_upstream(const VpnUpstreamProtocolConfig &protocol) {
    std::unique_ptr<ServerUpstream> upstream;

    switch (protocol.type) {
    case VPN_UP_HTTP2:
        upstream = std::make_unique<UpstreamMultiplexer>(VpnClient::next_upstream_id(), protocol,
                protocol.http2.connections_num,
                [](const VpnUpstreamProtocolConfig &protocol_config, int id, VpnClient *vpn,
                        ServerHandler handler) -> std::unique_ptr<MultiplexableUpstream> {
                    return std::make_unique<Http2Upstream>(protocol_config, id, vpn, handler);
                });
        break;
    case VPN_UP_HTTP3:
        upstream = std::make_unique<Http3Upstream>(VpnClient::next_upstream_id(), protocol);
        break;
    }

    return upstream;
}

static VpnError start_dns_proxy(VpnClient *self) {
    VpnSocksListenerConfig dns_listener_config{};
    self->dns_proxy_listener = std::make_unique<SocksListener>(&dns_listener_config);
    if (self->dns_proxy_listener->init(self, {&dns_proxy_listener_handler, self})
            != ClientListener::InitResult::SUCCESS) {
        return {VPN_EC_INVALID_SETTINGS, "Failed to initialize DNS proxy listener"};
    }

    self->dns_proxy = std::make_unique<DnsProxyAccessor>(DnsProxyAccessor::Parameters{
            .resolver_address = self->listener_config.dns_upstream,
            .socks_listener_address = ((SocksListener &) *self->dns_proxy_listener).get_listen_address(),
            .cert_verify_handler = self->parameters.cert_verify_handler,
            .ipv6_available = self->ipv6_available,
    });

    if (!self->dns_proxy->start(self->upstream_config.timeout)) {
        self->dns_proxy.reset();
        return {VPN_EC_ERROR, "Failed to start DNS proxy"};
    }

    return {VPN_EC_NOERROR};
}

VpnError VpnClient::connect(vpn_client::EndpointConnectionConfig config, std::optional<Millis> timeout) {
    log_client(this, dbg, "...");

    VpnError error = {};
    if (this->fsm.get_state() != vpn_client::S_DISCONNECTED) {
        error = {VPN_EC_ERROR, "Invalid state"};
        log_client(this, err, "{}: {}", safe_to_string_view(error.text), this->fsm.get_state());
        return error;
    }

    this->upstream_config = std::move(config);

    EndpointConnectorParameters connector_parameters = {
            this->parameters.ev_loop,
            this,
            {&vpn_upstream_handler, this},
            {&endpoint_connector_handler, this},
    };

    std::unique_ptr<ServerUpstream> main_upstream = make_upstream(this->upstream_config.main_protocol);
    if (this->upstream_config.fallback.enabled) {
        std::unique_ptr<ServerUpstream> fallback_upstream = make_upstream(this->upstream_config.fallback.protocol);
        this->endpoint_connector = std::make_unique<FallbackableUpstreamConnector>(connector_parameters,
                std::move(main_upstream), std::move(fallback_upstream),
                std::chrono::milliseconds(this->upstream_config.fallback.connect_delay_ms));
    } else {
        this->endpoint_connector =
                std::make_unique<SingleUpstreamConnector>(connector_parameters, std::move(main_upstream));
    }

    error = client_connect(this, timeout);
    if (error.code != VPN_EC_NOERROR) {
        goto fail;
    }

    log_client(this, dbg, "Done");
    return error;

fail:
    disconnect();

    if (error.code == 0) {
        error.code = VPN_EC_ERROR;
    }
    if (error.text == nullptr) {
        error.text = "Internal error";
    }

    log_client(this, dbg, "Failed: {} ({})", safe_to_string_view(error.text), error.code);

    return error;
}

VpnError VpnClient::listen(
        std::unique_ptr<ClientListener> listener, const VpnListenerConfig *config, bool ipv6_available) {
    log_client(this, dbg, "...");

    this->client_listener = std::move(listener);
    this->listener_config = vpn_listener_config_clone(config);

    VpnError error = {.code = VPN_EC_ERROR};

    this->ipv6_available = ipv6_available;
    if (this->listener_config.timeout_ms == 0) {
        this->listener_config.timeout_ms = VPN_DEFAULT_TCP_TIMEOUT_MS;
    }

    switch (this->client_listener->init(this, {&listener_handler, this})) {
    case ClientListener::InitResult::SUCCESS:
        break;
    case ClientListener::InitResult::ADDR_IN_USE:
        error = {VPN_EC_ADDR_IN_USE, "Failed to initialize client listener: address in use"};
        goto fail;
    case ClientListener::InitResult::FAILURE:
        error.text = "Failed to initialize client listener";
        goto fail;
    }

    if (this->tmp_files_base_path.has_value()) {
        clean_up_buffer_files(this->tmp_files_base_path->c_str());
    }

    // got here after connect procedure completion
    if (this->fsm.get_state() == vpn_client::S_CONNECTED) {
        this->tunnel->on_exclusions_updated();

        if (this->listener_config.dns_upstream != nullptr && this->dns_proxy == nullptr) {
            error = start_dns_proxy(this);
            if (error.code != VPN_EC_NOERROR) {
                goto fail;
            }
            if (!this->do_dns_upstream_health_check()) {
                error.text = "Failed to start DNS upstream health check";
                goto fail;
            }
        }
    }

    log_client(this, dbg, "Done");
    return {};

fail:
    this->fsm.perform_transition(vpn_client::E_RUN_PREPARATION_FAIL, nullptr);
    log_client(this, err, "Failed: {}", error.text);
    return error;
}

void VpnClient::disconnect() {
    log_client(this, dbg, "...");

    this->in_disconnect = true;
    this->fsm.perform_transition(vpn_client::E_DISCONNECT, nullptr);
    this->in_disconnect = false;

    log_client(this, dbg, "Done");
}

void VpnClient::finalize_disconnect() {
    log_client(this, dbg, "...");

    if (this->client_listener != nullptr) {
        this->client_listener->deinit();
        this->client_listener = nullptr;
    }

    if (this->dns_proxy != nullptr) {
        this->dns_proxy->stop();
        this->dns_proxy = nullptr;
    }

    if (this->dns_proxy_listener != nullptr) {
        this->dns_proxy_listener->deinit();
        this->dns_proxy_listener = nullptr;
    }

    if (this->endpoint_upstream != nullptr) {
        this->endpoint_upstream->deinit();
        this->endpoint_upstream = nullptr;
    }

    if (this->bypass_upstream != nullptr) {
        this->bypass_upstream->close_session();
    }

    if (this->tunnel != nullptr) {
        this->tunnel->deinit();
    }

    this->endpoint_connector.reset();

    if (this->tmp_files_base_path.has_value()) {
        clean_up_buffer_files(this->tmp_files_base_path->c_str());
    }

    this->deferred_tasks.clear();
    this->fsm.reset();

    log_client(this, dbg, "Done");
}

void VpnClient::deinit() {
    log_client(this, dbg, "...");

    if (this->bypass_upstream != nullptr) {
        this->bypass_upstream->deinit();
        this->bypass_upstream = nullptr;
    }

    log_client(this, dbg, "Done");
}

VpnClient::~VpnClient() {
    log_client(this, dbg, "...");

    vpn_listener_config_destroy(&this->listener_config);

    log_client(this, dbg, "Done");
}

void VpnClient::process_client_packets(VpnPackets packets) {
    if (!this->client_listener) {
        log_client(this, warn, "Packet listener is not initialized, dropping client packet.");
        VpnPacketsHolder holder(packets);
        return;
    }
    this->client_listener->process_client_packets(packets);
}

void VpnClient::update_exclusions(VpnMode mode, std::string_view exclusions) {
    log_client(this, dbg, "Mode={}", magic_enum::enum_name(mode));
    this->domain_filter.update_exclusions(mode, exclusions);
    if (this->fsm.get_state() == vpn_client::S_CONNECTED) {
        this->tunnel->on_exclusions_updated();
    }
}

void VpnClient::reset_connections(int uid) {
    if (this->fsm.get_state() == vpn_client::S_CONNECTED) {
        this->tunnel->reset_connections(uid);
    }
}

void VpnClient::update_parameters(vpn_client::Parameters parameters) {
    this->parameters = parameters;
}

void VpnClient::do_health_check() {
    submit_health_check(this, milliseconds(0));
}

bool VpnClient::do_dns_upstream_health_check() {
    return this->tunnel->dns_resolver
            ->resolve(VDRQ_FOREGROUND, std::string(DNS_PROXY_CHECK_DOMAIN), 1 << dns_utils::RT_A,
                    {dns_resolver_handler, this})
            .has_value();
}

VpnConnectionStats VpnClient::get_connection_stats() const {
    // should be ensured by `vpn_manager`
    assert(this->fsm.get_state() == vpn_client::S_CONNECTED);
    return (this->fsm.get_state() == vpn_client::S_CONNECTED) ? this->endpoint_upstream->get_connection_stats()
                                                              : VpnConnectionStats{};
}

std::unique_ptr<DataBuffer> VpnClient::make_buffer(uint64_t id) const {
    if (this->tmp_files_base_path.has_value()) {
        return std::make_unique<MemfileBuffer>(make_buffer_file_path(this->tmp_files_base_path->c_str(), id),
                this->conn_memory_buffer_threshold, this->max_conn_buffer_file_size);
    }

    return std::make_unique<MemoryBuffer>();
}

int VpnClient::next_upstream_id() {
    static std::atomic_int next_upstream_id = 0;
    return next_upstream_id.fetch_add(1, std::memory_order_relaxed);
}

bool VpnClient::may_send_icmp_request() const {
    return this->fsm.get_state() == vpn_client::S_CONNECTED;
}

void VpnClient::handle_sleep() {
    log_client(this, dbg, "...");
    switch (auto s = (vpn_client::State) this->fsm.get_state()) {
    case vpn_client::S_CONNECTING:
        if (this->endpoint_upstream == nullptr) {
            if (this->endpoint_connector != nullptr) {
                this->endpoint_connector->handle_sleep();
            } else {
                log_client(this, warn, "Both upstream and connector are null");
            }
            return;
        }
        [[fallthrough]];
    case vpn_client::S_CONNECTED:
        this->endpoint_upstream->handle_sleep();
        break;
    case vpn_client::S_DISCONNECTED:
    case vpn_client::S_DISCONNECTING:
        log_client(this, dbg, "Ignoring due to state: {}", magic_enum::enum_name(s));
        break;
    }
    log_client(this, dbg, "Done");
}

void VpnClient::handle_wake() {
    log_client(this, dbg, "...");
    switch (auto s = (vpn_client::State) this->fsm.get_state()) {
    case vpn_client::S_CONNECTING:
        if (this->endpoint_upstream == nullptr) {
            if (this->endpoint_connector != nullptr) {
                this->endpoint_connector->handle_wake();
            } else {
                log_client(this, warn, "Both upstream and connector are null");
            }
            return;
        }
        [[fallthrough]];
    case vpn_client::S_CONNECTED:
        this->endpoint_upstream->handle_wake();
        break;
    case vpn_client::S_DISCONNECTED:
    case vpn_client::S_DISCONNECTING:
        log_client(this, dbg, "Ignoring due to state: {}", magic_enum::enum_name(s));
        break;
    }
    log_client(this, dbg, "Done");
}

std::optional<VpnConnectAction> VpnClient::finalize_connect_action(
        ConnectRequestResult &request_result, bool only_app_initiated_dns) const {
    return this->tunnel->finalize_connect_action(request_result, only_app_initiated_dns);
}

// NOLINT(readability-make-member-function-const)
void VpnClient::complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action) {
    return this->tunnel->complete_connect_request(id, action);
}

void VpnClient::reject_connect_request(uint64_t id) { // NOLINT(readability-make-member-function-const)
    return this->client_listener->complete_connect_request(id, CCR_REJECT);
}

void VpnClient::reset_connection(uint64_t id) { // NOLINT(readability-make-member-function-const)
    this->tunnel->reset_connection(id);
}

static bool vpn_client::is_successful(const void *ctx, void *data) {
    const VpnError *error = (VpnError *) data;
    const VpnClient *vpn = (VpnClient *) ctx;
    return (error == nullptr || error->code == VPN_EC_NOERROR)
            && (!vpn->pending_error.has_value() || vpn->pending_error->code == VPN_EC_NOERROR);
}

static void vpn_client::run_connect(void *ctx, void *data) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    auto timeout = (data == nullptr) ? std::nullopt : *(std::optional<Millis> *) data;
    if (VpnError e = vpn->endpoint_connector->connect(timeout); e.code != VPN_EC_NOERROR) {
        vpn->pending_error = e;
    }

    log_client(vpn, trace, "Done");
}

static void vpn_client::schedule_health_check(void *ctx, void *) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    submit_health_check(vpn, vpn->upstream_config.endpoint_pinging_period);

    log_client(vpn, trace, "Done");
}

static void vpn_client::raise_connected(void *ctx, void *) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    vpn->parameters.handler.func(vpn->parameters.handler.arg, EVENT_CONNECTED, nullptr);

    log_client(vpn, trace, "Done");
}

static void vpn_client::raise_disconnected(void *ctx, void *) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    if (!vpn->pending_error.has_value()) {
        vpn->parameters.handler.func(vpn->parameters.handler.arg, EVENT_DISCONNECTED, nullptr);
    } else {
        vpn->parameters.handler.func(vpn->parameters.handler.arg, EVENT_ERROR, &vpn->pending_error.value());
        vpn->pending_error.reset();
    }

    log_client(vpn, trace, "Done");
}

static void vpn_client::run_disconnect(void *ctx, void *data) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    // @fixme: It turns out that sometimes for some reason not all DNS proxy listener connections
    //         are closed during a shutdown. That's why `dns_proxy_listener->deinit()` was
    //         replaced with `tunnel->reset_connections(dns_proxy_listener)` here.
    if (vpn->dns_proxy_listener != nullptr) {
        // Reset DNS proxy listener connections to complete all the pending DNS requests.
        // But do not deinitialize it here, because connections in the tunnel refer to it.
        vpn->tunnel->reset_connections(vpn->dns_proxy_listener.get());
    }

    vpn->tunnel->on_before_endpoint_disconnect(vpn->endpoint_upstream.get());

    const VpnError *error = (VpnError *) data;
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->pending_error = *error;
    }

    if (vpn->dns_proxy != nullptr) {
        vpn->dns_proxy->stop();
        vpn->dns_proxy = nullptr;
    }

    if (vpn->endpoint_connector != nullptr) {
        vpn->endpoint_connector->disconnect();
    } else {
        vpn->endpoint_upstream->close_session();
    }
    // @note: this is kind of ad hoc solution just to be sure that tunnel will not try to close
    // a server side connection through this upstream after the corresponding client side
    // connection is closed
    vpn->tunnel->on_after_endpoint_disconnect(vpn->endpoint_upstream.get());

    if (vpn->dns_proxy_listener != nullptr) {
        vpn->dns_proxy_listener->deinit();
    }

    log_client(vpn, trace, "Done");
}

static void vpn_client::submit_disconnect(void *ctx, void *data) {
    auto *vpn = (VpnClient *) ctx;
    log_client(vpn, trace, "...");

    const VpnError *error = (VpnError *) data;
    if (!vpn->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
        vpn->pending_error = *error;
    }

    vpn->deferred_tasks.emplace(event_loop::submit(vpn->parameters.ev_loop, {vpn, [](void *arg, TaskId task_id) {
                                                                         auto *vpn = (VpnClient *) arg;
                                                                         release_deferred_task(vpn, task_id);
                                                                         vpn->fsm.perform_transition(
                                                                                 E_DEFERRED_DISCONNECT, nullptr);
                                                                     }}));

    log_client(vpn, trace, "Done");
}

} // namespace ag
