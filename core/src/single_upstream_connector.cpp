#include "single_upstream_connector.h"

#include <atomic>
#include <magic_enum/magic_enum.hpp>
#include <optional>

#include "common/logger.h"
#include "vpn/fsm.h"
#include "vpn/utils.h"

#define log_connector(con_, lvl_, fmt_, ...) lvl_##log((con_)->log, "[{}] " fmt_, (con_)->id, ##__VA_ARGS__)

namespace ag {

static std::atomic<int> g_next_connector_id = 0;

enum State : uint32_t {
    S_DISCONNECTED,
    S_CONNECTING,
    S_DISCONNECTING,
};

enum Event {
    E_RUN_CONNECT,
    E_DISCONNECT,
    E_DEFERRED_DISCONNECT,
    E_SESSION_OPENED,
    E_SESSION_CLOSED,
    E_SESSION_ERROR,
    E_HEALTH_CHECK_ERROR,
};

static constexpr auto STATE_NAMES = make_enum_names_array<State>();
static constexpr auto EVENT_NAMES = make_enum_names_array<Event>();

struct SingleUpstreamConnector::Impl {
    Fsm fsm;
    std::unique_ptr<ServerUpstream> upstream;
    SingleUpstreamConnector &parent;
    std::optional<VpnError> pending_error;
    event_loop::AutoTaskId deferred_task;
    int id = g_next_connector_id.fetch_add(1, std::memory_order_relaxed);
    ag::Logger log{"SUCONNECTOR"};

    static FsmParameters make_fsm_params(SingleUpstreamConnector::Impl *self) {
        return {S_DISCONNECTED, FsmTransitionTable{std::begin(TRANSITION_TABLE), std::end(TRANSITION_TABLE)}, self,
                "SUCONNECTOR", STATE_NAMES.data(), EVENT_NAMES.data()};
    }

    Impl(SingleUpstreamConnector &parent, std::unique_ptr<ServerUpstream> upstream)
            : fsm(make_fsm_params(this))
            , upstream(std::move(upstream))
            , parent(parent) {
    }

    ~Impl() = default;

    static void upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *self = (Impl *) arg;

        switch (what) {
        case SERVER_EVENT_SESSION_OPENED: {
            log_connector(self, dbg, "Session is opened successfully");
            self->fsm.perform_transition(E_SESSION_OPENED, nullptr);
            break;
        }
        case SERVER_EVENT_SESSION_CLOSED: {
            log_connector(self, dbg, "Server session is closed");
            self->fsm.perform_transition(E_SESSION_CLOSED, nullptr);
            break;
        }
        case SERVER_EVENT_HEALTH_CHECK_ERROR: {
            const auto *error = (VpnError *) data;
            if (error == nullptr || error->code == VPN_EC_NOERROR) {
                log_connector(self, dbg, "Health check succeeded");
            } else {
                log_connector(self, dbg, "Health check error: {} ({})", error->text, error->code);
            }
            self->fsm.perform_transition(E_HEALTH_CHECK_ERROR, data);
            break;
        }
        case SERVER_EVENT_ERROR: {
            const auto *event = (ServerError *) data;
            assert(event->id == NON_ID);
            log_connector(self, dbg, "Server session terminated with error: {} ({})",
                    safe_to_string_view(event->error.text), event->error.code);
            self->fsm.perform_transition(E_SESSION_ERROR, (void *) &event->error);
            break;
        }
        case SERVER_EVENT_CONNECTION_OPENED:
        case SERVER_EVENT_CONNECTION_CLOSED:
        case SERVER_EVENT_READ:
        case SERVER_EVENT_DATA_SENT:
        case SERVER_EVENT_GET_AVAILABLE_TO_SEND:
        case SERVER_EVENT_ECHO_REPLY:
            assert(0);
            break;
        }
    }

    static void do_connect(void *arg, void *data) {
        auto *self = (Impl *) arg;
        log_connector(self, trace, "...");

        auto timeout = (data == nullptr) ? std::nullopt : *(std::optional<Millis> *) data;
        self->upstream->handler = {upstream_handler, self};
        if (!self->upstream->open_session(timeout)) {
            self->pending_error = {VPN_EC_ERROR, "Failed to open session with endpoint"};
        }

        log_connector(self, trace, "Done");
    }

    static void do_disconnect(void *arg, void *data) {
        auto *self = (Impl *) arg;
        log_connector(self, trace, "...");

        if (const auto *error = (VpnError *) data;
                !self->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
            self->pending_error = *error;
        }

        self->upstream->close_session();
        self->upstream->deinit();
        self->deferred_task.reset();

        log_connector(self, trace, "Done");
    }

    static void submit_disconnect(void *arg, void *data) {
        auto *self = (Impl *) arg;
        log_connector(self, trace, "...");

        const auto *error = (VpnError *) data;
        if (!self->pending_error.has_value() && error != nullptr && error->code != VPN_EC_NOERROR) {
            self->pending_error = *error;
        }

        self->deferred_task = event_loop::submit(
                self->parent.PARAMETERS.ev_loop, {self, [](void *arg, TaskId) {
                                                      auto *self = (Impl *) arg;
                                                      self->deferred_task.release();
                                                      self->fsm.perform_transition(E_DEFERRED_DISCONNECT, nullptr);
                                                  }});

        log_connector(self, trace, "Done");
    }

    static void raise_connected(void *arg, void *) {
        auto *self = (Impl *) arg;

        self->upstream->handler = self->parent.PARAMETERS.upstream_handler;
        EndpointConnectorHandler connector_handler = self->parent.PARAMETERS.connector_handler;
        connector_handler.func(connector_handler.arg, std::move(self->upstream));
    }

    static void raise_disconnected(void *arg, void *data) {
        auto *self = (Impl *) arg;

        VpnError e = {};
        if (self->pending_error.has_value()) {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            e = std::exchange(self->pending_error, std::nullopt).value();
        } else if (data != nullptr) {
            e = *(VpnError *) data;
        }

        EndpointConnectorHandler connector_handler = self->parent.PARAMETERS.connector_handler;
        connector_handler.func(connector_handler.arg, e);
    }

    // clang-format off
    static constexpr FsmTransitionEntry TRANSITION_TABLE[] = {
            {S_DISCONNECTED,        E_RUN_CONNECT,         Fsm::ANYWAY,    do_connect,        S_CONNECTING,           Fsm::DO_NOTHING},
            {S_DISCONNECTED,        E_SESSION_CLOSED,      Fsm::ANYWAY,    Fsm::DO_NOTHING,   Fsm::SAME_TARGET_STATE, Fsm::DO_NOTHING},
            {S_DISCONNECTED,        E_DISCONNECT,          Fsm::ANYWAY,    Fsm::DO_NOTHING,   Fsm::SAME_TARGET_STATE, Fsm::DO_NOTHING},

            {S_CONNECTING,          E_SESSION_OPENED,      Fsm::ANYWAY,    Fsm::DO_NOTHING,   S_DISCONNECTED,         raise_connected},
            {S_CONNECTING,          E_SESSION_CLOSED,      Fsm::ANYWAY,    Fsm::DO_NOTHING,   S_DISCONNECTED,         raise_disconnected},
            {S_CONNECTING,          E_SESSION_ERROR,       Fsm::ANYWAY,    submit_disconnect, S_DISCONNECTING,        Fsm::DO_NOTHING},

            {S_DISCONNECTING,       E_SESSION_CLOSED,      Fsm::ANYWAY,    Fsm::DO_NOTHING,   S_DISCONNECTED,         raise_disconnected},
            {S_DISCONNECTING,       E_DEFERRED_DISCONNECT, Fsm::ANYWAY,    do_disconnect,     S_DISCONNECTED,         raise_disconnected},

            {Fsm::ANY_SOURCE_STATE, E_DISCONNECT,          Fsm::ANYWAY,    do_disconnect,     S_DISCONNECTED,         Fsm::DO_NOTHING},
    };
    // clang-format on
};

SingleUpstreamConnector::SingleUpstreamConnector(
        const EndpointConnectorParameters &parameters, std::unique_ptr<ServerUpstream> upstream)
        : EndpointConnector(parameters)
        , m_impl(new Impl(*this, std::move(upstream))) {
}

SingleUpstreamConnector::~SingleUpstreamConnector() = default;

VpnError SingleUpstreamConnector::connect(std::optional<Millis> timeout) {
    log_connector(m_impl, trace, "...");
    if (State s = (State) m_impl->fsm.get_state(); s != S_DISCONNECTED) {
        log_connector(m_impl, dbg, "Invalid state: {}", magic_enum::enum_name(s));
        return {VPN_EC_ERROR, "Invalid state"};
    }

    if (!m_impl->upstream->init(this->PARAMETERS.vpn_client, {&Impl::upstream_handler, m_impl.get()})) {
        return {VPN_EC_ERROR, "Failed to initialize upstream"};
    }

    m_impl->fsm.perform_transition(E_RUN_CONNECT, &timeout);
    if (m_impl->pending_error.has_value()) {
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        VpnError e = std::exchange(m_impl->pending_error, std::nullopt).value();
        this->disconnect();
        log_connector(m_impl, dbg, "Failed: {} ({})", e.text, e.code);
        return e;
    }

    log_connector(m_impl, trace, "Done");
    return {};
}

void SingleUpstreamConnector::disconnect() {
    log_connector(m_impl, dbg, "...");
    m_impl->fsm.perform_transition(E_DISCONNECT, nullptr);
    log_connector(m_impl, dbg, "Done");
}

void SingleUpstreamConnector::handle_sleep() {
    if (auto s = (State) m_impl->fsm.get_state(); s == S_CONNECTING) {
        m_impl->upstream->handle_sleep();
    }
}

void SingleUpstreamConnector::handle_wake() {
    if (auto s = (State) m_impl->fsm.get_state(); s == S_CONNECTING) {
        m_impl->upstream->handle_wake();
    }
}

} // namespace ag
