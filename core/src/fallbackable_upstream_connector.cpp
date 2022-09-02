#include "fallbackable_upstream_connector.h"

#include <atomic>

#include "single_upstream_connector.h"

#define log_connector(con_, lvl_, fmt_, ...) lvl_##log((con_)->m_log, "[{}] " fmt_, (con_)->m_id, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

static std::atomic<int> next_connector_id = 0;

FallbackableUpstreamConnector::FallbackableUpstreamConnector(const EndpointConnectorParameters &parameters,
        std::unique_ptr<ServerUpstream> main, std::unique_ptr<ServerUpstream> fallback, Millis fallback_delay)
        : EndpointConnector(parameters)
        , m_main({
                  std::make_unique<SingleUpstreamConnector>(
                          this->make_connector_parameters({&main_connector_handler, this}), std::move(main)),
          })
        , m_fallback({
                  std::make_unique<SingleUpstreamConnector>(
                          this->make_connector_parameters({&fallback_connector_handler, this}), std::move(fallback)),
                  fallback_delay,
          })
        , m_id(next_connector_id.fetch_add(1, std::memory_order_relaxed)) {
}

VpnError FallbackableUpstreamConnector::connect(std::optional<Millis> timeout) {
    m_connect_timeout = timeout;
    m_main.start_ts = steady_clock::now();

    if (VpnError error = m_main.connector->connect(timeout); error.code != VPN_EC_NOERROR) {
        log_connector(this, dbg, "Failed to start connect to main upstream, trying fallback immediately");
        this->handle_connect_result(m_main.connector.get(), error);
    } else {
        m_fallback.delay_task = event_loop::schedule(this->PARAMETERS.ev_loop,
                {
                        this,
                        [](void *arg, TaskId) {
                            auto *self = (FallbackableUpstreamConnector *) arg;
                            self->m_fallback.delay_task.release();
                            self->start_fallback_connection();
                        },
                },
                m_fallback.delay);
    }
    return {};
}

void FallbackableUpstreamConnector::disconnect() {
    if (!m_main.has_result && m_main.connector != nullptr) {
        m_main.connector->disconnect();
    }
    m_main.result_task.reset();

    if (m_fallback.tried && !m_fallback.has_result && m_fallback.connector != nullptr) {
        m_fallback.connector->disconnect();
    }
    m_fallback.delay_task.reset();
    m_fallback.result_task.reset();
}

void FallbackableUpstreamConnector::handle_sleep() {
    if (!m_main.has_result && m_main.connector != nullptr) {
        m_main.connector->handle_sleep();
    }

    if (m_fallback.tried && !m_fallback.has_result && m_fallback.connector != nullptr) {
        m_fallback.connector->handle_sleep();
    }
}

void FallbackableUpstreamConnector::handle_wake() {
    if (!m_main.has_result && m_main.connector != nullptr) {
        m_main.connector->handle_wake();
    }

    if (m_fallback.tried && !m_fallback.has_result && m_fallback.connector != nullptr) {
        m_fallback.connector->handle_wake();
    }
}

EndpointConnectorParameters FallbackableUpstreamConnector::make_connector_parameters(EndpointConnectorHandler h) const {
    return {
            this->PARAMETERS.ev_loop,
            this->PARAMETERS.vpn_client,
            this->PARAMETERS.upstream_handler,
            h,
    };
}

void FallbackableUpstreamConnector::handle_connect_result(
        const EndpointConnector *connector, EndpointConnectorResult result) {
    bool need_raise = false;
    if (std::holds_alternative<std::unique_ptr<ServerUpstream>>(result)) {
        log_connector(this, dbg, "Got successful result from {} connector",
                (m_main.connector.get() == connector) ? "main" : "m_fallback");
        EndpointConnector *another_connector =
                (m_main.connector.get() == connector) ? m_main.connector.get() : m_fallback.connector.get();
        another_connector->disconnect();
        need_raise = true;
    }

    if (m_main.connector.get() == connector) {
        m_main.connector.reset();
        m_main.has_result = true;
        m_main.result_task.release();
    } else {
        m_fallback.connector.reset();
        m_fallback.has_result = true;
        m_fallback.result_task.release();
    }

    if (m_main.has_result && m_fallback.has_result) {
        log_connector(this, dbg, "Both endpoint connectors failed");
        need_raise = true;
    }

    if (need_raise) {
        EndpointConnectorHandler h = this->PARAMETERS.connector_handler;
        h.func(h.arg, std::move(result));
        m_main = {};
        m_fallback = {};
    } else if (!m_fallback.tried) {
        log_connector(this, dbg, "Main protocol failed, trying fallback immediately");
        m_fallback.delay_task = event_loop::submit(this->PARAMETERS.ev_loop,
                {
                        this,
                        [](void *arg, TaskId) {
                            auto *self = (FallbackableUpstreamConnector *) arg;
                            self->m_fallback.delay_task.release();
                            self->start_fallback_connection();
                        },
                });
    }
}

VpnEventLoopTask FallbackableUpstreamConnector::make_deferred_handle_task(
        const EndpointConnector *c, EndpointConnectorResult result) const {
    struct connector_result_ctx_t {
        FallbackableUpstreamConnector *self;
        const EndpointConnector *ready_connector;
        EndpointConnectorResult result;
    };

    return {
            new connector_result_ctx_t{(FallbackableUpstreamConnector *) this, c, std::move(result)},
            [](void *arg, TaskId task_id) {
                auto *ctx = (connector_result_ctx_t *) arg;
                FallbackableUpstreamConnector *self = ctx->self;
                self->handle_connect_result(ctx->ready_connector, std::move(ctx->result));
            },
            [](void *arg) {
                delete (connector_result_ctx_t *) arg;
            },
    };
}

void FallbackableUpstreamConnector::start_fallback_connection() {
    assert(!m_fallback.tried);
    assert(!m_fallback.has_result);
    m_fallback.tried = true;

    std::optional<Millis> timeout;
    if (m_connect_timeout.has_value()) {
        timeout = std::make_optional<Millis>(m_connect_timeout.value() - duration_cast<Millis>(steady_clock::now() - m_main.start_ts));
        timeout = std::max(timeout.value(), m_connect_timeout.value() / 10);
    }
    VpnError error = m_fallback.connector->connect(timeout);
    if (error.code != VPN_EC_NOERROR) {
        this->handle_connect_result(m_fallback.connector.get(), error);
    }
}

void FallbackableUpstreamConnector::main_connector_handler(void *arg, EndpointConnectorResult result) {
    auto *self = (FallbackableUpstreamConnector *) arg;
    assert(!self->m_main.result_task.has_value());
    self->m_main.result_task = event_loop::submit(
            self->PARAMETERS.ev_loop, self->make_deferred_handle_task(self->m_main.connector.get(), std::move(result)));
}

void FallbackableUpstreamConnector::fallback_connector_handler(void *arg, EndpointConnectorResult result) {
    auto *self = (FallbackableUpstreamConnector *) arg;
    assert(!self->m_fallback.result_task.has_value());
    self->m_fallback.result_task = event_loop::submit(self->PARAMETERS.ev_loop,
            self->make_deferred_handle_task(self->m_fallback.connector.get(), std::move(result)));
}

} // namespace ag
