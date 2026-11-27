#include "trusttunnel/trusttunnel.h"

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

#include <toml++/toml.h>

#include "common/logger.h"
#include "common/utils.h"
#include "src/vpn_controller.h"
#include "vpn/event_loop.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"
#include "vpn/vpn.h"

using namespace ag::trusttunnel_linux;

static ag::Logger g_logger("TRUSTTUNNEL");

/// The instance handle. Defined in the global namespace: `trusttunnel_t` is a typedef for this
/// very structure (see the public header).
struct trusttunnel_s {
    VpnController controller;

    explicit trusttunnel_s(VpnController::Callbacks callbacks)
            : controller(std::move(callbacks)) {
    }
};

/// Convert C callbacks into the controller's std::function-based callbacks
static VpnController::Callbacks make_controller_callbacks(on_state_changed_t state_changed_cb, void *state_changed_arg,
        on_connection_info_t connection_info_cb, void *connection_info_arg) {
    VpnController::Callbacks callbacks;
    if (state_changed_cb != nullptr) {
        callbacks.on_state_changed = [state_changed_cb, state_changed_arg](int state) {
            state_changed_cb(state_changed_arg, state);
        };
    }
    if (connection_info_cb != nullptr) {
        callbacks.on_connection_info = [connection_info_cb, connection_info_arg](const std::string &json) {
            connection_info_cb(connection_info_arg, json.c_str());
        };
    }
    return callbacks;
}

/// Parse and validate the TOML configuration
static std::optional<ag::TrustTunnelConfig> parse_config(const char *toml_config) {
    if (toml_config == nullptr) {
        return std::nullopt;
    }
    toml::parse_result parsed = toml::parse(toml_config);
    if (!parsed) {
        errlog(g_logger, "Failed to parse the TOML config");
        return std::nullopt;
    }
    auto config = ag::TrustTunnelConfig::build_config(parsed.table());
    if (!config) {
        errlog(g_logger, "Failed to build a TrustTunnel client config");
        return std::nullopt;
    }
    return config;
}

namespace {

/// The manager's own event loop, running on a dedicated thread.
///
/// Serializes `start` and `stop` requests so that rapid toggling cannot interleave a teardown with
/// the next session start.
class EasyEventLoop {
public:
    bool start() {
        if (!m_ev_loop) {
            m_ev_loop.reset(ag::vpn_event_loop_create());
        }
        if (!m_ev_loop) {
            errlog(g_logger, "Failed to create event loop");
            return false;
        }

        infolog(g_logger, "Starting event loop...");

        m_executor_thread = std::thread([this]() {
            int ret = ag::vpn_event_loop_run(m_ev_loop.get());
            if (ret != 0) {
                errlog(g_logger, "Event loop run returned {}", ret);
            }
        });

        if (!ag::vpn_event_loop_dispatch_sync(m_ev_loop.get(), nullptr, nullptr)) {
            errlog(g_logger, "Event loop did not start");
            ag::vpn_event_loop_stop(m_ev_loop.get());
            if (m_executor_thread.joinable()) {
                m_executor_thread.join();
            }
            return false;
        }

        infolog(g_logger, "Event loop has been started");
        return true;
    }

    void submit(std::function<void()> task) {
        if (m_ev_loop) {
            ag::event_loop::submit(m_ev_loop.get(), std::move(task)).release();
        }
    }

    void stop() {
        ag::vpn_event_loop_stop(m_ev_loop.get());
        if (m_executor_thread.joinable()) {
            m_executor_thread.join();
        }
    }

private:
    ag::UniquePtr<ag::VpnEventLoop, &ag::vpn_event_loop_destroy> m_ev_loop{ag::vpn_event_loop_create()};
    std::thread m_executor_thread;
};

/// Owns the single client instance shared by the async `start`/`stop` entry points
class TrusttunnelManager {
public:
    static TrusttunnelManager &instance() {
        static TrusttunnelManager inst;
        return inst;
    }

    void start_async(const std::string &config, bool fall_into_recovery, on_state_changed_t callback, void *arg) {
        std::lock_guard<std::mutex> lock(m_guard);
        if (m_shutting_down) {
            return;
        }
        if (!m_loop) {
            EasyEventLoop loop;
            if (!loop.start()) {
                errlog(g_logger, "Can't start VPN because of event loop error");
                return;
            }
            m_loop = std::move(loop);
        }
        // The mutex is held across `submit()` but not across the queued task: `submit()` only queues,
        // while the task itself takes the mutex. This way the destructor cannot move `m_loop` out from
        // under an in-flight request.
        m_loop->submit([this, config, fall_into_recovery, callback, arg]() {
            std::lock_guard<std::mutex> task_lock(m_guard);
            if (m_vpn) {
                warnlog(g_logger, "VPN has been already started");
                return;
            }
            // Blocks while the connection is initiated; a later failure arrives via the callback
            m_vpn = trusttunnel_start_ex(config.c_str(), fall_into_recovery, callback, arg, nullptr, nullptr);
            if (!m_vpn) {
                errlog(g_logger, "Failed to start VPN!");
            }
        });
    }

    void stop_async() {
        std::lock_guard<std::mutex> lock(m_guard);
        if (!m_loop) {
            warnlog(g_logger, "Can't stop VPN because the event loop is not running");
            return;
        }
        m_loop->submit([this]() {
            std::lock_guard<std::mutex> task_lock(m_guard);
            if (!m_vpn) {
                warnlog(g_logger, "VPN is not running");
                return;
            }
            auto *vpn = std::exchange(m_vpn, nullptr);
            trusttunnel_stop_ex(vpn);
        });
    }

    ~TrusttunnelManager() {
        std::optional<EasyEventLoop> loop;
        {
            std::lock_guard<std::mutex> lock(m_guard);
            m_shutting_down = true;
            loop = std::move(m_loop);
        }
        // Join outside the mutex: the executor thread may be running a task that needs it. Stopping the
        // loop first guarantees every submitted task has finished, so no task can create a new session
        // after the one below is torn down.
        if (loop) {
            loop->stop();
        }
        std::unique_lock<std::mutex> lock(m_guard);
        if (trusttunnel_t *vpn = std::exchange(m_vpn, nullptr)) {
            lock.unlock();
            trusttunnel_stop_ex(vpn);
        }
    }

private:
    TrusttunnelManager() = default;

    std::mutex m_guard;
    bool m_shutting_down = false;
    trusttunnel_t *m_vpn = nullptr;
    std::optional<EasyEventLoop> m_loop;
};

} // namespace

trusttunnel_t *trusttunnel_start_ex(const char *toml_config, bool fall_into_recovery,
        on_state_changed_t state_changed_cb, void *state_changed_cb_arg, on_connection_info_t connection_info_cb,
        void *connection_info_cb_arg) {
    // Nothing below may propagate an exception across the C boundary: a C caller cannot catch one,
    // and even for C++ callers an unwind through C frames is undesirable.
    try {
        if (toml_config == nullptr) {
            return nullptr;
        }

        std::optional<ag::TrustTunnelConfig> config = parse_config(toml_config);
        if (!config) {
            return nullptr;
        }

        // Apply the configured log level before anything below emits logs so that
        // the whole process logs at the level requested by the config.
        ag::Logger::set_log_level(config->loglevel);

        std::unique_ptr<trusttunnel_s> vpn = std::make_unique<trusttunnel_s>(make_controller_callbacks(
                state_changed_cb, state_changed_cb_arg, connection_info_cb, connection_info_cb_arg));
        if (!vpn->controller.start(std::move(*config), fall_into_recovery)) {
            return nullptr;
        }
        return vpn.release();
    } catch (const std::exception &e) {
        errlog(g_logger, "Exception in trusttunnel_start_ex: {}", e.what());
        return nullptr;
    } catch (...) {
        errlog(g_logger, "Unknown exception in trusttunnel_start_ex");
        return nullptr;
    }
}

void trusttunnel_stop_ex(trusttunnel_t *vpn) {
    try {
        std::unique_ptr<trusttunnel_s> instance{vpn};
    } catch (const std::exception &e) {
        errlog(g_logger, "Exception in trusttunnel_stop_ex: {}", e.what());
    } catch (...) {
        errlog(g_logger, "Unknown exception in trusttunnel_stop_ex");
    }
}

void trusttunnel_start(const char *toml_config, bool fall_into_recovery, on_state_changed_t state_changed_cb,
        void *state_changed_cb_arg) {
    try {
        TrusttunnelManager::instance().start_async(
                toml_config != nullptr ? toml_config : "", fall_into_recovery, state_changed_cb, state_changed_cb_arg);
    } catch (const std::exception &e) {
        errlog(g_logger, "Exception in trusttunnel_start: {}", e.what());
    } catch (...) {
        errlog(g_logger, "Unknown exception in trusttunnel_start");
    }
}

void trusttunnel_stop() {
    try {
        TrusttunnelManager::instance().stop_async();
    } catch (const std::exception &e) {
        errlog(g_logger, "Exception in trusttunnel_stop: {}", e.what());
    } catch (...) {
        errlog(g_logger, "Unknown exception in trusttunnel_stop");
    }
}
