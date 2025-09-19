#include "vpn/vpn_easy.h"

#include <memory>
#include <optional>
#include <variant>

#include <magic_enum/magic_enum.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "net/tls.h"
#include "vpn/platform.h"
#include "vpn/event_loop.h"
#include "vpn/standalone/client.h"
#include "vpn/standalone/config.h"

static ag::Logger g_logger{"VPN_SIMPLE"};

static void vpn_windows_verify_certificate(ag::VpnVerifyCertificateEvent *event) {
    event->result = !!ag::tls_verify_cert(event->cert, event->chain, nullptr);
}

static constexpr auto CONNECT_TIMEOUT = ag::Secs{5};

static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
static HMODULE g_wintun_handle;

class EasyEventLoop {
public:
    bool start() {
        if (!m_ev_loop) {
            m_ev_loop.reset(ag::vpn_event_loop_create());
        }

        if (!m_ev_loop)  {
            errlog(g_logger, "Failed to create event loop");
            return false;
        }

        infolog(g_logger, "Starting event loop...");

        m_executor_thread = std::thread([this]() {
            int ret = vpn_event_loop_run(m_ev_loop.get());
            if (ret != 0) {
                errlog(g_logger, "Event loop run returned {}", ret);
            }
        });

        if (!vpn_event_loop_dispatch_sync(m_ev_loop.get(), nullptr, nullptr)) {
            errlog(g_logger, "Event loop did not start");
            vpn_event_loop_stop(m_ev_loop.get());
            if (m_executor_thread.joinable()) {
                m_executor_thread.join();
            }
            assert(0);
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

struct vpn_easy_s {
    std::unique_ptr<ag::VpnStandaloneClient> client;
};

static vpn_easy_t *vpn_easy_start_internal(const char *toml_config, on_state_changed_t state_changed_cb, void *state_changed_cb_arg) {
    toml::parse_result parsed_config = toml::parse(toml_config);
    if (!parsed_config) {
        warnlog(g_logger, "Failed to parse the TOML config: {}", parsed_config.error().description());
        return nullptr;
    }

    auto standalone_config = ag::VpnStandaloneConfig::build_config(parsed_config);
    if (!standalone_config) {
        warnlog(g_logger, "Failed to build a standalone client config");
        return nullptr;
    }

    ag::VpnCallbacks callbacks;
    if (std::holds_alternative<ag::VpnStandaloneConfig::TunListener>(standalone_config->listener)) {
        callbacks.protect_handler = [](ag::SocketProtectEvent *event) {
            event->result = !ag::vpn_win_socket_protect(event->fd, event->peer);
        };
    } else {
        callbacks.protect_handler = [](ag::SocketProtectEvent *event) {
            event->result = 0;
        };
    }
    callbacks.verify_handler = [](ag::VpnVerifyCertificateEvent *event) {
        vpn_windows_verify_certificate(event);
    };
    callbacks.state_changed_handler = [state_changed_cb, state_changed_cb_arg](ag::VpnStateChangedEvent *event) {
        infolog(g_logger, "VPN state changed: {}", magic_enum::enum_name(event->state));
        if (state_changed_cb) {
            state_changed_cb(state_changed_cb_arg, event->state);
        }
    };

    auto vpn = std::make_unique<vpn_easy_t>();

    vpn->client = std::make_unique<ag::VpnStandaloneClient>(std::move(*standalone_config), std::move(callbacks));
    if (auto connect_error = vpn->client->connect(CONNECT_TIMEOUT, ag::VpnStandaloneClient::AutoSetup{})) {
        errlog(g_logger, "Failed to connect: {}", connect_error->pretty_str());
        return nullptr;
    }

    return vpn.release();
}

static void vpn_easy_stop_internal(vpn_easy_t *vpn) {
    if (!vpn) {
        return;
    }
    if (vpn->client) {
        vpn->client->disconnect();
    }
    delete vpn;
}

class VpnEasyManager {
public:
    static VpnEasyManager& instance() {
        static VpnEasyManager inst;
        return inst;
    }

    void start_async(const std::string& config, on_state_changed_t callback, void *arg) {
        if (!m_loop) {
            EasyEventLoop loop;
            if (!loop.start()) {
                errlog(g_logger, "Can't start VPN because of event loop error");
                return;
            }
            m_loop = std::move(loop);
        }
        m_loop->submit([this, config = config, callback, arg]() {
            if (m_vpn) {
                warnlog(g_logger, "VPN has been already started");
                return;
            }
            m_vpn = vpn_easy_start_internal(config.data(), callback, arg);  // blocking
            if (!m_vpn) {
                errlog(g_logger, "Failed to start VPN!");
                return;
            }
        });
    }
    void stop_async() {
        if (!m_loop) {
            errlog(g_logger, "Can't stop VPN service because event loop is not running");
            return;
        }
        m_loop->submit([this]() {
            if (!m_vpn) {
                warnlog(g_logger, "VPN is not running");
                return;
            }
            auto *vpn = std::exchange(m_vpn, nullptr);
            vpn_easy_stop_internal(vpn);
        });
    }

    ~VpnEasyManager() {
        if (m_loop) {
            m_loop->stop();
        }
    }

private:
    VpnEasyManager() = default;
    vpn_easy_t *m_vpn = nullptr;
    std::optional<EasyEventLoop> m_loop;
};

void vpn_easy_start(const char *toml_config, on_state_changed_t state_changed_cb, void *state_changed_cb_arg) {
    VpnEasyManager::instance().start_async(toml_config, state_changed_cb, state_changed_cb_arg);
}

void vpn_easy_stop() {
    VpnEasyManager::instance().stop_async();
}