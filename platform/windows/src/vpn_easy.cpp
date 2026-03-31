#include "vpn/vpn_easy.h"
#include "vpn/vpn_easy_service.h"

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <variant>

#include <magic_enum/magic_enum.hpp>
#include <toml++/toml.h>

#include <fmt/format.h>
#include <fmt/xchar.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "net/tls.h"
#include "vpn/event_loop.h"
#include "vpn/platform.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"

static ag::Logger g_logger{"VPN_SIMPLE"};

static void vpn_windows_verify_certificate(ag::VpnVerifyCertificateEvent *event) {
    event->result = !!ag::tls_verify_cert(event->cert, event->chain, nullptr);
}

static INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT;
static HMODULE g_wintun_handle;

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
    std::unique_ptr<ag::TrustTunnelClient> client;
    std::unique_ptr<ag::AutoNetworkMonitor> network_monitor;
};

vpn_easy_t *vpn_easy_start_ex(const char *toml_config, on_state_changed_t state_changed_cb, void *state_changed_cb_arg,
        on_connection_info_t connection_info_cb, void *connection_info_cb_arg) {
    toml::parse_result parsed_config = toml::parse(toml_config);
    if (!parsed_config) {
        warnlog(g_logger, "Failed to parse the TOML config: {}", parsed_config.error().description());
        return nullptr;
    }

    auto trusttunnel_config = ag::TrustTunnelConfig::build_config(parsed_config);
    if (!trusttunnel_config) {
        warnlog(g_logger, "Failed to build a trusttunnel client config");
        return nullptr;
    }

    ag::vpn_post_quantum_group_set_enabled(trusttunnel_config->post_quantum_group_enabled);

    ag::VpnCallbacks callbacks;
    if (std::holds_alternative<ag::TrustTunnelConfig::TunListener>(trusttunnel_config->listener)) {
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
    if (connection_info_cb) {
        callbacks.connection_info_handler = [connection_info_cb, connection_info_cb_arg](
                                                    ag::VpnConnectionInfoEvent *event) {
            connection_info_cb(connection_info_cb_arg, event);
        };
    }

    auto vpn = std::make_unique<vpn_easy_t>();

    std::string bound_if;
    if (const auto *tun = std::get_if<ag::TrustTunnelConfig::TunListener>(&trusttunnel_config->listener)) {
        bound_if = tun->bound_if;
    }

    vpn->client = std::make_unique<ag::TrustTunnelClient>(std::move(*trusttunnel_config), std::move(callbacks));
    vpn->network_monitor = std::make_unique<ag::AutoNetworkMonitor>(vpn->client.get(), std::move(bound_if));
    if (!vpn->network_monitor->start()) {
        errlog(g_logger, "Failed to start network monitor");
        return nullptr;
    }
    if (auto connect_error = vpn->client->connect(ag::TrustTunnelClient::AutoSetup{})) {
        errlog(g_logger, "Failed to connect: {}", connect_error->pretty_str());
        return nullptr;
    }

    return vpn.release();
}

void vpn_easy_stop_ex(vpn_easy_t *vpn) {
    if (!vpn) {
        return;
    }
    if (vpn->client) {
        vpn->client->disconnect();
    }
    if (vpn->network_monitor) {
        vpn->network_monitor->stop();
    }
    delete vpn;
}

class VpnEasyManager {
public:
    static VpnEasyManager &instance() {
        static VpnEasyManager inst;
        return inst;
    }

    void start_async(const std::string &config, on_state_changed_t callback, void *arg) {
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
            m_vpn = vpn_easy_start_ex(config.data(), callback, arg, nullptr, nullptr); // blocking
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
            vpn_easy_stop_ex(vpn);
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

static std::wstring escape(const wchar_t *str, const wchar_t *chars_to_escape, wchar_t escape_char) {
    std::wstring ret;
    ret.reserve(wcslen(str) * 2);
    while (*str != L'\0') {
        if (wcschr(chars_to_escape, *str)) {
            ret += escape_char;
        }
        ret += *str;
        ++str;
    }
    return ret;
}

using AutoScHandle = ag::UniquePtr<std::remove_pointer_t<SC_HANDLE>, &CloseServiceHandle>;

int32_t vpn_easy_service_install(const wchar_t *image_path_, const wchar_t *logfile_path_, const wchar_t *pipe_name_,
        const wchar_t *name, const wchar_t *display_name, const wchar_t *description) {
    std::wstring image_path = escape(image_path_, L"\"", L'\\');
    std::wstring logfile_path = escape(logfile_path_, L"\"", L'\\');
    std::wstring pipe_name = escape(pipe_name_, L"\"", L'\\');

    std::wstring cmd = fmt::format(L"\"{}\" \"{}\" \"{}\"", image_path, logfile_path, pipe_name);

    AutoScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!scm) {
        if (ERROR_ACCESS_DENIED == GetLastError()) {
            return VPN_EASY_SVC_ERR_ACCESS;
        }
        dbglog(g_logger, "OpenSCManagerW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    AutoScHandle svc{CreateServiceW(scm.get(), name, display_name, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr)};
    if (!svc) {
        if (ERROR_SERVICE_EXISTS == GetLastError()) {
            return VPN_EASY_SVC_ERR_SERVICE_EXISTS;
        }
        if (ERROR_ACCESS_DENIED == GetLastError()) {
            return VPN_EASY_SVC_ERR_ACCESS;
        }
        dbglog(g_logger, "CreateServiceW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    SERVICE_DESCRIPTIONW desc{.lpDescription = (wchar_t *) description};
    ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        dbglog(g_logger, "StartServiceW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    return 0;
}

int32_t vpn_easy_service_uninstall(const wchar_t *name) {
    AutoScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) {
        if (ERROR_ACCESS_DENIED == GetLastError()) {
            return VPN_EASY_SVC_ERR_ACCESS;
        }
        dbglog(g_logger, "OpenSCManagerW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    AutoScHandle svc{OpenServiceW(scm.get(), name, STANDARD_RIGHTS_DELETE | SERVICE_STOP)};
    if (!svc) {
        if (ERROR_ACCESS_DENIED == GetLastError()) {
            return VPN_EASY_SVC_ERR_ACCESS;
        }
        dbglog(g_logger, "OpenServiceW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    SERVICE_STATUS status{};
    if (!ControlService(svc.get(), SERVICE_CONTROL_STOP, &status) && ERROR_SERVICE_NOT_ACTIVE != GetLastError()) {
        dbglog(g_logger, "ControlService(STOP): {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
    }

    if (!DeleteService(svc.get())) {
        dbglog(g_logger, "DeleteService: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return VPN_EASY_SVC_ERR_OTHER;
    }

    return 0;
}
