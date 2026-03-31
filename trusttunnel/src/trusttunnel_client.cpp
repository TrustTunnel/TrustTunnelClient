#include <atomic>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <cxxopts.hpp>
#include <magic_enum/magic_enum.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "net/network_manager.h"
#include "net/tls.h"
#include "utils.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"
#include "vpn/trusttunnel/version.h"

#ifdef __APPLE__
#include "AppleSleepNotifier.h"
#endif

#ifdef _WIN32
#include <filesystem>
#endif

#ifdef __linux__
#include <net/if.h>
#endif

static constexpr std::string_view DEFAULT_CONFIG_FILE = "trusttunnel_client.toml";

using namespace ag;

static const ag::Logger g_logger("TRUSTTUNNEL_CLIENT_APP");
static std::atomic_bool keep_running{true};
static std::condition_variable g_waiter;
static std::mutex g_waiter_mutex;
static std::weak_ptr<TrustTunnelClient> g_client;

static std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const TrustTunnelConfig &config);
static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback();
static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback();
static std::function<void(VpnConnectionInfoEvent *)> get_connection_info_callback();

#ifdef _WIN32
static int service_run(const cxxopts::ParseResult *cli_args);
static int service_uninstall();
static int service_install(const std::string &config_path);
static void report_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint);
static bool g_svc_running = false;
#endif

int run_client(const cxxopts::ParseResult &cli_args);

static void stop_trusttunnel_client() {
    keep_running = false;
    g_waiter.notify_all();
}

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (auto client = g_client.lock()) {
#ifndef _WIN32
        if (sig == SIGHUP) {
            client->notify_network_change(ag::VPN_NS_NOT_CONNECTED);
            std::thread t([client]() {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                client->notify_network_change(ag::VPN_NS_CONNECTED);
            });
            t.detach();
            return;
        }
#endif
        stop_trusttunnel_client();
    } else {
        exit(1);
    }
}

static void setup_sighandler() {
#ifdef _WIN32
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
#else
    signal(SIGPIPE, SIG_IGN);
    // Block SIGINT and SIGTERM - they will be waited using sigwait().
    sigset_t sigset; // NOLINT(cppcoreguidelines-init-variables)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    std::thread([sigset] {
        int signum = 0;
        while (true) {
            sigwait(&sigset, &signum);
            sighandler(signum);
        }
    }).detach();
#endif
}

int main(int argc, char **argv) {
    setup_sighandler();

    cxxopts::Options args("trusttunnel_client", "TrustTunnel console client");
    // clang-format off
    args.add_options()
            ("v,version", "Print version")
            ("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))
            ("c,config", "Config file name.", cxxopts::value<std::string>()->default_value(std::string(DEFAULT_CONFIG_FILE)))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.", cxxopts::value<std::string>()->default_value("info"))
            ("h,help", "Print usage");
#ifdef _WIN32
    args.add_options()
            ("service-install", "Install as Windows service", cxxopts::value<bool>()->default_value("false"))
            ("service-uninstall", "Uninstall Windows service", cxxopts::value<bool>()->default_value("false"));
    args.add_options("internal")
            ("service-run", "Run as Windows service", cxxopts::value<bool>()->default_value("false"));
#endif
    // clang-format on

    auto result = args.parse(argc, argv);
    if (result.count("version")) {
        std::cout << args.program() << " " TRUSTTUNNEL_VERSION << '\n';
        return 0;
    }

    if (result.count("help")) {
        // `{""}` mean print only options from default options group
        std::cout << args.help({""}) << '\n';
        return 1;
    }

#ifdef _WIN32
    if (result.count("service-install") && result.count("service-uninstall")) {
        errlog(g_logger, "--service-install and --service-uninstall are mutually exclusive");
        return 1;
    }
    if (result.count("service-install")) {
        return service_install(result["config"].as<std::string>());
    }
    if (result.count("service-uninstall")) {
        return service_uninstall();
    }
    if (result["service-run"].as<bool>()) {
        return service_run(&result);
    }
#endif

    return run_client(result);
}

int run_client(const cxxopts::ParseResult &cli_args) {
    toml::parse_result parse_result = toml::parse_file(cli_args["config"].as<std::string>());
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return 1;
    }

    std::optional config_res = TrustTunnelConfig::build_config(parse_result.table());
    if (!config_res) {
        errlog(g_logger, "Failed to parse config");
        return 1;
    }
    auto &config = *config_res;
    if (!TrustTunnelCliUtils::apply_cmd_args(config, cli_args)) {
        return 1;
    }
    ag::Logger::set_log_level(config.loglevel);

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    VpnCallbacks callbacks = {
            .protect_handler = get_protect_socket_callback(config),
            .verify_handler = get_verify_certificate_callback(),
            .state_changed_handler = get_state_changed_callback(),
            .connection_info_handler = get_connection_info_callback(),
    };

    std::string bound_if;
    if (const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener)) {
        bound_if = tun->bound_if;
    }

    auto client = std::make_shared<TrustTunnelClient>(std::move(config), std::move(callbacks));
    g_client = client;
    AutoNetworkMonitor network_monitor(client.get(), std::move(bound_if));
    if (!network_monitor.start()) {
        errlog(g_logger, "Failed to start network monitor");
        return 1;
    }

    auto res = client->set_system_dns();
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }
    res = client->connect(TrustTunnelClient::AutoSetup{});
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }

#ifdef _WIN32
    if (g_svc_running) {
        report_service_status(SERVICE_RUNNING, NO_ERROR, 0);
    }
#endif

#ifdef __APPLE__
    auto sleep_notifier = std::make_unique<AppleSleepNotifier>(
            [client_weak = std::weak_ptr(client)] {
                if (auto client = client_weak.lock()) {
                    client->notify_sleep();
                }
            },
            [client_weak = std::weak_ptr(client)] {
                if (auto client = client_weak.lock()) {
                    client->notify_wake();
                }
            });
#endif

    std::unique_lock<std::mutex> lock(g_waiter_mutex);
    g_waiter.wait(lock, []() {
        return !keep_running.load();
    });

#ifdef __APPLE__
    sleep_notifier.reset();
#endif

    network_monitor.stop();
    client->disconnect();

    return 0;
}

std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const TrustTunnelConfig &config) {
    const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener);
    if (!tun) {
        return [](auto) {};
    }

    return [](SocketProtectEvent *event) {
#ifdef __APPLE__
        uint32_t idx = vpn_network_manager_get_outbound_interface();
        if (idx == 0) {
            return;
        }
        if (event->peer->sa_family == AF_INET) {
            if (setsockopt(event->fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx)) != 0) {
                event->result = -1;
            }
        } else if (event->peer->sa_family == AF_INET6) {
            if (setsockopt(event->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx)) != 0) {
                event->result = -1;
            }
        }
#endif // __APPLE__

#ifdef __linux__
        uint32_t idx = vpn_network_manager_get_outbound_interface();
        char if_name[IF_NAMESIZE]{};
        if_indextoname(idx, if_name);
        std::string bound_if{if_name};
        if (!bound_if.empty()) {
            if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, bound_if.data(), (socklen_t) bound_if.size()) != 0) {
                event->result = -1;
            }
        }
#endif

#ifdef _WIN32
        bool protect_success = vpn_win_socket_protect(event->fd, event->peer);
        if (!protect_success) {
            event->result = -1;
        }
#endif
    };
}

static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback() {
    return [](VpnVerifyCertificateEvent *event) {
        const char *err = tls_verify_cert(event->cert, event->chain, nullptr);
        if (err == nullptr) {
            tracelog(g_logger, "Certificate verified successfully");
            event->result = 0;
        } else {
            errlog(g_logger, "Failed to verify certificate: {}", err);
            event->result = -1;
        }
    };
}

static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback() {
    return [](VpnStateChangedEvent *event) {
        switch (event->state) {
        case VPN_SS_DISCONNECTED:
            if (event->error.code != 0) {
                errlog(g_logger, "Error: {} {}", event->error.code, safe_to_string_view(event->error.text));
            }
            stop_trusttunnel_client();
            break;
        case VPN_SS_WAITING_RECOVERY:
            infolog(g_logger, "Waiting recovery: to next={}ms error={} {}",
                    event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                    safe_to_string_view(event->waiting_recovery_info.error.text));
            break;
        case VPN_SS_CONNECTED: {
            infolog(g_logger, "Successfully connected to endpoint");
            break;
        }
        case VPN_SS_CONNECTING:
        case VPN_SS_RECOVERING:
        case VPN_SS_WAITING_FOR_NETWORK:
            break;
        }
    };
}

static std::function<void(VpnConnectionInfoEvent *)> get_connection_info_callback() {
    return [](VpnConnectionInfoEvent *event) {
        std::string src = SocketAddress(*event->src).host_str(/*ipv6_brackets=*/true);
        std::string proto = event->proto == IPPROTO_TCP ? "TCP" : "UDP";
        std::string dst;
        if (event->domain) {
            dst = event->domain;
        }
        if (event->dst) {
            dst = AG_FMT("{}({})", dst, src);
        }
        auto action = magic_enum::enum_name(event->action);

        std::string log_message;

        log_message = fmt::format("{}, {} -> {}. Action: {}", proto, src, dst, action);

        dbglog(g_logger, "{}", log_message);
    };
}

#ifdef _WIN32

static constexpr std::wstring_view SERVICE_NAME = L"TrustTunnelClient";
static constexpr std::wstring_view SERVICE_DISPLAY_NAME = L"TrustTunnel VPN Client";

using ScHandle = ag::UniquePtr<std::remove_pointer_t<SC_HANDLE>, &CloseServiceHandle>;

static const ag::Logger g_svc_logger("WIN_SERVICE");

static SERVICE_STATUS_HANDLE g_status_handle = nullptr;
static SERVICE_STATUS g_service_status = {};
static std::mutex g_service_status_mutex;
// g_svc_cli_args is safe to dereference in service_main() because StartServiceCtrlDispatcherW
// blocks until the service stops, and the ParseResult it points to lives in main().
static const cxxopts::ParseResult *g_svc_cli_args = nullptr;

static void report_service_status(DWORD current_state, DWORD win32_exit_code, DWORD wait_hint) {
    std::lock_guard lock(g_service_status_mutex);
    static DWORD check_point = 1;

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = win32_exit_code;
    g_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING) {
        g_service_status.dwControlsAccepted = 0;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }

    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        g_service_status.dwCheckPoint = 0;
    } else {
        g_service_status.dwCheckPoint = check_point++;
    }

    SetServiceStatus(g_status_handle, &g_service_status);
}

static void WINAPI service_ctrl_handler(DWORD control) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        report_service_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
        stop_trusttunnel_client();
        break;
    case SERVICE_CONTROL_INTERROGATE:
        report_service_status(g_service_status.dwCurrentState, NO_ERROR, 0);
        break;
    default:
        break;
    }
}

static void WINAPI service_main(DWORD argc, LPWSTR *argv) {
    (void) argc;
    (void) argv;
    g_status_handle = RegisterServiceCtrlHandlerW(SERVICE_NAME.data(), service_ctrl_handler);
    if (g_status_handle == nullptr) {
        return;
    }

    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    report_service_status(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_svc_running = true;
    int result = run_client(*g_svc_cli_args);
    g_svc_running = false;

    report_service_status(SERVICE_STOPPED, result == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

static bool validate_config(const std::string &config_path) {
    toml::parse_result parse_result = toml::parse_file(config_path);
    if (!parse_result) {
        errlog(g_svc_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return false;
    }

    std::optional config_res = TrustTunnelConfig::build_config(parse_result.table());
    if (!config_res) {
        errlog(g_svc_logger, "Failed to parse config");
        return false;
    }
    return true;
}

static std::optional<std::wstring> get_exe_path() {
    std::wstring buf(MAX_PATH, L'\0');
    DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (len == 0) {
        errlog(g_svc_logger, "GetModuleFileNameW failed: error {}", GetLastError());
        return std::nullopt;
    }
    while (len == buf.size()) {
        buf.resize(buf.size() * 2);
        len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            errlog(g_svc_logger, "GetModuleFileNameW failed: error {}", GetLastError());
            return std::nullopt;
        }
    }
    buf.resize(len);
    return buf;
}

static void print_usage_manual() {
    std::cout << "\nService 'TrustTunnelClient' installed successfully.\n\n"
              << "The service is configured to start automatically on boot.\n\n"
              << "To start/stop the service:\n"
              << "  cmd.exe:\n"
              << "    sc start TrustTunnelClient\n"
              << "    sc stop TrustTunnelClient\n"
              << "  PowerShell:\n"
              << "    Start-Service TrustTunnelClient\n"
              << "    Stop-Service TrustTunnelClient\n\n"
              << "To query service status:\n"
              << "  cmd.exe:\n"
              << "    sc query TrustTunnelClient\n"
              << "  PowerShell:\n"
              << "    Get-Service TrustTunnelClient\n\n"
              << "To disable auto-start:\n"
              << "  cmd.exe:\n"
              << "    sc config TrustTunnelClient start= demand\n"
              << "  PowerShell:\n"
              << "    Set-Service TrustTunnelClient -StartupType Manual\n";
}

static int service_install(const std::string &config_path) {
    if (!validate_config(config_path)) {
        return 1;
    }

    std::filesystem::path abs_config = std::filesystem::absolute(config_path);
    auto exe_path = get_exe_path();
    if (!exe_path) {
        return 1;
    }

    std::wstring image_path = L"\"" + *exe_path + L"\" --service-run --config \"" + abs_config.wstring() + L"\"";

    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to install the service");
        } else {
            errlog(g_svc_logger, "Failed to open Service Control Manager: error {}", err);
        }
        return 1;
    }

    ScHandle svc{CreateServiceW(scm.get(), SERVICE_NAME.data(), SERVICE_DISPLAY_NAME.data(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, image_path.c_str(), nullptr, nullptr,
            nullptr, nullptr, nullptr)};
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            errlog(g_svc_logger, "Service is already installed. Uninstall first to reinstall.");
        } else if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to install the service");
        } else {
            errlog(g_svc_logger, "Failed to create service: error {}", err);
        }
        return 1;
    }

    wchar_t svc_description[] = L"TrustTunnel VPN client service";
    SERVICE_DESCRIPTIONW desc = {};
    desc.lpDescription = svc_description;
    ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &desc);

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        DWORD err = GetLastError();
        warnlog(g_svc_logger, "Service installed but failed to start: error {}", err);
    }

    print_usage_manual();
    return 0;
}

static int service_uninstall() {
    ScHandle scm{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!scm) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to uninstall the service");
        } else {
            errlog(g_svc_logger, "Failed to open Service Control Manager: error {}", err);
        }
        return 1;
    }

    ScHandle svc{
            OpenServiceW(scm.get(), SERVICE_NAME.data(), STANDARD_RIGHTS_DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS)};
    if (!svc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            errlog(g_svc_logger, "Service is not installed");
        } else if (err == ERROR_ACCESS_DENIED) {
            errlog(g_svc_logger, "Administrator privileges required to uninstall the service");
        } else {
            errlog(g_svc_logger, "Failed to open service: error {}", err);
        }
        return 1;
    }

    SERVICE_STATUS status = {};
    if (QueryServiceStatus(svc.get(), &status) && status.dwCurrentState != SERVICE_STOPPED) {
        infolog(g_svc_logger, "Stopping running service...");
        if (!ControlService(svc.get(), SERVICE_CONTROL_STOP, &status)) {
            DWORD err = GetLastError();
            if (err != ERROR_SERVICE_NOT_ACTIVE) {
                warnlog(g_svc_logger, "Failed to send stop control to service: error {}", err);
            }
        }

        constexpr int MAX_WAIT_MS = 10000;
        constexpr int POLL_INTERVAL_MS = 500;
        int waited_ms = 0;
        while (waited_ms < MAX_WAIT_MS) {
            Sleep(POLL_INTERVAL_MS);
            waited_ms += POLL_INTERVAL_MS;
            if (!QueryServiceStatus(svc.get(), &status)) {
                break;
            }
            if (status.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
        }
        if (status.dwCurrentState != SERVICE_STOPPED) {
            warnlog(g_svc_logger, "Service did not stop within {} seconds", MAX_WAIT_MS / 1000);
        }
    }

    if (!DeleteService(svc.get())) {
        DWORD err = GetLastError();
        errlog(g_svc_logger, "Failed to delete service: error {}", err);
        return 1;
    }

    std::cout << "Service 'TrustTunnelClient' uninstalled successfully.\n";
    return 0;
}

static int service_run(const cxxopts::ParseResult *cli_args) {
    g_svc_cli_args = cli_args;

    wchar_t svc_name[] = L"TrustTunnelClient";
    SERVICE_TABLE_ENTRYW dispatch_table[] = {
            {svc_name, service_main},
            {nullptr, nullptr},
    };

    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        DWORD err = GetLastError();
        errlog(g_svc_logger, "StartServiceCtrlDispatcher failed: error {}", err);
        return 1;
    }

    return 0;
}

#endif // _WIN32
