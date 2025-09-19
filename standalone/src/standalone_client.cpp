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
#include <toml++/toml.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "net/tls.h"
#include "net/network_manager.h"
#include "vpn/standalone/client.h"
#include "vpn/standalone/config.h"
#include "utils.h"

#ifdef __APPLE__
#include "AppleSleepNotifier.h"
#endif

static constexpr std::string_view DEFAULT_CONFIG_FILE = "standalone_client.toml";

using namespace ag;

static const ag::Logger g_logger("STANDALONE_CLIENT_APP");
static std::atomic_bool keep_running{true};
static std::condition_variable g_waiter;
static std::mutex g_waiter_mutex;
static VpnStandaloneClient *g_client;

static std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const VpnStandaloneConfig &config);
static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback();
static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback();

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (g_client) {
#ifndef _WIN32
        if (sig == SIGHUP) {
            g_client->notify_network_change(ag::VPN_NS_NOT_CONNECTED);
            std::thread t([]() {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                g_client->notify_network_change(ag::VPN_NS_CONNECTED);
            });
            t.detach();
            return;
        }
#endif
        keep_running = false;
        g_waiter.notify_all();
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

    cxxopts::Options args("Standalone client", "Simple console client");
    // clang-format off
    args.add_options()
            ("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))
            ("c,config", "Config file name.", cxxopts::value<std::string>()->default_value(std::string(DEFAULT_CONFIG_FILE)))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.", cxxopts::value<std::string>()->default_value("info"))
            ("help", "Print usage");
    // clang-format on

    auto result = args.parse(argc, argv);
    if (result.count("help")) {
        std::cout << args.help() << '\n';
        return 1;
    }

    toml::parse_result parse_result = toml::parse_file(result["config"].as<std::string>());
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", parse_result.error().description());
        return 1;
    }

    std::optional config_res = VpnStandaloneConfig::build_config(parse_result.table());
    if (!config_res) {
        errlog(g_logger, "Failed to parse config");
        return 1;
    }
    auto& config = *config_res;
    if (!StandaloneUtils::apply_cmd_args(config, result)) {
        return 1;
    }
    StandaloneUtils::detect_bound_if(config);
    ag::Logger::set_log_level(config.loglevel);

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    VpnCallbacks callbacks = {
        .protect_handler = get_protect_socket_callback(config),
        .verify_handler = get_verify_certificate_callback(),
        .state_changed_handler = get_state_changed_callback()
    };

    g_client = new VpnStandaloneClient(std::move(config), std::move(callbacks));

    auto res = g_client->set_system_dns();
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }
    res = g_client->connect(std::chrono::seconds(30), VpnStandaloneClient::AutoSetup{});
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }

#ifdef __APPLE__
    auto sleep_notifier = std::make_unique<AppleSleepNotifier>(
            [] { g_client->notify_sleep(); },
            [] { g_client->notify_wake(); });
#endif

    std::unique_lock<std::mutex> lock(g_waiter_mutex);
    g_waiter.wait(lock, []() {
        return !keep_running.load();
    });

#ifdef __APPLE__
    sleep_notifier.reset();
#endif

    g_client->disconnect();
    delete g_client;

    return 0;
}

std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const VpnStandaloneConfig &config) {
    const auto *tun = std::get_if<VpnStandaloneConfig::TunListener>(&config.listener);
    if (!tun) {
        return [](auto){};
    }

    return [bound_if = tun->bound_if](SocketProtectEvent *event) {
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
        if (!bound_if.empty()) {
            if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, bound_if.data(), (socklen_t) bound_if.size())
                    != 0) {
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
            errlog(g_logger, "Error: {} {}", event->error.code, safe_to_string_view(event->error.text));
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
