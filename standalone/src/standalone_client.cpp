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
static std::unique_ptr<VpnOsTunnel> g_tunnel;
static DeclPtr<X509_STORE, &X509_STORE_free> g_ca_store;
#ifdef _WIN32
    static HMODULE g_wintun;
#endif


static std::function<void(SocketProtectEvent *)> get_protect_socket_callback(const VpnStandaloneConfig &config);
static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback(const VpnStandaloneConfig &config);
static std::function<void(VpnStateChangedEvent *)> get_state_changed_callback();
static std::optional<VpnStandaloneClient::ListenerHelper> make_listener(const VpnStandaloneConfig &config);

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

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    VpnCallbacks callbacks = {
        .protect_handler = get_protect_socket_callback(config),
        .verify_handler = get_verify_certificate_callback(config),
        .state_changed_handler = get_state_changed_callback()
    };

    auto listener = make_listener(config);
    if (!listener) {
        errlog(g_logger, "Failed to create listener helper");
        return 1;
    }

    g_client = new VpnStandaloneClient(std::move(config), std::move(callbacks));

    auto res = g_client->set_system_dns();
    if (res) {
        errlog(g_logger, "{}", res->str());
        return 1;
    }
    res = g_client->connect(std::chrono::seconds(30), std::move(*listener));
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
    if (g_tunnel) {
        g_tunnel->deinit();
    }

#ifdef _WIN32
    FreeLibrary(g_wintun);
#endif
    return 0;
}

static std::optional<VpnStandaloneClient::ListenerHelper> make_tun_listener_helper(const VpnStandaloneConfig::TunListener &config, const std::vector<VpnStandaloneConfig::Endpoint> &endpoints, bool killswitch_enabled) {
    std::vector<const char *> included_routes;
    included_routes.reserve(config.included_routes.size());
    for (const auto &route : config.included_routes) {
        included_routes.emplace_back(route.c_str());
    }

    std::vector<std::string> complete_excluded_routes = config.excluded_routes;
    for (const auto &endpoint : endpoints) {
        auto result = ag::utils::split_host_port(endpoint.address);
        if (result.has_error()) {
            errlog(g_logger, "Failed to parse endpoint address: address={}, error={}", endpoint.address,
                    result.error()->str());
            return std::nullopt;
        }
        auto [host_view, port_view] = result.value();
        complete_excluded_routes.emplace_back(host_view.data(), host_view.size());
    }

    std::vector<const char *> excluded_routes;
    excluded_routes.reserve(complete_excluded_routes.size());
    for (const auto &route : complete_excluded_routes) {
        excluded_routes.emplace_back(route.c_str());
    }

    const VpnOsTunnelSettings *defaults = vpn_os_tunnel_settings_defaults();
    VpnOsTunnelSettings tunnel_settings = {.ipv4_address = defaults->ipv4_address,
            .ipv6_address = defaults->ipv6_address,
            .included_routes = {.data = included_routes.data(), .size = uint32_t(included_routes.size())},
            .excluded_routes = {.data = excluded_routes.data(), .size = uint32_t(excluded_routes.size())},
            .mtu = int(config.mtu_size),
            .dns_servers = defaults->dns_servers};

    g_tunnel = ag::make_vpn_tunnel();
    if (g_tunnel == nullptr) {
        errlog(g_logger, "Tunnel create error");
        return std::nullopt;
    }

#ifdef _WIN32
    g_wintun = LoadLibraryEx(
            WINTUN_DLL_NAME.data(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (g_wintun == nullptr) {
        errlog(g_logger, "Failed to load wintun: {}", ag::sys::strerror(GetLastError()));
        return std::nullopt;
    }
    VpnWinTunnelSettings win_settings = *vpn_win_tunnel_settings_defaults();
    win_settings.wintun_lib = g_wintun;
    win_settings.block_inbound = killswitch_enabled;
    VpnError res = g_tunnel->init(&tunnel_settings, &win_settings);
#else
    (void) killswitch_enabled; // Used only in win
    VpnError res = g_tunnel->init(&tunnel_settings);
#endif
    if (res.code != 0) {
        errlog(g_logger, "Failed to initialize tunnel: {}", res.text);
        std::exchange(g_tunnel, nullptr)->deinit();
        return std::nullopt;
    }

    VpnTunListenerConfig listener_config = {
            .fd = g_tunnel->get_fd(),
#ifdef _WIN32
            .tunnel = g_tunnel.get(),
#endif
            .mtu_size = config.mtu_size,
    };

    return VpnStandaloneClient::ListenerHelper(listener_config);
}

static VpnStandaloneClient::ListenerHelper make_socks_listener_helper(const VpnStandaloneConfig::SocksListener &config) {
    VpnSocksListenerConfig cfg = {
            .listen_address = sockaddr_from_str(config.address.c_str()),
            .username = config.username.c_str(),
            .password = config.password.c_str(),
    };
    return VpnStandaloneClient::ListenerHelper(cfg);
}

static std::optional<VpnStandaloneClient::ListenerHelper> make_listener(const VpnStandaloneConfig &config) {
    if (const auto *tun = std::get_if<VpnStandaloneConfig::TunListener>(&config.listener)) {
        return make_tun_listener_helper(*tun, config.location.endpoints, config.killswitch_enabled);
    }
    if (const auto *socks = std::get_if<VpnStandaloneConfig::SocksListener>(&config.listener)) {
        return make_socks_listener_helper(*socks);
    }
    return std::nullopt;
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

static DeclPtr<X509_STORE, &X509_STORE_free> load_certificate(std::string_view pem_certificate) {
    DeclPtr<BIO, &BIO_free> bio {BIO_new_mem_buf(pem_certificate.data(), (long) pem_certificate.size())};

    DeclPtr<X509, &X509_free> cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
    if (cert == nullptr) {
        return nullptr;
    }

    DeclPtr<X509_STORE, &X509_STORE_free> store{tls_create_ca_store()};
    if (store == nullptr) {
        return nullptr;
    }

    X509_STORE_add_cert(store.get(), cert.get());

    return store;
}

static std::function<void(VpnVerifyCertificateEvent *)> get_verify_certificate_callback(const VpnStandaloneConfig &config) {
    if (config.location.skip_verification) {
        return [](VpnVerifyCertificateEvent *event) {
            event->result = VPN_SKIP_VERIFICATION_FLAG;
        };
    }

    g_ca_store = config.location.certificate
                            ? load_certificate(config.location.certificate.value())
                            : nullptr;
    return [](VpnVerifyCertificateEvent *event) {
        const char *err = tls_verify_cert(event->cert, event->chain, g_ca_store.get());
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
