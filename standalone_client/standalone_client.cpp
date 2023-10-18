#ifdef __APPLE__
#include <net/if.h>
#include <netinet/in.h>
#include "net/mac_dns_settings_manager.h"
#endif // __APPLE__

#ifdef __linux__
// clang-format off
#include <net/if.h>

#include <linux/if.h>
#include <linux/if_tun.h>
// clang-format on
#endif

#ifdef _WIN32
#include <WinSock2.h>
#endif

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <cxxopts.hpp>
#include <magic_enum.hpp>
#include <toml++/toml.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "config.h"
#include "net/network_manager.h"
#include "net/os_tunnel.h"
#include "net/tls.h"
#include "net/utils.h"
#include "vpn/vpn.h"

static constexpr std::string_view DEFAULT_CONFIG_FILE = "standalone_client.toml";

#ifdef _WIN32
static constexpr std::string_view WINTUN_DLL_NAME = "wintun";
#endif

using namespace ag;

static const ag::Logger g_logger("STANDALONE_CLIENT");
static DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> g_extra_loop{nullptr};
static std::atomic<Vpn *> g_vpn;
static Config g_config;
static std::unique_ptr<ag::VpnOsTunnel> g_tunnel;

static std::mutex g_listener_runner_mutex;
static std::condition_variable g_listener_runner_barrier;
static std::atomic_bool g_stop = false;
#ifdef _WIN32
static HMODULE g_wintun;
#endif

static void sighandler(int sig) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (g_vpn != nullptr) {
        if (sig == SIGHUP) {
            vpn_notify_network_change(g_vpn, true);
            return;
        }
        g_stop = true;
        g_listener_runner_barrier.notify_one();
    } else {
        exit(1);
    }
}

template <typename T>
static std::string streamable_to_string(const T &obj) {
    std::stringstream stream;
    stream << obj;
    return stream.str();
}

static void vpn_protect_socket(SocketProtectEvent *event) {
    const auto *tun = std::get_if<Config::TunListener>(&g_config.listener);
    if (tun == nullptr) {
        return;
    }

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
    if (!tun->bound_if.empty()) {
        if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, tun->bound_if.data(), (socklen_t) tun->bound_if.size())
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
}

static void vpn_handler(void *, VpnEvent what, void *data) {
    switch (what) {
    case VPN_EVENT_PROTECT_SOCKET: {
        // protect socket to avoid route loop
        auto *event = (SocketProtectEvent *) data;
        vpn_protect_socket(event);
        break;
    }
    case VPN_EVENT_CLIENT_OUTPUT:
    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
    case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
    case VPN_EVENT_TUNNEL_CONNECTION_STATS:
    case VPN_EVENT_TUNNEL_CONNECTION_CLOSED:
        // do nothing
        break;
    case VPN_EVENT_VERIFY_CERTIFICATE: {
        auto *event = (VpnVerifyCertificateEvent *) data;
        const char *err = g_config.endpoint.skip_verification
                ? nullptr
                : tls_verify_cert(event->ctx, g_config.endpoint.ca_store.get());
        if (err == nullptr) {
            tracelog(g_logger, "Certificate verified successfully");
            event->result = g_config.endpoint.skip_verification ? VPN_SKIP_VERIFICATION_FLAG : 0;
        } else {
            errlog(g_logger, "Failed to verify certificate: {}", err);
            event->result = -1;
        }
        break;
    }
    case VPN_EVENT_STATE_CHANGED: {
        const VpnStateChangedEvent *event = (VpnStateChangedEvent *) data;
        switch (event->state) {
        case VPN_SS_DISCONNECTED:
            errlog(g_logger, "Error: {} {}", event->error.code, safe_to_string_view(event->error.text));
            g_stop = true;
            g_listener_runner_barrier.notify_one();
            break;
        case VPN_SS_WAITING_RECOVERY:
            warnlog(g_logger, "Waiting recovery: to next={}ms error={} {}",
                    event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                    safe_to_string_view(event->waiting_recovery_info.error.text));
            break;
        case VPN_SS_CONNECTING:
        case VPN_SS_CONNECTED:
        case VPN_SS_RECOVERING:
            break;
        }
        break;
    }
    case VPN_EVENT_CONNECT_REQUEST: {
        const VpnConnectRequestEvent *event = (VpnConnectRequestEvent *) data;

        auto *info = new VpnConnectionInfo{event->id};
        info->action = VPN_CA_DEFAULT;

        info->appname = "standalone_client";
        vpn_event_loop_submit(g_extra_loop.get(),
                {
                        .arg = info,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *info = (VpnConnectionInfo *) arg;
                                    if (g_vpn) {
                                        vpn_complete_connect_request(g_vpn, info);
                                    }
                                },
                        .finalize =
                                [](void *arg) {
                                    delete (VpnConnectionInfo *) arg;
                                },
                });
        break;
    }
    }
} // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)

static bool connect_to_server(Vpn *v) {
    std::vector<VpnEndpoint> endpoints;
    endpoints.reserve(g_config.endpoint.addresses.size());
    for (const std::string &address : g_config.endpoint.addresses) {
        endpoints.emplace_back(VpnEndpoint{
                .address = sockaddr_from_str(address.c_str()),
                .name = g_config.endpoint.hostname.c_str(),
        });
    }

    VpnConnectParameters parameters = {
            .upstream_config =
                    {
                            .protocol = {.type = g_config.endpoint.upstream_protocol},
                            .location =
                                    {
                                            .id = "hello-location",
                                            .endpoints = {endpoints.data(), uint32_t(endpoints.size())},
                                    },
                            .username = g_config.endpoint.username.c_str(),
                            .password = g_config.endpoint.password.c_str(),
                            .anti_dpi = g_config.endpoint.anti_dpi,
                    },
    };

    if (g_config.endpoint.upstream_fallback_protocol.has_value()) {
        parameters.upstream_config.fallback.enabled = true;
        parameters.upstream_config.fallback.protocol.type = *g_config.endpoint.upstream_fallback_protocol;
    }

    VpnError err = vpn_connect(v, &parameters);
    if (err.code != 0) {
        errlog(g_logger, "Failed to initiate endpoint connection: {} ({})", safe_to_string_view(err.text),
                magic_enum::enum_name((VpnErrorCode) err.code));
        return false;
    }

    return true;
}

static VpnListener *make_tun_listener() {
    auto &config = std::get<Config::TunListener>(g_config.listener);
#ifdef __linux__
    if (config.bound_if.empty()) {
        infolog(g_logger, "Outbound interface is not specified, trying to detect it automatically");
        constexpr std::string_view CMD = "ip -o route show to default";
        infolog(g_logger, "{} {}", (geteuid() == 0) ? '#' : '$', CMD);
        Result result = tunnel_utils::fsystem_with_output(CMD);
        if (result.has_error()) {
            errlog(g_logger,
                    "Couldn't detect the outbound interface automatically. Please specify it manually. Error: {}",
                    result.error()->str());
            return nullptr;
        }

        dbglog(g_logger, "Command output: {}", result.value());
        std::vector parts = utils::split_by(result.value(), ' ');
        auto found = std::find(parts.begin(), parts.end(), "dev");
        if (found == parts.end() || std::next(found) == parts.end()) {
            errlog(g_logger, "Couldn't find the outbound interface name automatically. Please specify it manually.");
            return nullptr;
        }

        config.bound_if = *std::next(found);
        infolog(g_logger, "Using automatically detected outbound interface: {}", config.bound_if);
    }
#endif

    uint32_t if_index = 0;
    if (!config.bound_if.empty()) {
        if_index = if_nametoindex(config.bound_if.c_str());
        if (if_index == 0) {
            errlog(g_logger, "Unknown interface name, use 'ifconfig' to see possible values");
            return nullptr;
        }
    } else {
#ifdef _WIN32
        if_index = vpn_win_detect_active_if();
        if (if_index == 0) {
            errlog(g_logger, "Couldn't detect active network interface");
            return nullptr;
        }
        char if_name[IF_NAMESIZE]{};
        if_indextoname(if_index, if_name);
        infolog(g_logger, "Using network interface: {} ({})", if_name, if_index);
#endif
    }
    vpn_network_manager_set_outbound_interface(if_index);

    std::vector<const char *> included_routes;
    included_routes.reserve(config.included_routes.size());
    for (const auto &route : config.included_routes) {
        included_routes.emplace_back(route.c_str());
    }

    std::vector<std::string> complete_excluded_routes = config.excluded_routes;
    for (const std::string &address : g_config.endpoint.addresses) {
        auto result = ag::utils::split_host_port(address);
        if (result.has_error()) {
            errlog(g_logger, "Failed to parse endpoint address: address={}, error={}", address, result.error()->str());
            return nullptr;
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
    VpnOsTunnelSettings tunnel_settings = {
            .ipv4_address = defaults->ipv4_address,
            .ipv6_address = defaults->ipv6_address,
            .included_routes = {.data = included_routes.data(), .size = uint32_t(included_routes.size())},
            .excluded_routes = {.data = excluded_routes.data(), .size = uint32_t(excluded_routes.size())},
            .mtu = int(config.mtu_size),
    };

    g_tunnel = ag::make_vpn_tunnel();
    if (g_tunnel == nullptr) {
        errlog(g_logger, "Tunnel create error");
        return nullptr;
    }

#ifdef _WIN32
    g_wintun = LoadLibraryEx(
            WINTUN_DLL_NAME.data(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (g_wintun == nullptr) {
        errlog(g_logger, "Failed to load wintun: {}", ag::sys::strerror(GetLastError()));
        return nullptr;
    }
    VpnWinTunnelSettings win_settings{};
    const auto *win_defaults = vpn_win_tunnel_settings_defaults();
    win_settings.wintun_lib = g_wintun;
    win_settings.adapter_name = win_defaults->adapter_name;
    static constexpr const char *DNS_SERVERS[] = {
            // should be null-terminated
            AG_UNFILTERED_DNS_IPS_V4[0].data(),
    };
    win_settings.dns_servers = {
            .data = (const char **) DNS_SERVERS,
            .size = uint32_t(std::size(DNS_SERVERS)),
    };
    VpnError res = g_tunnel->init(&tunnel_settings, &win_settings);
#else
    VpnError res = g_tunnel->init(&tunnel_settings);
#endif
    if (res.code != 0) {
        errlog(g_logger, "Failed to initialize tunnel: {}", res.text);
        std::exchange(g_tunnel, nullptr)->deinit();
        return nullptr;
    }

    VpnTunListenerConfig listener_config = {
            .fd = g_tunnel->get_fd(),
#ifdef _WIN32
            .tunnel = g_tunnel.get(),
#endif
            .mtu_size = config.mtu_size,
    };

    return vpn_create_tun_listener(g_vpn, &listener_config);
}

static VpnListener *make_socks_listener() {
    const auto &cfg = std::get<Config::SocksListener>(g_config.listener);
    VpnSocksListenerConfig config = {
            .listen_address = sockaddr_from_str(cfg.address.c_str()),
            .username = cfg.username.c_str(),
            .password = cfg.password.c_str(),
    };
    return vpn_create_socks_listener(g_vpn, &config);
}

static void vpn_runner() {
    if (!connect_to_server(g_vpn)) {
        g_stop = true;
        return;
    }

    VpnListener *listener = std::holds_alternative<Config::TunListener>(g_config.listener) ? make_tun_listener()
                                                                                           : make_socks_listener();
    if (listener == nullptr) {
        g_stop = true;
        return;
    }

    std::vector<const char *> dns_upstreams;
    dns_upstreams.reserve(g_config.dns_upstreams.size());
    for (const std::string &upstream : g_config.dns_upstreams) {
        dns_upstreams.emplace_back(upstream.c_str());
    }

    VpnListenerConfig listener_config = {
            .dns_upstreams = {.data = dns_upstreams.data(), .size = uint32_t(dns_upstreams.size())},
    };
    VpnError error = vpn_listen(g_vpn, listener, &listener_config);
    if (error.code != 0) {
        errlog(g_logger, "Failed to start listening: {} ({})", safe_to_string_view(error.text),
                magic_enum::enum_name((VpnErrorCode) error.code));
        std::exchange(g_tunnel, nullptr)->deinit();
        g_stop = true;
    }
}

static int listener_runner() {
#ifdef _WIN32
    uint32_t if_index = vpn_win_detect_active_if();
    if (if_index == 0) {
        errlog(g_logger, "Couldn't detect active network interface");
        return 1;
    }
    Result<SystemDnsServers, RetrieveInterfaceDnsError> result = retrieve_interface_dns_servers(if_index);
    if (result.has_error()) {
        errlog(g_logger, "Failed to collect DNS servers: {}", result.error()->str());
        return 1;
    }
    if (!vpn_network_manager_update_system_dns(std::move(result.value()))) {
        errlog(g_logger, "Failed to update DNS servers");
        return 1;
    }
#else
    Result<SystemDnsServers, RetrieveSystemDnsError> result = retrieve_system_dns_servers();
    if (result.has_error()) {
        errlog(g_logger, "Failed to collect DNS servers: {}", result.error()->str());
        return 1;
    }
    if (!vpn_network_manager_update_system_dns(std::move(result.value()))) {
        errlog(g_logger, "Failed to update DNS servers");
        return 1;
    }
#ifdef __APPLE__
    std::unique_ptr<VpnMacDnsSettingsManager> dns_manager;
    if (std::holds_alternative<Config::TunListener>(g_config.listener)) {
        dns_manager = VpnMacDnsSettingsManager::create(AG_UNFILTERED_DNS_IPS_V4[0]);
    }
#endif // __APPLE__
#endif

    VpnSettings settings = {
            .handler = {vpn_handler, nullptr},
            .mode = g_config.mode,
            .exclusions = {g_config.exclusions.data(), (uint32_t) g_config.exclusions.size()},
            .killswitch_enabled = g_config.killswitch_enabled,
    };
    g_vpn = vpn_open(&settings);
    if (g_vpn == nullptr) {
        errlog(g_logger, "Failed on create VPN instance");
        return 1;
    }

    vpn_runner();
    std::unique_lock<std::mutex> listener_runner_lock(g_listener_runner_mutex);
    g_listener_runner_barrier.wait(listener_runner_lock, []() {
        return g_stop.load();
    });
    listener_runner_lock.unlock();
    Vpn *vpn = g_vpn.exchange(nullptr);
    vpn_stop(vpn);
    vpn_close(vpn);

    if (auto tun = std::exchange(g_tunnel, nullptr); tun != nullptr) {
        tun->deinit();
    }

#ifdef _WIN32
    FreeLibrary(g_wintun);
#endif

    return 0;
}

static void setup_sighandler() {
#ifdef _WIN32
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
    signal(SIGHUP, sighandler);
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
        std::cout << args.help() << std::endl;
        exit(0);
    }

    toml::parse_result parse_result = toml::parse_file(result["config"].as<std::string>());
    if (!parse_result) {
        errlog(g_logger, "Failed parsing configuration: {}", streamable_to_string(parse_result.error()));
        exit(1);
    }

    g_config.apply_config(parse_result.table());
    g_config.apply_cmd_args(result);

    ag::Logger::set_log_level(g_config.loglevel);

    g_extra_loop.reset(vpn_event_loop_create());
    std::thread m_loop_thread = std::thread([loop = g_extra_loop.get()]() {
        vpn_event_loop_run(loop);
    });

    int ret = listener_runner();

    vpn_event_loop_stop(g_extra_loop.get());
    if (m_loop_thread.joinable()) {
        m_loop_thread.join();
    }

    return ret;
}
