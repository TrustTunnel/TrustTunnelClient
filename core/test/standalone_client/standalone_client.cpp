#ifdef __APPLE__
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
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
#else
#include <sys/ioctl.h>
#endif

#include <atomic>
#include <csignal>
#include <fstream>
#include <optional>
#include <unordered_map>
#include <vector>

#define CXXOPTS_NO_RTTI
#include <cxxopts.hpp>
#include <magic_enum.hpp>
#include <nlohmann/json.hpp>

#include "common/cidr_range.h"
#include "common/file.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "net/os_tunnel.h"
#include "net/tls.h"
#include "tcpip/tcpip.h"
#include "vpn/vpn.h"

static constexpr std::string_view DEFAULT_CONFIG_FILE = "standalone_client.conf";

#ifdef _WIN32
static constexpr std::string_view WINTUN_DLL_NAME = "wintun";
#endif

using namespace ag;

static bool connect_to_server(Vpn *v, int line);
static void vpn_handler(void *arg, VpnEvent what, void *data);

static const ag::Logger g_logger("STANDALONE_CLIENT");

#ifdef __APPLE__
static uint32_t g_bound_if_index = 0; // bound interface index, to avoid route loop
#endif

enum ListenerType {
    LT_TUN,
    LT_SOCKS,
};

static const std::unordered_map<std::string, ag::LogLevel> LOG_LEVEL_MAP = {
        {"error", ag::LOG_LEVEL_ERROR},
        {"warn", ag::LOG_LEVEL_WARN},
        {"info", ag::LOG_LEVEL_INFO},
        {"debug", ag::LOG_LEVEL_DEBUG},
        {"trace", ag::LOG_LEVEL_TRACE},
};

static const std::unordered_map<std::string, ListenerType> LISTENER_TYPE_MAP = {
        {"tun", LT_TUN},
        {"socks", LT_SOCKS},
};

static const std::unordered_map<std::string, VpnUpstreamProtocol> UPSTREAM_PROTO_MAP = {
        {"http2", VPN_UP_HTTP2},
        {"http3", VPN_UP_HTTP3},
};

static const std::unordered_map<std::string, VpnMode> VPN_MODE_MAP = {
        {"general", VPN_MODE_GENERAL},
        {"selective", VPN_MODE_SELECTIVE},
};

static cxxopts::Options g_options("Standalone client", "Simple macOS/Linux console client");

static std::optional<std::string> read_file_to_str(const std::string &filename) {
    std::string file_str;

    auto file = ag::file::open(filename, ag::file::RDONLY);
    if (file < 0) {
        errlog(g_logger, "Cannot open file: {}", strerror(errno));
        return std::nullopt;
    }
    size_t size = ag::file::get_size(file);
    file_str.resize(size);
    auto read_size = ag::file::read(file, file_str.data(), size);

    if (read_size == 0) {
        errlog(g_logger, "Cannot read data from file: {}", strerror(errno));
        return std::nullopt;
    }
    ag::file::close(file);
    return file_str;
}

struct Params {
    std::string hostname;
    std::vector<std::string> addresses;
    std::string username;
    std::string password;
    std::string listener_pass;
    std::string listener_username;
    std::string listener_address;
    ag::LogLevel loglevel = ag::LOG_LEVEL_INFO;
    ListenerType listener_type = LT_SOCKS;
    bool skip_verify = false;
    uint32_t mtu_size = DEFAULT_MTU_SIZE;
    std::vector<std::string> included_routes;
    std::vector<std::string> excluded_routes;
    std::string dns_upstream;
    std::string bound_if;
    bool killswitch_enabled;
    std::string exclusions;
    VpnUpstreamProtocol upstream_protocol;
    std::optional<VpnUpstreamProtocol> upstream_fallback_protocol;
    VpnMode mode;

    void init(cxxopts::ParseResult &result, const std::string &config) {
        parse_json_config(config);
        parse_args(result);
    }

    void parse_args(cxxopts::ParseResult &result) {
        if (result.count("s") > 0) {
            skip_verify = result["s"].as<bool>();
        }
        if (result.count("loglevel") > 0) {
            set_loglevel(result["loglevel"].as<std::string>());
        }
    }

    void parse_listener_info(nlohmann::json::reference &listener_info) {
        listener_username = listener_info["socks_user"];
        listener_pass = listener_info["socks_pass"];
        std::string host = listener_info["socks_host"];
        if (listener_username.empty() && listener_pass.empty()) {
            host = "127.0.0.1";
        }
        std::string port = listener_info["socks_port"];
        listener_address = host + ":" + port;
    }

    void parse_server_info(nlohmann::json::reference &server_info) {
        hostname = server_info["hostname"];
        auto json_addrs = server_info["addresses"];
        addresses.reserve(json_addrs.size());
        std::transform(json_addrs.begin(), json_addrs.end(), std::back_inserter(addresses), [](auto &json_addr) {
            return (std::string) json_addr;
        });
        username = server_info["username"];
        password = server_info["password"];
        skip_verify = server_info["skip_cert_verify"];
        if (server_info.contains("upstream_protocol")) {
            upstream_protocol = UPSTREAM_PROTO_MAP.at(server_info["upstream_protocol"]);
        }
        if (server_info.contains("upstream_fallback_protocol")) {
            upstream_fallback_protocol = UPSTREAM_PROTO_MAP.at(server_info["upstream_fallback_protocol"]);
        }
    }

    void parse_routes(
            nlohmann::json::reference &included_routes_info, nlohmann::json::reference &excluded_routes_info) {
        for (std::string route : included_routes_info) {
            included_routes.emplace_back(std::move(route));
        }
        for (std::string route : excluded_routes_info) {
            excluded_routes.emplace_back(std::move(route));
        }
    }

    void parse_json_config(const std::string &config) {
        nlohmann::json config_file = nlohmann::json::parse(config);
        parse_server_info(config_file["server_info"]);

        if (auto it = LISTENER_TYPE_MAP.find(config_file["listener_type"]); it != LISTENER_TYPE_MAP.end()) {
            listener_type = it->second;
        }
        if (auto it = VPN_MODE_MAP.find(config_file["vpn_mode"]); it != VPN_MODE_MAP.end()) {
            mode = it->second;
        }

        if (listener_type == LT_TUN) {
            auto tun_info = config_file["tun_info"];
            mtu_size = tun_info["mtu_size"];
            parse_routes(tun_info["included_routes"], tun_info["excluded_routes"]);
            if (tun_info.contains("bound_if") && tun_info["bound_if"].is_string()) {
                bound_if = tun_info["bound_if"];
            }
#ifdef __APPLE__
            if (bound_if.empty()) {
                g_bound_if_index = 0;
            } else {
                g_bound_if_index = if_nametoindex(bound_if.c_str());
                // user put wrong interface name in settings
                if (g_bound_if_index == 0) {
                    errlog(g_logger, "Unknown interface type, use 'ifconfig' to see possible values");
                    exit(1);
                }
            }
#endif
#ifdef _WIN32
            uint32_t idx;
            bound_if.empty() ? idx = 0 : idx = if_nametoindex(bound_if.c_str());
            if (idx == 0) {
                idx = vpn_win_detect_active_if();
            }
            vpn_win_set_bound_if(idx);
#endif
        } else if (listener_type == LT_SOCKS) {
            parse_listener_info(config_file["socks_info"]);
        }

        set_loglevel(config_file["loglevel"]);

        if (config_file.contains("dns_upstream")) {
            dns_upstream = config_file["dns_upstream"];
        }
        if (config_file.contains("killswitch_enabled")) {
            killswitch_enabled = config_file["killswitch_enabled"];
        }
        if (config_file.contains("exclusions")) {
            for (auto x : config_file["exclusions"]) {
                exclusions += x;
                exclusions += ' ';
            }
        }
    }

    void set_loglevel(const std::string &loglevel_str) {
        if (auto it = LOG_LEVEL_MAP.find(loglevel_str); it != LOG_LEVEL_MAP.end()) {
            loglevel = it->second;
        } else {
            errlog(g_logger, "Unknown logger type, pass --help to see possible values");
            exit(1);
        }
    }
};

static DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> g_extra_loop{nullptr};
static VpnSettings g_vpn_settings = {{vpn_handler, nullptr}, {}};
static VpnUpstreamConfig g_vpn_server_config;
static std::vector<VpnEndpoint> g_endpoints;
static VpnListenerConfig g_vpn_common_listener_config;
static VpnTunListenerConfig g_vpn_tun_listener_config;
static VpnSocksListenerConfig g_vpn_socks_listener_config;
static std::atomic<Vpn *> g_vpn;
static Params g_params;
static std::unique_ptr<ag::VpnOsTunnel> g_tunnel;

static std::mutex g_listener_runner_mutex;
static std::condition_variable g_listener_runner_barrier;
static std::atomic_bool g_stop = false;
#ifdef _WIN32
static HMODULE g_wintun;
#endif

static void sighandler(int /*sig*/) {
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);

    if (g_vpn != nullptr) {
        g_stop = true;
        g_listener_runner_barrier.notify_one();
    } else {
        exit(1);
    }
}

static bool connect_to_server(Vpn *v, int line) {
    VpnConnectParameters parameters = {
            .upstream_config = g_vpn_server_config,
    };
    VpnError err = vpn_connect(v, &parameters);
    if (err.code != 0) {
        errlog(g_logger, "Failed to connect to server (line={}): {} ({})\n", line, safe_to_string_view(err.text),
                err.code);
        return false;
    }

    return true;
}

static void vpn_runner(ListenerType type) {
    if (!connect_to_server(g_vpn, __LINE__)) {
        g_stop = true;
        return;
    }

    VpnListener *listener;

    switch (type) {
    case LT_TUN: {
        VpnOsTunnelSettings common_settings{};
        const auto *defaults = vpn_os_tunnel_settings_defaults();
        // append endpoint address to excluded routes
        std::string ipv4_address = "172.16.218.0";
        std::string ipv6_address = "fd00::0";
        common_settings.ipv4_address = ipv4_address.c_str();
        common_settings.ipv6_address = ipv6_address.c_str();
        common_settings.mtu = defaults->mtu;
        std::vector<const char *> included_routes;
        for (auto &route : g_params.included_routes) {
            included_routes.emplace_back(route.c_str());
        }
        common_settings.included_routes.data = included_routes.data();
        common_settings.included_routes.size = included_routes.size();

        std::vector<std::string> owned_excluded_routes = g_params.excluded_routes;
        for (const std::string &address : g_params.addresses) {
            auto [host_view, port_view] = ag::utils::split_host_port(address.c_str());
            owned_excluded_routes.emplace_back(host_view.data(), host_view.size());
        }

        std::vector<const char *> excluded_routes;
        for (auto &route : owned_excluded_routes) {
            excluded_routes.emplace_back(route.c_str());
        }

        common_settings.excluded_routes.data = excluded_routes.data();
        common_settings.excluded_routes.size = excluded_routes.size();
        g_tunnel = ag::make_vpn_tunnel();
        if (g_tunnel == nullptr) {
            errlog(g_logger, "Tunnel create error");
            g_stop = true;
            return;
        }

#ifdef _WIN32
        g_wintun = LoadLibraryEx(WINTUN_DLL_NAME.data(), nullptr,
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (g_wintun == nullptr) {
            errlog(g_logger, "Failed to load wintun: {}", ag::sys::strerror(GetLastError()));
            g_stop = true;
            return;
        }
        VpnWinTunnelSettings win_settings{};
        const auto *win_defaults = vpn_win_tunnel_settings_defaults();
        win_settings.wintun_lib = g_wintun;
        win_settings.adapter_name = win_defaults->adapter_name;
        static const char *dns_servers[] = {
                AG_UNFILTERED_DNS_IPS_V4[0].data(),
                AG_UNFILTERED_DNS_IPS_V4[1].data(),
                AG_UNFILTERED_DNS_IPS_V6[0].data(),
                AG_UNFILTERED_DNS_IPS_V6[1].data(),
        };
        win_settings.dns_servers = {dns_servers, 4};
        auto res = g_tunnel->init(&common_settings, &win_settings);
#else
        auto res = g_tunnel->init(&common_settings);
#endif
        if (res.code != 0) {
            errlog(g_logger, "{}", res.text);
            g_tunnel->deinit();
            g_tunnel.reset();
            g_stop = true;
            return;
        }
        g_vpn_tun_listener_config.fd = g_tunnel->get_fd();
        g_vpn_tun_listener_config.mtu_size = common_settings.mtu;
#ifdef _WIN32
        g_vpn_tun_listener_config.tunnel = g_tunnel.get();
#endif
        listener = vpn_create_tun_listener(g_vpn, &g_vpn_tun_listener_config);
        break;
    }
    case LT_SOCKS:
        listener = vpn_create_socks_listener(g_vpn, &g_vpn_socks_listener_config);
        break;
    default:
        assert(0);
    }

    assert(listener != nullptr);

    auto error = vpn_listen(g_vpn, listener, &g_vpn_common_listener_config);
    if (error.code != 0) {
        errlog(g_logger, "Failed on start listening: {} ({})", safe_to_string_view(error.text),
                magic_enum::enum_name((VpnErrorCode) error.code));
        g_tunnel->deinit();
        g_tunnel.reset();
        g_stop = true;
    }
}

static void listener_runner(ListenerType listener_type) {
    g_vpn = vpn_open(&g_vpn_settings);
    if (g_vpn == nullptr) {
        abort();
    }

    vpn_runner(listener_type);
    std::unique_lock<std::mutex> listener_runner_lock(g_listener_runner_mutex);
    g_listener_runner_barrier.wait(listener_runner_lock, []() {
        return g_stop.load();
    });
    listener_runner_lock.unlock();
    Vpn *vpn = g_vpn.exchange(nullptr);
    vpn_stop(vpn);
    vpn_close(vpn);
    if (g_tunnel) {
        g_tunnel->deinit();
        g_tunnel.reset();
    }
#ifdef _WIN32
    FreeLibrary(g_wintun);
#endif
}

static void vpn_protect_socket(SocketProtectEvent *event) {
#ifdef __APPLE__
    uint32_t idx = g_bound_if_index;
    if (idx == 0) {
        return;
    }
    if (event->peer->sa_family == AF_INET) {
        setsockopt(event->fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
    } else if (event->peer->sa_family == AF_INET6) {
        setsockopt(event->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
    }
#endif // __APPLE__
#ifdef __linux__
    if (!g_params.bound_if.empty()) {
        setsockopt(
                event->fd, SOL_SOCKET, SO_BINDTODEVICE, g_params.bound_if.data(), (socklen_t) g_params.bound_if.size());
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
        // do nothing
        break;
    case VPN_EVENT_VERIFY_CERTIFICATE: {
        auto *event = (VpnVerifyCertificateEvent *) data;
        const char *err = g_params.skip_verify ? nullptr : tls_verify_cert(event->ctx, nullptr);
        if (err == nullptr) {
            tracelog(g_logger, "Certificate verified successfully\n");
            event->result = 0;
        } else {
            errlog(g_logger, "Failed to verify certificate: {}\n", err);
            event->result = -1;
        }
        break;
    }
    case VPN_EVENT_STATE_CHANGED: {
        const VpnStateChangedEvent *event = (VpnStateChangedEvent *) data;
        if (event->state == VPN_SS_WAITING_RECOVERY) {
            tracelog(g_logger, "Endpoint connection state changed: state={} to_next={}ms err={} {}\n", event->state,
                    (int) event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                    safe_to_string_view(event->waiting_recovery_info.error.text));
        } else if (event->error.code != 0 && event->state != VPN_SS_CONNECTED) {
            tracelog(g_logger, "Endpoint connection state changed: state={} err={} {}\n", event->state,
                    event->error.code, safe_to_string_view(event->error.text));
        }
        break;
    }
    case VPN_EVENT_CONNECT_REQUEST: {
        const VpnConnectRequestEvent *event = (VpnConnectRequestEvent *) data;

        auto *info = new VpnConnectionInfo{event->id};
#ifndef REDIRECT_ONLY_TCP
        info->action = VPN_CA_DEFAULT;
#else
        info->action = (event->proto == IPPROTO_TCP) ? VPN_CA_DEFAULT : VPN_CA_FORCE_BYPASS;
#endif

#ifdef FUZZY_ACTION
        info->action = rand() % (VPN_CA_FORCE_REDIRECT + 1);
#endif

        info->appname = "standalone_client";
        vpn_event_loop_submit(g_extra_loop.get(),
                {
                        .arg = info,
                        .action =
                                [](void *arg, TaskId) {
                                    auto info = (VpnConnectionInfo *) arg;
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
}

static std::string get_config(const std::string &filename) {
    auto file_str = read_file_to_str(filename);
    if (file_str.has_value()) {
        return file_str.value();
    }
    errlog(g_logger, "Cannot parse config file");
    exit(1);
}

void apply_vpn_settings() {
    g_vpn_settings.killswitch_enabled = g_params.killswitch_enabled;
    g_vpn_settings.exclusions = {g_params.exclusions.data(), (uint32_t) g_params.exclusions.size()};
    g_vpn_settings.mode = g_params.mode;

    g_endpoints.reserve(g_params.addresses.size());
    for (const std::string &address : g_params.addresses) {
        g_endpoints.emplace_back(VpnEndpoint{
                .address = sockaddr_from_str(address.c_str()),
                .name = g_params.hostname.c_str(),
        });
    }
    g_vpn_server_config.location = {"test-location", {g_endpoints.data(), uint32_t(g_endpoints.size())}};
    g_vpn_server_config.username = g_params.username.c_str();
    g_vpn_server_config.password = g_params.password.c_str();
    g_vpn_server_config.protocol.type = g_params.upstream_protocol;
    if (g_params.upstream_fallback_protocol.has_value()) {
        g_vpn_server_config.fallback.enabled = true;
        g_vpn_server_config.fallback.protocol.type = g_params.upstream_fallback_protocol.value();
    }

    switch (g_params.listener_type) {
    case LT_TUN:
        break;
    case LT_SOCKS:
        g_vpn_socks_listener_config.listen_address = sockaddr_from_str(g_params.listener_address.c_str());
        g_vpn_socks_listener_config.username = g_params.listener_username.c_str();
        g_vpn_socks_listener_config.password = g_params.listener_pass.c_str();
        break;
    default:
        assert(0);
    }

    if (!g_params.dns_upstream.empty()) {
        g_vpn_common_listener_config.dns_upstream = g_params.dns_upstream.c_str();
    }
}

static void setup_sighandler() {
#ifdef _WIN32
    signal(SIGINT, sighandler);
    signal(SIGTERM, sighandler);
#else
    // Block SIGINT and SIGTERM - they will be waited using sigwait().
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
    std::thread([sigset] {
        int signum = 0;
        sigwait(&sigset, &signum);
        sighandler(signum);
    }).detach();
#endif
}

int main(int argc, char **argv) {
    srand(time(nullptr));
    setup_sighandler();
#ifndef _WIN32
    // Ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    // clang-format off
    g_options.add_options()
            ("s", "Skip verify certificate", cxxopts::value<bool>()->default_value("false"))
            ("c,config", "Config file name.", cxxopts::value<std::string>()->default_value(std::string(DEFAULT_CONFIG_FILE)))
            ("l,loglevel", "Logging level. Possible values: error, warn, info, debug, trace.", cxxopts::value<std::string>()->default_value("info"))
            ("help", "Print usage");
    // clang-format on

    auto result = g_options.parse(argc, argv);
    if (result.count("help")) {
        std::cout << g_options.help() << std::endl;
        exit(0);
    }
    auto filename = result["config"].as<std::string>();
    g_params.init(result, get_config(filename));

    ag::Logger::set_log_level(g_params.loglevel);

    apply_vpn_settings();

    g_extra_loop.reset(vpn_event_loop_create());
    std::thread m_loop_thread = std::thread([loop = g_extra_loop.get()]() {
        vpn_event_loop_run(loop);
    });

    listener_runner(g_params.listener_type);

    vpn_event_loop_stop(g_extra_loop.get());
    if (m_loop_thread.joinable()) {
        m_loop_thread.join();
    }

    return 0;
}
