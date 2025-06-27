#ifdef __APPLE__
#include <net/if.h>
#include <netinet/in.h>
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

#include <memory>
#include <string>
#include <vector>

#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "net/network_manager.h"
#include "net/os_tunnel.h"
#include "net/tls.h"
#include "net/utils.h"
#include "vpn/standalone/client.h"
#include "vpn/standalone/config.h"
#include "vpn/vpn.h"

namespace ag {

VpnStandaloneClient::VpnStandaloneClient(VpnStandaloneConfig &&config)
        : m_config(std::move(config))
        , m_extra_loop(vpn_event_loop_create()) {
    if (!m_config.log_file_path.empty()) {
        m_logfile_handler.emplace(m_config.log_file_path);
        m_logtofile.emplace(m_logfile_handler->get_file());
        ag::Logger::set_callback(m_logtofile.value());
    }
    ag::Logger::set_log_level(m_config.loglevel);
    m_loop_thread = std::thread([loop = m_extra_loop.get()]() {
        vpn_event_loop_run(loop);
    });
};

VpnStandaloneClient::~VpnStandaloneClient() {
    vpn_event_loop_stop(m_extra_loop.get());
    if (m_loop_thread.joinable()) {
        m_loop_thread.join();
    }
}

Error<VpnStandaloneClient::ConnectResultError> VpnStandaloneClient::connect(std::chrono::milliseconds timeout) {
    m_connect_timeout = timeout;
    return connect_impl();
}

int VpnStandaloneClient::disconnect() {
    Vpn *vpn = m_vpn.exchange(nullptr);
    vpn_stop(vpn);
    vpn_close(vpn);

    if (auto tun = std::exchange(m_tunnel, nullptr); tun != nullptr) {
        tun->deinit();
    }

#ifdef _WIN32
    FreeLibrary(m_wintun);
#endif
    return 0;
}

void VpnStandaloneClient::notify_network_change(VpnNetworkState state) {
    vpn_notify_network_change(m_vpn, state);
}

void VpnStandaloneClient::notify_sleep() {
    vpn_notify_sleep(m_vpn, [](void *){}, nullptr);
}

void VpnStandaloneClient::notify_wake() {
    vpn_notify_wake(m_vpn);
}

void VpnStandaloneClient::vpn_protect_socket(SocketProtectEvent *event) {
    const auto *tun = std::get_if<VpnStandaloneConfig::TunListener>(&m_config.listener);
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

int VpnStandaloneClient::set_outbound_interface() {
    auto &config = std::get<VpnStandaloneConfig::TunListener>(m_config.listener);
    uint32_t if_index = 0;
    if (!config.bound_if.empty()) {
        if_index = if_nametoindex(config.bound_if.c_str());
        if (if_index == 0) {
            if (auto idx = ag::utils::to_integer<uint32_t>(config.bound_if)) {
                if_index = idx.value();
            }
        }
        if (if_index == 0) {
            errlog(m_logger, "Unknown interface name: {}. Use 'ifconfig' to see possible values", config.bound_if);
            return -1;
        }
    }
    vpn_network_manager_set_outbound_interface(if_index);
    return 0;
}

Error<VpnStandaloneClient::ConnectResultError> VpnStandaloneClient::dns_runner() {
#ifdef _WIN32
    uint32_t if_index = vpn_win_detect_active_if();
    if (if_index == 0) {
        return make_error(ConnectResultError{}, "Couldn't detect active network interface");
    }
    Result<SystemDnsServers, RetrieveInterfaceDnsError> result = retrieve_interface_dns_servers(if_index);
    if (result.has_error()) {
        return make_error(ConnectResultError{}, AG_FMT("Failed to collect DNS servers: {}", result.error()->str()));
    }
    if (!vpn_network_manager_update_system_dns(std::move(result.value()))) {
        return make_error(ConnectResultError{}, "Failed to update DNS servers");
    }
#elif !defined(__ANDROID__)
    Result<SystemDnsServers, RetrieveSystemDnsError> result = retrieve_system_dns_servers();
    if (result.has_error()) {
        return make_error(ConnectResultError{}, AG_FMT("Failed to collect DNS servers: {}", result.error()->str()));
    }
    if (!vpn_network_manager_update_system_dns(std::move(result.value()))) {
        return make_error(ConnectResultError{}, "Failed to update DNS servers");
    }
#endif
    return {};
}

Error<VpnStandaloneClient::ConnectResultError> VpnStandaloneClient::connect_impl() {
    auto error = dns_runner();
    if (error) {
        return error;
    }

    VpnSettings settings = {
            .handler = {static_vpn_handler, this},
            .mode = m_config.mode,
            .exclusions = {m_config.exclusions.data(), (uint32_t) m_config.exclusions.size()},
            .killswitch_enabled = m_config.killswitch_enabled,
    };

    if (m_config.ssl_session_storage_path.has_value()) {
        settings.ssl_sessions_storage_path = m_config.ssl_session_storage_path->c_str();
    }

    if (std::holds_alternative<VpnStandaloneConfig::TunListener>(m_config.listener)) {
        if (int r = set_outbound_interface(); r < 0) {
            return make_error(ConnectResultError{}, "Failed to set outbound interface");
        }
    }

    m_vpn = vpn_open(&settings);
    if (m_vpn == nullptr) {
        return make_error(ConnectResultError{}, "Failed on create VPN instance");
    }

    return vpn_runner();
}

Error<VpnStandaloneClient::ConnectResultError> VpnStandaloneClient::vpn_runner() {
    if (auto r = connect_to_server(); r) {
        return r;
    }

    VpnListener *listener = std::holds_alternative<VpnStandaloneConfig::TunListener>(m_config.listener)
            ? make_tun_listener()
            : make_socks_listener();
    if (listener == nullptr) {
        return make_error(ConnectResultError{}, "Failed to create listener");
    }

    std::vector<const char *> dns_upstreams;
    dns_upstreams.reserve(m_config.dns_upstreams.size());
    for (const std::string &upstream : m_config.dns_upstreams) {
        dns_upstreams.emplace_back(upstream.c_str());
    }

    VpnListenerConfig listener_config = {
            .dns_upstreams = {.data = dns_upstreams.data(), .size = uint32_t(dns_upstreams.size())},
    };
    VpnError error = vpn_listen(m_vpn, listener, &listener_config);
    if (error.code != 0) {
        std::exchange(m_tunnel, nullptr)->deinit();
        return make_error(ConnectResultError{},
                AG_FMT("Failed to start listening: {} ({})", safe_to_string_view(error.text),
                        magic_enum::enum_name((VpnErrorCode) error.code)));
    }
    return {};
}

Error<VpnStandaloneClient::ConnectResultError> VpnStandaloneClient::connect_to_server() {
    std::vector<VpnEndpoint> endpoints;
    std::vector<VpnRelay> relays;
    std::vector<std::string> hostnames;
    std::vector<std::string> remote_ids;
    hostnames.reserve(m_config.location.endpoints.size());
    remote_ids.reserve(m_config.location.endpoints.size());
    endpoints.reserve(m_config.location.endpoints.size());
    for (const auto &endpoint : m_config.location.endpoints) {
        if (auto pos = endpoint.hostname.find('|'); pos != std::string::npos) {
            hostnames.emplace_back(endpoint.hostname.substr(0, pos));
            remote_ids.emplace_back(endpoint.hostname.substr(pos + 1));
        } else {
            hostnames.emplace_back(endpoint.hostname);
            remote_ids.emplace_back("");
        }
        if (endpoint.address.starts_with("|")) {
            relays.emplace_back(sockaddr_from_str(endpoint.address.substr(1).c_str()));
            continue;
        }
        endpoints.emplace_back(VpnEndpoint{
                .address = sockaddr_from_str(endpoint.address.c_str()),
                .name = hostnames.back().c_str(),
                .remote_id = remote_ids.back().c_str(),
        });
    }
    VpnConnectParameters parameters = {
            .upstream_config =
                    {
                            .protocol = {.type = m_config.location.upstream_protocol},
                            .location =
                                    {
                                            .id = "hello-location",
                                            .endpoints = {endpoints.data(), uint32_t(endpoints.size())},
                                            .relays = {relays.data(), uint32_t(relays.size())},
                                    },
                            .username = m_config.location.username.c_str(),
                            .password = m_config.location.password.c_str(),
                            .anti_dpi = m_config.location.anti_dpi,
                    },
    };
    if (m_config.location.upstream_fallback_protocol.has_value()) {
        parameters.upstream_config.fallback.enabled = true;
        parameters.upstream_config.fallback.protocol.type = *m_config.location.upstream_fallback_protocol;
    }

    {
        std::unique_lock l(m_guard);
        VpnError err = vpn_connect(m_vpn, &parameters);
        auto res = m_connect_waiter.wait_for(l, m_connect_timeout);
        if (res == std::cv_status::timeout) {
            disconnect();
            return make_error(ConnectResultError{}, "Connect timed out");
        }
        if (err.code != 0) {
            return make_error(ConnectResultError{},
                    AG_FMT("Failed to initiate endpoint connection: {} ({})", safe_to_string_view(err.text),
                            magic_enum::enum_name((VpnErrorCode) err.code)));
        }
    }

    return {};
}

VpnListener *VpnStandaloneClient::make_tun_listener() {
    auto &config = std::get<VpnStandaloneConfig::TunListener>(m_config.listener);

    std::vector<const char *> included_routes;
    included_routes.reserve(config.included_routes.size());
    for (const auto &route : config.included_routes) {
        included_routes.emplace_back(route.c_str());
    }

    std::vector<std::string> complete_excluded_routes = config.excluded_routes;
    for (const auto &endpoint : m_config.location.endpoints) {
        auto result = ag::utils::split_host_port(endpoint.address);
        if (result.has_error()) {
            errlog(m_logger, "Failed to parse endpoint address: address={}, error={}", endpoint.address,
                    result.error()->str());
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
    VpnOsTunnelSettings tunnel_settings = {.ipv4_address = defaults->ipv4_address,
            .ipv6_address = defaults->ipv6_address,
            .included_routes = {.data = included_routes.data(), .size = uint32_t(included_routes.size())},
            .excluded_routes = {.data = excluded_routes.data(), .size = uint32_t(excluded_routes.size())},
            .mtu = int(config.mtu_size),
            .dns_servers = defaults->dns_servers};

    m_tunnel = ag::make_vpn_tunnel();
    if (m_tunnel == nullptr) {
        errlog(m_logger, "Tunnel create error");
        return nullptr;
    }

#ifdef _WIN32
    m_wintun = LoadLibraryEx(
            WINTUN_DLL_NAME.data(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (m_wintun == nullptr) {
        errlog(m_logger, "Failed to load wintun: {}", ag::sys::strerror(GetLastError()));
        return nullptr;
    }
    VpnWinTunnelSettings win_settings = *vpn_win_tunnel_settings_defaults();
    win_settings.wintun_lib = m_wintun;
    win_settings.block_inbound = m_config.killswitch_enabled;
    VpnError res = m_tunnel->init(&tunnel_settings, &win_settings);
#else
    VpnError res = m_tunnel->init(&tunnel_settings);
#endif
    if (res.code != 0) {
        errlog(m_logger, "Failed to initialize tunnel: {}", res.text);
        std::exchange(m_tunnel, nullptr)->deinit();
        return nullptr;
    }

    VpnTunListenerConfig listener_config = {
            .fd = m_tunnel->get_fd(),
#ifdef _WIN32
            .tunnel = m_tunnel.get(),
#endif
            .mtu_size = config.mtu_size,
    };

    return vpn_create_tun_listener(m_vpn, &listener_config);
}

VpnListener *VpnStandaloneClient::make_socks_listener() {
    const auto &cfg = std::get<VpnStandaloneConfig::SocksListener>(m_config.listener);
    VpnSocksListenerConfig config = {
            .listen_address = sockaddr_from_str(cfg.address.c_str()),
            .username = cfg.username.c_str(),
            .password = cfg.password.c_str(),
    };
    return vpn_create_socks_listener(m_vpn, &config);
}

void VpnStandaloneClient::static_vpn_handler(void *arg, VpnEvent what, void *data) {
    auto *client = (VpnStandaloneClient *) (arg);
    if (client) {
        client->vpn_handler(nullptr, what, data);
    }
}

void VpnStandaloneClient::vpn_handler(void *, VpnEvent what, void *data) {
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
        const char *err = m_config.location.skip_verification
                ? nullptr
                : tls_verify_cert(event->cert, event->chain, m_config.location.ca_store.get());
        if (err == nullptr) {
            tracelog(m_logger, "Certificate verified successfully");
            event->result = m_config.location.skip_verification ? VPN_SKIP_VERIFICATION_FLAG : 0;
        } else {
            errlog(m_logger, "Failed to verify certificate: {}", err);
            event->result = -1;
        }
        break;
    }
    case VPN_EVENT_STATE_CHANGED: {
        const VpnStateChangedEvent *event = (VpnStateChangedEvent *) data;
        switch (event->state) {
        case VPN_SS_DISCONNECTED:
            errlog(m_logger, "Error: {} {}", event->error.code, safe_to_string_view(event->error.text));
            break;
        case VPN_SS_WAITING_RECOVERY:
            infolog(m_logger, "Waiting recovery: to next={}ms error={} {}",
                    event->waiting_recovery_info.time_to_next_ms, event->waiting_recovery_info.error.code,
                    safe_to_string_view(event->waiting_recovery_info.error.text));
            break;
        case VPN_SS_CONNECTED: {
            std::unique_lock l(m_guard);
            m_connect_waiter.notify_one();
        } break;
        case VPN_SS_CONNECTING:
        case VPN_SS_RECOVERING:
        case VPN_SS_WAITING_FOR_NETWORK:
            break;
        }
        break;
    }
    case VPN_EVENT_CONNECT_REQUEST: {
        struct TaskContext {
            VpnConnectionInfo *info;
            Vpn *vpn;
        };
        auto *task_context = new TaskContext;
        const VpnConnectRequestEvent *event = (VpnConnectRequestEvent *) data;
        auto *info = new VpnConnectionInfo{event->id};
        info->action = VPN_CA_DEFAULT;
        info->appname = safe_to_string_view(event->app_name).empty() ? "standalone_client" : event->app_name;
        task_context->info = info;
        task_context->vpn = m_vpn;
        vpn_event_loop_submit(m_extra_loop.get(),
                {
                        .arg = (void *) task_context,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *context = (TaskContext *) arg;
                                    auto *info = context->info;
                                    if (context->vpn) {
                                        vpn_complete_connect_request(context->vpn, info);
                                    }
                                },
                        .finalize =
                                [](void *arg) {
                                    auto *context = (TaskContext *) arg;
                                    delete (VpnConnectionInfo *) context->info;
                                    delete (TaskContext *) context;
                                },
                });
        break;
    }
    case VPN_EVENT_CONNECTION_INFO:
        const VpnConnectionInfoEvent *info = (VpnConnectionInfoEvent *) data;
        std::string src = sockaddr_ip_to_str((sockaddr *) info->src);
        std::string proto = info->proto == IPPROTO_TCP ? "TCP" : "UDP";
        std::string dst;
        if (info->domain) {
            dst = info->domain;
        }
        if (info->dst) {
            dst = AG_FMT("{}({})", dst, sockaddr_ip_to_str((sockaddr *) info->dst));
        }
        auto action = magic_enum::enum_name(info->action);

        std::string log_message;

        log_message = fmt::format("{}, {} -> {}. Action: {}", proto, src, dst, action);

        dbglog(m_logger, "{}", log_message);
        break;
    }
} // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)

} // namespace ag
