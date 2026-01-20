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
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"
#include "vpn/vpn.h"

namespace ag {

TrustTunnelClient::TrustTunnelClient(TrustTunnelConfig &&config, VpnCallbacks &&callbacks)
        : m_config(std::move(config))
        , m_extra_loop(vpn_event_loop_create())
        , m_callbacks(std::move(callbacks)) {
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

TrustTunnelClient::~TrustTunnelClient() {
    vpn_event_loop_stop(m_extra_loop.get());
    if (m_loop_thread.joinable()) {
        m_loop_thread.join();
    }
}

Error<TrustTunnelClient::ConnectResultError> TrustTunnelClient::connect(ListenerSettings listener_settings) {
    return connect_impl(std::move(listener_settings));
}

int TrustTunnelClient::disconnect() {
    if (Vpn *vpn = m_vpn.exchange(nullptr)) {
        vpn_stop(vpn);
        vpn_close(vpn);
    }

    return 0;
}

void TrustTunnelClient::notify_network_change(VpnNetworkState state) {
    if (m_vpn) {
        vpn_notify_network_change(m_vpn, state);
    }
}

void TrustTunnelClient::notify_sleep() {
    if (m_vpn) {
        vpn_notify_sleep(m_vpn, [](void *) {}, nullptr);
    }
}

void TrustTunnelClient::notify_wake() {
    if (m_vpn) {
        vpn_notify_wake(m_vpn);
    }
}

bool TrustTunnelClient::process_client_packets(VpnPackets packets) {
    return m_vpn && vpn_process_client_packets(m_vpn, packets);
}

void TrustTunnelClient::vpn_protect_socket(SocketProtectEvent *event) {
    const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&m_config.listener);
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

int TrustTunnelClient::set_outbound_interface() {
    auto &config = std::get<TrustTunnelConfig::TunListener>(m_config.listener);
    if (config.bound_if.empty()) {
        return 0;
    }
    uint32_t if_index = if_nametoindex(config.bound_if.c_str());
    if (if_index == 0) {
        if (auto idx = ag::utils::to_integer<uint32_t>(config.bound_if)) {
            if_index = idx.value();
        }
    }
    if (if_index == 0) {
        errlog(m_logger, "Unknown interface name: {}. Use 'ifconfig' to see possible values", config.bound_if);
        return -1;
    }
    vpn_network_manager_set_outbound_interface(if_index);
    return 0;
}

Error<TrustTunnelClient::ConnectResultError> TrustTunnelClient::set_system_dns() {
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
    Result<SystemDnsServers, RetrieveSystemDnsError> result = utils::retrieve_system_dns_servers();
    if (result.has_error()) {
        return make_error(ConnectResultError{}, AG_FMT("Failed to collect DNS servers: {}", result.error()->str()));
    }
    if (!vpn_network_manager_update_system_dns(std::move(result.value()))) {
        return make_error(ConnectResultError{}, "Failed to update DNS servers");
    }
#endif
    return {};
}

Error<TrustTunnelClient::ConnectResultError> TrustTunnelClient::connect_impl(ListenerSettings listener_settings) {
    VpnSettings settings = {
            .handler = {static_vpn_handler, this},
            .mode = m_config.mode,
            .exclusions = {m_config.exclusions.data(), (uint32_t) m_config.exclusions.size()},
            .killswitch_enabled = m_config.killswitch_enabled,
    };

    if (m_config.ssl_session_storage_path.has_value()) {
        settings.ssl_sessions_storage_path = m_config.ssl_session_storage_path->c_str();
    }

    if (std::holds_alternative<TrustTunnelConfig::TunListener>(m_config.listener)) {
        if (int r = set_outbound_interface(); r < 0) {
            return make_error(ConnectResultError{}, "Failed to set outbound interface");
        }
    }

    m_vpn = vpn_open(&settings);
    if (m_vpn == nullptr) {
        return make_error(ConnectResultError{}, "Failed on create VPN instance");
    }

    auto r = vpn_runner(std::move(listener_settings));

    if (r) {
        disconnect();
    }
    return r;
}

Error<TrustTunnelClient::ConnectResultError> TrustTunnelClient::vpn_runner(ListenerSettings listener_settings) {
    if (auto r = connect_to_server(); r) {
        return r;
    }
    VpnListener *listener = std::holds_alternative<TrustTunnelConfig::TunListener>(m_config.listener)
            ? make_tun_listener(std::move(listener_settings))
            : make_socks_listener(std::move(listener_settings));

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
        return make_error(ConnectResultError{},
                AG_FMT("Failed to start listening: {} ({})", safe_to_string_view(error.text),
                        magic_enum::enum_name((VpnErrorCode) error.code)));
    }
    return {};
}

Error<TrustTunnelClient::ConnectResultError> TrustTunnelClient::connect_to_server() {
    std::vector<VpnEndpoint> endpoints;
    std::vector<VpnRelay> relays;
    std::vector<std::string> hostnames;
    std::vector<std::string> remote_ids;
    hostnames.reserve(m_config.location.endpoints.size());
    remote_ids.reserve(m_config.location.endpoints.size());
    endpoints.reserve(m_config.location.endpoints.size());

    auto copy_to_c_buffer = [](auto &dst, std::string_view src) {
        auto decoded = utils::decode_hex(src);
        size_t data_len = decoded.size();
        dst.size = data_len;
        if (data_len == 0) {
            return;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,hicpp-no-malloc)
        dst.data = static_cast<uint8_t *>(std::malloc(data_len));
        std::memcpy(dst.data, decoded.data(), data_len);
    };

    for (const auto &endpoint : m_config.location.endpoints) {
        if (auto pos = endpoint.hostname.find('|'); pos != std::string::npos) {
            hostnames.emplace_back(endpoint.hostname.substr(0, pos));
            remote_ids.emplace_back(endpoint.hostname.substr(pos + 1));
        } else {
            hostnames.emplace_back(endpoint.hostname);
            remote_ids.emplace_back("");
        }
        if (endpoint.address.starts_with("|")) {
            auto &relay = relays.emplace_back(sockaddr_from_str(endpoint.address.substr(1).c_str()));
            if (!m_config.location.client_random.empty()) {
                copy_to_c_buffer(relay.tls_client_random, m_config.location.client_random);
            }
            if (!m_config.location.client_random_mask.empty()) {
                copy_to_c_buffer(relay.tls_client_random_mask, m_config.location.client_random_mask);
            }
            continue;
        }
        auto &last_el = endpoints.emplace_back(VpnEndpoint{
                .address = sockaddr_from_str(endpoint.address.c_str()),
                .name = hostnames.back().c_str(),
                .remote_id = remote_ids.back().c_str(),
                .has_ipv6 = m_config.location.has_ipv6,
        });
        if (!m_config.location.client_random.empty()) {
            copy_to_c_buffer(last_el.tls_client_random, m_config.location.client_random);
        }
        if (!m_config.location.client_random_mask.empty()) {
            copy_to_c_buffer(last_el.tls_client_random_mask, m_config.location.client_random_mask);
        }
    }
    VpnConnectParameters parameters = {
            .upstream_config =
                    {
                            .main_protocol = m_config.location.upstream_protocol,
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

    {
        VpnError err = vpn_connect(m_vpn, &parameters);
        if (err.code != 0) {
            return make_error(ConnectResultError{},
                    AG_FMT("Failed to initiate endpoint connection: {} ({})", safe_to_string_view(err.text),
                            magic_enum::enum_name((VpnErrorCode) err.code)));
        }
    }

    return {};
}

VpnListener *TrustTunnelClient::make_tun_listener(ListenerSettings listener_settings) {
    auto &config = std::get<TrustTunnelConfig::TunListener>(m_config.listener);

    if (auto *use_fd = std::get_if<UseTunnelFd>(&listener_settings)) {
        VpnTunListenerConfig listener_config = {
                .fd = use_fd->fd.release(),
                .mtu_size = config.mtu_size,
        };

        return vpn_create_tun_listener(m_vpn, &listener_config);
    }

    if (std::holds_alternative<UseProcessPackets>(listener_settings)) {
        VpnTunListenerConfig listener_config = {
                .fd = -1,
                .mtu_size = config.mtu_size,
        };

        return vpn_create_tun_listener(m_vpn, &listener_config);
    }

    assert(std::holds_alternative<AutoSetup>(listener_settings));

#if defined(ANDROID) || TARGET_OS_IPHONE
    errlog(m_logger, "Current platform doesn't support automatic tunnel creation");
    return nullptr;
#else

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
            .dns_servers = config.change_system_dns ? defaults->dns_servers : VpnAddressArray{}};

    m_tunnel = ag::make_vpn_tunnel();
    if (m_tunnel == nullptr) {
        errlog(m_logger, "Tunnel create error");
        return nullptr;
    }

#ifdef _WIN32
    m_wintun = LoadLibraryExA(
            WINTUN_DLL_NAME.data(), nullptr, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (m_wintun == nullptr) {
        errlog(m_logger, "Failed to load wintun: {}", ag::sys::strerror(GetLastError()));
        return nullptr;
    }
    VpnWinTunnelSettings win_settings = *vpn_win_tunnel_settings_defaults();
    win_settings.wintun_lib = m_wintun;
    win_settings.block_untunneled = m_config.killswitch_enabled;
    win_settings.block_untunneled_exclude_ports = m_config.killswitch_allow_ports.c_str();
    VpnError res = m_tunnel->init(&tunnel_settings, &win_settings);
#else
#ifdef __linux__
    VpnError res = m_tunnel->init(&tunnel_settings, config.netns);
#else
    VpnError res = m_tunnel->init(&tunnel_settings);
#endif
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
#endif // ANDROID
}

VpnListener *TrustTunnelClient::make_socks_listener(ListenerSettings listener_settings) {
    if (!std::holds_alternative<AutoSetup>(listener_settings)) {
        errlog(m_logger, "Socks listener can only be created with `AutoSetup` setting!");
        return nullptr;
    }
    const auto &cfg = std::get<TrustTunnelConfig::SocksListener>(m_config.listener);
    VpnSocksListenerConfig config = {
            .listen_address = sockaddr_from_str(cfg.address.c_str()),
            .username = cfg.username.c_str(),
            .password = cfg.password.c_str(),
    };
    return vpn_create_socks_listener(m_vpn, &config);
}

void TrustTunnelClient::static_vpn_handler(void *arg, VpnEvent what, void *data) {
    auto *client = (TrustTunnelClient *) (arg);
    if (client) {
        client->vpn_handler(nullptr, what, data);
    }
}

void TrustTunnelClient::vpn_handler(void *, VpnEvent what, void *data) {
    switch (what) {
    case VPN_EVENT_PROTECT_SOCKET: {
        // protect socket to avoid route loop
        auto *event = (SocketProtectEvent *) data;
        m_callbacks.protect_handler(event);
        break;
    }
    case VPN_EVENT_CLIENT_OUTPUT: {
        auto *event = (VpnClientOutputEvent *) data;
        if (m_callbacks.client_output_handler) {
            m_callbacks.client_output_handler(event);
        }
        break;
    }
    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
    case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
    case VPN_EVENT_TUNNEL_CONNECTION_STATS:
    case VPN_EVENT_TUNNEL_CONNECTION_CLOSED:
        // do nothing
        break;
    case VPN_EVENT_VERIFY_CERTIFICATE: {
        auto *event = (VpnVerifyCertificateEvent *) data;
        if (m_config.location.skip_verification) {
            dbglog(m_logger, "Skipping certificate verification");
            event->result = VPN_SKIP_VERIFICATION_FLAG;
        } else if (m_config.location.ca_store) {
            const char *err = tls_verify_cert(event->cert, event->chain, m_config.location.ca_store.get());
            if (err != nullptr) {
                errlog(m_logger, "Failed to verify certificate: {}", err);
                event->result = -1;
            } else {
                dbglog(m_logger, "Certificate verified successfully");
                event->result = 0;
            }
        } else {
            m_callbacks.verify_handler(event);
        }
        break;
    }
    case VPN_EVENT_STATE_CHANGED: {
        auto *event = (VpnStateChangedEvent *) data;
        m_callbacks.state_changed_handler(event);
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
        info->appname = safe_to_string_view(event->app_name).empty() ? "trusttunnel_client" : event->app_name;
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
        auto *info = (VpnConnectionInfoEvent *) data;
        if (m_callbacks.connection_info_handler) {
            m_callbacks.connection_info_handler(info);
        }
        break;
    }
} // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)

} // namespace ag
