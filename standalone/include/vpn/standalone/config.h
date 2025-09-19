#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <toml++/toml.h>

#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {

struct VpnStandaloneConfig {
    struct Endpoint {
        std::string hostname;
        std::string address;
    };

    struct Location {
        std::string username;
        std::string password;
        std::vector<Endpoint> endpoints;
        ag::UniquePtr<X509_STORE, &X509_STORE_free> ca_store;
        ag::VpnUpstreamProtocol upstream_protocol = ag::VPN_UP_HTTP2;
        std::optional<ag::VpnUpstreamProtocol> upstream_fallback_protocol;
        std::string client_random;
        bool skip_verification = false;
        bool anti_dpi = false;
        bool has_ipv6 = false;
    };

    struct SocksListener {
        std::string username;
        std::string password;
        std::string address;
    };

    struct TunListener {
        std::vector<std::string> included_routes;
        std::vector<std::string> excluded_routes;
        uint32_t mtu_size = 0;
        std::string bound_if;
        std::optional<std::string> netns;
    };

    using Listener = std::variant<SocksListener, TunListener>;

    ag::LogLevel loglevel = ag::LOG_LEVEL_INFO;
    ag::VpnMode mode = ag::VPN_MODE_GENERAL;
    bool killswitch_enabled = false;
    bool post_quantum_group_enabled = false;
    std::string log_file_path;
    std::string exclusions;
    std::optional<std::string> ssl_session_storage_path;
    std::vector<std::string> dns_upstreams;
    Location location;
    Listener listener;

    static std::optional<VpnStandaloneConfig> build_config(const toml::table &config);
};
} // namespace ag
