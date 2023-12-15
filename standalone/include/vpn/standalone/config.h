#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <cxxopts.hpp>
#include <toml++/toml.h>

#include "vpn/utils.h"
#include "vpn/vpn.h"

namespace ag {

struct VpnStandaloneConfig {
    struct Endpoint {
        std::string hostname;
        std::vector<std::string> addresses;
        std::string username;
        std::string password;
        bool skip_verification = false;
        ag::DeclPtr<X509_STORE, &X509_STORE_free> ca_store;
        ag::VpnUpstreamProtocol upstream_protocol = ag::VPN_UP_HTTP2;
        std::optional<ag::VpnUpstreamProtocol> upstream_fallback_protocol;
        bool anti_dpi = false;
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
    };

    using Listener = std::variant<SocksListener, TunListener>;

    ag::LogLevel loglevel = ag::LOG_LEVEL_INFO;
    ag::VpnMode mode = ag::VPN_MODE_GENERAL;
    bool killswitch_enabled = false;
    std::string log_file_path;
    std::string exclusions;
    std::vector<std::string> dns_upstreams;
    Endpoint endpoint = {};
    Listener listener;

    void apply_config(const toml::table &config);

    void apply_cmd_args(const cxxopts::ParseResult &result);
};
} // namespace ag
