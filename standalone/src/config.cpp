#include <cstdio>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include <magic_enum/magic_enum.hpp>
#include <openssl/pem.h>

#include "net/tls.h"
#include "vpn/standalone/config.h"
#include "utils.h"

#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#endif

using namespace ag; // NOLINT(google-build-using-namespace)

static constexpr uint32_t DEFAULT_MTU = 1500;
static const Logger g_logger("STANDALONE_CLIENT"); // NOLINT(readability-identifier-naming)

static const std::unordered_map<std::string_view, VpnUpstreamProtocol> UPSTREAM_PROTO_MAP = {
        {"auto", VPN_UP_AUTO},
        {"http2", VPN_UP_HTTP2},
        {"http3", VPN_UP_HTTP3},
};

static const std::unordered_map<std::string_view, VpnMode> VPN_MODE_MAP = {
        {"general", VPN_MODE_GENERAL},
        {"selective", VPN_MODE_SELECTIVE},
};

template <typename T>
static std::string streamable_to_string(const T &obj) {
    std::stringstream stream;
    stream << obj;
    return stream.str();
}

static UniquePtr<X509_STORE, &X509_STORE_free> load_certificate(std::string_view pem_certificate) {
    UniquePtr<BIO, &BIO_free> bio {BIO_new_mem_buf(pem_certificate.data(), (long) pem_certificate.size())};

    UniquePtr<X509, &X509_free> cert{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)};
    if (cert == nullptr) {
        warnlog(g_logger, "Failed to parse certificate, ensure it is in PEM format");
        return nullptr;
    }

    UniquePtr<X509_STORE, &X509_STORE_free> store{tls_create_ca_store()};
    if (store == nullptr) {
        warnlog(g_logger, "Failed to create CA store");
        return nullptr;
    }

    X509_STORE_add_cert(store.get(), cert.get());

    return store;
}

static std::optional<VpnStandaloneConfig::Location> build_endpoint(const toml::table &config) {
    VpnStandaloneConfig::Location location;
    std::vector<VpnStandaloneConfig::Endpoint> endpoint;

    auto hostname = config["hostname"].value<std::string>();
    if (!hostname) {
        return std::nullopt;
    }

    if (const auto *x = config["addresses"].as_array(); x != nullptr) {
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                location.endpoints.emplace_back(
                        VpnStandaloneConfig::Endpoint{.hostname = *hostname, .address = std::string(addr.value())});
            }
        }
    }

    if (location.endpoints.empty()) {
        errlog(g_logger, "Endpoint addresses are invalid or not specified");
        return std::nullopt;
    }

    if (auto username = config["username"].value<std::string>()) {
        location.username = *username;
    } else {
        errlog(g_logger, "Username is not specified");
        return std::nullopt;
    }
    if (auto password = config["password"].value<std::string>()) {
        location.password = *password;
    } else {
        errlog(g_logger, "Password is not specified");
        return std::nullopt;
    }
    location.skip_verification = config["skip_verification"].value_or(false);
    location.anti_dpi = config["anti_dpi"].value_or(false);
    location.has_ipv6 = config["has_ipv6"].value_or(true);
    if (std::optional x = config["certificate"].value<std::string>();
            !location.skip_verification && x.has_value() && !x->empty()) {
        location.ca_store = load_certificate(*x);
    }

    if (auto upstream_protocol = config["upstream_protocol"].value<std::string_view>(); upstream_protocol && UPSTREAM_PROTO_MAP.contains(*upstream_protocol)) {
        location.upstream_protocol = UPSTREAM_PROTO_MAP.at(*upstream_protocol);
    } else {
        errlog(g_logger, "Unexpected endpoint upstream protocol value: {}",
                            streamable_to_string(config["upstream_protocol"].node()));
        return std::nullopt;
    }
    if (auto upstream_fallback_protocol = config["upstream_fallback_protocol"].value<std::string_view>();
            upstream_fallback_protocol && !upstream_fallback_protocol->empty()) {
        if (UPSTREAM_PROTO_MAP.contains(*upstream_fallback_protocol)) {
            location.upstream_fallback_protocol = UPSTREAM_PROTO_MAP.at(*upstream_fallback_protocol);
        } else {
            errlog(g_logger, "Unexpected endpoint upstream fallback protocol value: {}",
                   streamable_to_string(config["upstream_protocol"].node()));
            return std::nullopt;
        }
    }

    // Parse client random
    if (auto client_random = config["client_random"].value<std::string>()) {
        location.client_random = *client_random;
    }

    return location;
}

static std::optional<VpnStandaloneConfig::SocksListener> parse_socks_listener_config(const toml::table &config) {
    const toml::table *socks_config = config["socks"].as_table();
    if (socks_config == nullptr) {
        return std::nullopt;
    }
    auto address = (*socks_config)["address"].value<std::string>();
    if (!address) {
        return std::nullopt;
    }

    return VpnStandaloneConfig::SocksListener{
            .username = (*socks_config)["username"].value_or<std::string>({}),
            .password = (*socks_config)["password"].value_or<std::string>({}),
            .address = std::move(*address),
    };
}

static std::optional<VpnStandaloneConfig::TunListener> parse_tun_listener_config(const toml::table &config) {
    const toml::table *tun_config = config["tun"].as_table();
    if (tun_config == nullptr) {
        return std::nullopt;
    }

    std::string bound_if;
#if defined(_WIN32) || defined(__linux__)
    bound_if = (*tun_config)["bound_if"].value_or<std::string>({});
#elif defined(__APPLE__)
    bound_if = (*tun_config)["bound_if"].value_or<std::string>({});
    if (bound_if.empty()) {
        bound_if = "en0";
    }
#else
    errlog(g_logger, "Outbound interface is not specified");
    return std::nullopt;
#endif

    VpnStandaloneConfig::TunListener tun = {
        .mtu_size = (*tun_config)["mtu_size"].value<uint32_t>().value_or(DEFAULT_MTU),
        .bound_if = std::move(bound_if),
        .netns = (*tun_config)["netns"].value<std::string>(),
    };

    if (const auto *x = (*tun_config)["included_routes"].as_array(); x != nullptr) {
        tun.included_routes.reserve(x->size());
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                tun.included_routes.emplace_back(addr.value());
            }
        }
    }

    if (const auto *x = (*tun_config)["excluded_routes"].as_array(); x != nullptr) {
        tun.excluded_routes.reserve(x->size());
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                tun.excluded_routes.emplace_back(addr.value());
            }
        }
    }

    return tun;
}

static std::optional<VpnStandaloneConfig::Listener> build_listener_config(const toml::table &config) {
    std::optional socks = parse_socks_listener_config(config);
    std::optional tun = parse_tun_listener_config(config);

    if (socks.has_value() == tun.has_value()) {
        if (socks.has_value()) {
            errlog(g_logger, "Several listener types are specified simultaneously");
            return std::nullopt;
        } else {
            errlog(g_logger, "Listener type is not specified or unexpected");
            return std::nullopt;
        }
    }

    if (socks.has_value()) {
        return socks;
    }

    return tun;
}

std::optional<VpnStandaloneConfig> VpnStandaloneConfig::build_config(const toml::table &config) {
    VpnStandaloneConfig result;

    if (std::optional lvl = config["loglevel"].value<std::string_view>(); lvl.has_value()) {
        if (auto loglevel = StandaloneUtils::parse_loglevel(lvl.value())) {
            result.loglevel = loglevel.value();
        } else {
            errlog(g_logger, "Unexpected log level: {}", lvl.value());
            return std::nullopt;
        }
    }

    if (auto mode = config["vpn_mode"].value<std::string_view>(); mode && VPN_MODE_MAP.contains(*mode)) {
        result.mode = VPN_MODE_MAP.at(*mode);
    } else {
        errlog(g_logger, "Unexpected VPN mode: {}", streamable_to_string(config["vpn_mode"].node()));
        return std::nullopt;
    }

    result.killswitch_enabled = config["killswitch_enabled"].value_or<bool>(false);
    result.post_quantum_group_enabled = config["post_quantum_group_enabled"].value_or<bool>(false);

    result.ssl_session_storage_path = config["ssl_session_cache_path"].value<std::string_view>();

    if (const auto *x = config["exclusions"].as_array(); x != nullptr) {
        for (const auto &e : *x) {
            if (std::optional ex = e.value<std::string_view>(); ex.has_value() && !ex->empty()) {
                result.exclusions.append(ex.value());
                result.exclusions.push_back(' ');
            }
        }
    }

    if (const auto *x = config["dns_upstreams"].as_array(); x != nullptr) {
        result.dns_upstreams.reserve(x->size());
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                result.dns_upstreams.emplace_back(addr.value());
            }
        }
    }


    const toml::table *endpoint_config = config["endpoint"].as_table();
    if (endpoint_config == nullptr) {
        errlog(g_logger, "Endpoint configuration is not a table: {}", streamable_to_string(config["endpoint"].node()));
        return std::nullopt;
    }
    if (auto endpoint = build_endpoint(*endpoint_config)) {
        result.location = std::move(*endpoint);
    } else {
        errlog(g_logger, "Failed to parse endpoint part of the config");
        return std::nullopt;
    }

    const toml::table *listener_config = config["listener"].as_table();
    if (listener_config == nullptr) {
        errlog(g_logger, "Endpoint configuration is not a table: {}", streamable_to_string(config["endpoint"].node()));
        return std::nullopt;
    }
    if (auto listener = build_listener_config(*listener_config)) {
        result.listener = std::move(*listener);
    } else {
        errlog(g_logger, "Failed to parse listener part of the config");
        return std::nullopt;
    }

    return result;
}
