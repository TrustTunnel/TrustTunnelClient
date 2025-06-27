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

#ifndef _WIN32
#include <unistd.h>
#include <sys/types.h>
#endif

using namespace ag; // NOLINT(google-build-using-namespace)

static constexpr uint32_t DEFAULT_MTU = 1500;
static const Logger g_logger("STANDALONE_CLIENT"); // NOLINT(readability-identifier-naming)

static const std::unordered_map<std::string_view, ag::LogLevel> LOG_LEVEL_MAP = {
        {"error", ag::LOG_LEVEL_ERROR},
        {"warn", ag::LOG_LEVEL_WARN},
        {"info", ag::LOG_LEVEL_INFO},
        {"debug", ag::LOG_LEVEL_DEBUG},
        {"trace", ag::LOG_LEVEL_TRACE},
};

static const std::unordered_map<std::string_view, VpnUpstreamProtocol> UPSTREAM_PROTO_MAP = {
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

#define FAIL(fmt_, ...)                                                                                                \
    do {                                                                                                               \
        errlog(g_logger, fmt_, ##__VA_ARGS__);                                                                         \
        exit(1);                                                                                                       \
    } while (0)

template <typename T>
static std::optional<T> get_field(const toml::table &table, std::string_view name) {
    return table[name].value<T>();
}

template <typename T>
class Field {
public:
    Field(const toml::table &table, std::string_view name)
            : m_value(get_field<T>(table, name)) {
    }

    explicit Field(T value)
            : m_value(std::move(value)) {
    }

    Field(const Field &) = default;
    Field &operator=(const Field &) = default;
    Field(Field &&) noexcept = default;
    Field &operator=(Field &&) noexcept = default;
    ~Field() = default;

    template <typename Fn>
    auto map(Fn &&fn) && {
        using U = std::remove_cv_t<std::invoke_result_t<Fn, T>>;
        return Field<U>{
                m_value.has_value() ? std::make_optional<U>(fn(std::move(m_value.value()))) : std::nullopt,
        };
    }

    template <typename... Ts>
    Field check_value(std::function<bool(const T &)> fn, std::string_view fmt_str, Ts &&...args) && {
        if (m_value.has_value() && !fn(m_value.value())) {
            std::string message = fmt::vformat(fmt_str, fmt::make_format_args(args...));
            FAIL("{}", message);
        }
        return std::move(*this);
    }

    template <typename... Ts>
    T unwrap(std::string_view fmt_str, Ts &&...args) && {
        if (!m_value.has_value()) {
            std::string message = fmt::vformat(fmt_str, fmt::make_format_args(args...));
            FAIL("{}", message);
        }
        return std::move(m_value.value());
    }

    T unwrap() && {
        if (!m_value.has_value()) {
            FAIL("Bad optional access");
        }
        return std::move(m_value.value());
    }

    T unwrap_or(T &&x) {
        return m_value.value_or(std::move(x));
    }

private:
    std::optional<T> m_value;

    template <typename U>
    friend class Field;

    explicit Field(std::optional<T> value)
            : m_value(std::move(value)) {
    }
};

void set_loglevel(VpnStandaloneConfig *self, std::string_view x) {
    if (auto it = LOG_LEVEL_MAP.find(x); it != LOG_LEVEL_MAP.end()) {
        if (self->loglevel != it->second) {
            infolog(g_logger, "Log level was overwritten: old={}, new={}", magic_enum::enum_name(self->loglevel),
                    magic_enum::enum_name(it->second));
        }
        self->loglevel = it->second;
    } else {
        FAIL("Unexpected log level: {}", x);
    }
}

DeclPtr<X509_STORE, &X509_STORE_free> load_certificate(const char *path) {
    DeclPtr<FILE, &std::fclose> file{std::fopen(path, "r")};
    if (file == nullptr) {
        FAIL("Cannot open certificate file ({}): {}", path, strerror(errno));
    }

    DeclPtr<X509, &X509_free> cert{PEM_read_X509(file.get(), nullptr, nullptr, nullptr)};
    if (cert == nullptr) {
        FAIL("Couldn't parse certificate");
    }

    DeclPtr<X509_STORE, &X509_STORE_free> store{tls_create_ca_store()};
    if (store == nullptr) {
        FAIL("Couldn't create store");
    }

    X509_STORE_add_cert(store.get(), cert.get());

    return store;
}

static void apply_endpoint_config(VpnStandaloneConfig *self, const toml::table &config) {
    std::vector<VpnStandaloneConfig::Endpoint> endpoint;

    auto hostname = Field<std::string>(config, "hostname").unwrap("Hostname is not specified");

    if (const auto *x = config["addresses"].as_array(); x != nullptr) {
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                self->location.endpoints.emplace_back(
                        VpnStandaloneConfig::Endpoint{.hostname = hostname, .address = std::string(addr.value())});
            }
        }
    }

    if (self->location.endpoints.empty()) {
        FAIL("Endpoint addresses are invalid or not specified");
    }

    self->location.username = Field<std::string>(config, "username").unwrap("Username is not specified");
    self->location.password = Field<std::string>(config, "password").unwrap("Password is not specified");
    self->location.skip_verification = Field<bool>(config, "skip_verification").unwrap_or(false);
    self->location.anti_dpi = Field<bool>(config, "anti_dpi").unwrap_or(false);

    if (std::optional x = get_field<std::string>(config, "certificate");
            !self->location.skip_verification && x.has_value() && !x->empty()) {
        self->location.ca_store = load_certificate(x->c_str());
    }

    self->location.upstream_protocol = Field<std::string_view>(config, "upstream_protocol")
                                               .check_value(
                                                       [](std::string_view x) -> bool {
                                                           return UPSTREAM_PROTO_MAP.contains(x);
                                                       },
                                                       "Unexpected endpoint upstream protocol value: {}",
                                                       streamable_to_string(config["upstream_protocol"]))
                                               .map([](std::string_view x) {
                                                   return UPSTREAM_PROTO_MAP.at(x);
                                               })
                                               .unwrap("Endpoint upstream protocol is not specified");
    if (std::optional x = get_field<std::string>(config, "upstream_fallback_protocol"); x.has_value() && !x->empty()) {
        self->location.upstream_fallback_protocol =
                Field(x.value())
                        .check_value(
                                [](std::string_view x) -> bool {
                                    return UPSTREAM_PROTO_MAP.contains(x);
                                },
                                "Unexpected endpoint upstream fallback protocol value: {}",
                                streamable_to_string(config["upstream_fallback_protocol"]))
                        .map([](std::string_view x) {
                            return UPSTREAM_PROTO_MAP.at(x);
                        })
                        .unwrap();
    }
}

static std::optional<VpnStandaloneConfig::SocksListener> parse_socks_listener_config(
        VpnStandaloneConfig *, const toml::table &config) {
    const toml::table *socks_config = config["socks"].as_table();
    if (socks_config == nullptr) {
        return std::nullopt;
    }

    return VpnStandaloneConfig::SocksListener{
            .username = (*socks_config)["username"].value_or<std::string>({}),
            .password = (*socks_config)["password"].value_or<std::string>({}),
            .address = Field<std::string>(*socks_config, "address").unwrap("SOCKS listener address is not specified"),
    };
}

static std::optional<VpnStandaloneConfig::TunListener> parse_tun_listener_config(
        VpnStandaloneConfig *, const toml::table &config) {
    const toml::table *tun_config = config["tun"].as_table();
    if (tun_config == nullptr) {
        return std::nullopt;
    }

    VpnStandaloneConfig::TunListener tun = {
        .mtu_size = (*tun_config)["mtu_size"].value<uint32_t>().value_or(DEFAULT_MTU),
        .bound_if = Field<std::string>(*tun_config, "bound_if")
#if defined(_WIN32) || defined(__linux__)
                            // will be detected automatically later
                            .unwrap_or({}),
#elif defined(__APPLE__)
                            .unwrap_or("en0"),
#else
                            .unwrap("Outbound interface is not specified"),
#endif
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

static void apply_listener_config(VpnStandaloneConfig *self, const toml::table &config) {
    std::optional socks = parse_socks_listener_config(self, config);
    std::optional tun = parse_tun_listener_config(self, config);

    if (socks.has_value() == tun.has_value()) {
        if (socks.has_value()) {
            FAIL("Several listener types are specified simultaneously");
        } else {
            FAIL("Listener type is not specified or unexpected");
        }
    }

    if (socks.has_value()) {
        self->listener = std::move(socks.value());
        return;
    }

    self->listener = std::move(tun.value());
}

void VpnStandaloneConfig::apply_config(const toml::table &config) {
    if (std::optional lvl = config["loglevel"].value<std::string_view>(); lvl.has_value()) {
        set_loglevel(this, lvl.value());
    }

    mode = Field<std::string_view>(config, "vpn_mode")
                   .check_value(
                           [](std::string_view x) -> bool {
                               return VPN_MODE_MAP.contains(x);
                           },
                           "Unexpected VPN mode: {}", streamable_to_string(config["vpn_mode"]))
                   .map([](std::string_view x) {
                       return VPN_MODE_MAP.at(x);
                   })
                   .unwrap_or(VPN_MODE_GENERAL);

    killswitch_enabled = Field<bool>(config, "killswitch_enabled").unwrap_or(false);
    post_quantum_group_enabled = Field<bool>(config, "post_quantum_group_enabled").unwrap_or(false);

    ssl_session_storage_path = config["ssl_session_cache_path"].value<std::string_view>();

    if (const auto *x = config["exclusions"].as_array(); x != nullptr) {
        for (const auto &e : *x) {
            if (std::optional ex = e.value<std::string_view>(); ex.has_value() && !ex->empty()) {
                exclusions.append(ex.value());
                exclusions.push_back(' ');
            }
        }
    }

    if (const auto *x = config["dns_upstreams"].as_array(); x != nullptr) {
        dns_upstreams.reserve(x->size());
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                dns_upstreams.emplace_back(addr.value());
            }
        }
    }

    if (const toml::table *endpoint_config = config["endpoint"].as_table(); endpoint_config == nullptr) {
        FAIL("Endpoint configuration is not a table: {}", streamable_to_string(config["endpoint"]));
    } else {
        apply_endpoint_config(this, *endpoint_config);
    }

    if (const toml::table *listener_config = config["listener"].as_table(); listener_config == nullptr) {
        FAIL("Endpoint configuration is not a table: {}", streamable_to_string(config["endpoint"]));
    } else {
        apply_listener_config(this, *listener_config);
    }
}

void VpnStandaloneConfig::apply_cmd_args(const cxxopts::ParseResult &args) {
    if (args.count("s") > 0) {
        bool x = args["s"].as<bool>();
        if (x != location.skip_verification) {
            infolog(g_logger, "Skip verification value was overwritten: old={}, new={}", location.skip_verification, x);
        }
        location.skip_verification = x;
    }
    if (args.count("loglevel") > 0) {
        set_loglevel(this, args["loglevel"].as<std::string>());
    }
}

void VpnStandaloneConfig::detect_bound_if() {
    if (!std::holds_alternative<TunListener>(this->listener)) {
        return;
    }
    TunListener &config = std::get<TunListener>(this->listener);
    if (!config.bound_if.empty()) {
        return;
    }
#ifdef __linux__
    constexpr std::string_view CMD = "ip -o route show to default";
    infolog(g_logger, "{} {}", (geteuid() == 0) ? '#' : '$', CMD);
    Result result = tunnel_utils::fsystem_with_output(CMD);
    if (result.has_error()) {
        errlog(g_logger, "Failed to detect outbound interface automatically: {}", result.error()->str());
        return;
    }

    dbglog(g_logger, "Detect command output: {}", result.value());
    std::vector parts = utils::split_by(result.value(), ' ');
    auto found = std::find(parts.begin(), parts.end(), "dev");
    if (found == parts.end() || std::next(found) == parts.end()) {
        warnlog(g_logger, "Failed to detect outbound interface name");
        return;
    }
    config.bound_if = *std::next(found);
#endif
#ifdef _WIN32
    uint32_t if_index = vpn_win_detect_active_if();
    if (if_index == 0) {
        warnlog(g_logger, "Failed to detect active network interface");
        return;
    }
    char if_name[IF_NAMESIZE]{};
    if_indextoname(if_index, if_name);
    config.bound_if = if_name;
#endif // _WIN32
    infolog(g_logger, "Using automatically detected outbound interface: {}", config.bound_if);
}
