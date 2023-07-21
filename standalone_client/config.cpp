#include <cstdio>
#include <functional>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include <magic_enum.hpp>
#include <openssl/pem.h>

#include "config.h"
#include "net/tls.h"

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
        return std::move(m_value.value_or(std::move(x)));
    }

private:
    std::optional<T> m_value;

    template <typename U>
    friend class Field;

    explicit Field(std::optional<T> value)
            : m_value(std::move(value)) {
    }
};

void set_loglevel(Config *self, std::string_view x) {
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

static void apply_endpoint_config(Config *self, const toml::table &config) {
    self->endpoint.hostname = Field<std::string>(config, "hostname").unwrap("Hostname is not specified");

    if (const auto *x = config["addresses"].as_array(); x != nullptr) {
        self->endpoint.addresses.reserve(x->size());
        for (const auto &a : *x) {
            if (std::optional addr = a.value<std::string_view>(); addr.has_value() && !addr->empty()) {
                self->endpoint.addresses.emplace_back(addr.value());
            }
        }
    }

    if (self->endpoint.addresses.empty()) {
        FAIL("Endpoint addresses are invalid or not specified");
    }

    self->endpoint.hostname = Field<std::string>(config, "hostname").unwrap("Hostname is not specified");
    self->endpoint.username = Field<std::string>(config, "username").unwrap("Username is not specified");
    self->endpoint.password = Field<std::string>(config, "password").unwrap("Password is not specified");
    self->endpoint.skip_verification = Field<bool>(config, "skip_verification").unwrap_or(false);

    if (std::optional x = get_field<std::string>(config, "certificate");
            !self->endpoint.skip_verification && x.has_value() && !x->empty()) {
        self->endpoint.ca_store = load_certificate(x->c_str());
    }

    self->endpoint.upstream_protocol = Field<std::string_view>(config, "upstream_protocol")
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
        self->endpoint.upstream_fallback_protocol =
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

static std::optional<Config::SocksListener> parse_socks_listener_config(Config *, const toml::table &config) {
    const toml::table *socks_config = config["socks"].as_table();
    if (socks_config == nullptr) {
        return std::nullopt;
    }

    return Config::SocksListener{
            .username = (*socks_config)["username"].value_or<std::string>({}),
            .password = (*socks_config)["password"].value_or<std::string>({}),
            .address = Field<std::string>(*socks_config, "address").unwrap("SOCKS listener address is not specified"),
    };
}

static std::optional<Config::TunListener> parse_tun_listener_config(Config *, const toml::table &config) {
    const toml::table *tun_config = config["tun"].as_table();
    if (tun_config == nullptr) {
        return std::nullopt;
    }

    Config::TunListener tun = {
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

static void apply_listener_config(Config *self, const toml::table &config) {
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

void Config::apply_config(const toml::table &config) {
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

void Config::apply_cmd_args(const cxxopts::ParseResult &args) {
    if (args.count("s") > 0) {
        bool x = args["s"].as<bool>();
        if (x != endpoint.skip_verification) {
            infolog(g_logger, "Skip verification value was overwritten: old={}, new={}", endpoint.skip_verification, x);
        }
        endpoint.skip_verification = x;
    }
    if (args.count("loglevel") > 0) {
        set_loglevel(this, args["loglevel"].as<std::string>());
    }
}
