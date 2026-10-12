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

struct TrustTunnelConfig {
    struct Endpoint {
        std::string hostname;
        std::string address; ///< IP:port or hostname:port
        std::string custom_sni;
    };

    struct Location {
        std::string username;
        std::string password;
        std::vector<Endpoint> endpoints;
        ag::UniquePtr<X509_STORE, &X509_STORE_free> ca_store;
        ag::VpnUpstreamProtocol upstream_protocol = ag::VPN_UP_HTTP2;
        ag::VpnTlsProfile tls_profile = ag::VPN_TLS_PROFILE_CHROME;
        std::string client_random;
        std::string client_random_mask;
        std::string client_random_auth_key;
        std::optional<std::vector<std::string>> dns_upstreams;
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
        std::string device_name;
        std::vector<std::string> included_routes;
        std::vector<std::string> excluded_routes;
        uint32_t mtu_size = 0;
        uint32_t tcp_recv_buf_size = 0; ///< TCP receive window size in bytes (0 = compile-time default)
        uint32_t tcp_send_buf_size = 0; ///< TCP send buffer size in bytes (0 = compile-time default)
        std::string bound_if;
        bool change_system_dns = true;
        bool use_existing = false;
        std::optional<std::string> netns;
    };

    using Listener = std::variant<SocksListener, TunListener>;

    ag::LogLevel loglevel = ag::LOG_LEVEL_INFO;
    ag::VpnMode mode = ag::VPN_MODE_GENERAL;
    bool killswitch_enabled = false;
    std::string killswitch_allow_ports;
    bool post_quantum_group_enabled = true;
    bool exclusions_tcp_early_ack_enabled = false;
    bool exclusions_preresolve_enabled = true;
    uint32_t exclusions_preresolve_max_queries = 0; // Use default value
    std::string exclusions_scannable_ports;         // Empty = use default list
    std::string log_file_path;
    std::string exclusions;
    std::optional<std::string> ssl_session_storage_path;
    std::vector<std::string> legacy_dns_upstreams;
    Location location;
    Listener listener;

    static std::optional<TrustTunnelConfig> build_config(const toml::table &config);

    /**
     * Check if a PEM certificate chain can be verified with a trust store.
     * @param pem_bundle PEM-encoded certificate chain (leaf certificate first)
     * @param hostname Hostname to verify the leaf certificate against. The pipe syntax
     *                 (`sni|remote_id`) is accepted, in which case the leaf certificate is
     *                 verified against the `remote_id` part, just like at connect time
     * @param store Trusted CA store, the system one is used if null. Intended for tests
     * @return true if the chain is verifiable by the trust store, false otherwise
     */
    static bool is_certificate_system_verifiable(
            std::string_view pem_bundle, std::string_view hostname, X509_STORE *store = nullptr);

    /**
     * Build the `[endpoint]` table to be encoded as a deep-link out of a parsed configuration.
     *
     * Empty `addresses` and `dns_upstreams` entries are dropped, just like at connect time.
     * The pipe syntax in `hostname` is split into `hostname` and `custom_sni`, mirroring the
     * way the client resolves the SNI and the certificate verification name at connect time.
     * A non-empty `name` overrides the endpoint name from the configuration.
     * The certificate is omitted when the endpoint certificate chain is verifiable with the
     * system trust store.
     * @param config Root table of the client configuration
     * @param name Server display name override, the configuration value is used when empty
     * @param store Trusted CA store, the system one is used if null. Intended for tests
     * @return Table holding the single `endpoint` key, or `std::nullopt` on an invalid configuration
     */
    static std::optional<toml::table> build_deeplink_export_table(
            const toml::table &config, std::string_view name = {}, X509_STORE *store = nullptr);
};
} // namespace ag
