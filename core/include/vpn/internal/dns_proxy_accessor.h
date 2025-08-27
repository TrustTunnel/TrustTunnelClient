#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#ifdef __APPLE__
#include <TargetConditionals.h>

#if TARGET_OS_IPHONE
#include "vpn/internal/qos_settings.h"
#endif // TARGET_OS_IPHONE

#endif // __APPLE__

#include "common/net_utils.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "vpn/internal/utils.h"

namespace ag {

namespace dns {
class DnsProxy;
} // namespace dns

class DnsProxyAccessor {
public:
    // See `upstream_options` in the DNS libs for the syntax details
    struct Upstream {
        std::string address;
        std::optional<SocketAddress> resolved_host;
    };

    struct Parameters {
        /// The DNS resolver URLs
        std::vector<Upstream> upstreams;
        /// Fallbacks to support failing resolvers
        std::vector<std::string> fallbacks;
        /// Bootstraps DNS servers used for initial resolution
        std::vector<std::string> bootstraps;
        /// The address which the outbound proxy for the DNS proxy is listening on
        std::optional<SocketAddress> socks_listener_address;
        /// Certificate verification handler
        CertVerifyHandler cert_verify_handler = {};
#if defined(__APPLE__) && TARGET_OS_IPHONE
        /// QoS class and relative priority for threads on iOS platform
        VpnQosSettings qos_settings;
#endif // __APPLE__ && TARGET_OS_IPHONE
    };

    explicit DnsProxyAccessor(Parameters p);
    ~DnsProxyAccessor();

    DnsProxyAccessor(const DnsProxyAccessor &) = delete;
    DnsProxyAccessor &operator=(const DnsProxyAccessor &) = delete;
    DnsProxyAccessor(DnsProxyAccessor &&) = delete;
    DnsProxyAccessor &operator=(DnsProxyAccessor &&) = delete;

    /**
     * Start the DNS proxy
     */
    bool start();

    /**
     * Stop the DNS proxy
     */
    void stop();

    /**
     * Get a listener address by the given protocol
     */
    [[nodiscard]] const SocketAddress &get_listen_address(utils::TransportProtocol protocol) const;

private:
    std::unique_ptr<dns::DnsProxy> m_dns_proxy;
    Parameters m_parameters = {};
    SocketAddress m_dns_proxy_udp_listen_address = {};
    SocketAddress m_dns_proxy_tcp_listen_address = {};
    ag::Logger m_log{"DNS_PROXY_ACCESSOR"};
};

} // namespace ag

template <>
struct fmt::formatter<ag::DnsProxyAccessor::Upstream> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::DnsProxyAccessor::Upstream &u, FormatContext &ctx) {
        return fmt::format_to(ctx.out(), "address={}, resolved_host={}", u.address,
                u.resolved_host.has_value() ? u.resolved_host->host_str() : "<none>");
    }
};
