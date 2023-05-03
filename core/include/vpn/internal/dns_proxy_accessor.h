#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

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
        /// The address which the outbound proxy for the DNS proxy is listening on
        std::optional<sockaddr_storage> socks_listener_address;
        /// Certificate verification handler
        CertVerifyHandler cert_verify_handler = {};
    };

    explicit DnsProxyAccessor(Parameters p);
    ~DnsProxyAccessor();

    DnsProxyAccessor(const DnsProxyAccessor &) = delete;
    DnsProxyAccessor &operator=(const DnsProxyAccessor &) = delete;
    DnsProxyAccessor(DnsProxyAccessor &&) = delete;
    DnsProxyAccessor &operator=(DnsProxyAccessor &&) = delete;

    /**
     * Start the DNS proxy
     * @param timeout queries expiration time
     */
    bool start(std::optional<std::chrono::milliseconds> timeout);

    /**
     * Stop the DNS proxy
     */
    void stop();

    /**
     * Get a listener address by the given protocol
     */
    [[nodiscard]] const sockaddr_storage &get_listen_address(utils::TransportProtocol protocol) const;

private:
    std::unique_ptr<dns::DnsProxy> m_dns_proxy;
    Parameters m_parameters = {};
    sockaddr_storage m_dns_proxy_udp_listen_address = {};
    sockaddr_storage m_dns_proxy_tcp_listen_address = {};
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
