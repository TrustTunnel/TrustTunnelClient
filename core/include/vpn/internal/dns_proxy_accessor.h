#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

#include "vpn/event_loop.h"
#include "vpn/internal/utils.h"

namespace ag {

namespace dns {
class DnsProxy;
} // namespace dns

class DnsProxyAccessor {
public:
    struct Parameters {
        /// The DNS resolver URL (see `upstream_options::address` in the DNS libs for the syntax details)
        std::string resolver_address;
        /// The address which the outbound proxy for the DNS proxy is listening on
        sockaddr_storage socks_listener_address = {};
        /// Certificate verification handler
        CertVerifyHandler cert_verify_handler = {};
        /// Whether IPv6 is available
        bool ipv6_available = true;
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
    bool start(std::chrono::milliseconds timeout);

    /**
     * Stop the DNS proxy
     */
    void stop();

    /**
     * Get a listener address by the given protocol
     */
    [[nodiscard]] const sockaddr_storage &get_listen_address(int proto) const;

private:
    std::unique_ptr<dns::DnsProxy> m_dns_proxy;
    Parameters m_parameters = {};
    sockaddr_storage m_dns_proxy_udp_listen_address = {};
    sockaddr_storage m_dns_proxy_tcp_listen_address = {};
    ag::Logger m_log{"DNS_PROXY_ACCESSOR"};
};

} // namespace ag
