#include <algorithm>

#include <magic_enum/magic_enum.hpp>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOCRYPT
#undef gettid
#include "dns/proxy/dnsproxy.h"

#include "common/defs.h"
#include "common/logger.h"
#include "net/network_manager.h"
#include "vpn/internal/dns_proxy_accessor.h"

#define log_accessor(r_, lvl_, fmt_, ...) lvl_##log((r_)->m_log, fmt_, ##__VA_ARGS__)

namespace ag {

static dns::DnsProxySettings make_dns_proxy_settings(const DnsProxyAccessor::Parameters &parameters) {
    dns::DnsProxySettings settings = dns::DnsProxySettings::get_default();
    settings.upstreams.clear();
    settings.upstreams.reserve(parameters.upstreams.size());
    uint32_t outbound_interface = vpn_network_manager_get_outbound_interface();
    std::transform(parameters.upstreams.begin(), parameters.upstreams.end(), std::back_inserter(settings.upstreams),
            [id = 0, outbound_interface](const DnsProxyAccessor::Upstream &upstream) mutable {
                IpAddress resolved_host;
                if (upstream.resolved_host.has_value()) {
                    uint8_t *data = nullptr;
                    if (upstream.resolved_host->is_ipv4()) {
                        data = resolved_host.emplace<Ipv4Address>().data();
                    } else {
                        data = resolved_host.emplace<Ipv6Address>().data();
                    }
                    auto *ip = (uint8_t *) sockaddr_get_ip_ptr(upstream.resolved_host->c_sockaddr());
                    size_t size = sockaddr_get_ip_size(upstream.resolved_host->c_sockaddr());
                    std::copy(ip, ip + size, data);
                }

                return dns::UpstreamOptions{
                        .address = upstream.address,
                        .bootstrap = {std::begin(AG_UNFILTERED_DNS_IPS_V4), std::end(AG_UNFILTERED_DNS_IPS_V4)},
                        .resolved_server_ip = resolved_host,
                        .id = id++,
                        .outbound_interface =
                                (outbound_interface != 0) ? IfIdVariant(outbound_interface) : std::monostate{},
                };
            });

    settings.fallbacks.clear();

    settings.listeners.clear();
    settings.listeners.reserve(magic_enum::enum_count<utils::TransportProtocol>());
    for (utils::TransportProtocol protocol : magic_enum::enum_values<utils::TransportProtocol>()) {
        settings.listeners.push_back({
                .address = "127.0.0.1",
                .protocol = protocol,
        });
    }

    if (parameters.socks_listener_address.has_value()) {
        settings.outbound_proxy = {{
                .protocol = dns::OutboundProxyProtocol::SOCKS5_UDP,
                .address = sockaddr_ip_to_str((sockaddr *) &parameters.socks_listener_address.value()),
                .port = sockaddr_get_port((sockaddr *) &parameters.socks_listener_address.value()),
        }};
    }

    settings.enable_route_resolver = false;

    return settings;
}

DnsProxyAccessor::DnsProxyAccessor(Parameters p)
        : m_parameters(std::move(p)) {
}

DnsProxyAccessor::~DnsProxyAccessor() = default;

bool DnsProxyAccessor::start() {
    if (m_dns_proxy != nullptr) {
        log_accessor(this, err, "Already started");
        return false;
    }

    m_dns_proxy = std::make_unique<dns::DnsProxy>();
    auto [ok, msg] = m_dns_proxy->init(make_dns_proxy_settings(m_parameters),
            {
                    .on_request_processed = nullptr,
                    .on_certificate_verification =
                            [this](dns::CertificateVerificationEvent e) -> std::optional<std::string> {
                        const unsigned char *d = e.certificate.data();
                        DeclPtr<X509_STORE_CTX, &X509_STORE_CTX_free> store{X509_STORE_CTX_new()};
                        DeclPtr<X509, &X509_free> cert{
                                d2i_X509(nullptr, (const unsigned char **) &d, (long) e.certificate.size())};
                        X509_STORE_CTX_set_cert(store.get(), cert.get());

                        STACK_OF(X509) *chain = sk_X509_new_null();
                        for (const std::vector<uint8_t> &c : e.chain) {
                            d = c.data();
                            sk_X509_push(chain, d2i_X509(nullptr, (const unsigned char **) &d, (long) c.size()));
                        }
                        X509_STORE_CTX_set_chain(store.get(), chain);

                        int verify_result = m_parameters.cert_verify_handler.func(
                                // server name and ip are already verified by the DNS proxy
                                nullptr, nullptr, store.get(), m_parameters.cert_verify_handler.arg);

                        sk_X509_pop_free(chain, &X509_free);
                        return (verify_result > 0) ? std::nullopt : std::make_optional("Verification failed");
                    },
            });

    if (!ok) {
        log_accessor(this, err, "Failed to initialize DNS proxy: {}", msg->str());
        m_dns_proxy.reset();
        this->stop();
        return false;
    }

    if (msg != nullptr) {
        log_accessor(this, warn, "DNS proxy initialization warning: {}", msg->str());
    }

    const auto &settings = m_dns_proxy->get_settings();
    for (const auto &listener : settings.listeners) {
        switch (listener.protocol) {
        case utils::TP_UDP:
            m_dns_proxy_udp_listen_address = sockaddr_from_str(listener.address.c_str());
            sockaddr_set_port((sockaddr *) &m_dns_proxy_udp_listen_address, listener.port);
            break;
        case utils::TP_TCP:
            m_dns_proxy_tcp_listen_address = sockaddr_from_str(listener.address.c_str());
            sockaddr_set_port((sockaddr *) &m_dns_proxy_tcp_listen_address, listener.port);
            break;
        }
    }

    if (AF_UNSPEC == m_dns_proxy_udp_listen_address.ss_family
            || AF_UNSPEC == m_dns_proxy_tcp_listen_address.ss_family) {
        log_accessor(this, err, "DNS proxy is not listening for queries over {}",
                (m_dns_proxy_udp_listen_address.ss_family == AF_UNSPEC) ? "UDP" : "TCP");
        this->stop();
        return false;
    }

    return true;
}

void DnsProxyAccessor::stop() {
    if (m_dns_proxy != nullptr) {
        m_dns_proxy->deinit();
        m_dns_proxy.reset();
    }
    m_dns_proxy_udp_listen_address = {};
    m_dns_proxy_tcp_listen_address = {};
}

const sockaddr_storage &DnsProxyAccessor::get_listen_address(utils::TransportProtocol protocol) const {
    switch (protocol) {
    case utils::TP_UDP:
        return m_dns_proxy_udp_listen_address;
    case utils::TP_TCP:
        return m_dns_proxy_tcp_listen_address;
    }
}

} // namespace ag
