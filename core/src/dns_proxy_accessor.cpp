#include "vpn/internal/dns_proxy_accessor.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOCRYPT
#undef gettid
#include "dns/proxy/dnsproxy.h"

#include "common/logger.h"

#define log_accessor(r_, lvl_, fmt_, ...) lvl_##log((r_)->m_log, fmt_, ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

static constexpr std::string_view BOOTSTRAP_ADDRESSES[] = {
        "94.140.14.140:53",
};

static dns::DnsProxySettings make_dns_proxy_settings(const DnsProxyAccessor::Parameters &parameters, milliseconds timeout) {
    dns::DnsProxySettings settings = dns::DnsProxySettings::get_default();
    settings.upstreams = {{
            .address = parameters.resolver_address,
            .bootstrap = {std::begin(BOOTSTRAP_ADDRESSES), std::end(BOOTSTRAP_ADDRESSES)},
            .timeout = timeout,
            .id = 0,
    }};

    settings.fallbacks = {};

    settings.listeners = {
            {
                    .address = "127.0.0.1",
                    .port = 0,
                    .protocol = ag::utils::TP_UDP,
            },
            {
                    .address = "127.0.0.1",
                    .port = 0,
                    .protocol = ag::utils::TP_TCP,
            },
    };

    settings.outbound_proxy = {{
            .protocol = dns::OutboundProxyProtocol::SOCKS5_UDP,
            .address = sockaddr_ip_to_str((sockaddr *) &parameters.socks_listener_address),
            .port = sockaddr_get_port((sockaddr *) &parameters.socks_listener_address),
            .auth_info = std::nullopt,
            .trust_any_certificate = false,
            .ignore_if_unavailable = false,
    }};

    settings.ipv6_available = parameters.ipv6_available;

    return settings;
}

DnsProxyAccessor::DnsProxyAccessor(Parameters p)
        : m_dns_proxy(std::make_unique<dns::DnsProxy>())
        , m_parameters(std::move(p)) {
}

DnsProxyAccessor::~DnsProxyAccessor() = default;

bool DnsProxyAccessor::start(std::chrono::milliseconds timeout) {
    auto [ok, msg] = m_dns_proxy->init(make_dns_proxy_settings(m_parameters, timeout),
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
        if (msg.has_value()) {
            log_accessor(this, err, "Failed to initialize DNS proxy: {}", *msg);
        }
        return false;
    }

    if (msg.has_value()) {
        log_accessor(this, warn, "DNS proxy initialization warning: {}", *msg);
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

    if (m_dns_proxy_udp_listen_address.ss_family == AF_UNSPEC
            || m_dns_proxy_tcp_listen_address.ss_family == AF_UNSPEC) {
        log_accessor(this, err, "DNS proxy is not listening for queries over {}",
                (m_dns_proxy_udp_listen_address.ss_family == AF_UNSPEC) ? "UDP" : "TCP");
        return false;
    }

    return true;
}

void DnsProxyAccessor::stop() {
    if (m_dns_proxy != nullptr) {
        m_dns_proxy->deinit();
    }
}

const sockaddr_storage &DnsProxyAccessor::get_listen_address(int proto) const {
    return (proto == IPPROTO_UDP) ? m_dns_proxy_udp_listen_address : m_dns_proxy_tcp_listen_address;
}

} // namespace ag
