#pragma once

#include <openssl/x509.h>

#include "net/tls.h"
#include "vpn/internal/vpn_client.h"

namespace ag {

struct VerifyCallbackResult {
    int ret;
    const char *host_name;
    X509 *cert;
    STACK_OF(X509) * chain;
};

/**
 * Common endpoint certificate verification logic for HTTP/2 and QUIC/H3 upstreams.
 * Extracts cert/chain/SSL from store_ctx, resolves the endpoint hostname,
 * and calls the platform cert_verify_handler.
 */
inline VerifyCallbackResult verify_endpoint_cert(X509_STORE_CTX *store_ctx, VpnClient *vpn) {
    auto *cert = X509_STORE_CTX_get0_cert(store_ctx);
    auto *chain = X509_STORE_CTX_get0_untrusted(store_ctx);
    auto *ssl = (SSL *) X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());

    const char *host_name = !safe_to_string_view(vpn->upstream_config.endpoint->remote_id).empty()
            ? vpn->upstream_config.endpoint->remote_id
            : vpn->upstream_config.endpoint->name;

    int ret = vpn->parameters.cert_verify_handler.func(host_name, (sockaddr *) &vpn->upstream_config.endpoint->address,
            {cert, chain, ssl, VT_ENDPOINT}, vpn->parameters.cert_verify_handler.arg);

    return {ret, host_name, cert, chain};
}

} // namespace ag
