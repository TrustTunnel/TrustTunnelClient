#pragma once

#include <cstdbool>
#include <string>
#include <string_view>

#include "vpn/platform.h" // Unbreak Windows builddows

#include <openssl/x509.h>

#include "vpn/utils.h"

namespace ag {

using TlsCert = AG_ARRAY_OF(uint8_t);
using TlsChain = AG_ARRAY_OF(TlsCert);

enum TlsParseResult {
    TLS_RERR = 1,
    TLS_RMORE,
    TLS_RCLIENT_HELLO,
    TLS_RCLIENT_HELLO_SNI,
    TLS_RSERV_HELLO,
    TLS_RCERT,
    TLS_RDONE,
};

struct TlsReader {
    int state;
    U8View in;
    U8View rec;
    U8View buf;
    std::string_view tls_hostname;
    std::string x509_subject_common_name;
};

extern "C" {

/**
 * Get the X509 certificate from context
 * @param ctx certificate context
 * @return X509 certificate
 */
WIN_EXPORT X509 *tls_get_cert(X509_STORE_CTX *ctx);

/**
 * Get the X509 certificates chain from context
 * @param ctx certificate context
 * @return STACK_OF(X509) certificates chain
 */
WIN_EXPORT STACK_OF(X509) * tls_get_chain(X509_STORE_CTX *ctx);

/**
 * Serialize certificate.
 * @param cert Certificate to serialize.
 * @return Serialized certificate, or NULL on failure, free with `tls_free_serialized_cert()`.
 */
WIN_EXPORT TlsCert *tls_serialize_cert(X509 *cert);

/**
 * Free memory of serialized cert
 * @param cert cert to free
 */
WIN_EXPORT void tls_free_serialized_cert(TlsCert *cert);

/**
 * Serialize certificate chain
 * @return Serialized chain, or NULL on failure, free with `tls_free_serialized_chain()`.
 */
WIN_EXPORT TlsChain *tls_serialize_cert_chain(STACK_OF(X509) * chain);

/**
 * Free memory of serialized chain
 * @param chain chain to free
 */
WIN_EXPORT void tls_free_serialized_chain(TlsChain *chain);

} // extern "C"

/**
 * Check if the certificate Subject Alternative Name (SAN) or Subject CommonName (CN) matches
 * the specified host name
 * @param cert certificate
 * @param host host name to check
 * @return true if matches, false otherwise
 */
bool tls_verify_cert_host_name(X509 *cert, const char *host);

/**
 * Check if the certificate matches a specified IPv4 or IPv6 address
 * @param cert certificate
 * @param ip address
 * @return true if matches, false otherwise
 */
bool tls_verify_cert_ip(X509 *cert, const char *ip);

/**
 * Verify given certificate via OpenSSL API
 * @param ctx certificate context to verify
 * @param store trusted CA store (if NULL, `tls_create_ca_store` will be used)
 * @return NULL if verified successfully, error message otherwise
 */
const char *tls_verify_cert(X509_STORE_CTX *ctx, X509_STORE *store);

/**
 * Create trusted CA store from system's one
 * @return CA store
 */
X509_STORE *tls_create_ca_store();

#define tls_input(t, d, s) (t)->in = {(uint8_t *) (d), size_t(s)}

/**
 * Parse TLS record
 * @return enum tls_parse_result_t
 */
TlsParseResult tls_parse(TlsReader *t);

} // namespace ag
