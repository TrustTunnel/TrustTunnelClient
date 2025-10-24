#include "net/tls13_utils.h"

#include <span>

#include <openssl/evp.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "common/defs.h"

extern "C" void ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx);

namespace ag::tls13_utils {

bool hkdf_extract(std::span<uint8_t> dest, std::span<const uint8_t> secret, std::span<const uint8_t> salt) {
    // SHA256 is used for QUIC [rfc 9001 5.2]
    const EVP_MD *prf = EVP_sha256();
    size_t dest_len = EVP_MD_size(prf);
    if (dest.size() < dest_len) {
        return false;
    }

    ngtcp2_crypto_ctx ctx;
    ngtcp2_crypto_ctx_initial(&ctx);

    return ngtcp2_crypto_hkdf_extract(dest.data(), &ctx.md, secret.data(), secret.size(), salt.data(), salt.size()) == 0;
}

bool hkdf_expand_label(std::span<uint8_t> dest, std::span<const uint8_t> secret, std::string_view label,
        std::span<const uint8_t> context) {

    std::string full_label = std::string("tls13 ") + label.data();
    Uint8Vector info;
    // 2 first bytes store out key length
    info.push_back((uint8_t) (dest.size() >> CHAR_BIT));
    info.push_back((uint8_t) dest.size());
    // 3rd byte stores label length
    info.push_back((uint8_t) full_label.size());
    info.insert(info.end(), full_label.begin(), full_label.end());
    // Context length
    info.push_back((uint8_t) context.size());
    info.insert(info.end(), context.begin(), context.end());

    ngtcp2_crypto_ctx ctx;
    ngtcp2_crypto_ctx_initial(&ctx);
    return ngtcp2_crypto_hkdf_expand(dest.data(), dest.size(), &ctx.md, secret.data(), secret.size(),
                   info.data(), info.size()) == 0;
}

}  // namespace ag::tls13_utils
