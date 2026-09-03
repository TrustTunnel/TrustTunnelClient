#include "net/tls_client_random_psk.h"

#ifdef SSL_set_custom_client_random

#include <algorithm>
#include <climits>
#include <cstring>
#include <string_view>

#include <openssl/aes.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifndef OPENSSL_IS_BORINGSSL
#warning "SSL_set_custom_client_random is defined but OPENSSL_IS_BORINGSSL is not; \
HKDF argument order may differ from BoringSSL and break PSK derivation"
#endif

namespace ag {

std::optional<std::array<uint8_t, SSL3_RANDOM_SIZE>> derive_client_random_from_psk(
        Uint8View psk_key, const char *sni, Uint8View salt) {
    constexpr size_t half = SSL3_RANDOM_SIZE / 2;
    static constexpr std::string_view INFO = "tls13 encryption context";

    if (sni == nullptr || sni[0] == '\0') {
        return std::nullopt;
    }

    uint8_t generated[half];
    if (salt.empty()) {
        if (1 != RAND_bytes(generated, half)) {
            return std::nullopt;
        }
        salt = {generated, sizeof(generated)};
    } else if (salt.size() != half) {
        return std::nullopt;
    }

    uint8_t sni_hash[SHA256_DIGEST_LENGTH];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    SHA256(reinterpret_cast<const uint8_t *>(sni), std::strlen(sni), sni_hash);

    uint8_t derived_key[half];
    if (1
            != HKDF(derived_key, half, EVP_sha256(), psk_key.data(), psk_key.size(), salt.data(), salt.size(),
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    reinterpret_cast<const uint8_t *>(INFO.data()), INFO.size())) {
        return std::nullopt;
    }

    AES_KEY aes_key;
    if (0 != AES_set_encrypt_key(derived_key, half * CHAR_BIT, &aes_key)) {
        return std::nullopt;
    }

    uint8_t ciphertext[half];
    AES_encrypt(sni_hash, ciphertext, &aes_key); // encrypts the first 16 bytes of sni_hash

    std::array<uint8_t, SSL3_RANDOM_SIZE> result{};
    std::copy_n(salt.data(), half, result.begin());
    std::copy_n(ciphertext, half, result.begin() + half);

    OPENSSL_cleanse(derived_key, half);
    OPENSSL_cleanse(&aes_key, sizeof(aes_key));
    return result;
}

} // namespace ag

#endif // SSL_set_custom_client_random
