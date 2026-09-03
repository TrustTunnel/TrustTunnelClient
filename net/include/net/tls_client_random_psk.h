#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <openssl/ssl.h>

#include "common/defs.h"

namespace ag {

// Gated on SSL_set_custom_client_random: the whole feature only exists on the
// AdGuard-patched OpenSSL builds (not on the stock OpenSSL used on MIPS).
#ifdef SSL_set_custom_client_random

/**
 * Derive the full 32-byte TLS client_random from a PSK key and the SNI.
 * @param psk_key PSK key bytes
 * @param sni SNI host name (may be nullptr/empty)
 * @param salt the explicit 16-byte salt, or empty (default) to generate one
 *        randomly. The fixed-salt form is exposed for known-answer tests only.
 * @return 32-byte client_random, or std::nullopt if derivation failed
 */
std::optional<std::array<uint8_t, SSL3_RANDOM_SIZE>> derive_client_random_from_psk(
        ag::Uint8View psk_key, const char *sni, ag::Uint8View salt = {});

#endif

} // namespace ag
