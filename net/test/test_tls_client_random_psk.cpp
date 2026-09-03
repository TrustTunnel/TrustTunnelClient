#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string_view>
#include <variant>
#include <vector>

#include "common/defs.h"
#include "net/tls_client_random_psk.h"
#include "net/utils.h"

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#ifdef SSL_set_custom_client_random

static constexpr std::string_view TLS13_INFO = "tls13 encryption context";

// Independently computed known-good vectors (derived with OpenSSL CLI via
// `openssl kdf` (HKDF-SHA256) + `openssl enc -aes-128-ecb`), grounding the
// algorithm against external ground truth rather than a test-side reimplementation.
static constexpr std::array<uint8_t, 16> VECTOR_PSK_ABCD = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
static constexpr std::array<uint8_t, 16> VECTOR_SALT_ABCD = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
static constexpr std::array<uint8_t, 32> VECTOR_CLIENT_RANDOM_ABCD = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x95, 0x91, 0x80, 0x72, 0x66, 0xc9, 0x01, 0xdf, 0xe8, 0xc7,
        0x3c, 0x30, 0x40, 0xb1, 0xbd, 0x82};

static constexpr std::array<uint8_t, 16> VECTOR_PSK_WORD_TIPS = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static constexpr std::array<uint8_t, 16> VECTOR_SALT_WORD_TIPS = {
        0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
static constexpr std::array<uint8_t, 32> VECTOR_CLIENT_RANDOM_WORD_TIPS = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x1f, 0xdc, 0x0a, 0xe9, 0x7c, 0xd3, 0x6d, 0x55, 0x7d,
        0xd4, 0x26, 0xc3, 0x45, 0x66, 0xe2, 0x34};

// Derive the 16-byte AES key from a PSK, the salt (first half of client_random)
// and the SNI, mirroring the production HKDF parameters. Used as the test-side
// complement for the decrypt round-trip check.
static bool derive_test_key(const ag::U8View &psk_key, const uint8_t *salt, const char *sni, uint8_t *out_key) {
    constexpr size_t KEY_LEN = 16;
    return 1
            == HKDF(out_key, KEY_LEN, EVP_sha256(), psk_key.data(), psk_key.size(), salt, KEY_LEN,
                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                    reinterpret_cast<const uint8_t *>(TLS13_INFO.data()), TLS13_INFO.size());
}

// Decrypt the second half of client_random with the key derived from its first
// half and check that it equals SHA256(SNI)[..16]. This validates the encrypt
// direction against an independent (decrypt) operation.
static bool decrypt_round_trip_valid(const ag::U8View &psk_key, const uint8_t *client_random, const char *sni) {
    uint8_t derived_key[16];
    if (!derive_test_key(psk_key, client_random, sni, derived_key)) {
        return false;
    }

    uint8_t sni_hash[SHA256_DIGEST_LENGTH];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    SHA256(reinterpret_cast<const uint8_t *>(sni), std::strlen(sni), sni_hash);

    AES_KEY aes_key;
    if (0 != AES_set_decrypt_key(derived_key, 128, &aes_key)) {
        return false;
    }

    uint8_t plaintext[16];
    AES_decrypt(client_random + 16, plaintext, &aes_key);
    return 0 == std::memcmp(plaintext, sni_hash, 16);
}

TEST(TlsClientRandomPsk, MatchesIndependentlyComputedVectorAbcd) {
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};
    ag::U8View salt{VECTOR_SALT_ABCD.data(), VECTOR_SALT_ABCD.size()};

    auto derived = ag::derive_client_random_from_psk(psk, "abcd", salt);
    ASSERT_TRUE(derived.has_value());
    ASSERT_EQ(VECTOR_CLIENT_RANDOM_ABCD.size(), derived->size());
    EXPECT_EQ(0, std::memcmp(VECTOR_CLIENT_RANDOM_ABCD.data(), derived->data(), derived->size()));
}

TEST(TlsClientRandomPsk, MatchesIndependentlyComputedVectorWordTips) {
    ag::U8View psk{VECTOR_PSK_WORD_TIPS.data(), VECTOR_PSK_WORD_TIPS.size()};
    ag::U8View salt{VECTOR_SALT_WORD_TIPS.data(), VECTOR_SALT_WORD_TIPS.size()};

    auto derived = ag::derive_client_random_from_psk(psk, "word.tips", salt);
    ASSERT_TRUE(derived.has_value());
    ASSERT_EQ(VECTOR_CLIENT_RANDOM_WORD_TIPS.size(), derived->size());
    EXPECT_EQ(0, std::memcmp(VECTOR_CLIENT_RANDOM_WORD_TIPS.data(), derived->data(), derived->size()));
}

TEST(TlsClientRandomPsk, RandomClientRandomPassesDecryptRoundTrip) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());
    ASSERT_EQ(SSL3_RANDOM_SIZE, derived->size());

    EXPECT_TRUE(decrypt_round_trip_valid(psk, derived->data(), SNI));
}

TEST(TlsClientRandomPsk, WrongSniFailsDecryptRoundTrip) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());

    EXPECT_FALSE(decrypt_round_trip_valid(psk, derived->data(), "other.example.com"));
}

TEST(TlsClientRandomPsk, WrongPskFailsDecryptRoundTrip) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};
    ag::U8View other_psk{VECTOR_PSK_WORD_TIPS.data(), VECTOR_PSK_WORD_TIPS.size()};

    auto derived = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(derived.has_value());

    EXPECT_FALSE(decrypt_round_trip_valid(other_psk, derived->data(), SNI));
}

TEST(TlsClientRandomPsk, RandomSaltDiffersBetweenCalls) {
    static constexpr char SNI[] = "test.example.com";
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};

    auto first = ag::derive_client_random_from_psk(psk, SNI);
    auto second = ag::derive_client_random_from_psk(psk, SNI);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());

    // The random salt (first half) should differ between calls.
    EXPECT_NE(0, std::memcmp(first->data(), second->data(), SSL3_RANDOM_SIZE / 2));
}

TEST(TlsClientRandomPsk, EmptySniFails) {
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};
    ag::U8View salt{VECTOR_SALT_ABCD.data(), VECTOR_SALT_ABCD.size()};

    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, nullptr).has_value());
    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, "").has_value());
    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, nullptr, salt).has_value());
    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, "", salt).has_value());
}

TEST(TlsClientRandomPsk, WrongSaltSizeFails) {
    static constexpr std::array<uint8_t, 8> SHORT_SALT = {};
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};

    EXPECT_FALSE(ag::derive_client_random_from_psk(psk, "abcd", {SHORT_SALT.data(), SHORT_SALT.size()}).has_value());
}

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
// End-to-end wiring: make_ssl() with a PSK key must put the derived value into
// the actual ClientHello, not just compute it. The second half of the
// client_random in the emitted hello must decrypt to SHA256(SNI)[0:16] under
// the key derived from the PSK and the hello's own first half.
TEST(TlsClientRandomPsk, MakeSslAppliesDerivedClientRandom) {
    static constexpr char SNI[] = "psk.example.org";
    static constexpr uint8_t H2_ALPN[] = {2, 'h', '2'};
    ag::U8View psk{VECTOR_PSK_ABCD.data(), VECTOR_PSK_ABCD.size()};

    auto r = ag::make_ssl(nullptr, nullptr, {H2_ALPN, std::size(H2_ALPN)}, SNI, ag::MSPT_TLS, {}, {}, {}, psk);
    ASSERT_TRUE(std::holds_alternative<ag::SslPtr>(r)) << std::get<std::string>(r);
    ag::SslPtr ssl = std::move(std::get<ag::SslPtr>(r));

    // Drive the handshake against an in-memory BIO and read out the ClientHello bytes.
    SSL_set0_wbio(ssl.get(), BIO_new(BIO_s_mem()));
    SSL_connect(ssl.get());
    std::vector<uint8_t> hello(UINT16_MAX);
    const int n = BIO_read(SSL_get_wbio(ssl.get()), hello.data(), (int) hello.size());
    // TLS record (5) + handshake header (4) + legacy_version (2) + client_random (32).
    ASSERT_GT(n, 11 + (int) SSL3_RANDOM_SIZE);
    const uint8_t *client_random = hello.data() + 11;

    EXPECT_TRUE(decrypt_round_trip_valid(psk, client_random, SNI));
    // Sanity: it must be the derived value, not arbitrary random bytes.
    EXPECT_FALSE(decrypt_round_trip_valid(psk, client_random, "other.example.org"));
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

#endif
