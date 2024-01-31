#include "net/quic_utils.h"

#include <climits>
#include <set>

#include <common/logger.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <quiche.h>

namespace ag {

/// client initial secret length [rfc 9001 A.1]
static constexpr size_t QUIC_INITIAL_SECRETLEN = 32;
/// quic key (for payload decryption) and quic hp (header protection) length [rfc 9001 A.1]
static constexpr size_t QUIC_INITIAL_KEYLEN = 16;
/// quic iv (Initialization Vector) length [rfc 9001 A.1]
static constexpr size_t QUIC_INITIAL_IVLEN = 12;
/// initial salt length
static constexpr size_t QUIC_INITIAL_SALTLEN = 20;
/// header protection mask length (AES 128 key size = 16 bits)
static constexpr size_t QUIC_HPMASKLEN = 16;

static ag::Logger log{"QUIC_UTILS"};

struct QuicInitialSalt {
    uint32_t version;
    std::array<uint8_t, QUIC_INITIAL_SALTLEN> salt;
};

// Versions in decreasing order
static constexpr QuicInitialSalt QUIC_INITIAL_SALTS[] = {
        // QUIC draft 34
        {.version = 0xff000022,
                .salt = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
                        0xcc, 0xbb, 0x7f, 0x0a,}},

        // QUIC draft 28
        {.version = 0xff00001c,
                .salt = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
                        0x43, 0x90, 0xa8, 0x99,}},

        // QUIC v1 (same as latest draft)
        {.version = 0x00000001,
                .salt = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
                        0xcc, 0xbb, 0x7f, 0x0a,}
        },
};

static uint64_t get_varint(size_t *length, const uint8_t *buf);

static bool create_hp_mask(uint8_t *hp_mask, const uint8_t *key, const uint8_t *sample) {
    AES_KEY aes_key{};
    static const size_t AES_KEY_SIZE = 128;
    if (AES_set_encrypt_key(key, AES_KEY_SIZE, &aes_key) != 0) {
        return false;
    }
    AES_ecb_encrypt(sample, hp_mask, &aes_key, true);
    return true;
}

static bool decrypt_quic_payload(uint8_t *dest, const uint8_t *payload_key, const uint8_t *ciphertext,
        size_t ciphertext_len, const uint8_t *nonce, const uint8_t *associated_data, size_t associated_data_len,
        size_t *max_overhead) {
    const EVP_AEAD *cipher = EVP_aead_aes_128_gcm_tls13();
    size_t keylen = EVP_AEAD_key_length(cipher);
    uint8_t nonce_len = EVP_AEAD_nonce_length(cipher);

    DeclPtr<EVP_AEAD_CTX, &EVP_AEAD_CTX_free> actx{
            EVP_AEAD_CTX_new(cipher, payload_key, keylen, EVP_AEAD_DEFAULT_TAG_LENGTH)};
    if (actx == nullptr) {
        return false;
    }
    size_t max_outlen = ciphertext_len;
    size_t outlen = 0;

    if (EVP_AEAD_CTX_open(actx.get(), dest, &outlen, max_outlen, nonce, nonce_len, ciphertext, ciphertext_len,
                associated_data, associated_data_len)
            != 1) {
        return false;
    }
    // value to calculate decrypted packet size
    *max_overhead = EVP_AEAD_max_overhead(cipher);
    return true;
}

std::optional<std::vector<uint8_t>> quic_utils::decrypt_initial(
        U8View initial_packet, const quic_utils::QuicPacketHeader &hd) {

    if (initial_packet.size() < QUICHE_MIN_CLIENT_INITIAL_LEN) {
        return std::nullopt;
    }
    const auto *initial_salt_it = std::find_if(
            std::begin(QUIC_INITIAL_SALTS), std::end(QUIC_INITIAL_SALTS), [&](const QuicInitialSalt &salt) {
                return hd.version >= salt.version;
            });
    if (initial_salt_it == std::end(QUIC_INITIAL_SALTS)) {
        return std::nullopt;
    }
    // Extract common initial secret for further extraction of
    // the secrets for protecting client packets
    std::array<uint8_t, QUIC_INITIAL_SECRETLEN> initial_secret_buf{};

    if (!tls13_utils::hkdf_extract(initial_secret_buf, std::span{hd.dcid.data(), hd.dcid_len},
                initial_salt_it->salt)) {
        return std::nullopt;
    }

    // Extract client secret to get key, iv and hp afterwards
    std::array<uint8_t, QUIC_INITIAL_SECRETLEN> client_secret{};

    if (!tls13_utils::hkdf_expand_label(client_secret, initial_secret_buf, "client in")) {
        return std::nullopt;
    }
    // Extract key for payload decryption
    std::array<uint8_t, QUIC_INITIAL_KEYLEN> payload_key{};
    if (!tls13_utils::hkdf_expand_label(payload_key, client_secret, "quic key")) {
        return std::nullopt;
    }
    // Extract initialization vector for getting nonce for payload decryption
    std::array<uint8_t, QUIC_INITIAL_IVLEN> payload_iv{};
    if (!tls13_utils::hkdf_expand_label(payload_iv, client_secret, "quic iv")) {
        return std::nullopt;
    }
    // Extract header protection data
    std::array<uint8_t, QUIC_INITIAL_KEYLEN> hp_key{};
    if (!tls13_utils::hkdf_expand_label(hp_key, client_secret, "quic hp")) {
        return std::nullopt;
    }
    // Parse token length offset
    // [RFC 9001 5.4.1, Figure 7]
    // 8 protected bits + version + length of dcid_len + length of dcid + length of scid_len + lenght of scid
    size_t token_length_offset = 1 + 4 + 1 + hd.dcid_len + 1 + hd.scid_len;
    size_t token_length_size = 1 << (initial_packet[token_length_offset] >> 6);
    // Parse length offset
    size_t payload_length_offset = token_length_offset + token_length_size + hd.token_len;
    size_t payload_length_size = 1 << (initial_packet[payload_length_offset] >> 6);
    // get packet number offset
    size_t pn_offset = 7 + hd.dcid_len + hd.scid_len + payload_length_size + token_length_size + hd.token_len;
    // get sample offset
    size_t sample_offset = pn_offset + 4;
    // create hp mask
    std::array<uint8_t, QUIC_HPMASKLEN> hp_mask{};
    if (!create_hp_mask(hp_mask.data(), hp_key.data(), initial_packet.data() + sample_offset)) {
        return std::nullopt;
    }
    // we got all preparation info
    // begin to decrypt initial packet
    // copy initial packet as it shouldn't be changed
    std::vector<uint8_t> decrypted_packet(initial_packet.data(), initial_packet.data() + initial_packet.size());
    // get packet number length
    decrypted_packet[0] ^= hp_mask[0] & 0x0f; // Decrypt pkt_num_len
    size_t pn_length = (decrypted_packet[0] & 0x03) + 1;
    for (size_t i = 0; i < pn_length; ++i) {
        decrypted_packet[pn_offset + i] ^= hp_mask[i + 1];
    }
    // Decrypt payload
    // Nonce is IV XOR left-padded(packet number, IVLEN)
    for (size_t i = 0; i < pn_length; ++i) {
        payload_iv[QUIC_INITIAL_IVLEN - pn_length + i] ^= decrypted_packet[pn_offset + i];
    }
    size_t payload_offset = pn_offset + pn_length;
    size_t payload_len = get_varint(&payload_length_size, &decrypted_packet[payload_length_offset]) - pn_length;
    if (payload_len > decrypted_packet.size() - payload_offset) {
        return std::nullopt;
    }
    size_t max_overhead = 0;
    if (!decrypt_quic_payload(decrypted_packet.data() + payload_offset, payload_key.data(),
                initial_packet.data() + payload_offset, payload_len, payload_iv.data(), decrypted_packet.data(),
                payload_offset, &max_overhead)) {
        return std::nullopt;
    }
    // decrypted packet size
    size_t decrypted_size = decrypted_packet.size() - max_overhead;
    // remove info before payload start position
    decrypted_packet.resize(decrypted_size);
    decrypted_packet.erase(decrypted_packet.begin(), decrypted_packet.begin() + payload_offset);
    return decrypted_packet;
}

// get int from array of bytes
static uint64_t get_varint(size_t *length, const uint8_t *buf) {
    uint16_t n16 = 0;
    uint32_t n32 = 0;
    uint64_t n64 = 0;
    *length = (size_t) (1u << (*buf >> 6));

    switch (*length) {
    case 1:
        return *buf;
    case 2:
        memcpy(&n16, buf, 2);
        ((uint8_t *) &n16)[0] &= 0x3f;
        return ntohs(n16);
    case 4:
        memcpy(&n32, buf, 4);
        ((uint8_t *) &n32)[0] &= 0x3f;
        return ntohl(n32);
    case 8:
        memcpy(&n64, buf, 8);
        ((uint8_t *) &n64)[0] &= 0x3f;
        n64 = (uint64_t) ntohl(n64) << (CHAR_BIT * 4) | ntohl(n64 >> (CHAR_BIT * 4));
        return n64;
    }
    return 0;
}

// Return -1 on error
static int64_t read_varint_advance(U8View &b) {
    if (b.empty()) {
        return -1;
    }
    size_t len = (1u << (b[0] >> 6));
    if (len > b.size()) {
        return -1;
    }
    uint64_t v = get_varint(&len, b.data());
    b.remove_prefix(len);
    return (int64_t) v; // Safe, as varint is at most 62 bits long
}

std::optional<std::vector<uint8_t>> quic_utils::reassemble_initial_crypto_frames(U8View payload) {
    std::vector<uint8_t> ret;
    ret.reserve(payload.size());
    struct Link {
        int64_t offset;
        U8View data;

        explicit Link(int64_t offset, const uint8_t *data, size_t len) noexcept
                : offset{offset}
                , data{data, len} {
        }

        bool operator<(const Link &r) const noexcept {
            return offset < r.offset;
        }
    };
    std::set<Link> fragments;
    int64_t type = 0;
    while ((type = read_varint_advance(payload)) >= 0) {
        switch (type) {
        case 0x00: // PADDING
        case 0x01: // PING
            continue;
        case 0x06: { // CRYPTO
            int64_t offset = read_varint_advance(payload);
            if (offset < 0) {
                return std::nullopt;
            }
            int64_t len = read_varint_advance(payload);
            if (len < 0 || (size_t) len > payload.size()) {
                return std::nullopt;
            }
            fragments.emplace(offset, payload.data(), len);
            payload.remove_prefix((size_t) len);
            continue;
        }
        default:
            // Unexpected frame, can't decode the rest
            goto loop_exit;
        }
    }
loop_exit:
    // no crypto frames were found
    if (fragments.empty()) {
        return std::nullopt;
    }
    for (const auto &[_, data] : fragments) {
        ret.insert(ret.end(), data.begin(), data.end());
    }
    return ret;
}

std::optional<quic_utils::QuicPacketHeader> quic_utils::parse_quic_header(U8View initial_packet) {
    if (initial_packet.empty()) {
        return std::nullopt;
    }

    ag::quic_utils::QuicPacketHeader hd;
    // Extract data needed for decryption of initial packet
    int parsing_result = quiche_header_info(initial_packet.data(), initial_packet.size(), QUIC_MAX_CONN_ID_LEN,
            &hd.version, &hd.type, hd.scid.data(), &hd.scid_len, hd.dcid.data(), &hd.dcid_len, hd.token.data(),
            &hd.token_len);
    if (parsing_result != 0) {
        return std::nullopt;
    }
    dbglog(log, "QUIC Packet type = {}", magic_enum::enum_name(quic_utils::QuicPacketType(hd.type)));
    return hd;
}

std::optional<std::vector<uint8_t>> quic_utils::prepare_for_domain_lookup(
        U8View initial_packet, const quic_utils::QuicPacketHeader &hd) {
    auto payload = ag::quic_utils::decrypt_initial(initial_packet, hd);
    if (!payload.has_value()) {
        return std::nullopt;
    }
    auto crypto_frames = ag::quic_utils::reassemble_initial_crypto_frames({payload->data(), payload->size()});
    if (!crypto_frames.has_value()) {
        dbglog(log, "QUIC unable to reassemble crypto frames");
    }
    return crypto_frames;
}

} // namespace ag
