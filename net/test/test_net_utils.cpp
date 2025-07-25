#include <gtest/gtest.h>

#include <cstdint>
#include <list>
#include <string>
#include <utility>
#include <vector>

#include "common/defs.h"
#include "net/quic_utils.h"
#include "net/utils.h"
#include "vpn/utils.h"

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <quiche.h>

#include "ja4.h"

#ifdef _WIN32

TEST(NetUtils, RetrieveSystemDnsServers) {
    WSADATA wsa_data;
    ASSERT_EQ(0, WSAStartup(MAKEWORD(2, 2), &wsa_data));

    uint32_t iface = ag::vpn_win_detect_active_if();
    ASSERT_NE(iface, 0);

    auto result = ag::retrieve_interface_dns_servers(iface);
    ASSERT_FALSE(result.has_error()) << result.error()->str();
    ASSERT_FALSE(result.value().main.empty());
    ASSERT_TRUE(ag::SocketAddress{result.value().main.front().address}.valid());
}

#endif // _WIN32

static std::vector<uint8_t> prepare_client_hello(const char *sni);
static std::list<std::vector<uint8_t>> prepare_quic_initials(const char *sni);

struct TestDatum {
    std::string sni;
    std::vector<std::string> allowed_fingerprints;
};

// Fingerprint: Version 135.0.7049.85 (Official Build) (arm64), source: Wireshark.
static const TestDatum TEST_DATA_TCP[] = {
        {"example.org", {"t13d1516h2_8daaf6152771_d8a2da3f94cd"}},
};

// Fingerprint: Version 135.0.7049.85 (Official Build) (arm64), source: Wireshark.
static const TestDatum TEST_DATA_QUIC[] = {
        {"example.org", {"q13d0311h3_55b375c5d22e_653d80c3fe9d"}},
};

TEST(NetUtils, JA4Tcp) {
    ag::vpn_post_quantum_group_set_enabled(true);
    for (const auto &[sni, fingerprints] : TEST_DATA_TCP) {
        auto client_hello = prepare_client_hello(sni.c_str());
        auto fingerprint = ag::ja4::compute({client_hello.data(), client_hello.size()}, /*quic*/ false);
        ASSERT_NE(fingerprints.end(), std::find(fingerprints.begin(), fingerprints.end(), fingerprint)) << fingerprint;
    }
}

TEST(NetUtils, JA4Quic) {
    ag::vpn_post_quantum_group_set_enabled(true);
    for (const auto &[sni, fingerprints] : TEST_DATA_QUIC) {
        auto initials = prepare_quic_initials(sni.c_str());
        std::vector<uint8_t> handshake;
        for (const std::vector<uint8_t> &initial : initials) {
            auto header = ag::quic_utils::parse_quic_header({initial.data(), initial.size()});
            ASSERT_TRUE(header);
            auto decrypted = ag::quic_utils::decrypt_initial({initial.data(), initial.size()}, *header);
            ASSERT_TRUE(decrypted);
            auto reassembled = ag::quic_utils::reassemble_initial_crypto_frames({decrypted->data(), decrypted->size()});
            ASSERT_TRUE(reassembled);
            handshake.insert(handshake.end(), reassembled->begin(), reassembled->end());
        }
        auto fingerprint = ag::ja4::compute({handshake.data(), handshake.size()}, /*quic*/ true);
        ASSERT_NE(fingerprints.end(), std::find(fingerprints.begin(), fingerprints.end(), fingerprint)) << fingerprint;
    }
}

std::vector<uint8_t> prepare_client_hello(const char *sni) {
    static constexpr uint8_t HTTP2_ALPN[] = {2, 'h', '2'};
    ag::SslPtr ssl;
    auto r = ag::make_ssl(nullptr, nullptr, {HTTP2_ALPN, std::size(HTTP2_ALPN)}, sni, ag::MSPT_TLS);
    assert(std::holds_alternative<ag::SslPtr>(r));
    ssl = std::move(std::get<ag::SslPtr>(r));
    SSL_set0_wbio(ssl.get(), BIO_new(BIO_s_mem()));
    SSL_connect(ssl.get());
    std::vector<uint8_t> initial;
    initial.resize(UINT16_MAX);
    auto ret = BIO_read(SSL_get_wbio(ssl.get()), initial.data(), (int) initial.size());
    assert(ret > 0);
    initial.resize(ret);
    return initial;
}

std::list<std::vector<uint8_t>> prepare_quic_initials(const char *sni) {
    static constexpr uint8_t H3_ALPN[] = {2, 'h', '3'};
    ag::SslPtr ssl;
    auto r = ag::make_ssl(nullptr, nullptr, {H3_ALPN, std::size(H3_ALPN)}, sni, ag::MSPT_QUICHE);
    assert(std::holds_alternative<ag::SslPtr>(r));
    ssl = std::move(std::get<ag::SslPtr>(r));
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    RAND_bytes(scid, sizeof(scid));
    sockaddr_storage dummy_address{.ss_family = AF_INET};
    ag::DeclPtr<quiche_config, &quiche_config_free> config{quiche_config_new(QUICHE_PROTOCOL_VERSION)};
    quiche_config_set_max_recv_udp_payload_size(config.get(), UINT16_MAX);
    quiche_config_set_max_send_udp_payload_size(config.get(), UINT16_MAX);
    // clang-format off
    ag::DeclPtr<quiche_conn, &quiche_conn_free> qconn{quiche_conn_new_with_tls(
            scid, sizeof(scid), RUST_EMPTY, 0,
            (sockaddr *) &dummy_address, ag::sockaddr_get_size((sockaddr *) &dummy_address),
            (sockaddr *) &dummy_address, ag::sockaddr_get_size((sockaddr *) &dummy_address),
            config.get(), ssl.release(), false)};
    // clang-format on
    std::list<std::vector<uint8_t>> initials;
    quiche_send_info info{};
    for (;;) {
        std::vector<uint8_t> &initial = initials.emplace_back();
        initial.resize(UINT16_MAX);
        ssize_t ret = quiche_conn_send(qconn.get(), initial.data(), initial.size(), &info);
        assert(ret == QUICHE_ERR_DONE || ret > 0);
        if (ret == QUICHE_ERR_DONE) {
            initials.pop_back();
            break;
        }
    }
    return initials;
}
