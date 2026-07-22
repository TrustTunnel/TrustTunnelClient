#include <gtest/gtest.h>

#include <cstdint>
#include <list>
#include <string>
#include <utility>
#include <vector>

#include "common/defs.h"
#include "common/socket_address.h"
#include "net/quic_utils.h"
#include "net/utils.h"
#include "vpn/utils.h"

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

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
static std::list<std::vector<uint8_t>> prepare_quic_initials_ngtcp2(const char *sni);

struct TestDatum {
    std::string sni;
    std::vector<std::string> allowed_fingerprints;
};

// Fingerprint: Chrome 150.0.7871.129 (Official Build) (arm64), source: Wireshark.
static const TestDatum TEST_DATA_TCP[] = {
        {"example.org", {"t13d1516h2_8daaf6152771_806a8c22fdea"}},
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

// Capture TLS handshake bytes from BoringSSL QUIC callbacks
struct QuicCapture {
    std::vector<uint8_t> initial_data;
};

static int capture_set_read_secret(SSL *, ssl_encryption_level_t, const SSL_CIPHER *, const uint8_t *, size_t) {
    return 1;
}
static int capture_set_write_secret(SSL *, ssl_encryption_level_t, const SSL_CIPHER *, const uint8_t *, size_t) {
    return 1;
}
static int capture_add_handshake_data(SSL *ssl, ssl_encryption_level_t level, const uint8_t *data, size_t len) {
    if (level == ssl_encryption_initial) {
        auto *cap = static_cast<QuicCapture *>(SSL_get_app_data(ssl));
        if (cap) {
            cap->initial_data.insert(cap->initial_data.end(), data, data + len);
        }
    }
    return 1;
}
static int capture_flush_flight(SSL *) {
    return 1;
}
static int capture_send_alert(SSL *, ssl_encryption_level_t, uint8_t) {
    return 1;
}
static const SSL_QUIC_METHOD g_capture_quic_method = {
        .set_read_secret = capture_set_read_secret,
        .set_write_secret = capture_set_write_secret,
        .add_handshake_data = capture_add_handshake_data,
        .flush_flight = capture_flush_flight,
        .send_alert = capture_send_alert,
};

// Measures raw TLS ClientHello bytes produced by make_ssl(MSPT_NGTCP2) + PQ groups
// to diagnose why the ngtcp2 path generates a different ClientHello than Quiche.
TEST(NetUtils, JA4Ngtcp2Quic) {
    ag::vpn_post_quantum_group_set_enabled(true);
    for (const auto &[sni, fingerprints] : TEST_DATA_QUIC) {
        auto initials = prepare_quic_initials_ngtcp2(sni.c_str());
        std::vector<uint8_t> handshake;
        for (const std::vector<uint8_t> &initial : initials) {
            auto header = ag::quic_utils::parse_quic_header({initial.data(), initial.size()});
            ASSERT_TRUE(header);
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            auto decrypted = ag::quic_utils::decrypt_initial({initial.data(), initial.size()}, *header);
            ASSERT_TRUE(decrypted);
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            auto reassembled = ag::quic_utils::reassemble_initial_crypto_frames({decrypted->data(), decrypted->size()});
            ASSERT_TRUE(reassembled);
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            handshake.insert(handshake.end(), reassembled->begin(), reassembled->end());
        }
        auto fingerprint = ag::ja4::compute({handshake.data(), handshake.size()}, /*quic*/ true);
        ASSERT_NE(fingerprints.end(), std::find(fingerprints.begin(), fingerprints.end(), fingerprint)) << fingerprint;
    }
}

TEST(NetUtils, JA4Ngtcp2ClientHelloSize) {
    ag::vpn_post_quantum_group_set_enabled(true);
    static constexpr uint8_t H3_ALPN[] = {2, 'h', '3'};
    auto r = ag::make_ssl(nullptr, nullptr, {H3_ALPN, std::size(H3_ALPN)}, "example.org", ag::MSPT_NGTCP2);
    ASSERT_TRUE(std::holds_alternative<ag::SslPtr>(r)) << "make_ssl(MSPT_NGTCP2) failed";
    auto &ssl = std::get<ag::SslPtr>(r);

    QuicCapture capture;
    SSL_set_app_data(ssl.get(), &capture);
    ASSERT_EQ(1, SSL_set_quic_method(ssl.get(), &g_capture_quic_method));
    // Minimal transport params so BoringSSL includes quic_transport_params extension
    static constexpr uint8_t kDummyParams[] = {0x00};
    ASSERT_EQ(1, SSL_set_quic_transport_params(ssl.get(), kDummyParams, sizeof(kDummyParams)));

    // Trigger ClientHello generation; returns SSL_ERROR_WANT_READ waiting for server
    SSL_do_handshake(ssl.get());

    ASSERT_FALSE(capture.initial_data.empty()) << "No TLS data was captured";

    auto fingerprint = ag::ja4::compute({capture.initial_data.data(), capture.initial_data.size()}, /*quic*/ true);
    // Expected to match Chrome 135 QUIC fingerprint, same as JA4Quic test
    EXPECT_EQ("q13d0311h3_55b375c5d22e_653d80c3fe9d", fingerprint) << "Ngtcp2 fingerprint mismatch";
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

// ngtcp2_crypto_conn_ref glue: allows BoringSSL QUIC callbacks to reach ngtcp2_conn
struct Ngtcp2TestCtx {
    ngtcp2_crypto_conn_ref conn_ref;
    ngtcp2_conn *conn = nullptr;
};

std::list<std::vector<uint8_t>> prepare_quic_initials_ngtcp2(const char *sni) {
    static constexpr uint8_t H3_ALPN[] = {2, 'h', '3'};
    auto r = ag::make_ssl(nullptr, nullptr, {H3_ALPN, std::size(H3_ALPN)}, sni, ag::MSPT_NGTCP2);
    assert(std::holds_alternative<ag::SslPtr>(r));
    ag::SslPtr ssl = std::move(std::get<ag::SslPtr>(r));

    Ngtcp2TestCtx ctx;
    ctx.conn_ref.get_conn = [](ngtcp2_crypto_conn_ref *ref) {
        return static_cast<Ngtcp2TestCtx *>(ref->user_data)->conn;
    };
    ctx.conn_ref.user_data = &ctx;
    // ngtcp2 crypto callbacks require SSL_get_app_data to return ngtcp2_crypto_conn_ref*
    SSL_set_app_data(ssl.get(), &ctx.conn_ref);

    ngtcp2_callbacks callbacks{};
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
    callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
    callbacks.rand = [](uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
        RAND_bytes(dest, (int) destlen);
    };
    callbacks.get_new_connection_id = [](ngtcp2_conn *, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *) -> int {
        cid->datalen = cidlen;
        RAND_bytes(cid->data, (int) cidlen);
        RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
        return 0;
    };

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_pkt_num = 1;
    settings.initial_ts = 1;

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_stream_data_uni = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 3;

    ag::SocketAddress local{"0.0.0.0", 0};
    ag::SocketAddress remote{"0.0.0.0", 443};
    ngtcp2_path path{
            .local = {.addr = (sockaddr *) local.c_sockaddr(), .addrlen = local.c_socklen()},
            .remote = {.addr = (sockaddr *) remote.c_sockaddr(), .addrlen = remote.c_socklen()},
    };

    uint8_t dcid_buf[NGTCP2_MAX_CIDLEN];
    uint8_t scid_buf[NGTCP2_MAX_CIDLEN];
    RAND_bytes(dcid_buf, sizeof(dcid_buf));
    RAND_bytes(scid_buf, sizeof(scid_buf));
    ngtcp2_cid dcid;
    ngtcp2_cid scid;
    ngtcp2_cid_init(&dcid, dcid_buf, sizeof(dcid_buf));
    ngtcp2_cid_init(&scid, scid_buf, sizeof(scid_buf));

    ngtcp2_conn *conn_ptr = nullptr;
    [[maybe_unused]] int rv = ngtcp2_conn_client_new(
            &conn_ptr, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, nullptr, &ctx);
    assert(rv == 0 && conn_ptr != nullptr);
    ag::DeclPtr<ngtcp2_conn, &ngtcp2_conn_del> conn{conn_ptr};
    ctx.conn = conn_ptr;

    ngtcp2_conn_set_tls_native_handle(conn.get(), ssl.get());

    std::list<std::vector<uint8_t>> initials;
    ngtcp2_pkt_info pi{};
    for (;;) {
        std::vector<uint8_t> &pkt = initials.emplace_back();
        pkt.resize(UINT16_MAX);
        ngtcp2_ssize ret = ngtcp2_conn_write_pkt(conn.get(), nullptr, &pi, pkt.data(), pkt.size(), settings.initial_ts);
        assert(ret >= 0);
        if (ret == 0) {
            initials.pop_back();
            break;
        }
        pkt.resize((size_t) ret);
        // Skip non-Initial long-header packets (type bits [5:4] != 0)
        if ((pkt[0] & 0x30) != 0x00) {
            initials.pop_back();
        }
    }
    return initials;
}
