#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "net/tls.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static RSA *gen_rsa(int bits) {
    RSA *rsa = RSA_new();
    if (!rsa) {
        return nullptr;
    }
    BIGNUM *e = BN_new();
    if (!e) {
        RSA_free(rsa);
        return nullptr;
    }
    if (!BN_set_word(e, RSA_F4)) {
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    if (!RSA_generate_key_ex(rsa, bits, e, nullptr)) {
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }

    BN_free(e);

    return rsa;
}

X509 *make_cert() {
    ag::DeclPtr<X509, &X509_free> cert(X509_new());
    RSA *rsa = gen_rsa(2048);
    ag::DeclPtr<EVP_PKEY, &EVP_PKEY_free> pkey{EVP_PKEY_new()};
    EVP_PKEY_assign_RSA(pkey.get(), rsa);

    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,
    // cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (!cert || //
            !X509_set_version(cert.get(), X509_VERSION_3)
            || !X509_NAME_add_entry_by_txt(X509_get_issuer_name(cert.get()), "CN", MBSTRING_UTF8,
                    reinterpret_cast<const uint8_t *>("Self-signed cert"), -1, -1, 0)
            || !X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()), "CN", MBSTRING_UTF8,
                    reinterpret_cast<const uint8_t *>("Self-signed cert"), -1, -1, 0)
            || !X509_set_pubkey(cert.get(), pkey.get())
            || !ASN1_TIME_adj(X509_getm_notBefore(cert.get()), 1474934400, -1, 0)
            || !ASN1_TIME_adj(X509_getm_notAfter(cert.get()), 1474934400, 1, 0)) {
        return nullptr;
    }
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast,
    // cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    ag::DeclPtr<BASIC_CONSTRAINTS, &BASIC_CONSTRAINTS_free> bc(BASIC_CONSTRAINTS_new());
    if (!bc) {
        return nullptr;
    }
    bc->ca = true ? 0xff : 0x00; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    if (!X509_add1_ext_i2d(cert.get(), NID_basic_constraints, bc.get(),
                /*crit=*/1, /*flags=*/0)) {
        return nullptr;
    }
    X509_sign(cert.get(), pkey.get(), EVP_sha256());
    return cert.release();
}
#pragma GCC diagnostic pop

TEST(TlsSerialize, CertWorks) {
    X509 *x = make_cert();
    ag::TlsCert *cert = ag::tls_serialize_cert(x);
    ASSERT_TRUE(cert);
    ASSERT_TRUE(cert->data);
    ASSERT_GT(cert->size, 0);
    ag::tls_free_serialized_cert(cert);
    X509_free(x);
}

TEST(TlsSerialize, ChainWorks) {
    static constexpr size_t NUM_CERTS = 10;

    STACK_OF(X509) *c = sk_X509_new_null();
    for (size_t i = 0; i < NUM_CERTS; ++i) {
        sk_X509_push(c, make_cert());
    }

    ag::TlsChain *chain = ag::tls_serialize_cert_chain(c);
    ASSERT_TRUE(chain);
    ASSERT_TRUE(chain->data);
    ASSERT_EQ(chain->size, sk_X509_num(c));
    for (uint32_t i = 0; i < chain->size; ++i) {
        ASSERT_TRUE(chain->data[i].data);
        ASSERT_GT(chain->data[i].size, 0);
    }
    ag::tls_free_serialized_chain(chain);

    sk_X509_pop_free(c, [](X509 *x) {
        X509_free(x);
    });
}
