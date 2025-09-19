#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include "vpn/platform.h"

#include <wincrypt.h>

#include "wincrypt_helper.h"

#include <cstdint>
#include <vector>

#include "common/utils.h"

static std::vector<uint8_t> x509_to_der(X509 *x) {
    std::vector<uint8_t> ret;
    if (int len = i2d_X509(x, nullptr); len > 0) {
        ret.resize(len);
        auto *pdata = ret.data();
        i2d_X509(x, &pdata);
    }
    return ret;
}

static WinCryptValidateError wcrypt_get_store_with_certchain(
        X509 *leaf, STACK_OF(X509) * chain, HCERTSTORE *pstore, const CERT_CONTEXT **primary_cert) {
    HCERTSTORE store = nullptr;
    const CERT_CONTEXT *primary = nullptr;

    ag::utils::ScopeExit e{[&] {
        CertFreeCertificateContext(primary);
        CertCloseStore(store, 0);
    }};

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
    if (nullptr == store) {
        return WCRYPT_E_CERT_OPEN_STORE;
    }

    std::vector<uint8_t> p_data = x509_to_der(leaf);
    const CERT_CONTEXT **p = &primary;
    if (!CertAddEncodedCertificateToStore(
                store, X509_ASN_ENCODING, p_data.data(), p_data.size(), CERT_STORE_ADD_ALWAYS, p)) {
        return WCRYPT_E_CERT_ADD_ENCODED_CERTIFICATE_TO_STORE;
    }

    for (unsigned int i = 0; i != sk_X509_num(chain); i++) {
        X509 *x = sk_X509_value(chain, i);
        std::vector<uint8_t> x_data = x509_to_der(x);
        if (x_data.empty()) {
            return WCRYPT_E_I2D_X509;
        }
        if (!CertAddEncodedCertificateToStore(
                    store, X509_ASN_ENCODING, x_data.data(), x_data.size(), CERT_STORE_ADD_ALWAYS, nullptr)) {
            return WCRYPT_E_CERT_ADD_ENCODED_CERTIFICATE_TO_STORE;
        }
    }

    *primary_cert = std::exchange(primary, nullptr);
    *pstore = std::exchange(store, nullptr);
    return WCRYPT_E_OK;
}

static void wcrypt_prepare_params(CERT_CHAIN_PARA &chain_para, CERT_STRONG_SIGN_PARA &strong_sign_params,
        CERT_STRONG_SIGN_SERIALIZED_INFO &strong_signed_info, wchar_t *hash_algs, wchar_t *min_key_lengths) {
    memset(&chain_para, 0, sizeof(chain_para));
    chain_para.cbSize = sizeof(chain_para);
    static constexpr LPCSTR USAGE[] = {szOID_PKIX_KP_SERVER_AUTH};
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = sizeof(USAGE) / sizeof(*USAGE);
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = const_cast<LPSTR *>(USAGE);

    memset(&strong_signed_info, 0, sizeof(strong_signed_info));
    strong_signed_info.dwFlags = 0; // Don't check OCSP or CRL signatures.
    strong_signed_info.pwszCNGSignHashAlgids = hash_algs;
    strong_signed_info.pwszCNGPubKeyMinBitLengths = min_key_lengths;

    memset(&strong_sign_params, 0, sizeof(strong_sign_params));
    strong_sign_params.cbSize = sizeof(strong_sign_params);
    strong_sign_params.dwInfoChoice = CERT_STRONG_SIGN_SERIALIZED_INFO_CHOICE;
    strong_sign_params.pSerializedInfo = &strong_signed_info;

    chain_para.dwStrongSignFlags = 0;
    chain_para.pStrongSignPara = &strong_sign_params;
}

static WinCryptValidateError wcrypt_check_policy(PCCERT_CHAIN_CONTEXT chain_context) {
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA extra_policy_para;
    memset(&extra_policy_para, 0, sizeof(extra_policy_para));
    extra_policy_para.cbSize = sizeof(extra_policy_para);
    extra_policy_para.dwAuthType = AUTHTYPE_SERVER;
    extra_policy_para.fdwChecks = 0x00001000; // SECURITY_FLAG_IGNORE_CERT_CN_INVALID
    extra_policy_para.pwszServerName = nullptr;

    CERT_CHAIN_POLICY_PARA policy_para;
    memset(&policy_para, 0, sizeof(policy_para));
    policy_para.cbSize = sizeof(policy_para);
    policy_para.dwFlags = 0;
    policy_para.pvExtraPolicyPara = &extra_policy_para;

    CERT_CHAIN_POLICY_STATUS policy_status;
    memset(&policy_status, 0, sizeof(policy_status));
    policy_status.cbSize = sizeof(policy_status);

    if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain_context, &policy_para, &policy_status)) {
        return WCRYPT_E_CERT_VERIFY_CERTIFICATE_CHAIN_POLICY;
    }

    if (policy_status.dwError != 0) {
        return WCRYPT_E_POLICY_STATUS;
    }

    return WCRYPT_E_OK;
}

WinCryptValidateError wcrypt_validate_cert(X509 *leaf, STACK_OF(X509) * chain) {
    HCERTSTORE store = nullptr;
    const CERT_CONTEXT *primary_cert = nullptr;
    PCCERT_CHAIN_CONTEXT chain_context = nullptr;

    ag::utils::ScopeExit e{[&] {
        CertFreeCertificateChain(chain_context);
        CertFreeCertificateContext(primary_cert);
        CertCloseStore(store, 0);
    }};

    if (WinCryptValidateError rc = wcrypt_get_store_with_certchain(leaf, chain, &store, &primary_cert);
            rc != WCRYPT_E_OK) {
        return rc;
    }

    CERT_CHAIN_PARA chain_para;
    CERT_STRONG_SIGN_PARA strong_sign_params;
    CERT_STRONG_SIGN_SERIALIZED_INFO strong_signed_info;

    wchar_t hash_algs[] = L"RSA/SHA256;RSA/SHA384;RSA/SHA512;"
                          L"ECDSA/SHA256;ECDSA/SHA384;ECDSA/SHA512";
    wchar_t min_key_lengths[] = L"RSA/1024;ECDSA/256";
    wcrypt_prepare_params(chain_para, strong_sign_params, strong_signed_info, hash_algs, min_key_lengths);

    DWORD chain_flags = CERT_CHAIN_REVOCATION_CHECK_CHAIN | CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;

    if (!CertGetCertificateChain(
                nullptr, primary_cert, nullptr, store, &chain_para, chain_flags, nullptr, &chain_context)) {
        return WCRYPT_E_CERT_GET_CERTIFICATE_CHAIN;
    }

    DWORD trust_status = chain_context->TrustStatus.dwErrorStatus;
    trust_status &= ~(CERT_TRUST_REVOCATION_STATUS_UNKNOWN | CERT_TRUST_IS_OFFLINE_REVOCATION);

    if (trust_status != 0) {
        return WCRYPT_E_TRUST_STATUS;
    }

    if (WinCryptValidateError rc = wcrypt_check_policy(chain_context); rc != WCRYPT_E_OK) {
        return rc;
    }

    return WCRYPT_E_OK;
}
