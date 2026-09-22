#include "client_authenticator.h"

#include <filesystem>
#include <utility>

#include <softpub.h>
#include <stringapiset.h>
#include <wincrypt.h>
#include <wintrust.h>

#include "common/logger.h"
#include "common/system_error.h"
#include "process_info.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"CLIENT_AUTH"};

static constexpr size_t PIN_HEX_LENGTH = 64;
static constexpr size_t SHA256_LENGTH = 32;

static bool is_hex_digit(wchar_t c) {
    return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
}

static wchar_t to_ascii_lower(wchar_t c) {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

static std::string sha256_hex(const BYTE *data, DWORD size) {
    BYTE digest[SHA256_LENGTH];
    DWORD digest_size = sizeof(digest);
    if (!CryptHashCertificate(0, CALG_SHA_256, 0, data, size, digest, &digest_size)) {
        return {};
    }
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest_size * 2);
    for (DWORD i = 0; i < digest_size; ++i) {
        out.push_back(HEX_DIGITS[digest[i] >> 4]);
        out.push_back(HEX_DIGITS[digest[i] & 0xF]);
    }
    return out;
}

bool is_same_directory(std::wstring_view first, std::wstring_view second) {
    std::wstring first_dir = std::filesystem::path{first}.parent_path().generic_wstring();
    std::wstring second_dir = std::filesystem::path{second}.parent_path().generic_wstring();
    return CompareStringOrdinal(first_dir.c_str(), static_cast<int>(first_dir.size()), second_dir.c_str(),
                   static_cast<int>(second_dir.size()), TRUE)
            == CSTR_EQUAL;
}

AuthenticodeSignature AuthenticodeSignature::of_file(const std::wstring &path) {
    AuthenticodeSignature signature;

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    // Offline verification: a pinned thumbprint supersedes revocation and chain trust anyway.
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    signature.m_status = static_cast<int32_t>(WinVerifyTrust(nullptr, &action, &trust_data));

    // The provider state is available for any intact signature, including one whose chain is not
    // trusted, so it is queried regardless of the verification status.
    if (trust_data.hWVTStateData != nullptr) {
        if (CRYPT_PROVIDER_DATA *provider = WTHelperProvDataFromStateData(trust_data.hWVTStateData)) {
            for (DWORD i = 0; i < provider->csSigners; ++i) {
                CRYPT_PROVIDER_SGNR *signer = WTHelperGetProvSignerFromChain(provider, i, FALSE, 0);
                if (signer == nullptr || signer->csCertChain == 0) {
                    continue;
                }
                CRYPT_PROVIDER_CERT *cert = WTHelperGetProvCertFromChain(signer, 0);
                if (cert == nullptr || cert->pCert == nullptr || cert->pCert->pbCertEncoded == nullptr) {
                    continue;
                }
                std::string thumbprint = sha256_hex(cert->pCert->pbCertEncoded, cert->pCert->cbCertEncoded);
                if (!thumbprint.empty()) {
                    signature.m_signer_thumbprints.push_back(std::move(thumbprint));
                }
            }
        }
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &trust_data);
    }

    return signature;
}

std::optional<CertificatePin> CertificatePin::parse(std::wstring_view value) {
    if (value.empty()) {
        return std::nullopt;
    }
    std::string normalized;
    normalized.reserve(value.size());
    bool well_formed = value.size() == PIN_HEX_LENGTH;
    for (wchar_t c : value) {
        well_formed = well_formed && is_hex_digit(c);
        normalized.push_back(static_cast<char>(to_ascii_lower(c)));
    }
    if (!well_formed) {
        warnlog(g_logger, "Pin is not a 64-character SHA-256 hex digest; every client will be rejected");
    }
    return CertificatePin{std::move(normalized)};
}

ClientValidationDecision ClientValidationPolicy::decide(const AuthenticodeSignature &signature) const {
    if (signature.status() == TRUST_E_NOSIGNATURE) {
        return ClientValidationDecision::NO_SIGNATURE;
    }
    if (signature.status() == TRUST_E_BAD_DIGEST) {
        return ClientValidationDecision::BAD_DIGEST;
    }
    // Any other status may still leave signer certificates recoverable (an untrusted chain is the
    // expected case for self-signed dev certificates). When it does not, the machinery failed.
    if (!signature.has_signer()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    for (const std::string &thumbprint : signature.signer_thumbprints()) {
        if (m_pin.matches(thumbprint)) {
            return ClientValidationDecision::ALLOWED;
        }
    }
    return ClientValidationDecision::NO_MATCHING_SIGNER;
}

ClientAuthenticator::ClientAuthenticator(std::optional<CertificatePin> pin, std::optional<ProcessInfo> service_info)
        : m_service_info{std::move(service_info)} {
    if (pin.has_value()) {
        m_policy.emplace(std::move(*pin));
    }
    if (!m_service_info.has_value()) {
        warnlog(g_logger, "The service's own process info is unresolved; every client will be rejected");
    }
}

ClientValidationDecision ClientAuthenticator::validate(HANDLE pipe) const {
    std::optional<ProcessInfo> process = ProcessInfo::from_pipe(pipe);
    if (!process.has_value()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    if (!m_service_info.has_value()) {
        // The service's own process info could not be resolved, so no client can be a sibling.
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    // The sibling gate is always active, pin or no pin: the path is the credential, so it needs
    // no provisioning and no file to verify after the fact.
    if (!is_same_directory(process->image_path(), m_service_info->image_path())) {
        return ClientValidationDecision::SIBLING_PATH_MISMATCH;
    }
    if (!m_policy.has_value()) {
        // Pinless mode: the sibling gate alone decides, and no signature is computed.
        return ClientValidationDecision::ALLOWED;
    }
    return m_policy->decide(AuthenticodeSignature::of_file(process->image_path()));
}

} // namespace ag::trusttunnel_windows
