#include "client_authenticator.h"

#include <filesystem>
#include <set>
#include <utility>

#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

#include "common/logger.h"
#include "process_info.h"
#include "vpn/utils.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"CLIENT_AUTH"};

static constexpr size_t SHA256_LENGTH = 32;

bool is_same_directory(std::wstring_view first, std::wstring_view second) {
    std::wstring first_dir = std::filesystem::path{first}.parent_path().generic_wstring();
    std::wstring second_dir = std::filesystem::path{second}.parent_path().generic_wstring();
    return CompareStringOrdinal(first_dir.c_str(), static_cast<int>(first_dir.size()), second_dir.c_str(),
                   static_cast<int>(second_dir.size()), TRUE)
            == CSTR_EQUAL;
}

static std::string sha256_thumbprint(PCCERT_CONTEXT cert) {
    BYTE digest[SHA256_LENGTH];
    DWORD digest_size = sizeof(digest);
    if (!CertGetCertificateContextProperty(cert, CERT_SHA256_HASH_PROP_ID, digest, &digest_size)) {
        return {};
    }
    return ag::encode_to_hex({digest, digest_size});
}

/// Report whether the mapped image of the calling process has a non-empty security directory.
static bool has_embedded_signature() {
    // The loader has validated the headers of the mapped executable.
    const auto *base = reinterpret_cast<const uint8_t *>(GetModuleHandleW(nullptr));
    const auto *dos_header = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    const auto *nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos_header->e_lfanew);
    const IMAGE_DATA_DIRECTORY &security = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    return security.VirtualAddress != 0 && security.Size != 0;
}

/// Report whether two signer leaf sets are equal, ignoring order and duplicates.
static bool is_same_signer_set(const std::vector<std::string> &first, const std::vector<std::string> &second) {
    return std::set<std::string>(first.begin(), first.end()) == std::set<std::string>(second.begin(), second.end());
}

AuthenticodeSignature AuthenticodeSignature::of_file(const std::wstring &path) {
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
    // Offline verification: the leaf comparison supersedes revocation and chain trust anyway.
    trust_data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    auto status = static_cast<int32_t>(WinVerifyTrust(nullptr, &action, &trust_data));

    // The provider state is available for any intact signature, including one whose chain is not
    // trusted, so it is queried regardless of the verification status.
    std::vector<std::string> signer_thumbprints;
    if (trust_data.hWVTStateData != nullptr) {
        if (CRYPT_PROVIDER_DATA *provider = WTHelperProvDataFromStateData(trust_data.hWVTStateData)) {
            for (DWORD i = 0; i < provider->csSigners; ++i) {
                CRYPT_PROVIDER_SGNR *signer = WTHelperGetProvSignerFromChain(provider, i, FALSE, 0);
                if (signer == nullptr || signer->csCertChain == 0) {
                    continue;
                }
                CRYPT_PROVIDER_CERT *cert = WTHelperGetProvCertFromChain(signer, 0);
                if (cert == nullptr || cert->pCert == nullptr) {
                    continue;
                }
                std::string thumbprint = sha256_thumbprint(cert->pCert);
                if (!thumbprint.empty()) {
                    signer_thumbprints.push_back(std::move(thumbprint));
                }
            }
        }
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &trust_data);
    }

    return AuthenticodeSignature{status, std::move(signer_thumbprints)};
}

std::optional<AuthenticodeSignature> AuthenticodeSignature::of_current_process() {
    // `WinVerifyTrust` also reports `TRUST_E_NOSIGNATURE` for an unreadable file, so it cannot tell unsigned.
    if (!has_embedded_signature()) {
        return std::nullopt;
    }
    std::optional<ProcessInfo> process = ProcessInfo::current();
    if (!process.has_value()) {
        return AuthenticodeSignature{TRUST_E_SYSTEM_ERROR, {}};
    }
    return of_file(process->image_path());
}

bool AuthenticodeSignature::is_valid() const {
    switch (m_status) {
    case S_OK:
    case CERT_E_UNTRUSTEDROOT:
    case CERT_E_CHAINING:
    case CERT_E_EXPIRED:
        return !m_signer_thumbprints.empty();
    default:
        return false;
    }
}

ClientValidationDecision match_signatures(
        const AuthenticodeSignature &service_signature, const AuthenticodeSignature &client_signature) {
    if (!service_signature.is_valid()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    if (client_signature.status() == TRUST_E_NOSIGNATURE) {
        return ClientValidationDecision::NO_SIGNATURE;
    }
    if (client_signature.status() == TRUST_E_BAD_DIGEST) {
        return ClientValidationDecision::BAD_DIGEST;
    }
    if (!client_signature.is_valid()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    if (!is_same_signer_set(service_signature.signer_thumbprints(), client_signature.signer_thumbprints())) {
        return ClientValidationDecision::NO_MATCHING_SIGNER;
    }
    return ClientValidationDecision::ALLOWED;
}

ClientAuthenticator::ClientAuthenticator(
        std::optional<ProcessInfo> service_info, std::optional<AuthenticodeSignature> service_signature)
        : m_service_info{std::move(service_info)}
        , m_service_signature{std::move(service_signature)} {
    if (!m_service_info.has_value()) {
        warnlog(g_logger, "The service's own process info is unresolved; every client will be rejected");
    } else if (!m_service_signature.has_value()) {
        warnlog(g_logger, "The service is unsigned; clients are checked by the sibling path only");
    } else if (!m_service_signature->is_valid()) {
        errlog(g_logger, "The service's own signature is invalid; every client will be rejected");
    } else {
        infolog(g_logger, "The service is signed; clients must be signed with the same certificate");
    }
}

ClientValidationDecision ClientAuthenticator::validate(HANDLE pipe) const {
    if (!m_service_info.has_value()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    std::optional<ProcessInfo> client = ProcessInfo::from_pipe(pipe);
    if (!client.has_value()) {
        return ClientValidationDecision::VERIFICATION_FAILURE;
    }
    if (!is_same_directory(client->image_path(), m_service_info->image_path())) {
        return ClientValidationDecision::SIBLING_PATH_MISMATCH;
    }
    if (!m_service_signature.has_value()) {
        return ClientValidationDecision::ALLOWED;
    }
    return match_signatures(*m_service_signature, AuthenticodeSignature::of_file(client->image_path()));
}

} // namespace ag::trusttunnel_windows
