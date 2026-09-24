#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "process_info.h"

namespace ag::trusttunnel_windows {

/** Result of verifying an executable's Authenticode signature. */
class AuthenticodeSignature {
public:
    AuthenticodeSignature(int32_t status, std::vector<std::string> signer_thumbprints)
            : m_status{status}
            , m_signer_thumbprints{std::move(signer_thumbprints)} {
    }

    /** Verify `path` and collect the lowercase SHA-256 leaf thumbprints of all of its signers. */
    static AuthenticodeSignature of_file(const std::wstring &path);

    /**
     * Verify the executable of the calling process. `std::nullopt` when its mapped image has an
     * empty `IMAGE_DIRECTORY_ENTRY_SECURITY` entry, i.e. the image is unsigned.
     */
    static std::optional<AuthenticodeSignature> of_current_process();

    /** `WinVerifyTrust` status: `0` (`S_OK`) when the signature is intact and the chain is trusted. */
    int32_t status() const {
        return m_status;
    }

    /**
     * Report whether `WinVerifyTrust` returned `S_OK`, `CERT_E_UNTRUSTEDROOT`, `CERT_E_CHAINING`, or
     * `CERT_E_EXPIRED`, and at least one signer leaf was recovered.
     */
    bool is_valid() const;

    const std::vector<std::string> &signer_thumbprints() const {
        return m_signer_thumbprints;
    }

private:
    int32_t m_status;
    std::vector<std::string> m_signer_thumbprints;
};

/** Verdict for one accepted client connection. */
enum class ClientValidationDecision {
    ALLOWED,
    /** The client's executable is not in the service's own directory. */
    SIBLING_PATH_MISMATCH,
    NO_SIGNATURE,
    BAD_DIGEST,
    NO_MATCHING_SIGNER,
    VERIFICATION_FAILURE,
};

/**
 * Report whether the directory containing each of the two paths is the same. The comparison is
 * lexical: case-insensitive, separator-normalizing, and ignoring trailing separators. No
 * file-system access is performed and no symlinks or junctions are resolved: the path itself is
 * the credential.
 */
bool is_same_directory(std::wstring_view first, std::wstring_view second);

/**
 * Decide whether a signed service authorizes a client by their signatures: both must be valid and
 * their signer leaf sets equal, ignoring order and duplicates. Chain trust is irrelevant.
 */
ClientValidationDecision match_signatures(
        const AuthenticodeSignature &service_signature, const AuthenticodeSignature &client_signature);

/** Connect-time authentication of the process holding an accepted pipe connection. */
class ClientAuthenticator {
public:
    /**
     * @param service_info      The service's own process info; `std::nullopt` rejects every client.
     * @param service_signature The service's own signature; `std::nullopt` when the service is
     *                          unsigned, which leaves the sibling-path gate as the only check.
     */
    ClientAuthenticator(
            std::optional<ProcessInfo> service_info, std::optional<AuthenticodeSignature> service_signature);

    /** Validate the process at the other end of `pipe`. */
    ClientValidationDecision validate(HANDLE pipe) const;

private:
    std::optional<ProcessInfo> m_service_info;
    std::optional<AuthenticodeSignature> m_service_signature;
};

} // namespace ag::trusttunnel_windows
