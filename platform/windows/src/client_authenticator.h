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
    AuthenticodeSignature() = default;

    AuthenticodeSignature(int32_t status, std::vector<std::string> signer_thumbprints)
            : m_status{status}
            , m_signer_thumbprints{std::move(signer_thumbprints)} {
    }

    /** Verify `path` and collect the leaf thumbprints of all of its signers. */
    static AuthenticodeSignature of_file(const std::wstring &path);

    /** `WinVerifyTrust` status: `0` (`S_OK`) when the signature is intact and the chain is trusted. */
    int32_t status() const {
        return m_status;
    }

    bool has_signer() const {
        return !m_signer_thumbprints.empty();
    }

    const std::vector<std::string> &signer_thumbprints() const {
        return m_signer_thumbprints;
    }

private:
    int32_t m_status = 0;
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
 * Authenticode certificate pin: the lowercase SHA-256 thumbprint of a signer leaf certificate.
 * An absent pin (`std::nullopt`) disables certificate pinning, leaving the always-on sibling-path
 * gate as the only check; a present but malformed pin can never match a signer and therefore
 * rejects every client.
 */
class CertificatePin {
public:
    /** Parse a pin from the service command line (`argv[4]`); `std::nullopt` when it is empty. */
    static std::optional<CertificatePin> parse(std::wstring_view value);

    const std::string &value() const {
        return m_value;
    }

    bool matches(std::string_view thumbprint) const {
        return m_value == thumbprint;
    }

private:
    explicit CertificatePin(std::string value)
            : m_value{std::move(value)} {
    }

    std::string m_value;
};

/**
 * Report whether the directory containing each of the two paths is the same. The comparison is
 * lexical: case-insensitive, separator-normalizing, and ignoring trailing separators. No
 * file-system access is performed and no symlinks or junctions are resolved: the path itself is
 * the credential.
 */
bool is_same_directory(std::wstring_view first, std::wstring_view second);

/** Decides whether a verified Authenticode signature is authorized by a certificate pin. */
class ClientValidationPolicy {
public:
    explicit ClientValidationPolicy(CertificatePin pin)
            : m_pin{std::move(pin)} {
    }

    /**
     * An intact signature whose chain is not trusted (e.g. a self-signed dev certificate) is
     * authorized when a signer matches.
     */
    ClientValidationDecision decide(const AuthenticodeSignature &signature) const;

private:
    CertificatePin m_pin;
};

/** Connect-time authentication of the process holding an accepted pipe connection. */
class ClientAuthenticator {
public:
    /**
     * @param pin          Certificate pin to enforce. `std::nullopt` enables pinless mode: every
     *                     client whose executable lives in the service's own directory is accepted.
     * @param service_info The service's own process info, or `std::nullopt` when it could not be
     *                     resolved, which rejects every client.
     */
    explicit ClientAuthenticator(std::optional<CertificatePin> pin, std::optional<ProcessInfo> service_info);

    /** Validate the process at the other end of `pipe`. */
    ClientValidationDecision validate(HANDLE pipe) const;

private:
    std::optional<ProcessInfo> m_service_info;
    std::optional<ClientValidationPolicy> m_policy;
};

} // namespace ag::trusttunnel_windows
