#include "client_authenticator.h"

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ag::trusttunnel_windows;

static constexpr std::string_view VALID_PIN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static constexpr std::wstring_view VALID_PIN_W = L"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static constexpr std::wstring_view VALID_PIN_UPPER_W =
        L"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
static constexpr std::string_view OTHER_PIN = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

static AuthenticodeSignature signature_with(std::vector<std::string> thumbprints, int32_t status) {
    return AuthenticodeSignature{status, std::move(thumbprints)};
}

static CertificatePin pin_from(std::wstring_view value) {
    std::optional<CertificatePin> pin = CertificatePin::parse(value);
    EXPECT_TRUE(pin.has_value());
    return pin.value();
}

static ClientValidationPolicy policy_with(std::wstring_view pin) {
    return ClientValidationPolicy{pin_from(pin)};
}

static std::wstring current_module_path() {
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (size == 0) {
            return {};
        }
        if (size < path.size()) {
            path.resize(size);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

TEST(CertificatePin, EmptyValueIsAbsent) {
    EXPECT_FALSE(CertificatePin::parse(L"").has_value());
}

TEST(CertificatePin, LowercaseValueIsParsedAsIs) {
    std::optional<CertificatePin> pin = CertificatePin::parse(VALID_PIN_W);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(pin->value(), VALID_PIN);
}

TEST(CertificatePin, UppercaseValueIsNormalizedToLowercase) {
    std::optional<CertificatePin> pin = CertificatePin::parse(VALID_PIN_UPPER_W);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(pin->value(), VALID_PIN);
}

TEST(CertificatePin, MatchesNormalizedValue) {
    CertificatePin pin = pin_from(VALID_PIN_UPPER_W);
    EXPECT_TRUE(pin.matches(VALID_PIN));
    EXPECT_FALSE(pin.matches(OTHER_PIN));
    EXPECT_FALSE(pin.matches(""));
}

TEST(ClientValidationPolicy, DeniesUnsignedBinary) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({}, TRUST_E_NOSIGNATURE)),
            ClientValidationDecision::NO_SIGNATURE);
}

TEST(ClientValidationPolicy, DeniesBadDigestEvenWithRecoveredSigners) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{VALID_PIN}}, TRUST_E_BAD_DIGEST)),
            ClientValidationDecision::BAD_DIGEST);
}

TEST(ClientValidationPolicy, DeniesMachineryFailure) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({}, TRUST_E_SYSTEM_ERROR)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(ClientValidationPolicy, AllowsMatchingSignerOnTrustedChain) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{VALID_PIN}}, 0)),
            ClientValidationDecision::ALLOWED);
}

TEST(ClientValidationPolicy, AllowsMatchingSignerAmongMany) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{OTHER_PIN}, std::string{VALID_PIN}}, 0)),
            ClientValidationDecision::ALLOWED);
}

TEST(ClientValidationPolicy, AllowsMatchingSignerOnUntrustedChain) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{VALID_PIN}}, CERT_E_UNTRUSTEDROOT)),
            ClientValidationDecision::ALLOWED);
}

TEST(ClientValidationPolicy, AllowsMatchingSignerOnExpiredCertificate) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{VALID_PIN}}, CERT_E_EXPIRED)),
            ClientValidationDecision::ALLOWED);
}

TEST(ClientValidationPolicy, DeniesNonMatchingSigner) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({std::string{OTHER_PIN}}, 0)),
            ClientValidationDecision::NO_MATCHING_SIGNER);
}

TEST(ClientValidationPolicy, DeniesUntrustedChainWithoutRecoveredSigners) {
    EXPECT_EQ(policy_with(VALID_PIN_W).decide(signature_with({}, CERT_E_UNTRUSTEDROOT)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(ClientValidationPolicy, DeniesMalformedPin) {
    // A malformed pin can never equal a thumbprint, so every client is rejected.
    EXPECT_EQ(policy_with(L"not-a-pin").decide(signature_with({std::string{VALID_PIN}}, 0)),
            ClientValidationDecision::NO_MATCHING_SIGNER);
}

TEST(ClientAuthenticator, RejectsUnresolvablePipe) {
    ClientAuthenticator authenticator{pin_from(VALID_PIN_W)};
    EXPECT_EQ(authenticator.validate(nullptr), ClientValidationDecision::VERIFICATION_FAILURE);
}

class ClientAuthenticatorTest : public testing::Test {
protected:
    void SetUp() override {
        static std::atomic<uint64_t> counter{0};
        std::wstring name = L"\\\\.\\pipe\\agvpn_client_auth_test_" + std::to_wstring(GetCurrentProcessId()) + L"_"
                + std::to_wstring(counter.fetch_add(1));
        m_server = CreateNamedPipeW(
                name.c_str(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096, 0, nullptr);
        ASSERT_NE(m_server, INVALID_HANDLE_VALUE);
        m_client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        ASSERT_NE(m_client, INVALID_HANDLE_VALUE);
        if (!ConnectNamedPipe(m_server, nullptr)) {
            ASSERT_EQ(GetLastError(), ERROR_PIPE_CONNECTED);
        }
    }

    void TearDown() override {
        if (m_client != nullptr) {
            CloseHandle(m_client);
            m_client = nullptr;
        }
        if (m_server != INVALID_HANDLE_VALUE) {
            CloseHandle(m_server);
            m_server = INVALID_HANDLE_VALUE;
        }
    }

    HANDLE m_server = INVALID_HANDLE_VALUE;
    HANDLE m_client = nullptr;
};

TEST_F(ClientAuthenticatorTest, ValidatesPipeClientAgainstComputedPin) {
    ClientAuthenticator authenticator{pin_from(VALID_PIN_W)};
    EXPECT_NE(authenticator.validate(m_server), ClientValidationDecision::ALLOWED);

    std::optional<CertificatePin> pin = CertificatePin::from_executable(current_module_path().c_str());
    if (pin.has_value()) {
        ClientAuthenticator self_authenticator{*pin};
        EXPECT_EQ(self_authenticator.validate(m_server), ClientValidationDecision::ALLOWED);
    }
}

TEST(AuthenticodeSignature, ExtractsSignersFromSignedBinaryWhenPresent) {
    AuthenticodeSignature signature = AuthenticodeSignature::of_file(current_module_path());
    if (signature.status() == TRUST_E_NOSIGNATURE) {
        // Local and CI build binaries are unsigned; only staged release binaries are signed.
        EXPECT_FALSE(signature.has_signer());
        GTEST_SKIP() << "test binary is not Authenticode-signed";
    }
    EXPECT_TRUE(signature.has_signer());
    for (const std::string &thumbprint : signature.signer_thumbprints()) {
        EXPECT_EQ(thumbprint.size(), 64u);
    }
}

TEST(CertificatePin, ComputesPinFromSignedBinaryWhenPresent) {
    std::optional<CertificatePin> pin = CertificatePin::from_executable(current_module_path().c_str());
    if (!pin.has_value()) {
        GTEST_SKIP() << "test binary has no Authenticode signer";
    }
    EXPECT_EQ(pin->value().size(), 64u);
}

TEST(CertificatePin, ReturnsNoPinForMissingExecutable) {
    EXPECT_FALSE(CertificatePin::from_executable(L"X:\\this\\file\\does\\not\\exist.exe").has_value());
    EXPECT_FALSE(CertificatePin::from_executable(L"").has_value());
    EXPECT_FALSE(CertificatePin::from_executable(nullptr).has_value());
}
