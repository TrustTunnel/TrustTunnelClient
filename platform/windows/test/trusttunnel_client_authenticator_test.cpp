#include "client_authenticator.h"
#include "process_info.h"

#include <gtest/gtest.h>

#include <atomic>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace ag::trusttunnel_windows;

static constexpr std::string_view LEAF_A = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
static constexpr std::string_view LEAF_B = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

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

static AuthenticodeSignature signature_with(std::vector<std::string> thumbprints, int32_t status = S_OK) {
    return AuthenticodeSignature{status, std::move(thumbprints)};
}

/// A service at the test binary's path, so that the sibling gate passes for this process.
static ProcessInfo sibling_service_info() {
    return ProcessInfo{current_module_path()};
}

TEST(ProcessInfo, CurrentResolvesOwnImagePath) {
    // The sibling check compares the service's path and the client's path, both resolved by this
    // module, so it must agree with the module path the process was loaded from.
    std::optional<ProcessInfo> info = ProcessInfo::current();
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->image_path(), current_module_path());
}

TEST(SiblingPath, MatchesSameDirectory) {
    EXPECT_TRUE(is_same_directory(L"C:\\app\\client.exe", L"C:\\app\\service.exe"));
}

TEST(SiblingPath, RejectsDifferentDirectory) {
    EXPECT_FALSE(is_same_directory(L"C:\\other\\client.exe", L"C:\\app\\service.exe"));
    EXPECT_FALSE(is_same_directory(L"C:\\app\\sub\\client.exe", L"C:\\app\\service.exe"));
    EXPECT_FALSE(is_same_directory(L"client.exe", L"C:\\app\\service.exe"));
}

TEST(SiblingPath, IgnoresLetterCase) {
    EXPECT_TRUE(is_same_directory(L"c:\\APP\\client.exe", L"C:\\app\\service.exe"));
    EXPECT_TRUE(is_same_directory(L"C:\\App\\CLIENT.EXE", L"c:\\aPP\\Service.Exe"));
}

TEST(SiblingPath, IgnoresSeparatorStyle) {
    EXPECT_TRUE(is_same_directory(L"C:/app/client.exe", L"C:\\app\\service.exe"));
    EXPECT_TRUE(is_same_directory(L"C:\\app/client.exe", L"C:/app\\service.exe"));
}

TEST(SiblingPath, NormalizesTrailingSeparators) {
    EXPECT_TRUE(is_same_directory(L"C:\\app\\", L"C:\\app\\service.exe"));
    EXPECT_TRUE(is_same_directory(L"C:\\app\\client.exe", L"C:\\app\\"));
    EXPECT_FALSE(is_same_directory(L"C:\\app\\sub\\", L"C:\\app\\service.exe"));
}

TEST(SiblingPath, SameDirectoryDifferentFileNames) {
    EXPECT_TRUE(is_same_directory(L"C:\\app\\first.exe", L"C:\\app\\second.exe"));
}

TEST(AuthenticodeSignature, ValidStatusesRequireARecoveredSigner) {
    EXPECT_TRUE(signature_with({std::string{LEAF_A}}).is_valid());
    EXPECT_TRUE(signature_with({std::string{LEAF_A}}, CERT_E_UNTRUSTEDROOT).is_valid());
    EXPECT_TRUE(signature_with({std::string{LEAF_A}}, CERT_E_CHAINING).is_valid());
    EXPECT_TRUE(signature_with({std::string{LEAF_A}}, CERT_E_EXPIRED).is_valid());
    EXPECT_FALSE(signature_with({}).is_valid());
    EXPECT_FALSE(signature_with({}, CERT_E_UNTRUSTEDROOT).is_valid());
    EXPECT_FALSE(signature_with({std::string{LEAF_A}}, TRUST_E_NOSIGNATURE).is_valid());
    EXPECT_FALSE(signature_with({std::string{LEAF_A}}, TRUST_E_BAD_DIGEST).is_valid());
    EXPECT_FALSE(signature_with({std::string{LEAF_A}}, TRUST_E_SYSTEM_ERROR).is_valid());
}

TEST(AuthenticodeSignature, CurrentProcessIsUnsignedOrValid) {
    std::optional<AuthenticodeSignature> signature = AuthenticodeSignature::of_current_process();
    if (!signature.has_value()) {
        // Local and CI build binaries are unsigned.
        GTEST_SKIP() << "test binary has no embedded signature";
    }
    EXPECT_TRUE(signature->is_valid());
    for (const std::string &thumbprint : signature->signer_thumbprints()) {
        EXPECT_EQ(thumbprint.size(), 64u);
    }
}

TEST(MatchSignatures, AllowsEqualSignerSets) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}), signature_with({std::string{LEAF_A}})),
            ClientValidationDecision::ALLOWED);
}

TEST(MatchSignatures, IgnoresSignerOrderAndDuplicates) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}, std::string{LEAF_B}}),
                      signature_with({std::string{LEAF_B}, std::string{LEAF_A}, std::string{LEAF_A}})),
            ClientValidationDecision::ALLOWED);
}

TEST(MatchSignatures, RejectsDisjointSignerSets) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}), signature_with({std::string{LEAF_B}})),
            ClientValidationDecision::NO_MATCHING_SIGNER);
}

TEST(MatchSignatures, RejectsSubsetSignerSet) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}, std::string{LEAF_B}}),
                      signature_with({std::string{LEAF_A}})),
            ClientValidationDecision::NO_MATCHING_SIGNER);
}

TEST(MatchSignatures, RejectsSupersetSignerSet) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}),
                      signature_with({std::string{LEAF_A}, std::string{LEAF_B}})),
            ClientValidationDecision::NO_MATCHING_SIGNER);
}

TEST(MatchSignatures, AllowsEqualSetsOnUntrustedRoot) {
    // A self-signed dev certificate is expected to fail chain building; the leaf set still counts.
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}, CERT_E_UNTRUSTEDROOT),
                      signature_with({std::string{LEAF_A}}, CERT_E_UNTRUSTEDROOT)),
            ClientValidationDecision::ALLOWED);
}

TEST(MatchSignatures, AllowsEqualSetsOnExpiredCertificate) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}, CERT_E_EXPIRED),
                      signature_with({std::string{LEAF_A}}, CERT_E_EXPIRED)),
            ClientValidationDecision::ALLOWED);
}

TEST(MatchSignatures, RejectsUnsignedClient) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}), signature_with({}, TRUST_E_NOSIGNATURE)),
            ClientValidationDecision::NO_SIGNATURE);
}

TEST(MatchSignatures, RejectsBadDigestEvenWithRecoveredSigners) {
    EXPECT_EQ(match_signatures(
                      signature_with({std::string{LEAF_A}}), signature_with({std::string{LEAF_A}}, TRUST_E_BAD_DIGEST)),
            ClientValidationDecision::BAD_DIGEST);
}

TEST(MatchSignatures, RejectsClientStatusOutsideAcceptedSet) {
    // A recovered signer alone is not enough: the status must be one of the accepted ones.
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}),
                      signature_with({std::string{LEAF_A}}, TRUST_E_SYSTEM_ERROR)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(MatchSignatures, RejectsClientWithoutRecoveredSigners) {
    EXPECT_EQ(match_signatures(signature_with({std::string{LEAF_A}}), signature_with({}, CERT_E_UNTRUSTEDROOT)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(MatchSignatures, RejectsEveryClientWhenServiceSignatureIsInvalid) {
    AuthenticodeSignature service = signature_with({std::string{LEAF_A}}, TRUST_E_SYSTEM_ERROR);
    EXPECT_EQ(match_signatures(service, signature_with({std::string{LEAF_A}})),
            ClientValidationDecision::VERIFICATION_FAILURE);
    EXPECT_EQ(match_signatures(service, signature_with({std::string{LEAF_B}})),
            ClientValidationDecision::VERIFICATION_FAILURE);
    EXPECT_EQ(match_signatures(service, signature_with({}, TRUST_E_NOSIGNATURE)),
            ClientValidationDecision::VERIFICATION_FAILURE);
    EXPECT_EQ(match_signatures(service, signature_with({std::string{LEAF_A}}, TRUST_E_BAD_DIGEST)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(MatchSignatures, RejectsEveryClientWhenServiceSignatureHasNoSigners) {
    AuthenticodeSignature service = signature_with({});
    EXPECT_EQ(match_signatures(service, signature_with({std::string{LEAF_A}})),
            ClientValidationDecision::VERIFICATION_FAILURE);
    EXPECT_EQ(match_signatures(service, signature_with({}, TRUST_E_NOSIGNATURE)),
            ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(ClientAuthenticator, RejectsUnresolvablePipe) {
    ClientAuthenticator authenticator{sibling_service_info(), signature_with({std::string{LEAF_A}})};
    EXPECT_EQ(authenticator.validate(nullptr), ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(ClientAuthenticator, RejectsUnresolvablePipeWhenServiceIsUnsigned) {
    ClientAuthenticator authenticator{sibling_service_info(), std::nullopt};
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

TEST_F(ClientAuthenticatorTest, ResolvesClientProcessInfoFromPipe) {
    std::optional<ProcessInfo> info = ProcessInfo::from_pipe(m_server);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->image_path(), current_module_path());
}

TEST_F(ClientAuthenticatorTest, RejectsPipeClientWithDifferentSignature) {
    // The sibling check passes (the test process runs in the service directory), so the rejection
    // comes from the signature check: the unsigned test binary's leaf set cannot equal the
    // service's.
    ClientAuthenticator authenticator{sibling_service_info(), signature_with({std::string{LEAF_A}})};
    EXPECT_NE(authenticator.validate(m_server), ClientValidationDecision::ALLOWED);
}

TEST_F(ClientAuthenticatorTest, AllowsPipeClientInServiceDirectoryWhenServiceIsUnsigned) {
    // An unsigned service accepts any sibling, signed or not.
    ClientAuthenticator authenticator{sibling_service_info(), std::nullopt};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::ALLOWED);
}

TEST_F(ClientAuthenticatorTest, AllowsPipeClientSignedLikeTheService) {
    std::optional<AuthenticodeSignature> own_signature = AuthenticodeSignature::of_current_process();
    if (!own_signature.has_value()) {
        GTEST_SKIP() << "test binary has no embedded signature";
    }
    // The client is this process, so its signature equals the service's.
    ClientAuthenticator authenticator{sibling_service_info(), own_signature};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::ALLOWED);
}

TEST_F(ClientAuthenticatorTest, RejectsPipeClientOutsideServiceDirectoryWhenServiceIsUnsigned) {
    ClientAuthenticator authenticator{ProcessInfo{L"X:\\somewhere\\else\\service.exe"}, std::nullopt};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::SIBLING_PATH_MISMATCH);
}

TEST_F(ClientAuthenticatorTest, RejectsWhenServiceProcessInfoIsUnresolved) {
    // No client can be a sibling when the service's own process info is unknown.
    ClientAuthenticator authenticator{std::nullopt, std::nullopt};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST_F(ClientAuthenticatorTest, SiblingMismatchWinsOverSignatureCheck) {
    // A sibling mismatch rejects the client before the signature is even considered.
    ClientAuthenticator authenticator{
            ProcessInfo{L"X:\\somewhere\\else\\service.exe"}, signature_with({std::string{LEAF_A}})};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::SIBLING_PATH_MISMATCH);
}

TEST_F(ClientAuthenticatorTest, RejectsWhenServiceSignatureIsInvalid) {
    ClientAuthenticator authenticator{
            sibling_service_info(), signature_with({std::string{LEAF_A}}, TRUST_E_SYSTEM_ERROR)};
    EXPECT_EQ(authenticator.validate(m_server), ClientValidationDecision::VERIFICATION_FAILURE);
}

TEST(AuthenticodeSignature, ExtractsSignersFromSignedBinaryWhenPresent) {
    AuthenticodeSignature signature = AuthenticodeSignature::of_file(current_module_path());
    if (signature.status() == TRUST_E_NOSIGNATURE) {
        // Local and CI build binaries are unsigned.
        EXPECT_TRUE(signature.signer_thumbprints().empty());
        GTEST_SKIP() << "test binary is not Authenticode-signed";
    }
    EXPECT_FALSE(signature.signer_thumbprints().empty());
    for (const std::string &thumbprint : signature.signer_thumbprints()) {
        EXPECT_EQ(thumbprint.size(), 64u);
    }
}
