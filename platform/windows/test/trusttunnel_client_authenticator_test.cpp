#include "client_authenticator.h"
#include "process_info.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <winioctl.h>

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

/// Layout of `REPARSE_DATA_BUFFER` for a mount point, which the user-mode SDK does not declare.
struct MountPointReparseHeader {
    ULONG reparse_tag;
    USHORT reparse_data_length;
    USHORT reserved;
    USHORT substitute_name_offset;
    USHORT substitute_name_length;
    USHORT print_name_offset;
    USHORT print_name_length;
};

/// Create a directory junction at `link` pointing to `target`; unlike a symlink it needs no privilege.
static bool create_junction(const std::filesystem::path &link, const std::filesystem::path &target) {
    std::error_code ec;
    if (!std::filesystem::create_directory(link, ec)) {
        return false;
    }
    HANDLE dir = CreateFileW(link.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (dir == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::wstring substitute_name = L"\\??\\" + std::filesystem::absolute(target).wstring();
    std::wstring print_name = target.wstring();
    std::vector<uint8_t> buffer(
            sizeof(MountPointReparseHeader) + (substitute_name.size() + print_name.size() + 2) * sizeof(wchar_t));
    auto *header = reinterpret_cast<MountPointReparseHeader *>(buffer.data());
    header->reparse_tag = IO_REPARSE_TAG_MOUNT_POINT;
    header->reparse_data_length =
            static_cast<USHORT>(buffer.size() - offsetof(MountPointReparseHeader, substitute_name_offset));
    header->substitute_name_length = static_cast<USHORT>(substitute_name.size() * sizeof(wchar_t));
    header->print_name_offset = static_cast<USHORT>((substitute_name.size() + 1) * sizeof(wchar_t));
    header->print_name_length = static_cast<USHORT>(print_name.size() * sizeof(wchar_t));
    auto *names = reinterpret_cast<wchar_t *>(buffer.data() + sizeof(MountPointReparseHeader));
    std::copy(substitute_name.begin(), substitute_name.end(), names);
    std::copy(print_name.begin(), print_name.end(), names + substitute_name.size() + 1);

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(dir, FSCTL_SET_REPARSE_POINT, buffer.data(), static_cast<DWORD>(buffer.size()), nullptr,
            0, &returned, nullptr);
    CloseHandle(dir);
    return ok != FALSE;
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

TEST_F(ClientAuthenticatorTest, LocksPipeClientImage) {
    std::optional<LockedImage> image = LockedImage::of_pipe_client(m_server);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->path(), current_module_path());
    EXPECT_NE(image->file(), nullptr);
}

TEST(LockedImage, RejectsUnresolvablePipe) {
    EXPECT_FALSE(LockedImage::of_pipe_client(nullptr).has_value());
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

TEST(AuthenticodeSignature, ReadsThroughGivenFileHandle) {
    std::wstring path = current_module_path();
    AuthenticodeSignature by_path = AuthenticodeSignature::of_file(path);
    if (by_path.status() == TRUST_E_NOSIGNATURE) {
        // An unreadable path also reports `TRUST_E_NOSIGNATURE`, so only a signed binary can tell them apart.
        GTEST_SKIP() << "test binary is not Authenticode-signed";
    }
    HANDLE file = CreateFileW(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(file, INVALID_HANDLE_VALUE);
    // The path only names the handle, so a nonexistent one yields the same result as the real one.
    AuthenticodeSignature by_handle = AuthenticodeSignature::of_file(L"X:\\nonexistent\\client.exe", file);
    CloseHandle(file);
    EXPECT_EQ(by_handle.status(), by_path.status());
    EXPECT_EQ(by_handle.signer_thumbprints(), by_path.signer_thumbprints());
}

/// A suspended copy of the test binary at `<dir>\app\client.exe`, standing in for a pipe client.
class LockedImageTest : public testing::Test {
protected:
    void SetUp() override {
        static std::atomic<uint64_t> counter{0};
        m_dir = std::filesystem::temp_directory_path()
                / (L"tt_locked_image_test_" + std::to_wstring(GetCurrentProcessId()) + L"_"
                        + std::to_wstring(counter.fetch_add(1)));
        m_app = m_dir / L"app";
        m_client = m_app / L"client.exe";
        std::filesystem::create_directories(m_app);
        std::filesystem::copy_file(current_module_path(), m_client);

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION info{};
        std::wstring command = L"\"" + m_client.wstring() + L"\"";
        ASSERT_TRUE(CreateProcessW(m_client.c_str(), command.data(), nullptr, nullptr, FALSE,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info));
        CloseHandle(info.hThread);
        m_process = info.hProcess;
        std::optional<ProcessInfo> child = ProcessInfo::from_process(m_process);
        ASSERT_TRUE(child.has_value());
        m_image_path = child->image_path();
    }

    void TearDown() override {
        if (m_process != nullptr) {
            TerminateProcess(m_process, 0);
            WaitForSingleObject(m_process, INFINITE);
            CloseHandle(m_process);
            m_process = nullptr;
        }
        // Unlink a junction left at the app path, so that the removal never descends into its target.
        RemoveDirectoryW(m_app.c_str());
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    std::filesystem::path m_dir;
    std::filesystem::path m_app;
    std::filesystem::path m_client;
    std::wstring m_image_path;
    HANDLE m_process = nullptr;
};

TEST_F(LockedImageTest, LocksImageOfProcess) {
    std::optional<LockedImage> image = LockedImage::lock(m_process, m_image_path);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->path(), m_image_path);
    EXPECT_NE(image->file(), nullptr);
}

TEST_F(LockedImageTest, PinsImageAndItsDirectoriesWhileLocked) {
    std::filesystem::path other = m_dir / L"other.exe";
    std::filesystem::copy_file(current_module_path(), other);
    std::optional<LockedImage> image = LockedImage::lock(m_process, m_image_path);
    ASSERT_TRUE(image.has_value());

    EXPECT_FALSE(MoveFileExW(m_client.c_str(), (m_app / L"moved.exe").c_str(), 0));
    EXPECT_FALSE(MoveFileExW(other.c_str(), m_client.c_str(), MOVEFILE_REPLACE_EXISTING));
    EXPECT_FALSE(MoveFileExW(m_app.c_str(), (m_dir / L"app_moved").c_str(), 0));
    EXPECT_FALSE(MoveFileExW(m_dir.c_str(), (m_dir.wstring() + L"_moved").c_str(), 0));
}

TEST_F(LockedImageTest, RejectsDecoyAtPathOfRenamedImage) {
    // The image is renamed after its path was queried, and a decoy takes over the path.
    ASSERT_TRUE(MoveFileExW(m_client.c_str(), (m_app / L"evil.exe").c_str(), 0));
    std::filesystem::copy_file(current_module_path(), m_client);
    EXPECT_FALSE(LockedImage::lock(m_process, m_image_path).has_value());
}

TEST_F(LockedImageTest, RejectsPathRedirectedByJunction) {
    // The image's directory is moved after its path was queried, and a junction to a decoy takes its place.
    std::filesystem::path decoy = m_dir / L"decoy";
    std::filesystem::create_directories(decoy);
    std::filesystem::copy_file(current_module_path(), decoy / L"client.exe");
    ASSERT_TRUE(MoveFileExW(m_app.c_str(), (m_dir / L"app_real").c_str(), 0));
    ASSERT_TRUE(create_junction(m_app, decoy));
    EXPECT_FALSE(LockedImage::lock(m_process, m_image_path).has_value());
}

TEST_F(LockedImageTest, RejectsFileOpenForWriting) {
    std::filesystem::path other = m_dir / L"other.exe";
    std::filesystem::copy_file(current_module_path(), other);
    HANDLE writer = CreateFileW(other.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    ASSERT_NE(writer, INVALID_HANDLE_VALUE);
    EXPECT_FALSE(LockedImage::lock(m_process, other.wstring()).has_value());
    CloseHandle(writer);
}
