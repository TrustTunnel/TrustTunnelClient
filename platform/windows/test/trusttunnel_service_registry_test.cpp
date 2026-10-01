#include "service_registry.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <string_view>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace ag::trusttunnel_windows;

static constexpr std::wstring_view PIPE_NAME = L"\\\\.\\pipe\\trusttunnel_vpn-0123456789abcdef0123456789abcdef";

// ---------------------------------------------------------------------------
// Missing keys need no elevation and are checked always.
// ---------------------------------------------------------------------------

TEST(ServiceRegistry, MissingValuesAreNotRead) {
    ServiceRegistry registry{L"trusttunnel_service_registry_test_no_such_service"};
    EXPECT_FALSE(registry.pipe_name().read_string().has_value());
}

TEST(ServiceRegistry, RemovingMissingValuesSucceeds) {
    ServiceRegistry registry{L"trusttunnel_service_registry_test_no_such_service"};
    EXPECT_EQ(registry.pipe_name().remove(), 0);
}

// ---------------------------------------------------------------------------
// The real registry under a dedicated test service key. These require elevation to create the
// key and skip themselves otherwise.
// ---------------------------------------------------------------------------

class ServiceRegistryTest : public testing::Test {
protected:
    void SetUp() override {
        m_service_name = L"trusttunnel_service_registry_test_" + std::to_wstring(GetCurrentProcessId());
        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE, service_key_path().c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (status != ERROR_SUCCESS) {
            m_service_name.clear();
            GTEST_SKIP() << "creating a service registry key requires elevation";
        }
        RegCloseKey(key);
    }

    void TearDown() override {
        if (!m_service_name.empty()) {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, service_key_path().c_str());
        }
    }

    std::wstring service_key_path() const {
        return L"SYSTEM\\CurrentControlSet\\Services\\" + m_service_name;
    }

    /** Overwrite `PipeName` with raw data, bypassing `RegistryValue`. */
    void set_raw_pipe_name(DWORD type, const void *data, DWORD size) const {
        HKEY key = nullptr;
        std::wstring path = service_key_path() + L"\\Parameters";
        ASSERT_EQ(RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_SET_VALUE, &key), ERROR_SUCCESS);
        EXPECT_EQ(RegSetValueExW(key, L"PipeName", 0, type, static_cast<const BYTE *>(data), size), ERROR_SUCCESS);
        RegCloseKey(key);
    }

    std::wstring m_service_name;
};

TEST_F(ServiceRegistryTest, WritesAndReadsThePipeName) {
    RegistryValue pipe_name = ServiceRegistry{m_service_name}.pipe_name();
    ASSERT_EQ(pipe_name.write_string(PIPE_NAME), 0);
    EXPECT_EQ(pipe_name.read_string(), PIPE_NAME);

    constexpr std::wstring_view SECOND = L"\\\\.\\pipe\\trusttunnel_vpn-fedcba9876543210fedcba9876543210";
    ASSERT_EQ(pipe_name.write_string(SECOND), 0);
    EXPECT_EQ(pipe_name.read_string(), SECOND);
}

TEST_F(ServiceRegistryTest, RemovesValuesIdempotently) {
    RegistryValue pipe_name = ServiceRegistry{m_service_name}.pipe_name();
    ASSERT_EQ(pipe_name.write_string(PIPE_NAME), 0);

    ASSERT_EQ(pipe_name.remove(), 0);
    EXPECT_FALSE(pipe_name.read_string().has_value());
    EXPECT_EQ(pipe_name.remove(), 0);
}

TEST_F(ServiceRegistryTest, AValueOfTheWrongTypeIsNotRead) {
    RegistryValue pipe_name = ServiceRegistry{m_service_name}.pipe_name();
    ASSERT_EQ(pipe_name.write_string(PIPE_NAME), 0);
    DWORD value = 42;
    set_raw_pipe_name(REG_DWORD, &value, sizeof(value));

    EXPECT_FALSE(pipe_name.read_string().has_value());
}

TEST_F(ServiceRegistryTest, AnOddLengthStringIsNotRead) {
    RegistryValue pipe_name = ServiceRegistry{m_service_name}.pipe_name();
    ASSERT_EQ(pipe_name.write_string(PIPE_NAME), 0);
    constexpr wchar_t VALUE[] = L"\\\\.\\pipe\\trusttunnel_vpn-X";
    set_raw_pipe_name(REG_SZ, VALUE, sizeof(VALUE) - 1);

    EXPECT_FALSE(pipe_name.read_string().has_value());
}
