#include "pipe_name_registry.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

using namespace ag::trusttunnel_windows;

static constexpr std::wstring_view PIPE_NAME_PREFIX = L"\\\\.\\pipe\\trusttunnel_vpn-";
static constexpr size_t PIPE_NAME_HEX_LENGTH = 32;

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

TEST(PipeNameGenerator, ProducesFullPathWith32LowercaseHexSuffix) {
    std::optional<std::wstring> name = generate_pipe_name();
    ASSERT_TRUE(name.has_value());
    ASSERT_GE(name->size(), PIPE_NAME_PREFIX.size());
    EXPECT_TRUE(std::wstring_view{*name}.starts_with(PIPE_NAME_PREFIX));

    std::wstring_view suffix = std::wstring_view{*name}.substr(PIPE_NAME_PREFIX.size());
    EXPECT_EQ(suffix.size(), PIPE_NAME_HEX_LENGTH);
    EXPECT_TRUE(std::all_of(suffix.begin(), suffix.end(), [](wchar_t c) {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
    }));
}

TEST(PipeNameGenerator, ProducesDistinctNames) {
    constexpr size_t COUNT = 100;
    std::vector<std::wstring> names;
    names.reserve(COUNT);
    for (size_t i = 0; i < COUNT; ++i) {
        std::optional<std::wstring> name = generate_pipe_name();
        ASSERT_TRUE(name.has_value());
        names.push_back(std::move(*name));
    }
    std::sort(names.begin(), names.end());
    EXPECT_EQ(std::adjacent_find(names.begin(), names.end()), names.end());
}

// ---------------------------------------------------------------------------
// Registry layout: missing keys need no elevation and are checked always.
// ---------------------------------------------------------------------------

TEST(PipeNameRegistry, DeletingMissingKeySucceeds) {
    PipeNameRegistry registry{L"trusttunnel_pipe_name_test_no_such_service"};
    EXPECT_EQ(registry.remove(), 0);
}

TEST(PipeNameRegistry, DiscoveringMissingKeyReturnsNothing) {
    PipeNameRegistry registry{L"trusttunnel_pipe_name_test_no_such_service"};
    EXPECT_FALSE(registry.discover().has_value());
}

// ---------------------------------------------------------------------------
// Registry publication against the real registry under a dedicated test service key. These
// require elevation to create the key and skip themselves otherwise.
// ---------------------------------------------------------------------------

class PipeNameRegistryTest : public testing::Test {
protected:
    void SetUp() override {
        m_service_name = L"trusttunnel_pipe_name_test_" + std::to_wstring(GetCurrentProcessId());
        if (!can_create_service_key()) {
            GTEST_SKIP() << "creating a service registry key requires elevation";
        }
    }

    void TearDown() override {
        if (!m_service_name.empty()) {
            RegDeleteTreeW(HKEY_LOCAL_MACHINE, service_key_path().c_str());
        }
    }

    std::wstring service_key_path() const {
        return L"SYSTEM\\CurrentControlSet\\Services\\" + m_service_name;
    }

    bool can_create_service_key() const {
        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(
                HKEY_LOCAL_MACHINE, service_key_path().c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (key != nullptr) {
            RegCloseKey(key);
        }
        return status == ERROR_SUCCESS;
    }

    std::wstring m_service_name;
};

TEST_F(PipeNameRegistryTest, PublishesAndDiscovers) {
    constexpr std::wstring_view NAME = L"\\\\.\\pipe\\trusttunnel_vpn-0123456789abcdef0123456789abcdef";
    PipeNameRegistry registry{m_service_name};
    ASSERT_EQ(registry.publish(NAME), 0);

    std::optional<std::wstring> discovered = registry.discover();
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(*discovered, NAME);
}

TEST_F(PipeNameRegistryTest, OverwritesThePreviousName) {
    constexpr std::wstring_view FIRST = L"\\\\.\\pipe\\trusttunnel_vpn-0123456789abcdef0123456789abcdef";
    constexpr std::wstring_view SECOND = L"\\\\.\\pipe\\trusttunnel_vpn-fedcba9876543210fedcba9876543210";
    PipeNameRegistry registry{m_service_name};
    ASSERT_EQ(registry.publish(FIRST), 0);
    ASSERT_EQ(registry.publish(SECOND), 0);

    std::optional<std::wstring> discovered = registry.discover();
    ASSERT_TRUE(discovered.has_value());
    EXPECT_EQ(*discovered, SECOND);
}

TEST_F(PipeNameRegistryTest, DeletesThePublishedName) {
    PipeNameRegistry registry{m_service_name};
    ASSERT_EQ(registry.publish(L"\\\\.\\pipe\\trusttunnel_vpn-0123456789abcdef0123456789abcdef"), 0);
    ASSERT_EQ(registry.remove(), 0);
    EXPECT_FALSE(registry.discover().has_value());
}
