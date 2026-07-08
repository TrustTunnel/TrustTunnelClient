#include <filesystem>
#include <system_error>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "vpn/vpn_easy.h"
#include "vpn_easy_log.h"

namespace fs = std::filesystem;

/// Unique temp dir per test with guaranteed cleanup. `TearDown` cleanup is
/// best-effort: the `VpnEasyApi*` test installs a process-global file logger
/// that keeps a log file open (opened without FILE_SHARE_DELETE) with no
/// teardown API, so a file may still be open here and is only released at
/// process exit. A throwing `remove_all` would therefore fail in `TearDown`.
class WindowsFileLoggingTest : public ::testing::Test {
protected:
    void SetUp() override {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
        m_dir = fs::temp_directory_path() / "tt_win_log_test" / std::to_string(reinterpret_cast<uintptr_t>(this));
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }

    void TearDown() override {
        // Detach any installed global sink so it no longer references test state.
        ag::Logger::set_callback([](ag::LogLevel, std::string_view) {});
        std::error_code ec;
        fs::remove_all(m_dir, ec);
    }

    fs::path m_dir;
};

TEST_F(WindowsFileLoggingTest, SyncRunsActionExclusively) {
    fs::create_directories(m_dir);
    ag::vpn_easy::WindowsFileLoggerSync sync;
    bool ran = false;
    sync.with_exclusive(m_dir, "service", [&] {
        ran = true;
    });
    EXPECT_TRUE(ran);
}

TEST_F(WindowsFileLoggingTest, VpnEasyApiInitExportClear) {
    vpn_easy_log_init(m_dir.wstring().c_str());
    ag::Logger t{"TEST"};
    infolog(t, "client message routed through the adapter file logger");

    std::vector<std::wstring> exported;
    vpn_easy_log_export((m_dir / "export").wstring().c_str(),
            [](void *arg, const wchar_t *path) {
                static_cast<std::vector<std::wstring> *>(arg)->emplace_back(path);
            },
            &exported);
    EXPECT_FALSE(exported.empty());

    vpn_easy_log_clear();
    EXPECT_TRUE(fs::exists(m_dir / "client.log"));
    EXPECT_EQ(fs::file_size(m_dir / "client.log"), 0u);
}
