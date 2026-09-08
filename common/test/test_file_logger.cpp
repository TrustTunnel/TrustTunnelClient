#include <filesystem>
#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "vpn/file_logger.h"

namespace fs = std::filesystem;

static std::string read_file(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

class FileLoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Guarantee INFO messages reach the sink regardless of the global default level.
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
        m_dir = fs::temp_directory_path() / fs::path("tt_filelogger_test");
        fs::remove_all(m_dir);
    }
    void TearDown() override {
        ag::Logger::set_callback([](ag::LogLevel, std::string_view) {});
        fs::remove_all(m_dir);
    }
    fs::path m_dir;
};

TEST_F(FileLoggerTest, AppendsFormattedRecord) {
    {
        ag::FileLogger logger(m_dir, "app");
        logger.install();
        infolog((ag::Logger{"TEST"}), "hello world");
    } // flush + close on destruction

    std::string content = read_file(m_dir / "app.log");
    // Record separator present, level tag present, message present.
    EXPECT_NE(content.find("[INFO]"), std::string::npos);
    EXPECT_NE(content.find("hello world"), std::string::npos);
    EXPECT_NE(content.find('\x1E'), std::string::npos);
    // ISO8601-ish prefix: starts with a 4-digit year and contains a 'T'.
    EXPECT_TRUE(content.size() > 5 && content[4] == '-');
    EXPECT_NE(content.find('T'), std::string::npos);
}

TEST_F(FileLoggerTest, RotatesWhenExceedingMaxSize) {
    ag::Logger t{"TEST"};
    {
        // Tiny max so a couple of lines force a rotation. archive_count = 1.
        ag::FileLogger logger(m_dir, "app", /*max_file_size*/ 64, /*archive_count*/ 1);
        logger.install();
        infolog(t, "first message that is reasonably long to fill the tiny file");
        infolog(t, "second message that triggers rotation to app.1.log");
    }
    EXPECT_TRUE(fs::exists(m_dir / "app.log"));
    EXPECT_TRUE(fs::exists(m_dir / "app.1.log"));
}

TEST_F(FileLoggerTest, SnapshotCopiesFamilyAndSkipsMissing) {
    ag::Logger t{"TEST"};
    {
        ag::FileLogger logger(m_dir, "service");
        logger.install();
        infolog(t, "service line");
    }
    fs::path dest = m_dir / "export";
    std::vector<fs::path> copied = ag::FileLogger::snapshot(m_dir, "service", dest);
    ASSERT_EQ(copied.size(), 1u); // only service.log exists (no archive yet)
    EXPECT_TRUE(fs::exists(dest / "service.log"));
    EXPECT_NE(read_file(dest / "service.log").find("service line"), std::string::npos);
}

TEST_F(FileLoggerTest, InstanceClearResetsToEmpty) {
    ag::Logger t{"TEST"};
    ag::FileLogger logger(m_dir, "app");
    logger.install();
    infolog(t, "old content");
    logger.clear_logs();
    // Fresh file exists and is empty right after clear.
    EXPECT_TRUE(fs::exists(m_dir / "app.log"));
    EXPECT_EQ(fs::file_size(m_dir / "app.log"), 0u);
}
