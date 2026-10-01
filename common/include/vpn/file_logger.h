#pragma once

#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "common/file.h"
#include "common/logger.h"

namespace ag {

/// Cross-process coordination for log rotation, snapshot and clear.
class FileLoggerSync {
public:
    virtual ~FileLoggerSync() = default;
    /// Run `action` under exclusive access to the `base_name` family in `directory`.
    virtual void with_exclusive(const std::filesystem::path &directory, std::string_view base_name,
            const std::function<void()> &action) = 0;
};

/// Rotating single-writer file logger; becomes the global `ag::Logger` sink.
class FileLogger {
public:
    static constexpr std::size_t DEFAULT_MAX_FILE_SIZE = 2'500'000;
    static constexpr int DEFAULT_ARCHIVE_COUNT = 1;

    FileLogger(std::filesystem::path directory, std::string base_name,
            std::size_t max_file_size = DEFAULT_MAX_FILE_SIZE, int archive_count = DEFAULT_ARCHIVE_COUNT,
            std::shared_ptr<FileLoggerSync> sync = nullptr);
    ~FileLogger();

    FileLogger(const FileLogger &) = delete;
    FileLogger &operator=(const FileLogger &) = delete;

    /// Register as the global `ag::Logger` sink.
    void install();

    /// Clear own files and reopen a fresh current file.
    void clear_logs();

    /// Copy the `base_name` family into `dest_dir`; missing files are skipped.
    static std::vector<std::filesystem::path> snapshot(const std::filesystem::path &directory,
            std::string_view base_name, const std::filesystem::path &dest_dir,
            int archive_count = DEFAULT_ARCHIVE_COUNT, FileLoggerSync *sync = nullptr);

private:
    void append_line(LogLevel level, std::string_view message);
    void rotate();
    void open_or_create_file();
    void close_file();

    static std::vector<std::filesystem::path> candidate_paths(
            const std::filesystem::path &directory, std::string_view base_name, int archive_count);
    static void delete_files(const std::filesystem::path &directory, std::string_view base_name, int archive_count);
    static std::string format_line(LogLevel level, std::string_view message);
    static const char *level_tag(LogLevel level);

    std::filesystem::path m_directory;
    std::string m_base_name;
    std::size_t m_max_file_size;
    int m_archive_count;
    std::shared_ptr<FileLoggerSync> m_sync;
    std::mutex m_mutex;
    ag::file::Handle m_file = ag::file::INVALID_HANDLE;
    std::size_t m_current_size = 0;
    bool m_installed = false;
};

} // namespace ag
