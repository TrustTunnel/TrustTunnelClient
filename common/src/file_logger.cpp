#include "vpn/file_logger.h"

#include <chrono>
#include <system_error>

#include <fmt/format.h>

#include "common/file.h"
#include "common/time_utils.h"

namespace ag {

static void run_exclusive(FileLoggerSync *sync, const std::filesystem::path &directory, std::string_view base_name,
        const std::function<void()> &action) {
    if (sync != nullptr) {
        sync->with_exclusive(directory, base_name, action);
    } else {
        action();
    }
}

FileLogger::FileLogger(std::filesystem::path directory, std::string base_name, std::size_t max_file_size,
        int archive_count, std::shared_ptr<FileLoggerSync> sync)
        : m_directory(std::move(directory))
        , m_base_name(std::move(base_name))
        , m_max_file_size(max_file_size)
        , m_archive_count(archive_count)
        , m_sync(std::move(sync)) {
    std::scoped_lock guard{m_mutex};
    open_or_create_file();
}

FileLogger::~FileLogger() {
    if (m_installed) {
        // Detach the global sink so no further callbacks touch this instance.
        ag::Logger::set_callback([](LogLevel, std::string_view) {});
    }
    std::scoped_lock guard{m_mutex};
    close_file();
}

void FileLogger::install() {
    m_installed = true;
    ag::Logger::set_callback([this](LogLevel level, std::string_view message) {
        append_line(level, message);
    });
}

void FileLogger::clear_logs() {
    std::scoped_lock guard{m_mutex};
    run_exclusive(m_sync.get(), m_directory, m_base_name, [this] {
        close_file();
        delete_files(m_directory, m_base_name, m_archive_count);
        open_or_create_file();
    });
}

std::vector<std::filesystem::path> FileLogger::snapshot(const std::filesystem::path &directory,
        std::string_view base_name, const std::filesystem::path &dest_dir, int archive_count, FileLoggerSync *sync) {
    std::vector<std::filesystem::path> result;
    run_exclusive(sync, directory, base_name, [&] {
        std::error_code ec;
        std::filesystem::create_directories(dest_dir, ec);
        for (const auto &src : candidate_paths(directory, base_name, archive_count)) {
            if (!std::filesystem::exists(src, ec)) {
                continue;
            }
            std::filesystem::path dst = dest_dir / src.filename();
            std::filesystem::copy_file(src, dst, std::filesystem::copy_options::overwrite_existing, ec);
            if (!ec) {
                result.push_back(std::move(dst));
            }
        }
    });
    return result;
}

void FileLogger::append_line(LogLevel level, std::string_view message) {
    std::scoped_lock guard{m_mutex};
    std::string line = format_line(level, message);
    if (m_current_size + line.size() > m_max_file_size) {
        rotate();
    }
    if (!ag::file::is_valid(m_file)) {
        return;
    }
    ssize_t written = ag::file::write(m_file, line.data(), line.size());
    if (written > 0) {
        m_current_size += (std::size_t) written;
    }
}

void FileLogger::rotate() {
    run_exclusive(m_sync.get(), m_directory, m_base_name, [this] {
        close_file();
        std::error_code ec;
        // Shift archives up (base.N.log -> base.(N+1).log), dropping the oldest.
        for (int idx = m_archive_count - 1; idx >= 1; --idx) {
            std::filesystem::path src = m_directory / (m_base_name + "." + std::to_string(idx) + ".log");
            std::filesystem::path dst = m_directory / (m_base_name + "." + std::to_string(idx + 1) + ".log");
            std::filesystem::remove(dst, ec);
            std::filesystem::rename(src, dst, ec);
        }
        std::filesystem::path current = m_directory / (m_base_name + ".log");
        std::filesystem::path archived = m_directory / (m_base_name + ".1.log");
        std::filesystem::remove(archived, ec);
        std::filesystem::rename(current, archived, ec);
        open_or_create_file();
    });
}

void FileLogger::open_or_create_file() {
    std::error_code ec;
    std::filesystem::create_directories(m_directory, ec);
    std::filesystem::path path = m_directory / (m_base_name + ".log");
    m_file = ag::file::open(path.string(), ag::file::WRONLY | ag::file::CREAT | ag::file::APPEND);
    m_current_size = ag::file::is_valid(m_file) ? (std::size_t) ag::file::get_size(m_file) : 0;
}

void FileLogger::close_file() {
    if (ag::file::is_valid(m_file)) {
        ag::file::close(m_file);
        m_file = ag::file::INVALID_HANDLE;
    }
    m_current_size = 0;
}

std::vector<std::filesystem::path> FileLogger::candidate_paths(
        const std::filesystem::path &directory, std::string_view base_name, int archive_count) {
    std::vector<std::filesystem::path> paths;
    std::string base(base_name);
    paths.push_back(directory / (base + ".log"));
    for (int idx = 1; idx <= archive_count; ++idx) {
        paths.push_back(directory / (base + "." + std::to_string(idx) + ".log"));
    }
    return paths;
}

void FileLogger::delete_files(const std::filesystem::path &directory, std::string_view base_name, int archive_count) {
    std::error_code ec;
    for (const auto &p : candidate_paths(directory, base_name, archive_count)) {
        std::filesystem::remove(p, ec);
    }
}

std::string FileLogger::format_line(LogLevel level, std::string_view message) {
    std::string escaped(message);
    for (std::size_t pos = 0; (pos = escaped.find('\x1E', pos)) != std::string::npos; pos += 4) {
        escaped.replace(pos, 1, "\\x1E");
    }
    std::string timestamp = ag::format_gmtime(std::chrono::system_clock::now(), "%Y-%m-%dT%H:%M:%S.%fZ");
    return fmt::format("{} [{}] {}\n\x1E", timestamp, level_tag(level), escaped);
}

const char *FileLogger::level_tag(LogLevel level) {
    switch (level) {
    case LOG_LEVEL_ERROR:
        return "ERROR";
    case LOG_LEVEL_WARN:
        return "WARN";
    case LOG_LEVEL_INFO:
        return "INFO";
    case LOG_LEVEL_DEBUG:
        return "DEBUG";
    case LOG_LEVEL_TRACE:
        return "TRACE";
    }
    return "INFO";
}

} // namespace ag
