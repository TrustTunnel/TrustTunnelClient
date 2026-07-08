#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

#include "vpn/file_logger.h"
#include "scoped_file_lock.h"

namespace ag {
namespace vpn_easy {

/// Base name of the client-process rotating log family (`<CLIENT_LOG_BASE>.log`).
inline constexpr const char *CLIENT_LOG_BASE = "client";
/// Base name of the service-process rotating log family (`<SERVICE_LOG_BASE>.log`).
inline constexpr const char *SERVICE_LOG_BASE = "service";

/// `FileLoggerSync` backed by an exclusive `LockFileEx` on a per-family lock
/// sidecar (reuses `ScopedFileLock`). Stateless: safe to share across families
/// and threads.
class WindowsFileLoggerSync : public ag::FileLoggerSync {
public:
    void with_exclusive(const std::filesystem::path &directory, std::string_view base_name,
            const std::function<void()> &action) override {
        ScopedFileLock lock{directory / (std::string(base_name) + ".log")};
        action();
    }
};

} // namespace vpn_easy
} // namespace ag
