#pragma once

#include <filesystem>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace ag {
namespace vpn_easy {

/// RAII exclusive byte-range lock on a "<path>.lock" sidecar via `LockFileEx`.
/// Cross-session safe (any process with directory access can take it, avoiding
/// named-mutex namespace/privilege issues). Use `operator bool()` to check
/// whether the lock was acquired.
class ScopedFileLock {
public:
    explicit ScopedFileLock(const std::filesystem::path &file_path)
            : m_handle(open_and_lock(file_path)) {
    }

    ~ScopedFileLock() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            OVERLAPPED ov{};
            UnlockFileEx(m_handle, 0, 1, 0, &ov);
            CloseHandle(m_handle);
        }
    }

    ScopedFileLock(const ScopedFileLock &) = delete;
    ScopedFileLock &operator=(const ScopedFileLock &) = delete;

    explicit operator bool() const {
        return m_handle != INVALID_HANDLE_VALUE;
    }

private:
    static HANDLE open_and_lock(const std::filesystem::path &file_path) {
        // Build the lock file path: "<file_path>.lock"
        std::filesystem::path lock_path = file_path;
        lock_path += ".lock";
        std::wstring wpath = lock_path.wstring();

        // Create the lock file if it doesn't exist. It's just an empty
        // synchronization marker — harmless to create, independent of the
        // data file lifecycle.
        HANDLE h = CreateFileW(wpath.c_str(), GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            return INVALID_HANDLE_VALUE;
        }

        OVERLAPPED ov{};

        // Blocking exclusive lock on byte 0. Will wait until available.
        if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ov)) {
            CloseHandle(h);
            return INVALID_HANDLE_VALUE;
        }

        return h;
    }

    HANDLE m_handle;
};

} // namespace vpn_easy
} // namespace ag
