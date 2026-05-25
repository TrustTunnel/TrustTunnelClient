#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace ag {
namespace vpn_easy {

/**
 * Acquire an exclusive byte-range lock on a lock file for cross-process ring
 * buffer synchronization. Uses a separate ".lock" file and LockFileEx instead
 * of a named mutex, avoiding cross-session namespace and privilege issues:
 * any process with directory access can take the lock.
 *
 * Both the service (writer, session 0) and the app (reader, session N) must
 * acquire this lock before touching the ring buffer to avoid reading
 * partially-written slots.
 */
class RingBufferLock {
public:
    explicit RingBufferLock(const std::string &file_path)
            : m_handle(open_and_lock(file_path)) {
    }

    ~RingBufferLock() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            OVERLAPPED ov{};
            UnlockFileEx(m_handle, 0, 1, 0, &ov);
            CloseHandle(m_handle);
        }
    }

    RingBufferLock(const RingBufferLock &) = delete;
    RingBufferLock &operator=(const RingBufferLock &) = delete;

    explicit operator bool() const {
        return m_handle != INVALID_HANDLE_VALUE;
    }

private:
    static HANDLE open_and_lock(const std::string &file_path) {
        // Build the lock file path: "<ring_buffer_path>.lock"
        std::string lock_path = file_path + ".lock";

        int wpath_len = MultiByteToWideChar(CP_UTF8, 0, lock_path.c_str(), -1, nullptr, 0);
        if (wpath_len <= 0) {
            return INVALID_HANDLE_VALUE;
        }
        std::wstring wpath(wpath_len - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, lock_path.c_str(), -1, &wpath[0], wpath_len);

        // Create the lock file if it doesn't exist. It's just an empty
        // synchronization marker — harmless to create, independent of the
        // ring buffer data file lifecycle.
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
