#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace ag::vpn_easy {

/**
 * Acquire a cross-process named mutex protecting a PersistentRingBuffer file.
 * Both the service (writer) and the app (reader) must acquire this mutex before
 * touching the ring buffer to avoid reading partially-written slots.
 *
 * The mutex name is derived from the file path hash so that different ring buffer
 * files get independent mutexes.
 */
class RingBufferLock {
public:
    explicit RingBufferLock(const std::string &file_path)
            : m_mutex(open_or_create_mutex(file_path)) {
        if (m_mutex) {
            WaitForSingleObject(m_mutex, INFINITE);
        }
    }

    ~RingBufferLock() {
        if (m_mutex) {
            ReleaseMutex(m_mutex);
            CloseHandle(m_mutex);
        }
    }

    RingBufferLock(const RingBufferLock &) = delete;
    RingBufferLock &operator=(const RingBufferLock &) = delete;

    explicit operator bool() const {
        return m_mutex != nullptr;
    }

private:
    static HANDLE open_or_create_mutex(const std::string &file_path) {
        size_t hash = std::hash<std::string>{}(file_path);
        std::wstring name = L"Global\\TrustTunnelRingBuffer_" + std::to_wstring(hash);
        HANDLE m = CreateMutexW(nullptr, FALSE, name.c_str());
        if (!m && GetLastError() == ERROR_ACCESS_DENIED) {
            // Fall back to Local\\ namespace if Global\\ is not allowed
            name = L"Local\\TrustTunnelRingBuffer_" + std::to_wstring(hash);
            m = CreateMutexW(nullptr, FALSE, name.c_str());
        }
        return m;
    }

    HANDLE m_mutex;
};

} // namespace ag::vpn_easy
