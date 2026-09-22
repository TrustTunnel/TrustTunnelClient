#pragma once

#include <optional>
#include <string>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace ag::trusttunnel_windows {

/** Identity information about a process. */
class ProcessInfo {
public:
    /**
     * Resolve the process at the client end of an accepted named-pipe connection. Returns
     * `std::nullopt` when the client PID cannot be obtained, the process cannot be opened, or its
     * image path cannot be resolved.
     */
    static std::optional<ProcessInfo> from_pipe(HANDLE pipe);

    /**
     * Resolve the calling process. Returns `std::nullopt` when its image path cannot be resolved.
     */
    static std::optional<ProcessInfo> current();

    /** Construct from an already-known image path. */
    explicit ProcessInfo(std::wstring image_path)
            : m_image_path{std::move(image_path)} {
    }

    /** Full image path of the process executable. */
    const std::wstring &image_path() const {
        return m_image_path;
    }

private:
    /** Resolve the borrowed `process` handle into a `ProcessInfo`; `std::nullopt` on failure. */
    static std::optional<ProcessInfo> from_process(HANDLE process);

    std::wstring m_image_path;
};

} // namespace ag::trusttunnel_windows
