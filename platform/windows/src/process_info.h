#pragma once

#include <optional>
#include <string>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "common/defs.h"

namespace ag::trusttunnel_windows {

/** Identity information about a process. */
class ProcessInfo {
public:
    /**
     * Resolve the calling process. Returns `std::nullopt` when its image path cannot be resolved.
     */
    static std::optional<ProcessInfo> current();

    /**
     * Resolve the borrowed `process` handle. Returns `std::nullopt` when its image path cannot be
     * resolved.
     */
    static std::optional<ProcessInfo> from_process(HANDLE process);

    /** Construct from an already-known image path. */
    explicit ProcessInfo(std::wstring image_path)
            : m_image_path{std::move(image_path)} {
    }

    /** Full image path of the process executable. */
    const std::wstring &image_path() const {
        return m_image_path;
    }

private:
    std::wstring m_image_path;
};

/**
 * The executable file of a process, held open without write and delete sharing. While it is held,
 * neither the file nor any directory above it can be renamed, deleted, or written, so the file is
 * pinned at `path()` and its content can be verified without a race.
 */
class LockedImage {
public:
    /**
     * Lock the executable of the process at the client end of an accepted pipe connection.
     * Returns `std::nullopt` when the process cannot be resolved or its image cannot be locked.
     */
    static std::optional<LockedImage> of_pipe_client(HANDLE pipe);

    /**
     * Lock the file at `path`, which must be the executable of the borrowed `process` handle.
     * Returns `std::nullopt` when the file cannot be opened without write and delete sharing, the
     * path resolves to a file at another location, or the image path of the process changes.
     */
    static std::optional<LockedImage> lock(HANDLE process, std::wstring path);

    /** Image path of the process, at which the locked file is located. */
    const std::wstring &path() const {
        return m_path;
    }

    /** Open handle to the locked file. */
    HANDLE file() const {
        return m_file.get();
    }

private:
    LockedImage(std::wstring path, ag::UniquePtr<void, &CloseHandle> file)
            : m_path{std::move(path)}
            , m_file{std::move(file)} {
    }

    std::wstring m_path;
    ag::UniquePtr<void, &CloseHandle> m_file;
};

} // namespace ag::trusttunnel_windows
