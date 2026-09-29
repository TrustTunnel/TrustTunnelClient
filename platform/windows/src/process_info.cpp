#include "process_info.h"

#include <string_view>

#include "common/defs.h"
#include "common/logger.h"
#include "common/system_error.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"PROCESS_INFO"};

static bool is_same_path(const std::wstring &first, const std::wstring &second) {
    return CompareStringOrdinal(
                   first.c_str(), static_cast<int>(first.size()), second.c_str(), static_cast<int>(second.size()), TRUE)
            == CSTR_EQUAL;
}

/// Return the path `file` was opened by, after reparse points, in the form `QueryFullProcessImageNameW` reports.
static std::optional<std::wstring> opened_path(HANDLE file) {
    // `FILE_NAME_OPENED` keeps 8.3 components as opened, as the image path does; a normalized name would expand them.
    static constexpr DWORD FLAGS = FILE_NAME_OPENED | VOLUME_NAME_DOS;
    std::wstring path(MAX_PATH, L'\0');
    for (;;) {
        DWORD len = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()), FLAGS);
        if (len == 0) {
            dbglog(g_logger, "GetFinalPathNameByHandleW: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
            return std::nullopt;
        }
        if (len < path.size()) {
            path.resize(len);
            break;
        }
        path.resize(len);
    }
    static constexpr std::wstring_view LONG_PATH_PREFIX = L"\\\\?\\";
    if (path.starts_with(LONG_PATH_PREFIX)) {
        path.erase(0, LONG_PATH_PREFIX.size());
    }
    return path;
}

std::optional<ProcessInfo> ProcessInfo::current() {
    return from_process(GetCurrentProcess());
}

std::optional<ProcessInfo> ProcessInfo::from_process(HANDLE process) {
    std::wstring image_path;
    DWORD buf_size = MAX_PATH;
    for (;;) {
        image_path.resize(buf_size);
        // `QueryFullProcessImageNameW` does not report the required size on failure, so a
        // too-small buffer is the retry signal and the size must be grown by the caller.
        DWORD len = buf_size;
        if (QueryFullProcessImageNameW(process, 0, image_path.data(), &len)) {
            image_path.resize(len);
            return ProcessInfo{std::move(image_path)};
        }
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            dbglog(g_logger, "QueryFullProcessImageNameW: {} ({})", err, ag::sys::strerror(err));
            return std::nullopt;
        }
        buf_size *= 2;
    }
}

std::optional<LockedImage> LockedImage::of_pipe_client(HANDLE pipe) {
    DWORD pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) {
        dbglog(g_logger, "GetNamedPipeClientProcessId: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return std::nullopt;
    }
    ag::UniquePtr<void, &CloseHandle> process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process) {
        dbglog(g_logger, "OpenProcess({}): {} ({})", pid, GetLastError(), ag::sys::strerror(GetLastError()));
        return std::nullopt;
    }
    std::optional<ProcessInfo> info = ProcessInfo::from_process(process.get());
    if (!info.has_value()) {
        return std::nullopt;
    }
    return lock(process.get(), info->image_path());
}

std::optional<LockedImage> LockedImage::lock(HANDLE process, std::wstring path) {
    HANDLE raw_file = CreateFileW(
            path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (raw_file == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        warnlog(g_logger, "Image cannot be locked, it may be open for writing or deletion: {} ({})", err,
                ag::sys::strerror(err));
        return std::nullopt;
    }
    ag::UniquePtr<void, &CloseHandle> file{raw_file};

    // The locked file stays at its opened path, so the image having that path proves they are the same file.
    std::optional<std::wstring> locked_path = opened_path(file.get());
    if (!locked_path.has_value() || !is_same_path(*locked_path, path)) {
        warnlog(g_logger, "Image path resolves to a file at another location");
        return std::nullopt;
    }
    std::optional<ProcessInfo> current = ProcessInfo::from_process(process);
    if (!current.has_value() || !is_same_path(current->image_path(), path)) {
        warnlog(g_logger, "Image was renamed while being locked");
        return std::nullopt;
    }
    return LockedImage{std::move(path), std::move(file)};
}

} // namespace ag::trusttunnel_windows
