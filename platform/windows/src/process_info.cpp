#include "process_info.h"

#include "common/defs.h"
#include "common/logger.h"
#include "common/system_error.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"PROCESS_INFO"};

std::optional<ProcessInfo> ProcessInfo::from_pipe(HANDLE pipe) {
    DWORD pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) {
        dbglog(g_logger, "GetNamedPipeClientProcessId: {} ({})", GetLastError(), ag::sys::strerror(GetLastError()));
        return std::nullopt;
    }

    // The handle is only needed to resolve the image path, so it is closed before returning.
    ag::UniquePtr<void, &CloseHandle> process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!process) {
        dbglog(g_logger, "OpenProcess({}): {} ({})", pid, GetLastError(), ag::sys::strerror(GetLastError()));
        return std::nullopt;
    }
    return from_process(process.get());
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

} // namespace ag::trusttunnel_windows
