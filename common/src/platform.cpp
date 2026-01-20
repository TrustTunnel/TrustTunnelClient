#include <cstring>
#include <string>
#include <vector>

#include "common/utils.h"
#include "vpn/platform.h"

#ifdef _WIN32
#include <winver.h>
#endif

namespace ag::sys {

#ifdef _WIN32

static size_t get_wide_error_message(DWORD code, wchar_t *dst, size_t dst_cap) {
    DWORD n = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK,
            nullptr, code, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPWSTR) dst, DWORD(dst_cap), nullptr);
    if (n == 0) {
        return 0;
    }
    if (n > 2 && dst[n - 2] == '.' && dst[n - 1] == ' ') {
        n -= 2;
    }

    return n;
}

static std::string get_error_message(DWORD code) {
    wchar_t w[255];
    size_t n = get_wide_error_message(code, w, std::size(w));
    return utils::from_wstring({w, n});
}

int last_error() {
    return int(GetLastError());
}

const char *strerror(int code) {
    static thread_local char buffer[255];
    std::string str = get_error_message(DWORD(code));
    size_t len = std::min(str.length(), std::size(buffer) - 1);
    std::memcpy(buffer, str.data(), len);
    buffer[len] = '\0';
    return buffer;
}

bool is_windows_11_or_greater() {
    constexpr DWORD WIN11_MAJOR_VERSION = HIBYTE(_WIN32_WINNT_WIN10);
    constexpr DWORD WIN11_MINOR_VERSION = LOBYTE(_WIN32_WINNT_WIN10);
    constexpr DWORD FIRST_WIN11_BUILD_NUMBER = 22000;
    constexpr const wchar_t *SYSTEM = L"kernel32.dll";

    DWORD dummy;
    DWORD file_ver_buffer_size = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, SYSTEM, &dummy);
    if (file_ver_buffer_size <= 0) {
        return false;
    }

    std::vector<uint8_t> file_ver_buffer(file_ver_buffer_size);
    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, SYSTEM, dummy, file_ver_buffer.size(), file_ver_buffer.data())) {
        return false;
    }

    void *value = nullptr;
    UINT value_size = 0;
    if (!VerQueryValueW(file_ver_buffer.data(), L"\\", &value, &value_size)) {
        return false;
    }
    if (value_size < sizeof(VS_FIXEDFILEINFO)) {
        return false;
    }

    const auto *info = (VS_FIXEDFILEINFO *) value;
    return WIN11_MAJOR_VERSION <= HIWORD(info->dwFileVersionMS) && WIN11_MINOR_VERSION <= LOWORD(info->dwFileVersionMS)
            && FIRST_WIN11_BUILD_NUMBER <= HIWORD(info->dwFileVersionLS);
}

#endif //_WIN32

#if defined __MACH__ || defined __linux__

int last_error() {
    return errno;
}

const char *strerror(int code) {
    return ::strerror(code);
}

#endif

} // namespace ag::sys
