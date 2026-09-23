#include "pipe_name_registry.h"

#include <cwchar>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>

#include "common/defs.h"
#include "common/logger.h"
#include "common/system_error.h"
#include "trusttunnel/trusttunnel_service.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"SERVICE_PIPE_NAME"};

static constexpr wchar_t PIPE_NAME_PREFIX[] = L"\\\\.\\pipe\\trusttunnel_vpn-";
static constexpr size_t PIPE_NAME_RANDOM_BYTES = 16;
static constexpr wchar_t SERVICE_KEY_PREFIX[] = L"SYSTEM\\CurrentControlSet\\Services\\";
static constexpr wchar_t SERVICE_KEY_SUFFIX[] = L"\\Parameters";
static constexpr wchar_t PIPE_NAME_VALUE[] = L"PipeName";

using AutoRegKey = ag::UniquePtr<std::remove_pointer_t<HKEY>, &RegCloseKey>;

static std::wstring service_key_path(std::wstring_view service_name) {
    std::wstring path = SERVICE_KEY_PREFIX;
    path.append(service_name);
    path.append(SERVICE_KEY_SUFFIX);
    return path;
}

static int32_t map_registry_error(LSTATUS status) {
    return status == ERROR_ACCESS_DENIED ? TRUSTTUNNEL_SVC_ERR_ACCESS : TRUSTTUNNEL_SVC_ERR_OTHER;
}

std::optional<std::wstring> generate_pipe_name() {
    BYTE random[PIPE_NAME_RANDOM_BYTES];
    NTSTATUS status = BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) {
        errlog(g_logger, "BCryptGenRandom: {:#x}", static_cast<uint32_t>(status));
        return std::nullopt;
    }

    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::wstring name = PIPE_NAME_PREFIX;
    name.reserve(name.size() + PIPE_NAME_RANDOM_BYTES * 2);
    for (BYTE byte : random) {
        name.push_back(HEX_DIGITS[byte >> 4]);
        name.push_back(HEX_DIGITS[byte & 0xF]);
    }
    return name;
}

PipeNameRegistry::PipeNameRegistry(std::wstring_view service_name)
        : m_key_path{service_key_path(service_name)} {
}

int32_t PipeNameRegistry::publish(std::wstring_view pipe_name) const {
    HKEY raw_key = nullptr;
    LSTATUS status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, nullptr, 0, KEY_SET_VALUE, nullptr, &raw_key, nullptr);
    AutoRegKey key{raw_key};
    if (!key) {
        dbglog(g_logger, "RegCreateKeyExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }

    std::wstring value{pipe_name};
    status = RegSetValueExW(key.get(), PIPE_NAME_VALUE, 0, REG_SZ, reinterpret_cast<const BYTE *>(value.c_str()),
            static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegSetValueExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    return 0;
}

int32_t PipeNameRegistry::remove() const {
    HKEY raw_key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, KEY_SET_VALUE, &raw_key);
    if (status != ERROR_SUCCESS) {
        // The key is gone, so there is nothing left to delete.
        if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
            return 0;
        }
        dbglog(g_logger, "RegOpenKeyExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }

    AutoRegKey key{raw_key};
    status = RegDeleteValueW(key.get(), PIPE_NAME_VALUE);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        dbglog(g_logger, "RegDeleteValueW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    return 0;
}

std::optional<std::wstring> PipeNameRegistry::discover() const {
    HKEY raw_key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, KEY_QUERY_VALUE, &raw_key);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegOpenKeyExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }
    AutoRegKey key{raw_key};

    DWORD type = 0;
    DWORD size = 0;
    status = RegQueryValueExW(key.get(), PIPE_NAME_VALUE, nullptr, &type, nullptr, &size);
    if (status != ERROR_SUCCESS || type != REG_SZ || size < sizeof(wchar_t)) {
        dbglog(g_logger, "RegQueryValueExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }

    std::wstring value(size / sizeof(wchar_t), L'\0');
    status =
            RegQueryValueExW(key.get(), PIPE_NAME_VALUE, nullptr, &type, reinterpret_cast<BYTE *>(value.data()), &size);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegQueryValueExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }
    value.resize(std::wcslen(value.c_str()));
    return value;
}

} // namespace ag::trusttunnel_windows
