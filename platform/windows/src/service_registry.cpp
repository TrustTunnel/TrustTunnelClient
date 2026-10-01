#include "service_registry.h"

#include <cstring>
#include <cwchar>
#include <utility>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <sddl.h>

#include "common/defs.h"
#include "common/logger.h"
#include "common/system_error.h"
#include "trusttunnel/trusttunnel_service.h"

namespace ag::trusttunnel_windows {

static ag::Logger g_logger{"SERVICE_REGISTRY"};

static constexpr wchar_t SERVICES_KEY[] = L"SYSTEM\\CurrentControlSet\\Services\\";
static constexpr wchar_t PARAMETERS_SUBKEY[] = L"\\Parameters";
static constexpr wchar_t PIPE_NAME_VALUE[] = L"PipeName";
static constexpr wchar_t SAVED_CONFIG_SUBKEY[] = L"\\SavedConfig";
static constexpr wchar_t SAVED_CONFIG_VALUE[] = L"Config";
// Protected (`P`), so the parent key's Authenticated Users read access is not inherited.
static constexpr wchar_t ADMINS_ONLY_SDDL[] = L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)";

using AutoRegKey = ag::UniquePtr<std::remove_pointer_t<HKEY>, &RegCloseKey>;
using AutoSecurityDescriptor = ag::UniquePtr<SECURITY_DESCRIPTOR, &LocalFree>;

static int32_t map_registry_error(LSTATUS status) {
    return status == ERROR_ACCESS_DENIED ? TRUSTTUNNEL_SVC_ERR_ACCESS : TRUSTTUNNEL_SVC_ERR_OTHER;
}

RegistryValue::RegistryValue(std::wstring key_path, std::wstring name, KeyAccess access)
        : m_key_path{std::move(key_path)}
        , m_name{std::move(name)}
        , m_access{access} {
}

int32_t RegistryValue::write_string(std::wstring_view value) const {
    std::wstring terminated{value};
    return write(REG_SZ, terminated.c_str(), (terminated.size() + 1) * sizeof(wchar_t));
}

std::optional<std::wstring> RegistryValue::read_string() const {
    std::optional<std::string> bytes = read(REG_SZ);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    if (bytes->size() % sizeof(wchar_t) != 0) {
        dbglog(g_logger, "Ignoring a string value of {} bytes", bytes->size());
        return std::nullopt;
    }

    std::wstring value(bytes->size() / sizeof(wchar_t), L'\0');
    std::memcpy(value.data(), bytes->data(), bytes->size());
    // A stored string may lack the terminating NUL or carry several.
    value.resize(std::wcslen(value.c_str()));
    return value;
}

int32_t RegistryValue::write_binary(std::string_view value) const {
    return write(REG_BINARY, value.data(), value.size());
}

std::optional<std::string> RegistryValue::read_binary() const {
    return read(REG_BINARY);
}

int32_t RegistryValue::remove() const {
    HKEY raw_key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, KEY_SET_VALUE, &raw_key);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) {
        return 0;
    }
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegOpenKeyExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    AutoRegKey key{raw_key};

    status = RegDeleteValueW(key.get(), m_name.c_str());
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) {
        dbglog(g_logger, "RegDeleteValueW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    return 0;
}

int32_t RegistryValue::write(uint32_t type, const void *data, size_t size) const {
    const bool admins_only = m_access == KeyAccess::ADMINS_ONLY;
    AutoSecurityDescriptor descriptor;
    if (admins_only) {
        PSECURITY_DESCRIPTOR raw_descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    ADMINS_ONLY_SDDL, SDDL_REVISION_1, &raw_descriptor, nullptr)) {
            DWORD error = GetLastError();
            dbglog(g_logger, "ConvertStringSecurityDescriptorToSecurityDescriptorW: {} ({})", error,
                    ag::sys::strerror(error));
            return TRUSTTUNNEL_SVC_ERR_OTHER;
        }
        descriptor.reset(static_cast<SECURITY_DESCRIPTOR *>(raw_descriptor));
    }

    // Applied at creation, so a new key is never readable through an inherited DACL.
    SECURITY_ATTRIBUTES security{.nLength = sizeof(security), .lpSecurityDescriptor = descriptor.get()};
    HKEY raw_key = nullptr;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, nullptr, 0,
            KEY_SET_VALUE | (admins_only ? WRITE_DAC : 0), &security, &raw_key, nullptr);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegCreateKeyExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    AutoRegKey key{raw_key};

    // Creation ignores the security attributes of an existing key.
    if (admins_only) {
        status = RegSetKeySecurity(key.get(), DACL_SECURITY_INFORMATION, descriptor.get());
        if (status != ERROR_SUCCESS) {
            dbglog(g_logger, "RegSetKeySecurity: {} ({})", status, ag::sys::strerror(status));
            return map_registry_error(status);
        }
    }

    status = RegSetValueExW(
            key.get(), m_name.c_str(), 0, type, static_cast<const BYTE *>(data), static_cast<DWORD>(size));
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegSetValueExW: {} ({})", status, ag::sys::strerror(status));
        return map_registry_error(status);
    }
    return 0;
}

std::optional<std::string> RegistryValue::read(uint32_t type) const {
    HKEY raw_key = nullptr;
    LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, m_key_path.c_str(), 0, KEY_QUERY_VALUE, &raw_key);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegOpenKeyExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }
    AutoRegKey key{raw_key};

    DWORD actual_type = 0;
    DWORD size = 0;
    status = RegQueryValueExW(key.get(), m_name.c_str(), nullptr, &actual_type, nullptr, &size);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegQueryValueExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }
    if (actual_type != type) {
        dbglog(g_logger, "Ignoring a value of type {}, expected {}", actual_type, type);
        return std::nullopt;
    }

    std::string value(size, '\0');
    status = RegQueryValueExW(
            key.get(), m_name.c_str(), nullptr, nullptr, reinterpret_cast<BYTE *>(value.data()), &size);
    if (status != ERROR_SUCCESS) {
        dbglog(g_logger, "RegQueryValueExW: {} ({})", status, ag::sys::strerror(status));
        return std::nullopt;
    }
    value.resize(size);
    return value;
}

ServiceRegistry::ServiceRegistry(std::wstring_view service_name)
        : m_parameters_path{std::wstring{SERVICES_KEY}.append(service_name).append(PARAMETERS_SUBKEY)} {
}

RegistryValue ServiceRegistry::pipe_name() const {
    return {m_parameters_path, PIPE_NAME_VALUE, RegistryValue::KeyAccess::INHERITED};
}

RegistryValue ServiceRegistry::saved_config() const {
    return {m_parameters_path + SAVED_CONFIG_SUBKEY, SAVED_CONFIG_VALUE, RegistryValue::KeyAccess::ADMINS_ONLY};
}

} // namespace ag::trusttunnel_windows
