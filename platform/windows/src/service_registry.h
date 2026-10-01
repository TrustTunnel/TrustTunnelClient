#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ag::trusttunnel_windows {

/**
 * A named value under a key of `HKEY_LOCAL_MACHINE`. The key is created on the first write.
 * Writes and removal return zero or a `TrusttunnelServiceError`. Reads return `std::nullopt` on
 * any failure (missing key or value, wrong value type or size, access denied, or another registry
 * error).
 */
class RegistryValue {
public:
    /** Who may access the key that holds the value. */
    enum class KeyAccess {
        /** Keep the DACL inherited from the parent key. */
        INHERITED,
        /** Grant full control to SYSTEM and Administrators only. Use it for values holding credentials. */
        ADMINS_ONLY,
    };

    RegistryValue(std::wstring key_path, std::wstring name, KeyAccess access);

    /** Store `value` as `REG_SZ`. */
    int32_t write_string(std::wstring_view value) const;

    /** Read a `REG_SZ` value. */
    std::optional<std::wstring> read_string() const;

    /** Store `value` as `REG_BINARY`. */
    int32_t write_binary(std::string_view value) const;

    /** Read a `REG_BINARY` value. */
    std::optional<std::string> read_binary() const;

    /** Delete the value. A missing key or value is a success, so this is idempotent. */
    int32_t remove() const;

private:
    int32_t write(uint32_t type, const void *data, size_t size) const;
    std::optional<std::string> read(uint32_t type) const;

    std::wstring m_key_path;
    std::wstring m_name;
    KeyAccess m_access;
};

/**
 * The values a service keeps under its own key,
 * `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>\Parameters`.
 */
class ServiceRegistry {
public:
    explicit ServiceRegistry(std::wstring_view service_name);

    /** The pipe name the running service listens on. Any authenticated user can read it. */
    RegistryValue pipe_name() const;

    /**
     * The saved VPN configuration in TOML format the service auto-connects with. It holds the
     * endpoint credentials, so it lives in a subkey only SYSTEM and Administrators can access.
     */
    RegistryValue saved_config() const;

private:
    std::wstring m_parameters_path;
};

} // namespace ag::trusttunnel_windows
