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
    RegistryValue(std::wstring key_path, std::wstring name);

    /** Store `value` as `REG_SZ`. */
    int32_t write_string(std::wstring_view value) const;

    /** Read a `REG_SZ` value. */
    std::optional<std::wstring> read_string() const;

    /** Delete the value. A missing key or value is a success, so this is idempotent. */
    int32_t remove() const;

private:
    int32_t write(uint32_t type, const void *data, size_t size) const;
    std::optional<std::string> read(uint32_t type) const;

    std::wstring m_key_path;
    std::wstring m_name;
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

private:
    std::wstring m_parameters_path;
};

} // namespace ag::trusttunnel_windows
