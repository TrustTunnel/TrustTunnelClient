#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ag::trusttunnel_windows {

/**
 * Generate a fresh named-pipe name of the form `\\.\pipe\trusttunnel_vpn-<32 hex>` using the OS
 * cryptographic RNG. Returns `std::nullopt` when the RNG fails.
 */
std::optional<std::wstring> generate_pipe_name();

/**
 * Registry storage of a service's pipe name, under the service's own key
 * (`HKLM\SYSTEM\CurrentControlSet\Services\<service_name>\Parameters\PipeName`). The service name
 * is bound once, so publish, remove, and discover cannot disagree on the key.
 */
class PipeNameRegistry {
public:
    /** Bind to the service whose key stores the pipe name. */
    explicit PipeNameRegistry(std::wstring_view service_name);

    /** Publish `pipe_name` under the service's key. Returns zero or a `TrusttunnelServiceError`. */
    int32_t publish(std::wstring_view pipe_name) const;

    /**
     * Delete the published pipe name. A missing key or value is a success, so this is idempotent.
     * Returns zero or a `TrusttunnelServiceError`.
     */
    int32_t remove() const;

    /**
     * Read the published pipe name. Returns `std::nullopt` on any failure (missing key or value,
     * wrong value type, access denied, or another registry error).
     */
    std::optional<std::wstring> discover() const;

private:
    std::wstring m_key_path;
};

} // namespace ag::trusttunnel_windows
