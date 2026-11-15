#pragma once

#include <cstdint>

namespace ag::trusttunnel_linux {

// VPN session state. The values mirror `ag::VpnSessionState` 1:1 (and the public
// `trusttunnel_vpn_state_t` C enum), so the mapping to/from the library enum is a plain
// static_cast.
enum class VpnState : int32_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    CONNECTED = 2,
    WAITING_RECOVERY = 3,
    RECOVERING = 4,
    WAITING_FOR_NETWORK = 5,
};

// Error codes returned by Start/Stop operations. The values mirror the public
// `trusttunnel_vpn_error_t` C enum.
enum class VpnError : uint32_t {
    SUCCESS = 0,
    ALREADY_RUNNING = 1,
    INVALID_CONFIG = 2,
};

} // namespace ag::trusttunnel_linux
