#pragma once

#include <cstdint>

namespace ag::trusttunnel_linux {

// D-Bus service, object path and interface identifiers
inline constexpr const char *BUS_NAME = "com.adguard.TrustTunnel";
inline constexpr const char *OBJECT_PATH = "/com/adguard/TrustTunnel";
inline constexpr const char *INTERFACE_NAME = "com.adguard.TrustTunnel.Vpn1";

// D-Bus method names
inline constexpr const char *METHOD_START = "Start";
inline constexpr const char *METHOD_STOP = "Stop";
inline constexpr const char *METHOD_GET_STATE = "GetState";
inline constexpr const char *METHOD_CLEAR_LOGS = "ClearLogs";

// D-Bus signal names
inline constexpr const char *SIGNAL_STATE_CHANGED = "StateChanged";
inline constexpr const char *SIGNAL_CONNECTION_INFO = "ConnectionInfo";
inline constexpr const char *SIGNAL_NETWORK_READY = "NetworkReady";

// VPN session state. The values mirror `ag::VpnSessionState` 1:1, so the mapping
// to/from the library enum is a plain static_cast.
enum class VpnState : int32_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    CONNECTED = 2,
    WAITING_RECOVERY = 3,
    RECOVERING = 4,
    WAITING_FOR_NETWORK = 5,
};

// Error codes returned by Start/Stop methods
enum class VpnError : uint32_t {
    SUCCESS = 0,
    ALREADY_RUNNING = 1,
    INVALID_CONFIG = 2,
};

} // namespace ag::trusttunnel_linux
