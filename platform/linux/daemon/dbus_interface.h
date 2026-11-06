#pragma once

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
