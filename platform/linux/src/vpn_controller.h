#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "src/dbus_interface.h"

namespace ag::trusttunnel_linux {

// Simple callback for timer scheduling: run fn after delay_ms.
using TimerScheduler = std::function<void(uint32_t delay_ms, std::function<void()> fn)>;

/**
 * High-level VPN controller and state machine simulation.
 * In a production implementation, this is where ag::TrustTunnelClient is plugged in.
 */
class VpnController {
public:
    struct Callbacks {
        std::function<void(VpnState new_state)> on_state_changed;
        std::function<void(const std::string &json_info)> on_connection_info;
    };

    explicit VpnController(TimerScheduler scheduler, Callbacks callbacks);
    ~VpnController() = default;

    // Start connection attempt with the provided TOML config.
    VpnError start(const std::string &toml_config);

    // Stop active connection or connection attempt.
    VpnError stop();

    // Query current state.
    VpnState state() const {
        return m_state;
    }

private:
    void transition_to(VpnState state);
    void schedule_next_connection_info(uint64_t current_session_id);

    TimerScheduler m_scheduler;
    Callbacks m_callbacks;
    VpnState m_state = VpnState::DISCONNECTED;
    uint64_t m_session_id = 0;
    uint64_t m_connection_counter = 0;
};

} // namespace ag::trusttunnel_linux
