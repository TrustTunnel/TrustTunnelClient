#include "src/vpn_controller.h"

#include <iostream>

namespace ag::trusttunnel_linux {

static constexpr uint32_t CONNECT_SIMULATION_DELAY_MS = 1500;
static constexpr uint32_t CONNECTION_INFO_INTERVAL_MS = 5000;

VpnController::VpnController(TimerScheduler scheduler, Callbacks callbacks)
        : m_scheduler(std::move(scheduler))
        , m_callbacks(std::move(callbacks)) {
}

VpnError VpnController::start(const std::string &toml_config) {
    if (m_state == VpnState::CONNECTING || m_state == VpnState::CONNECTED) {
        return VpnError::ALREADY_RUNNING;
    }
    if (toml_config.empty()) {
        return VpnError::INVALID_CONFIG;
    }

    m_session_id++;
    m_connection_counter = 0;
    const uint64_t current_session = m_session_id;

    transition_to(VpnState::CONNECTING);

    // Simulate connection delay
    m_scheduler(CONNECT_SIMULATION_DELAY_MS, [this, current_session]() {
        if (m_session_id != current_session || m_state != VpnState::CONNECTING) {
            return;
        }
        transition_to(VpnState::CONNECTED);
        schedule_next_connection_info(current_session);
    });

    return VpnError::SUCCESS;
}

VpnError VpnController::stop() {
    if (m_state == VpnState::DISCONNECTED) {
        return VpnError::SUCCESS;
    }

    // Invalidate pending timers by advancing session id
    m_session_id++;
    transition_to(VpnState::DISCONNECTED);
    return VpnError::SUCCESS;
}

void VpnController::transition_to(VpnState new_state) {
    if (m_state == new_state) {
        return;
    }
    m_state = new_state;
    if (m_callbacks.on_state_changed) {
        m_callbacks.on_state_changed(m_state);
    }
}

void VpnController::schedule_next_connection_info(uint64_t current_session) {
    m_scheduler(CONNECTION_INFO_INTERVAL_MS, [this, current_session]() {
        if (m_session_id != current_session || m_state != VpnState::CONNECTED) {
            return;
        }

        m_connection_counter++;
        if (m_callbacks.on_connection_info) {
            // Simulated connection record JSON
            std::string json = "{\"id\":" + std::to_string(m_connection_counter)
                    + ",\"host\":\"example.org\",\"protocol\":\"TCP\",\"bytes_in\":1024,\"bytes_out\":512}";
            m_callbacks.on_connection_info(json);
        }

        // Schedule subsequent events periodically
        schedule_next_connection_info(current_session);
    });
}

} // namespace ag::trusttunnel_linux
