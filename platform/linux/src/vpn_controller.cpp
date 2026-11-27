#include "src/vpn_controller.h"

#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <exception>
#include <utility>
#include <variant>

#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "common/system_error.h"
#include "net/network_manager.h"
#include "net/tls.h"
#include "vpn/trusttunnel/connection_info.h"
#include "vpn/utils.h"

namespace ag::trusttunnel_linux {

static const Logger g_logger("TRUSTTUNNEL");

void VpnController::protect_socket(SocketProtectEvent *event) {
    uint32_t if_index = vpn_network_manager_get_outbound_interface();
    if (if_index == 0) {
        // There is no known outbound interface: when the tunnel is already active, an unprotected
        // socket would route through it and loop back into the tunnel.
        if (vpn_network_manager_get_tunnel_active()) {
            event->result = -1;
        }
        return;
    }
    char if_name[IF_NAMESIZE]{};
    if (if_indextoname(if_index, if_name) == nullptr) {
        errlog(g_logger, "Failed to resolve outbound interface name for index {}", if_index);
        event->result = -1;
        return;
    }
    std::string name{if_name};
    if (setsockopt(event->fd, SOL_SOCKET, SO_BINDTODEVICE, name.data(), static_cast<socklen_t>(name.size())) != 0) {
        errlog(g_logger, "Failed to bind socket to {}: {}", name, sys::strerror(errno));
        event->result = -1;
    }
}

void VpnController::verify_certificate(VpnVerifyCertificateEvent *event) {
    const char *error = tls_verify_cert(event->cert, event->chain, nullptr);
    if (error == nullptr) {
        dbglog(g_logger, "Certificate verified successfully");
        event->result = 0;
    } else {
        errlog(g_logger, "Failed to verify certificate: {}", error);
        event->result = -1;
    }
}

VpnCallbacks VpnController::make_client_callbacks(bool protect_sockets) {
    // Binding sockets to the outbound interface only makes sense when a TUN device is managed; in SOCKS
    // mode it would add an unexpected SO_BINDTODEVICE to every outgoing socket.
    return VpnCallbacks{
            .protect_handler = protect_sockets
                    ? std::function<void(SocketProtectEvent *)>{[this](SocketProtectEvent *event) {
                          protect_socket(event);
                      }}
                    : std::function<void(SocketProtectEvent *)>{},
            .verify_handler =
                    [this](VpnVerifyCertificateEvent *event) {
                        verify_certificate(event);
                    },
            .state_changed_handler =
                    [this](VpnStateChangedEvent *event) {
                        infolog(g_logger, "VPN state changed: {}", magic_enum::enum_name(event->state));
                        if (m_callbacks.on_state_changed) {
                            m_callbacks.on_state_changed(static_cast<int>(event->state));
                        }
                    },
            .connection_info_handler =
                    [this](VpnConnectionInfoEvent *event) {
                        if (m_callbacks.on_connection_info) {
                            m_callbacks.on_connection_info(ConnectionInfo::to_json(event));
                        }
                    },
    };
}

bool VpnController::start(TrustTunnelConfig &&config, bool fall_into_recovery) {
    // `start()` may be called on a controller that already owns a session; tear it down first so the
    // previous client is disconnected instead of leaking a live session with callbacks bound to `this`.
    stop();

    const bool protect_sockets = std::holds_alternative<TrustTunnelConfig::TunListener>(config.listener);

    std::string bound_if;
    if (const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener)) {
        bound_if = tun->bound_if;
    }

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    m_client = std::make_unique<TrustTunnelClient>(std::move(config), make_client_callbacks(protect_sockets));
    m_monitor = std::make_unique<AutoNetworkMonitor>(m_client.get(), std::move(bound_if));
    if (!m_monitor->start()) {
        errlog(g_logger, "Failed to start network monitor");
        stop();
        return false;
    }

    if (auto res = m_client->set_system_dns()) {
        errlog(g_logger, "Failed to set system DNS: {}", res->str());
        stop();
        return false;
    }

    auto res = m_client->connect(TrustTunnelClient::AutoSetup{},
            TrustTunnelClient::ConnectOptions{.fall_into_recovery = fall_into_recovery});
    if (res) {
        errlog(g_logger, "Failed to connect: {}", res->str());
        stop();
        return false;
    }
    return true;
}

void VpnController::stop() {
    // `stop()` runs from destructors (`~VpnController`, `trusttunnel_stop_ex`): an exception escaping
    // here would call `std::terminate` through the noexcept destructor instead of reaching any caller.
    try {
        if (m_monitor) {
            m_monitor->stop();
        }
        if (m_client) {
            // Must happen before the client is destroyed: the destructor does not stop the VPN
            m_client->disconnect();
        }
        m_client.reset();
        m_monitor.reset();
    } catch (const std::exception &e) {
        errlog(g_logger, "Exception while stopping the VPN session: {}", e.what());
    } catch (...) {
        errlog(g_logger, "Unknown exception while stopping the VPN session");
    }
}

VpnController::VpnController(Callbacks callbacks)
        : m_callbacks(std::move(callbacks)) {
}

VpnController::~VpnController() {
    stop();
}

} // namespace ag::trusttunnel_linux
