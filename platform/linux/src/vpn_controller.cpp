#include "src/vpn_controller.h"

#include <net/if.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <utility>

#include "common/logger.h"
#include "common/system_error.h"
#include "net/network_manager.h"
#include "net/tls.h"
#include "vpn/trusttunnel/auto_network_monitor.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"
#include "vpn/trusttunnel/connection_info.h"

namespace ag::trusttunnel_linux {

static const Logger g_logger("TRUSTTUNNELD");

std::optional<TrustTunnelConfig> parse_daemon_config(std::string_view toml_config) {
    toml::parse_result parsed = toml::parse(toml_config);
    if (!parsed) {
        errlog(g_logger, "Failed to parse TOML: {}", parsed.error().description());
        return std::nullopt;
    }
    return TrustTunnelConfig::build_config(parsed.table());
}

/// Bind an outgoing endpoint socket to the current outbound interface to avoid a route loop.
static void protect_socket(SocketProtectEvent *event) {
    uint32_t if_index = vpn_network_manager_get_outbound_interface();
    if (if_index == 0) {
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

static void verify_certificate(VpnVerifyCertificateEvent *event) {
    const char *error = tls_verify_cert(event->cert, event->chain, nullptr);
    if (error == nullptr) {
        dbglog(g_logger, "Certificate verified successfully");
        event->result = 0;
    } else {
        errlog(g_logger, "Failed to verify certificate: {}", error);
        event->result = -1;
    }
}

VpnController::VpnController(Callbacks callbacks)
        : m_callbacks(std::move(callbacks))
        , m_event_fd(AutoFd::adopt_fd(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))) {
    if (!m_event_fd.is_valid()) {
        errlog(g_logger, "Failed to create eventfd: {}", sys::strerror(errno));
    }
}

VpnController::~VpnController() {
    request_stop();
    if (m_run_thread.joinable()) {
        m_run_thread.join();
    }
}

VpnError VpnController::start(const std::string &toml_config) {
    {
        std::lock_guard lock(m_mutex);
        if (m_running) {
            return VpnError::ALREADY_RUNNING;
        }
    }

    std::optional<TrustTunnelConfig> config = parse_daemon_config(toml_config);
    if (!config.has_value()) {
        return VpnError::INVALID_CONFIG;
    }

    {
        std::lock_guard lock(m_mutex);
        m_config = std::move(*config);
        m_stop_requested = false;
        m_client_finished = false;
        m_state = VpnState::CONNECTING;
        m_running = true;
    }
    if (m_callbacks.on_state_changed) {
        // This runs on the loop thread, so the signal is emitted before Start() replies
        m_callbacks.on_state_changed(VpnState::CONNECTING);
    }

    // Any previous thread has finished on its own (m_running is false), so this returns at once
    if (m_run_thread.joinable()) {
        m_run_thread.join();
    }
    m_run_thread = std::thread(&VpnController::run, this);
    return VpnError::SUCCESS;
}

VpnError VpnController::stop() {
    {
        std::lock_guard lock(m_mutex);
        if (!m_running) {
            return VpnError::SUCCESS;
        }
        m_stop_requested = true;
    }
    m_cv.notify_all();
    return VpnError::SUCCESS;
}

VpnState VpnController::state() const {
    std::lock_guard lock(m_mutex);
    return m_state;
}

bool VpnController::running() const {
    std::lock_guard lock(m_mutex);
    return m_running;
}

void VpnController::drain() {
    // Consume the wakeup counter; the messages themselves are picked up from the queue below
    uint64_t counter = 0;
    (void) read(m_event_fd.get(), &counter, sizeof(counter));

    while (true) {
        Message message;
        {
            std::lock_guard lock(m_mutex);
            if (m_queue.empty()) {
                return;
            }
            message = std::move(m_queue.front());
            m_queue.pop_front();
        }
        if (auto *state = std::get_if<StateChangedMessage>(&message)) {
            if (m_callbacks.on_state_changed) {
                m_callbacks.on_state_changed(state->state);
            }
        } else if (auto *info = std::get_if<ConnectionInfoMessage>(&message)) {
            if (m_callbacks.on_connection_info) {
                m_callbacks.on_connection_info(info->json);
            }
        } else if (auto *network = std::get_if<NetworkReadyMessage>(&message)) {
            if (m_callbacks.on_network_ready) {
                m_callbacks.on_network_ready(*network->info);
            }
        }
    }
}

VpnCallbacks VpnController::make_client_callbacks() {
    return VpnCallbacks{
            .protect_handler =
                    [](SocketProtectEvent *event) {
                        protect_socket(event);
                    },
            .verify_handler =
                    [](VpnVerifyCertificateEvent *event) {
                        verify_certificate(event);
                    },
            .state_changed_handler =
                    [this](VpnStateChangedEvent *event) {
                        handle_state_changed(event);
                    },
            .connection_info_handler =
                    [this](VpnConnectionInfoEvent *event) {
                        handle_connection_info(event);
                    },
            .network_ready_handler =
                    [this](const VpnNetworkInfo *info) {
                        handle_network_ready(*info);
                    },
    };
}

void VpnController::run() {
    TrustTunnelConfig config;
    {
        std::lock_guard lock(m_mutex);
        config = std::move(m_config);
    }

    std::string bound_if;
    if (const auto *tun = std::get_if<TrustTunnelConfig::TunListener>(&config.listener)) {
        bound_if = tun->bound_if;
    }

    vpn_post_quantum_group_set_enabled(config.post_quantum_group_enabled);

    auto client = std::make_unique<TrustTunnelClient>(std::move(config), make_client_callbacks());
    AutoNetworkMonitor monitor(client.get(), std::move(bound_if));
    if (!monitor.start()) {
        errlog(g_logger, "Failed to start network monitor");
    } else if (auto res = client->set_system_dns()) {
        errlog(g_logger, "Failed to set system DNS: {}", res->str());
    } else if (auto res = client->connect(TrustTunnelClient::AutoSetup{}, TrustTunnelClient::ConnectOptions{})) {
        errlog(g_logger, "Failed to connect: {}", res->str());
    } else {
        // Wait until a stop is requested or the client reports the final disconnection
        std::unique_lock lock(m_mutex);
        m_cv.wait(lock, [this]() {
            return m_stop_requested || m_client_finished;
        });
    }

    monitor.stop();
    // Must happen before the client is destroyed: the destructor does not stop the VPN
    client->disconnect();
    client.reset();

    // On a failed connection attempt the client has already reported DISCONNECTED,
    // in which case this is deduplicated; on an early failure this is the final state
    push_state(VpnState::DISCONNECTED);
    {
        std::lock_guard lock(m_mutex);
        m_running = false;
    }
    m_cv.notify_all();
}

void VpnController::request_stop() {
    {
        std::lock_guard lock(m_mutex);
        m_stop_requested = true;
    }
    m_cv.notify_all();
}

void VpnController::push_state(VpnState state) {
    {
        std::lock_guard lock(m_mutex);
        if (m_state == state) {
            return;
        }
        m_state = state;
        m_queue.emplace_back(StateChangedMessage{state});
    }
    notify_event_fd();
}

void VpnController::push_message(Message message) {
    {
        std::lock_guard lock(m_mutex);
        m_queue.push_back(std::move(message));
    }
    notify_event_fd();
}

void VpnController::handle_state_changed(VpnStateChangedEvent *event) {
    auto state = static_cast<VpnState>(event->state);
    if (state == VpnState::DISCONNECTED && event->error.code != 0) {
        errlog(g_logger, "Disconnected with error: {} {}", event->error.code, safe_to_string_view(event->error.text));
    }
    push_state(state);
    if (state == VpnState::DISCONNECTED) {
        {
            std::lock_guard lock(m_mutex);
            m_client_finished = true;
        }
        m_cv.notify_all();
    }
}

void VpnController::handle_connection_info(VpnConnectionInfoEvent *event) {
    push_message(ConnectionInfoMessage{ConnectionInfo::to_json(event)});
}

void VpnController::handle_network_ready(const VpnNetworkInfo &info) {
    infolog(g_logger, "Network ready: iface={} mtu={}", info.iface_name, info.mtu);
    push_message(NetworkReadyMessage{std::make_shared<VpnNetworkInfo>(info)});
}

void VpnController::notify_event_fd() {
    uint64_t wakeup = 1;
    // The only possible failure is EAGAIN when the counter is about to overflow, which
    // still means a wakeup is pending, so the result can be safely ignored
    (void) write(m_event_fd.get(), &wakeup, sizeof(wakeup));
}

} // namespace ag::trusttunnel_linux
