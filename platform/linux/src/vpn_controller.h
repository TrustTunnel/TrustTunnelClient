#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include "common/autofd.h"
#include "src/vpn_types.h"
#include "vpn/trusttunnel/client.h"
#include "vpn/trusttunnel/config.h"

namespace ag::trusttunnel_linux {

/**
 * Parse a daemon configuration from a TOML document.
 * @return the parsed configuration, or `std::nullopt` if the document is not a valid configuration
 */
std::optional<ag::TrustTunnelConfig> parse_daemon_config(std::string_view toml_config);

/**
 * Strip privileged `[listener.tun]` fields from a client-supplied configuration.
 * `netns` lets an unprivileged caller direct the daemon's root-level `ip` commands at
 * an arbitrary network namespace, and `use_existing` makes it operate on an arbitrary
 * existing interface. `netns` is removed, `use_existing` is reset to false; every other
 * field is left untouched. Documents that do not parse are returned unchanged: the
 * regular validation reports the parse error.
 */
std::string sanitize_daemon_config(std::string_view toml_config);

/**
 * Owns the TrustTunnel client and bridges it to the single-threaded D-Bus event loop.
 *
 * The client invokes the callbacks from its own threads, so the callbacks only put messages
 * into a thread-safe queue and wake the loop thread through an eventfd: the loop thread drains
 * the queue (see `drain()`) and emits the D-Bus signals.
 *
 * The client lifecycle runs on a dedicated thread (see `run()`), modelled after the CLI client:
 * `AutoNetworkMonitor` + `set_system_dns()` + `connect()`, then wait for a stop request or a
 * client-reported disconnection, then a blocking `disconnect()` before the client is destroyed.
 */
class VpnController {
public:
    struct Callbacks {
        /// Called on the loop thread when the VPN session state changes
        std::function<void(VpnState new_state)> on_state_changed;
        /// Called on the loop thread with a JSON connection record
        std::function<void(const std::string &json_info)> on_connection_info;
        /// Called on the loop thread once the tunnel device is ready
        std::function<void(const ag::VpnNetworkInfo &info)> on_network_ready;
    };

    explicit VpnController(Callbacks callbacks);
    ~VpnController();

    VpnController(const VpnController &) = delete;
    VpnController &operator=(const VpnController &) = delete;

    /**
     * Start a connection with the provided TOML configuration.
     * Parses the configuration synchronously (INVALID_CONFIG on failure), reports the
     * CONNECTING state through the callback queue and spawns the client thread. May be called
     * again once a previous session has finished on its own.
     */
    VpnError start(const std::string &toml_config);

    /**
     * Request a stop of the active session. Does not block: the final DISCONNECTED state
     * arrives through the queue once the client thread has torn the client down.
     */
    VpnError stop();

    /// Last known VPN state. Reflects enqueued transitions immediately.
    VpnState state() const;

    /// True while the client thread is running (including the teardown after a stop request).
    bool running() const;

    /// False if the controller could not allocate its eventfd, in which case it cannot
    /// deliver any events and `trusttunnel_create()` rejects the instance.
    bool valid() const {
        return m_event_fd.is_valid();
    }

    /// The eventfd that gets written whenever a new message is queued. Read it with `drain()`.
    int event_fd() const {
        return m_event_fd.get();
    }

    /// Drain queued messages, invoking the corresponding callbacks. Must be called on the
    /// loop thread whenever `event_fd()` is readable.
    void drain();

private:
    /// Messages passed from client threads to the loop thread
    struct StateChangedMessage {
        VpnState state;
    };
    struct ConnectionInfoMessage {
        std::string json;
    };
    struct NetworkReadyMessage {
        std::shared_ptr<const ag::VpnNetworkInfo> info;
    };
    using Message = std::variant<StateChangedMessage, ConnectionInfoMessage, NetworkReadyMessage>;

    void run();
    void request_stop();
    /// Assemble the callbacks handed over to the client
    ag::VpnCallbacks make_client_callbacks();
    /// Record a state transition and queue a notification unless it repeats the previous state
    void push_state(VpnState state);
    void push_message(Message message);
    void handle_state_changed(ag::VpnStateChangedEvent *event);
    void handle_connection_info(ag::VpnConnectionInfoEvent *event);
    void handle_network_ready(const ag::VpnNetworkInfo &info);
    /// Wake the loop thread blocked on the eventfd
    void notify_event_fd();

    Callbacks m_callbacks;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<Message> m_queue;
    ag::TrustTunnelConfig m_config;
    VpnState m_state = VpnState::DISCONNECTED;
    bool m_running = false;
    bool m_stop_requested = false;
    bool m_client_finished = false;

    ag::AutoFd m_event_fd;
    std::thread m_run_thread;
};

} // namespace ag::trusttunnel_linux
