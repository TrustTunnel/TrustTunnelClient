#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <utility>
#include <vector>

#include "common/logger.h"
#include "daemon/dbus_interface.h"
#include "src/vpn_controller.h"
#include "trusttunnel/trusttunnel.h"

namespace ag::trusttunnel_linux {

static const Logger g_logger("TRUSTTUNNELD");

// Daemon context holding bus, event loop and vpn client instance
struct DaemonContext {
    sd_bus *bus = nullptr;
    sd_event *event = nullptr;
    trusttunnel_t *vpn = nullptr;
    // Polkit is available on the system bus only: on the session bus (dev mode)
    // Start/Stop run with the daemon user's own privileges without authorization
    bool session_bus = true;
};

static DaemonContext g_ctx;

/// Bumped on every Start/Stop request. A request parked for Polkit authorization carries the
/// generation it was created with; if a newer request arrives meanwhile, the parked one is stale
/// and must not be applied (e.g. a Start must not start the VPN after a newer Stop).
static uint64_t g_request_generation = 0;

// ---------------------------------------------------------------------------
// Polkit authorization
// ---------------------------------------------------------------------------

static constexpr const char *POLKIT_SERVICE = "org.freedesktop.PolicyKit1";
static constexpr const char *POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority";
static constexpr const char *POLKIT_INTERFACE = "org.freedesktop.PolicyKit1.Authority";
static constexpr const char *POLKIT_ACTION = "com.adguard.TrustTunnel.vpn.control";
// AllowUserInteraction: polkitd may raise the admin authentication dialog
static constexpr uint32_t POLKIT_ALLOW_USER_INTERACTION = 0x1;

/// A D-Bus method request parked until the Polkit verdict arrives. Holds a
/// reference to the request message and the arguments needed to perform it.
struct PendingRequest {
    sd_bus_message *request = nullptr;
    /// Sanitized TOML configuration, only used by Start
    std::string config;
    /// Distinguishes Start from Stop: an empty sanitized config is a valid Start argument
    /// (it fails validation later), not a request to stop.
    bool is_start = false;
    /// Passed through to the client's connect options when `is_start` is true
    bool fall_into_recovery = false;
    /// `g_request_generation` value at the time the request was received
    uint64_t generation = 0;

    ~PendingRequest() {
        sd_bus_message_unref(request);
    }
};

/// Perform the request and reply to the client on the parked message
static void perform_request(const PendingRequest &pending) {
    if (pending.generation != g_request_generation) {
        infolog(g_logger, "Skipping a stale {} request superseded by a newer one", pending.is_start ? "Start" : "Stop");
        // The superseded caller still waits for a reply on its own message
        int r = sd_bus_reply_method_errorf(
                pending.request, SD_BUS_ERROR_FAILED, "Superseded by a newer Start/Stop request");
        if (r < 0) {
            errlog(g_logger, "Failed to reply to the stale request: {}", strerror(-r));
        }
        return;
    }
    uint32_t error = 0;
    if (pending.is_start) {
        trusttunnel_start_options_t options{};
        options.fall_into_recovery = pending.fall_into_recovery;
        error = static_cast<uint32_t>(trusttunnel_start_with_options(g_ctx.vpn, pending.config.c_str(), &options));
    } else {
        error = static_cast<uint32_t>(trusttunnel_stop(g_ctx.vpn));
    }
    int r = sd_bus_reply_method_return(pending.request, "u", error);
    if (r < 0) {
        errlog(g_logger, "Failed to reply to the parked request: {}", strerror(-r));
    }
}

/// Deny a parked request; `error_name` may be NULL for the generic access denied error
static void deny_request(const PendingRequest &pending, const char *error_name, const char *message) {
    error_name = error_name != nullptr ? error_name : SD_BUS_ERROR_ACCESS_DENIED;
    int r = sd_bus_reply_method_errorf(pending.request, error_name, "%s", message);
    if (r < 0) {
        errlog(g_logger, "Failed to deny the parked request: {}", strerror(-r));
    }
}

static int on_polkit_result(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error);

/// Send the Polkit CheckAuthorization call for a parked request.
/// On success the request and its ownership are handed over to `on_polkit_result`.
static int send_check_authorization(PendingRequest *pending) {
    sd_bus_message *req = nullptr;
    int r = sd_bus_message_new_method_call(
            g_ctx.bus, &req, POLKIT_SERVICE, POLKIT_PATH, POLKIT_INTERFACE, "CheckAuthorization");
    if (r < 0) {
        errlog(g_logger, "Failed to create the Polkit request: {}", strerror(-r));
        return r;
    }

    // CheckAuthorization(in (sa{sv}) subject, in s action_id, in a{ss} details,
    //                    in u flags, in s cancellation_id,
    //                    out (bba{ss}) result)
    const char *sender = sd_bus_message_get_sender(pending->request);
    if (sender != nullptr) {
        r = sd_bus_message_open_container(req, SD_BUS_TYPE_STRUCT, "sa{sv}");
    }
    if (r >= 0) {
        r = sd_bus_message_append(req, "s", "system-bus-name");
    }
    if (r >= 0) {
        r = sd_bus_message_open_container(req, SD_BUS_TYPE_ARRAY, "{sv}");
    }
    if (r >= 0) {
        r = sd_bus_message_open_container(req, SD_BUS_TYPE_DICT_ENTRY, "sv");
    }
    if (r >= 0) {
        r = sd_bus_message_append(req, "s", "name");
    }
    if (r >= 0) {
        r = sd_bus_message_open_container(req, SD_BUS_TYPE_VARIANT, "s");
    }
    if (r >= 0) {
        r = sd_bus_message_append(req, "s", sender);
    }
    if (r >= 0) {
        r = sd_bus_message_close_container(req); // v
    }
    if (r >= 0) {
        r = sd_bus_message_close_container(req); // e
    }
    if (r >= 0) {
        r = sd_bus_message_close_container(req); // a
    }
    if (r >= 0) {
        r = sd_bus_message_close_container(req); // (sa{sv})
    }
    if (r >= 0) {
        r = sd_bus_message_append(req, "s", POLKIT_ACTION);
    }
    if (r >= 0) {
        r = sd_bus_message_open_container(req, SD_BUS_TYPE_ARRAY, "{ss}");
    }
    if (r >= 0) {
        r = sd_bus_message_close_container(req); // details
    }
    if (r >= 0) {
        r = sd_bus_message_append(req, "us", POLKIT_ALLOW_USER_INTERACTION, "");
    }
    if (r < 0) {
        errlog(g_logger, "Failed to build the Polkit request: {}", strerror(-r));
        sd_bus_message_unref(req);
        return r;
    }

    r = sd_bus_call_async(g_ctx.bus, nullptr, req, on_polkit_result, pending, 0);
    sd_bus_message_unref(req);
    if (r < 0) {
        errlog(g_logger, "Failed to call Polkit: {}", strerror(-r));
    }
    return r;
}

/// Polkit CheckAuthorization reply handler: perform or deny the parked request
static int on_polkit_result(sd_bus_message *reply, void *userdata, sd_bus_error *ret_error) {
    std::unique_ptr<PendingRequest> pending(static_cast<PendingRequest *>(userdata));
    bool authorized = false;
    int is_challenge = 0;
    int r = sd_bus_message_read(reply, "bb", &authorized, &is_challenge);
    if (r < 0) {
        errlog(g_logger, "Failed to read the Polkit reply: {}", strerror(-r));
        deny_request(*pending, ret_error != nullptr ? ret_error->name : nullptr,
                ret_error != nullptr && ret_error->message != nullptr ? ret_error->message : "Polkit check failed");
        return 1; // the error has been replied to the client already
    }
    if (!authorized) {
        warnlog(g_logger, "Polkit denied the request");
        deny_request(*pending, nullptr, "Not authorized to control the TrustTunnel VPN");
        return 1;
    }
    perform_request(*pending);
    return 1;
}

/// True if the caller of a D-Bus method runs as root: root bypasses Polkit
static bool caller_is_root(sd_bus_message *m) {
    sd_bus_creds *creds = nullptr;
    if (sd_bus_query_sender_creds(m, SD_BUS_CREDS_UID, &creds) < 0) {
        return false;
    }
    uid_t uid = (uid_t) -1;
    bool root = sd_bus_creds_get_uid(creds, &uid) >= 0 && uid == 0;
    sd_bus_creds_unref(creds);
    return root;
}

/// Authorize a parked request: on success the request is performed and replied to
/// asynchronously; on failure an error is replied synchronously. Takes the ownership
/// of `pending` in both cases.
/// @return 0 on success, a negative errno-style code on a synchronous failure
static int authorize(PendingRequest *pending) {
    sd_bus_message *m = pending->request;
    if (g_ctx.session_bus || caller_is_root(m)) {
        perform_request(*pending);
        delete pending;
        return 0;
    }

    int r = send_check_authorization(pending);
    if (r < 0) {
        // Fail closed: without a Polkit verdict the request is denied
        deny_request(*pending, nullptr, "Failed to check the authorization to control the VPN");
        delete pending;
    }
    return r;
}

// ---------------------------------------------------------------------------
// D-Bus Method Handlers
// ---------------------------------------------------------------------------

/// Sanitize and park a Start request until it is authorized.
/// `fall_into_recovery` selects the core's failure-handling mode.
static int submit_start(sd_bus_message *m, const char *config, bool fall_into_recovery) {
    infolog(g_logger, "Start requested (fall_into_recovery={})", fall_into_recovery);
    auto pending = std::make_unique<PendingRequest>();
    pending->request = sd_bus_message_ref(m);
    pending->config = sanitize_daemon_config(config != nullptr ? config : "");
    pending->is_start = true;
    pending->fall_into_recovery = fall_into_recovery;
    pending->generation = ++g_request_generation;
    return authorize(pending.release());
}

static int method_start(sd_bus_message *m, void *, sd_bus_error *ret_error) {
    const char *config = nullptr;
    int r = sd_bus_message_read(m, "s", &config);
    if (r < 0) {
        return sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Expected string config argument");
    }
    // Default options: a fixed number of connection attempts
    return submit_start(m, config, false);
}

static int method_start_ex(sd_bus_message *m, void *, sd_bus_error *ret_error) {
    const char *config = nullptr;
    int fall_into_recovery = 0;
    int r = sd_bus_message_read(m, "sb", &config, &fall_into_recovery);
    if (r < 0) {
        return sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS,
                "Expected string config and boolean fall_into_recovery arguments");
    }
    return submit_start(m, config, fall_into_recovery != 0);
}

static int method_stop(sd_bus_message *m, void *, sd_bus_error *) {
    infolog(g_logger, "Stop requested");
    auto pending = std::make_unique<PendingRequest>();
    pending->request = sd_bus_message_ref(m);
    pending->is_start = false;
    pending->generation = ++g_request_generation;
    return authorize(pending.release());
}

static int method_get_state(sd_bus_message *m, void *, sd_bus_error *) {
    trusttunnel_vpn_state_t state = trusttunnel_get_state(g_ctx.vpn);
    return sd_bus_reply_method_return(m, "i", static_cast<int32_t>(state));
}

// ---------------------------------------------------------------------------
// D-Bus VTable
// ---------------------------------------------------------------------------

static const sd_bus_vtable vpn_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD(METHOD_START, "s", "u", method_start, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_START_EX, "sb", "u", method_start_ex, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_STOP, "", "u", method_stop, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_GET_STATE, "", "i", method_get_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL(SIGNAL_STATE_CHANGED, "i", 0),
        SD_BUS_SIGNAL(SIGNAL_CONNECTION_INFO, "s", 0),
        SD_BUS_SIGNAL(SIGNAL_NETWORK_READY, "ssusuuas", 0),
        SD_BUS_VTABLE_END,
};

// ---------------------------------------------------------------------------
// Client -> event loop bridge
// ---------------------------------------------------------------------------

// The client callbacks are invoked from the library's threads, so they only emit
// here on the loop thread after the queue has been drained (see on_client_events).
// The emission helpers below are therefore always called on the loop thread.

static void emit_state_changed(trusttunnel_vpn_state_t new_state) {
    infolog(g_logger, "State -> {}", static_cast<int32_t>(new_state));
    if (sd_bus_emit_signal(
                g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_STATE_CHANGED, "i", static_cast<int32_t>(new_state))
            < 0) {
        errlog(g_logger, "Failed to emit StateChanged({})", static_cast<int32_t>(new_state));
    }
}

static void emit_connection_info(const char *info_json) {
    if (sd_bus_emit_signal(g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_CONNECTION_INFO, "s", info_json) < 0) {
        errlog(g_logger, "Failed to emit ConnectionInfo");
    }
}

static void emit_network_ready(const trusttunnel_network_info_t *info) {
    // sd-bus takes a NULL-terminated array of non-const strings for `append_strv`;
    // the composite "as" array type cannot be appended through the varargs interface
    // of `sd_bus_message_append` (that form expects an element count + elements)
    std::vector<std::string> dns_servers;
    dns_servers.reserve(info->dns_servers_count);
    for (size_t i = 0; i < info->dns_servers_count; ++i) {
        dns_servers.emplace_back(info->dns_servers[i]);
    }
    std::vector<char *> dns_strv;
    dns_strv.reserve(dns_servers.size() + 1);
    for (std::string &server : dns_servers) {
        dns_strv.push_back(server.data());
    }
    dns_strv.push_back(nullptr);

    infolog(g_logger, "Network ready: iface={} mtu={}", info->iface_name, info->mtu);
    sd_bus_message *message = nullptr;
    int r = sd_bus_message_new_signal(g_ctx.bus, &message, OBJECT_PATH, INTERFACE_NAME, SIGNAL_NETWORK_READY);
    if (r >= 0) {
        r = sd_bus_message_append(message, "ssusuu", info->iface_name, info->ipv4_address, info->ipv4_prefix,
                info->ipv6_address, info->ipv6_prefix, info->mtu);
    }
    if (r >= 0) {
        r = sd_bus_message_append_strv(message, dns_strv.data());
    }
    if (r >= 0) {
        r = sd_bus_send(g_ctx.bus, message, nullptr);
    }
    if (r < 0) {
        errlog(g_logger, "Failed to emit NetworkReady: {}", strerror(-r));
    }
    sd_bus_message_unref(message);
}

// This io handler on the client event fd drains the queue on the loop thread,
// where emitting D-Bus signals is safe.
static int on_client_events(sd_event_source *, int, uint32_t, void *) {
    trusttunnel_drain(g_ctx.vpn);
    return 0;
}

// Signal callback to gracefully exit the event loop
static int on_signal(sd_event_source *, const struct signalfd_siginfo *, void *userdata) {
    auto *event = static_cast<sd_event *>(userdata);
    // Request the client stop while the bus is still usable: exiting the event loop
    // disconnects the buses attached to it, so anything queued after sd_event_exit() is
    // lost. The stop is asynchronous (the library thread performs a blocking disconnect),
    // so the final StateChanged(DISCONNECTED) may not make it to the bus - acceptable for
    // systemd shutdown.
    trusttunnel_stop(g_ctx.vpn);
    sd_bus_flush(g_ctx.bus);
    sd_event_exit(event, 0);
    return 0;
}

static void print_usage(const char *prog_name) {
    std::cerr << "Usage: " << prog_name << " [OPTIONS]\n"
              << "Options:\n"
              << "  --system         Connect to system D-Bus (default)\n"
              << "  --session, -s    Connect to session/user D-Bus\n"
              << "  --help, -h       Show this help message\n";
}

} // namespace ag::trusttunnel_linux

int main(int argc, char **argv) {
    using namespace ag::trusttunnel_linux;

    bool use_session_bus = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--session" || arg == "-s") {
            use_session_bus = true;
        } else if (arg == "--system") {
            use_session_bus = false;
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        } else {
            errlog(g_logger, "Unknown argument: {}", arg);
            print_usage(argv[0]);
            return 1;
        }
    }

    infolog(g_logger, "Starting daemon ({})...", use_session_bus ? "session bus" : "system bus");
    g_ctx.session_bus = use_session_bus;

    // Create event loop
    int r = sd_event_default(&g_ctx.event);
    if (r < 0) {
        errlog(g_logger, "Failed to allocate event loop: {}", strerror(-r));
        return 1;
    }

    // Connect to requested bus
    if (use_session_bus) {
        r = sd_bus_open_user(&g_ctx.bus);
    } else {
        r = sd_bus_open_system(&g_ctx.bus);
    }
    if (r < 0) {
        errlog(g_logger, "Failed to connect to bus: {}", strerror(-r));
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Attach bus to event loop
    r = sd_bus_attach_event(g_ctx.bus, g_ctx.event, SD_EVENT_PRIORITY_NORMAL);
    if (r < 0) {
        errlog(g_logger, "Failed to attach bus to event loop: {}", strerror(-r));
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Setup client callbacks: they run on the event loop thread (invoked from
    // trusttunnel_drain), so emitting D-Bus signals is safe here
    trusttunnel_callbacks_t callbacks{};
    callbacks.state_changed_arg = nullptr;
    callbacks.on_state_changed = [](void *, trusttunnel_vpn_state_t new_state) {
        emit_state_changed(new_state);
    };
    callbacks.connection_info_arg = nullptr;
    callbacks.on_connection_info = [](void *, const char *info_json) {
        emit_connection_info(info_json);
    };
    callbacks.network_ready_arg = nullptr;
    callbacks.on_network_ready = [](void *, const trusttunnel_network_info_t *info) {
        emit_network_ready(info);
    };

    g_ctx.vpn = trusttunnel_create(&callbacks);
    if (g_ctx.vpn == nullptr) {
        errlog(g_logger, "Failed to create the VPN client instance");
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Wake up the event loop whenever the client queues a message
    r = sd_event_add_io(g_ctx.event, nullptr, trusttunnel_event_fd(g_ctx.vpn), EPOLLIN, on_client_events, nullptr);
    if (r < 0) {
        errlog(g_logger, "Failed to subscribe to the client event fd: {}", strerror(-r));
        trusttunnel_destroy(g_ctx.vpn);
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Register object vtable
    r = sd_bus_add_object_vtable(g_ctx.bus, nullptr, OBJECT_PATH, INTERFACE_NAME, vpn_vtable, nullptr);
    if (r < 0) {
        errlog(g_logger, "Failed to register object vtable: {}", strerror(-r));
        trusttunnel_destroy(g_ctx.vpn);
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Request well-known name (flag 0 ensures another running instance is not replaced)
    r = sd_bus_request_name(g_ctx.bus, BUS_NAME, 0);
    if (r < 0) {
        errlog(g_logger, "Failed to acquire bus name '{}': {}", BUS_NAME, strerror(-r));
        trusttunnel_destroy(g_ctx.vpn);
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Setup UNIX signal handling via sd_event. The signals must be blocked first: sd-event
    // receives them through signalfd, which only sees signals that are blocked.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    r = sd_event_add_signal(g_ctx.event, nullptr, SIGINT, on_signal, g_ctx.event);
    if (r < 0) {
        errlog(g_logger, "Failed to subscribe to SIGINT: {}", strerror(-r));
        trusttunnel_destroy(g_ctx.vpn);
        sd_bus_flush_close_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }
    r = sd_event_add_signal(g_ctx.event, nullptr, SIGTERM, on_signal, g_ctx.event);
    if (r < 0) {
        errlog(g_logger, "Failed to subscribe to SIGTERM: {}", strerror(-r));
        trusttunnel_destroy(g_ctx.vpn);
        sd_bus_flush_close_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Notify systemd that service is ready
    sd_notify(0, "READY=1\nSTATUS=TrustTunnel daemon running");

    infolog(g_logger, "Service ready at {} {}", BUS_NAME, OBJECT_PATH);

    // Run the event loop
    r = sd_event_loop(g_ctx.event);

    sd_notify(0, "STOPPING=1");

    // Destroying the instance joins the client thread (blocking disconnect, no bus
    // involved), so it must happen while the bus is still referenced.
    trusttunnel_destroy(g_ctx.vpn);
    g_ctx.vpn = nullptr;
    sd_bus_flush_close_unref(g_ctx.bus);
    g_ctx.bus = nullptr;
    sd_event_unref(g_ctx.event);
    g_ctx.event = nullptr;

    infolog(g_logger, "Daemon exited gracefully.");
    return r < 0 ? 1 : 0;
}
