#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <utility>
#include <vector>

#include "src/dbus_interface.h"
#include "src/vpn_controller.h"
#include "vpn/trusttunnel/network_info.h"

namespace ag::trusttunnel_linux {

// Daemon context holding bus, event loop and vpn controller
struct DaemonContext {
    sd_bus *bus = nullptr;
    sd_event *event = nullptr;
    std::unique_ptr<VpnController> controller;
};

static DaemonContext g_ctx;

// ---------------------------------------------------------------------------
// D-Bus Method Handlers
// ---------------------------------------------------------------------------

static int method_start(sd_bus_message *m, void *, sd_bus_error *ret_error) {
    const char *config = nullptr;
    int r = sd_bus_message_read(m, "s", &config);
    if (r < 0) {
        return sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Expected string config argument");
    }

    std::cout << "[trusttunneld] Start requested" << '\n';
    VpnError err = g_ctx.controller->start(config != nullptr ? config : "");
    return sd_bus_reply_method_return(m, "u", static_cast<uint32_t>(err));
}

static int method_stop(sd_bus_message *m, void *, sd_bus_error *) {
    std::cout << "[trusttunneld] Stop requested" << '\n';
    VpnError err = g_ctx.controller->stop();
    return sd_bus_reply_method_return(m, "u", static_cast<uint32_t>(err));
}

static int method_get_state(sd_bus_message *m, void *, sd_bus_error *) {
    VpnState state = g_ctx.controller->state();
    return sd_bus_reply_method_return(m, "i", static_cast<int32_t>(state));
}

static int method_clear_logs(sd_bus_message *m, void *, sd_bus_error *) {
    std::cout << "[trusttunneld] ClearLogs requested" << '\n';
    return sd_bus_reply_method_return(m, "");
}

// ---------------------------------------------------------------------------
// D-Bus VTable
// ---------------------------------------------------------------------------

static const sd_bus_vtable vpn_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD(METHOD_START, "s", "u", method_start, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_STOP, "", "u", method_stop, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_GET_STATE, "", "i", method_get_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD(METHOD_CLEAR_LOGS, "", "", method_clear_logs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL(SIGNAL_STATE_CHANGED, "i", 0),
        SD_BUS_SIGNAL(SIGNAL_CONNECTION_INFO, "s", 0),
        SD_BUS_SIGNAL(SIGNAL_NETWORK_READY, "ssusuuas", 0),
        SD_BUS_VTABLE_END,
};

// ---------------------------------------------------------------------------
// Controller -> event loop bridge
// ---------------------------------------------------------------------------

// The controller callbacks are invoked from the client's threads, so they only enqueue
// messages; this io handler on the eventfd drains the queue on the loop thread, where
// emitting D-Bus signals is safe.
static int on_controller_events(sd_event_source *, int, uint32_t, void *) {
    g_ctx.controller->drain();
    return 0;
}

// Signal callback to gracefully exit the event loop
static int on_signal(sd_event_source *, const struct signalfd_siginfo *, void *userdata) {
    auto *event = static_cast<sd_event *>(userdata);
    // Request the controller stop while the bus is still usable: exiting the event loop
    // disconnects the buses attached to it, so anything queued after sd_event_exit() is lost.
    // The stop is asynchronous (the client thread performs a blocking disconnect), so the final
    // StateChanged(DISCONNECTED) may not make it to the bus - acceptable for systemd shutdown.
    g_ctx.controller->stop();
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
            std::cerr << "[trusttunneld] Unknown argument: " << arg << '\n';
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cout << "[trusttunneld] Starting daemon (" << (use_session_bus ? "session bus" : "system bus") << ")..."
              << '\n';

    // Create event loop
    int r = sd_event_default(&g_ctx.event);
    if (r < 0) {
        std::cerr << "Failed to allocate event loop: " << strerror(-r) << '\n';
        return 1;
    }

    // Connect to requested bus
    if (use_session_bus) {
        r = sd_bus_open_user(&g_ctx.bus);
    } else {
        r = sd_bus_open_system(&g_ctx.bus);
    }
    if (r < 0) {
        std::cerr << "Failed to connect to bus: " << strerror(-r) << '\n';
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Attach bus to event loop
    r = sd_bus_attach_event(g_ctx.bus, g_ctx.event, SD_EVENT_PRIORITY_NORMAL);
    if (r < 0) {
        std::cerr << "Failed to attach bus to event loop: " << strerror(-r) << '\n';
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Setup callbacks for VpnController: they run on the event loop thread
    // (invoked from VpnController::drain), so emitting signals is safe here
    VpnController::Callbacks callbacks;
    callbacks.on_state_changed = [](VpnState new_state) {
        std::cout << "[trusttunneld] State -> " << static_cast<int32_t>(new_state) << '\n';
        sd_bus_emit_signal(
                g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_STATE_CHANGED, "i", static_cast<int32_t>(new_state));
    };
    callbacks.on_connection_info = [](const std::string &info_json) {
        sd_bus_emit_signal(g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_CONNECTION_INFO, "s", info_json.c_str());
    };
    callbacks.on_network_ready = [](const ag::VpnNetworkInfo &info) {
        // sd-bus takes a NULL-terminated array of non-const strings for `append_strv`;
        // the composite "as" array type cannot be appended through the varargs interface
        // of `sd_bus_message_append` (that form expects an element count + elements)
        std::vector<std::string> dns(info.dns_servers.begin(), info.dns_servers.end());
        std::vector<char *> dns_strv;
        dns_strv.reserve(dns.size() + 1);
        for (std::string &server : dns) {
            dns_strv.push_back(server.data());
        }
        dns_strv.push_back(nullptr);

        std::cout << "[trusttunneld] Network ready: iface=" << info.iface_name << " mtu=" << info.mtu << '\n';
        sd_bus_message *message = nullptr;
        int r = sd_bus_message_new_signal(g_ctx.bus, &message, OBJECT_PATH, INTERFACE_NAME, SIGNAL_NETWORK_READY);
        if (r >= 0) {
            r = sd_bus_message_append(message, "ssusuu", info.iface_name.c_str(), info.ipv4_address.c_str(),
                    info.ipv4_prefix, info.ipv6_address.c_str(), info.ipv6_prefix, info.mtu);
        }
        if (r >= 0) {
            r = sd_bus_message_append_strv(message, dns_strv.data());
        }
        if (r >= 0) {
            r = sd_bus_send(g_ctx.bus, message, nullptr);
        }
        if (r < 0) {
            std::cerr << "[trusttunneld] Failed to emit NetworkReady: " << strerror(-r) << '\n';
        }
        sd_bus_message_unref(message);
    };

    g_ctx.controller = std::make_unique<VpnController>(std::move(callbacks));

    // Wake up the event loop whenever the controller queues a message
    r = sd_event_add_io(g_ctx.event, nullptr, g_ctx.controller->event_fd(), EPOLLIN, on_controller_events, nullptr);
    if (r < 0) {
        std::cerr << "Failed to subscribe to controller eventfd: " << strerror(-r) << '\n';
        return 1;
    }

    // Register object vtable
    r = sd_bus_add_object_vtable(g_ctx.bus, nullptr, OBJECT_PATH, INTERFACE_NAME, vpn_vtable, nullptr);
    if (r < 0) {
        std::cerr << "Failed to register object vtable: " << strerror(-r) << '\n';
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Request well-known name (flag 0 ensures another running instance is not replaced)
    r = sd_bus_request_name(g_ctx.bus, BUS_NAME, 0);
    if (r < 0) {
        std::cerr << "Failed to acquire bus name '" << BUS_NAME << "': " << strerror(-r) << '\n';
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
        std::cerr << "Failed to subscribe to SIGINT: " << strerror(-r) << '\n';
        return 1;
    }
    r = sd_event_add_signal(g_ctx.event, nullptr, SIGTERM, on_signal, g_ctx.event);
    if (r < 0) {
        std::cerr << "Failed to subscribe to SIGTERM: " << strerror(-r) << '\n';
        return 1;
    }

    // Notify systemd that service is ready
    sd_notify(0, "READY=1\nSTATUS=TrustTunnel daemon running");

    std::cout << "[trusttunneld] Service ready at " << BUS_NAME << " " << OBJECT_PATH << '\n';

    // Run the event loop
    r = sd_event_loop(g_ctx.event);

    sd_notify(0, "STOPPING=1");

    // Destroying the controller joins the client thread (blocking disconnect, no bus involved),
    // so it must happen while the bus is still referenced.
    g_ctx.controller.reset();
    sd_bus_flush_close_unref(g_ctx.bus);
    g_ctx.bus = nullptr;
    sd_event_unref(g_ctx.event);
    g_ctx.event = nullptr;

    std::cout << "[trusttunneld] Daemon exited gracefully." << '\n';
    return r < 0 ? 1 : 0;
}
