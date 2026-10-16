#include <pthread.h>
#include <signal.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-event.h>
#include <utility>

#include "src/dbus_interface.h"
#include "src/vpn_controller.h"

namespace ag::trusttunnel_linux {

// Daemon context holding bus, event loop and vpn controller
struct DaemonContext {
    sd_bus *bus = nullptr;
    sd_event *event = nullptr;
    std::unique_ptr<VpnController> controller;
};

static DaemonContext g_ctx;

// Helper to schedule a delayed callback on the systemd event loop
static void schedule_timer(uint32_t delay_ms, std::function<void()> fn) {
    if (g_ctx.event == nullptr) {
        return;
    }

    auto task = std::make_unique<std::function<void()>>(std::move(fn));
    uint64_t now_usec = 0;
    sd_event_now(g_ctx.event, CLOCK_MONOTONIC, &now_usec);

    auto timer_cb = [](sd_event_source *, uint64_t, void *userdata) -> int {
        auto *action = static_cast<std::function<void()> *>(userdata);
        (*action)();
        return 0;
    };

    sd_event_source *source = nullptr;
    int r = sd_event_add_time(g_ctx.event, &source, CLOCK_MONOTONIC, now_usec + static_cast<uint64_t>(delay_ms) * 1000,
            0, timer_cb, task.get());
    if (r < 0) {
        return;
    }

    // Pass ownership of the allocated task to the event source destroy callback
    (void) task.release();
    sd_event_source_set_destroy_callback(source, [](void *userdata) {
        delete static_cast<std::function<void()> *>(userdata);
    });

    // Floating source automatically frees when fired or when event loop is torn down
    sd_event_source_set_floating(source, 1);
}

// ---------------------------------------------------------------------------
// D-Bus Method Handlers
// ---------------------------------------------------------------------------

static int method_start(sd_bus_message *m, void *, sd_bus_error *ret_error) {
    const char *config = nullptr;
    int r = sd_bus_message_read(m, "s", &config);
    if (r < 0) {
        return sd_bus_error_setf(ret_error, SD_BUS_ERROR_INVALID_ARGS, "Expected string config argument");
    }

    std::cout << "[trusttunneld] Start requested" << std::endl;
    VpnError err = g_ctx.controller->start(config ? config : "");
    return sd_bus_reply_method_return(m, "u", static_cast<uint32_t>(err));
}

static int method_stop(sd_bus_message *m, void *, sd_bus_error *) {
    std::cout << "[trusttunneld] Stop requested" << std::endl;
    VpnError err = g_ctx.controller->stop();
    return sd_bus_reply_method_return(m, "u", static_cast<uint32_t>(err));
}

static int method_get_state(sd_bus_message *m, void *, sd_bus_error *) {
    VpnState state = g_ctx.controller->state();
    return sd_bus_reply_method_return(m, "i", static_cast<int32_t>(state));
}

static int method_clear_logs(sd_bus_message *m, void *, sd_bus_error *) {
    std::cout << "[trusttunneld] ClearLogs requested" << std::endl;
    return sd_bus_reply_method_return(m, "");
}

// ---------------------------------------------------------------------------
// D-Bus VTable
// ---------------------------------------------------------------------------

static const sd_bus_vtable vpn_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Start", "s", "u", method_start, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Stop", "", "u", method_stop, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("GetState", "", "i", method_get_state, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ClearLogs", "", "", method_clear_logs, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_SIGNAL("StateChanged", "i", 0),
        SD_BUS_SIGNAL("ConnectionInfo", "s", 0),
        SD_BUS_VTABLE_END,
};

// Signal callback to gracefully exit the event loop
static int on_signal(sd_event_source *, const struct signalfd_siginfo *, void *userdata) {
    auto *event = static_cast<sd_event *>(userdata);
    // Report the final disconnection while the bus is still usable: exiting the event loop
    // disconnects the buses attached to it, so anything queued after sd_event_exit() is lost.
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
            std::cerr << "[trusttunneld] Unknown argument: " << arg << std::endl;
            print_usage(argv[0]);
            return 1;
        }
    }

    std::cout << "[trusttunneld] Starting daemon (" << (use_session_bus ? "session bus" : "system bus") << ")..."
              << std::endl;

    // Create event loop
    int r = sd_event_default(&g_ctx.event);
    if (r < 0) {
        std::cerr << "Failed to allocate event loop: " << strerror(-r) << std::endl;
        return 1;
    }

    // Connect to requested bus
    if (use_session_bus) {
        r = sd_bus_open_user(&g_ctx.bus);
    } else {
        r = sd_bus_open_system(&g_ctx.bus);
    }
    if (r < 0) {
        std::cerr << "Failed to connect to bus: " << strerror(-r) << std::endl;
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Attach bus to event loop
    r = sd_bus_attach_event(g_ctx.bus, g_ctx.event, SD_EVENT_PRIORITY_NORMAL);
    if (r < 0) {
        std::cerr << "Failed to attach bus to event loop: " << strerror(-r) << std::endl;
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Setup callbacks for VpnController
    VpnController::Callbacks callbacks;
    callbacks.on_state_changed = [](VpnState new_state) {
        std::cout << "[trusttunneld] State -> " << static_cast<int32_t>(new_state) << std::endl;
        sd_bus_emit_signal(
                g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_STATE_CHANGED, "i", static_cast<int32_t>(new_state));
    };
    callbacks.on_connection_info = [](const std::string &info_json) {
        sd_bus_emit_signal(g_ctx.bus, OBJECT_PATH, INTERFACE_NAME, SIGNAL_CONNECTION_INFO, "s", info_json.c_str());
    };

    g_ctx.controller = std::make_unique<VpnController>(schedule_timer, std::move(callbacks));

    // Register object vtable
    r = sd_bus_add_object_vtable(g_ctx.bus, nullptr, OBJECT_PATH, INTERFACE_NAME, vpn_vtable, nullptr);
    if (r < 0) {
        std::cerr << "Failed to register object vtable: " << strerror(-r) << std::endl;
        sd_bus_close(g_ctx.bus);
        sd_bus_unref(g_ctx.bus);
        sd_event_unref(g_ctx.event);
        return 1;
    }

    // Request well-known name (flag 0 ensures another running instance is not replaced)
    r = sd_bus_request_name(g_ctx.bus, BUS_NAME, 0);
    if (r < 0) {
        std::cerr << "Failed to acquire bus name '" << BUS_NAME << "': " << strerror(-r) << std::endl;
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
        std::cerr << "Failed to subscribe to SIGINT: " << strerror(-r) << std::endl;
        return 1;
    }
    r = sd_event_add_signal(g_ctx.event, nullptr, SIGTERM, on_signal, g_ctx.event);
    if (r < 0) {
        std::cerr << "Failed to subscribe to SIGTERM: " << strerror(-r) << std::endl;
        return 1;
    }

    // Notify systemd that service is ready
    sd_notify(0, "READY=1\nSTATUS=TrustTunnel daemon running");

    std::cout << "[trusttunneld] Service ready at " << BUS_NAME << " " << OBJECT_PATH << std::endl;

    // Run the event loop
    r = sd_event_loop(g_ctx.event);

    sd_notify(0, "STOPPING=1");

    // The controller was already stopped and the final StateChanged(DISCONNECTED) flushed
    // inside the signal handler, before the loop exit disconnected the bus.
    g_ctx.controller.reset();
    sd_bus_flush_close_unref(g_ctx.bus);
    g_ctx.bus = nullptr;
    sd_event_unref(g_ctx.event);
    g_ctx.event = nullptr;

    std::cout << "[trusttunneld] Daemon exited gracefully." << std::endl;
    return r < 0 ? 1 : 0;
}
