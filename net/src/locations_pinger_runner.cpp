#include <net/locations_pinger_runner.h>

#include <atomic>
#include <condition_variable>
#include <mutex>

#include "common/logger.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

#define log_runner(runner_, lvl_, fmt_, ...) lvl_##log((runner_)->log, "[{}] " fmt_, (runner_)->id, ##__VA_ARGS__)

/** This dummy variable is preventing the linker from excluding modules from dll */
int g_exp_init_adguard_vpnnet [[maybe_unused]] = 0;

namespace ag {

static std::atomic_int g_next_runner_id = 0;

typedef struct LocationsPingerRunner {
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    DeclPtr<LocationsPinger, &locations_pinger_destroy> pinger;
    std::mutex stop_guard;
    std::condition_variable stop_barrier;
    bool actually_stopped = true;
    ag::Logger log{"LOCATIONS_PINGER_RUNNER"};
    int id = g_next_runner_id++;
    LocationsPingerHandler handler;
} LocationsPingerRunner;

extern "C" VpnEventLoop *locations_pinger_runner_get_loop(LocationsPingerRunner *runner) {
    return runner->ev_loop.get();
}

static void runner_handler(void *arg, const LocationsPingerResult *result) {
    auto *runner = (LocationsPingerRunner *) arg;
    if (result) {
        runner->handler.func(runner->handler.arg, result);
    } else {
        vpn_event_loop_exit(runner->ev_loop.get(), Millis{0});
    }
}

LocationsPingerRunner *locations_pinger_runner_create(const LocationsPingerInfo *info, LocationsPingerHandler handler) {
    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner{new LocationsPingerRunner{}};
    if (runner->ev_loop == nullptr) {
        log_runner(runner, err, "Failed to create event loop");
        return nullptr;
    }
    runner->handler = handler;
    runner->pinger.reset(locations_pinger_start(
            info, {runner_handler, runner.get()}, runner->ev_loop.get(), runner->network_manager.get()));
    return runner.release();
}

void locations_pinger_runner_run(LocationsPingerRunner *runner) {
    log_runner(runner, info, "...");

    {
        std::scoped_lock l(runner->stop_guard);
        runner->actually_stopped = false;
    }

    vpn_event_loop_run(runner->ev_loop.get());

    log_runner(runner, info, "Exited from event loop");

    std::scoped_lock l(runner->stop_guard);
    runner->actually_stopped = true;
    runner->stop_barrier.notify_all();

    log_runner(runner, info, "Done");
}

static void runner_stop(LocationsPingerRunner *runner) {
    log_runner(runner, info, "...");

    std::unique_lock l(runner->stop_guard);

    if (runner->ev_loop != nullptr) {
        vpn_event_loop_stop(runner->ev_loop.get());
    }
    if (runner->pinger != nullptr) {
        locations_pinger_stop(runner->pinger.get());
    }

    log_runner(runner, info, "Waiting for event loop stop");

    runner->stop_barrier.wait(l, [runner]() -> bool {
        return runner->actually_stopped;
    });

    log_runner(runner, info, "Done");
}

void locations_pinger_runner_free(LocationsPingerRunner *runner) {
    if (runner != nullptr) {
        runner_stop(runner);
        delete runner;
    }
}

} // namespace ag
