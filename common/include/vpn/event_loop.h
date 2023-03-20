#pragma once

#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>

#include <event2/event.h>

#include "common/defs.h"

namespace ag {

struct VpnEventLoop;
using TaskId = int64_t;

struct VpnEventLoopTask {
    /** User-provided argument which will be passed in the following functions */
    void *arg;
    /**
     * The function to be executed on the event loop.
     * Will not be called if the loop is stopped before the task's turn to run.
     */
    void (*action)(void *arg, TaskId task_id);
    /**
     * The helper function which can be used for example to deallocate some resources and
     * will be executed anyway either after the `action` or after the task cancellation
     * or after the event loop stop.
     * May be null.
     */
    void (*finalize)(void *arg);
};

/**
 * Create an event loop
 */
VpnEventLoop *vpn_event_loop_create();

/**
 * Destroy an event loop
 */
void vpn_event_loop_destroy(VpnEventLoop *loop);

/**
 * Run an event loop on the current thread.
 * Blocks until stopped, if not exited immediately with an error.
 * @return 0 if successful, non-zero value otherwise
 */
int vpn_event_loop_run(VpnEventLoop *loop);

/**
 * Stop an event loop.
 * Basically calls `vpn_event_loop_exit` and `vpn_event_loop_finalize_exit`.
 */
void vpn_event_loop_stop(VpnEventLoop *loop);

/**
 * Exit an event loop after the next iteration.
 * Non-blocking, `vpn_event_loop_finalize_exit` must be called next.
 * @param loop the event loop
 * @param timeout the amount of time after which the loop should exit
 */
void vpn_event_loop_exit(VpnEventLoop *loop, Millis timeout);

/**
 * Finalize an exitted event loop.
 * Blocks until the loop is actually stopped and calls `VpnEventLoopTask#finalize`
 * for each task.
 * Must be called after `vpn_event_loop_exit`.
 */
void vpn_event_loop_finalize_exit(VpnEventLoop *loop);

/**
 * Submit a task to be executed on the next iteration of an event loop
 * @param loop the event loop
 * @param task the task to be executed
 * @return the assigned identifier to the task
 */
TaskId vpn_event_loop_submit(VpnEventLoop *loop, VpnEventLoopTask task);

/**
 * Schedule a task to be executed after some time on an event loop
 * @param loop the event loop
 * @param task the task to be executed
 * @param defer the amount of time after which the task is fired
 * @return the assigned identifier to the task
 */
TaskId vpn_event_loop_schedule(VpnEventLoop *loop, VpnEventLoopTask task, Millis defer);

/**
 * Submit a task that runs `action` to the event loop and block until it is finalized.
 * Note that the task may not be executed in some circumstances (e.g. if the event
 * loop is stopped before it has the chance to execute it), but it is always finalized.
 * @param loop the event loop
 * @param action the action to be executed
 * @param arg the argument for the action
 * @return whether the action has been executed
 */
bool vpn_event_loop_dispatch_sync(VpnEventLoop *loop, void (*action)(void *arg), void *arg);

/**
 * Cancel a task execution
 * @param loop the event loop
 * @param task_id the identifier of the task
 */
void vpn_event_loop_cancel(VpnEventLoop *loop, TaskId task_id);

/**
 * Get underlying event base
 */
struct event_base *vpn_event_loop_get_base(const VpnEventLoop *loop);

/**
 * Check if event loop is running
 */
bool vpn_event_loop_is_active(const VpnEventLoop *loop);

namespace event_loop {

class [[nodiscard]] AutoTaskId {
public:
    AutoTaskId() = default;
    AutoTaskId(VpnEventLoop *loop, std::weak_ptr<bool> weak, TaskId id);

    ~AutoTaskId();

    AutoTaskId(const AutoTaskId &) = delete;
    AutoTaskId &operator=(const AutoTaskId &) = delete;

    AutoTaskId(AutoTaskId &&other) noexcept;
    AutoTaskId &operator=(AutoTaskId &&other) noexcept;

    /**
     * Cancel the task and clean up
     */
    void reset();

    /**
     * Release the ownership of the managed task
     */
    void release();

    /**
     * Check if contains a valid task identifier
     */
    [[nodiscard]] bool has_value() const;

    bool operator<(const AutoTaskId &other) const;

private:
    friend AutoTaskId make_auto_id(TaskId id);

    explicit AutoTaskId(TaskId id);

    VpnEventLoop *m_loop = nullptr;
    std::weak_ptr<bool> m_guard;
    std::optional<TaskId> m_id;
};

/**
 * Helper function to search in containers by id
 */
AutoTaskId make_auto_id(TaskId id);

/**
 * Just like `vpn_event_loop_submit` but more convenient for C++
 */
AutoTaskId submit(VpnEventLoop *loop, VpnEventLoopTask task);

/**
 * Just like `vpn_event_loop_schedule` but more convenient for C++
 */
AutoTaskId schedule(VpnEventLoop *loop, VpnEventLoopTask task, Millis defer);

/**
 * Just like `vpn_event_loop_dispatch_sync` but more convenient for C++
 */
template <typename Func>
bool dispatch_sync(VpnEventLoop *loop, Func &&func) {
    return vpn_event_loop_dispatch_sync(
            loop,
            [](void *arg) {
                (*(decltype(std::addressof(func))) arg)();
            },
            std::addressof(func));
}

} // namespace event_loop

} // namespace ag
