#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <list>
#include <memory>
#include <mutex>
#include <optional>

#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <magic_enum/magic_enum.hpp>

#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
#include <signal.h>
#endif

#include "common/logger.h"
#include "vpn/event_loop.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

#define log_loop(loop_, lvl_, fmt_, ...) lvl_##log((loop_)->log, "[{}] " fmt_, (loop_)->id, ##__VA_ARGS__)
#define log_task(loop_, tid_, lvl_, fmt_, ...)                                                                         \
    lvl_##log((loop_)->log, "[{}/id={}] " fmt_, (loop_)->id, tid_, ##__VA_ARGS__)

namespace ag {

static constexpr size_t TASK_QUEUE_BUDGET = 64;

std::atomic<TaskId> g_next_task_id = 0;
std::atomic_int g_next_loop_id = 0;

static event_base *make_event_base();
static void run_task_queue(evutil_socket_t, short, void *arg);
static void run_deferred_task(evutil_socket_t, short, void *arg);
static void vpn_timer_event_free_finalize(event *ev);

struct TaskInfo {
    TaskId id;
    VpnEventLoopTask task;
};

struct DeferredTaskCtx {
    VpnEventLoop *parent_loop;
    TaskId id;
};

struct DeferredTaskInfo {
    TaskInfo basic;
    DeclPtr<event, &vpn_timer_event_free_finalize> timer_event;
};

/**
 * timer_event is required to be finalized because it is created with EV_FINALIZE flag.
 * If it is created without this flag, event_del may block while the event's callback is running.
 * This can lead to deadlocks in multithreaded applications, so we use EV_FINALIZE
 */
static void vpn_timer_event_free_finalize(event *ev) {
    if (ev) {
        event_free_finalize(0, ev, [](event *, void *arg) {
            delete (DeferredTaskCtx *) arg;
        });
    }
}

enum EventLoopState {
    ELS_STOPPED,
    ELS_RUNNING,
    ELS_BASE_EXITED,
};

struct VpnEventLoop {
    DeclPtr<event_base, &event_base_free> ev_base{make_event_base()};
    mutable std::mutex guard;
    std::condition_variable stop_barrier;
    bool task_queue_scheduled = false;
    std::list<TaskInfo> task_queue;
    std::list<DeferredTaskInfo> deferred_task_queue;
    EventLoopState state = ELS_STOPPED;
    bool stopping_externally = false;
    ag::Logger log{"EVLOOP"};
    int id = g_next_loop_id++;
    std::shared_ptr<bool> shutdown_guard = std::make_shared<bool>(true);
};

extern "C" struct evthread_lock_callbacks *evthread_get_lock_callbacks(void);

static const struct EventLoopStaticInitializer {
    EventLoopStaticInitializer() {
#ifndef NDEBUG
        event_enable_debug_mode();
#endif
        // Check if `evthread_use_*()` was called before, because calling it twice leads to
        // program termination in case Libevent's debugging checks are enabled
        if (evthread_get_lock_callbacks()->lock == nullptr) {
#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
            evthread_use_pthreads();
#endif
#ifdef EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED
            evthread_use_windows_threads();
            static WSADATA wsa_data;
            static const auto wsa_ret [[maybe_unused]] = WSAStartup(MAKEWORD(2, 2), &wsa_data);
            assert(wsa_ret == 0);
#endif
        }

#if 0
        event_enable_debug_logging(EVENT_DBG_ALL);
#endif

        event_set_log_callback([](int severity, const char *msg) {
            static ag::Logger libevent_logger{"LIBEVENT"};
            switch (severity) {
            case EVENT_LOG_DEBUG:
                dbglog(libevent_logger, "{}", msg);
                break;
            case EVENT_LOG_MSG:
                infolog(libevent_logger, "{}", msg);
                break;
            case EVENT_LOG_WARN:
                warnlog(libevent_logger, "{}", msg);
                break;
            case EVENT_LOG_ERR:
                errlog(libevent_logger, "{}", msg);
                break;
            default:
                dbglog(libevent_logger, "???: {}", msg);
                break;
            }
        });
    }
} ENSURE_INITIALIZED [[maybe_unused]];

VpnEventLoop *vpn_event_loop_create() {
    std::unique_ptr<VpnEventLoop> loop{new VpnEventLoop{}};
    if (loop->ev_base == nullptr) {
        log_loop(loop, err, "Failed to create event base");
        return nullptr;
    }
    return loop.release();
}

void vpn_event_loop_destroy(VpnEventLoop *loop) {
    assert(loop == nullptr || loop->task_queue.empty());
    assert(loop == nullptr || loop->deferred_task_queue.empty());
    delete loop;
}

int vpn_event_loop_run(VpnEventLoop *loop) {
    log_loop(loop, dbg, "...");

#ifdef __MACH__
    static auto ensure_sigpipe_ignored [[maybe_unused]] = signal(SIGPIPE, SIG_IGN);
#if !TARGET_OS_IPHONE
    if (0 != pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0)) {
        log_loop(loop, warn, "Failed to set qos class to user-initiated: {}", strerror(errno));
    }
#endif // TARGET_OS_IPHONE

#elif defined EVTHREAD_USE_PTHREADS_IMPLEMENTED
    // Block SIGPIPE
    sigset_t sigset, oldset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigset, &oldset);
#endif // __MACH__

    loop->guard.lock();
    assert(loop->state == ELS_STOPPED);
    loop->state = ELS_RUNNING;
    loop->guard.unlock();

    log_loop(loop, dbg, "Running event base...");
    int r = event_base_loop(loop->ev_base.get(), EVLOOP_NO_EXIT_ON_EMPTY);
    log_loop(loop, dbg, "Exited from event base ({})", r);
    if (r == -1) {
        log_loop(loop, err, "Error in event base: {}", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    loop->guard.lock();
    loop->state = (loop->stopping_externally) ? ELS_BASE_EXITED : ELS_STOPPED;
    loop->guard.unlock();
    loop->stop_barrier.notify_one();

#if defined(EVTHREAD_USE_PTHREADS_IMPLEMENTED) && !defined(__MACH__)
    // Restore SIGPIPE state
    pthread_sigmask(SIG_SETMASK, &oldset, nullptr);
#endif

    log_loop(loop, dbg, "Done");

    return r;
}

void vpn_event_loop_stop(VpnEventLoop *loop) {
    vpn_event_loop_exit(loop, Millis{0});
    vpn_event_loop_finalize_exit(loop);
}

void vpn_event_loop_exit(VpnEventLoop *loop, Millis timeout) {
    log_loop(loop, dbg, "...");
    timeval tv = ms_to_timeval(uint32_t(timeout.count()));
    event_base_loopexit(loop->ev_base.get(), &tv);
    log_loop(loop, dbg, "Done");
}

void vpn_event_loop_finalize_exit(VpnEventLoop *loop) {
    log_loop(loop, dbg, "...");

    std::unique_lock l(loop->guard);
    log_loop(loop, dbg, "Waiting until run finished (current state={})", magic_enum::enum_name(loop->state));
    loop->stopping_externally = true;
    loop->stop_barrier.wait(l, [loop]() -> bool {
        return loop->state != ELS_RUNNING;
    });
    log_loop(loop, dbg, "Run finish waited");

    for (TaskInfo &info : loop->task_queue) {
        if (info.task.finalize != nullptr) {
            log_task(loop, info.id, trace, "Finalizing");
            info.task.finalize(info.task.arg);
        }
    }
    loop->task_queue.clear();

    for (DeferredTaskInfo &info : loop->deferred_task_queue) {
        if (info.basic.task.finalize != nullptr) {
            log_task(loop, info.basic.id, trace, "Finalizing");
            info.basic.task.finalize(info.basic.task.arg);
        }
    }
    loop->deferred_task_queue.clear();

    loop->state = ELS_STOPPED;
    loop->stopping_externally = false;

    log_loop(loop, dbg, "Done");
}

TaskId vpn_event_loop_submit(VpnEventLoop *loop, VpnEventLoopTask task) {
    loop->guard.lock();

    TaskId task_id = g_next_task_id++;

    switch (loop->state) {
    case ELS_BASE_EXITED:
        loop->guard.unlock();
        if (task.finalize != nullptr) {
            log_task(loop, task_id, trace, "Finalizing immediately as loop is exited");
            task.finalize(task.arg);
        }
        return -1;
    case ELS_STOPPED:
    case ELS_RUNNING:
        // handled below
        break;
    }

    loop->task_queue.push_back({task_id, task});
    log_task(loop, task_id, trace, "Queued");

    if (!loop->task_queue_scheduled) {
        loop->task_queue_scheduled = true;
        loop->guard.unlock();

        event_base_once(loop->ev_base.get(), -1, EV_TIMEOUT, &run_task_queue, loop, nullptr);
    } else {
        loop->guard.unlock();
    }

    return task_id;
}

TaskId vpn_event_loop_schedule(VpnEventLoop *loop, VpnEventLoopTask task, Millis defer) {
    TaskId task_id = g_next_task_id++;

    loop->guard.lock();

    switch (loop->state) {
    case ELS_BASE_EXITED:
        loop->guard.unlock();
        log_task(loop, task_id, trace, "Finalizing immediately as loop is exited");
        task.finalize(task.arg);
        return -1;
    case ELS_STOPPED:
    case ELS_RUNNING:
        // handled below
        break;
    }

    DeferredTaskInfo &info = loop->deferred_task_queue.emplace_back(
            DeferredTaskInfo{{task_id, task}});

    // Will be freed by `vpn_timer_event_free_finalize`
    auto *task_ctx = new DeferredTaskCtx{loop, task_id};

    info.timer_event.reset(event_new(loop->ev_base.get(), -1, EV_FINALIZE, &run_deferred_task, task_ctx));
    const struct timeval tv = ms_to_timeval(uint32_t(defer.count()));
    event_add(info.timer_event.get(), &tv);

    log_task(loop, task_id, trace, "Scheduled");

    loop->guard.unlock();

    return task_id;
}

bool vpn_event_loop_dispatch_sync(VpnEventLoop *loop, void (*action)(void *), void *arg) {
    struct DispatchContext {
        void (*action)(void *);
        void *arg;
        std::mutex mutex;
        std::condition_variable cv;
        bool executed = false;
        bool finalized = false;
    };
    DispatchContext ctx{.action = action, .arg = arg};
    vpn_event_loop_submit(loop,
            {
                    .arg = &ctx,
                    .action =
                            [](void *arg, TaskId) {
                                auto *ctx = (DispatchContext *) arg;
                                if (ctx->action) {
                                    ctx->action(ctx->arg);
                                }
                                std::scoped_lock l(ctx->mutex);
                                ctx->executed = true;
                            },
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (DispatchContext *) arg;
                                // Hold the lock during `notify_all()` since `ctx` might be deleted after releasing
                                // `ctx->mutex`
                                std::scoped_lock l(ctx->mutex);
                                ctx->finalized = true;
                                ctx->cv.notify_all();
                            },
            });
    std::unique_lock l(ctx.mutex);
    ctx.cv.wait(l, [&] {
        return ctx.finalized;
    });
    return ctx.executed;
}

void vpn_event_loop_cancel(VpnEventLoop *loop, TaskId task_id) {
    log_task(loop, task_id, trace, "...");

    std::optional<TaskInfo> info;

    loop->guard.lock();

    for (auto i = loop->task_queue.begin(); i != loop->task_queue.end(); ++i) {
        if (i->id == task_id) {
            info = *i;
            loop->task_queue.erase(i);
            break;
        }
    }

    if (!info.has_value()) {
        for (auto i = loop->deferred_task_queue.begin(); i != loop->deferred_task_queue.end(); ++i) {
            if (i->basic.id == task_id) {
                info = i->basic;
                loop->deferred_task_queue.erase(i);
                break;
            }
        }
    }

    loop->guard.unlock();

    if (!info.has_value()) {
        log_task(loop, task_id, trace, "Not found");
    } else if (info->task.finalize != nullptr) {
        log_task(loop, task_id, trace, "Finalizing");
        info->task.finalize(info->task.arg);
    }
}

struct event_base *vpn_event_loop_get_base(const VpnEventLoop *loop) {
    if (loop == nullptr) {
        return nullptr;
    }
    return loop->ev_base.get();
}

bool vpn_event_loop_is_active(const VpnEventLoop *loop) {
    if (loop == nullptr) {
        return false;
    }

    std::scoped_lock l(loop->guard);
    return loop->state == ELS_RUNNING && !event_base_got_exit(loop->ev_base.get())
            && !event_base_got_break(loop->ev_base.get());
}

void vpn_event_loop_hijack(VpnEventLoop *loop) {
    log_loop(loop, dbg, "...");
    vpn_event_loop_exit(loop, {});

    std::unique_lock l(loop->guard);
    log_loop(loop, dbg, "Waiting until run finished (current state={})", magic_enum::enum_name(loop->state));
    loop->stopping_externally = true;
    loop->stop_barrier.wait(l, [loop]() -> bool {
        return loop->state != ELS_RUNNING;
    });
    log_loop(loop, dbg, "Run finish waited");

    loop->state = ELS_STOPPED;
    loop->stopping_externally = false;

    log_loop(loop, dbg, "Done");
}

namespace event_loop {

AutoTaskId make_auto_id(TaskId id) {
    return AutoTaskId{id};
}

AutoTaskId submit(VpnEventLoop *loop, VpnEventLoopTask task) {
    return {loop, loop->shutdown_guard, vpn_event_loop_submit(loop, task)};
}

static VpnEventLoopTask func_to_task(std::function<void()> &&func) {
    return VpnEventLoopTask{
            new std::function(std::move(func)),
            [](void *arg, TaskId) {
                auto *func = (std::function<void()> *) arg;
                (*func)();
            },
            [](void *arg) {
                delete (std::function<void()> *) arg;
            },
    };
}

AutoTaskId submit(VpnEventLoop *loop, std::function<void()> func) {
    return {loop, loop->shutdown_guard, vpn_event_loop_submit(loop, func_to_task(std::move(func)))};
}

AutoTaskId schedule(VpnEventLoop *loop, VpnEventLoopTask task, Millis defer) {
    return {loop, loop->shutdown_guard, vpn_event_loop_schedule(loop, task, defer)};
}

AutoTaskId schedule(VpnEventLoop *loop, std::function<void()> func, Millis defer) {
    return {loop, loop->shutdown_guard, vpn_event_loop_schedule(loop, func_to_task(std::move(func)), defer)};
}

AutoTaskId::AutoTaskId(VpnEventLoop *loop, std::weak_ptr<bool> weak, TaskId id)
        : m_loop(loop)
        , m_guard(std::move(weak))
        , m_id((id >= 0) ? std::make_optional<TaskId>(id) : std::nullopt) {
}

AutoTaskId::AutoTaskId(TaskId id)
        : m_id((id >= 0) ? std::make_optional<TaskId>(id) : std::nullopt) {
}

AutoTaskId::~AutoTaskId() {
    this->reset();
}

AutoTaskId::AutoTaskId(AutoTaskId &&other) noexcept {
    *this = std::move(other);
}

AutoTaskId &AutoTaskId::operator=(AutoTaskId &&other) noexcept {
    std::swap(m_loop, other.m_loop);
    std::swap(m_guard, other.m_guard);
    std::swap(m_id, other.m_id);
    return *this;
}

void AutoTaskId::reset() {
    if (m_loop != nullptr && m_id.has_value()) {
        if (!m_guard.expired()) {
            vpn_event_loop_cancel(m_loop, m_id.value());
        }
    }
    this->release();
}

void AutoTaskId::release() {
    m_loop = nullptr;
    m_guard.reset();
    m_id.reset();
}

bool AutoTaskId::has_value() const {
    return m_id.has_value();
}

bool AutoTaskId::operator<(const AutoTaskId &other) const {
    return m_id < other.m_id;
}

} // namespace event_loop

static event_base *make_event_base() {
    DeclPtr<event_base, &event_base_free> base{event_base_new()};
    if (base != nullptr && 0 != evthread_make_base_notifiable(base.get())) {
        return nullptr;
    }
    return base.release();
}

static void run_task_queue(evutil_socket_t, short, void *arg) {
    auto *loop = (VpnEventLoop *) arg;
    log_loop(loop, trace, "...");

    TaskId task_queue_last_id = -1;
    if (std::scoped_lock l(loop->guard); !loop->task_queue.empty()) {
        if (loop->task_queue.front().id <= loop->task_queue.back().id) {
            task_queue_last_id = loop->task_queue.back().id;
        } else {
            log_loop(loop, err, "Event loop inconsistency: front task id={} is larger than last task id={}",
                    loop->task_queue.front().id, loop->task_queue.back().id);
            task_queue_last_id = std::numeric_limits<TaskId>::max();
            // FIXME: we need to investigate this but at this time just execute whole queue.
            assert(0);
        }
    }
    TaskInfo info = {};
    for (size_t i = 0;; ++i) {
        {
            std::scoped_lock l(loop->guard);
            if (loop->task_queue.empty()) {
                loop->task_queue_scheduled = false;
                break;
            }
            if (loop->task_queue.front().id > task_queue_last_id || i == TASK_QUEUE_BUDGET) {
                event_base_once(loop->ev_base.get(), -1, EV_TIMEOUT, &run_task_queue, loop, nullptr);
                break;
            }
            info = loop->task_queue.front();
            loop->task_queue.pop_front();
        }

        log_task(loop, info.id, trace, "Running");
        info.task.action(info.task.arg, info.id);
        if (info.task.finalize != nullptr) {
            log_task(loop, info.id, trace, "Finalizing");
            info.task.finalize(info.task.arg);
        }
    }

    log_loop(loop, trace, "Done");
}

static void run_deferred_task(evutil_socket_t, short, void *arg) {
    auto *ctx = (DeferredTaskCtx *) arg;
    VpnEventLoop *loop = ctx->parent_loop;
    std::optional<DeferredTaskInfo> info;

    TaskId task_id = ctx->id;
    log_task(loop, task_id, trace, "...");

    {
        std::scoped_lock l(loop->guard);
        auto it = std::find_if(loop->deferred_task_queue.begin(), loop->deferred_task_queue.end(),
                [task_id](const DeferredTaskInfo &info) -> bool {
                    return info.basic.id == task_id;
                });
        if (it != loop->deferred_task_queue.end()) {
            info = std::move(*it);
            loop->deferred_task_queue.erase(it);
        }
    }

    if (info.has_value()) {
        log_task(loop, task_id, trace, "Running");
        info->basic.task.action(info->basic.task.arg, info->basic.id);
        if (info->basic.task.finalize != nullptr) {
            log_task(loop, task_id, trace, "Finalizing");
            info->basic.task.finalize(info->basic.task.arg);
        }
    } else {
        log_task(loop, task_id, trace, "Not found");
    }

    log_task(loop, task_id, trace, "Done");
}

} // namespace ag
