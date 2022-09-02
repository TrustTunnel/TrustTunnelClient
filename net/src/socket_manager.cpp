#include <net/socket_manager.h>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <iterator>
#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

static constexpr timeval LINGER_TV = {30, 0};

struct DeferredWriteCtx {
    SocketManager *manager = nullptr;
    DeclPtr<event, &event_free> ev;
    DeclPtr<bufferevent, &bufferevent_free> bev;
};

struct TimerSubscriber {
    void (*tick_handler)(void *arg, struct timeval now);
    void *arg;
};

struct TimerCallbackCtx {
    SocketManager *manager = nullptr;
    event_base *base = nullptr;
};

struct TimerInfo {
    DeclPtr<event, &event_free> ev;
    std::unique_ptr<TimerCallbackCtx> ctx;
    std::map<int, TimerSubscriber> subscribers;
    uint32_t min_period = 0;
    int next_subscriber_id = 0;
};

struct TimevalComparator {
    bool operator()(const timeval &l, const timeval &r) const {
        return evutil_timercmp(&l, &r, <);
    }
};

struct DeferredWrites {
    std::unordered_map<evutil_socket_t, std::unique_ptr<DeferredWriteCtx>> by_fd;
    std::multimap<timeval, evutil_socket_t, TimevalComparator> deadlines;
    std::optional<int> timer_id;

    void insert(std::unique_ptr<DeferredWriteCtx> ctx);

    void remove_by_fd(evutil_socket_t fd);
};

struct SocketManager {
    DeferredWrites deferred_writes;
    std::optional<TimerInfo> timer;

    int timer_subscribe(event_base *base, uint32_t timeout_ms, void (*tick_handler)(void *, struct timeval), void *arg);

    void clear_writes();
};

// Private interface
/**
 * Complete data sending on bufferevent
 */
extern "C" bool socket_manager_complete_write(SocketManager *manager, struct bufferevent *bev);
/**
 * Subscribe to timer events.
 * Note, that `tick_handler` may be fired with the period less than the specified time out value.
 * @param manager the manager
 * @param loop event loop for operation
 *        (caller must always pass the same event loop)
 *        @todo: remove the restriction above
 * @param timeout_ms time out value of the subscriber
 * @param tick_handler timer tick handler
 * @param arg user context
 * @return <0 if failed, otherwise the subscriber idendtifier
 */
extern "C" int socket_manager_timer_subscribe(SocketManager *manager, VpnEventLoop *loop, uint32_t timeout_ms,
        void (*tick_handler)(void *arg, struct timeval now), void *arg);
/**
 * Unsubscribe from timer events
 * @param manager the manager
 * @param id the subscriber identifier returned from `socket_manager_timer_subscribe`
 */
extern "C" void socket_manager_timer_unsubscribe(SocketManager *manager, int id);

/**
 * Socket's bufferevent after-destruction handler for write flush (shutdowns socket writes)
 * @param bev Bufferevent handle
 */
static void free_after_flush(struct bufferevent *bev, void *arg) {
    if (evbuffer_get_length(bufferevent_get_output(bev)) != 0) {
        // Ignore in case the event was scheduled before zeroing the watermark.
        // Libevent will eventually raise this event once the buffer is exhausted.
        return;
    }
    shutdown(bufferevent_getfd(bev), AG_SHUT_WR);
    auto *self = (SocketManager *) arg;
    self->deferred_writes.remove_by_fd(bufferevent_getfd(bev));
    if (self->deferred_writes.by_fd.empty()) {
        self->clear_writes();
    }
}

/**
 * Socket's bufferevent after-destruction handler for socket errors and eof (frees socket)
 * @param bev Bufferevent handle
 */
static void free_after_event(bufferevent *bev, short, void *arg) {
    auto *self = (SocketManager *) arg;
    self->deferred_writes.remove_by_fd(bufferevent_getfd(bev));
    if (self->deferred_writes.by_fd.empty()) {
        self->clear_writes();
    }
}

static void deferred_write_timer_tick(void *arg, struct timeval) {
    auto *self = (SocketManager *) arg;

    if (!self->deferred_writes.by_fd.empty()) {
        timeval now = {};
        event_base_gettimeofday_cached(
                // @todo: handle different bases
                bufferevent_get_base(self->deferred_writes.by_fd.begin()->second->bev.get()), &now);

        auto non_expired = self->deferred_writes.deadlines.upper_bound(now);
        for (auto it = self->deferred_writes.deadlines.begin(); it != non_expired; ++it) {
            self->deferred_writes.remove_by_fd(it->second);
        }
        self->deferred_writes.deadlines.erase(self->deferred_writes.deadlines.begin(), non_expired);
    }

    if (self->deferred_writes.by_fd.empty()) {
        self->clear_writes();
    }
}

SocketManager *socket_manager_create() {
    auto *manager = new SocketManager{};
    return manager;
}

void socket_manager_complete_all(SocketManager *manager) {
    manager->clear_writes();
    manager->timer.reset();
}

void socket_manager_destroy(SocketManager *manager) {
    delete manager;
}

bool socket_manager_complete_write(SocketManager *manager, struct bufferevent *bev) {
    if (!manager->deferred_writes.by_fd.empty()) {
        // @todo: handle different bases
        assert(bufferevent_get_base(bev)
                == bufferevent_get_base(manager->deferred_writes.by_fd.begin()->second->bev.get()));
    }

    std::unique_ptr<DeferredWriteCtx> ctx = std::make_unique<DeferredWriteCtx>();
    ctx->manager = manager;
    ctx->bev.reset(bev);

    if (!manager->deferred_writes.timer_id.has_value()) {
        int id = manager->timer_subscribe(
                bufferevent_get_base(bev), uint32_t(timeval_to_ms(LINGER_TV)), deferred_write_timer_tick, manager);
        if (id < 0) {
            return false;
        }
        manager->deferred_writes.timer_id = id;
    }

    // if we didn't write all data in 30 seconds, force close
    bufferevent_set_timeouts(ctx->bev.get(), nullptr, &LINGER_TV);
    bufferevent_setwatermark(ctx->bev.get(), EV_WRITE, 0, 0);
    bufferevent_setcb(ctx->bev.get(), nullptr, free_after_flush, free_after_event, manager);

    manager->deferred_writes.insert(std::move(ctx));

    return true;
}

static void timer_callback(evutil_socket_t, short, void *arg) {
    auto *ctx = (TimerCallbackCtx *) arg;
    if (!ctx->manager->timer.has_value()) {
        return;
    }

    timeval now; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    event_base_gettimeofday_cached(ctx->base, &now);

    const TimerInfo &timer = ctx->manager->timer.value();
    std::vector<TimerSubscriber> subscribers;
    subscribers.reserve(timer.subscribers.size());

    std::transform(timer.subscribers.begin(), timer.subscribers.end(), std::back_inserter(subscribers),
            [](const auto &i) -> TimerSubscriber {
                return i.second;
            });

    for (const TimerSubscriber &s : subscribers) {
        s.tick_handler(s.arg, now);
    }
}

int socket_manager_timer_subscribe(SocketManager *manager, VpnEventLoop *loop, uint32_t timeout_ms,
        void (*tick_handler)(void *, struct timeval), void *arg) {
    return manager->timer_subscribe(vpn_event_loop_get_base(loop), timeout_ms, tick_handler, arg);
}

void socket_manager_timer_unsubscribe(SocketManager *manager, int id) {
    if (!manager->timer.has_value()) {
        return;
    }

    TimerInfo &timer = manager->timer.value();
    timer.subscribers.erase(id);
    if (timer.subscribers.empty()) {
        manager->timer.reset();
    }
}

int SocketManager::timer_subscribe(
        event_base *base, uint32_t timeout_ms, void (*tick_handler)(void *, struct timeval), void *arg) {
    if (!this->timer.has_value()) {
        this->timer = std::make_optional<TimerInfo>();
        this->timer->ctx = std::make_unique<TimerCallbackCtx>(TimerCallbackCtx{this, base});
        this->timer->ev.reset(event_new(base, -1, EV_PERSIST, timer_callback, this->timer->ctx.get()));
    }

    TimerInfo &timer_info = this->timer.value();
    uint32_t new_period = (timer_info.min_period == 0) ? timeout_ms : std::min(timer_info.min_period, timeout_ms);
    if (timer_info.min_period == 0 || new_period < timer_info.min_period) {
        timeval tv = ms_to_timeval(new_period / 4);
        if (0 != event_del(timer_info.ev.get()) || 0 != event_add(timer_info.ev.get(), &tv)) {
            return -1;
        }
        timer_info.min_period = new_period;
    }

    int id = timer_info.next_subscriber_id++;
    timer_info.subscribers[id] = {tick_handler, arg};

    return id;
}

void SocketManager::clear_writes() {
    this->deferred_writes.by_fd.clear();
    this->deferred_writes.deadlines.clear();
    if (this->deferred_writes.timer_id.has_value()) {
        socket_manager_timer_unsubscribe(this, std::exchange(this->deferred_writes.timer_id, std::nullopt).value());
    }
}

void DeferredWrites::insert(std::unique_ptr<DeferredWriteCtx> ctx) {
    bufferevent *bev = ctx->bev.get();
    evutil_socket_t fd = bufferevent_getfd(bev);

    timeval now; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    event_base_gettimeofday_cached(bufferevent_get_base(bev), &now);

    timeval deadline; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
    evutil_timeradd(&now, &LINGER_TV, &deadline);

    this->by_fd.insert(std::make_pair(fd, std::move(ctx)));
    this->deadlines.insert(std::make_pair(deadline, fd));
}

void DeferredWrites::remove_by_fd(evutil_socket_t fd) {
    this->by_fd.erase(fd);
}

} // namespace ag
