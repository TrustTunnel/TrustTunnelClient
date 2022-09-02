#include "ping.h"

#ifndef _WIN32
#include <net/if.h>
#else
#include <Netioapi.h>
#endif

#ifdef __MACH__
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <atomic>
#include <cassert>
#include <chrono>
#include <list>
#include <string>
#include <unordered_set>

#include <event2/event.h>

#include "common/logger.h"
#include "net/utils.h"
#include "vpn/utils.h"

namespace ag {

static ag::Logger g_logger{"PING"}; // NOLINT(cert-err58-cpp)

#define log_ping(ping_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (ping_)->id, ##__VA_ARGS__)

static std::atomic<uint32_t> g_bound_if = 0;
static std::atomic_int g_next_id;

using PingClock = std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;

static constexpr int MIN_SHORT_TIMEOUT_MS = 50;
static constexpr int MAX_SHORT_TIMEOUT_MS = 400;

class AutoFd {
private:
    evutil_socket_t m_fd = -1;

public:
    AutoFd() = default;
    explicit AutoFd(evutil_socket_t fd)
            : m_fd{fd} {
    }
    ~AutoFd() {
        reset();
    }

    AutoFd(const AutoFd &) = delete;
    AutoFd &operator=(const AutoFd &) = delete;

    AutoFd(AutoFd &&other) noexcept {
        *this = std::move(other);
    }

    AutoFd &operator=(AutoFd &&other) noexcept {
        std::swap(m_fd, other.m_fd);
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept {
        return m_fd != -1;
    }

    [[nodiscard]] evutil_socket_t get() const noexcept {
        return m_fd;
    }

    void reset() noexcept {
        evutil_closesocket(std::exchange(m_fd, -1));
    }
};

struct PingConn {
    sockaddr_storage dest{};
    AutoFd fd;
    DeclPtr<event, &event_free> event;
    PingClock::time_point started_at;
    std::optional<int> best_result_ms;
    uint32_t bound_if = 0;
    std::string bound_if_name;
};

struct Ping {
    int id = g_next_id.fetch_add(1, std::memory_order_relaxed);

    VpnEventLoop *loop;
    PingHandler handler;

    std::list<PingConn> pending;
    std::list<PingConn> syn_sent;
    std::list<PingConn> errors;
    std::list<PingConn> done;

    DeclPtr<event, &event_free> timer;

    uint32_t rounds_started;
    uint32_t rounds_total;
    uint32_t round_timeout_ms;

    event_loop::AutoTaskId prepare_task_id;
    event_loop::AutoTaskId connect_task_id;
    event_loop::AutoTaskId report_task_id;

    bool have_round_winner;
};

static void do_prepare(void *arg);
static void do_report(void *arg);
static void do_connect(void *arg);
static void on_event(evutil_socket_t fd, short, void *arg);
static void on_timer(evutil_socket_t fd, short, void *arg);

static void on_event(evutil_socket_t fd, short, void *arg) {
    auto *self = (Ping *) arg;

    auto it = std::find_if(self->syn_sent.begin(), self->syn_sent.end(), [&](const PingConn &ep) {
        return ep.fd.get() == fd;
    });
    assert(it != self->syn_sent.end());

    int error = 0;
    ev_socklen_t error_len = sizeof(error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &error, &error_len);
    if (error != 0) {
        self->errors.splice(self->errors.end(), self->syn_sent, it);
        log_ping(self, dbg, "Failed to connect to {} via {}: ({}) {}", sockaddr_to_str((sockaddr *) &it->dest),
                it->bound_if_name, error, evutil_socket_error_to_string(error));
    } else {
        auto dt = PingClock::now() - it->started_at;
        auto dt_ms = int(duration_cast<milliseconds>(dt).count());
        it->best_result_ms = std::min(dt_ms, it->best_result_ms.value_or(INT_MAX));
        it->fd.reset();
        it->event.reset();
        self->done.splice(self->done.end(), self->syn_sent, it);
        log_ping(self, trace, "Connected to {} via {} in {} ms", sockaddr_to_str((sockaddr *) &it->dest),
                it->bound_if_name, dt_ms);

        if (!std::exchange(self->have_round_winner, true)) {
            uint32_t to_ms = std::min(2 * dt_ms + MIN_SHORT_TIMEOUT_MS, MAX_SHORT_TIMEOUT_MS);
            auto to_tv = ms_to_timeval(to_ms);
            evtimer_add(self->timer.get(), &to_tv);
            log_ping(self, dbg, "Reducing round timeout to {} ms", to_ms);
        }
    }

    if (self->syn_sent.empty() && self->pending.empty()) {
        log_ping(self, dbg, "Completed round {} of {}", self->rounds_started, self->rounds_total);
        evtimer_del(self->timer.get());
        self->prepare_task_id = event_loop::submit(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_prepare(arg);
                                },
                });
    }
}

// Round time out.
static void on_timer(evutil_socket_t, short, void *arg) {
    auto *self = (Ping *) arg;

    assert(!self->report_task_id.has_value());

    log_ping(self, dbg, "Round {} of {} timed out", self->rounds_started, self->rounds_total);

    self->done.splice(self->done.end(), self->syn_sent);
    self->done.splice(self->done.end(), self->pending);
    for (PingConn &ep : self->done) {
        ep.fd.reset();
        ep.event.reset();
    }

    self->connect_task_id.reset();
    self->prepare_task_id = event_loop::submit(self->loop,
            {
                    .arg = self,
                    .action =
                            [](void *arg, TaskId) {
                                do_prepare(arg);
                            },
            });
}

// Return 0 if connection started successfully (including if it is inprogress).
static int xconnect(const PingConn &ep) {
    if (0
            == connect(ep.fd.get(), (sockaddr *) &ep.dest,
                    sockaddr_get_size((sockaddr *) &ep.dest))) { // NOLINT(cppcoreguidelines-narrowing-conversions)
        return 0;
    }
    int error = evutil_socket_geterror(ep.fd.get());
#ifdef _WIN32
    return WSAEWOULDBLOCK == error ? 0 : error;
#else
    return EINPROGRESS == error ? 0 : error;
#endif
}

static void do_connect(void *arg) {
    auto *self = (Ping *) arg;
    self->connect_task_id.release();

    assert(!self->pending.empty());

    auto it = self->pending.begin();
    assert(it->fd.valid());

    log_ping(self, trace, "Connecting to {} via {}", sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
    it->started_at = PingClock::now();
    int error = xconnect(*it);
    if (error != 0) {
        log_ping(self, dbg, "Failed to connect to {} via {}: connect: ({}) {}", sockaddr_to_str((sockaddr *) &it->dest),
                it->bound_if_name, error, evutil_socket_error_to_string(error));
        goto error;
    }
    if (0 != event_add(it->event.get(), nullptr)) {
        log_ping(self, dbg, "Failed to connect to {} via {}: failed to add event",
                sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
        goto error;
    }

    self->syn_sent.splice(self->syn_sent.end(), self->pending, it);
    goto next;

error:
    it->fd.reset();
    it->event.reset();
    self->errors.splice(self->errors.end(), self->pending, it);

next:
    if (!self->pending.empty()) {
        // Schedule next connect. Don't connect all in one go to avoid stalling the loop.
        self->connect_task_id = event_loop::schedule(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_connect(arg);
                                },
                },
                Millis{1} /*ms to force libevent ot poll/select between connect callss*/);
    }
}

static void do_report(void *arg) {
    auto *self = (Ping *) arg;
    self->report_task_id.release();

    assert(self->syn_sent.empty());
    assert(self->pending.empty());
    assert(!self->connect_task_id.has_value());
    assert(!self->prepare_task_id.has_value());

    PingResult result{.ping = self};

    if (!self->done.empty()) {
        auto it = self->done.begin();
        result.addr = (sockaddr *) &it->dest;
        result.status = it->best_result_ms ? PING_OK : PING_TIMEDOUT;
        result.ms = it->best_result_ms.value_or(-1);
        self->handler.func(self->handler.arg, &result);
        self->done.pop_front();
        goto schedule_next;
    }

    if (!self->errors.empty()) {
        auto it = self->errors.begin();
        result.addr = (sockaddr *) &it->dest;
        result.status = it->best_result_ms ? PING_OK : PING_SOCKET_ERROR;
        result.ms = it->best_result_ms.value_or(-1);
        self->handler.func(self->handler.arg, &result);
        self->errors.pop_front();
        goto schedule_next;
    }

    result.status = PING_FINISHED;
    self->handler.func(self->handler.arg, &result);
    return;

schedule_next:
    self->report_task_id = event_loop::submit(self->loop,
            {
                    .arg = self,
                    .action =
                            [](void *arg, TaskId) {
                                do_report(arg);
                            },
            });
}

// Start a new round, creating and configuring all sockets and events and scheduling
// the connect call, or report the result if all rounds have been completed.
static void do_prepare(void *arg) {
    auto *self = (Ping *) arg;
    self->prepare_task_id.release();

    assert(!self->connect_task_id.has_value());
    assert(!self->report_task_id.has_value());
    assert(self->syn_sent.empty());
    assert(!self->pending.empty() ? (self->errors.empty() && self->done.empty())
                                  : (!self->errors.empty() || !self->done.empty()));

    if (self->rounds_total == self->rounds_started) {
        log_ping(self, dbg, "Pinging done, reporting results", self->rounds_started, self->rounds_total);
        self->timer.reset();
        self->report_task_id = event_loop::submit(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_report(arg);
                                },
                });
        return;
    }

    ++self->rounds_started;
    self->have_round_winner = false;

    log_ping(self, dbg, "Starting round {} of {}", self->rounds_started, self->rounds_total);

    self->pending.splice(self->pending.end(), self->errors);
    self->pending.splice(self->pending.end(), self->done);

    auto tv = ms_to_timeval(self->round_timeout_ms);
    evtimer_add(self->timer.get(), &tv);

    for (auto it = self->pending.begin(); it != self->pending.end();) {
        it->fd = AutoFd(socket(it->dest.ss_family, SOCK_STREAM, 0)); // NOLINT(cppcoreguidelines-narrowing-conversions)
        if (!it->fd.valid()) {
            log_ping(self, dbg, "Failed to connect to {} via {}: failed to create socket",
                    sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
            goto error;
        }
        if (0 != evutil_make_socket_nonblocking(it->fd.get())) {
            log_ping(self, dbg, "Failed to connect to {} via {}: failed to make socket non-blocking",
                    sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
            goto error;
        }
#ifndef _WIN32
        if (it->bound_if != 0) {
#ifdef __MACH__
            int option = (it->dest.ss_family == AF_INET) ? IP_BOUND_IF : IPV6_BOUND_IF;
            int level = (it->dest.ss_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
            int error = setsockopt(it->fd.get(), level, option, &it->bound_if, sizeof(it->bound_if));
#else
            int error = setsockopt(
                    it->fd.get(), SOL_SOCKET, SO_BINDTODEVICE, it->bound_if_name.data(), it->bound_if_name.size());
#endif
            if (error) {
                log_ping(self, dbg, "Failed to connect to {} via {}: faild to bind socket to interface: ({}) {}",
                        sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name, errno, strerror(errno));
                goto error;
            }
        }
#endif
        it->event.reset(event_new(vpn_event_loop_get_base(self->loop), it->fd.get(), EV_WRITE, on_event, self));
        if (it->event == nullptr) {
            log_ping(self, dbg, "Failed to connect to {} via {}: failed to create event",
                    sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
            goto error;
        }
        ++it;
        continue;
    error:
        it->fd.reset();
        auto next = std::next(it);
        self->errors.splice(self->errors.end(), self->pending, it);
        it = next;
    }

    if (self->pending.empty()) {
        // All errors, start next round or report result.
        // If this round is not the last, move errors to pending to try again.
        if (self->rounds_started != self->rounds_total) {
            self->pending.splice(self->pending.end(), self->errors);
        }
        self->prepare_task_id = event_loop::submit(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_prepare(arg);
                                },
                });
    } else {
        // Start first connect
        self->connect_task_id = event_loop::submit(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_connect(arg);
                                },
                });
    }
}

Ping *ping_start(const PingInfo *info, PingHandler handler) {
    DeclPtr<Ping, &ping_destroy> self{new Ping{}};
    log_ping(self, trace, "...");

    assert(info->loop);
    self->loop = info->loop;

    assert(handler.func);
    self->handler = handler;

    if ((self->rounds_total = info->nrounds) == 0) {
        self->rounds_total = DEFAULT_PING_ROUNDS;
    }
    if ((self->round_timeout_ms = info->timeout_ms) == 0) {
        self->round_timeout_ms = DEFAULT_PING_TIMEOUT_MS;
    }
    self->round_timeout_ms /= self->rounds_total;
    self->timer.reset(evtimer_new(vpn_event_loop_get_base(self->loop), on_timer, self.get()));

    assert(self->rounds_total > 0);
    assert(self->round_timeout_ms > 0);

    std::unordered_set<uint32_t> ifs;
#ifdef __MACH__
    if (info->query_all_interfaces) {
        ifaddrs *addrs = nullptr;
        getifaddrs(&addrs);
        for (ifaddrs *it = addrs; it; it = it->ifa_next) {
            if (!(it->ifa_flags & IFF_UP)) {
                continue;
            }
            if (it->ifa_name == nullptr || !strncmp(it->ifa_name, "lo", 2) || !strncmp(it->ifa_name, "utun", 4)
                    || !strncmp(it->ifa_name, "tun", 3) || !strncmp(it->ifa_name, "ipsec", 5)) {
                continue;
            }
            if (it->ifa_addr == nullptr
                    || (it->ifa_addr->sa_family != AF_INET && it->ifa_addr->sa_family != AF_INET6)) {
                continue;
            }
            if (it->ifa_addr->sa_family == AF_INET6) {
                uint16_t first_group = ntohs(((uint16_t *) &((sockaddr_in6 *) it->ifa_addr)->sin6_addr)[0]);
                // Skip interfaces without unicast and ULA addresses:
                // 2000::/3 Global unicast
                // fc00::/7 ULA
                if ((first_group & ~(uint16_t(~0) >> 3)) != 0x2000 && (first_group & ~(uint16_t(~0) >> 7)) != 0xfc00) {
                    continue;
                }
            }
            uint32_t ifindex = if_nametoindex(it->ifa_name);
            ifs.insert(ifindex);
        }
        freeifaddrs(addrs);
    } else
#endif
    {
        ifs.insert(g_bound_if.load(std::memory_order_relaxed));
    }

    for (const sockaddr_storage &addr : info->addrs) {
        for (uint32_t bound_if : ifs) {
            PingConn &endpoint = self->pending.emplace_back();
            endpoint.dest = addr;
            endpoint.bound_if = bound_if;

            char buf[IF_NAMESIZE]{};
            if (bound_if != 0) {
                if (if_indextoname(bound_if, buf)) {
                    endpoint.bound_if_name = buf;
                } else {
#ifndef _WIN32
                    log_ping(self, dbg, "if_indextoname: ({}) {}", errno, strerror(errno));
#else
                    log_ping(self, dbg, "if_indextoname failed");
#endif
                    endpoint.bound_if_name = "(unknown)";
                }
            } else {
                endpoint.bound_if_name = "(default)";
            }
        }
    }

    if (self->pending.empty()) {
        self->report_task_id = event_loop::submit(self->loop,
                {
                        .arg = self.get(),
                        .action =
                                [](void *arg, TaskId) {
                                    do_report(arg);
                                },
                });
    } else {
        self->prepare_task_id = event_loop::submit(self->loop,
                {
                        .arg = self.get(),
                        .action =
                                [](void *arg, TaskId) {
                                    do_prepare(arg);
                                },
                });
    }

    log_ping(self, trace, "Done");
    return self.release();
}

void ping_destroy(Ping *ping) {
    log_ping(ping, trace, "");
    delete ping;
}

int ping_get_id(const Ping *ping) {
    return ping->id;
}

#ifndef _WIN32
void ping_set_bound_if(uint32_t bound_if) {
    g_bound_if.store(bound_if, std::memory_order_relaxed);
}
#endif

} // namespace ag
