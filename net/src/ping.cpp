#ifndef _WIN32
#include <net/if.h>
#endif
#ifdef __MACH__
#include <sys/socket.h>
#endif

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <list>
#include <string>

#include <event2/event.h>

#include "common/logger.h"
#include "net/os_tunnel.h"
#include "net/utils.h"
#include "ping.h"
#include "vpn/utils.h"

// These includes must be here in order to compile
#include <openssl/rand.h>

namespace ag {

static ag::Logger g_logger{"PING"}; // NOLINT(cert-err58-cpp)

#define log_ping(ping_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (ping_)->id, ##__VA_ARGS__)

static std::atomic_int g_next_id;

using PingClock = std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;

static constexpr int MIN_SHORT_TIMEOUT_MS = 50;
static constexpr int MAX_SHORT_TIMEOUT_MS = 400;

static constexpr size_t QUIC_VERSION_PROBE_CONN_ID_LENGTH = 20;
static constexpr size_t QUIC_VERSION_PROBE_LENGTH = 2 * QUIC_VERSION_PROBE_CONN_ID_LENGTH + 7;

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
    int socket_error = 0;
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

    uint32_t rounds_failed;
    uint32_t rounds_started;
    uint32_t rounds_total;
    uint32_t round_timeout_ms;

    event_loop::AutoTaskId prepare_task_id;
    event_loop::AutoTaskId connect_task_id;
    event_loop::AutoTaskId report_task_id;

    bool have_round_winner;
    bool use_quic;
};

static void do_prepare(void *arg);
static void do_report(void *arg);
static void do_connect(void *arg);
static void on_event(evutil_socket_t fd, short, void *arg);
static void on_timer(evutil_socket_t fd, short, void *arg);
static std::array<uint8_t, QUIC_VERSION_PROBE_LENGTH> prepare_quic_version_probe();

static void on_event(evutil_socket_t fd, short, void *arg) {
    auto *self = (Ping *) arg;

    auto it = std::find_if(self->syn_sent.begin(), self->syn_sent.end(), [&](const PingConn &ep) {
        return ep.fd.get() == fd;
    });
    assert(it != self->syn_sent.end());

    ev_socklen_t error_len = sizeof(it->socket_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &it->socket_error, &error_len);
    if (it->socket_error != 0) {
        self->errors.splice(self->errors.end(), self->syn_sent, it);
        log_ping(self, dbg, "Failed to connect to {} via {}: ({}) {}", sockaddr_to_str((sockaddr *) &it->dest),
                it->bound_if_name, it->socket_error, evutil_socket_error_to_string(it->socket_error));
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

// Return 0 if connection started successfully (including if it is inprogress), errno (or equivalent) otherwise.
static int xconnect(const PingConn &ep) {
    if (0 == connect(ep.fd.get(), (sockaddr *) &ep.dest, (int) sockaddr_get_size((sockaddr *) &ep.dest))) {
        return 0;
    }
    int error = evutil_socket_geterror(ep.fd.get());
#ifdef _WIN32
    return WSAEWOULDBLOCK == error ? 0 : error;
#else
    return EINPROGRESS == error ? 0 : error;
#endif
}

// Return 0 if initial packet was sent successfully, errno (or equivalent) otherwise.
static int send_quic_version_probe(const PingConn &ep) {
    auto probe = prepare_quic_version_probe();
    if ((int) probe.size()
            != sendto(ep.fd.get(), (char *) probe.data(), (int) probe.size(), 0, (sockaddr *) &ep.dest,
                    (int) sockaddr_get_size((sockaddr *) &ep.dest))) {
        return evutil_socket_geterror(ep.fd.get());
    }
    return 0;
}

static void do_connect(void *arg) {
    auto *self = (Ping *) arg;
    self->connect_task_id.release();

    assert(!self->pending.empty());

    auto it = self->pending.begin();
    assert(it->fd.valid());

    log_ping(self, trace, "Connecting to {} via {}", sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
    it->started_at = PingClock::now();
    it->socket_error = self->use_quic ? send_quic_version_probe(*it) : xconnect(*it);
    if (it->socket_error != 0) {
        log_ping(self, dbg, "Failed to connect to {} via {}: connect: ({}) {}", sockaddr_to_str((sockaddr *) &it->dest),
                it->bound_if_name, it->socket_error, evutil_socket_error_to_string(it->socket_error));
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

    PingResult result{
            .ping = self,
            .status = PING_OK,
    };

    if (!self->done.empty()) {
        auto it = self->done.begin();
        result.addr = (sockaddr *) &it->dest;
        if (it->best_result_ms.has_value()) {
            result.ms = it->best_result_ms.value();
        } else {
            result.status = PING_TIMEDOUT;
        }
        self->handler.func(self->handler.arg, &result);
        self->done.pop_front();
        goto schedule_next;
    }

    if (!self->errors.empty()) {
        auto it = self->errors.begin();
        result.addr = (sockaddr *) &it->dest;
        if (it->best_result_ms.has_value()) {
            result.ms = it->best_result_ms.value();
        } else {
            result.status = PING_SOCKET_ERROR;
            result.socket_error = it->socket_error;
        }
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

    if (!self->use_quic && self->done.empty() && !self->errors.empty()
            && ++self->rounds_failed == self->rounds_total - 1) {
        self->use_quic = true;
    }

    log_ping(self, dbg, "Starting round {} of {}", self->rounds_started, self->rounds_total);

    self->pending.splice(self->pending.end(), self->errors);
    self->pending.splice(self->pending.end(), self->done);

    auto tv = ms_to_timeval(self->round_timeout_ms);
    evtimer_add(self->timer.get(), &tv);

    for (auto it = self->pending.begin(); it != self->pending.end();) {
        it->fd = AutoFd(socket(it->dest.ss_family, self->use_quic ? SOCK_DGRAM : SOCK_STREAM, 0)); // NOLINT(cppcoreguidelines-narrowing-conversions,bugprone-narrowing-conversions)
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
#else  // #ifdef __MACH__
            int error = setsockopt(
                    it->fd.get(), SOL_SOCKET, SO_BINDTODEVICE, it->bound_if_name.data(), it->bound_if_name.size());
#endif // #ifdef __MACH__
            if (error) {
                log_ping(self, dbg, "Failed to connect to {} via {}: failed to bind socket to interface: ({}) {}",
                        sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name, errno, strerror(errno));
                goto error;
            }
        }
#else  // #ifndef _WIN32
        if (!vpn_win_socket_protect(it->fd.get(), (sockaddr *) &it->dest)) {
            log_ping(self, dbg, "Failed to connect to {} via {}: failed to protect socket",
                    sockaddr_to_str((sockaddr *) &it->dest), it->bound_if_name);
            goto error;
        }
#endif // #ifndef _WIN32
        if (!self->use_quic) {
            // Send RST as soon as socket is closed.
            linger linger_0 = {.l_onoff = 1, .l_linger = 0};
            setsockopt(it->fd.get(), SOL_SOCKET, SO_LINGER, (char *) &linger_0, (int) sizeof(linger_0));
        }
        it->event.reset(event_new(vpn_event_loop_get_base(self->loop), it->fd.get(),
                self->use_quic ? EV_READ : EV_WRITE, on_event, self));
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

    if (info->loop == nullptr) {
        log_ping(self, warn, "Invalid settings");
        return nullptr;
    }
    if (handler.func == nullptr) {
        log_ping(self, warn, "Invalid handler");
        return nullptr;
    }

    self->loop = info->loop;
    self->handler = handler;
    self->use_quic = info->use_quic;

    self->rounds_total = info->nrounds ? info->nrounds : DEFAULT_PING_ROUNDS;
    self->round_timeout_ms = info->timeout_ms ? info->timeout_ms : DEFAULT_PING_TIMEOUT_MS;

    self->round_timeout_ms /= self->rounds_total;
    self->timer.reset(evtimer_new(vpn_event_loop_get_base(self->loop), on_timer, self.get()));

    assert(self->rounds_total > 0);
    assert(self->round_timeout_ms > 0);

    constexpr uint32_t DEFAULT_IF_IDX = 0;
    std::span<uint32_t> interfaces = info->interfaces_to_query;
    if (interfaces.empty()) {
        interfaces = {(uint32_t *) &DEFAULT_IF_IDX, size_t(1)};
    }
    for (const sockaddr_storage &addr : info->addrs) {
        for (uint32_t bound_if : interfaces) {
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

std::array<uint8_t, QUIC_VERSION_PROBE_LENGTH> prepare_quic_version_probe() {
    std::array<uint8_t, QUIC_VERSION_PROBE_LENGTH> probe{};
    RAND_bytes(probe.data(), QUIC_VERSION_PROBE_LENGTH);

    // Set the first bit to "1" for "long header".
    probe[0] |= 0x80;

    // This should be enough according to the spec (the remaining 7 bits are version-specific),
    // but Quiche also reads the packet type. Give it "Handshake" by zeroing the bits 3 and 4
    // and setting them to `2`. This way Quiche doesn't try to read past the connection IDs.
    probe[0] = (probe[0] & 0xcf) | 0x20;

    // Set the version to 0x?a?a?a?a to elicit version negotiation.
    probe[1] = (probe[1] & 0xf0) | 0x0a;
    probe[2] = (probe[2] & 0xf0) | 0x0a;
    probe[3] = (probe[3] & 0xf0) | 0x0a;
    probe[4] = (probe[4] & 0xf0) | 0x0a;

    probe[5] = QUIC_VERSION_PROBE_CONN_ID_LENGTH;
    probe[6 + QUIC_VERSION_PROBE_CONN_ID_LENGTH] = QUIC_VERSION_PROBE_CONN_ID_LENGTH;

    return probe;
}

} // namespace ag
