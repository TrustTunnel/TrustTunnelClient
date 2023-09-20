#include "ping.h"

#ifndef _WIN32
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <list>
#include <string>
#include <unordered_set>
#include <vector>

#include <event2/event.h>
#include <magic_enum.hpp>

#include "common/logger.h"
#include "common/net_utils.h"
#include "net/os_tunnel.h"
#include "net/utils.h"
#include "vpn/utils.h"

// These includes must be here in order to compile
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <quiche.h>

namespace ag {

static ag::Logger g_logger{"PING"}; // NOLINT(cert-err58-cpp,cppcoreguidelines-avoid-non-const-global-variables)

#define log_ping(ping_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (ping_)->id, ##__VA_ARGS__)
#define log_conn(ping_, conn_, lvl_, fmt_, ...)                                                                        \
    log_ping(ping_, lvl_, "Round {}: {}{} ({}{}) via {}: " fmt_, (ping_)->rounds_started,                              \
            (conn_)->use_quic ? "udp://" : "tcp://", (conn_)->endpoint->name,                                          \
            (conn_)->relay_address.ss_family ? "through relay " : "",                                                  \
            (conn_)->relay_address.ss_family ? sockaddr_to_str((sockaddr *) &(conn_)->relay_address)                   \
                                             : sockaddr_to_str((sockaddr *) &(conn_)->endpoint->address),              \
            (conn_)->bound_if_name, ##__VA_ARGS__)

static std::atomic_int g_next_id; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

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

enum PingConnState {
    PCS_SYN_SENT,
    PCS_HELLO_FRAGMENT_SENT,
    PCS_HELLO_SENT,
};

struct PingConn {
    AutoVpnEndpoint endpoint;
    sockaddr_storage relay_address{};
    std::vector<uint8_t> hello;
    AutoFd fd;
    DeclPtr<event, &event_free> event;
    PingClock::time_point started_at;
    std::optional<int> best_result_ms;
    uint32_t bound_if = 0;
    std::string bound_if_name;
    int socket_error = 0;
    PingConnState state = PCS_SYN_SENT;
    bool use_quic = false;
    uint32_t rounds_done = 0;
};

struct Ping {
    int id = g_next_id.fetch_add(1, std::memory_order_relaxed);

    VpnEventLoop *loop;
    PingHandler handler;

    std::list<PingConn> pending; // Waiting to start connection.
    std::list<PingConn> inprogress; // Connection started.
    std::list<PingConn> done; // Ready for next round.
    std::list<PingConn> report; // Ready to report.

    DeclPtr<event, &event_free> timer;

    uint32_t rounds_target;
    uint32_t rounds_started;
    uint32_t round_timeout_ms;

    event_loop::AutoTaskId prepare_task_id;
    event_loop::AutoTaskId connect_task_id;
    event_loop::AutoTaskId hello_task_id;
    event_loop::AutoTaskId report_task_id;

    std::vector<sockaddr_storage> relay_addresses; // These are in reverse order compared to the ones in `PingInfo`.

    bool have_round_winner;
    bool anti_dpi;
    bool use_quic;
};

static void do_prepare(void *arg);
static void do_connect(void *arg);
static void do_report(void *arg);
static void on_event(evutil_socket_t fd, short, void *arg);
static void on_timer(evutil_socket_t fd, short, void *arg);
static std::vector<uint8_t> prepare_quic_initial(const char *sni);
static std::vector<uint8_t> prepare_client_hello(const char *sni);

static void on_event(evutil_socket_t fd, short, void *arg) {
    auto *self = (Ping *) arg;

    auto conn = std::find_if(self->inprogress.begin(), self->inprogress.end(), [&](const PingConn &ep) {
        return ep.fd.get() == fd;
    });
    assert(conn != self->inprogress.end());

    event_del(conn->event.get());

    ev_socklen_t error_len = sizeof(conn->socket_error);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &conn->socket_error, &error_len);

    if (conn->socket_error != 0) {
        log_conn(self, conn, dbg, "Failed in state {}: ({}) {}", magic_enum::enum_name(conn->state), conn->socket_error,
                evutil_socket_error_to_string(conn->socket_error));
        goto end_round;
    }

    switch (conn->state) {
    case PCS_SYN_SENT: // TCP connected, send hello.
        assert(!conn->use_quic);
        assert(!conn->hello.empty());

        log_conn(self, conn, trace, "Connected");

        if (self->anti_dpi) {
            assert(conn->hello.size() > DPI_SPLIT_SIZE);
            U8View hello{conn->hello.data(), DPI_SPLIT_SIZE};

            if (auto ret = send(conn->fd.get(), (char *) hello.data(), (int) hello.size(), 0); ret < 0) {
                conn->socket_error = evutil_socket_geterror(conn->fd.get());
                log_conn(self, conn, dbg, "Failed to send hello fragment: ({}) {}", conn->socket_error,
                        evutil_socket_error_to_string(conn->socket_error));
                goto end_round;
            } else if (ret != (int) hello.size()) {
                conn->socket_error = -1;
                log_conn(self, conn, dbg, "Failed to send hello fragment: no buffer space");
                goto end_round;
            }

            timeval tv = ms_to_timeval(DPI_COOLDOWN_TIME.count());
            // clang-format off
            if (0 != event_assign(conn->event.get(), vpn_event_loop_get_base(self->loop),
                                  conn->fd.get(), EV_TIMEOUT, on_event, self)
                    || 0 != event_add(conn->event.get(), &tv)) {
                conn->socket_error = -1;
                log_conn(self, conn, dbg, "Failed to assign/add event to wait for hello fragment delay");
                goto end_round;
            }
            // clang-format on

            conn->state = PCS_HELLO_FRAGMENT_SENT;
            return;
        }

        [[fallthrough]];
    case PCS_HELLO_FRAGMENT_SENT: {
        U8View hello{conn->hello.data(), conn->hello.size()};
        if (self->anti_dpi) {
            assert(hello.size() > DPI_SPLIT_SIZE);
            hello.remove_prefix(DPI_SPLIT_SIZE);
        }

        if (auto ret = send(conn->fd.get(), (char *) hello.data(), (int) hello.size(), 0); ret < 0) {
            conn->socket_error = evutil_socket_geterror(conn->fd.get());
            log_conn(self, conn, dbg, "Failed to send hello: ({}) {}", conn->socket_error,
                    evutil_socket_error_to_string(conn->socket_error));
            goto end_round;
        } else if (ret != (int) hello.size()) {
            conn->socket_error = -1;
            log_conn(self, conn, dbg, "Failed to send hello: no buffer space");
            goto end_round;
        }

        // clang-format off
        if (0 != event_assign(conn->event.get(), vpn_event_loop_get_base(self->loop), conn->fd.get(), EV_READ, on_event, self)
                || 0 != event_add(conn->event.get(), nullptr)) {
            conn->socket_error = -1;
            log_conn(self, conn, dbg, "Failed to assign/add event to wait for response");
            goto end_round;
        }
        // clang-format on

        conn->started_at = PingClock::now();
        conn->state = PCS_HELLO_SENT;
        return;
    }
    case PCS_HELLO_SENT: {
        auto dt = PingClock::now() - conn->started_at;
        int dt_ms = int(duration_cast<milliseconds>(dt).count());

        char buf = 0;
        if (int ret = recv(conn->fd.get(), &buf, 1, 0); ret < 0) {
            int error = evutil_socket_geterror(conn->fd.get());
#ifdef _WIN32
            if (error != WSAEMSGSIZE) {
#endif
                conn->socket_error = error;
                log_conn(self, conn, trace, "Failed to receive response: ({}) {}", conn->socket_error,
                        evutil_socket_error_to_string(conn->socket_error));
                goto end_round;
#ifdef _WIN32
            }
#endif
        } else if (ret == 0) {
            // Treat this as an error for the purpose of switching to relay IPs.
            conn->socket_error = ag::utils::AG_ECONNRESET;
            log_conn(self, conn, trace, "Failed to receive response: unexpected EOF");
            goto end_round;
        }

        log_conn(self, conn, trace, "Got response");

        conn->best_result_ms = std::min(dt_ms, conn->best_result_ms.value_or(INT_MAX));

        if (!std::exchange(self->have_round_winner, true)) {
            uint32_t to_ms = std::min(2 * dt_ms + MIN_SHORT_TIMEOUT_MS, MAX_SHORT_TIMEOUT_MS);
            auto to_tv = ms_to_timeval(to_ms);
            evtimer_add(self->timer.get(), &to_tv);
            log_ping(self, dbg, "Round {}: timeout reduced to {} ms", self->rounds_started, to_ms);
        }
        break;
    }
    }

end_round:
    conn->fd.reset();
    conn->event.reset();

    self->done.splice(self->done.end(), self->inprogress, conn);

    // All done or errors.
    if (self->inprogress.empty() && self->pending.empty()) {
        log_ping(self, dbg, "Round {}: complete", self->rounds_started);
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

    self->pending.splice(self->pending.end(), self->inprogress);
    for (PingConn &ep : self->pending) {
        ep.fd.reset();
        ep.event.reset();
        if (!self->have_round_winner) {
            ep.socket_error = ag::utils::AG_ETIMEDOUT;
        }
        log_conn(self, &ep, dbg, "Timed out");
    }
    self->done.splice(self->done.end(), self->pending);

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
static int xconnect(const PingConn &conn) {
    auto *dest = conn.relay_address.ss_family ? (sockaddr *) &conn.relay_address : (sockaddr *) &conn.endpoint->address;
    if (0 == connect(conn.fd.get(), dest, (int) sockaddr_get_size(dest))) {
        return 0;
    }
    int error = evutil_socket_geterror(conn.fd.get());
#ifdef _WIN32
    return WSAEWOULDBLOCK == error ? 0 : error;
#else
    return EINPROGRESS == error ? 0 : error;
#endif
}

// Return 0 if initial packet was sent successfully, errno (or equivalent) otherwise.
static int send_quic_initial(const PingConn &conn) {
    auto *dest = conn.relay_address.ss_family ? (sockaddr *) &conn.relay_address : (sockaddr *) &conn.endpoint->address;
    int dest_size = (int) sockaddr_get_size(dest);
    if (0 != connect(conn.fd.get(), dest, dest_size)) {
        return evutil_socket_geterror(conn.fd.get());
    }
    if (int ret = send(conn.fd.get(), (char *) conn.hello.data(), (int) conn.hello.size(), 0); ret < 0) {
        return evutil_socket_geterror(conn.fd.get());
    }
    return 0;
}

static void do_connect(void *arg) {
    auto *self = (Ping *) arg;
    self->connect_task_id.release();

    assert(!self->pending.empty());

    auto conn = self->pending.begin();
    assert(conn->fd.valid());

    log_conn(self, conn, trace, "Connecting");
    conn->started_at = PingClock::now();
    conn->socket_error = conn->use_quic ? send_quic_initial(*conn) : xconnect(*conn);
    if (conn->socket_error != 0) {
        log_conn(self, conn, dbg, "Failed to {}: {}: ({}) {}", conn->use_quic ? "send initial" : "connect",
                conn->use_quic ? "send_quic_initial" : "xconnect", conn->socket_error,
                evutil_socket_error_to_string(conn->socket_error));
        goto error;
    }
    if (0 != event_add(conn->event.get(), nullptr)) {
        log_conn(self, conn, dbg, "Failed to add event");
        conn->socket_error = -1;
        goto error;
    }

    conn->state = conn->use_quic ? PCS_HELLO_SENT : PCS_SYN_SENT;
    self->inprogress.splice(self->inprogress.end(), self->pending, conn);
    goto next;

error:
    conn->fd.reset();
    conn->event.reset();
    self->done.splice(self->done.end(), self->pending, conn);

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
                Millis{1} /*force libevent to poll/select between connect calls*/);
    } else if (self->inprogress.empty()) {
        // All failed (some may have started and already finished). Run `do_prepare` to decide what to do next.
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

static void do_report(void *arg) {
    auto *self = (Ping *) arg;
    self->report_task_id.release();

    assert(self->inprogress.empty());
    assert(self->pending.empty());
    assert(!self->connect_task_id.has_value());
    assert(!self->prepare_task_id.has_value());

    PingResult result{.ping = self};

    if (!self->report.empty()) {
        auto it = self->report.begin();
        if (it->relay_address.ss_family) {
            result.relay_address = (sockaddr *) &it->relay_address;
        }
        result.endpoint = it->endpoint.get();
        if (it->best_result_ms.has_value()) {
            result.status = PING_OK;
            result.ms = it->best_result_ms.value();
        } else {
            result.socket_error = it->socket_error;
            result.status = (it->socket_error == 0 || it->socket_error == ag::utils::AG_ETIMEDOUT) ? PING_TIMEDOUT
                                                                                                   : PING_SOCKET_ERROR;
            result.ms = -1;
        }
        self->handler.func(self->handler.arg, &result);
        self->report.pop_front();
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
    assert(self->inprogress.empty());
    assert(!self->pending.empty() ? (self->done.empty() && self->report.empty())
                                  : (!self->done.empty() || !self->report.empty()));

    std::unordered_set<std::string> relay_snis; // Don't try to connect through a relay with the same SNI more than once

    for (auto conn = self->done.begin(); conn != self->done.end();) {
        if (conn->socket_error && conn->rounds_done == 0) {
            if (conn->use_quic) { // Fallback from QUIC to TLS
                conn->use_quic = false;
                conn->hello.clear();
            } else if (std::string sni; !self->relay_addresses.empty()
                       && !relay_snis.contains((sni = conn->endpoint->name))) { // NOLINT(*-assignment-in-if-condition)
                // Fallback to the next relay address
                conn->relay_address = self->relay_addresses.back();
                relay_snis.emplace(std::move(sni));
                // Restore QUIC after falling back to relay
                if (self->use_quic && !conn->use_quic) {
                    conn->use_quic = true;
                    conn->hello.clear();
                }
            } else {
                goto increment_rounds;
            }
            ++conn;
            continue;
        }
    increment_rounds:
        if (++conn->rounds_done == self->rounds_target) {
            self->report.splice(self->report.end(), self->done, conn++);
        } else {
            ++conn;
        }
    }

    if (!relay_snis.empty()) { // Consume relay address.
        self->relay_addresses.pop_back();
    }

    self->pending.splice(self->pending.end(), self->done);

    if (self->pending.empty()) {
        log_ping(self, dbg, "Pinging done, reporting results");
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

    auto tv = ms_to_timeval(self->round_timeout_ms);
    evtimer_add(self->timer.get(), &tv);

    for (auto conn = self->pending.begin(); conn != self->pending.end();) {
        conn->socket_error = 0;
        const auto *dest =
                (sockaddr *) (conn->relay_address.ss_family ? &conn->relay_address : &conn->endpoint->address);
        // NOLINTNEXTLINE(*-narrowing-conversions)
        conn->fd = AutoFd(socket(dest->sa_family, conn->use_quic ? SOCK_DGRAM : SOCK_STREAM, 0));
        if (!conn->fd.valid()) {
            conn->socket_error = evutil_socket_geterror(conn->fd.get());
            log_conn(self, conn, dbg, "Failed to create socket: ({})", conn->socket_error,
                    evutil_socket_error_to_string(conn->socket_error));
            goto error;
        }
        if (0 != evutil_make_socket_nonblocking(conn->fd.get())) {
            conn->socket_error = evutil_socket_geterror(conn->fd.get());
            log_conn(self, conn, dbg, "Failed to make socket non-blocking: ({}) {}", conn->socket_error,
                    evutil_socket_error_to_string(conn->socket_error));
            goto error;
        }
#ifndef _WIN32
        if (conn->bound_if != 0) {
#ifdef __MACH__
            const sockaddr *dest =
                    (sockaddr *) (conn->relay_address.ss_family ? &conn->relay_address : &conn->endpoint->address);
            int option = (dest->sa_family == AF_INET) ? IP_BOUND_IF : IPV6_BOUND_IF;
            int level = (dest->sa_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
            int error = setsockopt(conn->fd.get(), level, option, &conn->bound_if, sizeof(conn->bound_if));
#else  // #ifdef __MACH__
            int error = setsockopt(conn->fd.get(), SOL_SOCKET, SO_BINDTODEVICE, conn->bound_if_name.data(),
                    conn->bound_if_name.size());
#endif // #ifdef __MACH__
            if (error) {
                log_conn(self, conn, dbg, "Failed to bind socket to interface: ({}) {}", errno, strerror(errno));
                conn->socket_error = error;
                goto error;
            }
        }
#else  // #ifndef _WIN32
        if (!vpn_win_socket_protect(conn->fd.get(), dest)) {
            log_conn(self, conn, dbg, "Failed to protect socket");
            conn->socket_error = -1;
            goto error;
        }
#endif // #ifndef _WIN32
        if (!conn->use_quic) {
            // Send RST as soon as socket is closed. Ignore error, this is not essential.
            linger linger_0 = {.l_onoff = 1, .l_linger = 0};
            setsockopt(conn->fd.get(), SOL_SOCKET, SO_LINGER, (char *) &linger_0, (int) sizeof(linger_0));
            // Send data after each send() call.
            int nodelay = 1;
            if (0 != setsockopt(conn->fd.get(), IPPROTO_TCP, TCP_NODELAY, (char *) &nodelay, (int) sizeof(nodelay))) {
                conn->socket_error = evutil_socket_geterror(conn->fd.get());
                log_conn(self, conn, dbg, "Failed to set TCP_NODELAY: ({}) {}", conn->socket_error,
                        evutil_socket_error_to_string(conn->socket_error));
                goto error;
            }
        }
        conn->event.reset(event_new(vpn_event_loop_get_base(self->loop), conn->fd.get(),
                conn->use_quic ? EV_READ : EV_WRITE, on_event, self));
        if (conn->event == nullptr) {
            log_conn(self, conn, dbg, "Failed to create event");
            conn->socket_error = -1;
            goto error;
        }
        if (conn->hello.empty()) {
            conn->hello = conn->use_quic ? prepare_quic_initial(conn->endpoint->name)
                                         : prepare_client_hello(conn->endpoint->name);
        }
        ++conn;
        continue;
    error:
        conn->fd.reset();
        conn->event.reset();
        self->done.splice(self->done.end(), self->pending, conn++);
    }

    if (self->pending.empty()) {
        // All errors, start next round or report result.
        evtimer_del(self->timer.get());
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
    self->anti_dpi = info->anti_dpi;
    self->use_quic = info->use_quic;
    self->rounds_target = info->nrounds ? info->nrounds : DEFAULT_PING_ROUNDS;

    self->round_timeout_ms = info->timeout_ms ? info->timeout_ms : DEFAULT_PING_TIMEOUT_MS;
    self->timer.reset(evtimer_new(vpn_event_loop_get_base(self->loop), on_timer, self.get()));

    self->relay_addresses.insert(
            self->relay_addresses.begin(), info->relay_addresses.rbegin(), info->relay_addresses.rend());

    constexpr uint32_t DEFAULT_IF_IDX = 0;
    std::span<const uint32_t> interfaces = info->interfaces_to_query;
    if (interfaces.empty()) {
        interfaces = {(uint32_t *) &DEFAULT_IF_IDX, size_t(1)};
    }
    for (const VpnEndpoint &endpoint : info->endpoints) {
        for (uint32_t bound_if : interfaces) {
            PingConn &conn = self->pending.emplace_back();
            conn.endpoint = vpn_endpoint_clone(&endpoint);
            conn.bound_if = bound_if;
            conn.use_quic = self->use_quic;
            if (ag::utils::trim(safe_to_string_view(endpoint.name)).empty()) {
                log_ping(self, warn, "Endpoint {} has no name", sockaddr_to_str((sockaddr *) &endpoint.address));
                return nullptr;
            }

            char buf[IF_NAMESIZE]{};
            if (bound_if != 0) {
                if (if_indextoname(bound_if, buf)) {
                    conn.bound_if_name = buf;
                } else {
#ifndef _WIN32
                    log_ping(self, dbg, "if_indextoname: ({}) {}", errno, strerror(errno));
#else
                    log_ping(self, dbg, "if_indextoname failed");
#endif
                    conn.bound_if_name = "(unknown)";
                }
            } else {
                conn.bound_if_name = "(default)";
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

std::vector<uint8_t> prepare_quic_initial(const char *sni) {
    DeclPtr<SSL_CTX, &SSL_CTX_free> ctx{SSL_CTX_new(TLS_method())};
    DeclPtr<SSL, &SSL_free> ssl{SSL_new(ctx.get())};
    ssize_t ret [[maybe_unused]] = SSL_set_tlsext_host_name(ssl.get(), sni);
    assert(ret);
    uint8_t alpn[] = QUICHE_H3_APPLICATION_PROTOCOL;
    ret = SSL_set_alpn_protos(ssl.get(), alpn, sizeof(alpn) - 1);
    assert(ret == 0);
    uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
    RAND_bytes(scid, sizeof(scid));
    sockaddr_storage dummy_address{.ss_family = AF_INET};
    DeclPtr<quiche_config, &quiche_config_free> config{quiche_config_new(QUICHE_PROTOCOL_VERSION)};
    quiche_config_set_max_send_udp_payload_size(config.get(), QUICHE_MIN_CLIENT_INITIAL_LEN);
    // clang-format off
    DeclPtr<quiche_conn, &quiche_conn_free> qconn{quiche_conn_new_with_tls(
            scid, sizeof(scid), nullptr, 0,
            (sockaddr *) &dummy_address, sockaddr_get_size((sockaddr *) &dummy_address),
            (sockaddr *) &dummy_address, sockaddr_get_size((sockaddr *) &dummy_address),
            config.get(), ssl.release(), false)};
    // clang-format on
    std::vector<uint8_t> initial;
    initial.resize(QUICHE_MIN_CLIENT_INITIAL_LEN);
    quiche_send_info info{};
    ret = quiche_conn_send(qconn.get(), initial.data(), initial.size(), &info);
    assert(ret == QUICHE_MIN_CLIENT_INITIAL_LEN);
    return initial;
}

std::vector<uint8_t> prepare_client_hello(const char *sni) {
    DeclPtr<SSL_CTX, &SSL_CTX_free> ctx{SSL_CTX_new(TLS_method())};
    DeclPtr<SSL, &SSL_free> ssl{SSL_new(ctx.get())};
    int ret [[maybe_unused]] = SSL_set_tlsext_host_name(ssl.get(), sni);
    assert(ret);
    SSL_set0_wbio(ssl.get(), BIO_new(BIO_s_mem()));
    SSL_connect(ssl.get());
    std::vector<uint8_t> initial;
    initial.resize(QUICHE_MIN_CLIENT_INITIAL_LEN);
    ret = BIO_read(SSL_get_wbio(ssl.get()), initial.data(), (int) initial.size());
    assert(ret > 0);
    initial.resize(ret);
    return initial;
}

} // namespace ag
