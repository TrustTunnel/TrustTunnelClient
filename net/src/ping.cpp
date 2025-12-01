#include "ping.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <event2/event.h>
#include <event2/util.h>

#include "common/defs.h"
#include "common/logger.h"
#include "common/net_utils.h"
#include "net/network_manager.h"
#include "net/quic_connector.h"
#include "net/tcp_socket.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

#include <openssl/ssl.h>

#ifndef _WIN32
#include <net/if.h>
#else
#include "net/os_tunnel.h"
#endif

namespace ag {

static ag::Logger g_logger{"PING"}; // NOLINT(cert-err58-cpp,cppcoreguidelines-avoid-non-const-global-variables)

#define log_ping(ping_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (ping_)->id, ##__VA_ARGS__)
#define log_conn(ping_, conn_, lvl_, fmt_, ...)                                                                        \
    log_ping(ping_, lvl_, "Round {}: {}{} ({}){}{} via {}: " fmt_, (ping_)->rounds_started,                            \
            (conn_)->use_quic ? "udp://" : "tcp://", (conn_)->endpoint->name,                                          \
            SocketAddress((conn_)->endpoint->address),                                                                 \
            (conn_)->relay->address.sa_family ? " through relay " : "",                                                \
            (conn_)->relay->address.sa_family ? SocketAddress((conn_)->relay->address).str() : "",                     \
            (conn_)->bound_if_name, ##__VA_ARGS__)

using PingClock = std::chrono::high_resolution_clock;
using std::chrono::duration_cast;

static constexpr int MIN_SHORT_TIMEOUT_MS = 50;
static constexpr int MAX_SHORT_TIMEOUT_MS = 400;
static constexpr int RELAY_SHORTCUT_DELAY_MS = 500;

struct PingConn {
    Ping *ping = nullptr;
    AutoVpnEndpoint endpoint;
    AutoVpnRelay relay;
    PingClock::time_point started_at = PingClock::time_point::min();
    std::optional<int> best_result_ms;
    uint32_t bound_if = 0;
    std::string bound_if_name;
    int socket_error = 0;
    bool use_quic = false;
    bool no_quic_fallback = false; // If true, don't try to connect via TCP if QUIC connection fails.
    bool old_use_quic = false;
    bool no_relay_fallback = false;
    uint32_t rounds_done = 0;
    ag::DeclPtr<QuicConnector, &quic_connector_destroy> quic_connector;
    ag::DeclPtr<TcpSocket, &tcp_socket_destroy> tcp_socket;
    ag::DeclPtr<SSL, &SSL_free> ssl;
};

struct Ping {
    std::string id;

    VpnEventLoop *loop;
    VpnNetworkManager *network_manager;
    PingHandler handler;

    std::list<PingConn> pending;    // Waiting to start connection.
    std::list<PingConn> inprogress; // Connection started.
    std::list<PingConn> done;       // Ready for next round.
    std::list<PingConn> report;     // Ready to report.

    DeclPtr<event, &event_free> timer;

    // Immediately after starting the first round of connections, start a timer for `RELAY_SHORTCUT_DELAY_MS`.
    // Cancel this timer when the round finishes. Don't start it again for the next rounds.
    // If it fires during the first round, for each connection still in progress at that time, start a connection
    // to the same endpoint through a relay. The delayed connection behaves exactly the same as other connections,
    // except that it goes into a separate list when done. Further processing is done in `do_prepare`.
    DeclPtr<event, &event_free> relay_shortcut_timer;
    std::list<PingConn> pending_shortcut;
    std::list<PingConn> inprogress_shortcut;
    std::list<PingConn> done_shortcut;

    uint32_t rounds_target;
    uint32_t rounds_started;
    uint32_t round_timeout_ms;

    event_loop::AutoTaskId prepare_task_id;
    event_loop::AutoTaskId connect_task_id;
    event_loop::AutoTaskId connect_shortcut_task_id;
    event_loop::AutoTaskId report_task_id;

    std::vector<AutoVpnRelay> relays; // These are in reverse order compared to the ones in `PingInfo`.

    bool have_direct_result;
    bool have_round_winner;
    bool anti_dpi;
    VpnUpstreamProtocol main_protocol;
    bool handoff;

    uint32_t quic_max_idle_timeout_ms;
    uint32_t quic_version;

    int minimum_round_timeout_ms;
};

// clang-format off
static void add_endpoint(Ping *self, std::list<PingConn> &list, const VpnEndpoint &endpoint, uint32_t bound_if, const VpnRelay *relay_address);
static void add_endpoint(Ping *self, std::list<PingConn> &list, const VpnEndpoint &endpoint, uint32_t bound_if, const VpnRelay *relay_address, bool use_quic, bool no_quic_fallback);
static bool conn_prepare(Ping *ping, PingConn *conn);
static void do_prepare(void *arg);
static void do_connect(void *arg, bool shortcut);
static void do_report(void *arg);
static void on_timer(evutil_socket_t fd, short, void *arg);
static void conn_protect_socket(PingConn *conn, SocketProtectEvent *event);
static void conn_process_result(PingConn *conn, VpnError *error);
static void socket_handler(void *arg, TcpSocketEvent what, void *data);
static void quic_connector_handler(void *arg, QuicConnectorEvent what, void *data);
// clang-format on

// Round time out.
static void on_timer(evutil_socket_t, short, void *arg) {
    auto *self = (Ping *) arg;

    assert(!self->report_task_id.has_value());

    using P = std::tuple<std::list<PingConn> &, std::list<PingConn> &, std::list<PingConn> &>;
    for (auto &[pending, inprogress, done] : {
                 P{self->pending, self->inprogress, self->done},
                 P{self->pending_shortcut, self->inprogress_shortcut, self->done_shortcut},
         }) {
        pending.splice(pending.end(), inprogress);
        for (PingConn &ep : pending) {
            ep.tcp_socket.reset();
            ep.quic_connector.reset();
            ep.ssl.reset();
            if (!self->have_round_winner) {
                ep.socket_error = ag::utils::AG_ETIMEDOUT;
            }
            log_conn(self, &ep, dbg, "Timed out");
        }
        done.splice(done.end(), pending);
    }

    self->connect_task_id.reset();
    self->connect_shortcut_task_id.reset();
    if (!self->prepare_task_id.has_value()) {
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

// Relay shortcut.
static void on_shortcut_timer(evutil_socket_t, short, void *arg) {
    auto *self = (Ping *) arg;

    assert(!self->report_task_id.has_value());
    assert(!self->relays.empty());

    self->relay_shortcut_timer.reset();

    for (const PingConn &conn : self->inprogress) {
        if (conn.relay->address.sa_family != 0) {
            continue;
        }
        add_endpoint(self, self->pending_shortcut, *conn.endpoint, conn.bound_if, nullptr, conn.use_quic,
                conn.no_quic_fallback);

        PingConn &sc_conn = self->pending_shortcut.back();
        sc_conn.relay = vpn_relay_clone(self->relays.back().get());

        if (!conn_prepare(self, &sc_conn)) {
            self->pending_shortcut.pop_back();
        }
    }

    if (!self->pending_shortcut.empty()) {
        self->connect_shortcut_task_id = event_loop::submit(self->loop,
                {
                        .arg = self,
                        .action =
                                [](void *arg, TaskId) {
                                    do_connect(arg, /*shortcut*/ true);
                                },
                });
    }
}

static void do_connect(void *arg, bool shortcut) {
    auto *self = (Ping *) arg;

    std::list<PingConn> &pending = shortcut ? self->pending_shortcut : self->pending;
    std::list<PingConn> &inprogress = shortcut ? self->inprogress_shortcut : self->inprogress;
    std::list<PingConn> &done = shortcut ? self->done_shortcut : self->done;
    event_loop::AutoTaskId &task = shortcut ? self->connect_shortcut_task_id : self->connect_task_id;

    task.release();
    if (pending.empty()) {
        puts("");
    }
    assert(!pending.empty());

    auto conn = pending.begin();

    log_conn(self, conn, dbg, "Connecting");

    VpnError error{};
    SocketAddress dest = conn->relay->address.sa_family ? SocketAddress(conn->relay->address)
                                                        : SocketAddress(conn->endpoint->address);
    if (conn->use_quic) {
        assert(conn->quic_connector);
        assert(!conn->tcp_socket);
        QuicConnectorConnectParameters parameters{
                .peer = &dest,
                .ssl = conn->ssl.release(), // Always consumed by `quic_connector_connect`.
                .timeout = Millis{self->round_timeout_ms},
                .max_idle_timeout = Millis{self->quic_max_idle_timeout_ms},
                .quic_version = self->quic_version,
        };
        error = quic_connector_connect(conn->quic_connector.get(), &parameters);
    } else {
        assert(conn->tcp_socket);
        assert(!conn->quic_connector);
        TcpSocketConnectParameters parameters{
                .peer = &dest,
                .ssl = conn->ssl.get(),
                .anti_dpi = self->anti_dpi,
                .pause_tls = true,
        };
        error = tcp_socket_connect(conn->tcp_socket.get(), &parameters);
        if (error.code == 0) {
            (void) conn->ssl.release();
        }
    };

    if (error.code != 0) {
        log_conn(self, conn, dbg, "Failed to start connection: ({}) {}", error.code, error.text);
        conn->socket_error = error.code;
        goto error;
    }

    conn->started_at = PingClock::now();

    inprogress.splice(inprogress.end(), pending, conn);
    goto next;

error:
    conn->tcp_socket.reset();
    conn->quic_connector.reset();
    conn->ssl.reset();
    done.splice(done.end(), pending, conn);

next:
    if (!pending.empty()) {
        // Schedule next connect. Don't connect all in one go to avoid stalling the loop.
        // clang-format off
        auto action = shortcut ? [](void *arg, TaskId) { do_connect(arg, /*shortcut*/true); }
                               : [](void *arg, TaskId) { do_connect(arg, /*shortcut*/false); };
        // clang-format on
        task = event_loop::schedule(self->loop, {.arg = self, .action = action},
                Millis{1} /*force libevent to poll/select between connect calls*/);
    } else if (inprogress.empty() && !shortcut) {
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
    assert(self->inprogress_shortcut.empty());
    assert(self->pending.empty());
    assert(self->pending_shortcut.empty());
    assert(self->done_shortcut.empty());
    assert(!self->connect_task_id.has_value());
    assert(!self->prepare_task_id.has_value());

    PingResult result{.ping = self};

    if (!self->report.empty()) {
        auto it = self->report.begin();
        result.endpoint = it->endpoint.get();
        if (it->best_result_ms.has_value()) {
            result.is_quic = it->use_quic;
            if (self->handoff) {
                result.conn_state = it->use_quic ? (void *) it->quic_connector.release() : it->tcp_socket.release();
            }
            if (it->relay->address.sa_family) {
                result.relay = it->relay.get();
            }
            result.status = PING_OK;
            // Currently, due to sending real ClientHello messages, the traffic has significantly increased, affecting
            // ping times. As a temporary solution, the following formula is used to reduce peaks while keeping the
            // average values in place.
            // TODO: fix traffic jams
            result.ms = int(pow(double(it->best_result_ms.value()), 0.85) * 1.8) + 1;
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
    assert(self->inprogress_shortcut.empty());
    assert(!self->pending.empty() ? (self->done.empty() && self->report.empty())
                                  : (!self->done.empty() || !self->report.empty()));

    // Don't try to connect through a relay with the same SNI more than once.
    std::unordered_set<std::string> relay_snis;

    // Process relay shortcut connection results.
    for (auto it = self->done_shortcut.begin(); it != self->done_shortcut.end();) {
        auto next = std::next(it);
        if (!it->best_result_ms.has_value()) {
            self->done_shortcut.erase(it);
            it = next;
            continue;
        }
        auto orig_it = std::find_if(self->done.begin(), self->done.end(), [&](const PingConn &conn) {
            return vpn_endpoint_equals(conn.endpoint.get(), it->endpoint.get());
        });
        if (orig_it == self->done.end() || orig_it->best_result_ms.has_value()) {
            self->done_shortcut.erase(it);
            it = next;
            continue;
        }
        // If we got here, a shortcut relay connection succeeded, while the corresponding
        // direct connection did not. Replace the direct connection with the shortcut one.
        self->done.splice(orig_it, self->done_shortcut, it);
        self->done.erase(orig_it);
        relay_snis.emplace(it->endpoint->name);
        it = next;
    }
    assert(self->done_shortcut.empty());

    // Don't try to fall back to a relay if we ever received a response from at least one endpoint directly.
    self->have_direct_result =
            self->have_direct_result || std::any_of(self->done.begin(), self->done.end(), [](const PingConn &conn) {
                return conn.best_result_ms.has_value() && conn.relay->address.sa_family == 0;
            });

    for (auto conn = self->done.begin(); conn != self->done.end();) {
        if (conn->socket_error && conn->rounds_done == 0) {
            if (!conn->no_quic_fallback && conn->use_quic) { // Fall back from QUIC to TLS
                conn->use_quic = false;
                conn->old_use_quic = true;
            } else if (std::string sni; !conn->no_relay_fallback && !self->have_direct_result
                       && !self->relays.empty()
                       && !relay_snis.contains((sni = conn->endpoint->name))) { // NOLINT(*-assignment-in-if-condition)
                // Fall back to the next relay address
                conn->relay = vpn_relay_clone(self->relays.back().get());
                relay_snis.emplace(std::move(sni));
                // Restore QUIC after falling back to relay
                if (!conn->no_quic_fallback) {
                    conn->use_quic = conn->old_use_quic;
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
        self->relays.pop_back();
        self->relay_shortcut_timer.reset();
    }

    self->pending.splice(self->pending.end(), self->done);

    // If one of the in-parallel through-relay pings succeeded, stop pinging and report that.
    if (std::any_of(self->report.begin(), self->report.end(), [](const PingConn &conn) {
            return conn.no_relay_fallback && conn.best_result_ms.has_value();
        })) {
        log_ping(self, dbg, "Have result from in-parallel through-relay ping");
        self->pending.clear();
    }

    if (self->pending.empty()) {
        log_ping(self, dbg, "Pinging done, reporting results");
        self->timer.reset();
        self->relay_shortcut_timer.reset();
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
        if (conn_prepare(self, &*conn)) {
            ++conn;
        } else {
            conn->tcp_socket.reset();
            conn->quic_connector.reset();
            conn->ssl.reset();
            self->done.splice(self->done.end(), self->pending, conn++);
        }
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
                                    do_connect(arg, /*shortcut*/ false);
                                },
                });
    }
}

void add_endpoint(Ping *self, std::list<PingConn> &list, const VpnEndpoint &endpoint, uint32_t bound_if,
        const VpnRelay *relay) {

    VpnUpstreamProtocol protocol =
            self->main_protocol != VPN_UP_AUTO ? self->main_protocol : endpoint.preferred_protocol;

    if (protocol == VPN_UP_AUTO) {
        add_endpoint(self, list, endpoint, bound_if, relay, /*use_quic=*/ false, /*no_quic_fallback=*/ false);
        add_endpoint(self, list, endpoint, bound_if, relay, /*use_quic=*/ true, /*no_quic_fallback=*/ true);
    } else {
        add_endpoint(self, list, endpoint, bound_if, relay, /*use_quic=*/ protocol == VPN_UP_HTTP3, /*no_quic_fallback=*/ false);
    }
}

void add_endpoint(Ping *self, std::list<PingConn> &list, const VpnEndpoint &endpoint, uint32_t bound_if,
        const VpnRelay *relay, bool use_quic, bool no_quic_fallback) {
    PingConn &conn = list.emplace_back();
    conn.ping = self;
    conn.endpoint = vpn_endpoint_clone(&endpoint);
    conn.bound_if = bound_if;
    conn.use_quic = use_quic;
    conn.no_quic_fallback = no_quic_fallback;

    if (relay) {
        conn.relay = vpn_relay_clone(relay);
        conn.no_relay_fallback = true;
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

Ping *ping_start(const PingInfo *info, PingHandler handler) {
    DeclPtr<Ping, &ping_destroy> self{new Ping{}};
    log_ping(self, trace, "");

    if (info->loop == nullptr) {
        log_ping(self, warn, "Invalid settings");
        return nullptr;
    }
    if (handler.func == nullptr) {
        log_ping(self, warn, "Invalid handler");
        return nullptr;
    }

    static std::atomic_int next_id{0};

    self->network_manager = info->network_manager;
    if (!self->network_manager) {
        log_ping(self, err, "Failed to get a network manager");
        return nullptr;
    }

    self->id = info->id ? std::string{info->id} : AG_FMT("{}", next_id++);
    self->loop = info->loop;
    self->handler = handler;
    self->anti_dpi = info->anti_dpi;
#ifndef DISABLE_HTTP3
    self->main_protocol = info->main_protocol;
#else
    self->main_protocol = VPN_UP_HTTP2;
#endif
    self->handoff = info->handoff;
    self->rounds_target = info->nrounds ? info->nrounds : DEFAULT_PING_ROUNDS;

    self->round_timeout_ms = info->timeout_ms ? info->timeout_ms : DEFAULT_PING_TIMEOUT_MS;
    self->timer.reset(evtimer_new(vpn_event_loop_get_base(self->loop), on_timer, self.get()));

    for (auto it = info->relays.rbegin(); it != info->relays.rend(); ++it) {
        self->relays.push_back(vpn_relay_clone(&*it));
    }

#ifndef DISABLE_HTTP3
    self->quic_max_idle_timeout_ms =
            info->quic_max_idle_timeout_ms ? info->quic_max_idle_timeout_ms : 10 * DEFAULT_PING_TIMEOUT_MS;
    self->quic_version = info->quic_version ? info->quic_version : QUICHE_PROTOCOL_VERSION;
#endif

    constexpr uint32_t DEFAULT_IF_IDX = 0;
    std::span<const uint32_t> interfaces = info->interfaces_to_query;
    if (interfaces.empty()) {
        interfaces = {(uint32_t *) &DEFAULT_IF_IDX, size_t(1)};
    }
    for (const VpnEndpoint &endpoint : info->endpoints) {
        if (ag::utils::trim(safe_to_string_view(endpoint.name)).empty()) {
            log_ping(self, warn, "Endpoint {} has no name", SocketAddress(endpoint.address));
            return nullptr;
        }
        for (uint32_t bound_if : interfaces) {
            add_endpoint(self.get(), self->pending, endpoint, bound_if, nullptr);
            if (info->relay_parallel.address.sa_family) {
                add_endpoint(self.get(), self->pending, endpoint, bound_if, &info->relay_parallel);
            }
        }
    }
    self->minimum_round_timeout_ms = MIN_SHORT_TIMEOUT_MS;
#ifdef _WIN32
    static constexpr int MINIMUM_SELECT_TIME_MS = 20;
    self->minimum_round_timeout_ms =
            std::max(self->minimum_round_timeout_ms, int(MINIMUM_SELECT_TIME_MS * info->endpoints.size()));
#endif

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
        if (!self->relays.empty()) {
            self->relay_shortcut_timer.reset(
                    evtimer_new(vpn_event_loop_get_base(self->loop), on_shortcut_timer, self.get()));
            timeval tv = ms_to_timeval(RELAY_SHORTCUT_DELAY_MS);
            evtimer_add(self->relay_shortcut_timer.get(), &tv);
        }

        self->prepare_task_id = event_loop::submit(self->loop,
                {
                        .arg = self.get(),
                        .action =
                                [](void *arg, TaskId) {
                                    do_prepare(arg);
                                },
                });
    }

    return self.release();
}

void ping_destroy(Ping *ping) {
    log_ping(ping, trace, "");
    delete ping;
}

const char *ping_get_id(const Ping *ping) {
    return ping->id.c_str();
}

bool conn_prepare(Ping *ping, PingConn *conn) {
    conn->socket_error = 0;
    if (!conn->use_quic) {
        TcpSocketParameters parameters = {
                .ev_loop = ping->loop,
                .handler = {socket_handler, conn},
                .timeout = Millis{ping->round_timeout_ms},
                .socket_manager = ping->network_manager->socket,
                .read_threshold = TCP_READ_THRESHOLD,
#ifdef _WIN32
                .record_estats = TCP_RECORD_ESTATS,
#endif // _WIN32
        };
        conn->tcp_socket.reset(tcp_socket_create(&parameters));
        if (!conn->tcp_socket) {
            conn->socket_error = -1;
            log_conn(ping, conn, dbg, "Failed to create a TCP socket");
            return false;
        }
        tcp_socket_set_rst(conn->tcp_socket.get(), true);
    } else {
        QuicConnectorParameters parameters{
                .ev_loop = ping->loop,
                .handler = {quic_connector_handler, conn},
                .socket_manager = ping->network_manager->socket,
        };
        conn->quic_connector.reset(quic_connector_create(&parameters));
        if (!conn->quic_connector) {
            conn->socket_error = -1;
            log_conn(ping, conn, dbg, "Failed to create a QUIC connector");
            return false;
        }
    }
    Uint8View alpn_protos = conn->use_quic ? Uint8View{QUIC_H3_ALPN_PROTOS, std::size(QUIC_H3_ALPN_PROTOS)}
                                           : Uint8View{TCP_TLS_ALPN_PROTOS, std::size(TCP_TLS_ALPN_PROTOS)};
    U8View endpoint_data = conn->relay->address.sa_family
            ? Uint8View{conn->relay->additional_data.data, conn->relay->additional_data.size}
            : Uint8View{conn->endpoint->additional_data.data, conn->endpoint->additional_data.size};
    auto client_random_data = conn->relay->address.sa_family
            ? Uint8View{conn->relay->tls_client_random.data, conn->relay->tls_client_random.size}
            : Uint8View{conn->endpoint->tls_client_random.data, conn->endpoint->tls_client_random.size};
    auto client_random_mask = conn->relay->address.sa_family
            ? Uint8View{conn->relay->tls_client_random_mask.data, conn->relay->tls_client_random_mask.size}
            : Uint8View{conn->endpoint->tls_client_random_mask.data, conn->endpoint->tls_client_random_mask.size};
    auto ssl_result = make_ssl(nullptr, nullptr, alpn_protos, conn->endpoint->name,
            conn->use_quic ? MSPT_QUICHE : MSPT_TLS, endpoint_data, client_random_data, client_random_mask);
    if (!std::holds_alternative<SslPtr>(ssl_result)) {
        assert(std::holds_alternative<std::string>(ssl_result));
        log_conn(ping, conn, dbg, "Failed to create an SSL object: {}", std::get<std::string>(ssl_result));
        return false;
    }
    conn->ssl = std::move(std::get<SslPtr>(ssl_result));
    return true;
}

void conn_protect_socket(PingConn *conn, SocketProtectEvent *event) {
#ifndef _WIN32
    if (conn->bound_if != 0) {
#ifdef __MACH__
        int option = (event->peer->sa_family == AF_INET) ? IP_BOUND_IF : IPV6_BOUND_IF;
        int level = (event->peer->sa_family == AF_INET) ? IPPROTO_IP : IPPROTO_IPV6;
        int error = setsockopt(event->fd, level, option, &conn->bound_if, sizeof(conn->bound_if));
#else  // #ifdef __MACH__
        int error = setsockopt(
                event->fd, SOL_SOCKET, SO_BINDTODEVICE, conn->bound_if_name.data(), conn->bound_if_name.size());
#endif // #ifdef __MACH__
        if (error) {
            log_conn(conn->ping, conn, dbg, "Failed to bind socket to interface: ({}) {}", errno, strerror(errno));
            event->result = -1;
        }
    }
#else  // #ifndef _WIN32
    if (!vpn_win_socket_protect(event->fd, event->peer)) {
        log_conn(conn->ping, conn, dbg, "Failed to protect socket");
        event->result = -1;
    }
#endif // #ifndef _WIN32
}

void socket_handler(void *arg, TcpSocketEvent what, void *data) {
    auto *conn = (PingConn *) arg;
    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED:
        conn_process_result(conn, nullptr);
        break;
    case TCP_SOCKET_EVENT_ERROR:
        conn_process_result(conn, (VpnError *) data);
        break;
    case TCP_SOCKET_EVENT_READABLE:
    case TCP_SOCKET_EVENT_SENT:
    case TCP_SOCKET_EVENT_WRITE_FLUSH:
        // Ignored
        break;
    case TCP_SOCKET_EVENT_PROTECT:
        conn_protect_socket(conn, (SocketProtectEvent *) data);
        break;
    }
}

void quic_connector_handler(void *arg, QuicConnectorEvent what, void *data) {
    auto *conn = (PingConn *) arg;
    switch (what) {
    case QUIC_CONNECTOR_EVENT_READY:
        conn_process_result(conn, nullptr);
        break;
    case QUIC_CONNECTOR_EVENT_ERROR:
        conn_process_result(conn, (VpnError *) data);
        break;
    case QUIC_CONNECTOR_EVENT_PROTECT:
        conn_protect_socket(conn, (SocketProtectEvent *) data);
        break;
    }
}

void conn_process_result(PingConn *conn, VpnError *error) {
    Ping *ping = conn->ping;

    bool shortcut = false;
    auto it = std::find_if(ping->inprogress.begin(), ping->inprogress.end(), [&](const PingConn &conn_ref) {
        return std::addressof(conn_ref) == conn;
    });
    if (it == ping->inprogress.end()) {
        shortcut = true;
        it = std::find_if(
                ping->inprogress_shortcut.begin(), ping->inprogress_shortcut.end(), [&](const PingConn &conn_ref) {
                    return std::addressof(conn_ref) == conn;
                });
        assert(it != ping->inprogress_shortcut.end());
    }

    if (error) {
        log_conn(ping, conn, dbg, "Failed to get a response: ({}) {}", error->code, error->text);
        conn->socket_error = error->code;
        conn->tcp_socket.reset();
        conn->quic_connector.reset();
    } else {
        log_conn(ping, conn, dbg, "Got response");

        auto dt = PingClock::now() - conn->started_at;
        int dt_ms = int(duration_cast<Millis>(dt).count());

        // There's 2 network round trips before TcpSocket is ready.
        if (!conn->use_quic) {
            dt_ms /= 2;
        }

        conn->best_result_ms = std::min(dt_ms, conn->best_result_ms.value_or(INT_MAX));

        if (!std::exchange(ping->have_round_winner, true)) {
            uint32_t to_ms = std::min(2 * dt_ms + ping->minimum_round_timeout_ms, MAX_SHORT_TIMEOUT_MS);
            auto to_tv = ms_to_timeval(to_ms);
            evtimer_add(ping->timer.get(), &to_tv);
            log_ping(ping, dbg, "Round {}: timeout reduced to {} ms", ping->rounds_started, to_ms);
        }
    }

    if (!shortcut) {
        ping->done.splice(ping->done.end(), ping->inprogress, it);
    } else {
        ping->done_shortcut.splice(ping->done_shortcut.end(), ping->inprogress_shortcut, it);
    }

    // All done or errors.
    if (ping->inprogress.empty() && ping->pending.empty() && ping->inprogress_shortcut.empty()
            && ping->pending_shortcut.empty()) {
        log_ping(ping, dbg, "Round {}: complete", ping->rounds_started);
        evtimer_del(ping->timer.get());
        ping->prepare_task_id = event_loop::submit(ping->loop,
                {
                        .arg = ping,
                        .action =
                                [](void *arg, TaskId) {
                                    do_prepare(arg);
                                },
                });
    }
}

} // namespace ag
