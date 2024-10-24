#include "upstream_multiplexer.h"

#include <algorithm>
#include <cassert>
#include <numeric>

#include <magic_enum/magic_enum.hpp>

#include "common/net_utils.h"
#include "vpn/internal/vpn_client.h"

#define log_mux(mux_, lvl_, fmt_, ...) lvl_##log((mux_)->m_log, "[{}] " fmt_, (mux_)->id, ##__VA_ARGS__)
#define log_ups(mux_, ups_id_, lvl_, fmt_, ...)                                                                        \
    lvl_##log((mux_)->m_log, "[{}] [U:{}] " fmt_, (mux_)->id, ups_id_, ##__VA_ARGS__)
#define log_conn(mux_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((mux_)->m_log, "[{}] [R:{}] " fmt_, (mux_)->id, cid_, ##__VA_ARGS__)
#define log_ups_conn(mux_, ups_id_, cid_, lvl_, fmt_, ...)                                                             \
    lvl_##log((mux_)->m_log, "[{}] [U:{}] [R:{}] " fmt_, (mux_)->id, ups_id_, cid_, ##__VA_ARGS__)

namespace ag {

struct UpstreamCtx {
    UpstreamMultiplexer *mux;
    int id;
};

enum UpstreamState {
    US_OPENING_SESSION,
    US_SESSION_OPENED,
};

struct UpstreamInfo {
    UpstreamInfo(const UpstreamMultiplexer::MakeUpstream &make_upstream,
            const VpnUpstreamProtocolConfig &protocol_config, int id, VpnClient *vpn,
            decltype(ServerHandler::func) handler, std::unique_ptr<UpstreamCtx> ctx)
            : upstream(make_upstream(protocol_config, id, vpn, {handler, ctx.get()}))
            , ctx(std::move(ctx)) {
    }

    UpstreamState state = US_OPENING_SESSION;
    std::unique_ptr<MultiplexableUpstream> upstream;
    std::unique_ptr<UpstreamCtx> ctx;
    event_loop::AutoTaskId deferred_task_id;
};

UpstreamMultiplexer::UpstreamMultiplexer(
        int id, const VpnUpstreamProtocolConfig &protocol_config, size_t upstreams_num, MakeUpstream make_upstream)
        : ServerUpstream(id, protocol_config)
        , m_max_upstreams_num((upstreams_num == 0) ? DEFAULT_UPSTREAMS_NUM : upstreams_num)
        , m_make_upstream(std::move(make_upstream)) {
    m_upstreams_pool.reserve(m_max_upstreams_num);
}

UpstreamMultiplexer::~UpstreamMultiplexer() = default;

bool UpstreamMultiplexer::init(VpnClient *vpn, ServerHandler handler) {
    if (!this->ServerUpstream::init(vpn, handler)) {
        log_mux(this, err, "Failed to initialize base upstream");
        deinit();
        return false;
    }

    return true;
}

void UpstreamMultiplexer::deinit() {
}

bool UpstreamMultiplexer::open_session(std::optional<Millis> timeout) {
    log_mux(this, trace, "...");

    if (!m_upstreams_pool.empty()) {
        log_mux(this, warn, "Invalid state");
        assert(0);
        return false;
    }

    int upstream_id = select_upstream_for_connection();
    if (!open_new_upstream(upstream_id, timeout)) {
        log_mux(this, warn, "Failed to open session");
        return false;
    }

    // Here, we simply timeout if there's no read activity or health check results within the specified time window,
    // since no read activity on the socket should trigger a health check in an underlying upstream.
    m_timeout_timer.reset(evtimer_new(vpn_event_loop_get_base(this->vpn->parameters.ev_loop), timer_callback, this));
    timer_update();

    return true;
}

static void clear_upstreams_map(std::unordered_map<int, std::unique_ptr<UpstreamInfo>> &map) {
    for (auto it = map.begin(); it != map.end();) {
        // Extend `UpstreamCtx`'s lifetime until the upstream has been deleted:
        // upstream's destructor may raise events that use the `UpstreamCtx`.
        std::unique_ptr<UpstreamCtx> ctx = std::move(it->second->ctx);
        it = map.erase(it);
    }
}

void UpstreamMultiplexer::close_session() {
    for (auto &[_, info] : m_upstreams_pool) {
        info->upstream->close_session();
    }
    clear_upstreams_map(m_upstreams_pool);
    m_connections.clear();

    for (const auto &[conn_id, _] : std::exchange(m_pending_connections, {})) {
        ServerError err_event = {conn_id, {utils::AG_ECONNRESET, "Session closed"}};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &err_event);
    }

    m_health_check_upstream_id.reset();
    m_pending_error.reset();
    m_timeout_timer.reset();
}

uint64_t UpstreamMultiplexer::open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    if (m_upstreams_pool.empty()) {
        log_mux(this, dbg, "Session closed");
        return NON_ID;
    }

    int upstream_id = select_upstream_for_connection();
    uint64_t conn_id = this->vpn->upstream_conn_id_generator.get();

    auto i = m_upstreams_pool.find(upstream_id);
    if (i != m_upstreams_pool.end()) {
        log_ups_conn(this, upstream_id, conn_id, trace, "Using open upstream");
        if (!open_connection(upstream_id, conn_id, addr, proto, app_name)) {
            conn_id = NON_ID;
        }
    } else if (open_new_upstream(upstream_id, std::nullopt)) {
        log_ups_conn(this, upstream_id, conn_id, dbg, "Opening new upstream");
        m_pending_connections.emplace(conn_id, PendingConnection{{upstream_id}, *addr, proto, std::string(app_name)});
    } else if (std::optional<int> reserve_id = select_existing_upstream(upstream_id, true); reserve_id.has_value()) {
        upstream_id = reserve_id.value();
        log_ups_conn(this, upstream_id, conn_id, dbg, "Failed to create new upstream, using existing one");
        if (!open_connection(upstream_id, conn_id, addr, proto, app_name)) {
            log_ups_conn(this, upstream_id, conn_id, dbg, "Failed to fall back on existing upstream");
            conn_id = NON_ID;
        }
    } else {
        log_conn(this, conn_id, dbg, "Failed to create a new upstream, no upstreams available");
        conn_id = NON_ID;
    }

    return conn_id;
}

void UpstreamMultiplexer::close_connection(uint64_t id, bool graceful, bool async) {
    MultiplexableUpstream *upstream = get_upstream_by_conn(id);
    if (upstream != nullptr) {
        upstream->close_connection(id, graceful, async);
    } else {
        log_conn(this, id, dbg, "Connection was not found");
    }
}

ssize_t UpstreamMultiplexer::send(uint64_t id, const uint8_t *data, size_t length) {
    ssize_t result = -1;

    MultiplexableUpstream *upstream = get_upstream_by_conn(id);
    if (upstream != nullptr) {
        result = upstream->send(id, data, length);
    } else {
        log_conn(this, id, dbg, "Connection was not found");
    }

    return result;
}

void UpstreamMultiplexer::consume(uint64_t id, size_t length) {
    MultiplexableUpstream *upstream = get_upstream_by_conn(id);
    if (upstream != nullptr) {
        upstream->consume(id, length);
    } else {
        log_conn(this, id, dbg, "Connection was not found");
    }
}

size_t UpstreamMultiplexer::available_to_send(uint64_t id) {
    ssize_t result = 0;

    MultiplexableUpstream *upstream = get_upstream_by_conn(id);
    if (upstream != nullptr) {
        result = upstream->available_to_send(id);
    } else {
        log_conn(this, id, dbg, "Connection was not found");
    }

    return result;
}

void UpstreamMultiplexer::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
    MultiplexableUpstream *upstream = get_upstream_by_conn(id);
    if (upstream != nullptr) {
        upstream->update_flow_control(id, info);
    } else {
        log_conn(this, id, dbg, "Connection was not found");
    }
}

VpnError UpstreamMultiplexer::do_health_check() {
    if (m_health_check_upstream_id.has_value()) {
        log_ups(this, *m_health_check_upstream_id, dbg,
                "Another health check is already in progress, ignoring this one");
        return {};
    }

    std::optional<int> upstream_id;
    UpstreamInfo *info = nullptr;
    for (auto &[id, i] : m_upstreams_pool) {
        if (i->state == US_SESSION_OPENED) {
            upstream_id = id;
            info = i.get();
            break;
        }
    }

    if (info == nullptr) {
        return {VPN_EC_ERROR, "There are no open sessions"};
    }

    VpnError error = info->upstream->do_health_check();
    if (error.code == VPN_EC_NOERROR) {
        m_health_check_upstream_id = upstream_id;
    }

    return error;
}

VpnConnectionStats UpstreamMultiplexer::get_connection_stats() const {
    static constexpr auto PICK_WORST_RTT = [](uint32_t lh, uint32_t rh) -> uint32_t {
        return std::max(lh, rh);
    };

    static constexpr auto PICK_WORST_LOSS_RATIO = [](double lh, double rh) -> double {
        return std::max(lh, rh);
    };

    VpnConnectionStats stats = {};

    for (const auto &[_, i] : m_upstreams_pool) {
        if (i->state == US_SESSION_OPENED) {
            VpnConnectionStats i_stats = i->upstream->get_connection_stats();
            stats = {
                    PICK_WORST_RTT(stats.rtt_us, i_stats.rtt_us),
                    PICK_WORST_LOSS_RATIO(stats.packet_loss_ratio, i_stats.packet_loss_ratio),
            };
        }
    }

    return stats;
}

void UpstreamMultiplexer::on_icmp_request(IcmpEchoRequestEvent &event) {
    auto it = std::find_if(m_upstreams_pool.begin(), m_upstreams_pool.end(), [](const auto &i) {
        return i.second->state == US_SESSION_OPENED;
    });
    if (it == m_upstreams_pool.end()) {
        log_mux(this, dbg, "Failed to find a connected upstream");
        assert(0);
        event.result = -1;
        return;
    }

    it->second->upstream->on_icmp_request(event);
}

void UpstreamMultiplexer::close_upstream(int upstream_id) {
    log_ups(this, upstream_id, dbg, "...");

    auto it = m_upstreams_pool.find(upstream_id);
    if (it == m_upstreams_pool.end()) {
        log_ups(this, upstream_id, warn, "Upstream not found");
        assert(0);
        return;
    }

    m_upstreams_pool.erase(it);

    log_mux(this, dbg, "Remaining upstreams={}, connections={}, pending connections={}", m_upstreams_pool.size(),
            m_connections.size(), m_pending_connections.size());
    if (!m_upstreams_pool.empty()) {
        return;
    }

    log_mux(this, dbg, "All child upstreams are closed");
    m_timeout_timer.reset();
    if (m_pending_error.has_value()) {
        ServerError error = {NON_ID, std::exchange(m_pending_error, std::nullopt).value()};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &error);
    } else {
        this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    }
}

void UpstreamMultiplexer::timer_callback(evutil_socket_t, short, void *arg) {
    auto *mux = (UpstreamMultiplexer *) arg;
    log_mux(mux, dbg, "Timed out");
    mux->do_health_check();
}

static bool is_fatal_error(const VpnError &error) {
    return error.code == VPN_EC_AUTH_REQUIRED;
}

void UpstreamMultiplexer::child_upstream_handler(void *arg, ServerEvent what, void *data) {
    auto *ctx = (UpstreamCtx *) arg;
    UpstreamMultiplexer *mux = ctx->mux;

    auto pool_it = mux->m_upstreams_pool.find(ctx->id);
    if (pool_it == mux->m_upstreams_pool.end()) {
        log_ups(mux, ctx->id, warn, "Got event on closed or non-existent upstream: {}", magic_enum::enum_name(what));
        assert(0);
        return;
    }

    switch (what) {
    case SERVER_EVENT_SESSION_OPENED:
        if (mux->m_upstreams_pool.size() == 1) {
            mux->handler.func(mux->handler.arg, SERVER_EVENT_SESSION_OPENED, data);
        }

        pool_it->second->state = US_SESSION_OPENED;

        for (auto i = mux->m_pending_connections.begin(); i != mux->m_pending_connections.end();) {
            const PendingConnection *conn = &i->second;
            if (conn->upstream_id == ctx->id) {
                mux->proceed_pending_connection(conn->upstream_id, i->first, conn);
                i = mux->m_pending_connections.erase(i);
            } else {
                ++i;
            }
        }
        break;
    case SERVER_EVENT_SESSION_CLOSED: {
        for (auto i = mux->m_pending_connections.begin(); i != mux->m_pending_connections.end();) {
            const PendingConnection *conn = &i->second;
            if (conn->upstream_id == ctx->id) {
                ServerError err_event = {i->first, {ag::utils::AG_ECONNREFUSED, "Session closed"}};
                mux->handler.func(mux->handler.arg, SERVER_EVENT_ERROR, &err_event);
                i = mux->m_pending_connections.erase(i);
            } else {
                ++i;
            }
        }

        mux->close_upstream(ctx->id);
        break;
    }
    case SERVER_EVENT_CONNECTION_CLOSED: {
        uint64_t id = *(uint64_t *) data;
        assert(mux->m_connections.count(id) != 0);
        mux->m_connections.erase(id);
        log_mux(mux, dbg, "Remaining upstreams={} connections={} pending connections={}", mux->m_upstreams_pool.size(),
                mux->m_connections.size(), mux->m_pending_connections.size());
        mux->handler.func(mux->handler.arg, what, data);
        break;
    }
    case SERVER_EVENT_READ: {
        mux->timer_update();
        mux->handler.func(mux->handler.arg, what, data);
        break;
    }
    case SERVER_EVENT_CONNECTION_OPENED:
    case SERVER_EVENT_DATA_SENT:
    case SERVER_EVENT_GET_AVAILABLE_TO_SEND:
    case SERVER_EVENT_ECHO_REPLY:
        mux->handler.func(mux->handler.arg, what, data);
        break;
    case SERVER_EVENT_HEALTH_CHECK_RESULT: {
        mux->timer_update();
        // Ignore health check results from upstream
        if (mux->m_health_check_upstream_id == ctx->id) {
            mux->handler.func(mux->handler.arg, what, data);
            mux->m_health_check_upstream_id.reset();
        }
        break;
    }
    case SERVER_EVENT_ERROR: {
        const ServerError *event = (ServerError *) data;
        if (event->id != NON_ID) {
            // An error on connection also means that some data was received.
            mux->timer_update();
            mux->m_connections.erase(event->id);
            log_mux(mux, dbg, "Remaining upstreams={} connections={} pending connections={}",
                    mux->m_upstreams_pool.size(), mux->m_connections.size(), mux->m_pending_connections.size());
            mux->handler.func(mux->handler.arg, SERVER_EVENT_ERROR, data);
        } else if (is_fatal_error(event->error)
                // do not ignore errors on a health checking upstream
                || mux->m_health_check_upstream_id == ctx->id) {
            log_mux(mux, info, "Error on upstream id={}{} is fatal, closing all upstreams: ({}) {}", ctx->id,
                    (mux->m_health_check_upstream_id == ctx->id) ? " (healthcheck upstream)" : "", event->error.code,
                    event->error.text);
            if (event->error.code != 0) {
                mux->m_pending_error = event->error;
            }
            while (!mux->m_upstreams_pool.empty()) {
                const auto it = mux->m_upstreams_pool.begin();
                it->second->upstream->close_session();
                auto upstream_id = it->first;
                mux->close_upstream(upstream_id);
            }
        } else {
            log_mux(mux, info, "Error on upstream id={} is non-fatal, closing upstream: ({}) {}", ctx->id,
                    event->error.code, event->error.text);
            pool_it->second->upstream->close_session();
            mux->close_upstream(ctx->id);
        }
        break;
    }
    }
}

MultiplexableUpstream *UpstreamMultiplexer::get_upstream_by_conn(uint64_t id) const {
    auto it_id = m_connections.find(id);
    if (it_id == m_connections.end()) {
        log_conn(this, id, dbg, "Connection not found");
        return nullptr;
    }

    auto pool_it = m_upstreams_pool.find(it_id->second.upstream_id);
    if (pool_it == m_upstreams_pool.end()) {
        log_ups_conn(this, it_id->second.upstream_id, id, dbg, "Upstream for connection not found");
        return nullptr;
    }

    return pool_it->second->upstream.get();
}

std::optional<int> UpstreamMultiplexer::select_existing_upstream(
        std::optional<int> ignored_upstream, bool allow_underflow) const {
    // for the first try to pick underloaded upstream
    for (const auto &[id, _] : m_upstreams_pool) {
        if (ignored_upstream != id && connections_num_by_upstream(id) < NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD) {
            return id;
        }
    }

    // if a caller wants an existing upstream or the number of open upstreams reached the cap,
    // choose the least loaded
    if (allow_underflow || m_upstreams_pool.size() == DEFAULT_UPSTREAMS_NUM) {
        std::optional<decltype(m_upstreams_pool.begin())> least_loaded;
        for (auto i = m_upstreams_pool.begin(); i != m_upstreams_pool.end(); ++i) {
            if (i->first == ignored_upstream) {
                continue;
            }

            if (!least_loaded.has_value()
                    || (*least_loaded)->second->upstream->connections_num() > i->second->upstream->connections_num()) {
                least_loaded = i;
            }
        }

        if (least_loaded.has_value()) {
            return (*least_loaded)->first;
        }
    }

    return std::nullopt;
}

int UpstreamMultiplexer::select_upstream_for_connection() {
    std::optional<int> id = select_existing_upstream(std::nullopt, false);
    if (id.has_value()) {
        return id.value();
    }

    // otherwise, create a new one
    static std::atomic<int> next_upstream_id = 0;
    return next_upstream_id.fetch_add(1, std::memory_order_relaxed);
}

bool UpstreamMultiplexer::open_new_upstream(int id, std::optional<Millis> timeout) {
    assert(m_upstreams_pool.count(id) == 0);

    std::unique_ptr<UpstreamCtx> ctx = std::make_unique<UpstreamCtx>(UpstreamCtx{this, id});
    std::unique_ptr<UpstreamInfo> info = std::make_unique<UpstreamInfo>(
            m_make_upstream, this->PROTOCOL_CONFIG.value(), id, this->vpn, &child_upstream_handler, std::move(ctx));
    if (!info->upstream->open_session(timeout)) {
        log_ups(this, id, warn, "Failed to open session");
        return false;
    }

    m_upstreams_pool[id] = std::move(info);
    return true;
}

bool UpstreamMultiplexer::open_connection(
        int upstream_id, uint64_t conn_id, const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    auto i = m_upstreams_pool.find(upstream_id);
    if (i == m_upstreams_pool.end()) {
        log_ups(this, upstream_id, warn, "Failed to find selected upstream for connection in the list");
        assert(0);
        return false;
    }

    bool successful = true;
    UpstreamInfo *info = i->second.get();
    switch (info->state) {
    case US_OPENING_SESSION:
        log_ups_conn(this, upstream_id, conn_id, trace, "Postpone connection until session is established");
        m_pending_connections.emplace(conn_id, PendingConnection{{upstream_id}, *addr, proto, std::string(app_name)});
        break;
    case US_SESSION_OPENED:
        successful = info->upstream->open_connection(conn_id, addr, proto, app_name);
        if (successful) {
            m_connections.emplace(conn_id, Connection{upstream_id});
        }
        break;
    }

    return successful;
}

void UpstreamMultiplexer::proceed_pending_connection(int upstream_id, uint64_t conn_id, const PendingConnection *conn) {
    if (open_connection(upstream_id, conn_id, &conn->addr, conn->proto, conn->app_name)) {
        return;
    }

    assert(!m_upstreams_pool.empty());
    int fallback_upstream_id = m_upstreams_pool.begin()->first;
    log_ups_conn(this, upstream_id, conn_id, dbg,
            "Failed to open connection on new upstream, falling back on existing one (id={})", fallback_upstream_id);

    if (!open_connection(fallback_upstream_id, conn_id, &conn->addr, conn->proto, conn->app_name)) {
        log_ups_conn(this, fallback_upstream_id, conn_id, dbg, "Failed to fall back on existing upstream");
        ServerError err_event = {conn_id, {ag::utils::AG_ECONNREFUSED, "Failed to connect"}};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &err_event);
    }
}

size_t UpstreamMultiplexer::connections_num_by_upstream(int id) const {
    assert(m_upstreams_pool.count(id) != 0);

    return m_upstreams_pool.find(id)->second->upstream->connections_num()
            + std::accumulate(m_pending_connections.begin(), m_pending_connections.end(), 0,
                    [id](size_t acc, const auto &i) -> size_t {
                        return acc + ((id == i.second.upstream_id) ? 1 : 0);
                    });
}

void UpstreamMultiplexer::handle_sleep() {
    log_mux(this, dbg, "...");

    this->timer_stop();
    this->m_health_check_upstream_id.reset();
    for (auto &[_, info] : m_upstreams_pool) {
        info->upstream->handle_sleep();
    }

    log_mux(this, dbg, "Done");
}

void UpstreamMultiplexer::handle_wake() {
    log_mux(this, dbg, "...");

    for (auto &[_, info] : m_upstreams_pool) {
        info->upstream->handle_wake();
    }
    this->timer_update();
    this->do_health_check();

    log_mux(this, dbg, "Done");
}

void UpstreamMultiplexer::timer_update() {
    if (m_timeout_timer) {
        timeval tv = ms_to_timeval((this->vpn->upstream_config.timeout - this->vpn->upstream_config.health_check_timeout).count());
        tracelog(m_log, "Updating timer: {}.{:06}", tv.tv_sec, tv.tv_usec);
        evtimer_add(m_timeout_timer.get(), &tv);
    }
}

void UpstreamMultiplexer::timer_stop() {
    if (m_timeout_timer) {
        evtimer_del(m_timeout_timer.get());
    }
}

} // namespace ag
