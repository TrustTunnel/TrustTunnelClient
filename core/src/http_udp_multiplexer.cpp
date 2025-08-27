#include "http_udp_multiplexer.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <string_view>

#include "common/net_utils.h"
#include "common/socket_address.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/wire_utils.h"
#include "vpn/utils.h"

#define log_mux(mux_, lvl_, fmt_, ...)                                                                                 \
    lvl_##log((mux_)->m_log, "[{}] [SID:{}] " fmt_, (mux_)->m_id, (mux_)->m_stream_id, ##__VA_ARGS__)
#define log_conn(mux_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((mux_)->m_log, "[{}] [SID:{}-R:{}] " fmt_, (mux_)->m_id, (mux_)->m_stream_id, (uint64_t) (cid_),         \
            ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

struct CompleteCtx {
    HttpUdpMultiplexer *multiplexer;
    uint64_t id;
};

static std::atomic_int g_next_mux_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static constexpr Secs TIMER_PERIOD{15};

static std::vector<uint8_t> compose_udp_packet(
        const SocketAddress *src, const SocketAddress *dst, std::string_view app_name,
        const uint8_t *data, size_t length) {
    size_t full_length = UDPPKT_IN_PREFIX_SIZE + UDPPKT_APPLEN_SIZE + app_name.size() + length;

    std::vector<uint8_t> packet_buffer(full_length);
    wire_utils::Writer writer({packet_buffer.data(), packet_buffer.size()});

    writer.put_u32(full_length - UDPPKT_LENGTH_SIZE);
    writer.put_ip_padded(*src);
    writer.put_u16(src->port());
    writer.put_ip_padded(*dst);
    writer.put_u16(dst->port());

    app_name = app_name.substr(0, UINT8_MAX);
    writer.put_u8(uint8_t(app_name.size()));
    writer.put_data({(uint8_t *) app_name.data(), app_name.size()});

    writer.put_data({data, length});

    return packet_buffer;
}

HttpUdpMultiplexer::HttpUdpMultiplexer(HttpUdpMultiplexerParameters parameters)
        : m_params(std::move(parameters))
        , m_id(g_next_mux_id++) {
}

HttpUdpMultiplexer::~HttpUdpMultiplexer() = default;

void HttpUdpMultiplexer::close(ServerError serv_err) {
    ServerUpstream *upstream = m_params.parent;

    std::optional<ServerError> error = m_pending_error;
    if (!error.has_value() && serv_err.error.code != 0) {
        error = serv_err;
    }

    for (auto i = m_connections.begin(); i != m_connections.end();) {
        auto next = std::next(i);

        uint64_t id = i->first;
        if (error.has_value()) {
            error->id = id;
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_ERROR, &error.value());
        } else {
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
        }
        this->clean_connection_data(id);

        i = next;
    }

    log_mux(this, trace, "Closed: {} ({})", safe_to_string_view(serv_err.error.text), serv_err.error.code);

    reset();
}

void HttpUdpMultiplexer::reset() {
    m_state = MS_IDLE;
    m_stream_id = 0;
    m_addr_to_id.clear();
    m_recv_connection = {};
    m_timer_event.reset();
}

void HttpUdpMultiplexer::complete_udp_connection(void *arg, TaskId) {
    auto *ctx = (CompleteCtx *) arg;
    HttpUdpMultiplexer *mux = ctx->multiplexer;

    if (mux->m_state == MS_ESTABLISHED) {
        ServerUpstream *upstream = mux->m_params.parent;
        auto i = mux->m_connections.find(ctx->id);
        if (i != mux->m_connections.end()) {
            Connection *conn = &i->second;
            conn->open_task_id.release();
            mux->m_addr_to_id[conn->addr] = ctx->id;
            log_conn(mux, i->first, dbg, "Started handling UDP connection");
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &ctx->id);
        }
    }
}

bool HttpUdpMultiplexer::open_connection(uint64_t conn_id, const TunnelAddressPair *addr, std::string_view app_name) {
    if (std::get_if<SocketAddress>(&addr->dst) == nullptr) {
        log_conn(this, conn_id, err, "UDP connection must have socket address as destination");
        assert(0);
        return false;
    }

    auto i = m_connections.find(conn_id);
    if (i != m_connections.end()) {
        log_conn(this, conn_id, err, "Connection with such id already exists");
        assert(0);
        return false;
    }

    ServerUpstream *upstream = m_params.parent;

    switch (m_state) {
    case MS_IDLE: {
        assert(m_stream_id == 0);
        static const TunnelAddress UDP_HOST(NamePort{"_udp2", 0});
        std::optional<uint64_t> stream_id = m_params.send_connect_request_callback(upstream, &UDP_HOST, "_udp2");
        if (!stream_id.has_value()) {
            return false;
        }
        m_stream_id = stream_id.value();
        m_state = MS_ESTABLISHED;
        [[fallthrough]];
    }
    case MS_ESTABLISHED:
        m_connections.emplace(conn_id,
                Connection{
                        .addr = *addr,
                        .app_name = std::string{app_name},
                        .timeout = steady_clock::now() + milliseconds(VPN_DEFAULT_UDP_TIMEOUT_MS),
                        .open_task_id = event_loop::submit(upstream->vpn->parameters.ev_loop,
                                {
                                        new CompleteCtx{this, conn_id},
                                        complete_udp_connection,
                                        [](void *arg) {
                                            delete (CompleteCtx *) arg;
                                        },
                                }),
                });
        break;
    }

    if (m_timer_event == nullptr) {
        m_timer_event.reset(event_new(
                vpn_event_loop_get_base(upstream->vpn->parameters.ev_loop), -1, EV_PERSIST, timer_callback, this));
        timeval tv = ms_to_timeval(Millis(TIMER_PERIOD).count());
        event_add(m_timer_event.get(), &tv);
    }

    return true;
}

void HttpUdpMultiplexer::close_connection(uint64_t id, bool async) {
    if (!async) {
        close_connection(id);
        return;
    }

    ServerUpstream *upstream = m_params.parent;

    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
        return;
    }

    struct CloseCtx {
        HttpUdpMultiplexer *mux;
        uint64_t id;
    };

    Connection *conn = &i->second;
    conn->close_task_id = event_loop::submit(upstream->vpn->parameters.ev_loop,
            {
                    new CloseCtx{this, id},
                    [](void *arg, TaskId) {
                        auto *ctx = (CloseCtx *) arg;
                        ctx->mux->close_connection(ctx->id);
                    },
                    [](void *arg) {
                        delete (CloseCtx *) arg;
                    },
            });
}

void HttpUdpMultiplexer::close_connection(uint64_t id) {
    if (!clean_connection_data(id)) {
        return;
    }

    ServerHandler *handler = &m_params.parent->handler;
    handler->func(handler->arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
}

bool HttpUdpMultiplexer::check_connection(uint64_t id) const {
    return m_connections.contains(id);
}

ssize_t HttpUdpMultiplexer::send(uint64_t id, U8View data) {
    assert(m_state == MS_ESTABLISHED);

    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        return -1;
    }

    Connection *conn = &i->second;
    SocketAddress *src = &conn->addr.src;
    SocketAddress *dst = std::get_if<SocketAddress>(&conn->addr.dst);
    log_conn(this, id, trace, "Sending UDP packet: {}->{} len={}", *src, *dst, data.size());

    std::vector<uint8_t> packet = compose_udp_packet(src, dst, conn->app_name, data.data(), data.size());
    int r = m_params.send_data_callback(m_params.parent, m_stream_id, {packet.data(), packet.size()});
    if (r == 0) {
        conn->timeout = steady_clock::now() + milliseconds(VPN_DEFAULT_UDP_TIMEOUT_MS);
        conn->sent_bytes_since_flush += data.size();
        return data.size();
    }

    return -1;
}

HttpUdpMultiplexer::PacketInfo HttpUdpMultiplexer::read_prefix(const std::vector<uint8_t> &data) const {
    assert(data.size() == UDPPKT_IN_PREFIX_SIZE);

    PacketInfo info = {NON_ID, 0};

    wire_utils::Reader reader({data.data(), UDPPKT_IN_PREFIX_SIZE});

    uint32_t length = reader.get_u32().value();
    if (length < (UDPPKT_IN_PREFIX_SIZE - UDPPKT_LENGTH_SIZE)) {
        log_mux(this, dbg, "Drop packet as its length less than the prefix size ({})", length);
        return info;
    }

    SocketAddress src_addr = reader.get_ip_padded().value();
    src_addr.set_port(reader.get_u16().value());
    SocketAddress dst_addr = reader.get_ip_padded().value();
    dst_addr.set_port(reader.get_u16().value());

    log_mux(this, trace, "Got UDP packet: {}->{} len={}", src_addr, dst_addr, length);

    if (length > MAX_UDP_IN_PACKET_LENGTH) {
        log_mux(this, dbg, "Drop packet as its length more than the maximum allowed value ({})", length);
        return info;
    }

    info.payload_length = length - (UDPPKT_IN_PREFIX_SIZE - UDPPKT_LENGTH_SIZE);

    auto i = m_addr_to_id.find({dst_addr, src_addr});
    if (i != m_addr_to_id.end()) {
        info.id = i->second;
        log_conn(this, info.id, trace, "Payload length: {}", info.payload_length);
    } else {
        log_mux(this, dbg, "Connection has already been closed or never existed: {}->{}", src_addr, dst_addr);
    }

    return info;
}

int HttpUdpMultiplexer::process_read_event(U8View data) {
    assert(m_state == MS_ESTABLISHED);

    ServerUpstream *upstream = m_params.parent;
    RecvConnection *rconn = &m_recv_connection;
    size_t data_size = data.size();

    while (!data.empty()) {
        switch (rconn->state) {
        case RCS_IDLE: {
            assert(rconn->buffer.size() < UDPPKT_IN_PREFIX_SIZE);

            rconn->buffer.reserve(UDPPKT_IN_PREFIX_SIZE);
            size_t to_read = std::min(UDPPKT_IN_PREFIX_SIZE - rconn->buffer.size(), data.length());
            rconn->buffer.insert(rconn->buffer.end(), data.data(), data.data() + to_read);

            if (rconn->buffer.size() < UDPPKT_IN_PREFIX_SIZE) {
                data.remove_prefix(to_read);
                break;
            }

            assert(rconn->buffer.size() == UDPPKT_IN_PREFIX_SIZE);

            PacketInfo info = read_prefix(rconn->buffer);
            bool drop_packet = false;
            if (info.id == NON_ID) {
                // logged in `read_prefix`
                drop_packet = true;
            } else if (auto i = m_connections.find(info.id); i == m_connections.end()) {
                log_conn(this, info.id, dbg, "No such connection in table, dropping packet");
                drop_packet = true;
            } else if (!i->second.read_enabled) {
                log_conn(this, info.id, dbg, "Read is disabled, dropping packet");
                drop_packet = true;
            }

            if (!drop_packet) {
                rconn->state = RCS_PAYLOAD;
                rconn->id = info.id;
                rconn->buffer.reserve(info.payload_length);
            } else {
                rconn->state = RCS_DROPPING;
            }

            rconn->bytes_left = info.payload_length;
            rconn->buffer.clear();
            data.remove_prefix(to_read);
            break;
        }
        case RCS_PAYLOAD: {
            assert(m_connections.count(rconn->id));
            m_connections.at(rconn->id).timeout = steady_clock::now() + milliseconds(VPN_DEFAULT_UDP_TIMEOUT_MS);

            size_t to_read = std::min(rconn->bytes_left, data.length());
            rconn->buffer.insert(rconn->buffer.end(), data.data(), data.data() + to_read);
            data.remove_prefix(to_read);
            assert(rconn->bytes_left >= to_read);
            rconn->bytes_left -= to_read;

            if (rconn->bytes_left == 0) {
                ServerReadEvent serv_event = {rconn->id, rconn->buffer.data(), rconn->buffer.size(), 0};
                upstream->handler.func(upstream->handler.arg, SERVER_EVENT_READ, &serv_event);
                *rconn = {};
            }

            break;
        }
        case RCS_DROPPING: {
            size_t to_drop = std::min(rconn->bytes_left, data.length());

            data.remove_prefix(to_drop);
            assert(rconn->bytes_left >= to_drop);
            rconn->bytes_left -= to_drop;

            if (rconn->bytes_left == 0) {
                *rconn = {};
            }
            break;
        }
        }
    }

    // consume the whole packet as it must be fully processed in the loop above
    m_params.consume_callback(upstream, m_stream_id, data_size);

    return 0;
}

void HttpUdpMultiplexer::timer_callback(evutil_socket_t, short, void *arg) {
    auto *multiplexer = (HttpUdpMultiplexer *) arg;
    ServerUpstream *upstream = multiplexer->m_params.parent;

    time_point<steady_clock> now = steady_clock::now();

    for (auto i = multiplexer->m_connections.begin(); i != multiplexer->m_connections.end();) {
        auto next = std::next(i);

        Connection *conn = &i->second;
        if (conn->timeout <= now) {
            uint64_t id = i->first;
            log_conn(multiplexer, id, trace, "Timed out");
            multiplexer->clean_connection_data(id);
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
        }

        i = next;
    }
}

void HttpUdpMultiplexer::handle_response(const HttpHeaders *response) {
    assert(m_state == MS_ESTABLISHED);

    if (response->status_code != HTTP_OK_STATUS) {
        // will be raised in `close` after stream close
        m_pending_error = {0, {ag::utils::AG_ECONNREFUSED, "HTTP stream creation failed"}};
    }
}

bool HttpUdpMultiplexer::clean_connection_data(uint64_t id) {
    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        return false;
    }

    if (m_recv_connection.id == id) {
        m_recv_connection.state = RCS_DROPPING;
    }

    m_addr_to_id.erase(i->second.addr);
    m_connections.erase(i);
    log_mux(this, dbg, "Remaining connections: {}", m_connections.size());
    return true;
}

std::optional<uint64_t> HttpUdpMultiplexer::get_stream_id() const {
    std::optional<uint64_t> out;

    switch (m_state) {
    case MS_IDLE:
        break;
    case MS_ESTABLISHED:
        out = m_stream_id;
        break;
    }

    return out;
}

void HttpUdpMultiplexer::report_sent_bytes() {
    for (auto &[id, conn] : m_connections) {
        if (conn.sent_bytes_since_flush > 0) {
            ServerDataSentEvent serv_event = {id, conn.sent_bytes_since_flush};
            m_params.parent->handler.func(m_params.parent->handler.arg, SERVER_EVENT_DATA_SENT, &serv_event);
            conn.sent_bytes_since_flush = 0;
        }
    }
}

void HttpUdpMultiplexer::set_read_enabled(uint64_t id, bool v) {
    auto i = m_connections.find(id);
    if (i != m_connections.end()) {
        i->second.read_enabled = v;
    }
}

size_t HttpUdpMultiplexer::connections_num() const {
    return m_connections.size();
}

} // namespace ag
