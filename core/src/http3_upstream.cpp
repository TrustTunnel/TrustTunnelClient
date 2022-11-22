#include "http3_upstream.h"

#include <algorithm>
#include <cstdlib>
#include <unordered_set>

#include <magic_enum.hpp>
#include <openssl/rand.h>

#include "net/http_session.h"
#include "net/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

#define log_upstream(ups_, lvl_, fmt_, ...) lvl_##log((ups_)->m_log, "[{}] " fmt_, (ups_)->id, ##__VA_ARGS__)
#define log_conn(ups_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((ups_)->m_log, "[{}] [R:{}] " fmt_, (ups_)->id, (uint64_t) (cid_), ##__VA_ARGS__)
#define log_stream(ups_, sid_, lvl_, fmt_, ...)                                                                        \
    lvl_##log((ups_)->m_log, "[{}] [SID:{}] " fmt_, (ups_)->id, (uint64_t) (sid_), ##__VA_ARGS__)

namespace ag {

static constexpr size_t LOCAL_CONN_ID_LEN = 16;
// synchronized with the endpoint config
static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 100ul * 1024 * 1024;
// chosen empirically (looks like it works better than the Chrome default 6MB)
static constexpr uint64_t STREAM_WINDOW_SIZE = 1ul * 1024 * 1024;
// synchronized with the endpoint config
static constexpr uint64_t MAX_STREAMS_NUM = 4ul * 1024;
// synchronized with the endpoint config
static constexpr size_t MAX_QUIC_UDP_PAYLOAD_SIZE = 1350;

using namespace std::chrono;
using namespace ag;

// FIXME: these should be available from the HTTP/3 implementation
enum Http3Upstream::Http3ErrorCode : uint64_t {
    H3_NO_ERROR = 0x100,
    H3_REQUEST_CANCELLED = 0x10c,
};

struct CompleteCtx {
    Http3Upstream *upstream;
    uint64_t id;
};

enum Http3Upstream::State : int {
    H3US_IDLE,
    H3US_ESTABLISHING,
    H3US_ESTABLISHED,
    H3US_CLOSING,
};

enum Http3Upstream::TcpConnection::Flag : int {
    TCF_READ_ENABLED,           // `SERVER_EVENT_READ` can be raised
    TCF_ESTABLISHED,            // the endpoint has set up a tunnel for the connection
    TCF_STREAM_CLOSED,          // stream closed gracefully, but we're waiting until all data is sent
    TCF_NEED_NOTIFY_SENT_BYTES, // need to raise `SERVER_EVENT_DATA_SENT`
};

bool Http3Upstream::TcpConnection::has_unread_data() const {
    return this->unread_data != nullptr && this->unread_data->size() > 0;
}

Http3Upstream::Http3Upstream(int id, const VpnUpstreamProtocolConfig &protocol_config)
        : ServerUpstream(id, protocol_config)
        , m_udp_mux({this, mux_send_connect_request_callback, mux_send_data_callback, mux_consume_callback})
        , m_icmp_mux({this, mux_send_connect_request_callback, mux_send_data_callback, mux_consume_callback}) {
#if 0
    quiche_enable_debug_logging(
            [] (const char *line, void *) {
                static logger_ptr_t log{ logger_open("Q", LOG_LEVEL_TRACE) };
                tracelog(log, "{}", line);
            },
            nullptr);
#endif
}

Http3Upstream::~Http3Upstream() {
}

bool Http3Upstream::init(VpnClient *vpn, ServerHandler handler) {
    if (!this->ServerUpstream::init(vpn, handler)) {
        log_upstream(this, err, "Failed to initialize base upstream");
        deinit();
        return false;
    }

    m_credentials = make_credentials(vpn->upstream_config.username, vpn->upstream_config.password);

    return true;
}

void Http3Upstream::deinit() {
}

bool Http3Upstream::open_session(std::optional<Millis>) {
    if (m_state != H3US_IDLE) {
        log_upstream(this, err, "Invalid upstream state: {}", magic_enum::enum_name(m_state));
        assert(0);
        return false;
    }

    const vpn_client::EndpointConnectionConfig &upstream_config = this->vpn->upstream_config;
    UdpSocketParameters params = {this->vpn->parameters.ev_loop, {socket_handler, this},
            upstream_config.timeout, upstream_config.endpoint->address,
            this->vpn->parameters.network_manager->socket};
    m_socket.reset(udp_socket_create(&params));
    if (m_socket == nullptr) {
        log_upstream(this, err, "Failed to create UDP socket for connection");
        return false;
    }

    const VpnHttp3UpstreamConfig &h3_upstream_config = this->PROTOCOL_CONFIG->http3;
    quiche_config *config = quiche_config_new(
            (h3_upstream_config.quic_version == 0) ? QUICHE_PROTOCOL_VERSION : h3_upstream_config.quic_version);
    if (config == nullptr) {
        log_upstream(this, err, "Failed to create QUIC config");
        return false;
    }
    DeclPtr<quiche_config, &quiche_config_free> config_holder{config};

    // we are not able to update connection timeout dynamically, so set it greater than
    // the pinging period to make the connection live long enough until the following ping
    m_max_idle_timeout = std::max(upstream_config.timeout, 2 * upstream_config.endpoint_pinging_period);

    quiche_config_verify_peer(config, true);
    quiche_config_set_application_protos(
            config, (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL, strlen(QUICHE_H3_APPLICATION_PROTOCOL));
    quiche_config_set_max_idle_timeout(config, duration_cast<milliseconds>(m_max_idle_timeout).count());
    quiche_config_set_initial_max_data(config, QUIC_CONNECTION_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_bidi_local(config, STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_stream_data_uni(config, STREAM_WINDOW_SIZE);
    quiche_config_set_initial_max_streams_bidi(config, MAX_STREAMS_NUM);
    quiche_config_set_initial_max_streams_uni(config, MAX_STREAMS_NUM);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_QUIC_UDP_PAYLOAD_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_QUIC_UDP_PAYLOAD_SIZE);
    quiche_config_set_disable_active_migration(config, true);

    uint8_t scid[LOCAL_CONN_ID_LEN];
    static_assert(std::size(scid) <= QUICHE_MAX_CONN_ID_LEN);
    if (0 == RAND_bytes(scid, std::size(scid))) {
        log_upstream(this, err, "Failed to generate connection ID");
        assert(0);
    }

    SslPtr ssl;
    if (auto r = make_ssl(verify_callback, this,
                {(uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL, std::size(QUICHE_H3_APPLICATION_PROTOCOL) - 1},
                upstream_config.endpoint->name);
            std::holds_alternative<SslPtr>(r)) {
        ssl = std::move(std::get<SslPtr>(r));
    } else {
        log_upstream(this, err, "{}", std::get<std::string>(r));
        return false;
    }

#if 0
    if (char *ssl_keylog_file = getenv("SSLKEYLOGFILE")) {
        static DeclPtr<std::FILE, &std::fclose> handle{std::fopen(ssl_keylog_file, "a")};
        SSL_CTX_set_keylog_callback(SSL_get_SSL_CTX(ssl.get()), [] (const SSL *, const char *line) {
            fprintf(handle.get(), "%s\n", line);
            fflush(handle.get());
        });
    }
#endif

    m_quic_conn.reset(
            quiche_conn_new_with_tls(scid, sizeof(scid), nullptr, 0, (sockaddr *) &upstream_config.endpoint->address,
                    sockaddr_get_size((sockaddr *) &upstream_config.endpoint->address), config, ssl.release(), false));
    if (m_quic_conn == nullptr) {
        log_upstream(this, err, "Failed to create QUIC connection");
        return false;
    }

    if (!this->flush_pending_quic_data()) {
        return false;
    }

    m_state = H3US_ESTABLISHING;
    return true;
}

void Http3Upstream::close_session() {
    log_upstream(this, dbg, "...");
    m_state = H3US_CLOSING;

    std::unordered_set<uint64_t> remaining_connections;
    remaining_connections.reserve(
            m_tcp_connections.size() + m_retriable_tcp_requests.size() + m_closing_connections.size());
    for (auto &[id, _] : m_tcp_connections) {
        remaining_connections.insert(id);
    }
    for (auto &[id, _] : m_retriable_tcp_requests) {
        remaining_connections.insert(id);
    }
    for (auto &[id, _] : m_closing_connections) {
        remaining_connections.insert(id);
    }
    for (uint64_t conn_id : remaining_connections) {
        this->close_connection(conn_id, false, false);
    }

    if (std::optional<uint64_t> id = m_udp_mux.get_stream_id(); id.has_value()) {
        close_stream(id.value(), H3_REQUEST_CANCELLED);
    }

    if (std::optional<uint64_t> id = m_icmp_mux.get_stream_id(); id.has_value()) {
        close_stream(id.value(), H3_REQUEST_CANCELLED);
    }

    if (m_quic_conn != nullptr) {
        if (int r = quiche_conn_close(m_quic_conn.get(), true, 0, NULL, 0); r < 0 && r != QUICHE_ERR_DONE) {
            log_upstream(this, err, "Failed to close QUIC connection: {}", magic_enum::enum_name((quiche_error) r));
        } else {
            this->flush_pending_quic_data();
        }
    }

    m_udp_mux.close({});
    m_icmp_mux.close();
    m_h3_conn.reset();
    m_quic_conn.reset();
    m_quic_timer.reset();
    m_socket.reset();
    m_tcp_connections.clear();
    m_tcp_conn_by_stream_id.clear();
    m_retriable_tcp_requests.clear();
    m_closing_connections.clear();
    m_complete_read_task_id.reset();
    m_notify_sent_task_id.reset();
    m_close_connections_task_id.reset();
    m_post_receive_task_id.reset();
    m_flush_error_task_id.reset();
    m_health_check_info.reset();
    m_idle_timeout_at_ns.reset();
    m_close_on_idle_task_id.reset();
    m_state = H3US_IDLE;
    m_closed = false;

    log_upstream(this, dbg, "Done");
}

uint64_t Http3Upstream::open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    if (m_state != H3US_ESTABLISHED) {
        log_upstream(this, err, "Invalid upstream state: {}", magic_enum::enum_name(m_state));
        assert(0);
        return false;
    }

    uint64_t conn_id = this->vpn->upstream_conn_id_generator.get();
    if (proto == IPPROTO_UDP) {
        return m_udp_mux.open_connection(conn_id, addr, app_name) ? conn_id : NON_ID;
    }

    auto [stream_id, is_retriable] = this->send_connect_request(&addr->dst, app_name);
    if (stream_id.has_value()) {
        TcpConnection *conn = &m_tcp_connections[conn_id];
        conn->stream_id = stream_id.value();
        m_tcp_conn_by_stream_id[stream_id.value()] = conn_id;
        return conn_id;
    }

    if (is_retriable) {
        log_conn(this, conn_id, dbg, "Couldn't send connect request immediately but still can try later");
        m_retriable_tcp_requests[conn_id] = {addr->dst, std::string(app_name)};
        return conn_id;
    }

    return NON_ID;
}

void Http3Upstream::close_connection(uint64_t conn_id, bool graceful, bool async) {
    if (async) {
        m_closing_connections[conn_id] = graceful;
        if (!m_close_connections_task_id.has_value()) {
            m_close_connections_task_id =
                    event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                                   auto *self = (Http3Upstream *) arg;
                                                                   self->m_close_connections_task_id.release();
                                                                   std::unordered_map<uint64_t, bool> connections;
                                                                   std::swap(connections, self->m_closing_connections);
                                                                   for (const auto &[conn_id, graceful] : connections) {
                                                                       self->close_connection(conn_id, graceful, false);
                                                                   }
                                                               }});
        }
        return;
    }

    if (m_udp_mux.check_connection(conn_id)) {
        m_udp_mux.close_connection(conn_id, false);
    } else {
        this->close_tcp_connection(conn_id, graceful);
    }
}

ssize_t Http3Upstream::send(uint64_t id, const uint8_t *data, size_t length) {
    ssize_t r = 0;

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        r = quiche_h3_send_body(m_h3_conn.get(), m_quic_conn.get(), conn->stream_id, (uint8_t *) data, length, false);
        if (r == QUICHE_H3_ERR_DONE) {
            log_conn(this, id, dbg, "Can't send data via stream at the moment");
            r = 0;
        }

        // set the flag even if nothing was sent to poll the client side on receiving the next
        // QUIC packet from the endpoint
        conn->flags.set(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES, r >= 0);
        if (r > 0) {
            // quiche's api does not provide a possibility to get the number of acked bytes
            // on a stream, so we report it immediately - this does not seem bad as the next
            // call to `quiche_h3_send_body` will do the flow control checks
            conn->sent_bytes_to_notify += r;
            if (!m_notify_sent_task_id.has_value()) {
                m_notify_sent_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                        {
                                this,
                                [](void *arg, TaskId) {
                                    auto *self = (Http3Upstream *) arg;
                                    self->m_notify_sent_task_id.release();
                                    self->poll_tcp_connections();
                                },
                        });
            }
        }
    } else if (m_udp_mux.check_connection(id)) {
        r = m_udp_mux.send(id, {data, length});
    } else {
        log_conn(this, id, err, "Trying to send data on already closed or nonexistent connection");
        r = -1;
    }

    if (r < 0) {
        log_conn(this, id, dbg, "Failed to send data from client: {}", magic_enum::enum_name((quiche_h3_error) r));
    } else {
        this->flush_pending_quic_data();
    }

    return (int) r;
}

void Http3Upstream::consume(uint64_t, size_t) {
}

size_t Http3Upstream::available_to_send(uint64_t id) {
    std::optional<uint64_t> stream_id = get_stream_id(id);
    if (!stream_id.has_value()) {
        log_conn(this, id, dbg, "Trying to get window size on closed or nonexistent connection");
        return 0;
    }

    ssize_t r = quiche_conn_stream_capacity(m_quic_conn.get(), stream_id.value());
    if (r < 0) {
        log_conn(this, id, dbg, "Failed to get stream capacity: {}", magic_enum::enum_name((quiche_error) r));
        r = 0;
    }

    if (r == 0) {
        if (auto it = m_tcp_connections.find(id); it != m_tcp_connections.end()) {
            // set the flag to poll the client side on receiving the next QUIC packet from the endpoint
            it->second.flags.set(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
        }
    }

    return r;
}

void Http3Upstream::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
    if (m_udp_mux.check_connection(id)) {
        m_udp_mux.set_read_enabled(id, info.send_buffer_size > 0);
        return;
    }

    auto conn_it = m_tcp_connections.find(id);
    if (conn_it == m_tcp_connections.end()) {
        return;
    }

    TcpConnection *conn = &conn_it->second;
    if (conn->flags.test(TcpConnection::TCF_READ_ENABLED) == (info.send_buffer_size > 0)) {
        // nothing to do
        return;
    }

    log_conn(this, id, trace, "Read {}", info.send_buffer_size > 0 ? "on" : "off");
    conn->flags.set(TcpConnection::TCF_READ_ENABLED, info.send_buffer_size > 0);

    if (conn->flags.test(TcpConnection::TCF_READ_ENABLED) && !m_complete_read_task_id.has_value()
            && (conn->has_unread_data() || quiche_conn_stream_readable(m_quic_conn.get(), conn->stream_id))) {
        // we have some unread data on the connection - complete it
        m_complete_read_task_id = event_loop::submit(vpn->parameters.ev_loop, {this, complete_read});
    }
}

VpnError Http3Upstream::do_health_check() {
    if (m_health_check_info.has_value()) {
        log_upstream(this, dbg, "Ignoring as another health check is already in progress");
        return {};
    }
    // FIXME: AG-8909
    if (m_h3_conn == nullptr) {
        log_upstream(this, dbg, "No HTTP3 session");
        return {VPN_EC_ERROR, "No HTTP3 session"};
    }

    auto [stream_id, is_retriable] = this->send_connect_request(&HEALTH_CHECK_HOST, "");
    if (stream_id.has_value()) {
        m_health_check_info = {
                .stream_id = stream_id,
                .timeout_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                        {
                                this,
                                [](void *arg, TaskId) {
                                    auto *self = (Http3Upstream *) arg;
                                    self->close_stream(*self->m_health_check_info->stream_id, H3_REQUEST_CANCELLED);
                                    self->m_health_check_info.reset();
                                    VpnError e = {VPN_EC_ERROR, "Health check has timed out"};
                                    self->handler.func(self->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, &e);
                                },
                        },
                        this->vpn->upstream_config.timeout),
        };
        return {};
    }

    if (is_retriable) {
        HealthCheckInfo &info = m_health_check_info.emplace(HealthCheckInfo{});
        info.retry_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                {
                        this,
                        [](void *arg, TaskId) {
                            auto *self = (Http3Upstream *) arg;
                            self->m_health_check_info->retry_task_id.release();
                            self->do_health_check();
                        },
                },
                this->vpn->upstream_config.endpoint_pinging_period / 10);
        return {};
    }

    return {VPN_EC_ERROR, "Failed to send health check request"};
}

VpnConnectionStats Http3Upstream::get_connection_stats() const {
    quiche_stats stats = {};
    quiche_conn_stats(m_quic_conn.get(), &stats);
    return {(uint32_t) (stats.rtt / 1000), (stats.sent > 0) ? (double) stats.lost / stats.sent : 0};
}

void Http3Upstream::on_icmp_request(IcmpEchoRequestEvent &event) {
    event.result = m_icmp_mux.send_request(event.request) ? 0 : -1;
}

void Http3Upstream::socket_handler(void *arg, UdpSocketEvent what, void *data) {
    Http3Upstream *upstream = (Http3Upstream *) arg;

    switch (what) {
    case UDP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }

    case UDP_SOCKET_EVENT_READ: {
        auto *event = (UdpSocketReadEvent *) data;
        log_upstream(upstream, trace, "Read {} bytes from endpoint", event->length);
        upstream->handle_socket_data({event->data, event->length});
        event->closed = (upstream->m_socket == nullptr);
        break;
    }

    case UDP_SOCKET_EVENT_TIMEOUT:
        log_upstream(upstream, dbg, "Socket timed out");
        break;
    }
}

int Http3Upstream::verify_callback(X509_STORE_CTX *store_ctx, void *arg) {
    auto *self = (Http3Upstream *) arg;
    return self->vpn->parameters.cert_verify_handler.func(self->vpn->upstream_config.endpoint->name,
            (sockaddr *) &self->vpn->upstream_config.endpoint->address, store_ctx,
            self->vpn->parameters.cert_verify_handler.arg);
}

void Http3Upstream::quic_timer_callback(evutil_socket_t, short, void *arg) {
    Http3Upstream *upstream = (Http3Upstream *) arg;
    log_upstream(upstream, dbg, "...");

    quiche_conn_on_timeout(upstream->m_quic_conn.get());
    upstream->flush_pending_quic_data();

    if (quiche_conn_is_closed(upstream->m_quic_conn.get())) {
        log_upstream(upstream, dbg, "QUIC connection closed");
        upstream->close_session_inner();
    }

    log_upstream(upstream, dbg, "Done");
}

bool Http3Upstream::flush_pending_quic_data() {
    if (m_close_on_idle_task_id.has_value()) {
        log_upstream(this, dbg, "Not sending packets when the connection is being closed on idle timeout");
        return false;
    }

    int64_t now_ns = get_time_monotonic_nanos();

    if (m_idle_timeout_at_ns && now_ns >= m_idle_timeout_at_ns) {
        log_upstream(this, dbg, "Idle timeout occurred, connection will be closed");

        // Switch context since `close_session` should not be called in listener context,
        // and to avoid recursion since `close_session_inner` will call this function again
        m_close_on_idle_task_id =
                event_loop::submit(this->vpn->parameters.ev_loop, {.arg = this, .action = [](void *arg, TaskId) {
                                                               auto *upstream = (Http3Upstream *) arg;
                                                               upstream->close_session_inner();
                                                           }});

        return false;
    }

    // This function is also called when a UDP packet is received,
    // so it is sufficient to update the idle timeout only here.
    m_idle_timeout_at_ns = now_ns + duration_cast<nanoseconds>(m_max_idle_timeout).count();

    uint8_t out[UDP_MAX_DATAGRAM_SIZE];
    while (true) {
        quiche_send_info info{};
        ssize_t r = quiche_conn_send(m_quic_conn.get(), out, sizeof(out), &info);
        if (r == QUICHE_ERR_DONE) {
            log_upstream(this, trace, "Done writing");
            break;
        }

        if (r < 0) {
            log_upstream(this, dbg, "Failed to create QUIC packet: {}", magic_enum::enum_name((quiche_error) r));
            return false;
        }

        if (VpnError err = udp_socket_write(m_socket.get(), out, r); err.code != 0) {
            log_upstream(this, dbg, "Failed to send QUIC packet: {} ({})", safe_to_string_view(err.text), err.code);
            switch (m_state) {
            case H3US_ESTABLISHING:
            case H3US_ESTABLISHED:
                if (!AG_ERR_IS_EAGAIN(err.code) && err.code != AG_ENOBUFS && !m_flush_error_task_id.has_value()) {
                    // in the other states it is enough to indicate an error by returning
                    // the corresponding value from the function
                    m_flush_error_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                            {
                                    this,
                                    [](void *arg, TaskId) {
                                        auto *self = (Http3Upstream *) arg;
                                        self->m_flush_error_task_id.release();
                                        ServerError event = {NON_ID, {VPN_EC_ERROR, "UDP socket failure"}};
                                        self->handler.func(self->handler.arg, SERVER_EVENT_ERROR, &event);
                                    },
                            });
                }
                [[fallthrough]];
            case H3US_IDLE:
            case H3US_CLOSING:
                return false;
            }
        }

        log_upstream(this, trace, "Sent {} bytes", r);
    }

    if (m_quic_timer == nullptr) {
        m_quic_timer.reset(event_new(
                vpn_event_loop_get_base(this->vpn->parameters.ev_loop), -1, EV_PERSIST, quic_timer_callback, this));
    }

    uint64_t timeout_ms = std::min((uint64_t) duration_cast<milliseconds>(m_max_idle_timeout).count(),
            quiche_conn_timeout_as_millis(m_quic_conn.get()));
    log_upstream(this, trace, "Timeout: {}ms", timeout_ms);
    const timeval tv = ms_to_timeval(uint32_t(timeout_ms));
    event_del(m_quic_timer.get());
    event_add(m_quic_timer.get(), &tv);

    return true;
}

void Http3Upstream::handle_socket_data(U8View data) {
    quiche_conn *quic_conn = m_quic_conn.get();
    quiche_recv_info info{};
    info.from = (sockaddr *) &this->vpn->upstream_config.endpoint->address;
    info.from_len = sockaddr_get_size((sockaddr *) &this->vpn->upstream_config.endpoint->address);
    if (ssize_t r = quiche_conn_recv(quic_conn, (uint8_t *) data.data(), data.size(), &info); r < 0) {
        log_upstream(this, err, "Failed to process packet: {}", magic_enum::enum_name((quiche_error) r));
        return;
    }

    if (quiche_conn_is_closed(quic_conn)) {
        log_upstream(this, dbg, "QUIC connection closed");
        close_session_inner();
        return;
    }

    m_in_handler = true;

    switch (m_state) {
    case H3US_IDLE:
    case H3US_CLOSING:
        log_upstream(this, err, "Invalid state on read: {}", magic_enum::enum_name(m_state));
        assert(0);
        break;

    case H3US_ESTABLISHING: {
        if (!quiche_conn_is_established(quic_conn)) {
            break;
        }

        if (m_log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
            const uint8_t *proto = nullptr;
            size_t proto_len = 0;
            quiche_conn_application_proto(quic_conn, &proto, &proto_len);
            log_upstream(this, dbg, "QUIC connection established with ALPN: {}",
                    std::string_view{(char *) proto, proto_len});
        }

        if (!initiate_h3_session()) {
            close_session_inner();
            break;
        }

        m_state = H3US_ESTABLISHED;
        this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
        break;
    }

    case H3US_ESTABLISHED: {
        log_upstream(this, trace, "Polling h3 connections...");

        while (true) {
            quiche_h3_event *h3_event; // NOLINT(cppcoreguidelines-init-variables)
            int64_t poll_res = quiche_h3_conn_poll(m_h3_conn.get(), quic_conn, &h3_event);
            if (poll_res < 0) {
                if (poll_res != QUICHE_H3_ERR_DONE) {
                    log_upstream(this, dbg, "Failed to process data received from endpoint: {}",
                            magic_enum::enum_name((quiche_h3_error) poll_res));
                }
                break;
            }

            handle_h3_event(h3_event, poll_res);
            quiche_h3_event_free(h3_event);
        }

        log_upstream(this, trace, "Poll done");

        // do some things here as they may now be available
        // (for example, connection or stream windows could have been slid)
        if (!m_post_receive_task_id.has_value()) {
            m_post_receive_task_id =
                    event_loop::submit(this->vpn->parameters.ev_loop, {this, [](void *arg, TaskId) {
                                                                   auto *self = (Http3Upstream *) arg;
                                                                   self->m_post_receive_task_id.release();
                                                                   self->retry_connect_requests();
                                                                   self->poll_tcp_connections();
                                                                   self->m_udp_mux.report_sent_bytes();
                                                               }});
        }

        break;
    }
    }

    this->flush_pending_quic_data();

    if (quiche_conn_is_closed(quic_conn)) {
        log_upstream(this, dbg, "QUIC connection closed");
        close_session_inner();
    }

    m_in_handler = false;
    if (m_closed) {
        close_session_inner();
    }
}

bool Http3Upstream::initiate_h3_session() {
    quiche_h3_config *config = quiche_h3_config_new();
    if (config == nullptr) {
        log_upstream(this, err, "Failed to create HTTP/3 config");
        return false;
    }

    m_h3_conn.reset(quiche_h3_conn_new_with_transport(m_quic_conn.get(), config));
    quiche_h3_config_free(config);
    if (m_h3_conn == nullptr) {
        log_upstream(this, err, "Failed to create HTTP/3 session");
        return false;
    }

    return this->flush_pending_quic_data();
}

std::pair<uint64_t, Http3Upstream::TcpConnection *> Http3Upstream::get_tcp_conn_by_stream_id(uint64_t id) {
    std::pair<uint64_t, Http3Upstream::TcpConnection *> r = {NON_ID, nullptr};

    auto id_iter = m_tcp_conn_by_stream_id.find(id);
    if (id_iter != m_tcp_conn_by_stream_id.end()) {
        r.first = id_iter->second;
        auto found = m_tcp_connections.find(id_iter->second);
        if (found != m_tcp_connections.end()) {
            r.second = &found->second;
        }
    }

    return r;
}

static int collect_header(uint8_t *name, size_t name_len, uint8_t *value, size_t value_len, void *arg) {
    auto *h = (HttpHeaders *) arg;
    h->put_field(std::string{(char *) name, name_len}, std::string((char *) value, value_len));
    return 0;
}

void Http3Upstream::handle_h3_event(quiche_h3_event *h3_event, uint64_t stream_id) {
    switch (quiche_h3_event_type(h3_event)) {
    case QUICHE_H3_EVENT_HEADERS: {
        HttpHeaders headers{.version = HTTP_VER_3_0};
        quiche_h3_event_for_each_header(h3_event, collect_header, &headers);
        log_headers(m_log, stream_id, &headers, "Got response from server");
        handle_response(stream_id, &headers);
        break;
    }

    case QUICHE_H3_EVENT_DATA: {
        this->process_pending_data(stream_id);
        break;
    }

    case QUICHE_H3_EVENT_RESET:
    case QUICHE_H3_EVENT_FINISHED: {
        log_stream(this, stream_id, dbg, "Stream is closed");
        Http3ErrorCode stream_close_code = H3_REQUEST_CANCELLED;
        if (stream_id == m_udp_mux.get_stream_id()) {
            m_udp_mux.close({});
        } else if (stream_id == m_icmp_mux.get_stream_id()) {
            m_icmp_mux.close();
        } else if (is_health_check_stream(stream_id)) {
            this->handler.func(this->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, &m_health_check_info->error);
            stream_close_code =
                    (m_health_check_info->error.code == VPN_EC_NOERROR) ? H3_NO_ERROR : H3_REQUEST_CANCELLED;
            m_health_check_info.reset();
        } else if (auto [conn_id, conn] = this->get_tcp_conn_by_stream_id(stream_id); conn == nullptr) {
            log_stream(this, stream_id, dbg, "Got stream processed event on closed connection");
            assert(0);
        } else if (conn->pending_error.has_value()) {
            this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &conn->pending_error.value());
            this->clean_tcp_connection_data(conn_id);
        } else if (!conn->has_unread_data()) {
            this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &conn_id);
            this->clean_tcp_connection_data(conn_id);
        } else {
            // postpone until all data is sent to client
        }

        this->close_stream(stream_id, stream_close_code);

        break;
    }

    case QUICHE_H3_EVENT_DATAGRAM:
        log_stream(this, stream_id, err, "Unexpected datagram frame");
        assert(0);
        break;

    case QUICHE_H3_EVENT_GOAWAY:
        log_upstream(this, dbg, "Got GOAWAY");
        // session will be closed after `is_closed` returns true
        break;
    }
}

void Http3Upstream::handle_response(uint64_t stream_id, const HttpHeaders *headers) {
    if (m_udp_mux.get_stream_id() == stream_id) {
        m_udp_mux.handle_response(headers);
        return;
    }

    if (m_icmp_mux.get_stream_id() == stream_id) {
        m_icmp_mux.handle_response(headers);
        return;
    }

    if (is_health_check_stream(stream_id)) {
        if (headers->status_code == HTTP_AUTH_REQUIRED_STATUS) {
            m_health_check_info->error = {VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG};
        } else if (headers->status_code != HTTP_OK_STATUS) {
            m_health_check_info->error = {VPN_EC_ERROR, "Bad response code"};
        }
        m_health_check_info->timeout_task_id.reset();
        return;
    }

    auto found = get_tcp_conn_by_stream_id(stream_id);
    if (found.second == nullptr) {
        log_stream(this, stream_id, dbg, "Got response on nonexistent connection");
        assert(0);
        close_stream(stream_id, H3_REQUEST_CANCELLED);
        return;
    }

    TcpConnection *conn = found.second;
    if (headers->status_code == HTTP_OK_STATUS) {
        conn->flags.set(TcpConnection::TCF_ESTABLISHED);
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &found.first);
    } else {
        conn->pending_error = {found.first, bad_http_response_to_connect_error(headers)};
    }
}

// err is application-level error code (in our case, HTTP/3 error codes, defined in H3_* constants)
void Http3Upstream::close_stream(uint64_t stream_id, Http3ErrorCode err) {
    if (m_quic_conn == nullptr) {
        // Connection might be deleted due to idle timeout
        log_stream(this, stream_id, trace, "Nothing to do: no QUIC connection");
        return;
    }
    if (auto ret = quiche_conn_stream_shutdown(m_quic_conn.get(), stream_id, QUICHE_SHUTDOWN_READ, err); ret < 0) {
        log_stream(
                this, stream_id, dbg, "Failed to shut down read side: {}", magic_enum::enum_name((quiche_error) ret));
    }
    if (auto ret = quiche_conn_stream_shutdown(m_quic_conn.get(), stream_id, QUICHE_SHUTDOWN_WRITE, err); ret < 0) {
        log_stream(
                this, stream_id, dbg, "Failed to shut down write side: {}", magic_enum::enum_name((quiche_error) ret));
    }
    if (auto [_, conn] = this->get_tcp_conn_by_stream_id(stream_id); conn != nullptr) {
        conn->flags.set(TcpConnection::TCF_STREAM_CLOSED);
    }
    this->flush_pending_quic_data();
}

ssize_t Http3Upstream::read_out_h3_data(uint64_t stream_id, uint8_t *buffer, size_t cap) {
    ssize_t r = quiche_h3_recv_body(m_h3_conn.get(), m_quic_conn.get(), stream_id, buffer, cap);
    if (r == QUICHE_H3_ERR_DONE) {
        r = 0;
    } else if (r < 0) {
        log_stream(
                this, stream_id, dbg, "Failed to read stream data: err={}", magic_enum::enum_name((quiche_h3_error) r));
    }

    return r;
}

void Http3Upstream::process_pending_data(uint64_t stream_id) {
    size_t available_to_read = UDP_MAX_DATAGRAM_SIZE;
    bool drop = false;
    if (m_udp_mux.get_stream_id() == stream_id || m_icmp_mux.get_stream_id() == stream_id) {
        // do nothing
    } else if (this->is_health_check_stream(stream_id)) {
        log_stream(this, stream_id, dbg, "Got data on health check stream");
        drop = true;
    } else if (auto [conn_id, conn] = this->get_tcp_conn_by_stream_id(stream_id); conn == nullptr) {
        log_stream(this, stream_id, dbg, "Got data on closed connection");
        drop = true;
    } else if (0 != this->read_out_pending_data(conn_id, conn)) {
        this->close_tcp_connection(conn_id, false);
        drop = true;
    } else if (conn->flags.test(TcpConnection::TCF_STREAM_CLOSED) && !conn->has_unread_data()) {
        this->close_tcp_connection(conn_id, true);
        drop = true;
    } else if (!conn->flags.test(TcpConnection::TCF_READ_ENABLED)
            || !quiche_conn_stream_readable(m_quic_conn.get(), stream_id)) {
        available_to_read = 0;
    } else {
        ServerAvailableToSendEvent event = {conn_id};
        this->handler.func(this->handler.arg, SERVER_EVENT_GET_AVAILABLE_TO_SEND, &event);
        available_to_read = std::min(event.length, UDP_MAX_DATAGRAM_SIZE);
    }

    if (available_to_read == 0) {
        return;
    }

    std::vector<uint8_t> buffer(available_to_read);
    ssize_t n = this->read_out_h3_data(stream_id, buffer.data(), buffer.size());
    if (n <= 0) {
        return;
    }
    if (drop) {
        log_stream(this, stream_id, dbg, "Dropping data ({} bytes)", n);
        return;
    }

    U8View data = {buffer.data(), (size_t) n};
    if (m_udp_mux.get_stream_id() == stream_id) {
        m_udp_mux.process_read_event(data);
        return;
    }

    if (m_icmp_mux.get_stream_id() == stream_id) {
        m_icmp_mux.process_read_event(data);
        return;
    }

    auto [conn_id, conn] = this->get_tcp_conn_by_stream_id(stream_id);
    if (conn == nullptr) {
        assert(0);
        return;
    }

    assert(conn->flags.test(TcpConnection::TCF_READ_ENABLED));
    int r = this->raise_read_event(conn_id, data);
    if (r < 0) {
        this->close_tcp_connection(conn_id, false);
        return;
    }

    data.remove_prefix(r);
    if (!data.empty()) {
        this->push_unread_data(conn_id, conn, data);
    }
}

void Http3Upstream::close_session_inner() {
    if (m_in_handler) {
        m_closed = true;
        return;
    }

    std::optional<VpnError> error;
    if (m_quic_conn != nullptr) {
        uint64_t code;
        bool is_app;
        const uint8_t *reason_bytes;
        size_t reason_len;
        if (quiche_conn_peer_error(m_quic_conn.get(), &is_app, &code, &reason_bytes, &reason_len)) {
            std::string reason = escape_non_print({reason_bytes, reason_len});
            if (is_app) {
                log_upstream(
                        this, dbg, "QUIC connection closed due to application error: {}, reason: {}", code, reason);
                error = (code == HTTP_ERROR_AUTH_REQUIRED)
                        ? VpnError{VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG}
                        : VpnError{VPN_EC_ERROR, "QUIC connection closed due to application error"};
            } else {
                log_upstream(this, dbg, "QUIC connection closed due to transport error: {}, reason: {}", code, reason);
                error = {VPN_EC_ERROR, "QUIC connection closed due to transport error"};
            }
        }
    }

    close_session();

    if (error.has_value()) {
        ServerError event = {NON_ID, error.value()};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &event);
    } else {
        this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    }
}

Http3Upstream::SendConnectRequestResult Http3Upstream::send_connect_request(
        const TunnelAddress *dst_addr, std::string_view app_name) {
    if (m_h3_conn == nullptr) {
        log_upstream(this, dbg, "Failed to send connect request: upstream is not connected");
        return {std::nullopt, false};
    }

    HttpHeaders headers = make_http_connect_request(HTTP_VER_3_0, dst_addr, app_name, m_credentials);

    std::vector<NameValue> nva = http_headers_to_nv_list(&headers);
    std::vector<quiche_h3_header> h3_headers(nva.size());
    std::transform(nva.begin(), nva.end(), h3_headers.begin(), [](const NameValue &i) -> quiche_h3_header {
        return {i.name.data(), i.name.size(), i.value.data(), i.value.size()};
    });

    int64_t stream_id = quiche_h3_send_request(m_h3_conn.get(), m_quic_conn.get(), h3_headers.data(), h3_headers.size(), false);
    if (stream_id >= 0) {
        log_headers(m_log, stream_id, &headers, "Sending connect request");
        if (!this->flush_pending_quic_data()) {
            log_upstream(this, dbg, "Failed to send connect request");
            stream_id = -1;
        }
    } else {
        log_upstream(
                this, dbg, "Failed to send connect request: {}", magic_enum::enum_name((quiche_h3_error) stream_id));
    }

    return {
            (stream_id >= 0) ? std::make_optional(stream_id) : std::nullopt,
            // Due to a bug, Quiche may also return QUICHE_H3_ERR_DONE when sending is blocked.
            // TODO: this was fixed in later versions of Quiche, so remove when Quiche is updated.
            stream_id == QUICHE_H3_ERR_STREAM_BLOCKED || stream_id == QUICHE_H3_ERR_DONE,
    };
}

void Http3Upstream::close_tcp_connection(uint64_t id, bool graceful) {
    log_conn(this, id, dbg, "Closing");

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        const TcpConnection *conn = &i->second;
        if (m_h3_conn != nullptr && !conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
            this->close_stream(i->second.stream_id, graceful ? H3_NO_ERROR : H3_REQUEST_CANCELLED);
        }
    }

    this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);

    clean_tcp_connection_data(id);
}

void Http3Upstream::clean_tcp_connection_data(uint64_t id) {
    m_closing_connections.erase(id);

    if (0 != m_retriable_tcp_requests.erase(id)) {
        return;
    }

    auto i = m_tcp_connections.find(id);
    if (i == m_tcp_connections.end()) {
        return;
    }

    TcpConnection *conn = &i->second;
    if (conn->has_unread_data()) {
        log_conn(this, id, dbg, "Remaining unread={}", conn->unread_data->size());
    }

    m_tcp_conn_by_stream_id.erase(conn->stream_id);
    m_tcp_connections.erase(i);

    log_upstream(this, dbg, "Remaining connections: open={} ({}), retriable={}", m_tcp_connections.size(),
            m_tcp_conn_by_stream_id.size(), m_retriable_tcp_requests.size());
}

bool Http3Upstream::is_health_check_stream(uint64_t stream_id) const {
    return m_health_check_info.has_value() && m_health_check_info->stream_id == stream_id;
}

std::optional<uint64_t> Http3Upstream::get_stream_id(uint64_t id) const {
    std::optional<uint64_t> stream_id;
    if (m_udp_mux.check_connection(id)) {
        stream_id = m_udp_mux.get_stream_id();
    } else if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        stream_id = i->second.stream_id;
    }
    return stream_id;
}

bool Http3Upstream::push_unread_data(uint64_t conn_id, TcpConnection *conn, U8View data) const {
    if (conn->unread_data == nullptr) {
        conn->unread_data = this->vpn->make_buffer(conn_id);
        if (std::optional<std::string> err = conn->unread_data->init(); err.has_value()) {
            log_conn(this, conn_id, err, "Failed to initialize data buffer: {}", *err);
            return false;
        }
    }

    std::optional<std::string> err = conn->unread_data->push(data);
    if (err.has_value()) {
        log_conn(this, conn_id, err, "Failed to store data in buffer: {}", *err);
    }

    return !err.has_value();
}

int Http3Upstream::read_out_pending_data(uint64_t conn_id, TcpConnection *conn) {
    DataBuffer *pending = conn->unread_data.get();
    if (pending == nullptr) {
        return 0;
    }

    while (conn->flags.test(TcpConnection::TCF_READ_ENABLED) && pending->size() > 0) {
        BufferPeekResult res = pending->peek();
        if (res.err.has_value()) {
            log_conn(this, conn_id, err, "Failed to read buffered data: {}", *res.err);
            return -1;
        }
        int r = this->raise_read_event(conn_id, res.data);
        if (r > 0) {
            pending->drain(r);
        } else if (r < 0) {
            return r;
        }
    }

    return 0;
}

int Http3Upstream::raise_read_event(uint64_t conn_id, U8View data) {
    ServerReadEvent serv_event = {conn_id, data.data(), data.size(), 0};
    this->handler.func(this->handler.arg, SERVER_EVENT_READ, &serv_event);
    return serv_event.result;
}

void Http3Upstream::poll_tcp_connections() {
    for (auto i = m_tcp_connections.begin(); i != m_tcp_connections.end();) {
        auto next = std::next(i);

        auto &[conn_id, conn] = *i;
        if (conn.flags.test(TcpConnection::TCF_ESTABLISHED)
                && conn.flags.test(TcpConnection::TCF_READ_ENABLED)
                && !conn.flags.test(TcpConnection::TCF_STREAM_CLOSED)
                && (conn.has_unread_data() || quiche_conn_stream_readable(m_quic_conn.get(), conn.stream_id))) {
            this->process_pending_data(conn.stream_id);
        }

        if (conn.flags.test(TcpConnection::TCF_ESTABLISHED)
                && !conn.flags.test(TcpConnection::TCF_STREAM_CLOSED)
                && conn.flags.test(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES)
                && 0 < quiche_conn_stream_capacity(m_quic_conn.get(), conn.stream_id)) {
            conn.flags.reset(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
            ServerDataSentEvent event = {conn_id, std::exchange(conn.sent_bytes_to_notify, 0)};
            this->handler.func(this->handler.arg, SERVER_EVENT_DATA_SENT, &event);
        }

        i = next;
    }

    this->flush_pending_quic_data();
}

void Http3Upstream::retry_connect_requests() {
    for (auto i = m_retriable_tcp_requests.begin(); i != m_retriable_tcp_requests.end();) {
        RetriableTcpConnectRequest &request = i->second;

        auto [stream_id, is_retriable] = this->send_connect_request(&request.dst_addr, request.app_name);
        if (stream_id.has_value()) {
            TcpConnection *conn = &m_tcp_connections[i->first];
            conn->stream_id = stream_id.value();
            m_tcp_conn_by_stream_id[stream_id.value()] = i->first;
            i = m_retriable_tcp_requests.erase(i);
            continue;
        }

        if (is_retriable) {
            ++i;
            continue;
        }

        ServerError error = {i->first, {-1, "Failed to send connect request"}};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &error);
        i = m_retriable_tcp_requests.erase(i);
    }

    this->flush_pending_quic_data();
}

void Http3Upstream::complete_read(void *arg, TaskId) {
    auto *self = (Http3Upstream *) arg;
    self->m_complete_read_task_id.release();

    for (auto i = self->m_tcp_connections.begin(); i != self->m_tcp_connections.end();) {
        auto next = std::next(i);

        TcpConnection &conn = i->second;
        if (conn.has_unread_data() || quiche_conn_stream_readable(self->m_quic_conn.get(), conn.stream_id)) {
            self->process_pending_data(conn.stream_id);
        }

        i = next;
    }

    self->flush_pending_quic_data();
}

std::optional<uint64_t> Http3Upstream::mux_send_connect_request_callback(
        ServerUpstream *upstream, const TunnelAddress *dst_addr, std::string_view app_name) {
    auto *self = (Http3Upstream *) upstream;
    return self->send_connect_request(dst_addr, app_name).stream_id;
}

int Http3Upstream::mux_send_data_callback(ServerUpstream *upstream, uint64_t stream_id, U8View data) {
    auto *self = (Http3Upstream *) upstream;
    assert(self->m_udp_mux.get_stream_id() == stream_id || self->m_icmp_mux.get_stream_id() == stream_id);

    log_upstream(self, trace, "Trying to send packet of {} bytes on {} stream", data.size(),
            stream_id == self->m_udp_mux.get_stream_id() ? "UDP" : "ICMP");

    ssize_t stream_cap = quiche_conn_stream_capacity(self->m_quic_conn.get(), stream_id);
    if (stream_cap < 0) {
        log_upstream(self, dbg, "Failed to send packet on {} stream: quiche_conn_stream_capacity: {}",
                stream_id == self->m_udp_mux.get_stream_id() ? "UDP" : "ICMP",
                magic_enum::enum_name((quiche_h3_error) stream_cap));
        return (int) stream_cap;
    }

    // HTTP/3 DATA frame overhead
    size_t overhead = varint_len((uint64_t) data.size()) + varint_len(0);
    if ((overhead + data.size()) > (size_t) stream_cap) {
        log_upstream(self, dbg, "Failed to send packet on {} stream: not enough stream capacity ({})",
                stream_id == self->m_udp_mux.get_stream_id() ? "UDP" : "ICMP", stream_cap);
        return 0; // Silently drop packet
    }

    ssize_t r = quiche_h3_send_body(
            self->m_h3_conn.get(), self->m_quic_conn.get(), stream_id, (uint8_t *) data.data(), data.size(), false);
    if (r < 0) {
        log_upstream(self, dbg, "Failed to send packet on {} stream: quiche_h3_send_body: {}",
                stream_id == self->m_udp_mux.get_stream_id() ? "UDP" : "ICMP",
                magic_enum::enum_name((quiche_h3_error) r));
        return (int) r;
    }

    if ((size_t) r != data.size()) {
        log_upstream(self, warn, "Incomplete packet sent: {} of {} bytes", (size_t) r, data.size());
        assert(0);
    }

    return 0;
}

void Http3Upstream::mux_consume_callback(ServerUpstream *, uint64_t, size_t) {
    // Nothing to do
}

void Http3Upstream::handle_sleep() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE) {
        udp_socket_drain(m_socket.get(), 0);
        this->flush_pending_quic_data();
    }

    log_upstream(this, dbg, "Done");
}

void Http3Upstream::handle_wake() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE) {
        this->flush_pending_quic_data(); // Force timeout check
        this->do_health_check();
    }

    log_upstream(this, dbg, "Done");
}

} // namespace ag
