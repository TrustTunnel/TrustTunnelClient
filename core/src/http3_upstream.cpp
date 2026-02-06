#include "http3_upstream.h"

#include <algorithm>
#include <cstdlib>
#include <unordered_set>

#include <magic_enum/magic_enum.hpp>
#include <openssl/rand.h>

#include "net/http_session.h"
#include "net/quic_connector.h"
#include "net/udp_socket.h"
#include "net/utils.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/utils.h"

#define log_upstream(ups_, lvl_, fmt_, ...) lvl_##log((ups_)->m_log, "[{}] " fmt_, (ups_)->id, ##__VA_ARGS__)
#define log_conn(ups_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((ups_)->m_log, "[{}] [R:{}] " fmt_, (ups_)->id, (uint64_t) (cid_), ##__VA_ARGS__)
#define log_stream(ups_, sid_, lvl_, fmt_, ...)                                                                        \
    lvl_##log((ups_)->m_log, "[{}] [SID:{}] " fmt_, (ups_)->id, (uint64_t) (sid_), ##__VA_ARGS__)

using namespace std::chrono;
using namespace ag;

template <>
struct magic_enum::customize::enum_range<quiche_h3_error> {
    static constexpr int min = -1100;
    static constexpr int max = 0;
};

// FIXME: these should be available from the HTTP/3 implementation
enum Http3Upstream::Http3ErrorCode : uint64_t {
    H3_NO_ERROR = 0x100,
    H3_REQUEST_CANCELLED = 0x10c,
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
                static Logger log{"Q"};
                tracelog(log, "{}", line);
            },
            nullptr);
#endif
}

Http3Upstream::~Http3Upstream() = default;

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
    // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
    const VpnHttp3UpstreamConfig &h3_config = this->PROTOCOL_CONFIG->http3;

    // Let the connection live long enough to perform a health check.
    m_max_idle_timeout = 2 * (upstream_config.timeout + upstream_config.health_check_timeout);

    if (this->vpn->quic_connector) {
        m_quic_connector = std::move(this->vpn->quic_connector);
        if (continue_connecting()) {
            m_state = H3US_ESTABLISHING;
            flush_pending_quic_data();
            return true;
        }
        log_upstream(this, dbg, "Failed to continue handed-off connection");
    }

    U8View endpoint_data{
            upstream_config.endpoint->additional_data.data, upstream_config.endpoint->additional_data.size};
    U8View client_random_data{
            upstream_config.endpoint->tls_client_random.data, upstream_config.endpoint->tls_client_random.size};
    U8View client_random_mask{upstream_config.endpoint->tls_client_random_mask.data,
            upstream_config.endpoint->tls_client_random_mask.size};
    SslPtr ssl;
    if (auto r = make_ssl(verify_callback, this, {QUIC_H3_ALPN_PROTOS, std::size(QUIC_H3_ALPN_PROTOS)},
                upstream_config.endpoint->name, /*quic*/ MSPT_QUICHE, endpoint_data, client_random_data,
                client_random_mask);
            std::holds_alternative<SslPtr>(r)) {
        ssl = std::move(std::get<SslPtr>(r));
    } else {
        log_upstream(this, err, "{}", std::get<std::string>(r));
        return false;
    }

    QuicConnectorParameters quic_connector_prm{
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {.handler = quic_connector_handler, .arg = this},
            .socket_manager = this->vpn->parameters.network_manager->socket,
            .log_prefix = AG_FMT("h3-upstream-{}", this->id),
    };
    m_quic_connector.reset(quic_connector_create(&quic_connector_prm));
    if (!m_quic_connector) {
        log_upstream(this, err, "Failed to create a QUIC connector");
        return false;
    }

    SocketAddress sa_peer(upstream_config.endpoint->address);
    QuicConnectorConnectParameters connect_prm{
            .peer = &sa_peer,
            .ssl = ssl.release(),
            .timeout = upstream_config.timeout,
            .max_idle_timeout = m_max_idle_timeout,
            .quic_version = (h3_config.quic_version == 0) ? QUICHE_PROTOCOL_VERSION : h3_config.quic_version,
    };

    VpnError error = quic_connector_connect(m_quic_connector.get(), &connect_prm);
    if (error.code != 0) {
        log_upstream(this, err, "Failed to start QUIC connection: ({}) {}", error.code, error.text);
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
        if (int r = quiche_conn_close(m_quic_conn.get(), true, 0, RUST_EMPTY, 0); r < 0 && r != QUICHE_ERR_DONE) {
            log_upstream(this, err, "Failed to close QUIC connection: {}", magic_enum::enum_name((quiche_error) r));
        } else {
            this->flush_pending_quic_data();
        }
    }

    m_ssl_object = nullptr;
    m_udp_mux.close({});
    m_icmp_mux.close();
    m_h3_conn.reset();
    m_quic_conn.reset();
    m_quic_timer.reset();
    m_socket.reset();
    m_quic_connector.reset();
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
    if (m_udp_mux.check_connection(conn_id)) {
        m_udp_mux.close_connection(conn_id, async);
        return;
    }

    if (!async) {
        this->close_tcp_connection(conn_id, graceful);
    }

    m_closing_connections[conn_id] = graceful;
    if (!m_close_connections_task_id.has_value()) {
        m_close_connections_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *self = (Http3Upstream *) arg;
                                    self->m_close_connections_task_id.release();
                                    std::unordered_map<uint64_t, bool> connections;
                                    std::swap(connections, self->m_closing_connections);
                                    for (const auto &[conn_id_, graceful_] : connections) {
                                        self->close_tcp_connection(conn_id_, graceful_);
                                    }
                                },
                });
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
                                    self->poll_connections();
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

void Http3Upstream::do_health_check() {
    m_health_check_info.reset(); // Forget about the current health check.

    // FIXME: AG-8909
    if (m_h3_conn == nullptr) {
        log_upstream(this, warn, "No HTTP3 session");
        m_health_check_info = {
                .stream_id = std::nullopt,
                .timeout_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                        {
                                this,
                                [](void *arg, TaskId) {
                                    auto *self = (Http3Upstream *) arg;
                                    self->close_stream(*self->m_health_check_info->stream_id, H3_REQUEST_CANCELLED);
                                    self->m_health_check_info.reset();
                                    VpnError e = {VPN_EC_ERROR, "No HTTP3 session"};
                                    self->handler.func(self->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &e);
                                },
                        },
                        {}),
        };
        return;
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
                                    self->handler.func(self->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &e);
                                },
                        },
                        this->vpn->upstream_config.health_check_timeout),
        };
        return;
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
                this->vpn->upstream_config.health_check_timeout / 10);
        return;
    }

    m_health_check_info = {
            .stream_id = std::nullopt,
            .timeout_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                    {
                            this,
                            [](void *arg, TaskId) {
                                auto *self = (Http3Upstream *) arg;
                                self->close_stream(*self->m_health_check_info->stream_id, H3_REQUEST_CANCELLED);
                                self->m_health_check_info.reset();
                                VpnError e = {VPN_EC_ERROR, "Failed to send health check request"};
                                self->handler.func(self->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &e);
                            },
                    },
                    {}),
    };
}

void Http3Upstream::cancel_health_check() {
    m_health_check_info.reset();
}

VpnConnectionStats Http3Upstream::get_connection_stats() const {
    quiche_stats stats = {};
    quiche_conn_stats(m_quic_conn.get(), &stats);

    uint64_t rtt_ns = 0;
    for (size_t i = 0; i < stats.paths_count; ++i) {
        quiche_path_stats path_stats = {};
        quiche_conn_path_stats(m_quic_conn.get(), i, &path_stats);
        rtt_ns = std::max(rtt_ns, path_stats.rtt);
    }

    return {
            .rtt_us = uint32_t(rtt_ns / 1000),
            .packet_loss_ratio =
                    (stats.sent > 0) ? static_cast<double>(stats.lost) / static_cast<double>(stats.sent) : 0,
    };
}

void Http3Upstream::on_icmp_request(IcmpEchoRequestEvent &event) {
    event.result = m_icmp_mux.send_request(event.request) ? 0 : -1;
    this->flush_pending_quic_data();
}

void Http3Upstream::quic_connector_handler(void *arg, QuicConnectorEvent what, void *data) {
    auto *upstream = (Http3Upstream *) arg;
    switch (what) {
    case QUIC_CONNECTOR_EVENT_READY: {
        log_upstream(upstream, dbg, "QUIC connector ready");
        if (!upstream->continue_connecting()) {
            upstream->close_session_inner();
            break;
        }
        upstream->flush_pending_quic_data();
        break;
    }
    case QUIC_CONNECTOR_EVENT_ERROR: {
        auto *error = (VpnError *) data;
        log_upstream(upstream, dbg, "Closing session on QUIC connector error: ({}) {}", error->code, error->text);
        upstream->close_session_inner();
        break;
    }
    case QUIC_CONNECTOR_EVENT_PROTECT:
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
}

void Http3Upstream::socket_handler(void *arg, UdpSocketEvent what, void *data) {
    auto *upstream = (Http3Upstream *) arg;

    switch (what) {
    case UDP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }

    case UDP_SOCKET_EVENT_READABLE:
        upstream->on_udp_packet();
        break;

    case UDP_SOCKET_EVENT_TIMEOUT:
        if (!upstream->m_quic_conn || !quiche_conn_is_established(upstream->m_quic_conn.get())
                || !upstream->m_h3_conn) {
            log_upstream(upstream, dbg, "UDP socket timed out, closing session");
            upstream->close_session_inner();
        } else {
            quiche_conn_send_ack_eliciting(upstream->m_quic_conn.get());
            upstream->flush_pending_quic_data();
        }
        break;
    }
}

int Http3Upstream::verify_callback(X509_STORE_CTX *store_ctx, void *arg) {
    auto *self = (Http3Upstream *) arg;
    auto *cert = X509_STORE_CTX_get0_cert(store_ctx);
    auto *chain = X509_STORE_CTX_get0_untrusted(store_ctx);
    auto *ssl = (SSL *) X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    return self->vpn->parameters.cert_verify_handler.func(
            !safe_to_string_view(self->vpn->upstream_config.endpoint->remote_id).empty()
                    ? self->vpn->upstream_config.endpoint->remote_id
                    : self->vpn->upstream_config.endpoint->name,
            (sockaddr *) &self->vpn->upstream_config.endpoint->address, {cert, chain, ssl},
            self->vpn->parameters.cert_verify_handler.arg);
}

void Http3Upstream::quic_timer_callback(evutil_socket_t, short, void *arg) {
    auto *upstream = (Http3Upstream *) arg;
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
        m_close_on_idle_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *upstream = (Http3Upstream *) arg;
                                    upstream->close_session_inner();
                                },
                });

        return false;
    }

    // This function is also called when a UDP packet is received,
    // so it is sufficient to update the idle timeout only here.
    m_idle_timeout_at_ns = now_ns + duration_cast<nanoseconds>(m_max_idle_timeout).count();

    uint8_t out[QUIC_MAX_UDP_PAYLOAD_SIZE];
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

void Http3Upstream::on_udp_packet() {
    constexpr size_t READ_BUDGET = 64;

    quiche_conn *quic_conn = m_quic_conn.get();
    SocketAddress local_address = local_socket_address_from_fd(udp_socket_get_fd(m_socket.get()));

    quiche_recv_info info{
            .from = (sockaddr *) &this->vpn->upstream_config.endpoint->address,
            .from_len = SocketAddress(this->vpn->upstream_config.endpoint->address).c_socklen(),
            .to = (sockaddr *) local_address.c_sockaddr(),
            .to_len = local_address.c_socklen(),
    };
    uint8_t buffer[QUIC_MAX_UDP_PAYLOAD_SIZE];
    for (size_t i = 0; i < READ_BUDGET; ++i) {
        ssize_t r = udp_socket_recv(m_socket.get(), buffer, std::size(buffer));
        if (r <= 0) {
            int err = evutil_socket_geterror(udp_socket_get_fd(m_socket.get()));
            if (err != 0 && !AG_ERR_IS_EAGAIN(err)) {
                log_upstream(
                        this, dbg, "Failed to read data from socket: {} ({})", evutil_socket_error_to_string(err), err);
            }
            break;
        }

        log_upstream(this, trace, "Read {} bytes from endpoint", r);
        r = quiche_conn_recv(quic_conn, buffer, r, &info);
        if (r < 0) {
            log_upstream(this, warn, "Failed to process packet: {}", magic_enum::enum_name((quiche_error) r));
            break;
        }

        // Data receival indicates that the connection is alive.
        // Cancelling the health check now should reduce the probability
        // of bogus health check failures due to a slow remote.
        cancel_health_check();

        if (quiche_conn_is_closed(quic_conn)) {
            log_upstream(this, dbg, "QUIC connection closed");
            close_session_inner();
            return;
        }
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
            log_upstream(this, dbg, "QUIC connection established with ALPN: {}, session reused: {}",
                    std::string_view{(char *) proto, proto_len},
                    m_ssl_object ? SSL_session_reused((SSL *) m_ssl_object) : 0);
        }

        if (!initiate_h3_session()) {
            close_session_inner();
            break;
        }

        m_state = H3US_ESTABLISHED;
        assert(this->vpn->upstream_config.timeout >= this->vpn->upstream_config.health_check_timeout);

        // Prevent idle connection close by sending an ACK-eliciting packet on idle.
        udp_socket_set_timeout(m_socket.get(), this->vpn->upstream_config.timeout);

        if (m_ssl_object) {
            m_kex_group_nid = SSL_get_negotiated_group((SSL *) m_ssl_object);
        }
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
            m_post_receive_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                    {
                            .arg = this,
                            .action =
                                    [](void *arg, TaskId) {
                                        auto *self = (Http3Upstream *) arg;
                                        self->m_post_receive_task_id.release();
                                        self->retry_connect_requests();
                                        self->poll_connections();
                                        if (std::optional stream_id = self->m_udp_mux.get_stream_id();
                                                stream_id.has_value()
                                                && 0 < quiche_conn_stream_capacity(
                                                           self->m_quic_conn.get(), stream_id.value())) {
                                            self->m_udp_mux.report_sent_bytes();
                                        }
                                    },
                    });
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
        close_session_inner(std::exchange(m_pending_session_error, std::nullopt));
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
    switch (enum quiche_h3_event_type event_type = quiche_h3_event_type(h3_event); event_type) {
    case QUICHE_H3_EVENT_HEADERS: {
        HttpHeaders headers{.version = HTTP_VER_3_0};
        quiche_h3_event_for_each_header(h3_event, collect_header, &headers);
        log_upstream(this, dbg, "[SID:{}] Response: {}", stream_id, headers_to_log_str(headers));
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
            assert(this->vpn->upstream_config.timeout >= this->vpn->upstream_config.health_check_timeout);
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            if (m_health_check_info->error.code == VPN_EC_NOERROR) {
                stream_close_code = H3_NO_ERROR;
            } else {
                stream_close_code = H3_REQUEST_CANCELLED;
                // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
                this->handler.func(this->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &m_health_check_info->error);
            }
            m_health_check_info.reset();
        } else if (auto [conn_id, conn] = this->get_tcp_conn_by_stream_id(stream_id); conn == nullptr) {
            log_stream(this, stream_id, dbg, "Got stream processed event on closed connection");
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

    case QUICHE_H3_EVENT_GOAWAY:
        log_upstream(this, dbg, "Got GOAWAY");
        // session will be closed after `is_closed` returns true
        break;

    case QUICHE_H3_EVENT_DATAGRAM:
    case QUICHE_H3_EVENT_PRIORITY_UPDATE:
        log_stream(this, stream_id, warn, "Unexpected event: {}", magic_enum::enum_name(event_type));
        assert(0);
        break;
    }
}

void Http3Upstream::handle_response(uint64_t stream_id, const HttpHeaders *headers) {
    // Handle 407 (Proxy Authentication Required) on ANY stream as a fatal session error.
    // We defer the error reporting to avoid unsafe callback calls directly from handle_response.
    if (headers->status_code == HTTP_AUTH_REQUIRED_STATUS) {
        log_stream(this, stream_id, dbg, "Proxy authentication required");
        close_session_inner(VpnError{VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG});
        return;
    }

    if (m_udp_mux.get_stream_id() == stream_id) {
        m_udp_mux.handle_response(headers);
        return;
    }

    if (m_icmp_mux.get_stream_id() == stream_id) {
        m_icmp_mux.handle_response(headers);
        return;
    }

    if (is_health_check_stream(stream_id)) {
        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        if (headers->status_code != HTTP_OK_STATUS) {
            m_health_check_info->error = {VPN_EC_ERROR, "Bad response code"};
        }
        m_health_check_info->timeout_task_id.reset();
        // NOLINTEND(bugprone-unchecked-optional-access)
        return;
    }

    auto found = get_tcp_conn_by_stream_id(stream_id);
    if (found.second == nullptr) {
        log_stream(this, stream_id, dbg, "No connection for stream id={}", stream_id);
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

ssize_t Http3Upstream::read_out_h3_data(uint64_t stream_id, const uint8_t *buf, size_t cap) {
    U8View buffer = {buf, cap};
    while (!buffer.empty()) {
        ssize_t r = quiche_h3_recv_body(
                m_h3_conn.get(), m_quic_conn.get(), stream_id, (uint8_t *) buffer.data(), buffer.size());
        if (r >= 0) {
            buffer.remove_prefix(r);
        } else if (r == QUICHE_H3_ERR_DONE) {
            break;
        } else {
            log_stream(this, stream_id, dbg, "Failed to read stream data: err={}",
                    magic_enum::enum_name((quiche_h3_error) r));
            return r;
        }
    }
    return static_cast<ssize_t>(cap - buffer.size());
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

void Http3Upstream::close_session_inner(std::optional<VpnError> error) {
    if (m_in_handler) {
        m_closed = true;
        m_pending_session_error = error;
        return;
    }

    // If no explicit error provided, try to get it from QUIC peer error
    if (!error.has_value() && m_quic_conn != nullptr) {
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

    int64_t stream_id =
            quiche_h3_send_request(m_h3_conn.get(), m_quic_conn.get(), h3_headers.data(), h3_headers.size(), false);
    if (stream_id >= 0) {
        log_upstream(this, dbg, "[SID:{}] {}", stream_id, headers_to_log_str(headers));
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
            stream_id == QUICHE_H3_ERR_STREAM_BLOCKED,
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
        if (conn.flags.test(TcpConnection::TCF_ESTABLISHED) && conn.flags.test(TcpConnection::TCF_READ_ENABLED)
                && !conn.flags.test(TcpConnection::TCF_STREAM_CLOSED)
                && (conn.has_unread_data() || quiche_conn_stream_readable(m_quic_conn.get(), conn.stream_id))) {
            this->process_pending_data(conn.stream_id);
        }

        if (conn.flags.test(TcpConnection::TCF_ESTABLISHED) && !conn.flags.test(TcpConnection::TCF_STREAM_CLOSED)
                && conn.flags.test(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES)
                && 0 < quiche_conn_stream_capacity(m_quic_conn.get(), conn.stream_id)) {
            conn.flags.reset(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
            ServerDataSentEvent event = {conn_id, std::exchange(conn.sent_bytes_to_notify, 0)};
            this->handler.func(this->handler.arg, SERVER_EVENT_DATA_SENT, &event);
        }

        i = next;
    }
}

void Http3Upstream::poll_connections() {
    poll_tcp_connections();
    if (auto stream_id = m_udp_mux.get_stream_id();
            stream_id && quiche_conn_stream_readable(m_quic_conn.get(), *stream_id)) {
        this->process_pending_data(*stream_id);
    }
    if (auto stream_id = m_icmp_mux.get_stream_id();
            stream_id && quiche_conn_stream_readable(m_quic_conn.get(), *stream_id)) {
        this->process_pending_data(*stream_id);
    }
    this->flush_pending_quic_data();
}

void Http3Upstream::retry_connect_requests() {
    auto requests = std::exchange(m_retriable_tcp_requests, {});
    while (!requests.empty()) {
        auto node = requests.extract(requests.begin());
        uint64_t conn_id = node.key();
        const RetriableTcpConnectRequest &request = node.mapped();

        auto [stream_id, is_retriable] = this->send_connect_request(&request.dst_addr, request.app_name);
        if (stream_id.has_value()) {
            TcpConnection *conn = &m_tcp_connections[conn_id];
            conn->stream_id = stream_id.value();
            m_tcp_conn_by_stream_id[stream_id.value()] = conn_id;
            continue;
        }

        if (is_retriable) {
            requests.insert(std::move(node));
            break;
        }

        ServerError error = {conn_id, {-1, "Failed to send connect request"}};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &error);
        this->clean_tcp_connection_data(conn_id);
    }

    m_retriable_tcp_requests = std::move(requests);
    this->flush_pending_quic_data();
}

void Http3Upstream::complete_read(void *arg, TaskId) {
    auto *self = (Http3Upstream *) arg;
    self->m_complete_read_task_id.release();

    for (auto i = self->m_tcp_connections.begin(); i != self->m_tcp_connections.end();) {
        auto next = std::next(i);

        const TcpConnection &conn = i->second;
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
        return (r == QUICHE_ERR_DONE) ? 0 : (int) r;
    }

    if ((size_t) r != data.size()) {
        log_upstream(self, warn, "Incomplete packet sent: {} of {} bytes", (size_t) r, data.size());
        return -1;
    }

    return 0;
}

void Http3Upstream::mux_consume_callback(ServerUpstream *, uint64_t, size_t) {
    // Nothing to do
}

void Http3Upstream::handle_sleep() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE) {
        this->flush_pending_quic_data();
    }

    log_upstream(this, dbg, "Done");
}

void Http3Upstream::handle_wake() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE) {
        this->flush_pending_quic_data(); // Force timeout check
    }

    log_upstream(this, dbg, "Done");
}

// NOLINTBEGIN(bugprone-unchecked-optional-access)
bool ag::Http3Upstream::continue_connecting() {
    assert(m_quic_connector);

    auto result = quic_connector_get_result(m_quic_connector.get());
    assert(result);

    m_quic_conn = std::move(result->conn);

    SSL_CTX_set_verify(SSL_get_SSL_CTX(result->ssl), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(SSL_get_SSL_CTX(result->ssl), verify_callback, this);
    m_ssl_object = result->ssl;

    UdpSocketParameters params = {
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {socket_handler, this},
            .timeout = this->vpn->upstream_config.timeout,
            .peer = SocketAddress(this->vpn->upstream_config.endpoint->address),
            .socket_manager = this->vpn->parameters.network_manager->socket,
            .log_prefix = quic_connector_get_log_prefix(m_quic_connector.get()),
    };
    m_socket.reset(udp_socket_acquire_fd(&params, result->fd));
    if (!m_socket) {
        log_upstream(this, err, "Failed to acquire UDP socket fd");
        return false;
    }

    SocketAddress local_address = local_socket_address_from_fd(udp_socket_get_fd(m_socket.get()));
    quiche_recv_info info{
            .from = (sockaddr *) &this->vpn->upstream_config.endpoint->address,
            .from_len = SocketAddress(this->vpn->upstream_config.endpoint->address).c_socklen(),
            .to = (sockaddr *) local_address.c_sockaddr(),
            .to_len = local_address.c_socklen(),
    };

    ssize_t ret = quiche_conn_recv(m_quic_conn.get(), result->data.data(), result->data.size(), &info);
    if (ret < 0) {
        log_upstream(this, dbg, "quiche_conn_recv: ({}) {}", ret, magic_enum::enum_name((quiche_error) ret));
    }
    if (quiche_conn_is_closed(m_quic_conn.get())) {
        log_upstream(this, dbg, "QUIC connection closed");
        return false;
    }

    m_quic_connector.reset();

    return true;
}
// NOLINTEND(bugprone-unchecked-optional-access)

int Http3Upstream::kex_group_nid() const {
    return m_kex_group_nid;
}
