#include "http3_upstream.h"

#include <algorithm>
#include <cstdlib>
#include <unordered_set>

#include <magic_enum/magic_enum.hpp>
#include <openssl/rand.h>

#include "common/http/http3.h"
#include "net/http_session.h"
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

    // Let the connection live long enough to perform a health check.
    m_max_idle_timeout = 2 * (upstream_config.timeout + upstream_config.health_check_timeout);
    m_h3_settings.max_idle_timeout = Micros{m_max_idle_timeout};

    // Handoff — reuse connection pre-established by ping
    if (this->vpn->quic_connector.client) {
        m_h3_client = std::move(this->vpn->quic_connector.client);
        m_ssl_object = m_h3_client->get_ssl(); // non-owning; Http3Client owns SSL

        UdpSocketParameters params{
                .ev_loop = this->vpn->parameters.ev_loop,
                .handler = {socket_handler, this},
                .timeout = upstream_config.timeout,
                .peer = SocketAddress(upstream_config.endpoint->address),
                .socket_manager = this->vpn->parameters.network_manager->socket,
                .log_prefix = AG_FMT("h3-upstream-{}", this->id),
        };
        m_socket.reset(udp_socket_acquire_fd(&params, this->vpn->quic_connector.fd));
        this->vpn->quic_connector.fd = EVUTIL_INVALID_SOCKET;
        if (!m_socket) {
            log_upstream(this, err, "Failed to acquire UDP socket fd");
            m_h3_client.reset();
            return false;
        }

        // Replace ping-phase callbacks with upstream-phase callbacks
        m_h3_client->update_callbacks(make_upstream_callbacks(this));

        m_kex_group_nid = SSL_get_negotiated_group((SSL *) m_ssl_object);
        udp_socket_set_timeout(m_socket.get(), upstream_config.timeout);
        m_state = H3US_ESTABLISHED;
        this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
        return true;
    }

    // New connection
    U8View endpoint_data{
            upstream_config.endpoint->additional_data.data, upstream_config.endpoint->additional_data.size};
    U8View client_random_data{
            upstream_config.endpoint->tls_client_random.data, upstream_config.endpoint->tls_client_random.size};
    U8View client_random_mask{upstream_config.endpoint->tls_client_random_mask.data,
            upstream_config.endpoint->tls_client_random_mask.size};
    SslPtr ssl;
    if (auto r = make_ssl(verify_callback, this, {QUIC_H3_ALPN_PROTOS, std::size(QUIC_H3_ALPN_PROTOS)},
                upstream_config.endpoint->name, /*quic*/ MSPT_NGTCP2, endpoint_data, client_random_data,
                client_random_mask);
            std::holds_alternative<SslPtr>(r)) {
        ssl = std::move(std::get<SslPtr>(r));
    } else {
        log_upstream(this, err, "{}", std::get<std::string>(r));
        return false;
    }

    UdpSocketParameters sock_params{
            .ev_loop = this->vpn->parameters.ev_loop,
            .handler = {socket_handler, this},
            .timeout = upstream_config.timeout,
            .peer = SocketAddress(upstream_config.endpoint->address),
            .socket_manager = this->vpn->parameters.network_manager->socket,
            .log_prefix = AG_FMT("h3-upstream-{}", this->id),
    };
    m_socket.reset(udp_socket_create(&sock_params));
    if (!m_socket) {
        log_upstream(this, err, "Failed to create UDP socket");
        return false;
    }

    SSL *ssl_raw = ssl.get(); // save non-owning pointer before move into Http3Client
    SocketAddress local = local_socket_address_from_fd(udp_socket_get_fd(m_socket.get()));
    SocketAddress peer(upstream_config.endpoint->address);
    http::QuicNetworkPath path{
            .local = local.c_sockaddr(), .local_len = local.c_socklen(),
            .remote = peer.c_sockaddr(), .remote_len = peer.c_socklen(),
    };

    auto result = http::Http3Client::connect(m_h3_settings, make_upstream_callbacks(this), path, std::move(ssl));
    if (!result.has_value()) {
        log_upstream(this, err, "Failed to create Http3Client: {}", result.error()->str());
        m_socket.reset();
        return false;
    }
    m_h3_client = std::move(result.value());
    m_ssl_object = ssl_raw; // non-owning, for kex_group_nid() and SSL_session_reused

    if (auto err = m_h3_client->flush(); err != nullptr) {
        log_upstream(this, err, "Failed to flush initial QUIC packets: {}", err->str());
        m_h3_client.reset();
        m_socket.reset();
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

    m_ssl_object = nullptr;
    m_udp_mux.close({});
    m_icmp_mux.close();
    m_h3_client.reset();
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
        if (auto err = m_h3_client->submit_body(conn->stream_id, {data, length}, false); err != nullptr) {
            log_conn(this, id, dbg, "Failed to send data: {}", err->str());
            r = -1;
        } else {
            r = (ssize_t) length;
            conn->sent_bytes_to_notify += length;
            conn->window_remaining -= std::min(length, conn->window_remaining);
            conn->flags.set(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
            m_h3_client->flush();
        }
    } else if (m_udp_mux.check_connection(id)) {
        r = m_udp_mux.send(id, {data, length});
    } else {
        log_conn(this, id, err, "Trying to send data on already closed or nonexistent connection");
        r = -1;
    }

    return (int) r;
}

void Http3Upstream::consume(uint64_t, size_t) {
}

size_t Http3Upstream::available_to_send(uint64_t id) {
    // UDP/ICMP mux: a single stream, always return a large value
    if (m_udp_mux.check_connection(id)) {
        return http::Http3Settings::DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL;
    }

    if (auto it = m_tcp_connections.find(id); it != m_tcp_connections.end()) {
        if (it->second.window_remaining == 0) {
            // Mark: notify caller when the window opens (via on_window_update → poll_tcp_connections)
            it->second.flags.set(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
        }
        return it->second.window_remaining;
    }

    log_conn(this, id, dbg, "Trying to get window size on closed or nonexistent connection");
    return 0;
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
            && conn->has_unread_data()) {
        // we have some unread data on the connection - complete it
        m_complete_read_task_id = event_loop::submit(vpn->parameters.ev_loop, {this, complete_read});
    }
}

void Http3Upstream::do_health_check() {
    m_health_check_info.reset(); // Forget about the current health check.

    // FIXME: AG-8909
    if (!m_h3_client || m_state != H3US_ESTABLISHED) {
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
    if (!m_h3_client) {
        return {};
    }
    auto info = m_h3_client->get_stats();
    return {
        .rtt_us = uint32_t(info.smoothed_rtt / 1000), // nanoseconds → microseconds
        .packet_loss_ratio = (info.pkt_sent > 0)
                ? static_cast<double>(info.pkt_lost) / static_cast<double>(info.pkt_sent)
                : 0.0,
    };
}

void Http3Upstream::on_icmp_request(IcmpEchoRequestEvent &event) {
    event.result = m_icmp_mux.send_request(event.request) ? 0 : -1;
    if (m_h3_client) {
        m_h3_client->flush();
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

    case UDP_SOCKET_EVENT_READABLE: {
        if (!upstream->m_h3_client) {
            break;
        }

        constexpr size_t READ_BUDGET = 64;
        uint8_t buf[NGTCP2_DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE];
        SocketAddress local = local_socket_address_from_fd(udp_socket_get_fd(upstream->m_socket.get()));
        SocketAddress peer(upstream->vpn->upstream_config.endpoint->address);
        http::QuicNetworkPath path{
            .local = local.c_sockaddr(), .local_len = local.c_socklen(),
            .remote = peer.c_sockaddr(), .remote_len = peer.c_socklen(),
    };

        upstream->m_in_handler = true;
        for (size_t i = 0; i < READ_BUDGET; ++i) {
            ssize_t r = udp_socket_recv(upstream->m_socket.get(), buf, sizeof(buf));
            if (r <= 0) {
                if (int err = evutil_socket_geterror(udp_socket_get_fd(upstream->m_socket.get()));
                        err != 0 && !AG_ERR_IS_EAGAIN(err)) {
                    log_upstream(upstream, dbg, "Read error: {} ({})", evutil_socket_error_to_string(err), err);
                        }
                break;
            }
            log_upstream(upstream, trace, "Read {} bytes from endpoint", r);
            upstream->cancel_health_check();
            if (auto err = upstream->m_h3_client->input(path, {buf, (size_t) r}); err != nullptr) {
                log_upstream(upstream, dbg, "input() error: {}", err->str());
                break;
            }
        }
        upstream->m_in_handler = false;

        if (upstream->m_closed) {
            upstream->close_session_inner(std::exchange(upstream->m_pending_session_error, std::nullopt));
        } else if (upstream->m_h3_client) {
            upstream->m_h3_client->flush();
            // Schedule post-receive work (retry_connect_requests, poll_connections)
            if (!upstream->m_post_receive_task_id.has_value()) {
                upstream->m_post_receive_task_id = event_loop::submit(
                        upstream->vpn->parameters.ev_loop,
                        {
                                .arg = upstream,
                                .action =
                                        [](void *a, TaskId) {
                                            auto *self = (Http3Upstream *) a;
                                            self->m_post_receive_task_id.release();
                                            self->retry_connect_requests();
                                            self->poll_connections();
                                        },
                        });
            }
        }
        break;
    }

    case UDP_SOCKET_EVENT_TIMEOUT:
        if (!upstream->m_h3_client || upstream->m_state != H3US_ESTABLISHED) {
            log_upstream(upstream, dbg, "UDP socket timed out, closing session");
            upstream->close_session_inner();
        } else {
            // ACK-eliciting on idle: let ngtcp2 handle it
            upstream->m_h3_client->handle_expiry();
            upstream->m_h3_client->flush();
        }
        break;
    }
}

int Http3Upstream::verify_callback(X509_STORE_CTX *store_ctx, void *arg) {
    auto *self = (Http3Upstream *) arg;
    auto *cert = X509_STORE_CTX_get0_cert(store_ctx);
    auto *chain = X509_STORE_CTX_get0_untrusted(store_ctx);
    auto *ssl = (SSL *) X509_STORE_CTX_get_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    int ret = self->vpn->parameters.cert_verify_handler.func(
            !safe_to_string_view(self->vpn->upstream_config.endpoint->remote_id).empty()
                    ? self->vpn->upstream_config.endpoint->remote_id
                    : self->vpn->upstream_config.endpoint->name,
            (sockaddr *) &self->vpn->upstream_config.endpoint->address, {cert, chain, ssl, VT_ENDPOINT},
            self->vpn->parameters.cert_verify_handler.arg);
    self->m_cert_verify_failed = (ret != 1);
    return ret;
}

void Http3Upstream::quic_timer_callback(evutil_socket_t, short, void *arg) {
    auto *upstream = (Http3Upstream *) arg;
    log_upstream(upstream, dbg, "...");

    if (!upstream->m_h3_client) {
        return;
    }

    // Notify ngtcp2 that the timer fired, then flush
    // This may trigger on_close / on_output / on_expiry_update callbacks
    upstream->m_h3_client->handle_expiry();
    upstream->m_h3_client->flush();

    log_upstream(upstream, dbg, "Done");
}

http::Http3Client::Callbacks Http3Upstream::make_upstream_callbacks(Http3Upstream *self) {
    return {
            .arg = self,
            .on_handshake_completed = on_handshake_completed,
            .on_response = on_response,
            .on_trailer_headers = nullptr,
            .on_body = on_body,
            .on_window_update = on_window_update,
            .on_stream_read_finished = nullptr,
            .on_stream_closed = on_stream_closed,
            .on_close = on_close,
            .on_output = on_output,
            .on_data_sent = on_data_sent,
            .on_expiry_update = on_expiry_update,
            .on_available_streams = nullptr,
    };
}

// Called once after TLS handshake completes
void Http3Upstream::on_handshake_completed(void *arg) {
    auto *self = (Http3Upstream *) arg;
    log_upstream(self, dbg, "Handshake completed");

    if (self->m_ssl_object) {
        self->m_kex_group_nid = SSL_get_negotiated_group((SSL *) self->m_ssl_object);
        if (self->m_log.is_enabled(LOG_LEVEL_DEBUG)) {
            log_upstream(self, dbg, "Session reused: {}", SSL_session_reused((SSL *) self->m_ssl_object));
        }
    }

    // Prevent idle close — send ACK-eliciting packets on idle
    udp_socket_set_timeout(self->m_socket.get(), self->vpn->upstream_config.timeout);

    self->m_state = H3US_ESTABLISHED;
    self->handler.func(self->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
}

// Called when a response is received on a stream
void Http3Upstream::on_response(void *arg, uint64_t stream_id, http::Response response) {
    auto *self = (Http3Upstream *) arg;
    HttpHeaders headers{.version = HTTP_VER_3_0, .status_code = response.status_code()};
    for (const auto &h : response.headers()) {
        headers.fields.push_back({std::string(h.name), std::string(h.value)});
    }
    self->handle_response(stream_id, &headers);
}

// Called when body data arrives on a stream. Data is pushed by Http3Client
void Http3Upstream::on_body(void *arg, uint64_t stream_id, Uint8View chunk) {
    auto *self = (Http3Upstream *) arg;
    if (self->m_udp_mux.get_stream_id() == stream_id) {
        self->m_udp_mux.process_read_event(chunk);
        self->m_h3_client->consume_stream(stream_id, chunk.size());
        return;
    }

    if (self->m_icmp_mux.get_stream_id() == stream_id) {
        self->m_icmp_mux.process_read_event(chunk);
        self->m_h3_client->consume_stream(stream_id, chunk.size());
        return;
    }

    if (self->is_health_check_stream(stream_id)) {
        log_stream(self, stream_id, dbg, "Got data on health check stream, dropping");
        self->m_h3_client->consume_stream(stream_id, chunk.size());
        return;
    }

    auto [conn_id, conn] = self->get_tcp_conn_by_stream_id(stream_id);
    if (conn == nullptr) {
        log_stream(self, stream_id, dbg, "Got body on closed connection");
        self->m_h3_client->consume_stream(stream_id, chunk.size());
        return;
    }

    if (conn->flags.test(TcpConnection::TCF_READ_ENABLED) && !conn->has_unread_data()) {
        // Try to forward directly without buffering
        int r = self->raise_read_event(conn_id, chunk);
        if (r < 0) {
            self->close_tcp_connection(conn_id, false);
            self->m_h3_client->consume_stream(stream_id, chunk.size());
            return;
        }
        chunk.remove_prefix(r);
        if (r > 0) {
            self->m_h3_client->consume_stream(stream_id, r);
        }
    }

    if (!chunk.empty()) {
        // Buffer the remainder; consume_stream will be called as data is drained
        self->push_unread_data(conn_id, conn, chunk);
        return;
    }
}

// Called when a stream is closed (FIN or RST)
void Http3Upstream::on_stream_closed(void *arg, uint64_t stream_id, int error_code) {
    auto *self = (Http3Upstream *) arg;
    log_stream(self, stream_id, dbg, "Stream closed, error_code={}", error_code);

    Http3ErrorCode stream_close_code = H3_REQUEST_CANCELLED;
    if (self->m_udp_mux.get_stream_id() == stream_id) {
        self->m_udp_mux.close({});
    } else if (self->m_icmp_mux.get_stream_id() == stream_id) {
        self->m_icmp_mux.close();
    } else if (self->is_health_check_stream(stream_id)) {
        assert(self->vpn->upstream_config.timeout >= self->vpn->upstream_config.health_check_timeout);
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        if (self->m_health_check_info->error.code == VPN_EC_NOERROR) {
            stream_close_code = H3_NO_ERROR;
        } else {
            // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
            self->handler.func(self->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &self->m_health_check_info->error);
        }
        self->m_health_check_info.reset();
    } else if (auto [conn_id, conn] = self->get_tcp_conn_by_stream_id(stream_id); conn == nullptr) {
        log_stream(self, stream_id, dbg, "Got stream close on already-closed connection");
    } else if (conn->pending_error.has_value()) {
        self->handler.func(self->handler.arg, SERVER_EVENT_ERROR, &conn->pending_error.value());
        self->clean_tcp_connection_data(conn_id);
    } else if (!conn->has_unread_data()) {
        self->handler.func(self->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &conn_id);
        self->clean_tcp_connection_data(conn_id);
    } else {
        // Postpone close until all buffered data is forwarded to client
        conn->flags.set(TcpConnection::TCF_STREAM_CLOSED);
        return;
    }

    if (auto [_, conn] = self->get_tcp_conn_by_stream_id(stream_id); conn != nullptr) {
        conn->flags.set(TcpConnection::TCF_STREAM_CLOSED);
    }
    (void) stream_close_code; // used by the caller of close_stream, not here
}

// Called when the QUIC connection is closed
void Http3Upstream::on_close(void *arg, uint64_t error_code) {
    auto *self = (Http3Upstream *) arg;
    log_upstream(self, dbg, "Connection closed, error_code={}", error_code);

    std::optional<VpnError> error;
    std::string err_str;
    if (error_code != 0) {
        if (error_code == HTTP_ERROR_AUTH_REQUIRED) {
            error = VpnError{VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG};
        } else {
            err_str = AG_FMT("QUIC connection closed with error {}", error_code);
            error = VpnError{VPN_EC_ERROR, err_str.c_str()};
        }
    }
    self->close_session_inner(error);
}

// Called when Http3Client wants to send a UDP packet
void Http3Upstream::on_output(void *arg, const http::QuicNetworkPath &, Uint8View chunk) {
    auto *self = (Http3Upstream *) arg;
    if (!self->m_socket) {
        return;
    }

    if (VpnError err = udp_socket_write(self->m_socket.get(), chunk.data(), chunk.size()); err.code != 0) {
        log_upstream(self, dbg, "Failed to send QUIC packet: {} ({})", safe_to_string_view(err.text), err.code);
        if (!AG_ERR_IS_EAGAIN(err.code) && err.code != AG_ENOBUFS
                && !self->m_flush_error_task_id.has_value()) {
            self->m_flush_error_task_id = event_loop::submit(self->vpn->parameters.ev_loop,
                    {
                            self,
                            [](void *a, TaskId) {
                                auto *s = (Http3Upstream *) a;
                                s->m_flush_error_task_id.release();
                                ServerError event = {NON_ID, {VPN_EC_ERROR, "UDP socket failure"}};
                                s->handler.func(s->handler.arg, SERVER_EVENT_ERROR, &event);
                            },
                    });
        }
    }
}

// Called when data has been put into QUIC packets. Used to schedule SERVER_EVENT_DATA_SENT
void Http3Upstream::on_data_sent(void *arg, uint64_t /*stream_id*/, size_t /*n*/) {
    auto *self = (Http3Upstream *) arg;
    if (!self->m_notify_sent_task_id.has_value()) {
        self->m_notify_sent_task_id = event_loop::submit(self->vpn->parameters.ev_loop,
                {
                        self,
                        [](void *a, TaskId) {
                            auto *s = (Http3Upstream *) a;
                            s->m_notify_sent_task_id.release();
                            s->poll_tcp_connections();
                        },
                });
    }
}

// Called when the ngtcp2 timer deadline changes
void Http3Upstream::on_expiry_update(void *arg, Nanos period) {
    auto *self = (Http3Upstream *) arg;
    if (!self->m_quic_timer) {
        self->m_quic_timer.reset(event_new(
                vpn_event_loop_get_base(self->vpn->parameters.ev_loop), -1, 0, quic_timer_callback, self));
    }
    uint64_t timeout_ms = uint64_t(duration_cast<milliseconds>(period).count());
    // Cap by our own idle timeout so we don't let the connection silently die
    timeout_ms = std::min(timeout_ms, uint64_t(duration_cast<milliseconds>(self->m_max_idle_timeout).count()));
    const timeval tv = ms_to_timeval(uint32_t(timeout_ms));
    event_del(self->m_quic_timer.get());
    event_add(self->m_quic_timer.get(), &tv);
}

// Called when the server extends the send window for a stream (MAX_STREAM_DATA frame received)
// n = additional bytes made available
void Http3Upstream::on_window_update(void *arg, uint64_t stream_id, size_t n) {
    auto *self = (Http3Upstream *) arg;
    auto [conn_id, conn] = self->get_tcp_conn_by_stream_id(stream_id);
    if (conn == nullptr) {
        return;
    }

    conn->window_remaining += n;

    // Schedule SERVER_EVENT_DATA_SENT if the window was previously exhausted
    if (conn->flags.test(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES)
            && !self->m_notify_sent_task_id.has_value()) {
        self->m_notify_sent_task_id = event_loop::submit(self->vpn->parameters.ev_loop,
                {
                        self,
                        [](void *a, TaskId) {
                            auto *s = (Http3Upstream *) a;
                            s->m_notify_sent_task_id.release();
                            s->poll_tcp_connections();
                        },
                });
    }
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
    if (!m_h3_client) {
        log_stream(this, stream_id, trace, "Nothing to do: no H3 client");
        return;
    }
    if (auto error = m_h3_client->reset_stream(stream_id, (int) err); error != nullptr) {
        log_stream(this, stream_id, dbg, "Failed to reset stream: {}", error->str());
    }
    if (auto [_, conn] = this->get_tcp_conn_by_stream_id(stream_id); conn != nullptr) {
        conn->flags.set(TcpConnection::TCF_STREAM_CLOSED);
    }
    // NOTE: caller is responsible for calling flush() after close_stream()
}

void Http3Upstream::process_pending_data(uint64_t stream_id) {
    auto [conn_id, conn] = this->get_tcp_conn_by_stream_id(stream_id);
    if (conn == nullptr) {
        return;
    }

    if (0 != this->read_out_pending_data(conn_id, conn)) {
        this->close_tcp_connection(conn_id, false);
        return;
    }

    if (conn->flags.test(TcpConnection::TCF_STREAM_CLOSED) && !conn->has_unread_data()) {
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &conn_id);
        this->clean_tcp_connection_data(conn_id);
    }
}

void Http3Upstream::close_session_inner(std::optional<VpnError> error) {
    if (m_in_handler) {
        m_closed = true;
        m_pending_session_error = error;
        return;
    }

    if (!error.has_value() && m_cert_verify_failed) {
        log_upstream(this, dbg, "TLS certificate verification failed");
        error = {VPN_EC_CERTIFICATE_VERIFICATION_FAILED, "TLS certificate verification failed"};
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
    if (!m_h3_client || m_state != H3US_ESTABLISHED) {
        log_upstream(this, dbg, "Failed to send connect request: upstream is not connected");
        return {std::nullopt, false};
    }

    HttpHeaders headers = make_http_connect_request(HTTP_VER_3_0, dst_addr, app_name, m_credentials);
    http::Request request(http::HTTP_3_0);
    request.method(std::string(headers.method));        // "CONNECT"
    request.authority(std::string(headers.authority));  // "host:port"
    for (const auto &field : headers.fields) {
        request.headers().put(field.name, field.value); // proxy-authorization, user-agent
    }

    log_upstream(this, dbg, "{}", request.str());

    auto stream_id_result = m_h3_client->submit_request(request, /*eof=*/false);
    if (!stream_id_result.has_value()) {
        log_upstream(this, dbg, "Failed to send connect request: {}",
                stream_id_result.error()->str());
        // Treat as retriable — the stream limit may not be exhausted yet
        return {std::nullopt, true};
    }

    m_h3_client->flush();
    return {std::make_optional(stream_id_result.value()), false};
}

void Http3Upstream::close_tcp_connection(uint64_t id, bool graceful) {
    log_conn(this, id, dbg, "Closing");

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        const TcpConnection *conn = &i->second;
        if (m_h3_client && !conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
            this->close_stream(i->second.stream_id, graceful ? H3_NO_ERROR : H3_REQUEST_CANCELLED);
            m_h3_client->flush();
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
            // Tell server it can now send r more bytes on this stream
            if (m_h3_client) {
                m_h3_client->consume_stream(conn->stream_id, r);
            }
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
                && conn.has_unread_data()) {
            this->process_pending_data(conn.stream_id);
        }

        if (conn.flags.test(TcpConnection::TCF_ESTABLISHED) && !conn.flags.test(TcpConnection::TCF_STREAM_CLOSED)
                && conn.flags.test(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES)
                && conn.window_remaining > 0) {
            conn.flags.reset(TcpConnection::TCF_NEED_NOTIFY_SENT_BYTES);
            ServerDataSentEvent event = {conn_id, std::exchange(conn.sent_bytes_to_notify, 0)};
            this->handler.func(this->handler.arg, SERVER_EVENT_DATA_SENT, &event);
        }

        i = next;
    }
}

void Http3Upstream::poll_connections() {
    poll_tcp_connections();
    if (m_h3_client) {
        m_h3_client->flush();
    }
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
    if (m_h3_client) {
        m_h3_client->flush();
    }
}

void Http3Upstream::complete_read(void *arg, TaskId) {
    auto *self = (Http3Upstream *) arg;
    self->m_complete_read_task_id.release();

    for (auto i = self->m_tcp_connections.begin(); i != self->m_tcp_connections.end();) {
        auto next = std::next(i);

        const TcpConnection &conn = i->second;
        if (conn.has_unread_data()) {
            self->process_pending_data(conn.stream_id);
        }
        i = next;
    }

    if (self->m_h3_client) {
        self->m_h3_client->flush();
    }
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

    if (!self->m_h3_client) {
        return -1;
    }

    if (auto err = self->m_h3_client->submit_body(stream_id, data, false); err != nullptr) {
        log_upstream(self, dbg, "Failed to send packet on {} stream: {}",
                stream_id == self->m_udp_mux.get_stream_id() ? "UDP" : "ICMP", err->str());
        return -1;
    }

    return 0;
}

void Http3Upstream::mux_consume_callback(ServerUpstream *, uint64_t, size_t) {
    // Nothing to do
}

void Http3Upstream::handle_sleep() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE && m_h3_client) {
        m_h3_client->flush();
    }

    log_upstream(this, dbg, "Done");
}

void Http3Upstream::handle_wake() {
    log_upstream(this, dbg, "...");

    if (m_state != H3US_IDLE && m_h3_client) {
        m_h3_client->flush();
    }

    log_upstream(this, dbg, "Done");
}

int Http3Upstream::kex_group_nid() const {
    return m_kex_group_nid;
}
