#include "http2_upstream.h"

#include <cassert>
#include <string_view>
#include <vector>

#include <event2/util.h>
#include <nghttp2/nghttp2.h>

#include "common/net_utils.h"
#include "common/socket_address.h"
#include "net/tls.h"
#include "net/utils.h"
#include "vpn/utils.h"

#define log_upstream(ups_, lvl_, fmt_, ...) lvl_##log((ups_)->m_log, "[{}] " fmt_, (ups_)->id, ##__VA_ARGS__)
#define log_conn(ups_, cid_, lvl_, fmt_, ...)                                                                          \
    lvl_##log((ups_)->m_log, "[{}] [R:{}] " fmt_, (ups_)->id, (uint64_t) (cid_), ##__VA_ARGS__)

using namespace std::chrono;

namespace ag {

static constexpr size_t HTTP2_STREAM_INITIAL_WINDOW_SIZE = 131072; // Chrome constant

enum Http2Upstream::TcpConnection::Flag : int {
    TCF_READ_ENABLED,  // `SERVER_EVENT_READ` can be raised
    TCF_STREAM_CLOSED, // stream closed gracefully, but we're waiting until all data is sent
    TCF_CLIENT_CLOSED, // the client closed its side of the connection
};

struct CloseCtx {
    Http2Upstream *upstream;
    uint64_t id;
    bool graceful;
};

struct CompleteCtx {
    Http2Upstream *upstream;
    uint64_t id;
};

Http2Upstream::Http2Upstream(
        const VpnUpstreamProtocolConfig &protocol_config, int id, VpnClient *vpn, ServerHandler handler)
        : MultiplexableUpstream(protocol_config, id, vpn, handler)
        , m_udp_mux({this, send_connect_request_callback, send_data_callback, consume_callback})
        , m_icmp_mux({this, send_connect_request_callback, send_data_callback, consume_callback})
        , m_credentials(make_credentials(vpn->upstream_config.username, vpn->upstream_config.password)) {
#if 0
    nghttp2_set_debug_vprintf_callback([](const char *format, va_list args) {
        static Logger log{"NGH2"};
        tracelog(log, "{}", str_format(format, args));
    });
#endif
}

Http2Upstream::~Http2Upstream() {
    // reset it manually to be sure it's deleted before others
    m_session.reset();
}

int Http2Upstream::handle_read(uint64_t id, const uint8_t *data, size_t length) {
    ServerReadEvent serv_event = {id, data, length, 0};
    this->handler.func(this->handler.arg, SERVER_EVENT_READ, &serv_event);

    if (serv_event.result < 0) {
        this->close_tcp_connection(id, false);
    }

    return serv_event.result;
}

std::pair<uint64_t, Http2Upstream::TcpConnection *> Http2Upstream::get_conn_by_stream_id(uint32_t id) {
    std::pair<uint64_t, TcpConnection *> r = {NON_ID, nullptr};

    auto id_iter = m_conn_id_by_stream_id.find(id);
    if (id_iter != m_conn_id_by_stream_id.end()) {
        r.first = id_iter->second;
        auto found = m_tcp_connections.find(id_iter->second);
        if (found != m_tcp_connections.end()) {
            r.second = &found->second;
        }
    }

    return r;
}

void Http2Upstream::handle_response(const HttpHeadersEvent *http_event) {
    ServerHandler *handler = &this->handler;

    uint32_t stream_id = http_event->stream_id;
    if (stream_id == m_udp_mux.get_stream_id()) {
        m_udp_mux.handle_response(http_event->headers);
    } else if (stream_id == m_icmp_mux.get_stream_id()) {
        m_icmp_mux.handle_response(http_event->headers);
    } else if (m_health_check_info.has_value() && m_health_check_info->stream_id == stream_id) {
        if (http_event->headers->status_code == HTTP_AUTH_REQUIRED_STATUS) {
            m_health_check_info->error = {VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG};
        } else if (http_event->headers->status_code != HTTP_OK_STATUS) {
            m_health_check_info->error = {VPN_EC_ERROR, "Bad response code"};
        }
    } else {
        auto found = get_conn_by_stream_id(stream_id);

        if (found.second == nullptr) {
            log_upstream(this, dbg, "No connection for stream id={}", stream_id);
            m_streams_to_reset.push_back(stream_id);
            return;
        }

        if (http_event->headers->status_code == HTTP_STATUS_200_OK) {
            handler->func(handler->arg, SERVER_EVENT_CONNECTION_OPENED, &found.first);
        } else {
            TcpConnection *conn = found.second;
            conn->pending_error = {found.first, bad_http_response_to_connect_error(http_event->headers)};
        }
    }
}

int Http2Upstream::read_out_pending_data(uint64_t id, TcpConnection *conn) {
    DataBuffer *pending = conn->unread_data.get();

    while (conn->flags.test(TcpConnection::TCF_READ_ENABLED) && pending->size() > 0) {
        BufferPeekResult res = pending->peek();
        if (res.err.has_value()) {
            log_conn(this, id, err, "Failed to read buffered data: {}", *res.err);
            return -1;
        }
        int r = handle_read(id, res.data.data(), res.data.size());
        if (r > 0) {
            pending->drain(r);
        } else if (r < 0) {
            return r;
        }
    }

    return 0;
}

void Http2Upstream::http_handler(void *arg, HttpEventId what, void *data) {
    Http2Upstream *upstream = (Http2Upstream *) arg;

    switch (what) {
    case HTTP_EVENT_HEADERS: {
        const HttpHeadersEvent *http_event = (HttpHeadersEvent *) data;
        log_upstream(upstream, dbg, "[SID:{}] Response: {}", http_event->stream_id,
                headers_to_log_str(*http_event->headers));
        upstream->handle_response(http_event);
        break;
    }
    case HTTP_EVENT_DATA: {
        HttpDataEvent *http_event = (HttpDataEvent *) data;

        if ((uint32_t) http_event->stream_id == upstream->m_udp_mux.get_stream_id()) {
            http_event->result = upstream->m_udp_mux.process_read_event({http_event->data, http_event->length});
            break;
        }

        if ((uint32_t) http_event->stream_id == upstream->m_icmp_mux.get_stream_id()) {
            http_event->result = upstream->m_icmp_mux.process_read_event({http_event->data, http_event->length});
            break;
        }

        auto found = upstream->get_conn_by_stream_id(http_event->stream_id);
        if (found.second == nullptr) {
            log_upstream(upstream, dbg, "Got data on closed connection: stream={}", http_event->stream_id);
            assert(0);
            break;
        }

        http_event->result = 0;
        TcpConnection *conn = found.second;
        DataBuffer *pending = conn->unread_data.get();
        if (pending != nullptr) {
            http_event->result = upstream->read_out_pending_data(found.first, conn);
        }

        if (http_event->result < 0) {
            break;
        }

        http_event->result = 0;
        if (conn->flags.test(TcpConnection::TCF_READ_ENABLED)) {
            assert(pending == nullptr || pending->size() == 0);
            http_event->result = upstream->handle_read(found.first, http_event->data, http_event->length);
        }

        if (http_event->result >= 0) {
            if ((size_t) http_event->result < http_event->length) {
                const uint8_t *unread = http_event->data + http_event->result;
                size_t size = http_event->length - http_event->result;

                if (pending == nullptr) {
                    conn->unread_data = upstream->vpn->make_buffer(found.first);
                    pending = conn->unread_data.get();
                    if (std::optional<std::string> err = pending->init(); err.has_value()) {
                        log_conn(upstream, found.first, err, "Failed to initialize data buffer: {}", *err);
                        http_event->result = -1;
                        break;
                    }
                }

                // FIXME: this buffer grows too large for comfort:
                // 2..3 MB on a connection through which a high-speed download is happening.
                // Maybe we could do something about it?
                std::optional<std::string> err = pending->push({unread, size});
                if (err.has_value()) {
                    log_conn(upstream, found.first, err, "Failed to put data (size={}) in buffer: {}", size, *err);
                    http_event->result = -1;
                }
            }
            http_event->result = std::min(http_event->result, 0);
        }

        break;
    }
    case HTTP_EVENT_DATA_FINISHED: {
        // endpoint may send a couple of RST frames in response
        http_session_send_data(upstream->m_session.get(), (int32_t) *(uint32_t *) data, nullptr, 0, true);
        break;
    }
    case HTTP_EVENT_STREAM_PROCESSED: {
        const HttpStreamProcessedEvent *http_event = (HttpStreamProcessedEvent *) data;

        uint32_t stream_id = http_event->stream_id;
        if (stream_id == upstream->m_udp_mux.get_stream_id()) {
            ServerError serv_err = {0, {http_event->error_code, nghttp2_http2_strerror(http_event->error_code)}};
            upstream->m_udp_mux.close(serv_err);
        } else if (stream_id == upstream->m_icmp_mux.get_stream_id()) {
            log_upstream(upstream, dbg, "ICMP multiplexer stream has been closed: {} ({})",
                    nghttp2_http2_strerror(http_event->error_code), http_event->error_code);
            upstream->m_icmp_mux.close();
        } else if (upstream->m_health_check_info.has_value() && upstream->m_health_check_info->stream_id == stream_id) {
            if (upstream->m_closing) {
                upstream->m_health_check_info.reset();
                log_upstream(upstream, dbg, "Drop health check result while closing session");
                break;
            }

            // Save the error and reset health_check_info now: handler may request a new health check.
            VpnError hc_error = upstream->m_health_check_info->error;
            bool need_hc_result = upstream->m_health_check_info->need_result;
            upstream->m_health_check_info.reset(); // Also resets the health check timeout task.

            if (hc_error.code == 0 && http_event->error_code != NGHTTP2_NO_ERROR) {
                hc_error = {VPN_EC_ERROR, nghttp2_http2_strerror(http_event->error_code)};
            }

            if (hc_error.code != 0) {
                upstream->report_health_check_error(need_hc_result, hc_error);
            }
        } else {
            auto found = upstream->get_conn_by_stream_id(stream_id);
            if (found.second == nullptr) {
                log_upstream(upstream, dbg, "Got stream processed event on closed connection: stream={}: {} ({})",
                        stream_id, nghttp2_http2_strerror(http_event->error_code), http_event->error_code);
                break;
            }

            TcpConnection *conn = found.second;
            conn->flags.set(TcpConnection::TCF_STREAM_CLOSED);

            std::optional<ServerError> err_event = conn->pending_error;
            if (!err_event.has_value() && http_event->error_code != NGHTTP2_NO_ERROR) {
                err_event = {found.first, {ag::utils::AG_ECONNREFUSED, nghttp2_http2_strerror(http_event->error_code)}};
            }

            if (err_event.has_value()) {
                upstream->handler.func(upstream->handler.arg, SERVER_EVENT_ERROR, &err_event.value());
                upstream->clean_tcp_connection_data(found.first);
            } else if (conn->flags.test(TcpConnection::TCF_CLIENT_CLOSED) || conn->unread_data == nullptr
                    || conn->unread_data->size() == 0) {
                upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &found.first);
                upstream->clean_tcp_connection_data(found.first);
            } // else postpone until all data is sent to client
        }

        break;
    }
    case HTTP_EVENT_DATA_SENT: {
        const HttpDataSentEvent *http_event = (HttpDataSentEvent *) data;

        // for udp it will be reported in socket write buffer flushed event
        if ((uint32_t) http_event->stream_id != upstream->m_udp_mux.get_stream_id()) {
            auto found = upstream->get_conn_by_stream_id(http_event->stream_id);
            if (found.second != nullptr) {
                ServerDataSentEvent serv_event = {found.first, http_event->length};
                upstream->handler.func(upstream->handler.arg, SERVER_EVENT_DATA_SENT, &serv_event);
            }
        }

        break;
    }
    case HTTP_EVENT_GOAWAY: {
        const HttpGoawayEvent *http_event = (HttpGoawayEvent *) data;
        log_upstream(upstream, dbg, "HTTP_EVENT_GOAWAY {}", http_event->error_code);

        std::optional<VpnError> error;
        if (http_event->error_code != NGHTTP2_NO_ERROR) {
            switch (http_event->error_code) {
            case HTTP_ERROR_AUTH_REQUIRED:
                error = {VPN_EC_AUTH_REQUIRED, HTTP_AUTH_REQUIRED_MSG};
                break;
            default:
                error = {VPN_EC_ERROR, nghttp2_http2_strerror(http_event->error_code)};
                break;
            }
        }

        upstream->close_session_inner(error);

        break;
    }
    case HTTP_EVENT_OUTPUT: {
        const HttpOutputEvent *http_event = (HttpOutputEvent *) data;
        log_upstream(upstream, trace, "Sending {} bytes to server", http_event->length);

        VpnError error = tcp_socket_write(upstream->m_socket.get(), http_event->data, http_event->length);
        if (error.code != 0) {
            upstream->close_session_inner(VpnError{VPN_EC_ERROR, error.text});
        }
        break;
    }
    }
}

int Http2Upstream::establish_http_session() {
    assert(m_session == nullptr);

    HttpSessionParams params = {
            uint64_t(this->id), {http_handler, this}, HTTP2_STREAM_INITIAL_WINDOW_SIZE, HTTP_VER_2_0};
    m_session.reset(http_session_open(&params));

    int r = 0;
    if (m_session != nullptr && 0 != (r = http_session_send_settings(m_session.get()))) {
        if (r < 0) {
            log_upstream(this, err, "Failed to start HTTP session with endpoint: {}", nghttp2_strerror(r));
        } else {
            log_upstream(this, err, "Failed to start HTTP session with endpoint");
        }
    }
    return r == 0;
}

void Http2Upstream::net_handler(void *arg, TcpSocketEvent what, void *data) {
    Http2Upstream *upstream = (Http2Upstream *) arg;

    // Bufferevent writes can synchronously raise flush events while writing in socket,
    // so a boolean flag is not enough here.
    upstream->m_in_handler += 1;

    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED: {
        tcp_socket_set_timeout(upstream->m_socket.get(), Millis{});

        if (auto alpn = tcp_socket_get_selected_alpn(upstream->m_socket.get()); alpn != "h2") {
            log_upstream(upstream, dbg, "Unexpected protocol is selected by server: {}", alpn);
            upstream->close_session_inner(VpnError{VPN_EC_ERROR, "Unexpected protocol"});
            break;
        }

        log_upstream(upstream, dbg, "Established TCP connection to endpoint successfully");
        if (upstream->establish_http_session()) {
            tcp_socket_set_read_enabled(upstream->m_socket.get(), true);
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
        } else {
            upstream->close_session_inner(VpnError{VPN_EC_ERROR, "Failed to initiate HTTP2 session"});
        }

        break;
    }
    case TCP_SOCKET_EVENT_READABLE: {
        constexpr size_t READ_BUDGET = 64;
        TcpSocket *socket = upstream->m_socket.get();
        for (size_t i = 0; i < READ_BUDGET && tcp_socket_is_read_enabled(socket); ++i) {
            tcp_socket::PeekResult result = tcp_socket_peek(socket);
            if (std::holds_alternative<tcp_socket::NoData>(result)) {
                break;
            }

            if (std::holds_alternative<tcp_socket::Eof>(result)) {
                log_upstream(upstream, dbg, "Got EOF from endpoint");
                upstream->close_session_inner(std::nullopt);
                break;
            }

            U8View chunk = std::get<tcp_socket::Chunk>(result);
            log_upstream(upstream, trace, "Got {} bytes from endpoint", chunk.size());
            int r = http_session_input(upstream->m_session.get(), chunk.data(), chunk.size());
            if (r <= 0) {
                upstream->m_streams_to_reset.clear();
                log_upstream(
                        upstream, warn, "Failed to process HTTP data from server: {} ({})", nghttp2_strerror(r), r);
                upstream->close_session_inner(VpnError{VPN_EC_ERROR, nghttp2_strerror(r)});
                break;
            }

            // Data receival indicates that the connection is alive.
            // Cancelling the health check now should reduce the probability
            // of bogus health check failures due to a slow remote.
            upstream->cancel_health_check();

            for (uint32_t stream_id : upstream->m_streams_to_reset) {
                http_session_reset_stream(upstream->m_session.get(), (int32_t) stream_id, NGHTTP2_CANCEL);
            }
            upstream->m_streams_to_reset.clear();

            if (!tcp_socket_drain(socket, r)) {
                VpnError err = {VPN_EC_ERROR, "Couldn't drain data from socket buffer"};
                upstream->close_session_inner(err);
                break;
            }
        }
        break;
    }
    case TCP_SOCKET_EVENT_ERROR: {
        const VpnError *sock_event = (VpnError *) data;

        log_upstream(upstream, dbg, "Error on HTTP session socket: {} ({})", sock_event->text, sock_event->code);
        upstream->close_session_inner(VpnError{VPN_EC_ERROR, sock_event->text});

        break;
    }
    case TCP_SOCKET_EVENT_SENT: {
        // do nothing
        break;
    }
    case TCP_SOCKET_EVENT_WRITE_FLUSH: {
        log_upstream(upstream, trace, "Write buffer flushed");

        for (auto &[id, _] : upstream->m_tcp_connections) {
            ServerDataSentEvent serv_event = {id, 0};
            upstream->handler.func(upstream->handler.arg, SERVER_EVENT_DATA_SENT, &serv_event);
        }

        if (std::optional stream_id = upstream->m_udp_mux.get_stream_id(); stream_id.has_value()
                && 0 < http_session_available_to_write(
                           upstream->m_session.get(), static_cast<int32_t>(stream_id.value()))) {
            upstream->m_udp_mux.report_sent_bytes();
        }

        break;
    }
    case TCP_SOCKET_EVENT_PROTECT: {
        vpn_client::Handler *vpn_handler = &upstream->vpn->parameters.handler;
        vpn_handler->func(vpn_handler->arg, vpn_client::EVENT_PROTECT_SOCKET, data);
        break;
    }
    }

    upstream->m_in_handler -= 1;

    if (std::exchange(upstream->m_closed, false)) {
        upstream->close_session_inner(std::exchange(upstream->m_pending_session_error, std::nullopt));
    }
}

bool Http2Upstream::open_session(std::optional<Millis> timeout) {
    log_upstream(this, trace, "...");

    const vpn_client::EndpointConnectionConfig *config = &this->vpn->upstream_config;

    TcpSocketParameters sock_params = {
            this->vpn->parameters.ev_loop,
            {net_handler, this},
            timeout.value_or(config->timeout),
            this->vpn->parameters.network_manager->socket,
            TCP_READ_THRESHOLD,
            fmt::format("h2-upstream-{}", m_id),
#ifdef _WIN32
            TCP_RECORD_ESTATS,
#endif // _WIN32
    };

    if (this->vpn->tcp_socket) {
        m_socket = std::move(this->vpn->tcp_socket);

        SSL *ssl = tcp_socket_get_ssl(m_socket.get());
        SSL_CTX_set_verify(SSL_get_SSL_CTX(ssl), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_cert_verify_callback(SSL_get_SSL_CTX(ssl), verify_callback, this);

        tcp_socket_set_rst(m_socket.get(), false);

        VpnError error = tcp_socket_connect_continue(m_socket.get(), &sock_params);
        if (error.code == 0) {
            return true;
        }
        log_upstream(this, dbg, "Failed to continue handed-off connection: ({}) {}", error.code, error.text);
    }

    m_socket.reset(tcp_socket_create(&sock_params));
    if (m_socket == nullptr) {
        log_upstream(this, err, "Failed to create socket to server");
        return false;
    }

    U8View endpoint_data{config->endpoint->additional_data.data, config->endpoint->additional_data.size};
    U8View client_random_data{config->endpoint->tls_client_random.data, config->endpoint->tls_client_random.size};
    U8View client_random_mask{
            config->endpoint->tls_client_random_mask.data, config->endpoint->tls_client_random_mask.size};
    SslPtr ssl;
    if (auto r = make_ssl(verify_callback, this, {TCP_TLS_ALPN_PROTOS, std::size(TCP_TLS_ALPN_PROTOS)},
                config->endpoint->name, /*quic*/ MSPT_TLS, endpoint_data, client_random_data, client_random_mask);
            std::holds_alternative<SslPtr>(r)) {
        ssl = std::move(std::get<SslPtr>(r));
    } else {
        log_upstream(this, err, "{}", std::get<std::string>(r));
        return false;
    }

    SocketAddress sa_peer(config->endpoint->address);
    TcpSocketConnectParameters param = {
            .peer = &sa_peer,
            .ssl = ssl.release(),
            .anti_dpi = config->anti_dpi,
    };

    VpnError error = tcp_socket_connect(m_socket.get(), &param);
    if (error.code != 0) {
        log_upstream(this, err, "Failed to connect to endpoint: {} ({})", safe_to_string_view(error.text), error.code);
        m_socket.reset();
    }

    return error.code == 0;
}

void Http2Upstream::close_session_inner(std::optional<VpnError> error) {
    if (m_in_handler > 0) {
        m_closed = true;
        m_pending_session_error = error;
        return;
    }

    close_session();

    if (error.has_value()) {
        ServerError event = {NON_ID, error.value()};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &event);
    } else {
        this->handler.func(this->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    }
}

void Http2Upstream::close_session() {
    log_upstream(this, dbg, "...");

    m_closing = true;

    std::vector<uint64_t> remaining_connections;
    remaining_connections.reserve(m_tcp_connections.size());
    std::transform(m_tcp_connections.begin(), m_tcp_connections.end(), std::back_inserter(remaining_connections),
            [](const auto &i) -> uint64_t {
                return i.first;
            });
    for (uint64_t conn_id : remaining_connections) {
        this->close_connection(conn_id, false, false);
    }

    if (std::optional<uint64_t> id = m_udp_mux.get_stream_id(); id.has_value()) {
        http_session_reset_stream(m_session.get(), (int32_t) id.value(), NGHTTP2_CANCEL);
    }

    if (std::optional<uint64_t> id = m_icmp_mux.get_stream_id(); id.has_value()) {
        http_session_reset_stream(m_session.get(), (int32_t) id.value(), NGHTTP2_CANCEL);
    }

    m_session.reset();
    m_socket.reset();
    m_tcp_connections.clear();
    m_conn_id_by_stream_id.clear();
    m_udp_mux.close({});
    m_icmp_mux.close();
    m_stream_id_generator.reset();
    m_health_check_info.reset();

    m_closing = false;

    log_upstream(this, dbg, "Done");
}

std::optional<uint32_t> Http2Upstream::send_connect_request(
        uint64_t conn_id, const TunnelAddress *dst_addr, std::string_view app_name) {
    if (m_session == nullptr) {
        log_upstream(this, dbg, "Failed to send connect request: upstream is inactive");
        return std::nullopt;
    }

    HttpHeaders headers = make_http_connect_request(HTTP_VER_2_0, dst_addr, app_name, m_credentials);
    uint32_t stream_id = m_stream_id_generator.get();
    log_upstream(this, dbg, "[R:{}][SID:{}] {}", (int64_t) conn_id, stream_id, headers_to_log_str(headers));

    int r = http_session_send_headers(m_session.get(), (int32_t) stream_id, &headers, false);
    if (r != 0) {
        log_upstream(this, dbg, "Failed to send connect request: {} ({})", nghttp2_strerror(r), r);
    }

    return (r == 0) ? std::make_optional(stream_id) : std::nullopt;
}

bool Http2Upstream::open_connection(
        uint64_t conn_id, const TunnelAddressPair *addr, int proto, std::string_view app_name) {
    bool result = true;
    if (proto == IPPROTO_UDP) {
        result = m_udp_mux.open_connection(conn_id, addr, app_name);
    } else {
        std::optional<uint32_t> stream_id = send_connect_request(conn_id, &addr->dst, app_name);
        if (stream_id.has_value()) {
            TcpConnection *conn = &m_tcp_connections[conn_id];
            conn->stream_id = stream_id.value();
            m_conn_id_by_stream_id[conn->stream_id] = conn_id;
        } else {
            result = false;
        }
    }

    return result;
}

void Http2Upstream::on_icmp_request(IcmpEchoRequestEvent &event) {
    event.result = m_icmp_mux.send_request(event.request) ? 0 : -1;
}

void Http2Upstream::close_tcp_connection(uint64_t id, bool graceful) {
    log_conn(this, id, dbg, "Closing, graceful: {}", (int) graceful);

    // FIXME: We don't currently support the notion of a half-closed TCP connection
    // (see https://datatracker.ietf.org/doc/html/rfc9293#section-3.6.1).
    // When a FIN is received from a client, the TCP/IP module immediately sends a FIN back.
    // Supporting half-closed TCP connections would entail significant changes to the
    // ClientListener, Tunnel, ServerUpstream and the VPN endpoint, but might potentially
    // unbreak some obscure applications relying on half-closed connections.

    auto i = m_tcp_connections.find(id);
    if (m_session != nullptr && i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        if (!conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
            conn->flags.set(TcpConnection::TCF_CLIENT_CLOSED);
            int err = graceful ? NGHTTP2_NO_ERROR : NGHTTP2_CANCEL;
            http_session_reset_stream(m_session.get(), (int32_t) i->second.stream_id, err);
            return; // will be cleaned up in the stream processed event
        }
        // resetting stream again won't have any effect
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, (void *) &i->first);
    }

    clean_tcp_connection_data(id);
}

void Http2Upstream::close_connection(uint64_t id, bool graceful, bool async) {
    if (m_udp_mux.check_connection(id)) {
        m_udp_mux.close_connection(id, async);
        return;
    }

    auto it = m_tcp_connections.find(id);
    if (it == m_tcp_connections.end()) {
        // @fixme: AG-9352
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
        return;
    }

    if (!async) {
        close_tcp_connection(id, graceful);
        return;
    }

    TcpConnection *conn = &it->second;
    conn->close_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
            {
                    new CloseCtx{this, id, graceful},
                    [](void *arg, TaskId task_id) {
                        CloseCtx *ctx = (CloseCtx *) arg;
                        auto *self = ctx->upstream;

                        auto i = self->m_tcp_connections.find(ctx->id);
                        if (i == self->m_tcp_connections.end()) {
                            return;
                        }

                        i->second.close_task_id.release();
                        ctx->upstream->close_tcp_connection(ctx->id, ctx->graceful);
                    },
                    [](void *arg) {
                        delete (CloseCtx *) arg;
                    },
            });
}

ssize_t Http2Upstream::send(uint64_t id, const uint8_t *data, size_t length) {
    ssize_t r = 0;

    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        if (!conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
            r = http_session_send_data(m_session.get(), (int32_t) conn->stream_id, data, length, false);
            if (r == 0) {
                r = (ssize_t) length;
            } else if (r == NGHTTP2_ERR_BUFFER_ERROR) {
                r = 0;
            }
        } else {
            log_conn(this, id, err, "Trying to send data on connection with closed stream");
            r = -1;
        }
    } else if (m_udp_mux.check_connection(id)) {
        r = m_udp_mux.send(id, {data, length});
    } else {
        log_conn(this, id, err, "Trying to send data on already closed or inexistent connection");
        r = -1;
    }

    if (r < 0) {
        log_conn(this, id, dbg, "Failed to send data from client: {} ({})", nghttp2_strerror(r), r);
    }

    return r;
}

std::optional<uint32_t> Http2Upstream::get_stream_id(uint64_t id) const {
    std::optional<uint32_t> stream_id;
    if (m_udp_mux.check_connection(id)) {
        stream_id = m_udp_mux.get_stream_id();
    } else if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        stream_id = i->second.stream_id;
    }
    return stream_id;
}

void Http2Upstream::consume(uint64_t id, size_t length) {
    log_conn(this, id, trace, "{}", length);
    if (m_udp_mux.check_connection(id)) {
        // Prevent double consuming
        log_conn(this, id, trace, "Skipping manual consumung for udp_mux connection");
        return;
    }

    std::optional<uint32_t> stream_id = get_stream_id(id);
    if (!stream_id.has_value()) {
        log_conn(this, id, dbg, "Trying to consume on closed or inexistent connection");
        return;
    }

    if (stream_id.value() == 0) {
        // connection's stream is closed
        return;
    }

    int r = http_session_data_consume(m_session.get(), (int32_t) stream_id.value(), length);
    if (r != 0) {
        log_conn(this, id, err, "Failed to consume data: {} ({})", nghttp2_strerror(r), r);
    }
}

void Http2Upstream::clean_tcp_connection_data(uint64_t id) {
    auto i = m_tcp_connections.find(id);
    if (i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        if (conn->unread_data != nullptr && conn->unread_data->size() > 0) {
            log_conn(this, id, dbg, "Remaining unread={}", conn->unread_data->size());
        }

        m_conn_id_by_stream_id.erase(conn->stream_id);
        m_tcp_connections.erase(i);

        log_upstream(
                this, dbg, "Remaining connections: {} ({})", m_tcp_connections.size(), m_conn_id_by_stream_id.size());
    }
}

size_t Http2Upstream::available_to_send(uint64_t id) {
    std::optional<uint32_t> stream_id = get_stream_id(id);
    if (!stream_id.has_value()) {
        log_conn(this, id, dbg, "Trying to get window size on closed or inexistent connection");
        return 0;
    }

    if (stream_id.value() == 0) {
        // connection's stream is closed
        return 0;
    }

    return std::min(tcp_socket_available_to_write(m_socket.get()),
            http_session_available_to_write(m_session.get(), (int32_t) stream_id.value()));
}

void Http2Upstream::complete_read(void *arg, TaskId) {
    CompleteCtx *ctx = (CompleteCtx *) arg;
    Http2Upstream *upstream = ctx->upstream;
    auto i = upstream->m_tcp_connections.find(ctx->id);
    if (i == upstream->m_tcp_connections.end()) {
        return;
    }

    TcpConnection *conn = &i->second;
    conn->complete_read_task_id.release();

    int r = upstream->read_out_pending_data(ctx->id, conn);
    if (r < 0) {
        upstream->close_tcp_connection(ctx->id, false);
    } else if (conn->unread_data->size() == 0 && conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
        upstream->handler.func(upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &ctx->id);
        upstream->clean_tcp_connection_data(ctx->id);
    }
}

int Http2Upstream::verify_callback(X509_STORE_CTX *store_ctx, void *arg) {
    auto *self = (Http2Upstream *) arg;
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

void Http2Upstream::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
    if (auto i = m_tcp_connections.find(id); i != m_tcp_connections.end()) {
        TcpConnection *conn = &i->second;
        if (conn->flags.test(TcpConnection::TCF_READ_ENABLED) != (info.send_buffer_size > 0)) {
            log_conn(this, id, trace, "Read {}", info.send_buffer_size > 0 ? "on" : "off");
            conn->flags.set(TcpConnection::TCF_READ_ENABLED, info.send_buffer_size > 0);
        }

        if (!conn->flags.test(TcpConnection::TCF_STREAM_CLOSED)) {
            int r = http_session_set_recv_window(m_session.get(), (int32_t) conn->stream_id, info.send_window_size);
            if (r != 0) {
                log_conn(this, id, err, "Failed to set window: {} ({})", nghttp2_strerror(r), r);
            }
        }

        if (conn->flags.test(TcpConnection::TCF_READ_ENABLED) && !conn->complete_read_task_id.has_value()
                && conn->unread_data != nullptr && conn->unread_data->size() > 0) {
            // we have some unread data on the connection - complete it
            conn->complete_read_task_id = event_loop::submit(vpn->parameters.ev_loop,
                    {
                            new CompleteCtx{this, id},
                            complete_read,
                            [](void *arg) {
                                delete (CompleteCtx *) arg;
                            },
                    });
        }
    } else if (m_udp_mux.check_connection(id)) {
        m_udp_mux.set_read_enabled(id, info.send_buffer_size > 0);
    }
}

size_t Http2Upstream::connections_num() const {
    return m_tcp_connections.size() + m_udp_mux.connections_num();
}

void Http2Upstream::do_health_check(bool need_result) {
    m_health_check_info.reset(); // Forget about the current health check.

    std::optional<uint32_t> stream_id = send_connect_request(NON_ID, &HEALTH_CHECK_HOST, "");
    if (!stream_id.has_value()) {
        m_health_check_info = HealthCheckInfo{
                .stream_id = UINT32_MAX,
                .timeout_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                        {
                                this,
                                [](void *arg, TaskId) {
                                    auto *self = (Http2Upstream *) arg;
                                    bool need_result = self->m_health_check_info.has_value()
                                            ? self->m_health_check_info->need_result
                                            : true;
                                    self->m_health_check_info.reset();
                                    VpnError e = {VPN_EC_ERROR, "Failed to send health check request"};
                                    self->report_health_check_error(need_result, e);
                                },
                        },
                        {}),
                .need_result = need_result,
        };
        return;
    }

    m_health_check_info = HealthCheckInfo{
            .stream_id = stream_id.value(),
            .timeout_task_id = event_loop::schedule(this->vpn->parameters.ev_loop,
                    {
                            this,
                            [](void *arg, TaskId) {
                                auto *self = (Http2Upstream *) arg;
                                bool need_result = self->m_health_check_info.has_value()
                                        ? self->m_health_check_info->need_result
                                        : true;
                                self->m_health_check_info.reset();
                                VpnError e = {VPN_EC_ERROR, "Health check has timed out"};
                                self->report_health_check_error(need_result, e);
                            },
                    },
                    this->vpn->upstream_config.health_check_timeout),
    };
}

void Http2Upstream::cancel_health_check() {
    m_health_check_info.reset();
}

VpnConnectionStats Http2Upstream::get_connection_stats() const {
    return (m_socket != nullptr) ? tcp_socket_get_stats(m_socket.get()) : VpnConnectionStats{};
}

std::optional<uint64_t> Http2Upstream::send_connect_request_callback(
        ServerUpstream *upstream, const TunnelAddress *dst_addr, std::string_view app_name) {
    Http2Upstream *self = (Http2Upstream *) upstream;
    return self->send_connect_request(NON_ID, dst_addr, app_name);
}

int Http2Upstream::send_data_callback(ServerUpstream *upstream, uint64_t stream_id, U8View data) {
    auto *self = (Http2Upstream *) upstream;
    int r = http_session_send_data(self->m_session.get(), (int32_t) stream_id, data.data(), data.size(), false);
    if (r != 0) {
        log_upstream(self, dbg, "Failed to send data: {} ({})", nghttp2_strerror(r), r);
    }
    return r;
}

void Http2Upstream::consume_callback(ServerUpstream *upstream, uint64_t stream_id, size_t size) {
    Http2Upstream *self = (Http2Upstream *) upstream;
    int r = http_session_data_consume(self->m_session.get(), (int32_t) stream_id, size);
    if (r != 0) {
        log_upstream(self, dbg, "Failed to consume data: {} ({})", nghttp2_strerror(r), r);
    }
}

void Http2Upstream::handle_sleep() {
    // noop
}

void Http2Upstream::handle_wake() {
    // noop
}

int Http2Upstream::kex_group_nid() const {
    return tcp_socket_get_kex_group_nid(m_socket.get());
}

void Http2Upstream::report_health_check_error(bool need_result, ag::VpnError error) {
    if (need_result) {
        this->handler.func(this->handler.arg, SERVER_EVENT_HEALTH_CHECK_ERROR, &error);
    } else {
        ServerError err_event = {NON_ID, error};
        this->handler.func(this->handler.arg, SERVER_EVENT_ERROR, &err_event);
    }
}

} // namespace ag
