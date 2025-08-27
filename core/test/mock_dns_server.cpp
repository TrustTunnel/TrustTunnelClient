#include "mock_dns_server.h"

#include "../../common/include/vpn/utils.h"

#include <cassert>

#include <ldns/ldns.h>
#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "common/socket_address.h"
#include "vpn/internal/wire_utils.h"

static ag::Logger g_logger{"MOCK_DNS_SERVER"};

ag::MockDnsServer::~MockDnsServer() {
    if (m_udp_event) {
        evutil_closesocket(event_get_fd(m_udp_event.get()));
        m_udp_event.reset();
    }
}

std::optional<ag::SocketAddress> ag::MockDnsServer::start(ag::SocketAddress bind_addr, VpnEventLoop *event_loop,
        SocketManager *socket_manager, CompleteHandler complete_handler, UnexpectedHandler unexpected_handler) {
    if (m_unexpected_handler) {
        warnlog(g_logger, "Repeated call to start()");
        return std::nullopt;
    }

    if (!complete_handler || !unexpected_handler || !event_loop || !socket_manager) {
        warnlog(g_logger, "Event loop or handler not set");
        return std::nullopt;
    }

    m_event_loop = event_loop;
    m_socket_manager = socket_manager;
    m_complete_handler = std::move(complete_handler);
    m_unexpected_handler = std::move(unexpected_handler);

    static constexpr int MAX_ATTEMPTS = 10;
    for (int attempt = 1;; ++attempt) {
        evutil_socket_t fd = socket(bind_addr.c_sockaddr()->sa_family, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == EVUTIL_INVALID_SOCKET) {
            int error = evutil_socket_geterror(fd);
            infolog(g_logger, "socket(): ({}) {}", error, evutil_socket_error_to_string(error));
            return std::nullopt;
        }
        if (0 != evutil_make_socket_nonblocking(fd)) {
            evutil_closesocket(fd);
            infolog(g_logger, "Failed to make socket non-blocking");
            return std::nullopt;
        }
        ev_socklen_t bind_addrlen = bind_addr.c_socklen();
        if (0 != bind(fd, bind_addr.c_sockaddr(), bind_addrlen)) {
            int error = evutil_socket_geterror(fd);
            infolog(g_logger, "bind(): ({}) {}", error, evutil_socket_error_to_string(error));
            evutil_closesocket(fd);
            return std::nullopt;
        }
        SocketAddressStorage storage = *bind_addr.c_storage();
        if (0 != getsockname(fd, (sockaddr *) &storage, &bind_addrlen)) {
            int error = evutil_socket_geterror(fd);
            infolog(g_logger, "getsockname(): ({}) {}", error, evutil_socket_error_to_string(error));
            evutil_closesocket(fd);
            return std::nullopt;
        }
        bind_addr = SocketAddress(storage);
        assert(bind_addrlen == bind_addr.c_socklen());
        m_listener.reset(evconnlistener_new_bind(vpn_event_loop_get_base(event_loop), listener_handler, this,
                LEV_OPT_CLOSE_ON_FREE, -1, bind_addr.c_sockaddr(), bind_addrlen));
        if (!m_listener) {
            evutil_closesocket(fd);
            // There's a small chance that the bound port will already be in use by TCP.
            if (attempt < MAX_ATTEMPTS) {
                infolog(g_logger, "evconnlistener_new_bind() failed, retrying");
                bind_addr.set_port(1 + bind_addr.port());
                continue;
            }
            infolog(g_logger, "evconnlistener_new_bind() failed");
            return std::nullopt;
        }
        m_udp_event.reset(event_new(vpn_event_loop_get_base(event_loop), fd, EV_READ | EV_PERSIST, udp_handler, this));
        if (!m_udp_event) {
            evutil_closesocket(fd);
            infolog(g_logger, "event_new() failed");
            return std::nullopt;
        }
        break;
    }

    event_add(m_udp_event.get(), nullptr);

    infolog(g_logger, "Listening on {}", bind_addr);
    return bind_addr;
}

void ag::MockDnsServer::expect(Spec expect) {
    m_expected.emplace_back(std::move(expect));
}

void ag::MockDnsServer::udp_handler(evutil_socket_t fd, short /*what*/, void *arg) {
    auto *self = (MockDnsServer *) arg;
    uint8_t buf[UINT16_MAX];
    SocketAddressStorage from{};
    ev_socklen_t fromlen = sizeof(from);
    int ret = recvfrom(fd, (char *) buf, sizeof(buf), 0, (sockaddr *) &from, &fromlen);
    if (ret < 0) {
        int error = evutil_socket_geterror(fd);
        infolog(g_logger, "recvfrom(): ({}) {}", error, evutil_socket_error_to_string(error));
        return;
    }
    auto resp = self->on_dns_message({buf, size_t(ret)}, /*tcp*/ false);
    if (resp.has_value() && 0 > sendto(fd, (char *) resp->data(), resp->size(), 0, (sockaddr *) &from, fromlen)) {
        int error = evutil_socket_geterror(fd);
        infolog(g_logger, "sendto(): ({}) {}", error, evutil_socket_error_to_string(error));
    }
}

void ag::MockDnsServer::listener_handler(
        evconnlistener *, evutil_socket_t fd, sockaddr *from, int /*fromlen*/, void *arg) {
    auto *self = (MockDnsServer *) arg;

    TcpConn &conn = self->m_tcp_conns.emplace_back();
    conn.server = self;

    TcpSocketParameters parameters{
            .ev_loop = self->m_event_loop,
            .handler = {.handler = tcp_handler, .arg = &conn},
            .timeout = Secs{30},
            .socket_manager = self->m_socket_manager,
    };
    conn.socket.reset(tcp_socket_create(&parameters));
    assert(conn.socket);

    if (VpnError error = tcp_socket_acquire_fd(conn.socket.get(), fd); error.code) {
        infolog(g_logger, "tcp_socket_acquire_fd(): ({}) {}", error.code, error.text);
        self->m_tcp_conns.pop_back();
        return;
    }

    conn.from = SocketAddress(from);
    tcp_socket_set_read_enabled(conn.socket.get(), true);
}

void ag::MockDnsServer::tcp_handler(void *arg, TcpSocketEvent what, void *data) {
    auto *conn = (TcpConn *) arg;
    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED:
    case TCP_SOCKET_EVENT_PROTECT:
        assert(0);
        break;
    case TCP_SOCKET_EVENT_READABLE: {
        bool remove_conn = false;
        for (;;) {
            auto result = tcp_socket_peek(conn->socket.get());
            if (std::holds_alternative<tcp_socket::Eof>(result)) {
                remove_conn = true;
                break;
            }
            if (std::holds_alternative<tcp_socket::NoData>(result)) {
                break;
            }
            if (auto *chunk = std::get_if<tcp_socket::Chunk>(&result)) {
                conn->buf.insert(conn->buf.end(), chunk->begin(), chunk->end());
                tcp_socket_drain(conn->socket.get(), chunk->size());
                continue;
            }
            assert(0);
            break;
        }
        wire_utils::Reader reader{{conn->buf.begin(), conn->buf.end()}};
        int read = 0;
        for (;;) {
            std::optional<uint16_t> msg_size = reader.get_u16();
            if (!msg_size) {
                break;
            }
            std::optional<U8View> msg_data = reader.get_bytes(*msg_size);
            if (!msg_data) {
                break;
            }
            read += 2 + msg_data->size();
            if (auto response = conn->server->on_dns_message(*msg_data, /*tcp*/ true)) {
                uint16_t size = response->size();
                size = htons(size);
                VpnError error = tcp_socket_write(conn->socket.get(), (uint8_t *) &size, sizeof(size));
                if (!error.code) {
                    error = tcp_socket_write(conn->socket.get(), response->data(), ntohs(size));
                }
                if (error.code) {
                    infolog(g_logger, "Peer {} tcp_socket_write(): ({}) {}", conn->from,
                            error.code, error.text);
                    tcp_socket_set_rst(conn->socket.get(), true);
                    remove_conn = true;
                    break;
                }
            }
        }
        if (remove_conn) {
            conn->server->m_tcp_conns.remove_if([&](const TcpConn &e) {
                return std::addressof(e) == conn;
            });
        } else {
            conn->buf.erase(conn->buf.begin(), conn->buf.begin() + read);
        }
        break;
    }
    case TCP_SOCKET_EVENT_ERROR: {
        auto *error = (VpnError *) data;
        infolog(g_logger, "Peer {} error: ({}) {}", conn->from, error->code,
                error->text);
        tcp_socket_set_rst(conn->socket.get(), true);
        conn->server->m_tcp_conns.remove_if([&](const TcpConn &e) {
            return std::addressof(e) == conn;
        });
        break;
    }
    case TCP_SOCKET_EVENT_SENT:
    case TCP_SOCKET_EVENT_WRITE_FLUSH:
        break;
    }
}

std::optional<std::vector<uint8_t>> ag::MockDnsServer::on_dns_message(U8View message, bool tcp) {
    Request request{.tcp = tcp};
    ldns_pkt *pkt = nullptr;
    if (ldns_status status = ldns_wire2pkt(&pkt, message.data(), message.size()); status != LDNS_STATUS_OK) {
        infolog(g_logger, "ldns_wire2pkt(): {}", magic_enum::enum_name(status));
    } else if (!ldns_pkt_qr(pkt) && ldns_rr_list_rr_count(ldns_pkt_question(pkt))) {
        ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
        request.qtype = ldns_rr_get_type(question);
        UniquePtr<char, &free> qname{ldns_rdf2str(ldns_rr_owner(question))};
        request.qname = qname.get();
    }
    UniquePtr<ldns_pkt, &ldns_pkt_free> pkt_holder{pkt};

    std::optional<Response> response = on_dns_message(std::move(request));
    if (!response.has_value()) {
        return std::nullopt;
    }

    if (!pkt) {
        warnlog(g_logger, "Can't send a response without a valid request");
        return std::nullopt;
    }

    ldns_pkt_set_qr(pkt, true);
    ldns_pkt_set_rcode(pkt, response->rcode);
    for (const std::string &rrstr : response->answer) {
        ldns_rr *rr = nullptr;
        ldns_status status = ldns_rr_new_frm_str(&rr, rrstr.c_str(), 0, nullptr, nullptr);
        if (status != LDNS_STATUS_OK) {
            warnlog(g_logger, "Skipping invalid ({}) RR string: {}", magic_enum::enum_name(status), rrstr);
            continue;
        }
        ldns_pkt_push_rr(pkt, LDNS_SECTION_ANSWER, rr);
    }

    uint8_t *wire = nullptr;
    size_t wire_size = 0;
    if (ldns_status status = ldns_pkt2wire(&wire, pkt, &wire_size); status != LDNS_STATUS_OK) {
        warnlog(g_logger, "ldns_pkt2wire(): {}", magic_enum::enum_name(status));
        return std::nullopt;
    }

    std::vector<uint8_t> ret{wire, wire + wire_size};
    free(wire); // NOLINT(*-no-malloc)
    return ret;
}

std::optional<ag::MockDnsServer::Response> ag::MockDnsServer::on_dns_message(Request request) {
    bool expected = false;
    std::optional<Response> response;
    for (auto it = m_expected.begin(); it != m_expected.end(); ++it) {
        if (it->request == request) {
            expected = true;
            response = std::move(it->response);
            m_expected.erase(it);
            break;
        }
    }
    if (!expected) {
        return m_unexpected_handler(std::nullopt, std::move(request));
    }
    if (m_expected.empty()) {
        m_complete_handler();
    }
    return response;
}
