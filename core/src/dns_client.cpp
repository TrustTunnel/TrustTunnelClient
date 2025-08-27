#include "dns_client.h"

#include <cassert>

#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"

static ag::Logger g_logger{"DNS_CLIENT"};

static constexpr size_t DNS_MESSAGE_MAX_SIZE = 4096;

#define log_client(self_, lvl_, fmt_, ...) lvl_## log(g_logger, "[{}]: " fmt_, self_->m_parameters.tag, ## __VA_ARGS__)

void ag::DnsClient::tcp_socket_handler(void *arg, TcpSocketEvent what, void *data) {
    auto *self = (DnsClient *) arg;
    switch (what) {
    case TCP_SOCKET_EVENT_CONNECTED:
        self->on_connected({});
        break;
    case TCP_SOCKET_EVENT_READABLE:
        for (;;) {
            auto result = tcp_socket_peek(self->m_tcp_socket.get());
            if (std::holds_alternative<tcp_socket::NoData>(result)) {
                break;
            }
            if (std::holds_alternative<tcp_socket::Eof>(result)) {
                self->on_tcp_read({});
                break;
            }
            if (auto *chunk = std::get_if<tcp_socket::Chunk>(&result)) {
                self->on_tcp_read(*chunk);
                tcp_socket_drain(self->m_tcp_socket.get(), chunk->size());
                continue;
            }
            assert(0 && "Unexpected tcp_socket::PeekResult");
        }
        break;
    case TCP_SOCKET_EVENT_SENT:
        // Ignored
        break;
    case TCP_SOCKET_EVENT_ERROR: {
        auto *error = (VpnError *) data;
        log_client(self, dbg, "{}: ({}) {}", magic_enum::enum_name(what), error->code, error->text);
        if (self->m_tcp_socket_is_connecting) {
            self->on_connected(*error);
        } else {
            self->on_tcp_read({});
        }
        break;
    }
    case TCP_SOCKET_EVENT_WRITE_FLUSH:
        self->on_write_flush();
        break;
    case TCP_SOCKET_EVENT_PROTECT:
        self->m_parameters.handler.func(self->m_parameters.handler.arg, DNS_CLIENT_PROTECT, data);
        break;
    }
}

void ag::DnsClient::udp_socket_handler(void *arg, UdpSocketEvent what, void *data) {
    auto *self = (DnsClient *) arg;
    switch (what) {
    case UDP_SOCKET_EVENT_PROTECT:
        self->m_parameters.handler.func(self->m_parameters.handler.arg, DNS_CLIENT_PROTECT, data);
        break;
    case UDP_SOCKET_EVENT_READABLE: {
        for (;;) {
            uint8_t buffer[DNS_MESSAGE_MAX_SIZE]{};
            ssize_t ret = udp_socket_recv(self->m_udp_socket.get(), buffer, std::size(buffer));
            if (ret < 0) {
                int error = evutil_socket_geterror(udp_socket_get_fd(self->m_udp_socket.get()));
                if (error && !AG_ERR_IS_EAGAIN(error)) {
                    log_client(self, dbg, "recv(): ({}) {}", error, evutil_socket_error_to_string(error));
                }
                break;
            }
            self->on_udp_read({buffer, size_t(ret)});
        }
        break;
    }
    case UDP_SOCKET_EVENT_TIMEOUT:
        // Socket timeout is ignored.
        break;
    }
}

void ag::DnsClient::on_tcp_read(U8View response) {
    if (response.empty()) {
        log_client(this, dbg, "Socket disconnected");
        m_tcp_socket.reset();
        assert(!m_tcp_socket_is_connecting);

        // Fail in-flight requests.
        for (auto &[id, _] : m_original_id_by_request_id) {
            DnsClientResponse event{.id = id};
            m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &event);
        }
        m_request_id_by_deadline.clear();
        m_original_id_by_request_id.clear();

        // If deferred requests exist, try re-connecting.
        if (!m_deferred_request_id_by_deadline.empty()) {
            connect_socket();
        }

        return;
    }

    m_response_buffer.insert(m_response_buffer.end(), response.begin(), response.end());

    uint8_t *pos = m_response_buffer.data();
    size_t rem = m_response_buffer.size();

    for (;;) {
        if (!m_response_size.has_value()) {
            if (rem < sizeof(uint16_t)) {
                break;
            }
            m_response_size.emplace();
            std::memcpy(&*m_response_size, pos, sizeof(uint16_t));
            m_response_size = ntohs(*m_response_size);
            pos += sizeof(uint16_t);
            rem -= sizeof(uint16_t);
        }
        if (rem < m_response_size.value()) {
            break;
        }
        if (m_response_size.value() < sizeof(uint16_t)) {
            log_client(this, dbg, "Response is too short, skipping");
        } else {
            uint16_t id; // NOLINT(*-init-variables)
            std::memcpy(&id, pos, sizeof(uint16_t));
            id = ntohs(id);
            // Entry in `m_request_id_by_deadline` is cleared on timer event.
            if (auto node = m_original_id_by_request_id.extract(id); !node.empty()) {
                std::memcpy(pos, &node.mapped(), sizeof(uint16_t));
                log_client(this, dbg, "Read DNS response, id={}, size={}", id, m_response_size.value());
                DnsClientResponse event{.id = id, .data = {pos, m_response_size.value()}};
                m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &event);
            } else {
                log_client(this, dbg, "Request not found, id={}", id);
            }
        }
        pos += m_response_size.value();
        rem -= m_response_size.value();
        m_response_size.reset();
    }

    // Erase the processed part.
    m_response_buffer.erase(m_response_buffer.begin(), m_response_buffer.begin() + (pos - m_response_buffer.data()));
}

void ag::DnsClient::on_udp_read(Uint8Span response) {
    if (response.size() < sizeof(uint16_t)) {
        log_client(this, dbg, "Response is too short: {}", response.size());
        return;
    }
    uint16_t id; // NOLINT(*-init-variables)
    std::memcpy(&id, response.data(), sizeof(uint16_t));
    id = ntohs(id);
    // Entry in `m_request_id_by_deadline` is cleared on timer event.
    if (auto node = m_original_id_by_request_id.extract(id); !node.empty()) {
        std::memcpy(response.data(), &node.mapped(), sizeof(uint16_t));
        log_client(this, dbg, "Read DNS response, id={}, size={}", id, response.size());
        DnsClientResponse event{.id = id, .data = {response.data(), response.size()}};
        m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &event);
        return;
    }
    log_client(this, dbg, "Request not found, id={}", id);
}

void ag::DnsClient::on_write_flush() {
    send_deferred_requests();
}

void ag::DnsClient::on_connected(VpnError error) {
    assert(m_tcp_socket);
    assert(m_tcp_socket_is_connecting);
    m_tcp_socket_is_connecting = false;
    if (error.code) {
        m_tcp_socket.reset();
        log_client(this, dbg, "Failed to connect: ({}) {}", error.code, error.text);
        assert(m_request_id_by_deadline.empty());
        assert(m_original_id_by_request_id.empty());
        // Fail deferred requests. Will attempt to reconnect on next request.
        for (auto [_, id] : m_deferred_request_id_by_deadline) {
            DnsClientResponse event{.id = id};
            m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &event);
        }
        m_deferred_request_id_by_deadline.clear();
        m_deferred_request_by_request_id.clear();
        return;
    }
    log_client(this, dbg, "Connected");
    tcp_socket_set_read_enabled(m_tcp_socket.get(), true);
    send_deferred_requests();
}

void ag::DnsClient::timer_handler(evutil_socket_t, short, void *arg) {
    auto *self = (DnsClient *) arg;
    self->timer_handler();
}

void ag::DnsClient::timer_handler() {
    evtimer_del(m_timer.get());
    auto now = SteadyClock::now();

    // Fail in-flight timed out requests.
    for (auto it = m_request_id_by_deadline.begin(), expired_end = m_request_id_by_deadline.upper_bound(now);
            it != expired_end; it = m_request_id_by_deadline.erase(it)) {
        // If request is still in-flight.
        if (auto original_id_it = m_original_id_by_request_id.find(it->second);
                original_id_it != m_original_id_by_request_id.end()) {
            log_client(this, dbg, "Request timed out, id={}", it->second);
            m_original_id_by_request_id.erase(original_id_it);
            DnsClientResponse response{.id = it->second};
            m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &response);
        }
    }

    // Fail deferred timed out requests.
    for (auto it = m_deferred_request_id_by_deadline.begin(),
              expired_end = m_deferred_request_id_by_deadline.upper_bound(now);
            it != expired_end; it = m_deferred_request_id_by_deadline.erase(it)) {
        // If request is still deferred.
        if (auto request_it = m_deferred_request_by_request_id.find(it->second);
                request_it != m_deferred_request_by_request_id.end()) {
            log_client(this, dbg, "Deferred request timed out, id={}", it->second);
            m_deferred_request_by_request_id.erase(request_it);
            DnsClientResponse response{.id = it->second};
            m_parameters.handler.func(m_parameters.handler.arg, DNS_CLIENT_RESPONSE, &response);
        }
    }

    auto next_in_flight_deadline =
            m_request_id_by_deadline.empty() ? SteadyClock::time_point::max() : m_request_id_by_deadline.begin()->first;
    auto next_deferred_dealine = m_deferred_request_id_by_deadline.empty()
            ? SteadyClock::time_point::max()
            : m_deferred_request_id_by_deadline.begin()->first;
    auto next_deadline = std::min(next_in_flight_deadline, next_deferred_dealine);
    if (next_deadline == SteadyClock::time_point::max()) {
        return;
    }

    auto timeout_ms = std::chrono::duration_cast<Millis>(next_deadline - now).count();
    timeval tv = ms_to_timeval(timeout_ms);
    log_client(this, dbg, "Next timeout in {} s, {} us", (int) tv.tv_sec, (int) tv.tv_usec);
    evtimer_add(m_timer.get(), &tv);
}

void ag::DnsClient::send_deferred_requests() {
    assert(m_tcp_socket);
    for (auto it = m_deferred_request_id_by_deadline.begin(); it != m_deferred_request_id_by_deadline.end();) {
        uint16_t id = it->second;
        auto body = m_deferred_request_by_request_id.find(id);
        assert(body != m_deferred_request_by_request_id.end());
        if (!send_request({body->second.data(), body->second.size()}, id, /*tcp*/ true)) {
            break;
        }
        m_deferred_request_by_request_id.erase(body);
        m_request_id_by_deadline.emplace(it->first, id);
        it = m_deferred_request_id_by_deadline.erase(it);
    }
    log_client(this, dbg, "Remaining unsent: {}", m_deferred_request_id_by_deadline.size());
}

bool ag::DnsClient::send_request(U8View request, uint16_t id, bool tcp) {
    assert(request.size() > sizeof(uint16_t));

    uint16_t wire_id = htons(id);
    uint16_t original_id; // NOLINT(*-init-variables)
    std::memcpy(&original_id, request.data(), sizeof(original_id));

    if (tcp) {
        if (!m_tcp_socket || m_tcp_socket_is_connecting) {
            log_client(this, dbg, "Not connected, id={}", id);
            if (!m_tcp_socket_is_connecting) {
                connect_socket();
            }
            return false;
        }
        if (!tcp_socket_available_to_write(m_tcp_socket.get())) {
            log_client(this, dbg, "Socket write blocked, id={}", id);
            return false;
        }
        uint16_t wire_size = htons((uint16_t) request.size());
        request.remove_prefix(sizeof(uint16_t));
        tcp_socket_write(m_tcp_socket.get(), (uint8_t *) &wire_size, sizeof(wire_size));
        tcp_socket_write(m_tcp_socket.get(), (uint8_t *) &wire_id, sizeof(wire_id));
        tcp_socket_write(m_tcp_socket.get(), request.data(), request.size());
    } else {
        assert(m_udp_socket);
        uint8_t buffer[DNS_MESSAGE_MAX_SIZE]{};
        size_t size = std::min(request.size(), std::size(buffer));
        if (size < request.size()) {
            log_client(this, warn, "UDP payload truncated to {} bytes, id={}", size, id);
        }
        std::memcpy(buffer, request.data(), size);
        std::memcpy(buffer, &wire_id, sizeof(wire_id));
        udp_socket_write(m_udp_socket.get(), buffer, size);
    }

    auto [it, placed] = m_original_id_by_request_id.emplace(id, original_id);
    (void) it;
    assert(placed);

    log_client(this, dbg, "Request sent over {}, id={}", tcp ? "TCP" : "UDP", id);

    return true;
}

void ag::DnsClient::connect_socket() {
    log_client(this, info, "Connecting TCP socket to {}", m_parameters.tcp_server_address);
    assert(!m_tcp_socket_is_connecting);
    assert(!m_tcp_socket);

    TcpSocketParameters socket_parameters{
            .ev_loop = m_parameters.ev_loop,
            .handler = {.handler = tcp_socket_handler, .arg = this},
            .timeout = Millis::max(),
            .socket_manager = m_parameters.socket_manager,
    };

    m_tcp_socket.reset(tcp_socket_create(&socket_parameters));
    assert(m_tcp_socket);

    TcpSocketConnectParameters connect_parameters{
            .peer = &m_parameters.tcp_server_address,
    };

    if (VpnError error = tcp_socket_connect(m_tcp_socket.get(), &connect_parameters); error.code) {
        log_client(this, warn, "tcp_socket_connect(): ({}) {}", error.code, error.text);
        return;
    }

    m_tcp_socket_is_connecting = true;
}

ag::DnsClient::DnsClient(DnsClientParameters parameters)
        : m_parameters{std::move(parameters)} {
    assert(m_parameters.tcp_server_address.is_loopback()); // Intended for local DNS proxy
    assert(m_parameters.udp_server_address.is_loopback()); // Intended for local DNS proxy
    assert(m_parameters.ev_loop);
}

bool ag::DnsClient::init() {
    m_timer.reset(evtimer_new(vpn_event_loop_get_base(m_parameters.ev_loop), timer_handler, this));
    if (!m_timer) {
        log_client(this, info, "evtimer_new failed");
        return false;
    }
    UdpSocketParameters udp_param{
            .ev_loop = m_parameters.ev_loop,
            .handler = {.func = udp_socket_handler, .arg = this},
            .timeout = Millis::max(),
            .peer = m_parameters.udp_server_address,
            .socket_manager = m_parameters.socket_manager,
    };
    m_udp_socket.reset(udp_socket_create(&udp_param));
    if (!m_udp_socket) {
        log_client(this, info, "udp_socket_create failed");
        return false;
    }
    return true;
}

std::optional<uint16_t> ag::DnsClient::send(U8View request, bool tcp) {
    uint16_t id = m_next_request_id++;

    if (request.size() < 2) {
        log_client(this, warn, "Request is malformed");
        return std::nullopt;
    }

    // In the unlikely event of ID collision, fail.
    if (m_original_id_by_request_id.contains(id) || m_deferred_request_by_request_id.contains(id)) {
        log_client(this, dbg, "Request with the same id is already in-flight");
        return std::nullopt;
    }

    auto deadline = SteadyClock::now() + m_parameters.request_timeout;

    if (send_request(request, id, tcp)) {
        m_request_id_by_deadline.emplace(deadline, id);
    } else {
        assert(tcp);
        m_deferred_request_id_by_deadline.emplace(deadline, id);
        m_deferred_request_by_request_id.emplace(std::piecewise_construct, std::forward_as_tuple(id),
                std::forward_as_tuple(request.begin(), request.end()));
    }

    if (!evtimer_pending(m_timer.get(), nullptr)) {
        auto timeout_ms = duration_cast<Millis>(m_parameters.request_timeout).count();
        timeval tv = ms_to_timeval(timeout_ms);
        log_client(this, dbg, "Next timeout in {} s, {} us", (int) tv.tv_sec, (int) tv.tv_usec);
        evtimer_add(m_timer.get(), &tv);
    }

    return id;
}
