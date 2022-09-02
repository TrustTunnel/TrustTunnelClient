#include "fake_upstream.h"

#include "vpn/internal/vpn_client.h"

namespace ag {

FakeUpstream::FakeUpstream(int id)
        : ServerUpstream(id) {
}

FakeUpstream::~FakeUpstream() = default;

bool FakeUpstream::init(VpnClient *vpn, SeverHandler handler) {
    if (!this->ServerUpstream::init(vpn, handler)) {
        deinit();
        return false;
    }

    // `open_session` is not being used
    m_session_open = true;
    return true;
}

void FakeUpstream::deinit() {
}

bool FakeUpstream::open_session(std::optional<Millis>) {
    assert(0);
    return false;
}

void FakeUpstream::close_session() {
    std::unordered_set<uint64_t> connections;
    connections.reserve(m_opening_connections.size() + m_closing_connections.size());
    connections.insert(m_opening_connections.begin(), m_opening_connections.end());
    connections.insert(m_closing_connections.begin(), m_closing_connections.end());
    for (uint64_t conn : connections) {
        this->close_connection(conn, true, false);
    }

    m_opening_connections.clear();
    m_closing_connections.clear();
    m_async_task.reset();
    m_session_open = false;
}

uint64_t FakeUpstream::open_connection(const TunnelAddressPair *, int, std::string_view) {
    if (!m_session_open) {
        return NON_ID;
    }

    uint64_t id = this->vpn->upstream_conn_id_generator.get();
    m_opening_connections.insert(id);
    if (!m_async_task.has_value()) {
        m_async_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
    }

    return id;
}

void FakeUpstream::close_connection(uint64_t id, bool, bool async) {
    m_opening_connections.erase(id);
    if (!async) {
        this->handler.func(this->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
    } else if (m_session_open) {
        m_closing_connections.insert(id);
        if (!m_async_task.has_value()) {
            m_async_task = event_loop::submit(this->vpn->parameters.ev_loop, {this, on_async_task});
        }
    }
}

ssize_t FakeUpstream::send(uint64_t, const uint8_t *, size_t) {
    assert(0);
    return -1;
}

void FakeUpstream::consume(uint64_t, size_t) {
    assert(0);
}

size_t FakeUpstream::available_to_send(uint64_t) {
    assert(0);
    return 0;
}

void FakeUpstream::update_flow_control(uint64_t, TcpFlowCtrlInfo) {
    // can be called from tunnel
}

VpnError FakeUpstream::do_health_check() {
    assert(0);
    return {VPN_EC_ERROR, "Internal error"};
}

VpnConnectionStats FakeUpstream::get_connection_stats() const {
    assert(0);
    return {};
}

void FakeUpstream::on_icmp_request(IcmpEchoRequestEvent &) {
    assert(0);
}

void FakeUpstream::on_async_task(void *arg, TaskId) {
    auto *self = (FakeUpstream *) arg;
    self->m_async_task.release();

    std::unordered_set<uint64_t> connections;
    connections.swap(self->m_opening_connections);
    for (uint64_t id : connections) {
        self->handler.func(self->handler.arg, SERVER_EVENT_CONNECTION_OPENED, &id);
    }
    connections.clear();

    connections.swap(self->m_closing_connections);
    for (uint64_t id : connections) {
        self->close_connection(id, false, false);
    }
}

} // namespace ag
