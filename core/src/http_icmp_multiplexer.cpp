#include "http_icmp_multiplexer.h"

#include "vpn/internal/wire_utils.h"

namespace ag {

enum HttpIcmpMultiplexer::State : uint32_t {
    MS_IDLE,
    MS_ESTABLISHED,
};

/**
 * Outgoing ICMP packet format (sent from us to the endpoint)
 * <p>
 * +----------+---------------------+-----------------+---------------+-----------+
 * |  ID      | Destination address | Sequence number | TTL/Hop limit | Data size |
 * | 2 bytes  |  16 bytes           | 2 bytes         | 1 byte        | 2 bytes   |
 * +----------+---------------------+-----------------+---------------+-----------+
 * <p>
 * Incoming ICMP packet format (sent from the endpoint to us)
 * <p>
 * +----------+----------------+--------+--------+-----------------+
 * |  ID      | Source address | Type   | Code   | Sequence number |
 * | 2 bytes  |  16 bytes      | 1 byte | 1 byte | 2 bytes         |
 * +----------+----------------+--------+--------+-----------------+
 */
static constexpr size_t ICMPPKT_ID_SIZE = 2;
static constexpr size_t ICMPPKT_ADDR_SIZE = 16;
static constexpr size_t ICMPPKT_SEQNO_SIZE = 2;
static constexpr size_t ICMPPKT_TTL_SIZE = 1;
static constexpr size_t ICMPPKT_DATA_SIZE = 2;
static constexpr size_t ICMPPKT_TYPE_SIZE = 1;
static constexpr size_t ICMPPKT_CODE_SIZE = 1;

static constexpr size_t ICMPPKT_REQ_SIZE =
        ICMPPKT_ID_SIZE + ICMPPKT_ADDR_SIZE + ICMPPKT_SEQNO_SIZE + ICMPPKT_TTL_SIZE + ICMPPKT_DATA_SIZE;
static constexpr size_t ICMPPKT_REPLY_SIZE =
        ICMPPKT_ID_SIZE + ICMPPKT_ADDR_SIZE + ICMPPKT_TYPE_SIZE + ICMPPKT_CODE_SIZE + ICMPPKT_SEQNO_SIZE;

HttpIcmpMultiplexer::HttpIcmpMultiplexer(HttpIcmpMultiplexerParameters parameters)
        : m_params(std::move(parameters)) {
}

HttpIcmpMultiplexer::~HttpIcmpMultiplexer() = default;

void HttpIcmpMultiplexer::close() {
    m_state = MS_IDLE;
    m_stream_id.reset();
    m_reply_buffer.clear();
}

std::optional<uint64_t> HttpIcmpMultiplexer::get_stream_id() const {
    return m_stream_id;
}

bool HttpIcmpMultiplexer::send_request(const IcmpEchoRequest &request) {
    ServerUpstream *upstream = m_params.parent;

    switch (m_state) {
    case MS_IDLE: {
        assert(!m_stream_id.has_value());
        static const TunnelAddress ICMP_HOST(NamePort{"_icmp", 0});
        m_stream_id = m_params.send_connect_request_callback(upstream, &ICMP_HOST, "_icmp");
        if (!m_stream_id.has_value()) {
            return false;
        }
        m_stream_id = m_stream_id.value();
        m_state = MS_ESTABLISHED;
        [[fallthrough]];
    }
    case MS_ESTABLISHED:
        return this->send_request_established(request);
    }

    return true;
}

void HttpIcmpMultiplexer::handle_response(const HttpHeaders *) {
    assert(m_state == MS_ESTABLISHED);
    // if failed, `close` will be called after the stream close
}

int HttpIcmpMultiplexer::process_read_event(U8View data) {
    assert(m_state == MS_ESTABLISHED);
    size_t data_size = data.size();

    while (!data.empty()) {
        data = this->process_reply_chunk(data);
    }

    m_params.consume_callback(m_params.parent, m_stream_id.value(), data_size);
    return 0;
}

bool HttpIcmpMultiplexer::send_request_established(const IcmpEchoRequest &request) {
    uint8_t packet_buffer[ICMPPKT_REQ_SIZE]{};
    wire_utils::Writer writer({packet_buffer, sizeof(packet_buffer)});
    writer.put_u16(request.id);
    writer.put_ip_padded(request.peer);
    writer.put_u16(request.seqno);
    writer.put_u8(request.ttl);
    writer.put_u16(request.data_size);

    int r = m_params.send_data_callback(m_params.parent, m_stream_id.value(), {packet_buffer, sizeof(packet_buffer)});
    return r == 0;
}

U8View HttpIcmpMultiplexer::process_reply_chunk(U8View data) {
    U8View raw_reply;
    if (m_reply_buffer.empty() && data.size() >= ICMPPKT_REPLY_SIZE) {
        raw_reply = data.substr(0, ICMPPKT_REPLY_SIZE);
        data.remove_prefix(ICMPPKT_REPLY_SIZE);
    } else {
        m_reply_buffer.reserve(ICMPPKT_REPLY_SIZE);
        size_t to_read = std::min(data.size(), ICMPPKT_REPLY_SIZE - m_reply_buffer.size());
        m_reply_buffer.insert(m_reply_buffer.end(), data.begin(), std::next(data.begin(), (ssize_t) to_read));
        data.remove_prefix(to_read);
        if (m_reply_buffer.size() < ICMPPKT_REPLY_SIZE) {
            return data;
        }

        assert(m_reply_buffer.size() == ICMPPKT_REPLY_SIZE);
        raw_reply = {m_reply_buffer.data(), ICMPPKT_REPLY_SIZE};
    }

    wire_utils::Reader reader(raw_reply);

    IcmpEchoReply reply = {};
    reply.id = reader.get_u16().value();
    reply.peer = reader.get_ip_padded().value();
    reply.type = reader.get_u8().value();
    reply.code = reader.get_u8().value();
    reply.seqno = reader.get_u16().value();

    ServerHandler handler = m_params.parent->handler;
    handler.func(handler.arg, SERVER_EVENT_ECHO_REPLY, &reply);

    m_reply_buffer.clear();

    return data;
}

} // namespace ag
