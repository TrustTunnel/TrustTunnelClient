#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "http_udp_multiplexer.h"
#include "vpn/event_loop.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/vpn_client.h"

static int cert_verify_handler(
        const char * /*host_name*/, const sockaddr * /*host_ip*/, const ag::CertVerifyCtx & /*ctx*/,
        void * /*arg*/) {
    return 1;
}

class HttpUdpMultiplexer : public ::testing::Test, public ag::ServerUpstream {
public:
    HttpUdpMultiplexer()
            : ag::ServerUpstream(42) {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    ag::UniquePtr<ag::VpnEventLoop, ag::vpn_event_loop_destroy> ev_loop{ag::vpn_event_loop_create()};
    ag::VpnClient vpn{ag::vpn_client::Parameters{
            .ev_loop = ev_loop.get(),
            .cert_verify_handler = {&cert_verify_handler, this},
    }};
    ag::HttpUdpMultiplexer mux{ag::HttpUdpMultiplexerParameters{
            .parent = this,
            .send_connect_request_callback = on_send_connect_request,
            .send_data_callback = on_send_data,
            .consume_callback = on_consume,
    }};
    uint64_t next_stream_id = 1;
    size_t streams_num = 0;
    size_t consumed = 0;
    std::vector<uint8_t> output;
    std::vector<uint8_t> decoded_data;

    void SetUp() override {
        ASSERT_TRUE(init(&vpn,
                {
                        .func = upstream_handler,
                        .arg = this,
                }));
    }

    static std::optional<uint64_t> on_send_connect_request(
            ServerUpstream *upstream, const ag::TunnelAddress *, std::string_view) {
        auto *self = (HttpUdpMultiplexer *) upstream;
        uint64_t stream_id = self->next_stream_id++;
        self->streams_num += 1;
        return stream_id;
    }

    static int on_send_data(ServerUpstream *upstream, uint64_t, ag::U8View data) {
        auto *self = (HttpUdpMultiplexer *) upstream;
        self->output.insert(self->output.end(), data.begin(), data.end());
        return 0;
    }

    static void on_consume(ServerUpstream *upstream, uint64_t, size_t size) {
        auto *self = (HttpUdpMultiplexer *) upstream;
        self->consumed += size;
    }

    static void upstream_handler(void *arg, ag::ServerEvent what, void *data) {
        auto *self = (HttpUdpMultiplexer *) arg;
        if (what == ag::SERVER_EVENT_READ) {
            auto *event = (ag::ServerReadEvent *) data;
            self->decoded_data.insert(self->decoded_data.end(), event->data, event->data + event->length);
            event->result = event->length;
        }
    }

    void deinit() override {
    }
    bool open_session(std::optional<ag::Millis>) override {
        return true;
    }
    void close_session() override {
    }
    uint64_t open_connection(const ag::TunnelAddressPair *, int, std::string_view) override {
        return 1;
    }
    void close_connection(uint64_t, bool, bool) override {
    }
    ssize_t send(uint64_t, const uint8_t *, size_t length) override {
        return length;
    }
    void consume(uint64_t, size_t) override {
    }
    size_t available_to_send(uint64_t) override {
        return 42;
    }
    void update_flow_control(uint64_t, ag::TcpFlowCtrlInfo) override {
    }
    void do_health_check() override {
    }
    void cancel_health_check() override {
    }
    ag::VpnConnectionStats get_connection_stats() const override {
        return {};
    }
    void on_icmp_request(ag::IcmpEchoRequestEvent &event) override {
    }

    void loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(ev_loop.get(), ag::Millis{0});
        vpn_event_loop_run(ev_loop.get());
    }
};

TEST_F(HttpUdpMultiplexer, Encoding) {
    constexpr uint64_t CONNECTION_ID = 1;
    constexpr std::string_view APP_NAME = "app";
    constexpr std::string_view PACKET = "hello";
    constexpr uint8_t EXPECTED_PACKET[] = {// length
            0x00, 0x00, 0x00, 0x2d,
            // source ip
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
            // source port
            0x00, 0x01,
            // destination ip
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
            // destination port
            0x00, 0x02,
            // app name length
            0x03,
            // app name
            'a', 'p', 'p',
            // payload
            'h', 'e', 'l', 'l', 'o'};

    ag::TunnelAddressPair addr{ag::SocketAddress("1.1.1.1:1"), ag::SocketAddress("2.2.2.2:2")};
    ASSERT_TRUE(mux.open_connection(CONNECTION_ID, &addr, APP_NAME));
    ASSERT_EQ(streams_num, 1);
    loop_once();

    ag::HttpHeaders response;
    response.status_code = 200;
    mux.handle_response(&response);

    ASSERT_EQ(PACKET.length(), mux.send(CONNECTION_ID, {(uint8_t *) PACKET.data(), PACKET.length()}));
    ASSERT_EQ(ag::encode_to_hex({output.data(), output.size()}),
            ag::encode_to_hex({EXPECTED_PACKET, std::size(EXPECTED_PACKET)}));
}

class HttpUdpMultiplexerDecoding : public HttpUdpMultiplexer {
protected:
    static constexpr uint64_t CONNECTION_ID = 1;
    static constexpr std::string_view APP_NAME = "app";
    static constexpr std::string_view OUTGOING_PACKET = "hello";
    static constexpr uint8_t INCOMING_PACKET[] = {// length
            0x00, 0x00, 0x00, 0x27,
            // source ip
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x02,
            // source port
            0x00, 0x02,
            // destination ip
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
            // destination port
            0x00, 0x01,
            // payload
            'h', 'e', 'y'};
    static constexpr std::string_view EXPECTED_PAYLOAD = "hey";

    void SetUp() override {
        HttpUdpMultiplexer::SetUp();

        ag::TunnelAddressPair addr{ag::SocketAddress("1.1.1.1:1"), ag::SocketAddress("2.2.2.2:2")};
        ASSERT_TRUE(mux.open_connection(CONNECTION_ID, &addr, APP_NAME));
        ASSERT_EQ(streams_num, 1);
        loop_once();

        ag::HttpHeaders response;
        response.status_code = 200;
        mux.handle_response(&response);

        ASSERT_EQ(OUTGOING_PACKET.length(),
                mux.send(CONNECTION_ID, {(uint8_t *) OUTGOING_PACKET.data(), OUTGOING_PACKET.length()}));
        mux.set_read_enabled(CONNECTION_ID, true);
    }
};

TEST_F(HttpUdpMultiplexerDecoding, UnknownAddressPair) {
    std::vector<uint8_t> incoming_packet(std::begin(INCOMING_PACKET), std::end(INCOMING_PACKET));
    incoming_packet[4 + 16] = 42;
    ASSERT_EQ(0, mux.process_read_event({incoming_packet.data(), incoming_packet.size()}));
    ASSERT_TRUE(decoded_data.empty()) << ag::encode_to_hex({decoded_data.data(), decoded_data.size()});
}

TEST_F(HttpUdpMultiplexerDecoding, SinglePacketSingleChunk) {
    ASSERT_EQ(0, mux.process_read_event({INCOMING_PACKET, std::size(INCOMING_PACKET)}));
    ASSERT_EQ(ag::encode_to_hex({decoded_data.data(), decoded_data.size()}),
            ag::encode_to_hex({(uint8_t *) EXPECTED_PAYLOAD.data(), EXPECTED_PAYLOAD.size()}));
}

TEST_F(HttpUdpMultiplexerDecoding, SuccessfulAfterUnknownAddressPair) {
    std::vector<uint8_t> incoming_packet(std::begin(INCOMING_PACKET), std::end(INCOMING_PACKET));
    incoming_packet[4 + 16] = 42;
    ASSERT_EQ(0, mux.process_read_event({incoming_packet.data(), incoming_packet.size()}));
    ASSERT_TRUE(decoded_data.empty()) << ag::encode_to_hex({decoded_data.data(), decoded_data.size()});

    ASSERT_EQ(0, mux.process_read_event({INCOMING_PACKET, std::size(INCOMING_PACKET)}));
    ASSERT_EQ(ag::encode_to_hex({decoded_data.data(), decoded_data.size()}),
            ag::encode_to_hex({(uint8_t *) EXPECTED_PAYLOAD.data(), EXPECTED_PAYLOAD.size()}));
}

TEST_F(HttpUdpMultiplexerDecoding, SinglePacketMultipleChunks) {
    for (size_t i = 0; i < std::size(INCOMING_PACKET); ++i) {
        ASSERT_EQ(0, mux.process_read_event({&INCOMING_PACKET[i], 1}));
        if (i < std::size(INCOMING_PACKET) - 1) {
            ASSERT_TRUE(decoded_data.empty()) << ag::encode_to_hex({decoded_data.data(), decoded_data.size()});
        }
    }

    ASSERT_EQ(ag::encode_to_hex({decoded_data.data(), decoded_data.size()}),
            ag::encode_to_hex({(uint8_t *) EXPECTED_PAYLOAD.data(), EXPECTED_PAYLOAD.size()}));
}

TEST_F(HttpUdpMultiplexerDecoding, MultiplePacketsSingleChunk) {
    std::vector<uint8_t> incoming_packet(std::begin(INCOMING_PACKET), std::end(INCOMING_PACKET));
    incoming_packet.insert(incoming_packet.end(), std::begin(INCOMING_PACKET), std::end(INCOMING_PACKET));
    ASSERT_EQ(0, mux.process_read_event({incoming_packet.data(), incoming_packet.size()}));

    std::string expected_payload = AG_FMT("{}{}", EXPECTED_PAYLOAD, EXPECTED_PAYLOAD);
    ASSERT_EQ(ag::encode_to_hex({decoded_data.data(), decoded_data.size()}),
            ag::encode_to_hex({(uint8_t *) expected_payload.data(), expected_payload.size()}));
}
