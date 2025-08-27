#include <optional>
#include <thread>

#include <gtest/gtest.h>
#include <openssl/rand.h>

#include "common/net_utils.h"
#include "common/socket_address.h"
#include "fake_upstream.h"
#include "mock_dns_server.h"
#include "net/dns_utils.h"
#include "vpn/internal/tunnel.h"
#include "vpn/internal/vpn_client.h"

using namespace ag;

static constexpr uint8_t CLIENT_HELLO[] = {
        // sni=localhost
        0x16, 0x03, 0x01, 0x01, 0x3E, 0x01, 0x00, 0x01, 0x3A, 0x03, 0x03, 0x0C, 0xC1, 0x18, 0xB3, 0x53, 0xC8, 0x9A,
        0xCB, 0xDB, 0xB7, 0x40, 0x60, 0xB0, 0x7C, 0x2E, 0xC0, 0x5E, 0xBB, 0xD4, 0x58, 0x4D, 0xBC, 0x77, 0xE4, 0x4E,
        0x35, 0xD3, 0x25, 0x73, 0x34, 0xF8, 0xF7, 0x00, 0x00, 0xAA, 0xC0, 0x30, 0xC0, 0x2C, 0xC0, 0x28, 0xC0, 0x24,
        0xC0, 0x14, 0xC0, 0x0A, 0x00, 0xA5, 0x00, 0xA3, 0x00, 0xA1, 0x00, 0x9F, 0x00, 0x6B, 0x00, 0x6A, 0x00, 0x69,
        0x00, 0x68, 0x00, 0x39, 0x00, 0x38, 0x00, 0x37, 0x00, 0x36, 0x00, 0x88, 0x00, 0x87, 0x00, 0x86, 0x00, 0x85,
        0xC0, 0x32, 0xC0, 0x2E, 0xC0, 0x2A, 0xC0, 0x26, 0xC0, 0x0F, 0xC0, 0x05, 0x00, 0x9D, 0x00, 0x3D, 0x00, 0x35,
        0x00, 0x84, 0xC0, 0x2F, 0xC0, 0x2B, 0xC0, 0x27, 0xC0, 0x23, 0xC0, 0x13, 0xC0, 0x09, 0x00, 0xA4, 0x00, 0xA2,
        0x00, 0xA0, 0x00, 0x9E, 0x00, 0x67, 0x00, 0x40, 0x00, 0x3F, 0x00, 0x3E, 0x00, 0x33, 0x00, 0x32, 0x00, 0x31,
        0x00, 0x30, 0x00, 0x9A, 0x00, 0x99, 0x00, 0x98, 0x00, 0x97, 0x00, 0x45, 0x00, 0x44, 0x00, 0x43, 0x00, 0x42,
        0xC0, 0x31, 0xC0, 0x2D, 0xC0, 0x29, 0xC0, 0x25, 0xC0, 0x0E, 0xC0, 0x04, 0x00, 0x9C, 0x00, 0x3C, 0x00, 0x2F,
        0x00, 0x96, 0x00, 0x41, 0xC0, 0x11, 0xC0, 0x07, 0xC0, 0x0C, 0xC0, 0x02, 0x00, 0x05, 0x00, 0x04, 0xC0, 0x12,
        0xC0, 0x08, 0x00, 0x16, 0x00, 0x13, 0x00, 0x10, 0x00, 0x0D, 0xC0, 0x0D, 0xC0, 0x03, 0x00, 0x0A, 0x00, 0xFF,
        0x01, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x0E, 0x00, 0x0C, 0x00, 0x00, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
        0x68, 0x6F, 0x73, 0x74, 0x00, 0x0B, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0A, 0x00, 0x1C, 0x00, 0x1A,
        0x00, 0x17, 0x00, 0x19, 0x00, 0x1C, 0x00, 0x1B, 0x00, 0x18, 0x00, 0x1A, 0x00, 0x16, 0x00, 0x0E, 0x00, 0x0D,
        0x00, 0x0B, 0x00, 0x0C, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x20, 0x00, 0x1E,
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03,
        0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x0F, 0x00, 0x01, 0x01};

class TestUpstream : public ServerUpstream {
public:
    static inline int g_next_upstream_id = 0;

    std::vector<uint64_t> connections;
    size_t last_send = 0;
    TunnelAddress last_destination;

    TestUpstream()
            : ServerUpstream(g_next_upstream_id++) {
    }
    ~TestUpstream() override = default;

    TestUpstream(const TestUpstream &) = delete;
    TestUpstream &operator=(const TestUpstream &) = delete;

    TestUpstream(TestUpstream &&) noexcept = delete;
    TestUpstream &operator=(TestUpstream &&) noexcept = delete;

    void deinit() override {
    }
    bool open_session(std::optional<Millis>) override {
        return true;
    }
    void close_session() override {
    }

    uint64_t open_connection(const TunnelAddressPair *addr, int, std::string_view) override {
        connections.push_back(this->vpn->upstream_conn_id_generator.get());
        last_destination = addr->dst;
        return connections.back();
    }

    void close_connection(uint64_t id, bool, bool) override {
        connections.erase(std::remove(connections.begin(), connections.end(), id), connections.end());
        handler.func(handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &id);
    }

    ssize_t send(uint64_t, const uint8_t *, size_t length) override {
        last_send = length;
        return length;
    }
    void consume(uint64_t id, size_t length) override {
    }
    size_t available_to_send(uint64_t) override {
        return 1;
    }
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override {
    }
    void do_health_check() override {
    }
    void cancel_health_check() override {
    }
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override {
        return {};
    }
    void on_icmp_request(IcmpEchoRequestEvent &event) override {
    }
};

class TestListener : public ClientListener {
public:
    enum ConnectionState {
        CS_REQUESTED,
        CS_COMPLETED,
    };

    struct Connection {
        ConnectionState state = CS_REQUESTED;
        bool read_enabled = false;
        std::optional<ClientConnectResult> result;
    };

    std::unordered_map<size_t, Connection> connections;

    TestListener() = default;
    ~TestListener() override = default;

    TestListener(const TestListener &) = delete;
    TestListener &operator=(const TestListener &) = delete;

    TestListener(TestListener &&) noexcept = delete;
    TestListener &operator=(TestListener &&) noexcept = delete;

    InitResult init(VpnClient *vpn, ClientHandler handler) override {
        return ClientListener::init(vpn, handler);
    }

    void deinit() override {
    }

    void complete_connect_request(uint64_t id, ClientConnectResult result) override {
        connections[id].state = CS_COMPLETED;
        connections[id].result = result;
    }

    void close_connection(uint64_t id, bool, bool) override {
        connections.erase(id);
        handler.func(handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
    }

    ssize_t send(uint64_t, const uint8_t *, size_t length) override {
        return length;
    }

    void consume(uint64_t id, size_t n) override {
    }
    TcpFlowCtrlInfo flow_control_info(uint64_t) override {
        return {DEFAULT_SEND_BUFFER_SIZE, DEFAULT_SEND_WINDOW_SIZE};
    }
    void turn_read(uint64_t id, bool on) override {
        if (connections.count(id) != 0) {
            connections[id].read_enabled = on;
        }
    }
    int process_client_packets(VpnPackets) override {
        return 0;
    }
};

static vpn_client::Event g_last_raised_vpn_event;

static int cert_verify_handler(
        const char * /*host_name*/, const sockaddr * /*host_ip*/, const CertVerifyCtx & /*ctx*/,
        void * /*arg*/) {
    return 1;
}

static void vpn_handler(void *, vpn_client::Event what, void *) {
    g_last_raised_vpn_event = what;
}

class TunnelTest : public testing::Test {
public:
    TunnelTest()
            : vpn(vpn_client::Parameters{this->ev_loop.get()}) {
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    VpnClient vpn;
    Tunnel tun = {};
    SocketAddress src{};
    TunnelAddress dst;
    std::shared_ptr<TestUpstream> redirect_upstream;
    std::shared_ptr<TestUpstream> bypass_upstream;
    std::shared_ptr<TestListener> client_listener;
    int connection_protocol = IPPROTO_TCP;

    static void redirect_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (TunnelTest *) arg;
        test->tun.upstream_handler(test->redirect_upstream, what, data);
    }

    static void bypass_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (TunnelTest *) arg;
        test->tun.upstream_handler(test->bypass_upstream, what, data);
    }

    static void listener_handler(void *arg, ClientEvent what, void *data) {
        auto *test = (TunnelTest *) arg;
        test->tun.listener_handler(test->client_listener, what, data);
    }

    void SetUp() override {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);

        src = SocketAddress("1.1.1.1:1000");
        dst = SocketAddress("1.1.1.2:443");

        vpn.parameters.cert_verify_handler = {&cert_verify_handler, this};
        vpn.parameters.handler = {&vpn_handler, this};
        vpn.parameters.network_manager = network_manager.get();

        redirect_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(redirect_upstream->init(&vpn, {&redirect_upstream_handler, this}));
        vpn.endpoint_upstream = redirect_upstream;
        bypass_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(bypass_upstream->init(&vpn, {&bypass_upstream_handler, this}));
        vpn.bypass_upstream = bypass_upstream;

        client_listener = std::make_unique<TestListener>();
        ASSERT_EQ(ClientListener::InitResult::SUCCESS, client_listener->init(&vpn, {&listener_handler, this}));
        vpn.client_listener = client_listener;

        ASSERT_TRUE(tun.init(&vpn));

        tun.upstream_handler(vpn.endpoint_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);
    }

    void TearDown() override {
        tun.deinit();
    }

    void raise_client_connection(uint64_t id) {
        ClientConnectRequest event = {id, connection_protocol, &src, &dst};
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
        ASSERT_EQ(g_last_raised_vpn_event, vpn_client::EVENT_CONNECT_REQUEST);
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }
};

TEST_F(TunnelTest, IPv6Unavailable) {
    src = SocketAddress("[::1:1:1:1]:443");
    vpn.endpoint_upstream->update_ip_availability(IpVersionSet{1 << IPV4});
    size_t client_id = vpn.listener_conn_id_generator.get();

    dst = SocketAddress("[::2:2:2:2]:443");
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

    std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some", 1});
    ASSERT_NE(action, VPN_CA_FORCE_BYPASS);
    tun.complete_connect_request(client_id, action);
    run_event_loop_once();
    ASSERT_EQ(redirect_upstream->connections.size(), 0);
    ASSERT_NE(client_listener->connections.count(client_id), 0);
    ASSERT_EQ(client_listener->connections[client_id].result, CCR_UNREACH);
}

TEST_F(TunnelTest, LocalhostConnection) {
    size_t client_id = vpn.listener_conn_id_generator.get();
    dst = SocketAddress("127.0.0.1:443");
    ClientConnectRequest event = {client_id, connection_protocol, &src, &dst};
    tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
    ASSERT_GT(bypass_upstream->connections.size(), 0);
}

class MigrationTest : public TunnelTest {
public:
    uint64_t client_id = NON_ID;
    uint64_t redirect_id = NON_ID;
    uint64_t bypass_id = NON_ID;

    void SetUp() override {
        TunnelTest::SetUp();

        ASSERT_TRUE(vpn.domain_filter.update_exclusions(VPN_MODE_GENERAL, "localhost"));

        client_id = vpn.listener_conn_id_generator.get();

        // 1) Raise the request for connection
        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        // 2) Establish the connection through VPN endpoint
        size_t size_before = redirect_upstream->connections.size();
        std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some", 1});
        tun.complete_connect_request(client_id, action);
        ASSERT_GT(redirect_upstream->connections.size(), size_before);
        redirect_id = redirect_upstream->connections.back();

        tun.upstream_handler(redirect_upstream, SERVER_EVENT_CONNECTION_OPENED, &redirect_id);
        ASSERT_EQ(client_listener->connections[client_id].state, TestListener::CS_COMPLETED);

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);

        // 3) Receive client hello with bypassed domain and start the migration
        size_before = bypass_upstream->connections.size();
        ClientRead read_event = {client_id, CLIENT_HELLO, std::size(CLIENT_HELLO), 0};
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);

        ASSERT_GT(bypass_upstream->connections.size(), size_before);
        bypass_id = bypass_upstream->connections.back();

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        ASSERT_EQ(redirect_upstream->last_send, 0);
        ASSERT_EQ(bypass_upstream->last_send, 0);
    }

    void TearDown() override {
        TunnelTest::TearDown();
    }
};

TEST_F(MigrationTest, Successful) {
    // 4) Complete migration
    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &bypass_id);
    ASSERT_EQ(redirect_upstream->connections.end(),
            std::find(redirect_upstream->connections.begin(), redirect_upstream->connections.end(), redirect_id));
    ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    ASSERT_EQ(redirect_upstream->last_send, 0);
    ASSERT_EQ(bypass_upstream->last_send, 0);

    ClientRead read_event = {client_id, CLIENT_HELLO, std::size(CLIENT_HELLO), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
    ASSERT_EQ(redirect_upstream->last_send, 0);
    ASSERT_EQ(bypass_upstream->last_send, std::size(CLIENT_HELLO));
}

TEST_F(MigrationTest, ClosedDuringMigration) {
    // 4) Connection is closed during the migration
    tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_CLOSED, &client_id);

    // 5) Complete migration
    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &bypass_id);
    ASSERT_EQ(redirect_upstream->connections.end(),
            std::find(redirect_upstream->connections.begin(), redirect_upstream->connections.end(), redirect_id));
    ASSERT_EQ(bypass_upstream->last_send, 0);
    ASSERT_EQ(bypass_upstream->connections.end(),
            std::find(bypass_upstream->connections.begin(), bypass_upstream->connections.end(), bypass_id));
}

TEST_F(MigrationTest, ConnectionFailed) {
    // 4) Failed to connect to host directly
    ServerError err = {bypass_id, {ag::utils::AG_ECONNREFUSED, "refused"}};
    tun.upstream_handler(redirect_upstream, SERVER_EVENT_ERROR, &err);
    ASSERT_EQ(redirect_upstream->connections.end(),
            std::find(redirect_upstream->connections.begin(), redirect_upstream->connections.end(), redirect_id));
    ASSERT_EQ(bypass_upstream->last_send, 0);
    ASSERT_EQ(bypass_upstream->connections.end(),
            std::find(bypass_upstream->connections.begin(), bypass_upstream->connections.end(), bypass_id));
}

class TestFakeUpstream : public FakeUpstream {
public:
    std::vector<uint64_t> closing_connections;

    explicit TestFakeUpstream(std::shared_ptr<ServerUpstream> orig)
            : FakeUpstream(0) {
        ((ServerUpstream *) this)->init(orig->vpn, orig->handler);
    }

    void close_connection(uint64_t id, bool, bool) override {
        this->closing_connections.push_back(id);
    }
};

class FakeConnectionTest : public TunnelTest {
public:
    static constexpr uint8_t ANSWER_TTL_SEC = 1;

    uint64_t client_id = NON_ID;
    uint64_t redirect_id = NON_ID;
    uint64_t bypass_id = NON_ID;
    TestFakeUpstream *fake_upstream = nullptr;
    std::unique_ptr<MockDnsServer> dns_server = std::make_unique<MockDnsServer>();
    int mock_dns_server_completed = 0;
    int mock_dns_server_unexpected = 0;

    void SetUp() override {
        TunnelTest::SetUp();

        auto address = dns_server->start(
                SocketAddress("127.0.0.1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    vpn_event_loop_exit(this->ev_loop.get(), Millis{100});
                    ++this->mock_dns_server_completed;
                },
                [this](std::optional<MockDnsServer::Request> /*expected*/, MockDnsServer::Request /*actual*/) {
                    vpn_event_loop_exit(this->ev_loop.get(), Millis{100});
                    ++this->mock_dns_server_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(address.has_value());

        vpn_network_manager_update_system_dns({.main = {{.address = address->str()}}});
        run_event_loop_once();

        tun.fake_upstream = std::make_shared<TestFakeUpstream>(std::move(tun.fake_upstream));
        ASSERT_TRUE(tun.fake_upstream->open_session());
        this->fake_upstream = (TestFakeUpstream *) tun.fake_upstream.get();

        ASSERT_TRUE(vpn.domain_filter.update_exclusions(VPN_MODE_GENERAL, "localhost"));

        ASSERT_NO_FATAL_FAILURE(do_dns_resolve());

        client_id = vpn.listener_conn_id_generator.get();

        // 1) Raise the request for connection
        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        // 2) Tunnel sees the suspect address and routes the connection to the fake upstream
        size_t num_redirected = redirect_upstream->connections.size();
        size_t num_bypassed = bypass_upstream->connections.size();
        std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some", 1});
        ASSERT_FALSE(action.has_value());
        tun.complete_connect_request(client_id, action);
        run_event_loop_once();

        ASSERT_EQ(redirect_upstream->connections.size(), num_redirected);
        ASSERT_EQ(bypass_upstream->connections.size(), num_bypassed);
        ASSERT_EQ(client_listener->connections[client_id].state, TestListener::CS_COMPLETED);
        ASSERT_EQ(client_listener->connections[client_id].result, CCR_PASS);
        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);

        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    }

    void TearDown() override {
        tun.fake_upstream->close_session();
        tun.fake_upstream->deinit();
        dns_server.reset();
        TunnelTest::TearDown();
    }

    void do_dns_resolve() {
        uint64_t client_conn_id = vpn.listener_conn_id_generator.get();
        TunnelAddress resolver_address = SocketAddress("8.8.8.8:53");
        ClientConnectRequest event = {client_conn_id, IPPROTO_UDP, &src, &resolver_address};
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);

        std::optional<VpnConnectAction> action =
                tun.finalize_connect_action({client_conn_id, VPN_CA_DEFAULT, "some", 1});
        ASSERT_FALSE(!action.has_value());
        tun.complete_connect_request(client_conn_id, action);
        run_event_loop_once();

        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_conn_id);

        auto result = dns_utils::encode_request({.type = dns_utils::RT_A, .name = "localhost."});
        ASSERT_TRUE(std::holds_alternative<dns_utils::EncodedRequest>(result));
        auto &encoded = std::get<dns_utils::EncodedRequest>(result);
        ASSERT_GT(encoded.data.size(), 2);
        RAND_bytes(encoded.data.data(), 2);

        ClientRead client_read_event = {client_conn_id, encoded.data.data(), encoded.data.size(), 0};
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &client_read_event);
        ASSERT_EQ(client_read_event.result, int(encoded.data.size()));

        this->dns_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = "localhost."},
                .response = MockDnsServer::Response{.rcode = 0,
                        .answer = {AG_FMT("localhost. {} IN A 1.1.1.2", ANSWER_TTL_SEC)}},
        });

        vpn_event_loop_exit(this->ev_loop.get(), Millis{30000});
        vpn_event_loop_run(this->ev_loop.get());

        ASSERT_EQ(1, this->mock_dns_server_completed);
        ASSERT_EQ(0, this->mock_dns_server_unexpected);
    }
};

TEST_F(FakeConnectionTest, ExcludedDomain) {
    // 3) Receive client hello with bypassed domain and start the migration
    size_t size_before = bypass_upstream->connections.size();
    ClientRead read_event = {client_id, CLIENT_HELLO, std::size(CLIENT_HELLO), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
    ASSERT_EQ(read_event.result, 0) << "Buffer pointer must not be slid";
    ASSERT_GT(bypass_upstream->connections.size(), size_before);

    bypass_id = bypass_upstream->connections.back();
    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &bypass_id);

    ASSERT_EQ(fake_upstream->closing_connections.size(), 1);
    tun.fake_upstream->handler.func(
            tun.fake_upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &fake_upstream->closing_connections[0]);

    ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
}

TEST_F(FakeConnectionTest, ExcludedDomainWithAntiDpiImitation) {
    // 3) Receive client hello with bypassed domain and start the migration
    size_t size_before = bypass_upstream->connections.size();
    ClientRead read_event_first_fragment = {client_id, CLIENT_HELLO, 1, 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event_first_fragment);
    ASSERT_EQ(read_event_first_fragment.result, 1);

    ClientRead read_event_second_fragment = {client_id, CLIENT_HELLO + 1, std::size(CLIENT_HELLO) - 1, 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event_second_fragment);
    ASSERT_EQ(read_event_second_fragment.result, 0) << "Buffer pointer must not be slid";
    ASSERT_GT(bypass_upstream->connections.size(), size_before);

    bypass_id = bypass_upstream->connections.back();
    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &bypass_id);

    ASSERT_EQ(fake_upstream->closing_connections.size(), 1);
    tun.fake_upstream->handler.func(
            tun.fake_upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &fake_upstream->closing_connections[0]);

    // Read=off while buffered_packets is pending.
    ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
}

TEST_F(FakeConnectionTest, MissingDomain) {
    constexpr const char HTTP_REQUEST[] = "GET / HTTP/1.1\r\nAccept: text/html\r\n";

    // 3) Receive first HTTP request chunk without a domain name
    size_t size_before = redirect_upstream->connections.size();
    ClientRead read_event = {client_id, (uint8_t *) HTTP_REQUEST, std::size(HTTP_REQUEST), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
    ASSERT_EQ(read_event.result, 0) << "Buffer pointer must not be slid";
    ASSERT_GT(redirect_upstream->connections.size(), size_before);

    redirect_id = redirect_upstream->connections.back();
    tun.upstream_handler(redirect_upstream, SERVER_EVENT_CONNECTION_OPENED, &redirect_id);

    ASSERT_EQ(fake_upstream->closing_connections.size(), 1);
    tun.fake_upstream->handler.func(
            tun.fake_upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &fake_upstream->closing_connections[0]);

    ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
}

TEST_F(FakeConnectionTest, NonscannablePort) {
    client_id = vpn.listener_conn_id_generator.get();

    // 1) Raise the request for connection
    dst = SocketAddress("1.1.1.2:777");
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

    // 2) Establish the connection through VPN endpoint
    size_t size_before = redirect_upstream->connections.size();
    std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some", 1});
    ASSERT_FALSE(action.has_value());
    tun.complete_connect_request(client_id, action);
    ASSERT_GT(redirect_upstream->connections.size(), size_before);
    redirect_id = redirect_upstream->connections.back();

    tun.upstream_handler(redirect_upstream, SERVER_EVENT_CONNECTION_CLOSED, &redirect_id);
    ASSERT_EQ(client_listener->connections[client_id].state, TestListener::CS_COMPLETED);
    ASSERT_EQ(client_listener->connections[client_id].result, CCR_REJECT);
}

TEST_F(FakeConnectionTest, NonexcludedDomain) {
    constexpr const char HTTP_REQUEST[] = "GET / HTTP/1.1\r\nAccept: text/html\r\nHost: non-excluded\r\n";

    // 3) Receive HTTP request with non-excluded domain
    size_t size_before = redirect_upstream->connections.size();
    ClientRead read_event = {client_id, (uint8_t *) HTTP_REQUEST, std::size(HTTP_REQUEST), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
    ASSERT_EQ(read_event.result, 0) << "Buffer pointer must not be slid";
    ASSERT_GT(redirect_upstream->connections.size(), size_before);

    redirect_id = redirect_upstream->connections.back();
    tun.upstream_handler(redirect_upstream, SERVER_EVENT_CONNECTION_OPENED, &redirect_id);

    ASSERT_EQ(fake_upstream->closing_connections.size(), 1);
    tun.fake_upstream->handler.func(
            tun.fake_upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &fake_upstream->closing_connections[0]);

    ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
}

TEST_F(FakeConnectionTest, ExcludedBySelectiveMode) {
    ASSERT_TRUE(vpn.domain_filter.update_exclusions(VPN_MODE_SELECTIVE, "non-localhost"));

    // 3) Receive client hello with non-excluded domain
    size_t size_before = bypass_upstream->connections.size();
    ClientRead read_event = {client_id, CLIENT_HELLO, std::size(CLIENT_HELLO), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);

    ASSERT_GT(bypass_upstream->connections.size(), size_before);
    ASSERT_EQ(client_listener->connections.count(client_id), 1);
}

TEST_F(FakeConnectionTest, TTL) {
    std::this_thread::sleep_for(std::chrono::seconds(2 * ANSWER_TTL_SEC));

    client_id = vpn.listener_conn_id_generator.get();

    // 1) Raise the request for connection
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

    // 2) Establish the connection through VPN endpoint
    size_t size_before = redirect_upstream->connections.size();
    std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some", 1});
    ASSERT_EQ(action, VPN_CA_DEFAULT);
    tun.complete_connect_request(client_id, action);
    ASSERT_GT(redirect_upstream->connections.size(), size_before);
    redirect_id = redirect_upstream->connections.back();

    // 3) Target domain is bypassed, but TTL is over
    tun.upstream_handler(redirect_upstream, SERVER_EVENT_CONNECTION_CLOSED, &redirect_id);
    ASSERT_EQ(client_listener->connections[client_id].state, TestListener::CS_COMPLETED);
    ASSERT_EQ(client_listener->connections[client_id].result, CCR_REJECT);
}

static constexpr uint8_t HTTP3_IS_QUIC_CH[] =
        "\xca\x00\x00\x00\x01\x08" \
        "\x12\xea\xff\x04\xb8\x63\x53\x07\x03\xea\x5f\x00\x00\x42\x48\xd1" \
        "\x8a\x40\x44\x4f\xfb\x4f\x96\xe6\xb7\x3a\x74\x7b\xd5\x50\xf3\x6a" \
        "\x91\x8a\xab\x05\xec\x33\x5f\x55\x86\x7d\xfe\x7f\x07\xe3\x0b\xa1" \
        "\xd2\xf2\x64\x9d\x76\x70\x5f\x8a\xaf\x3a\x0c\xf5\xd7\x20\x1b\x93" \
        "\xaa\xb9\xf1\xea\x2a\x4a\xe0\x5b\x9e\x5b\xf6\xbf\xe7\x8c\xda\xe0" \
        "\xcf\x87\x1d\x29\x06\xd1\xe7\x9e\xaf\x18\xed\xc9\x2d\xbf\x73\x1c" \
        "\xa5\xea\x1a\x22\x96\xd4\xb4\x41\xa6\x9f\xc2\xf9\x04\x13\x58\xc9" \
        "\xbf\xab\x0d\x6b\x94\xa0\x93\x33\x3d\xe8\xbe\xf5\xbf\xba\x01\x35" \
        "\x22\x11\xce\x47\x34\x31\x0f\x21\x7e\xf5\x9c\xb3\xdd\x0e\x4f\xea" \
        "\x9e\xe5\x2b\x15\xc0\xc7\xc7\x31\x0e\xac\xe6\xbe\x73\xa3\x72\x41" \
        "\xa9\x6d\xd4\xa9\xa3\xea\x3d\x20\xe3\x97\x5b\x74\xbf\x13\xe6\x8e" \
        "\x53\x56\x2c\xf0\xb5\xc5\x49\x43\xbf\x78\x6f\x38\x51\x33\x91\x2a" \
        "\x85\x5e\xde\x1e\x26\xf7\x10\x4a\xa4\xa9\x48\x53\x55\x28\x47\x95" \
        "\x5a\x49\x9a\xc0\x63\xa3\x28\xde\x6d\x70\x23\x20\x7f\x25\x46\x6e" \
        "\x6b\xb7\x9b\x21\xf4\x00\x3e\xc5\xeb\x89\xf3\x7c\x82\x76\xa8\x3c" \
        "\x0a\x69\x3f\x8b\x5a\x96\xf3\x08\x8a\xe8\x3f\x2b\x8f\x2c\x8f\x83" \
        "\xa7\x0e\xad\x8d\xe1\xf5\x32\x19\x6f\xaf\x56\xcc\x02\xd9\x83\xae" \
        "\xda\x05\xc2\x4f\x35\xf4\x8f\x6a\xc6\x47\x30\x4a\xda\xd1\x0b\x23" \
        "\x42\x7a\x33\xc9\x40\x35\x9b\x59\x8e\x4b\x4b\xbf\x73\xa0\x26\x7a" \
        "\x41\xfb\xe0\x78\xb8\xa6\xc2\x6c\x34\x37\xe2\x26\xe5\x81\xf4\xdb" \
        "\x90\x7a\xe9\x94\x77\x8a\x6f\x09\xf8\x57\xea\x7e\x18\x64\x17\x7f" \
        "\xfa\xb5\xb0\x64\xb3\x37\x04\x24\x2a\x99\xfe\x82\x62\x05\x37\x83" \
        "\x92\x1d\xd1\x47\x19\x22\x19\xdd\x63\x55\x5d\x04\xaf\x84\x65\x08" \
        "\xe2\x12\xe1\xb1\x74\xbb\xb5\x21\xc5\x49\x4c\xc7\x5e\xb1\x72\xe8" \
        "\xb4\x0b\xdb\xe9\xe1\x32\x6f\x96\xfa\x2b\xc1\x88\xe5\x0b\x78\x0b" \
        "\x82\x6d\x23\x80\x70\xeb\xb6\xe0\x22\x06\x02\xed\xa7\x5e\xd6\xcc" \
        "\x4b\x0f\xa5\xe5\x82\x58\xd9\x0e\x2b\x0e\x17\x37\x13\x65\x01\xb7" \
        "\x3a\xf9\xe9\xe2\xe0\x21\x74\xfa\x54\x76\x31\x59\x76\x20\x34\xb9" \
        "\x93\xf6\x96\xea\xdf\xbb\x77\xf6\x0d\x82\x3c\xe6\x03\x9c\xeb\x15" \
        "\x32\x1f\x09\xd1\xbb\x3c\xaa\x93\xaa\xe5\x96\xb2\x0b\x8b\x3b\x93" \
        "\xc6\xfe\x63\x6f\x4c\xd0\x74\x71\x82\x27\x35\x4f\x8e\x2e\x5b\x4e" \
        "\x2e\x07\xd2\x4e\xd0\xa6\xc9\x7a\xaa\x64\x60\xa2\xde\x6e\xa5\xb6" \
        "\x28\x98\xe3\x63\xe6\xbc\x12\x38\xb9\x2b\xeb\x5c\xf0\xbe\xf7\x6f" \
        "\x4d\x0a\xbd\x5c\xac\x45\xdd\x5e\x77\x70\xd8\xce\xbe\x91\xd8\x85" \
        "\x74\xc5\x5a\xc9\x93\x18\x51\x92\xb7\xe1\x77\x62\x39\xe1\xf7\xf7" \
        "\x1d\xb7\x1b\xbc\x92\xce\x23\x81\x86\x1a\x4f\x4f\x37\x3e\x06\x3c" \
        "\x1f\x78\x40\x9f\xa4\xdd\xe3\x5c\xb4\x34\x9e\x84\x31\x25\xc2\x9c" \
        "\x7f\xdf\x94\xc3\x3c\x10\x35\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00";

static constexpr uint8_t HTTP3_IS_QUIC_SHORT_PKT[] =
        "\x28\x87\xba\x31\x1e\x2e\xbc\xd0\x74\x5c\x48\x08\x08\x00\x45\x00" \
        "\x01\x26\x00\x00\x40\x00\x40\x11\x16\x72\x0a\x2a\x00\x6b\x97\x65" \
        "\x81\x5b\xdd\x51\x01\xbb\x01\x12\xd0\x23\x7e\x1f\xa3\x34\xfe\x47" \
        "\xe8\xa4\xcc\xe9\x7e\xf2\x7a\x42\xb1\x8e\x38\xb9\x5a\xc9\xfb\x18" \
        "\xd0\x87\xab\x2f\xe0\xca\x8a\xc1\x0a\x26\x78\x1f\xf9\x60\x0d\xda" \
        "\x42\x72\xdc\x31\x58\x73\xb1\x24\x19\xc1\x8c\x95\x2b\x49\x9a\xc1" \
        "\x0a\x34\xeb\xb9\xd8\x52\x73\xf1\x91\xf1\xa7\xae\xb6\xaf\x49\x22" \
        "\x91\xe7\x70\xd3\x27\xb7\xff\xdd\x4d\xe8\x1b\x7c\xb5\xa0\x43\xc9" \
        "\x23\x45\xe2\x83\x4d\x8f\x96\x63\xb2\xaa\xc0\x8c\x7f\xcd\xa7\x1a" \
        "\x42\x97\xfd\x6e\x86\x48\xf9\xdf\x08\x72\x79\x50\x07\x03\x54\xe7" \
        "\xa7\x48\xcc\xfe\x9f\x13\xd2\x0e\xb8\xa8\x67\x96\x8d\xd6\x4f\x77" \
        "\x4a\x09\x7a\x1e\xd1\x8b\x68\x0b\x7f\x47\xad\xd2\xbe\x26\x31\xb3" \
        "\x93\xc9\x20\x1a\x3f\xda\xf4\xc5\xda\xf1\x83\xfd\xaf\x72\xa1\x66" \
        "\xba\x58\x39\x97\x81\xd9\x7c\x4f\xe0\x26\x9c\xcb\x0d\x48\x25\x56" \
        "\x63\x12\x4d\x2c\xa6\x3b\xe1\x7a\x4e\x1f\x3e\xd3\xd2\x0c\x78\x4b" \
        "\x5b\x75\x14\x63\x15\x72\xce\xe2\x9e\x2f\xe4\xb5\x21\x8c\x34\x24" \
        "\xf0\xe1\x22\xce\xfc\x4e\x6f\xbd\xc4\x03\xbe\xfa\x40\x77\x78\xc3" \
        "\x8e\xe1\x0e\xdb\x43\xf2\x02\x7d\xef\xd8\x30\xe1\x81\xd3\x20\x1a" \
        "\x74\x8e\x18\x2f\xc8\xc4\x33\x2d\xf2\xff\x54\x56\x26\xa9\x98\x7c" \
        "\xde\x16\xa9\x2e";

class UdpRebindingTest : public TunnelTest {
public:
    uint64_t client_id = NON_ID;
    TestFakeUpstream *fake_upstream = nullptr;

    void SetUp() override {
        connection_protocol = IPPROTO_UDP;
        TunnelTest::SetUp();

        tun.fake_upstream = std::make_shared<TestFakeUpstream>(std::move(tun.fake_upstream));
        ASSERT_TRUE(tun.fake_upstream->open_session());
        this->fake_upstream = (TestFakeUpstream *) tun.fake_upstream.get();

        ASSERT_TRUE(vpn.domain_filter.update_exclusions(VPN_MODE_SELECTIVE, "http3.is"));
        vpn.domain_filter.add_exclusion_suspect(std::get<SocketAddress>(dst), Secs{500});
    }
};

TEST_F(UdpRebindingTest, CachedUdpParams) {
    static const std::shared_ptr<WithMtx<LruTimeoutCache<TunnelAddressPair, DomainLookuperResult>>> cache{
            new WithMtx<LruTimeoutCache<TunnelAddressPair, DomainLookuperResult>>{
                    .val {300, Secs (300)}
            }
    };

    tun.udp_close_wait_hostname_cache = cache;

    // 1) Raise the request for connection
    client_id = vpn.listener_conn_id_generator.get();
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));
    std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some2", 1});
    tun.complete_connect_request(client_id, action);
    run_event_loop_once();

    {
        // 3) Receive client hello with non-excluded domain
        size_t size_before = redirect_upstream->connections.size();
        ClientRead read_event = {client_id, HTTP3_IS_QUIC_CH, sizeof(HTTP3_IS_QUIC_CH) - 1, 0};
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);

        ASSERT_GT(redirect_upstream->connections.size(), size_before);
        ASSERT_EQ(client_listener->connections.count(client_id), 1);
    }

    size_t cache_size = cache->val.size();

    tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_CLOSED, &client_id);
    run_event_loop_once();

    ASSERT_EQ(1, fake_upstream->closing_connections.size());
    tun.fake_upstream->handler.func(
            tun.fake_upstream->handler.arg, SERVER_EVENT_CONNECTION_CLOSED, &fake_upstream->closing_connections[0]);

    client_id = ~0;

    ASSERT_EQ(cache_size + 1, cache->val.size());

    // 1) Raise the request for connection
    client_id = vpn.listener_conn_id_generator.get();
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));
    action = tun.finalize_connect_action({client_id, VPN_CA_DEFAULT, "some3", 1});
    tun.complete_connect_request(client_id, action);
    run_event_loop_once();

    {
        // 3) Receive client hello with non-excluded domain
        size_t size_before = redirect_upstream->connections.size();
        ClientRead read_event = {client_id, HTTP3_IS_QUIC_SHORT_PKT, sizeof(HTTP3_IS_QUIC_SHORT_PKT) - 1, 0};
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);

        ASSERT_GT(redirect_upstream->connections.size(), size_before);
        ASSERT_EQ(client_listener->connections.count(client_id), 1);
    }
}
