#include <optional>
#include <thread>

#include <gtest/gtest.h>

#include "common/net_utils.h"
#include "fake_upstream.h"
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
    VpnError do_health_check() override {
        return {};
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
    sockaddr_storage src{};
    TunnelAddress dst;
    TestUpstream *redirect_upstream = nullptr;
    TestUpstream *bypass_upstream = nullptr;
    TestListener *client_listener = nullptr;
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

        src = sockaddr_from_str("1.1.1.1:1000");
        dst = sockaddr_from_str("1.1.1.2:443");

        vpn.parameters.handler = {&vpn_handler, this};
        vpn.parameters.network_manager = network_manager.get();

        vpn.endpoint_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(vpn.endpoint_upstream->init(&vpn, {&redirect_upstream_handler, this}));
        redirect_upstream = (TestUpstream *) vpn.endpoint_upstream.get();
        vpn.bypass_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(vpn.bypass_upstream->init(&vpn, {&bypass_upstream_handler, this}));
        bypass_upstream = (TestUpstream *) vpn.bypass_upstream.get();

        vpn.client_listener = std::make_unique<TestListener>();
        ASSERT_EQ(ClientListener::InitResult::SUCCESS, vpn.client_listener->init(&vpn, {&listener_handler, this}));
        client_listener = (TestListener *) vpn.client_listener.get();

        ASSERT_TRUE(tun.init(&vpn));

        tun.upstream_handler(vpn.endpoint_upstream.get(), SERVER_EVENT_SESSION_OPENED, nullptr);
    }

    void TearDown() override {
        tun.deinit();
    }

    void raise_client_connection(uint64_t id) {
        ClientConnectRequest event = {id, connection_protocol, (sockaddr *) &src, &dst};
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
        ASSERT_EQ(g_last_raised_vpn_event, vpn_client::EVENT_CONNECT_REQUEST);
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }
};

TEST_F(TunnelTest, IPv6Unavailable) {
    src = sockaddr_from_str("[::1:1:1:1]:443");
    vpn.endpoint_upstream->update_ip_availability(IpVersionSet{1 << IPV4});
    size_t client_id = vpn.listener_conn_id_generator.get();

    dst = sockaddr_from_str("[::2:2:2:2]:443");
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
    dst = sockaddr_from_str("127.0.0.1:443");
    ClientConnectRequest event = {client_id, connection_protocol, (sockaddr *) &src, &dst};
    tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
    ASSERT_GT(bypass_upstream->connections.size(), 0);
}

TEST_F(TunnelTest, SelectiveDisconnectedClientExclusion) {
    ASSERT_TRUE(vpn.domain_filter.update_exclusions(VPN_MODE_SELECTIVE, "localhost"));

    // Simulate not yet connected state
    vpn.endpoint_upstream.reset();

    uint64_t client_id = vpn.listener_conn_id_generator.get();
    ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

    ConnectRequestResult result = {client_id, VPN_CA_DEFAULT, "some", 1};
    std::optional<VpnConnectAction> action = tun.finalize_connect_action(result);
    tun.complete_connect_request(client_id, action);
    ASSERT_EQ(bypass_upstream->connections.size(), 1);
    uint64_t upstream_id = bypass_upstream->connections.back();

    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &upstream_id);
    ASSERT_EQ(client_listener->connections[client_id].state, TestListener::CS_COMPLETED);

    ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
    tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
    ASSERT_TRUE(client_listener->connections[client_id].read_enabled);

    ClientRead read_event = {client_id, CLIENT_HELLO, std::size(CLIENT_HELLO), 0};
    tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
    ASSERT_EQ(bypass_upstream->connections.size(), 1);
    ASSERT_LT(read_event.result, 0);
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

    explicit TestFakeUpstream(std::unique_ptr<ServerUpstream> orig)
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

    void SetUp() override {
        TunnelTest::SetUp();

        tun.fake_upstream = std::make_unique<TestFakeUpstream>(std::move(tun.fake_upstream));
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
        TunnelTest::TearDown();
    }

    void do_dns_resolve() {
        uint64_t client_conn_id = vpn.listener_conn_id_generator.get();
        TunnelAddress resolver_address = sockaddr_from_str("8.8.8.8:53");
        ClientConnectRequest event = {client_conn_id, IPPROTO_UDP, (sockaddr *) &src, &resolver_address};
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);

        size_t size_before = bypass_upstream->connections.size();
        std::optional<VpnConnectAction> action = tun.finalize_connect_action({client_conn_id, VPN_CA_DEFAULT, "some", 1});
        ASSERT_FALSE(!action.has_value());
        tun.complete_connect_request(client_conn_id, action);
        run_event_loop_once();

        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_conn_id);

        static constexpr uint8_t DNS_QUERY[] = {0x21, 0xfd, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
                0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x08, 0x45, 0x0a, 0xff, 0x02,
                0xb9, 0x8b, 0xb4, 0x10};

        ClientRead client_read_event = {client_conn_id, DNS_QUERY, std::size(DNS_QUERY), 0};
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &client_read_event);
        ASSERT_EQ(client_read_event.result, int(std::size(DNS_QUERY)));

        ASSERT_GT(bypass_upstream->connections.size(), size_before);
        uint64_t upstream_conn_id = bypass_upstream->connections.back();
        tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &upstream_conn_id);
        ASSERT_EQ(client_listener->connections[client_conn_id].state, TestListener::CS_COMPLETED);
        ASSERT_EQ(client_listener->connections[client_conn_id].result, CCR_PASS);

        static constexpr uint8_t DNS_REPLY[] = {0x21, 0xfd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c,
                0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, ANSWER_TTL_SEC, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02, 0x00,
                0x00, 0x29, 0xff, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        ServerReadEvent upstream_read_event = {upstream_conn_id, DNS_REPLY, std::size(DNS_REPLY), 0};
        tun.upstream_handler(redirect_upstream, SERVER_EVENT_READ, &upstream_read_event);
        ASSERT_EQ(upstream_read_event.result, int(std::size(DNS_REPLY)));

        run_event_loop_once();
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
    dst = sockaddr_from_str("1.1.1.2:777");
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
