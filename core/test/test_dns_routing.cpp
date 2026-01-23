#include <algorithm>
#include <optional>
#include <tuple>

#include <gtest/gtest.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/rand.h>

#include "common/utils.h"
#include "net/dns_utils.h"
#include "test_mock_vpn_client.h"
#include "vpn/internal/tunnel.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_connection.h"

#include "mock_dns_server.h"

#include <socks_listener.h>

using namespace ag; // NOLINT(google-build-using-namespace)

constexpr auto DEFAULT_EVENT_LOOP_EXIT_TIMEOUT = ag::Millis{100};
constexpr auto DEFAULT_TIMEOUT = ag::Millis{30000};

static int cert_verify_handler(
        const char * /*host_name*/, const sockaddr * /*host_ip*/, const CertVerifyCtx & /*ctx*/, void * /*arg*/) {
    return 1;
}

class TestUpstream : public ServerUpstream {
public:
    static inline int g_next_upstream_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

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
        return ssize_t(length);
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
        std::optional<std::vector<uint8_t>> last_send;
    };

    std::unordered_map<size_t, Connection> connections;
    std::unordered_map<size_t, Connection> closed_connections;

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
        closed_connections.insert(connections.extract(id));
        handler.func(handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);
    }

    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override {
        if (auto it = connections.find(id); it != connections.end()) {
            it->second.last_send.emplace(data, data + length);
        }
        return ssize_t(length);
    }

    void consume(uint64_t id, size_t n) override {
    }
    TcpFlowCtrlInfo flow_control_info(uint64_t) override {
        return {
                .send_buffer_size = size_t(DEFAULT_SEND_BUFFER_SIZE),
                .send_window_size = size_t(DEFAULT_SEND_WINDOW_SIZE),
        };
    }
    void turn_read(uint64_t id, bool on) override {
        if (connections.contains(id)) {
            connections[id].read_enabled = on;
        }
    }
    int process_client_packets(VpnPackets) override {
        return 0;
    }
};

using Exclusion = std::string_view;
using CheckedDomain = std::string_view;
using TestSample = std::tuple<VpnMode, VpnConnectAction, Exclusion, CheckedDomain>;
class DnsRouting : public testing::TestWithParam<TestSample> {
public:
    DnsRouting()
            : vpn({
                      .ev_loop = this->ev_loop.get(),
              }) {
        Logger::set_log_level(LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    VpnClient vpn;
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    SocketAddress src = SocketAddress("1.1.1.1:42");
    TunnelAddress dst = SocketAddress("2.2.2.2:53");
    std::shared_ptr<TestUpstream> redirect_upstream;
    std::shared_ptr<TestUpstream> bypass_upstream;
    std::shared_ptr<TestListener> client_listener;
    uint64_t client_id = vpn.listener_conn_id_generator.get();
    static inline std::optional<vpn_client::Event>
            g_last_raised_vpn_event; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    std::unique_ptr<MockDnsServer> mock_system_dns_server = std::make_unique<MockDnsServer>();
    int system_complete = 0;
    int system_unexpected = 0;

    static void vpn_handler(void *, vpn_client::Event what, void *) {
        g_last_raised_vpn_event = what;
    }

    static void redirect_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->vpn.tunnel->upstream_handler(test->redirect_upstream, what, data);
    }

    static void bypass_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->vpn.tunnel->upstream_handler(test->bypass_upstream, what, data);
    }

    static void listener_handler(void *arg, ClientEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->vpn.tunnel->listener_handler(test->client_listener, what, data);
    }

    void SetUp() override {
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

        ASSERT_TRUE(vpn.tunnel->init(&vpn));
        vpn.tunnel->upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);

        auto system_address = mock_system_dns_server->start(
                SocketAddress("127.0.0.1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_complete;
                },
                [this](std::optional<MockDnsServer::Request>, MockDnsServer::Request) {
                    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(system_address.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        vpn_network_manager_update_system_dns({.main = {{.address = system_address->str()}}});
        run_event_loop_once();
    }

    void TearDown() override {
        vpn.tunnel->deinit();
        g_last_raised_vpn_event.reset();
        mock_system_dns_server.reset();
    }

    void raise_client_connection(uint64_t id) {
        ClientConnectRequest event = {id, IPPROTO_UDP, &src, &dst};
        vpn.tunnel->listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
        ASSERT_EQ(g_last_raised_vpn_event, vpn_client::EVENT_CONNECT_REQUEST);
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }

    void raise_dns_request(std::string_view domain) {
        dns_utils::EncodeResult encode_result = dns_utils::encode_request({dns_utils::RT_A, domain});
        ASSERT_TRUE(std::holds_alternative<dns_utils::EncodedRequest>(encode_result)) << encode_result.index();

        const auto &request = std::get<dns_utils::EncodedRequest>(encode_result);
        ClientRead read_event = {client_id, request.data.data(), std::size(request.data), 0};
        vpn.tunnel->listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
        ASSERT_EQ(read_event.result, int(std::size(request.data)));
    }

    void open_connection() {
        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        std::optional<VpnConnectAction> action = vpn.tunnel->finalize_connect_action({
                .id = client_id,
                .action = VPN_CA_DEFAULT,
                .appname = "some",
                .uid = 1,
        });
        ASSERT_EQ(action, VPN_CA_DEFAULT);
        vpn.tunnel->complete_connect_request(client_id, action);
        run_event_loop_once();

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        vpn.tunnel->listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    }
};

class NoProxy : public DnsRouting {};

TEST_P(NoProxy, Test) {
    auto [mode, action, exclusion, domain] = GetParam();
    vpn.update_exclusions(mode, exclusion);

    ASSERT_NO_FATAL_FAILURE(open_connection());
    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    if ((mode == VPN_MODE_GENERAL && exclusion == domain) || (mode == VPN_MODE_SELECTIVE && exclusion != domain)) {
        this->mock_system_dns_server->expect({
                .request =
                        MockDnsServer::Request{
                                .tcp = false,
                                .qtype = 1,
                                .qname = AG_FMT("{}.", domain),
                        },
        });
        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        ASSERT_EQ(1, this->system_complete);
        ASSERT_EQ(0, this->system_unexpected);
        ASSERT_EQ(0, redirect_upstream->connections.size());
    } else {
        run_event_loop_once();
        ASSERT_EQ(1, redirect_upstream->connections.size());
    }

    ASSERT_EQ(0, bypass_upstream->connections.size());
}

INSTANTIATE_TEST_SUITE_P(DnsRouting, NoProxy,
        testing::Combine(testing::Values(VPN_MODE_GENERAL, VPN_MODE_SELECTIVE), testing::Values(VPN_CA_DEFAULT),
                testing::Values("example.com"), testing::Values("example.com", "github.com")));

class AppInitiatedDnsRouting : public DnsRouting {
public:
    void SetUp() override {
        DnsRouting::SetUp();
        vpn.kill_switch_on = true;
        vpn.tunnel->on_before_endpoint_disconnect(redirect_upstream.get());
        vpn.tunnel->upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_CLOSED, nullptr);
        vpn.tunnel->on_after_endpoint_disconnect(redirect_upstream.get());
        vpn_network_manager_notify_app_request_domain("forward-to-system.example.com", -1);
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    void TearDown() override {
        vpn_network_manager_notify_app_request_domain("forward-to-system.example.com", 0);

        DnsRouting::TearDown();
    }
};

TEST_F(AppInitiatedDnsRouting, MatchingDomain) {
    ASSERT_NO_FATAL_FAILURE(raise_dns_request("forward-to-system.example.com"));
    this->mock_system_dns_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = "forward-to-system.example.com."},
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    ASSERT_EQ(1, this->system_complete);
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, bypass_upstream->connections.size());
    ASSERT_EQ(0, redirect_upstream->connections.size());
}

TEST_F(AppInitiatedDnsRouting, NonMatchingDomain) {
    constexpr auto TIMEOUT = ag::Millis{1000};
    ASSERT_NO_FATAL_FAILURE(raise_dns_request("example.org"));
    vpn_event_loop_exit(this->ev_loop.get(), TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    ASSERT_EQ(0, this->system_complete);
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, bypass_upstream->connections.size());
    ASSERT_EQ(0, redirect_upstream->connections.size());
}

class CustomDnsRouting : public DnsRouting {
public:
    void SetUp() override {
        vpn.parameters.cert_verify_handler = {&cert_verify_handler, this};
        vpn.parameters.handler = {&vpn_handler, this};
        vpn.parameters.network_manager = network_manager.get();

        redirect_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(redirect_upstream->init(&vpn, {&redirect_upstream_handler, this}));
        vpn.endpoint_upstream = redirect_upstream;
        bypass_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(bypass_upstream->init(&vpn, {&bypass_upstream_handler, this}));
        vpn.bypass_upstream = bypass_upstream;

        auto system_address = mock_system_dns_server->start(
                SocketAddress("127.0.0.1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_complete;
                },
                [this](std::optional<MockDnsServer::Request>, MockDnsServer::Request) {
                    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(system_address.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        vpn_network_manager_update_system_dns({.main = {{.address = system_address->str()}}});
        run_event_loop_once();
    }

    void open_connection(VpnConnectAction callback_action, VpnConnectAction expected_action) {
        client_listener = std::make_unique<TestListener>();
        ASSERT_EQ(ClientListener::InitResult::SUCCESS, client_listener->init(&vpn, {&listener_handler, this}));
        vpn.client_listener = client_listener;

        ASSERT_TRUE(vpn.tunnel->init(&vpn));
        vpn.tunnel->upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);

        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        std::optional<VpnConnectAction> action = vpn.tunnel->finalize_connect_action({
                .id = client_id,
                .action = callback_action,
                .appname = "some",
                .uid = 1,
        });
        ASSERT_EQ(action, expected_action);
        vpn.tunnel->complete_connect_request(client_id, action);
        run_event_loop_once();

        if (action == VPN_CA_FORCE_BYPASS) {
            ASSERT_FALSE(bypass_upstream->connections.empty());
            vpn.tunnel->upstream_handler(
                    bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &bypass_upstream->connections.back());
        } else if (action == VPN_CA_FORCE_REDIRECT) {
            ASSERT_FALSE(redirect_upstream->connections.empty());
            vpn.tunnel->upstream_handler(
                    redirect_upstream, SERVER_EVENT_CONNECTION_OPENED, &redirect_upstream->connections.back());
        }

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        vpn.tunnel->listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    }
};

class DnsAddressExcluded : public CustomDnsRouting {};

TEST_P(DnsAddressExcluded, CheckCreatedUpstreams) {
    auto [mode, action, exclusion, domain] = GetParam();

    vpn.update_exclusions(mode, exclusion);

    ASSERT_NO_FATAL_FAILURE(open_connection(action, action));
    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    if ((mode == VPN_MODE_GENERAL && exclusion.find(domain) != exclusion.npos)
            || (mode == VPN_MODE_SELECTIVE && exclusion.find(domain) == exclusion.npos)) {
        this->mock_system_dns_server->expect({
                .request =
                        MockDnsServer::Request{
                                .tcp = false,
                                .qtype = 1,
                                .qname = AG_FMT("{}.", domain),
                        },
        });
        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        ASSERT_EQ(1, this->system_complete);
        ASSERT_EQ(0, this->system_unexpected);
        ASSERT_EQ(0, redirect_upstream->connections.size());
    } else {
        run_event_loop_once();
        ASSERT_EQ(1, redirect_upstream->connections.size());
    }

    ASSERT_EQ(0, bypass_upstream->connections.size());
}

INSTANTIATE_TEST_SUITE_P(DnsAddressExcluded, DnsAddressExcluded,
        testing::Values(std::make_tuple(VPN_MODE_GENERAL, VPN_CA_DEFAULT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_DEFAULT, "2.2.2.2/32 example.com", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_DEFAULT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_DEFAULT, "2.2.2.2/32 example.com", "example.com")));

class DnsRoutingCustomAction : public CustomDnsRouting {};

TEST_P(DnsRoutingCustomAction, CheckCreatedUpstreams) {
    auto [mode, action, exclusion, domain] = GetParam();

    vpn.update_exclusions(mode, exclusion);

    ASSERT_NO_FATAL_FAILURE(open_connection(action, action));
    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    if (action == VPN_CA_FORCE_BYPASS) {
        ASSERT_EQ(bypass_upstream->connections.size(), 1);
        ASSERT_EQ(redirect_upstream->connections.size(), 0);
    } else if (action == VPN_CA_FORCE_REDIRECT) {
        ASSERT_EQ(redirect_upstream->connections.size(), 1);
        ASSERT_EQ(bypass_upstream->connections.size(), 0);
    }
}

INSTANTIATE_TEST_SUITE_P(CustomAction, DnsRoutingCustomAction,
        testing::Values(std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_REDIRECT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_BYPASS, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_REDIRECT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_BYPASS, "2.2.2.2/32", "example.com"),

                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_REDIRECT, "", "example.com"),
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_BYPASS, "", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_REDIRECT, "", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_BYPASS, "", "example.com"),

                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_REDIRECT, "example.com", "example.com"),
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_BYPASS, "example.com", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_REDIRECT, "example.com", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_BYPASS, "example.com", "example.com")));

struct DnsRoutingAllProxies : public ::testing::Test {
    int user_complete = 0;
    int user_unexpected = 0;

    int system_complete = 0;
    int system_unexpected = 0;

    int system_ipv6_complete = 0;
    int system_ipv6_unexpected = 0;

    std::unique_ptr<MockDnsServer> user_server = std::make_unique<MockDnsServer>();
    std::unique_ptr<MockDnsServer> system_server = std::make_unique<MockDnsServer>();
    std::unique_ptr<MockDnsServer> system_ipv6_server = std::make_unique<MockDnsServer>();

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    VpnClient vpn;
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    std::shared_ptr<TestUpstream> redirect_upstream;
    std::shared_ptr<TestUpstream> bypass_upstream;
    std::shared_ptr<TestListener> client_listener;

    std::optional<vpn_client::Event> last_raised_vpn_event;

    event_loop::AutoTaskId exit_task;

    DnsRoutingAllProxies()
            : vpn({.ev_loop = this->ev_loop.get()}) {
        Logger::set_log_level(LOG_LEVEL_TRACE);
    }

    void schedule_exit(Millis timeout) {
        exit_task = event_loop::schedule(
                this->ev_loop.get(),
                [this] {
                    vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
                },
                timeout);
    }

    static void vpn_handler(void *arg, vpn_client::Event what, void *) {
        auto *test = (DnsRoutingAllProxies *) arg;
        test->last_raised_vpn_event = what;
    }

    static void redirect_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRoutingAllProxies *) arg;
        test->vpn.tunnel->upstream_handler(test->redirect_upstream, what, data);
    }

    static void bypass_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRoutingAllProxies *) arg;
        test->vpn.tunnel->upstream_handler(test->bypass_upstream, what, data);
    }

    static void listener_handler(void *arg, ClientEvent what, void *data) {
        auto *test = (DnsRoutingAllProxies *) arg;
        test->vpn.tunnel->listener_handler(test->client_listener, what, data);
    }

    static void dns_proxy_listener_handler(void *arg, ClientEvent what, void *data) {
        auto *test = (DnsRoutingAllProxies *) arg;
        test->vpn.tunnel->listener_handler(test->vpn.dns_proxy_listener, what, data);
    }

    void SetUp() override {
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

        VpnSocksListenerConfig dns_listener_config{};
        vpn.dns_proxy_listener = std::make_unique<SocksListener>(&dns_listener_config);
        ASSERT_EQ(ClientListener::InitResult::SUCCESS,
                vpn.dns_proxy_listener->init(&vpn, {&dns_proxy_listener_handler, this}));
        auto user_server_addr = user_server->start(
                SocketAddress("127.0.0.1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->user_complete;
                },
                [this](std::optional<MockDnsServer::Request> expected, MockDnsServer::Request actual) {
                    if (expected) {
                        fputs(AG_FMT("Expected: tcp: {}, qtype: {}, qname: {}, got: tcp: {}, qtype: {}, qname: {}\n",
                                      expected->tcp, expected->qtype, expected->qname, actual.tcp, actual.qtype,
                                      actual.qname)
                                        .c_str(),
                                stderr);
                    } else {
                        fputs(AG_FMT("Expected: none, got: tcp: {}, qtype: {}, qname: {}\n", actual.tcp, actual.qtype,
                                      actual.qname)
                                        .c_str(),
                                stderr);
                    }
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->user_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(user_server_addr.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        std::string user_server_addr_str = user_server_addr->str();
        const char *upstream = user_server_addr_str.c_str();
        VpnListenerConfig listener_config{.dns_upstreams = {.data = &upstream, .size = 1}};
        vpn.listener_config = vpn_listener_config_clone(&listener_config);
        vpn.parameters.cert_verify_handler = {
                .func = [](const char *, const sockaddr *, const CertVerifyCtx &, void *) {
                    return 1;
                }};

        ASSERT_TRUE(vpn.tunnel->init(&vpn));
        vpn.tunnel->upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);

        auto system_server_addr = system_server->start(
                SocketAddress("127.0.0.1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_complete;
                },
                [this](std::optional<MockDnsServer::Request>, MockDnsServer::Request) {
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(system_server_addr.has_value());
        auto system_server_ipv6_addr = system_ipv6_server->start(
                SocketAddress("::1"), this->ev_loop.get(), this->network_manager->socket,
                [this] {
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_ipv6_complete;
                },
                [this](std::optional<MockDnsServer::Request>, MockDnsServer::Request) {
                    this->schedule_exit(DEFAULT_EVENT_LOOP_EXIT_TIMEOUT);
                    ++this->system_ipv6_unexpected;
                    return std::nullopt;
                });
        ASSERT_TRUE(system_server_ipv6_addr.has_value());

        // NOLINTBEGIN(bugprone-unchecked-optional-access)
        vpn_network_manager_update_system_dns({
                .main =
                        {
                                {.address = system_server_addr->str()},
                                {.address = system_server_ipv6_addr->str()},
                        },
        });
        // NOLINTEND(bugprone-unchecked-optional-access)

        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }

    void raise_and_complete(ClientConnectRequest event) {
        vpn.tunnel->listener_handler(this->vpn.client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
        ASSERT_EQ(last_raised_vpn_event, vpn_client::EVENT_CONNECT_REQUEST);
        vpn.tunnel->complete_connect_request(event.id,
                vpn.tunnel->finalize_connect_action({
                        .id = event.id,
                        .action = VPN_CA_DEFAULT,
                        .appname = "TestAppName",
                }));
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }

    void accept_and_send(ClientConnectRequest event, std::string qname, ldns_rr_type qtype) {
        vpn.tunnel->listener_handler(this->vpn.client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &event.id);

        ldns_pkt *qpkt;
        ASSERT_EQ(LDNS_STATUS_OK, ldns_pkt_query_new_frm_str(&qpkt, qname.c_str(), qtype, LDNS_RR_CLASS_IN, LDNS_RD));
        dns_utils::LdnsPktPtr qpkt_ptr{qpkt};
        dns_utils::LdnsBufferPtr qbuffer = dns_utils::encode_pkt(qpkt);
        ASSERT_TRUE(qbuffer);
        Uint8Span request{ldns_buffer_begin(qbuffer.get()), ldns_buffer_position(qbuffer.get())};

        ASSERT_GT(request.size(), 2);
        RAND_bytes(request.data(), 2);
        if (event.protocol == IPPROTO_TCP) {
            ASSERT_LE(request.size(), UINT16_MAX);
            uint16_t size = request.size();
            size = htons(size);
            ClientRead read{.id = event.id, .data = (uint8_t *) &size, .length = sizeof(size)};
            vpn.tunnel->listener_handler(this->vpn.client_listener, CLIENT_EVENT_READ, &read);
            ASSERT_EQ(read.result, int(read.length));
        }
        ClientRead read{.id = event.id, .data = request.data(), .length = request.size()};
        vpn.tunnel->listener_handler(this->vpn.client_listener, CLIENT_EVENT_READ, &read);
        ASSERT_EQ(read.result, int(read.length));
    }

    void TearDown() override {
        system_ipv6_server.reset();
        system_server.reset();
        user_server.reset();
        vpn.tunnel->deinit();
        vpn.dns_proxy_listener->deinit();
    }
};

TEST_F(DnsRoutingAllProxies, IpVersionsSystem) {
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    TunnelAddress dst_v6 = SocketAddress("[2001:4860:4860::8888]:53");
    SocketAddress src("127.0.0.1:50001");
    SocketAddress src_v6("[::1]:50002");

    vpn.update_exclusions(VPN_MODE_GENERAL, "*.example.org *.example.com");

    int i = 0;
    int j = 0;
    for (const char *dname : {"example.org", "example.com"}) {
        int complete_before = system_complete;
        int complete_v6_before = system_ipv6_complete;

        ClientConnectRequest udp_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_UDP,
                .src = &src,
                .dst = &dst,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
        ClientConnectRequest tcp_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_TCP,
                .src = &src,
                .dst = &dst,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(tcp_event));
        ClientConnectRequest udp6_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_UDP,
                .src = &src_v6,
                .dst = &dst_v6,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp6_event));
        ClientConnectRequest tcp6_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_TCP,
                .src = &src_v6,
                .dst = &dst_v6,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(tcp6_event));

        std::string udp_event_name = AG_FMT("{}.{}.", j++, dname);
        std::string udp6_event_name = AG_FMT("{}.{}.", j++, dname);

        ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, udp_event_name, LDNS_RR_TYPE_A));
        ASSERT_NO_FATAL_FAILURE(accept_and_send(udp6_event, udp6_event_name, LDNS_RR_TYPE_A));

        system_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = udp_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", udp_event_name, i++)},
                        },
        });
        system_ipv6_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = udp6_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", udp6_event_name, i++)},
                        },
        });

        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        vpn_event_loop_finalize_exit(this->ev_loop.get());

        ASSERT_EQ(0, system_unexpected);
        ASSERT_EQ(0, system_ipv6_unexpected);
        ASSERT_EQ(complete_before + 1, system_complete);
        ASSERT_EQ(complete_v6_before + 1, system_ipv6_complete);

        std::string tcp_event_name = AG_FMT("{}.{}.", j++, dname);
        std::string tcp6_event_name = AG_FMT("{}.{}.", j++, dname);

        ASSERT_NO_FATAL_FAILURE(accept_and_send(tcp_event, tcp_event_name, LDNS_RR_TYPE_A));
        ASSERT_NO_FATAL_FAILURE(accept_and_send(tcp6_event, tcp6_event_name, LDNS_RR_TYPE_A));

        system_server->expect({
                .request = MockDnsServer::Request{.tcp = true, .qtype = 1, .qname = tcp_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", tcp_event_name, i++)},
                        },
        });
        system_ipv6_server->expect({
                .request = MockDnsServer::Request{.tcp = true, .qtype = 1, .qname = tcp6_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", tcp6_event_name, i++)},
                        },
        });

        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        vpn_event_loop_finalize_exit(this->ev_loop.get());

        ASSERT_EQ(0, system_unexpected);
        ASSERT_EQ(0, system_ipv6_unexpected);
        ASSERT_EQ(complete_before + 2, system_complete);
        ASSERT_EQ(complete_v6_before + 2, system_ipv6_complete);
    }

    ASSERT_GT(i, 0);
    while (--i >= 0) {
        auto ret =
                vpn.domain_filter.match_tag({.addr = SocketAddress(AG_FMT("1.1.1.{}", i)), .appname = "TestAppName"});
        ASSERT_EQ(DFMS_SUSPECT_EXCLUSION, ret.status);
    }
}

TEST_F(DnsRoutingAllProxies, IpVersionsUser) {
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    TunnelAddress dst_v6 = SocketAddress("[2001:4860:4860::8888]:53");
    SocketAddress src("127.0.0.1:50001");
    SocketAddress src_v6("[::1]:50002");

    int i = 0;
    int j = 0;
    for (const char *dname : {"example.org", "example.com"}) {
        int complete_before = user_complete;

        ClientConnectRequest udp_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_UDP,
                .src = &src,
                .dst = &dst,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
        ClientConnectRequest tcp_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_TCP,
                .src = &src,
                .dst = &dst,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(tcp_event));
        ClientConnectRequest udp6_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_UDP,
                .src = &src_v6,
                .dst = &dst_v6,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp6_event));
        ClientConnectRequest tcp6_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_TCP,
                .src = &src_v6,
                .dst = &dst_v6,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(tcp6_event));

        std::string udp_event_name = AG_FMT("{}.{}.", j++, dname);
        std::string udp6_event_name = AG_FMT("{}.{}.", j++, dname);

        ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, udp_event_name, LDNS_RR_TYPE_A));
        ASSERT_NO_FATAL_FAILURE(accept_and_send(udp6_event, udp6_event_name, LDNS_RR_TYPE_A));

        user_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = udp_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", udp_event_name, i++)},
                        },
        });
        user_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = 1, .qname = udp6_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", udp6_event_name, i++)},
                        },
        });

        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        vpn_event_loop_finalize_exit(this->ev_loop.get());

        ASSERT_EQ(0, system_unexpected);
        ASSERT_EQ(0, system_ipv6_unexpected);
        ASSERT_EQ(0, user_unexpected);
        ASSERT_EQ(complete_before + 1, user_complete);

        std::string tcp_event_name = AG_FMT("{}.{}.", j++, dname);
        std::string tcp6_event_name = AG_FMT("{}.{}.", j++, dname);

        ASSERT_NO_FATAL_FAILURE(accept_and_send(tcp_event, tcp_event_name, LDNS_RR_TYPE_A));
        ASSERT_NO_FATAL_FAILURE(accept_and_send(tcp6_event, tcp6_event_name, LDNS_RR_TYPE_A));

        user_server->expect({
                .request = MockDnsServer::Request{.tcp = true, .qtype = 1, .qname = tcp_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", tcp_event_name, i++)},
                        },
        });
        user_server->expect({
                .request = MockDnsServer::Request{.tcp = true, .qtype = 1, .qname = tcp6_event_name},
                .response =
                        MockDnsServer::Response{
                                .rcode = 0,
                                .answer = {AG_FMT("{} 60 IN A 1.1.1.{}", tcp6_event_name, i++)},
                        },
        });

        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        vpn_event_loop_finalize_exit(this->ev_loop.get());

        ASSERT_EQ(0, system_unexpected);
        ASSERT_EQ(0, system_ipv6_unexpected);
        ASSERT_EQ(0, user_unexpected);
        ASSERT_EQ(complete_before + 2, user_complete);
    }
}

TEST_F(DnsRoutingAllProxies, RecordTypes) {
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    SocketAddress src("127.0.0.1:50001");

    for (ldns_rr_type qtype : {LDNS_RR_TYPE_A, LDNS_RR_TYPE_AAAA, LDNS_RR_TYPE_CNAME, LDNS_RR_TYPE_TXT,
                 LDNS_RR_TYPE_HTTPS, LDNS_RR_TYPE_SVCB}) {
        ClientConnectRequest udp_event{
                .id = this->vpn.listener_conn_id_generator.get(),
                .protocol = IPPROTO_UDP,
                .src = &src,
                .dst = &dst,
                .app_name = "TestAppName",
        };
        ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
        ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "example.org.", qtype));
        user_server->expect({
                .request = MockDnsServer::Request{.tcp = false, .qtype = qtype, .qname = "example.org."},
                .response = MockDnsServer::Response{.rcode = LDNS_RCODE_REFUSED},
        });
        int complete_before = this->user_complete;
        vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
        vpn_event_loop_run(this->ev_loop.get());
        vpn_event_loop_finalize_exit(this->ev_loop.get());
        ASSERT_EQ(complete_before + 1, this->user_complete);
        ASSERT_EQ(0, this->user_unexpected);
        ASSERT_EQ(0, this->system_unexpected);
        ASSERT_EQ(0, this->system_ipv6_unexpected);
    }
}

TEST_F(DnsRoutingAllProxies, ExclusionSuspectsGeneral) {
    vpn.update_exclusions(VPN_MODE_GENERAL, "example.org");
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    SocketAddress src("127.0.0.1:50001");
    ClientConnectRequest udp_event{
            .id = this->vpn.listener_conn_id_generator.get(),
            .protocol = IPPROTO_UDP,
            .src = &src,
            .dst = &dst,
            .app_name = "TestAppName",
    };
    ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
    ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "example.org.", LDNS_RR_TYPE_A));
    system_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = LDNS_RR_TYPE_A, .qname = "example.org."},
            .response =
                    MockDnsServer::Response{
                            .rcode = LDNS_RCODE_NOERROR,
                            .answer = {"example.org. 60 IN A 1.2.3.4"},
                    },
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    vpn_event_loop_finalize_exit(this->ev_loop.get());
    ASSERT_EQ(1, this->system_complete);
    ASSERT_EQ(0, this->user_unexpected);
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, this->system_ipv6_unexpected);
    auto ret = vpn.domain_filter.match_tag({.addr = SocketAddress("1.2.3.4"), .appname = "TestAppName"});
    ASSERT_EQ(DFMS_SUSPECT_EXCLUSION, ret.status);
}

TEST_F(DnsRoutingAllProxies, ExclusionSuspectsSelective) {
    vpn.update_exclusions(VPN_MODE_SELECTIVE, "example.org");
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    SocketAddress src("127.0.0.1:50001");
    ClientConnectRequest udp_event{
            .id = this->vpn.listener_conn_id_generator.get(),
            .protocol = IPPROTO_UDP,
            .src = &src,
            .dst = &dst,
            .app_name = "TestAppName",
    };
    ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
    ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "example.org.", LDNS_RR_TYPE_A));
    user_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = LDNS_RR_TYPE_A, .qname = "example.org."},
            .response =
                    MockDnsServer::Response{
                            .rcode = LDNS_RCODE_NOERROR,
                            .answer = {"example.org. 60 IN A 1.2.3.4"},
                    },
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    vpn_event_loop_finalize_exit(this->ev_loop.get());
    ASSERT_EQ(1, this->user_complete);
    ASSERT_EQ(0, this->user_unexpected);
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, this->system_ipv6_unexpected);
    auto ret = vpn.domain_filter.match_tag({.addr = SocketAddress("1.2.3.4"), .appname = "TestAppName"});
    ASSERT_EQ(DFMS_SUSPECT_EXCLUSION, ret.status);
}

TEST_F(DnsRoutingAllProxies, RemoveSvcParamsEchConfig) {
    TunnelAddress dst = SocketAddress("8.8.8.8:53");
    SocketAddress src("127.0.0.1:50001");

    // Without exclusion.
    ClientConnectRequest udp_event{
            .id = this->vpn.listener_conn_id_generator.get(),
            .protocol = IPPROTO_UDP,
            .src = &src,
            .dst = &dst,
            .app_name = "TestAppName",
    };
    ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
    ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "tls-ech.dev.", LDNS_RR_TYPE_HTTPS));
    user_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = LDNS_RR_TYPE_HTTPS, .qname = "tls-ech.dev."},
            .response =
                    MockDnsServer::Response{
                            .rcode = LDNS_RCODE_NOERROR,
                            .answer = {"tls-ech.dev.\t60\tIN\tHTTPS\t1 . echconfig=AEn+DQBFKwAgACABWIHUGj4u+"
                                       "PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA\n"},
                    },
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    vpn_event_loop_finalize_exit(this->ev_loop.get());
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, this->system_ipv6_unexpected);
    ASSERT_EQ(0, this->user_unexpected);
    ASSERT_EQ(1, this->user_complete);
    ASSERT_TRUE(this->client_listener->closed_connections.contains(udp_event.id));
    ASSERT_TRUE(this->client_listener->closed_connections[udp_event.id].last_send);
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    dns_utils::LdnsPktPtr pkt =
            dns_utils::decode_pkt({this->client_listener->closed_connections[udp_event.id].last_send->data(),
                    this->client_listener->closed_connections[udp_event.id].last_send->size()});
    // NOLINTEND(bugprone-unchecked-optional-access)
    ASSERT_TRUE(pkt);
    ASSERT_EQ(1, ldns_rr_list_rr_count(ldns_pkt_answer(pkt.get())));
    DeclPtr<char, &free> str{ldns_rr2str(ldns_rr_list_rr(ldns_pkt_answer(pkt.get()), 0))};
    ASSERT_STREQ("tls-ech.dev.\t60\tIN\tHTTPS\t1 . echconfig=AEn+DQBFKwAgACABWIHUGj4u+"
                 "PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA\n",
            str.get());

    // With exclusion in GENERAL mode.
    vpn.update_exclusions(VPN_MODE_GENERAL, "tls-ech.dev");
    udp_event = {
            .id = this->vpn.listener_conn_id_generator.get(),
            .protocol = IPPROTO_UDP,
            .src = &src,
            .dst = &dst,
            .app_name = "TestAppName",
    };
    ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
    ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "tls-ech.dev.", LDNS_RR_TYPE_HTTPS));
    system_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = LDNS_RR_TYPE_HTTPS, .qname = "tls-ech.dev."},
            .response =
                    MockDnsServer::Response{
                            .rcode = LDNS_RCODE_NOERROR,
                            .answer = {"tls-ech.dev. 60 IN HTTPS 1 . "
                                       "echconfig=AEn+DQBFKwAgACABWIHUGj4u+"
                                       "PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"},
                    },
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    vpn_event_loop_finalize_exit(this->ev_loop.get());
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, this->system_ipv6_unexpected);
    ASSERT_EQ(0, this->user_unexpected);
    ASSERT_EQ(1, this->system_complete);
    ASSERT_TRUE(this->client_listener->closed_connections.contains(udp_event.id));
    ASSERT_TRUE(this->client_listener->closed_connections[udp_event.id].last_send);
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    pkt = dns_utils::decode_pkt({this->client_listener->closed_connections[udp_event.id].last_send->data(),
            this->client_listener->closed_connections[udp_event.id].last_send->size()});
    // NOLINTEND(bugprone-unchecked-optional-access)
    ASSERT_TRUE(pkt);
    ASSERT_EQ(1, ldns_rr_list_rr_count(ldns_pkt_answer(pkt.get())));
    str.reset(ldns_rr2str(ldns_rr_list_rr(ldns_pkt_answer(pkt.get()), 0)));
    ASSERT_STREQ("tls-ech.dev.\t60\tIN\tHTTPS\t1 .\n", str.get());

    // With exclusion in SELECTIVE mode.
    vpn.update_exclusions(VPN_MODE_SELECTIVE, "1.tls-ech.dev");
    udp_event = {
            .id = this->vpn.listener_conn_id_generator.get(),
            .protocol = IPPROTO_UDP,
            .src = &src,
            .dst = &dst,
            .app_name = "TestAppName",
    };
    ASSERT_NO_FATAL_FAILURE(raise_and_complete(udp_event));
    ASSERT_NO_FATAL_FAILURE(accept_and_send(udp_event, "1.tls-ech.dev.", LDNS_RR_TYPE_HTTPS));
    user_server->expect({
            .request = MockDnsServer::Request{.tcp = false, .qtype = LDNS_RR_TYPE_HTTPS, .qname = "1.tls-ech.dev."},
            .response =
                    MockDnsServer::Response{
                            .rcode = LDNS_RCODE_NOERROR,
                            .answer = {"1.tls-ech.dev. 60 IN HTTPS 1 . "
                                       "echconfig=AEn+DQBFKwAgACABWIHUGj4u+"
                                       "PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"},
                    },
    });
    vpn_event_loop_exit(this->ev_loop.get(), DEFAULT_TIMEOUT);
    vpn_event_loop_run(this->ev_loop.get());
    vpn_event_loop_finalize_exit(this->ev_loop.get());
    ASSERT_EQ(0, this->system_unexpected);
    ASSERT_EQ(0, this->system_ipv6_unexpected);
    ASSERT_EQ(0, this->user_unexpected);
    ASSERT_EQ(2, this->user_complete);
    ASSERT_TRUE(this->client_listener->closed_connections.contains(udp_event.id));
    ASSERT_TRUE(this->client_listener->closed_connections[udp_event.id].last_send);
    // NOLINTBEGIN(bugprone-unchecked-optional-access)
    pkt = dns_utils::decode_pkt({this->client_listener->closed_connections[udp_event.id].last_send->data(),
            this->client_listener->closed_connections[udp_event.id].last_send->size()});
    // NOLINTEND(bugprone-unchecked-optional-access)
    ASSERT_TRUE(pkt);
    ASSERT_EQ(1, ldns_rr_list_rr_count(ldns_pkt_answer(pkt.get())));
    str.reset(ldns_rr2str(ldns_rr_list_rr(ldns_pkt_answer(pkt.get()), 0)));
    ASSERT_STREQ("1.tls-ech.dev.\t60\tIN\tHTTPS\t1 .\n", str.get());
}
