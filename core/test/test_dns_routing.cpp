#include <algorithm>
#include <optional>
#include <tuple>

#include <gtest/gtest.h>
#include <magic_enum/magic_enum.hpp>

#include "common/utils.h"
#include "net/dns_utils.h"
#include "plain_dns_manager.h"
#include "test_mock_vpn_client.h"
#include "vpn/internal/tunnel.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/internal/vpn_connection.h"

using namespace ag; // NOLINT(google-build-using-namespace)

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
    Tunnel tun = {};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    sockaddr_storage src = sockaddr_from_str("1.1.1.1:42");
    TunnelAddress dst = sockaddr_from_str("2.2.2.2:53");
    std::shared_ptr<TestUpstream> redirect_upstream;
    std::shared_ptr<TestUpstream> bypass_upstream;
    std::shared_ptr<TestListener> client_listener;
    uint64_t client_id = vpn.listener_conn_id_generator.get();
    static inline std::optional<vpn_client::Event>
            g_last_raised_vpn_event; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

    static void vpn_handler(void *, vpn_client::Event what, void *) {
        g_last_raised_vpn_event = what;
    }

    static void redirect_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->tun.upstream_handler(test->redirect_upstream, what, data);
    }

    static void bypass_upstream_handler(void *arg, ServerEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->tun.upstream_handler(test->bypass_upstream, what, data);
    }

    static void listener_handler(void *arg, ClientEvent what, void *data) {
        auto *test = (DnsRouting *) arg;
        test->tun.listener_handler(test->client_listener, what, data);
    }

    void SetUp() override {
        vpn_network_manager_update_system_dns({
                .main = {SystemDnsServer{
                        .address = "127.0.0.53",
                }},
        });

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
        tun.upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);

        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        std::optional<VpnConnectAction> action = tun.finalize_connect_action({
                .id = client_id,
                .action = VPN_CA_DEFAULT,
                .appname = "some",
                .uid = 1,
        });
        ASSERT_EQ(action, VPN_CA_DEFAULT);
        tun.complete_connect_request(client_id, action);
        run_event_loop_once();

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    }

    void TearDown() override {
        tun.deinit();
        g_last_raised_vpn_event.reset();
    }

    void raise_client_connection(uint64_t id) {
        ClientConnectRequest event = {id, IPPROTO_UDP, (sockaddr *) &src, &dst};
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECT_REQUEST, &event);
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
        tun.listener_handler(client_listener, CLIENT_EVENT_READ, &read_event);
        ASSERT_EQ(read_event.result, int(std::size(request.data)));
        run_event_loop_once();
    }
};

class NoProxy : public DnsRouting {};

TEST_P(NoProxy, Test) {
    auto [mode, action, exclusion, domain] = GetParam();
    vpn.update_exclusions(mode, exclusion);

    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    switch (mode) {
    case VPN_MODE_GENERAL:
        if (exclusion == domain) {
            ASSERT_EQ(bypass_upstream->connections.size(), 1);
        } else {
            ASSERT_EQ(redirect_upstream->connections.size(), 1);
        }
        break;
    case VPN_MODE_SELECTIVE:
        if (exclusion != domain) {
            ASSERT_EQ(bypass_upstream->connections.size(), 1);
        } else {
            ASSERT_EQ(redirect_upstream->connections.size(), 1);
        }
        break;
    }
}

INSTANTIATE_TEST_SUITE_P(DnsRouting, NoProxy,
        testing::Combine(
                testing::Values(VPN_MODE_GENERAL, VPN_MODE_SELECTIVE),
                testing::Values(VPN_CA_DEFAULT),
                testing::Values("example.com"),
                testing::Values("example.com", "github.com")));

class WithProxy : public DnsRouting {};

TEST_P(WithProxy, Test) {
    auto [mode, action, exclusion, domain] = GetParam();
    vpn.update_exclusions(mode, exclusion);
    vpn.dns_proxy = std::make_unique<DnsProxyAccessor>(DnsProxyAccessor::Parameters{});

    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    ASSERT_EQ(bypass_upstream->connections.size(), 1);
    uint64_t conn_upstream_id = bypass_upstream->connections.back();
    khiter_t iter = kh_get(connections_by_id, tun.connections.by_server_id, conn_upstream_id);
    ASSERT_NE(iter, kh_end(tun.connections.by_server_id));

    PlainDnsMessageHandler::RoutingPolicy expected_routing_policy = PlainDnsMessageHandler::RP_DEFAULT;
    switch (mode) {
    case VPN_MODE_GENERAL:
        expected_routing_policy = (exclusion == domain) ? PlainDnsMessageHandler::RP_EXCEPTIONAL
                                                        : PlainDnsMessageHandler::RP_THROUGH_DNS_PROXY;
        break;
    case VPN_MODE_SELECTIVE:
        expected_routing_policy = (exclusion == domain) ? PlainDnsMessageHandler::RP_THROUGH_DNS_PROXY
                                                        : PlainDnsMessageHandler::RP_DEFAULT;
        break;
    }

    ASSERT_EQ(expected_routing_policy,
            tun.plain_dns_manager->get_routing_policy(kh_value(tun.connections.by_server_id, iter)->client_id));
}

INSTANTIATE_TEST_SUITE_P(DnsRouting, WithProxy,
        testing::Combine(
                testing::Values(VPN_MODE_GENERAL, VPN_MODE_SELECTIVE),
                testing::Values(VPN_CA_DEFAULT),
                testing::Values("example.com"),
                testing::Values("example.com", "github.com")));

class AppInitiatedDnsRouting : public DnsRouting {
public:
    void SetUp() override {
        DnsRouting::SetUp();

        vpn_network_manager_notify_app_request_domain("example.com", -1);

        vpn.kill_switch_on = true;
    }

    void TearDown() override {
        vpn_network_manager_notify_app_request_domain("example.com", 0);

        DnsRouting::TearDown();
    }
};

TEST_F(AppInitiatedDnsRouting, MatchingDomain) {
    ASSERT_NO_FATAL_FAILURE(raise_dns_request("example.com"));

    ASSERT_EQ(bypass_upstream->connections.size(), 1);
    uint64_t upstream_id = bypass_upstream->connections.back();
    tun.upstream_handler(bypass_upstream, SERVER_EVENT_CONNECTION_OPENED, &upstream_id);

    const auto *last_destination = std::get_if<sockaddr_storage>(&bypass_upstream->last_destination);
    ASSERT_NE(last_destination, nullptr);
    ASSERT_TRUE(sockaddr_is_loopback((sockaddr *) last_destination))
            << "Last destination: " << tunnel_addr_to_str(&bypass_upstream->last_destination) << std::endl;
}

TEST_F(AppInitiatedDnsRouting, NonMatchingDomain) {
    ASSERT_NO_FATAL_FAILURE(raise_dns_request("example.org"));
    ASSERT_EQ(bypass_upstream->last_send, 0);
}

class CustomDnsRouting : public DnsRouting {
public:
    void SetUp() override {
        vpn_network_manager_update_system_dns({
                .main = {SystemDnsServer{
                        .address = "127.0.0.53",
                }},
        });

        vpn.parameters.handler = {&vpn_handler, this};
        vpn.parameters.network_manager = network_manager.get();

        redirect_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(redirect_upstream->init(&vpn, {&redirect_upstream_handler, this}));
        vpn.endpoint_upstream = redirect_upstream;
        bypass_upstream = std::make_unique<TestUpstream>();
        ASSERT_TRUE(bypass_upstream->init(&vpn, {&bypass_upstream_handler, this}));
        vpn.bypass_upstream = bypass_upstream;
    }

    void open_connection(VpnConnectAction callback_action, VpnConnectAction expected_action) {
        client_listener = std::make_unique<TestListener>();
        ASSERT_EQ(ClientListener::InitResult::SUCCESS, client_listener->init(&vpn, {&listener_handler, this}));
        vpn.client_listener = client_listener;

        ASSERT_TRUE(tun.init(&vpn));
        tun.upstream_handler(redirect_upstream, SERVER_EVENT_SESSION_OPENED, nullptr);

        ASSERT_NO_FATAL_FAILURE(raise_client_connection(client_id));

        std::optional<VpnConnectAction> action = tun.finalize_connect_action({
                .id = client_id,
                .action = callback_action,
                .appname = "some",
                .uid = 1,
        });
        ASSERT_EQ(action, expected_action);
        tun.complete_connect_request(client_id, action);
        run_event_loop_once();

        ASSERT_FALSE(client_listener->connections[client_id].read_enabled);
        tun.listener_handler(client_listener, CLIENT_EVENT_CONNECTION_ACCEPTED, &client_id);
        ASSERT_TRUE(client_listener->connections[client_id].read_enabled);
    }
};

class DnsAddressExcluded : public CustomDnsRouting {};

TEST_P(DnsAddressExcluded, CheckCreatedUpstreams) {
    auto [mode, action, exclusion, domain] = GetParam();

    vpn.update_exclusions(mode, exclusion);

    ASSERT_NO_FATAL_FAILURE(open_connection(action, action));
    ASSERT_NO_FATAL_FAILURE(raise_dns_request(domain));

    switch (mode) {
    case VPN_MODE_GENERAL:
        if (exclusion.find(domain) != std::string::npos) {
            ASSERT_EQ(bypass_upstream->connections.size(), 1);
            ASSERT_EQ(redirect_upstream->connections.size(), 0);
        } else {
            ASSERT_EQ(redirect_upstream->connections.size(), 1);
            ASSERT_EQ(bypass_upstream->connections.size(), 0);
        }
        break;
    case VPN_MODE_SELECTIVE:
        if (exclusion.find(domain) != std::string::npos) {
            ASSERT_EQ(redirect_upstream->connections.size(), 1);
            ASSERT_EQ(bypass_upstream->connections.size(), 0);
        } else {
            ASSERT_EQ(bypass_upstream->connections.size(), 1);
            ASSERT_EQ(redirect_upstream->connections.size(), 0);
        }
        break;
    }
}

INSTANTIATE_TEST_SUITE_P(DnsAddressExcluded, DnsAddressExcluded,
        testing::Values(
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_DEFAULT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_DEFAULT, "2.2.2.2/32 example.com", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_DEFAULT, "2.2.2.2/32", "example.com"),
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_DEFAULT, "2.2.2.2/32 example.com", "example.com")
                ));

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
        testing::Values(
                std::make_tuple(VPN_MODE_GENERAL, VPN_CA_FORCE_REDIRECT, "2.2.2.2/32", "example.com"),
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
                std::make_tuple(VPN_MODE_SELECTIVE, VPN_CA_FORCE_BYPASS, "example.com", "example.com")
                ));
