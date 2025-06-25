#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <optional>

#include <gtest/gtest.h>

#include "test_mock_c.h"
#include "vpn/internal/server_upstream.h"
#include "vpn_manager.h"

using namespace ag;

static const std::vector<VpnEndpoint> ENDPOINTS = {
        {sockaddr_from_str("127.0.0.1:443"), "localhost1"},
        {sockaddr_from_str("127.0.0.2:443"), "localhost2"},
        {sockaddr_from_str("127.0.0.3:443"), "localhost3"},
};

struct TestUpstream : public ServerUpstream {
    TestUpstream()
            : ServerUpstream(0) {
    }
    void deinit() override {
    }
    bool open_session(std::optional<Millis>) override {
        return true;
    }
    void close_session() override {
    }
    uint64_t open_connection(const TunnelAddressPair *, int, std::string_view) override {
        return NON_ID;
    }
    void close_connection(uint64_t, bool, bool) override {
    }
    ssize_t send(uint64_t, const uint8_t *, size_t) override {
        return -1;
    }
    void consume(uint64_t, size_t) override {
    }
    size_t available_to_send(uint64_t) override {
        return 0;
    }
    void update_flow_control(uint64_t, TcpFlowCtrlInfo) override {
    }
    void do_health_check() override {
    }
    void cancel_health_check() override {
    }
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override {
        return {};
    }
    void on_icmp_request(IcmpEchoRequestEvent &) override {
    }
};

static constexpr Secs TIMEOUT{ 10 };

struct ConnectingVpnManagerTest : MockedTest {
    Vpn *vpn = nullptr;
    std::optional<VpnSessionState> session_state;
    bool timed_out = false;

    void SetUp() override {
        MockedTest::SetUp();

        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);

        VpnSettings settings{.handler = {vpn_handler, this}};
        vpn = vpn_open(&settings);
        ASSERT_TRUE(vpn);

        vpn_event_loop_exit(vpn->ev_loop.get(), Millis{0});
        vpn_event_loop_finalize_exit(vpn->ev_loop.get());
        vpn_event_loop_hijack(vpn->ev_loop.get());

        VpnConnectParameters parameters = {
                .upstream_config =
                        {
                                .location = {.id = "1",
                                        .endpoints =
                                                {
                                                        .data = (VpnEndpoint *) ENDPOINTS.data(),
                                                        .size = uint32_t(ENDPOINTS.size()),
                                                }},
                                .username = "1",
                                .password = "1",
                                .recovery = {.backoff_rate = 1},
                        },
                .retry_info = {.policy = VPN_CRP_SEVERAL_ATTEMPTS, .attempts_num = 1},
        };
        vpn_connect(vpn, &parameters);
        ASSERT_TRUE(await_state_change(VPN_SS_CONNECTING));
    }

    void TearDown() override {
        vpn_stop(vpn);
        vpn_close(vpn);
        MockedTest::TearDown();
    }

    static void vpn_handler(void *arg, VpnEvent what, void *data) {
        auto *self = (ConnectingVpnManagerTest *) arg;
        switch (what) {
        case VPN_EVENT_PROTECT_SOCKET:
        case VPN_EVENT_VERIFY_CERTIFICATE:
        case VPN_EVENT_CLIENT_OUTPUT:
        case VPN_EVENT_CONNECT_REQUEST:
        case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
        case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
        case VPN_EVENT_TUNNEL_CONNECTION_STATS:
        case VPN_EVENT_TUNNEL_CONNECTION_CLOSED:
        case VPN_EVENT_CONNECTION_INFO:
            break;
        case VPN_EVENT_STATE_CHANGED: {
            auto *event = (VpnStateChangedEvent *) data;
            self->session_state = event->state;
            vpn_event_loop_exit(self->vpn->ev_loop.get(), Millis{0});
            break;
        }
        }
    }

    bool await_state_change(VpnSessionState expected,
            std::optional<Millis> timeout = std::nullopt) { // NOLINT(readability-make-member-function-const)
        using namespace std::chrono;
        TaskId timeout_task_id = vpn_event_loop_schedule(vpn->ev_loop.get(),
                {
                        .arg = this,
                        .action =
                                [](void *arg, TaskId) {
                                    auto *self = (ConnectingVpnManagerTest *) arg;
                                    self->timed_out = true;
                                    vpn_event_loop_exit(self->vpn->ev_loop.get(), Millis{0});
                                },
                },
                timeout.value_or(TIMEOUT));
        vpn_event_loop_run(vpn->ev_loop.get());
        vpn_event_loop_cancel(vpn->ev_loop.get(), timeout_task_id);
        return !std::exchange(timed_out, false) && std::exchange(session_state, std::nullopt) == expected;
    }

    void loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(vpn->ev_loop.get(), Millis{0});
        vpn_event_loop_run(vpn->ev_loop.get());
    }

    void raise_client_event(                             // NOLINT(readability-make-member-function-const)
            vpn_client::Event e, void *data = nullptr) { // NOLINT(readability-make-member-function-const)
        vpn->client.parameters.handler.func(vpn->client.parameters.handler.arg, e, data);
    }
};

struct ConnectedVpnManagerTest : public ConnectingVpnManagerTest {
    void SetUp() override {
        ConnectingVpnManagerTest::SetUp();
        g_infos[test_mock::IDX_LOCATIONS_PINGER_START].wait_called();
        vpn->selected_endpoint.emplace(vpn_endpoint_clone(&ENDPOINTS[0]), std::nullopt);
        vpn->client.endpoint_upstream = std::make_unique<TestUpstream>();
        raise_client_event(vpn_client::EVENT_CONNECTED);
        ASSERT_TRUE(await_state_change(VPN_SS_CONNECTED));
    }
};

TEST_F(ConnectedVpnManagerTest, BypassRequestsAreBypassedImmediately) {
    auto &c = test_mock::g_client;
    for (bool kill_switch : {false, true}) {
        c.reset();

        raise_client_event(vpn_client::EVENT_DISCONNECTED);
        ASSERT_TRUE(await_state_change(VPN_SS_WAITING_RECOVERY));
        vpn->client.kill_switch_on = kill_switch;

        VpnConnectionInfo info{.id = 1, .action = VPN_CA_FORCE_BYPASS};
        vpn_complete_connect_request(vpn, &info);
        loop_once();

        ASSERT_EQ(1, c.completed_connect_requests.back().id);
        ASSERT_EQ(VPN_CA_FORCE_BYPASS, c.completed_connect_requests.back().action);

        ASSERT_TRUE(await_state_change(VPN_SS_RECOVERING));
        info.id = 2;
        vpn_complete_connect_request(vpn, &info);
        loop_once();

        ASSERT_EQ(2, c.completed_connect_requests.back().id);
        ASSERT_EQ(VPN_CA_FORCE_BYPASS, c.completed_connect_requests.back().action);
    }
}

TEST_F(ConnectedVpnManagerTest, RedirectRequestsArePostponed) {
    using namespace std::chrono_literals;
    auto &c = test_mock::g_client;

    for (bool kill_switch : {false, true}) {
        c.reset();

        raise_client_event(vpn_client::EVENT_DISCONNECTED);
        ASSERT_TRUE(await_state_change(VPN_SS_WAITING_RECOVERY));
        vpn->client.kill_switch_on = kill_switch;

        VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
        vpn_complete_connect_request(vpn, &info);
        loop_once();

        ASSERT_EQ(0, c.completed_connect_requests.size());

        ASSERT_TRUE(await_state_change(VPN_SS_RECOVERING));
        info.id = 2;
        vpn_complete_connect_request(vpn, &info);
        loop_once();

        ASSERT_EQ(0, c.completed_connect_requests.size());

        raise_client_event(vpn_client::EVENT_CONNECTED);
        ASSERT_TRUE(await_state_change(VPN_SS_CONNECTED));

        ASSERT_EQ(2, c.completed_connect_requests.size());
        ASSERT_TRUE(std::any_of(
                c.completed_connect_requests.begin(), c.completed_connect_requests.end(), [](const auto &r) {
                    return r.action == VPN_CA_DEFAULT && r.id == 1;
                }));
        ASSERT_TRUE(std::any_of(
                c.completed_connect_requests.begin(), c.completed_connect_requests.end(), [](const auto &r) {
                    return r.action == VPN_CA_DEFAULT && r.id == 2;
                }));
    }
}

TEST_F(ConnectedVpnManagerTest, KillSwitchOff) {
    using namespace std::chrono_literals;
    auto &c = test_mock::g_client;
    c.reset();

    vpn->client.kill_switch_on = false;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);
    ASSERT_TRUE(await_state_change(VPN_SS_WAITING_RECOVERY));

    VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
    vpn_complete_connect_request(vpn, &info);
    loop_once();

    ASSERT_EQ(0, c.completed_connect_requests.size());

    std::this_thread::sleep_for(std::chrono::milliseconds{VPN_DEFAULT_POSTPONEMENT_WINDOW_MS * 2});
    ASSERT_TRUE(await_state_change(VPN_SS_RECOVERING));

    ASSERT_EQ(1, c.completed_connect_requests.back().id);
    ASSERT_EQ(VPN_CA_FORCE_BYPASS, c.completed_connect_requests.back().action);

    info.id = 2;
    vpn_complete_connect_request(vpn, &info);
    loop_once();

    ASSERT_EQ(2, c.completed_connect_requests.back().id);
    ASSERT_EQ(VPN_CA_FORCE_BYPASS, c.completed_connect_requests.back().action);

    raise_client_event(vpn_client::EVENT_CONNECTED);
    ASSERT_TRUE(await_state_change(VPN_SS_CONNECTED));

    ASSERT_EQ(2, c.reset_connections.size());
    ASSERT_EQ((std::unordered_set<uint64_t>{1, 2}),
            (std::unordered_set<uint64_t>{c.reset_connections.begin(), c.reset_connections.end()}));
}

TEST_F(ConnectedVpnManagerTest, KillSwitchOn) {
    auto &c = test_mock::g_client;
    c.reset();

    vpn->client.kill_switch_on = true;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);
    ASSERT_TRUE(await_state_change(VPN_SS_WAITING_RECOVERY));
    VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
    vpn_complete_connect_request(vpn, &info);
    loop_once();

    ASSERT_EQ(0, c.rejected_connect_requests.size());
    ASSERT_EQ(0, c.completed_connect_requests.size());

    std::this_thread::sleep_for(std::chrono::milliseconds{VPN_DEFAULT_POSTPONEMENT_WINDOW_MS * 2});
    ASSERT_TRUE(await_state_change(VPN_SS_RECOVERING));

    ASSERT_EQ(1, c.rejected_connect_requests.back());

    info.id = 2;
    vpn_complete_connect_request(vpn, &info);
    loop_once();

    ASSERT_EQ(2, c.rejected_connect_requests.back());

    raise_client_event(vpn_client::EVENT_CONNECTED);
    ASSERT_TRUE(await_state_change(VPN_SS_CONNECTED));

    ASSERT_EQ(0, c.reset_connections.size());
    ASSERT_EQ(0, c.completed_connect_requests.size());
}

TEST_F(ConnectedVpnManagerTest, Connected) {
    auto &c = test_mock::g_client;
    c.reset();

    VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(1, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);

    info.id = 2;
    info.action = VPN_CA_FORCE_BYPASS;
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(2, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);
}

TEST_F(ConnectingVpnManagerTest, Connecting) {
    auto &c = test_mock::g_client;
    c.reset();

    VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(1, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);

    info.id = 2;
    info.action = VPN_CA_FORCE_BYPASS;
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(2, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);
}

TEST_F(ConnectedVpnManagerTest, Disconnected) {
    auto &c = test_mock::g_client;
    c.reset();

    // Fatal
    VpnError error = {.code = VPN_EC_AUTH_REQUIRED, .text = "test"};
    raise_client_event(vpn_client::EVENT_ERROR, &error);
    ASSERT_TRUE(await_state_change(VPN_SS_DISCONNECTED));

    VpnConnectionInfo info{.id = 1, .action = VPN_CA_DEFAULT};
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(1, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);

    info.id = 2;
    info.action = VPN_CA_FORCE_BYPASS;
    vpn_complete_connect_request(vpn, &info);
    loop_once();
    ASSERT_EQ(2, c.completed_connect_requests.back().id);
    ASSERT_EQ(info.action, c.completed_connect_requests.back().action);
}
