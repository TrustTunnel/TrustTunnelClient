#include <condition_variable>

#include <gtest/gtest.h>

#include "test_mock_c.h"
#include "test_mock_vpn_client.h"
#include "vpn_manager.h"

using namespace std::chrono;
using namespace ag;

class TestUpstream : public ServerUpstream {
public:
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
    VpnError do_health_check() override {
        return {};
    }
    VpnConnectionStats get_connection_stats() const override {
        return {};
    }
    void on_icmp_request(IcmpEchoRequestEvent &) override {
    }
};

static void vpn_handler(void *arg, VpnEvent what, void *data);

class VpnManagerTest : public MockedTest {
public:
    VpnManagerTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    friend void vpn_handler(void *arg, VpnEvent what, void *data);

    ag::Logger log{"TEST"};

    Vpn *vpn = nullptr;
    std::mutex guard;
    std::condition_variable cond_var;
    VpnUpstreamConfig upstream;
    int raised_events;
    VpnError vpn_error;

    void SetUp() override {
        infolog(log, "\n\n{}(): ...\n\n", __func__);

        MockedTest::SetUp();

        raised_events = 0;
        vpn_error = {};

        upstream = {};
        upstream.username = "test";
        upstream.password = "test";
        upstream.timeout_ms = 1000;

        VpnSettings settings = {{vpn_handler, this}};
        vpn = vpn_open(&settings);
        ASSERT_NE(vpn, nullptr);

        infolog(log, "\n\n{}(): Done\n\n", __func__);
    }

    void TearDown() override {
        infolog(log, "\n\n{}(): ...\n\n", __func__);

        if (vpn != nullptr) {
            vpn_stop(vpn);
            vpn_close(vpn);
        }

        MockedTest::TearDown();

        infolog(log, "\n\n{}(): Done\n\n", __func__);
    }

    bool wait_cond(std::function<bool()> pred) {
        std::unique_lock l(this->guard);
        return this->cond_var.wait_for(l, std::chrono::seconds(10), pred);
    }

    void start_connect(int attempts = 0) {
        VpnConnectParameters parameters = {
                .upstream_config = this->upstream,
                .retry_info =
                        {
                                .policy = VPN_CRP_SEVERAL_ATTEMPTS,
                                .attempts_num = attempts,
                        },
        };
        this->vpn_error = vpn_connect(this->vpn, &parameters);
        // Check it's not failed immediately
        ASSERT_EQ(this->vpn_error.code, VPN_EC_NOERROR) << this->vpn_error.text;

        ASSERT_TRUE(wait_cond([this]() {
            return this->vpn_error.code != VPN_EC_NOERROR || this->vpn->fsm.get_state() != VPN_SS_DISCONNECTED;
        }));
        ASSERT_EQ(this->vpn->fsm.get_state(), VPN_SS_CONNECTING);
    }

    void check_connect_result(VpnErrorCode expected_error = VPN_EC_NOERROR) {
        ASSERT_TRUE(wait_cond([this, expected_error]() {
            return (expected_error == VPN_EC_NOERROR) ? (this->vpn->fsm.get_state() != VPN_SS_CONNECTING)
                                                      : (this->vpn_error.code != VPN_EC_NOERROR);
        })) << "state: "
            << (VpnSessionState) this->vpn->fsm.get_state() << std::endl
            << "error: " << (VpnErrorCode) this->vpn_error.code << " " << this->vpn_error.text;
        ASSERT_EQ(this->vpn_error.code, expected_error) << this->vpn_error.text;
        if (expected_error == VPN_EC_NOERROR) {
            ASSERT_EQ(this->vpn->fsm.get_state(), VPN_SS_CONNECTED);
        } else {
            ASSERT_EQ(this->vpn->fsm.get_state(), VPN_SS_DISCONNECTED);
        }
    }

    void ping_location(std::optional<LocationsPingerResult> result_ = std::nullopt,
            std::optional<VpnLocation> expected_location = std::nullopt) {
        auto &pinger_start_info = g_infos[test_mock::IDX_LOCATIONS_PINGER_START];
        ASSERT_TRUE(pinger_start_info.wait_called());
        if (expected_location.has_value()) {
            auto pinger_info = pinger_start_info.get_arg<test_mock::LocationsPingerInfo>(0);
            ASSERT_EQ(pinger_info->locations.size, 1);
            VpnLocation pinging_location = pinger_info->locations.data[0];
            ASSERT_STREQ(pinging_location.id, expected_location->id);
            ASSERT_EQ(pinging_location.endpoints.size, expected_location->endpoints.size);
            for (size_t i = 0; i < pinging_location.endpoints.size; ++i) {
                ASSERT_NO_FATAL_FAILURE(
                        check_endpoint(&pinging_location.endpoints.data[i], &expected_location->endpoints.data[i]));
            }
        }

        LocationsPingerResult result = result_.value_or(LocationsPingerResult{
                this->vpn->upstream_config.location.id, 10, this->vpn->upstream_config.location.endpoints.data});
        auto pinger_handler = pinger_start_info.get_arg<LocationsPingerHandler>(1);
        this->vpn->submit([pinger_handler, result]() {
            pinger_handler.func(pinger_handler.arg, &result);
        });
    }

    void check_endpoint(const VpnEndpoint *lh, const VpnEndpoint *rh) {
        ASSERT_TRUE(vpn_endpoint_equals(lh, rh))
                << "Left:  " << lh->name << " " << sockaddr_to_str((sockaddr *) &lh->address) << std::endl
                << "Right: " << rh->name << " " << sockaddr_to_str((sockaddr *) &rh->address);
    }

    void connect_client_ok(const VpnEndpoint *expected_endpoint = nullptr) {
        ASSERT_TRUE(test_mock::g_client.wait_called(test_mock::CMID_CONNECT));
        this->vpn->client.endpoint_upstream = std::make_unique<TestUpstream>();

        if (expected_endpoint != nullptr) {
            ASSERT_NO_FATAL_FAILURE(check_endpoint(expected_endpoint, this->vpn->client.upstream_config.endpoint));
        }

        raise_client_event(vpn_client::EVENT_CONNECTED);
    }

    void connect_client_fail(VpnErrorCode error = VPN_EC_NOERROR, const VpnEndpoint *expected_endpoint = nullptr) {
        ASSERT_TRUE(test_mock::g_client.wait_called(test_mock::CMID_CONNECT));

        if (expected_endpoint != nullptr) {
            ASSERT_NO_FATAL_FAILURE(check_endpoint(expected_endpoint, this->vpn->client.upstream_config.endpoint));
        }

        if (error == VPN_EC_NOERROR) {
            raise_client_event(vpn_client::EVENT_DISCONNECTED);
        } else {
            static VpnError e = {};
            e = {error, "test"};
            raise_client_event(vpn_client::EVENT_ERROR, &e);
        }
    }

    void raise_client_event(vpn_client::Event e, void *data = nullptr) {
        auto client_handler = vpn->client.parameters.handler;
        this->vpn->submit([client_handler, e, data]() {
            client_handler.func(client_handler.arg, e, data);
        });
    }

    bool wait_state(VpnSessionState s) {
        return wait_cond([this, s]() {
            return this->vpn->fsm.get_state() == s;
        });
    }
};

static void vpn_handler(void *arg, VpnEvent what, void *data) {
    VpnManagerTest *test = (VpnManagerTest *) arg;
    std::unique_lock l(test->guard);
    test->raised_events |= 1 << what;
    test->cond_var.notify_all();

    switch (what) {
    case VPN_EVENT_STATE_CHANGED: {
        VpnStateChangedEvent event = *(VpnStateChangedEvent *) data;
        switch (event.state) {
        case VPN_SS_CONNECTED:
            break;
        case VPN_SS_WAITING_RECOVERY:
            test->vpn_error = event.waiting_recovery_info.error;
            break;
        case VPN_SS_DISCONNECTED:
        case VPN_SS_CONNECTING:
        case VPN_SS_RECOVERING:
            test->vpn_error = event.error;
            break;
        }
        break;
    }
    case VPN_EVENT_PROTECT_SOCKET:
    case VPN_EVENT_VERIFY_CERTIFICATE:
    case VPN_EVENT_CLIENT_OUTPUT:
    case VPN_EVENT_CONNECT_REQUEST:
    case VPN_EVENT_ENDPOINT_CONNECTION_STATS:
    case VPN_EVENT_DNS_UPSTREAM_UNAVAILABLE:
        break;
    }
}

// Check that failed endpoint no longer takes part in connect procedure
TEST_F(VpnManagerTest, ConnectingEndpointsExclusionOnFailure) {
    VpnEndpoint endpoints[] = {
            {sockaddr_from_str("127.0.0.1:443"), "localhost"},
            {sockaddr_from_str("127.0.0.2:443"), "localhost"},
            {sockaddr_from_str("127.0.0.3:443"), "localhost"},
    };
    upstream.location = (VpnLocation){"1", {endpoints, std::size(endpoints)}};
    static_assert(std::size(endpoints) < VPN_DEFAULT_CONNECT_ATTEMPTS_NUM);

    ASSERT_NO_FATAL_FAILURE(start_connect());

    for (size_t i = 0; i < std::size(endpoints); ++i) {
        ASSERT_NO_FATAL_FAILURE(ping_location(
                LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[i]},
                VpnLocation{vpn->upstream_config.location.id, {&endpoints[i], uint32_t(std::size(endpoints) - i)}}));
        if (i != std::size(endpoints) - 1) {
            ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &endpoints[i]));
        } else {
            ASSERT_NO_FATAL_FAILURE(connect_client_ok(&endpoints[i]));
        }
    }
    ASSERT_TRUE(wait_state(VPN_SS_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(check_connect_result());
}

// Check reporting error correctness in case library failed to connect to any endpoint of a location
TEST_F(VpnManagerTest, AllConnectingEndpointsFail) {
    VpnEndpoint endpoints[] = {
            {sockaddr_from_str("127.0.0.1:443"), "localhost"},
            {sockaddr_from_str("127.0.0.2:443"), "localhost"},
            {sockaddr_from_str("127.0.0.3:443"), "localhost"},
    };
    upstream.location = (VpnLocation){"1", {endpoints, std::size(endpoints)}};
    static_assert(std::size(endpoints) < VPN_DEFAULT_CONNECT_ATTEMPTS_NUM);

    ASSERT_NO_FATAL_FAILURE(start_connect(std::size(endpoints)));

    for (size_t i = 0; i < std::size(endpoints); ++i) {
        ASSERT_NO_FATAL_FAILURE(ping_location(
                LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[i]},
                VpnLocation{vpn->upstream_config.location.id, {&endpoints[i], uint32_t(std::size(endpoints) - i)}}));
        ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &endpoints[i]));
    }
    ASSERT_TRUE(wait_state(VPN_SS_DISCONNECTED));
    ASSERT_NO_FATAL_FAILURE(check_connect_result(VPN_EC_ERROR));
}

// Check reporting error correctness in case library failed to connect to any endpoint of a location
// but there are some unused number of attempts left
TEST_F(VpnManagerTest, ConnectFailsWithSomeAttemptsLeft) {
    VpnEndpoint endpoints[] = {
            {sockaddr_from_str("127.0.0.1:443"), "localhost"},
            {sockaddr_from_str("127.0.0.2:443"), "localhost"},
            {sockaddr_from_str("127.0.0.3:443"), "localhost"},
    };
    upstream.location = (VpnLocation){"1", {endpoints, std::size(endpoints)}};
    static_assert(std::size(endpoints) < VPN_DEFAULT_CONNECT_ATTEMPTS_NUM);

    ASSERT_NO_FATAL_FAILURE(start_connect(2 * std::size(endpoints)));

    for (size_t i = 0; i < std::size(endpoints); ++i) {
        ASSERT_NO_FATAL_FAILURE(ping_location(
                LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[i]},
                VpnLocation{vpn->upstream_config.location.id, {&endpoints[i], uint32_t(std::size(endpoints) - i)}}));
        ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &endpoints[i]));
    }
    ASSERT_TRUE(wait_state(VPN_SS_DISCONNECTED));
    ASSERT_NO_FATAL_FAILURE(check_connect_result(VPN_EC_ERROR));
}

class ConnectedVpnManagerTest : public VpnManagerTest {
protected:
    const std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("127.0.0.1:443"), "localhost1"},
            {sockaddr_from_str("127.0.0.2:443"), "localhost2"},
            {sockaddr_from_str("127.0.0.3:443"), "localhost3"},
    };

    void SetUp() override {
        infolog(log, "\n\n{}(): ...\n\n", __func__);

        VpnManagerTest::SetUp();

        upstream.location = {"1", {(VpnEndpoint *) endpoints.data(), uint32_t(std::size(endpoints))}};
        upstream.recovery.backoff_rate = 1;

        ASSERT_NO_FATAL_FAILURE(start_connect());
        ASSERT_NO_FATAL_FAILURE(ping_location());
        ASSERT_NO_FATAL_FAILURE(connect_client_ok(&endpoints[0]));
        ASSERT_TRUE(wait_state(VPN_SS_CONNECTED));
        ASSERT_NO_FATAL_FAILURE(check_connect_result());

        infolog(log, "\n\n{}(): Done\n\n", __func__);
    }

    void TearDown() override {
        infolog(log, "\n\n{}(): ...\n\n", __func__);

        VpnManagerTest::TearDown();

        infolog(log, "\n\n{}(): Done\n\n", __func__);
    }
};

// Check that after disconnect library goes to the same endpoint if recovery took less than
// location update period
TEST_F(ConnectedVpnManagerTest, RecoverySameEndpoint) {
    const VpnEndpoint selected_endpoint = *vpn->selected_endpoint_info.endpoint;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);

    milliseconds start_ts = duration_cast<milliseconds>(steady_clock::now().time_since_epoch());
    for (size_t i = 0; i < 3; ++i) {
        ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));

        // check that endpoints were not refreshed
        milliseconds now = duration_cast<milliseconds>(steady_clock::now().time_since_epoch());
        ASSERT_LT((start_ts - now).count(), vpn->upstream_config.recovery.location_update_period_ms);

        ASSERT_EQ(vpn->inactive_endpoints.size(), 0) << i;
        ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &selected_endpoint));
    }
}

// Check that after disconnect library goes to the next endpoint if recovery took longer than
// location update period
TEST_F(ConnectedVpnManagerTest, RecoveryNextEndpoint) {
    const VpnEndpoint selected_endpoint = *vpn->selected_endpoint_info.endpoint;
    // Reduce refresh period to reasonable value for test
    vpn->upstream_config.recovery.location_update_period_ms = 5000;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);

    bool recovery_reset = false;
    do {
        ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));

        recovery_reset = vpn->recovery.start_ts == time_point<steady_clock>{};

        ASSERT_TRUE(wait_state(VPN_SS_RECOVERING));

        if (!recovery_reset) {
            ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &selected_endpoint));
        } else {
            ASSERT_NO_FATAL_FAILURE(
                    ping_location(LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[1]}));
            ASSERT_NO_FATAL_FAILURE(connect_client_ok(&endpoints[1]));
            ASSERT_TRUE(wait_state(VPN_SS_CONNECTED));
            ASSERT_EQ(vpn->inactive_endpoints.size(), 0);
        }
        ASSERT_EQ(vpn->inactive_endpoints.size(), 0);
    } while (!recovery_reset);
}

// Check that location unavailable is reported to an application and the library tries to refresh
// the failed location
TEST_F(ConnectedVpnManagerTest, LocationUnavailable) {
    // Make it single attempt for each endpoint
    vpn->upstream_config.recovery.location_update_period_ms = 1000;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);
    ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));

    for (size_t i = 1; i < endpoints.size(); ++i) {
        ASSERT_EQ(vpn->recovery.start_ts, time_point<steady_clock>{});
        ASSERT_NO_FATAL_FAILURE(
                ping_location(LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[i]},
                        VpnLocation{vpn->upstream_config.location.id,
                                {(VpnEndpoint *) &endpoints[i], uint32_t(std::size(endpoints) - i)}}));

        ASSERT_TRUE(wait_state(VPN_SS_RECOVERING));
        ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &endpoints[i]));

        ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));
        ASSERT_EQ(vpn->inactive_endpoints.size(), i + 1);
    }

    ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));

    ASSERT_EQ(vpn_error.code, VPN_EC_LOCATION_UNAVAILABLE) << vpn_error.text;

    ASSERT_NO_FATAL_FAILURE(ping_location(LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[0]},
            VpnLocation{vpn->upstream_config.location.id,
                    {(VpnEndpoint *) endpoints.data(), uint32_t(std::size(endpoints))}}));
    ASSERT_NO_FATAL_FAILURE(connect_client_ok(&endpoints[0]));
    ASSERT_TRUE(wait_state(VPN_SS_CONNECTED));
    ASSERT_NO_FATAL_FAILURE(check_connect_result());

    ASSERT_EQ(vpn->inactive_endpoints.size(), 0);
}

// Check that the library does a health check on network properties update
TEST_F(ConnectedVpnManagerTest, NetworkPropertiesUpdate) {
    vpn_notify_network_change(vpn, false);
    ASSERT_TRUE(test_mock::g_client.wait_called(test_mock::CMID_DO_HEALTH_CHECK));
    ASSERT_EQ(vpn->fsm.get_state(), VPN_SS_CONNECTED);
}

// Check that the library tries to reconnect on network loss
TEST_F(ConnectedVpnManagerTest, NetworkLoss) {
    vpn_notify_network_change(vpn, true);
    ASSERT_TRUE(wait_state(VPN_SS_RECOVERING));
    ASSERT_NO_FATAL_FAILURE(ping_location());
    ASSERT_NO_FATAL_FAILURE(connect_client_ok(&endpoints[0]));
}

// Check that the library clears the list of inactive endpoints on network loss
TEST_F(ConnectedVpnManagerTest, NetworkLossClearInactiveList) {
    // Make it single attempt for each endpoint
    vpn->upstream_config.recovery.location_update_period_ms = 1000;

    raise_client_event(vpn_client::EVENT_DISCONNECTED);
    ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));
    ASSERT_EQ(vpn->inactive_endpoints.size(), 1);

    for (size_t i = 1; i < endpoints.size() - 1; ++i) {
        ASSERT_EQ(vpn->recovery.start_ts, time_point<steady_clock>{});
        ASSERT_NO_FATAL_FAILURE(
                ping_location(LocationsPingerResult{vpn->upstream_config.location.id, 10, &endpoints[i]},
                        VpnLocation{vpn->upstream_config.location.id,
                                {(VpnEndpoint *) &endpoints[i], uint32_t(std::size(endpoints) - i)}}));

        ASSERT_TRUE(wait_state(VPN_SS_RECOVERING));
        ASSERT_NO_FATAL_FAILURE(connect_client_fail(VPN_EC_ERROR, &endpoints[i]));

        ASSERT_TRUE(wait_state(VPN_SS_WAITING_RECOVERY));
        ASSERT_EQ(vpn->inactive_endpoints.size(), i + 1);
    }

    vpn_notify_network_change(vpn, true);
    ASSERT_TRUE(wait_state(VPN_SS_RECOVERING));
    ASSERT_NO_FATAL_FAILURE(ping_location(std::nullopt,
            VpnLocation{vpn->upstream_config.location.id,
                    {(VpnEndpoint *) endpoints.data(), uint32_t(std::size(endpoints))}}));
    ASSERT_EQ(vpn->inactive_endpoints.size(), 0);
}
