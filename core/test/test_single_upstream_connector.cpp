#include <gtest/gtest.h>

#include "single_upstream_connector.h"

using namespace ag;

struct UpstreamReturnValues {
    bool open_session = true;
    VpnError do_health_check = {};
};

struct UpstreamCalledMethods {
    bool open_session = false;
    bool do_health_check = false;
};

class TestUpstream : public ServerUpstream {
public:
    UpstreamReturnValues return_values = {};
    UpstreamCalledMethods called_methods = {};

    TestUpstream()
            : ServerUpstream(0) {
    }
    void deinit() override {
    }
    bool open_session(std::optional<Millis>) override {
        this->called_methods.open_session = true;
        return this->return_values.open_session;
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
        this->called_methods.do_health_check = true;
        return this->return_values.do_health_check;
    }
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override {
        return {};
    }
    void on_icmp_request(IcmpEchoRequestEvent &) override {
    }
};

class SingleUpstreamConnectorTest : public testing::Test {
public:
    SingleUpstreamConnectorTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_loop;
    TestUpstream *m_upstream = nullptr;
    std::unique_ptr<EndpointConnector> m_connector;
    std::optional<EndpointConnectorResult> m_raised_result;

    static void connector_handler(void *arg, EndpointConnectorResult result) {
        auto *self = (SingleUpstreamConnectorTest *) arg;
        self->m_raised_result = std::move(result);
    }

    void SetUp() override {
        m_loop.reset(vpn_event_loop_create());
        std::unique_ptr<TestUpstream> u = std::make_unique<TestUpstream>();
        m_upstream = u.get();

        EndpointConnectorParameters connector_parameters = {
                m_loop.get(),
                (VpnClient *) this,
                {},
                {&connector_handler, this},
        };
        m_connector = std::make_unique<SingleUpstreamConnector>(connector_parameters, std::move(u));
    }

    void TearDown() override {
        m_connector.reset();
        m_upstream = nullptr;
        m_raised_result.reset();
    }

    void run_event_loop_once() {
        vpn_event_loop_exit(m_loop.get(), Millis{0});
        vpn_event_loop_run(m_loop.get());
    }
};

TEST_F(SingleUpstreamConnectorTest, Successful) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_upstream->called_methods.open_session);

    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_upstream->called_methods.do_health_check);

    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<std::unique_ptr<ServerUpstream>>(m_raised_result.value()))
            << m_raised_result->index();
}

TEST_F(SingleUpstreamConnectorTest, OpenSessionStartFail) {
    m_upstream->return_values.open_session = false;

    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_NE(err.code, VPN_EC_NOERROR);
}

TEST_F(SingleUpstreamConnectorTest, OpenSessionFailed) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_upstream->called_methods.open_session);

    ServerError event = {NON_ID, {-1, "test"}};
    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_ERROR, &event);
    this->run_event_loop_once();
    ASSERT_FALSE(m_upstream->called_methods.do_health_check);
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<VpnError>(m_raised_result.value())) << m_raised_result->index();
}

TEST_F(SingleUpstreamConnectorTest, HelthCheckStartFail) {
    m_upstream->return_values.do_health_check = {-1, "test"};

    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_upstream->called_methods.open_session);

    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_upstream->called_methods.do_health_check);

    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<VpnError>(m_raised_result.value())) << m_raised_result->index();
}

TEST_F(SingleUpstreamConnectorTest, HealthCheckFailed) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_upstream->called_methods.open_session);

    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_upstream->called_methods.do_health_check);

    err = {-1, "test"};
    m_upstream->handler.func(m_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, &err);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<VpnError>(m_raised_result.value())) << m_raised_result->index();
}
