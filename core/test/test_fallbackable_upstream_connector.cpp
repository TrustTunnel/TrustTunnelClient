#include <thread>

#include <gtest/gtest.h>

#include "fallbackable_upstream_connector.h"

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

class FallbackableUpstreamConnectorTest : public testing::Test {
public:
    FallbackableUpstreamConnectorTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    static constexpr std::chrono::milliseconds FALLBACK_DELAY = std::chrono::milliseconds(100);

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_loop;
    TestUpstream *m_main_upstream = nullptr;
    TestUpstream *m_fallback_upstream = nullptr;
    std::unique_ptr<EndpointConnector> m_connector;
    std::optional<EndpointConnectorResult> m_raised_result;

    static void connector_handler(void *arg, EndpointConnectorResult result) {
        auto *self = (FallbackableUpstreamConnectorTest *) arg;
        self->m_raised_result = std::move(result);
    }

    void SetUp() override {
        m_loop.reset(vpn_event_loop_create());

        std::unique_ptr<TestUpstream> main = std::make_unique<TestUpstream>();
        m_main_upstream = main.get();

        std::unique_ptr<TestUpstream> fallback = std::make_unique<TestUpstream>();
        m_fallback_upstream = fallback.get();

        EndpointConnectorParameters connector_parameters = {
                m_loop.get(),
                (VpnClient *) this,
                {},
                {&connector_handler, this},
        };
        m_connector = std::make_unique<FallbackableUpstreamConnector>(
                connector_parameters, std::move(main), std::move(fallback), FALLBACK_DELAY);
    }

    void TearDown() override {
        m_connector.reset();
        m_main_upstream = nullptr;
        m_fallback_upstream = nullptr;
        m_raised_result.reset();
    }

    void run_event_loop_once() {
        vpn_event_loop_exit(m_loop.get(), Millis{0});
        vpn_event_loop_run(m_loop.get());
    }
};

TEST_F(FallbackableUpstreamConnectorTest, MainSucceedsBeforeFallbackStart) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_main_upstream->called_methods.open_session);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_main_upstream->called_methods.do_health_check);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    ASSERT_FALSE(m_fallback_upstream->called_methods.open_session);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<std::unique_ptr<ServerUpstream>>(m_raised_result.value()))
            << m_raised_result->index();
    ASSERT_EQ(std::get<std::unique_ptr<ServerUpstream>>(m_raised_result.value()).get(), m_main_upstream);
}

TEST_F(FallbackableUpstreamConnectorTest, MainSucceedsFasterThanFallback) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_main_upstream->called_methods.open_session);

    std::this_thread::sleep_for(FALLBACK_DELAY * 3 / 2);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.open_session);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_main_upstream->called_methods.do_health_check);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<std::unique_ptr<ServerUpstream>>(m_raised_result.value()))
            << m_raised_result->index();
    ASSERT_EQ(std::get<std::unique_ptr<ServerUpstream>>(m_raised_result.value()).get(), m_main_upstream);
}

TEST_F(FallbackableUpstreamConnectorTest, FallbackSucceedsFasterThanMain) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_main_upstream->called_methods.open_session);

    std::this_thread::sleep_for(FALLBACK_DELAY * 3 / 2);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.open_session);

    m_fallback_upstream->handler.func(m_fallback_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.do_health_check);

    m_fallback_upstream->handler.func(m_fallback_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<std::unique_ptr<ServerUpstream>>(m_raised_result.value()))
            << m_raised_result->index();
    ASSERT_EQ(std::get<std::unique_ptr<ServerUpstream>>(m_raised_result.value()).get(), m_fallback_upstream);
}

TEST_F(FallbackableUpstreamConnectorTest, MainFailsFallbackSucceeds) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_main_upstream->called_methods.open_session);

    std::this_thread::sleep_for(FALLBACK_DELAY * 3 / 2);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.open_session);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    m_fallback_upstream->handler.func(m_fallback_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.do_health_check);

    m_fallback_upstream->handler.func(m_fallback_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<std::unique_ptr<ServerUpstream>>(m_raised_result.value()))
            << m_raised_result->index();
    ASSERT_EQ(std::get<std::unique_ptr<ServerUpstream>>(m_raised_result.value()).get(), m_fallback_upstream);
}

TEST_F(FallbackableUpstreamConnectorTest, NoDelayAfterImmediateMainFail) {
    m_main_upstream->return_values.open_session = false;

    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;

    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.open_session);
}

TEST_F(FallbackableUpstreamConnectorTest, BothFailImmediately) {
    m_main_upstream->return_values.open_session = false;
    m_fallback_upstream->return_values.open_session = false;

    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;

    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<VpnError>(m_raised_result.value())) << m_raised_result->index();
}

TEST_F(FallbackableUpstreamConnectorTest, BothFail) {
    VpnError err = m_connector->connect(std::nullopt);
    ASSERT_EQ(err.code, VPN_EC_NOERROR) << err.text;
    ASSERT_TRUE(m_main_upstream->called_methods.open_session);

    std::this_thread::sleep_for(FALLBACK_DELAY * 3 / 2);
    this->run_event_loop_once();
    ASSERT_TRUE(m_fallback_upstream->called_methods.open_session);

    m_main_upstream->handler.func(m_main_upstream->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    this->run_event_loop_once();
    ASSERT_FALSE(m_raised_result.has_value());

    m_fallback_upstream->handler.func(m_fallback_upstream->handler.arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    this->run_event_loop_once();
    ASSERT_TRUE(m_raised_result.has_value());
    ASSERT_TRUE(std::holds_alternative<VpnError>(m_raised_result.value())) << m_raised_result->index();
}
