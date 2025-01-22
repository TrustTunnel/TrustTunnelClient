#include <numeric>
#include <unordered_set>

#include <gtest/gtest.h>

#include "http2_upstream.h"
#include "upstream_multiplexer.h"

using namespace ag;

static int cert_verify_handler(
        const char * /*host_name*/, const sockaddr * /*host_ip*/, const CertVerifyCtx & /*ctx*/, void * /*arg*/) {
    return 1;
}

struct TestUpstreamInfo {
    ServerHandler handler;
    std::unordered_set<uint64_t> connections;
};

class TestUpstream : public MultiplexableUpstream {
public:
    TestUpstream(int id, VpnClient *vpn, ServerHandler handler)
            : MultiplexableUpstream({}, id, vpn, handler) {
    }

    ~TestUpstream() override = default;

    TestUpstream(const TestUpstream &) = delete;
    TestUpstream &operator=(const TestUpstream &) = delete;

    TestUpstream(TestUpstream &&) noexcept = delete;
    TestUpstream &operator=(TestUpstream &&) noexcept = delete;

    bool open_session(std::optional<Millis>) override;
    void close_session() override;
    bool open_connection(
            uint64_t conn_id, const TunnelAddressPair *addr, int proto, std::string_view app_name) override;
    void close_connection(uint64_t conn_id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t length) override;
    size_t available_to_send(uint64_t id) override;
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override;
    [[nodiscard]] size_t connections_num() const override;
    VpnError do_health_check() override;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override;
    void on_icmp_request(IcmpEchoRequestEvent &event) override;
};

class UpstreamMuxTest : public testing::Test {
public:
    UpstreamMuxTest()
            : vpn(vpn_client::Parameters{this->ev_loop.get()}) {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    static std::unordered_map<int, TestUpstreamInfo> g_upstreams;
    static std::optional<int> g_health_checking_upstream_id;
    static bool g_open_session_result;

    friend class TestUpstream;

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    VpnClient vpn;
    int events = 0;

    static void upstream_handler(void *arg, ServerEvent what, void *) {
        auto *test = (UpstreamMuxTest *) arg;
        test->events |= 1 << what;
    }

    void SetUp() override {
        g_open_session_result = true;

        this->vpn.parameters.cert_verify_handler = {&cert_verify_handler, this};
        this->vpn.endpoint_upstream = std::make_unique<UpstreamMultiplexer>(0, VpnUpstreamProtocolConfig{}, 0,
                [](const VpnUpstreamProtocolConfig &, int id, VpnClient *vpn,
                        ServerHandler handler) -> std::unique_ptr<MultiplexableUpstream> {
                    return std::make_unique<TestUpstream>(id, vpn, handler);
                });
        ASSERT_TRUE(this->vpn.endpoint_upstream->init(&this->vpn, {upstream_handler, this}));

        ASSERT_TRUE(this->vpn.endpoint_upstream->open_session());
        ASSERT_EQ(g_upstreams.size(), 1);

        ASSERT_NO_FATAL_FAILURE(notify_session_opened(g_upstreams.begin()->first));

        ASSERT_TRUE(is_raised(SERVER_EVENT_SESSION_OPENED)) << std::hex << this->events;
    }

    void TearDown() override {
        bool were_some = !g_upstreams.empty();
        while (!g_upstreams.empty()) {
            EXPECT_NO_FATAL_FAILURE(close_upstream(g_upstreams.begin()->first));
        }

        run_event_loop_once();

        if (were_some) {
            EXPECT_TRUE(is_raised(SERVER_EVENT_SESSION_CLOSED)) << std::hex << this->events;
        }
        g_upstreams.clear();
    }

    void notify_session_opened(int id) {
        ASSERT_EQ(g_upstreams.count(id), 1);

        ServerHandler *handler = &g_upstreams[id].handler;
        handler->func(handler->arg, SERVER_EVENT_SESSION_OPENED, nullptr);
    }

    void notify_session_closed(int id) {
        ASSERT_EQ(g_upstreams.count(id), 1);

        ServerHandler *handler = &g_upstreams[id].handler;
        handler->func(handler->arg, SERVER_EVENT_SESSION_CLOSED, nullptr);
    }

    void notify_session_error(int id, VpnErrorCode e) {
        ASSERT_EQ(g_upstreams.count(id), 1);

        ServerHandler *handler = &g_upstreams[id].handler;
        ServerError event = {NON_ID, {e, "test"}};
        handler->func(handler->arg, SERVER_EVENT_ERROR, &event);
    }

    uint64_t initiate_connection() { // NOLINT(readability-make-member-function-const)
        TunnelAddressPair addr = {sockaddr_from_str("1.1.1.1:1"), sockaddr_from_str("2.2.2.2:2")};
        uint64_t conn_id = this->vpn.endpoint_upstream->open_connection(&addr, IPPROTO_TCP, "");
        return conn_id;
    }

    void open_connection() {
        std::unordered_set<int> cur_upstreams = std::accumulate(g_upstreams.begin(), g_upstreams.end(),
                std::unordered_set<int>{}, [](std::unordered_set<int> acc, const auto &i) -> std::unordered_set<int> {
                    acc.emplace(i.first);
                    return acc;
                });

        uint64_t conn_id = initiate_connection();
        ASSERT_NE(conn_id, NON_ID);

        if (cur_upstreams.size() < g_upstreams.size()) {
            auto upstream_it =
                    std::find_if(g_upstreams.begin(), g_upstreams.end(), [&cur_upstreams](const auto &i) -> bool {
                        return cur_upstreams.count(i.first) == 0;
                    });
            ASSERT_NO_FATAL_FAILURE(notify_session_opened(upstream_it->first));
        }

        auto conn_it = std::find_if(g_upstreams.begin(), g_upstreams.end(), [conn_id](const auto &i) -> bool {
            return i.second.connections.count(conn_id) != 0;
        });
        ASSERT_NE(conn_it, g_upstreams.end());

        ServerHandler *handler = &g_upstreams[conn_it->first].handler;
        handler->func(handler->arg, SERVER_EVENT_CONNECTION_OPENED, &conn_id);
    }

    void close_connection(int upstream_id, uint64_t conn_id) {
        ASSERT_EQ(g_upstreams.count(upstream_id), 1) << upstream_id;
        ASSERT_EQ(g_upstreams[upstream_id].connections.erase(conn_id), 1) << conn_id;

        ServerHandler *handler = &g_upstreams[upstream_id].handler;
        handler->func(handler->arg, SERVER_EVENT_CONNECTION_CLOSED, &conn_id);
    }

    void close_upstream(int upstream_id) {
        ASSERT_EQ(g_upstreams.count(upstream_id), 1) << upstream_id;

        while (!g_upstreams[upstream_id].connections.empty()) {
            ASSERT_NO_FATAL_FAILURE(close_connection(upstream_id, *g_upstreams[upstream_id].connections.begin()));
        }

        ASSERT_NO_FATAL_FAILURE(notify_session_closed(upstream_id));

        run_event_loop_once();

        g_upstreams.erase(upstream_id);
    }

    void close_upstream_silent(int upstream_id) {
        ASSERT_EQ(g_upstreams.count(upstream_id), 1) << upstream_id;

        while (!g_upstreams[upstream_id].connections.empty()) {
            ASSERT_NO_FATAL_FAILURE(close_connection(upstream_id, *g_upstreams[upstream_id].connections.begin()));
        }

        g_upstreams.erase(upstream_id);
    }

    bool is_raised(ServerEvent e) { // NOLINT(readability-make-member-function-const)
        return !!(this->events & (1 << e));
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(this->ev_loop.get(), Millis{0});
        vpn_event_loop_run(this->ev_loop.get());
    }
};

std::unordered_map<int, TestUpstreamInfo> UpstreamMuxTest::g_upstreams;
std::optional<int> UpstreamMuxTest::g_health_checking_upstream_id;
bool UpstreamMuxTest::g_open_session_result;

bool TestUpstream::open_session(std::optional<Millis>) {
    UpstreamMuxTest::g_upstreams[m_id] = {handler};
    return UpstreamMuxTest::g_open_session_result;
}
void TestUpstream::close_session() {
    auto *test = (UpstreamMuxTest *) this->handler.arg;
    test->close_upstream_silent(m_id);
}
bool TestUpstream::open_connection(uint64_t conn_id, const TunnelAddressPair *, int, std::string_view) {
    return UpstreamMuxTest::g_upstreams[m_id].connections.emplace(conn_id).second;
}
void TestUpstream::close_connection(uint64_t conn_id, bool, bool) {
    UpstreamMuxTest::g_upstreams[m_id].connections.erase(conn_id);
}
ssize_t TestUpstream::send(uint64_t, const uint8_t *, size_t) {
    return 0;
}
void TestUpstream::consume(uint64_t id, size_t length) {
}
size_t TestUpstream::available_to_send(uint64_t) {
    return 0;
}
void TestUpstream::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
}
size_t TestUpstream::connections_num() const {
    return UpstreamMuxTest::g_upstreams[m_id].connections.size();
}
VpnError TestUpstream::do_health_check() {
    UpstreamMuxTest::g_health_checking_upstream_id = m_id;
    return {};
}
VpnConnectionStats TestUpstream::get_connection_stats() const {
    return {};
}
void TestUpstream::on_icmp_request(IcmpEchoRequestEvent &) {
}

// Check that the upstreams number does not grow if the number of connections is less than threshold
TEST_F(UpstreamMuxTest, SingleUpstreamBelowThreshold) {
    for (size_t i = 0; i < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD; ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
        ASSERT_EQ(g_upstreams.size(), 1);
    }
}

// Check that the upstreams number grow if the number of connections exceeds threshold
TEST_F(UpstreamMuxTest, UpstreamsGrowBeyondThreshold) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
        ASSERT_EQ(g_upstreams.size(), 1 + (i / UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD)) << i;
    }
}

// Check that the upstreams number grow don't grow beyond configured number
TEST_F(UpstreamMuxTest, UpstreamsNumCap) {
    for (size_t i = 0; i < 2 * UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD
                    * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
        if (i < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD
                        * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM) {
            ASSERT_LE(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM) << i;
        } else {
            ASSERT_EQ(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM) << i;
        }
    }
}

// Check that the least loaded upstream is selected for new connection
TEST_F(UpstreamMuxTest, LeastLoaded) {
    for (size_t i = 0; i < 2 * UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD
                    * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }
    ASSERT_EQ(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM);

    ASSERT_GT(g_upstreams.size(), 2); // otherwise the test makes no sense

    int id_1 = g_upstreams.begin()->first;
    int id_2 = std::next(g_upstreams.begin())->first;

    size_t connections_per_upstream = g_upstreams.begin()->second.connections.size();
    for (size_t i = 0; i < connections_per_upstream / 2; ++i) {
        ASSERT_NO_FATAL_FAILURE(close_connection(id_1, *g_upstreams[id_1].connections.begin()));
        ASSERT_NO_FATAL_FAILURE(close_connection(id_2, *g_upstreams[id_2].connections.begin()));
    }

    for (size_t i = 0; i < connections_per_upstream / 2; ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
        if ((i % 2) == 0) {
            ASSERT_NE(g_upstreams[id_1].connections.size(), g_upstreams[id_2].connections.size());
        } else {
            ASSERT_EQ(g_upstreams[id_1].connections.size(), g_upstreams[id_2].connections.size());
        }
    }
}

// Check that the session closed event is not raised after a non-fatal error on some (but not all) upstreams
TEST_F(UpstreamMuxTest, NonFatalErrorOnSomeUpstreams) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    // all but one upstreams raise errors
    while (g_upstreams.size() > 1) {
        int id = g_upstreams.begin()->first;
        ASSERT_NO_FATAL_FAILURE(notify_session_error(id, VPN_EC_ERROR));
        run_event_loop_once();
    }

    ASSERT_FALSE(is_raised(SERVER_EVENT_SESSION_CLOSED)) << std::hex << events;
}

// Check that the session closed event is raised after a non-fatal error on all the upstreams
TEST_F(UpstreamMuxTest, NonFatalErrorOnAllUpstreams) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    // all upstreams raise errors
    while (!g_upstreams.empty()) {
        int id = g_upstreams.begin()->first;
        ASSERT_NO_FATAL_FAILURE(notify_session_error(id, VPN_EC_ERROR));
        run_event_loop_once();
    }

    ASSERT_TRUE(is_raised(SERVER_EVENT_SESSION_CLOSED)) << std::hex << events;
}

// Check that the session closed event is raised after all the upstreams were closed
TEST_F(UpstreamMuxTest, AllUpstreamsClose) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    // all upstreams close
    while (!g_upstreams.empty()) {
        ASSERT_NO_FATAL_FAILURE(close_upstream(g_upstreams.begin()->first));
    }

    run_event_loop_once();

    ASSERT_TRUE(is_raised(SERVER_EVENT_SESSION_CLOSED)) << std::hex << events;
}

// Check that the session error event is raised after a fatal error on some upstream
TEST_F(UpstreamMuxTest, FatalErrorOnSomeUpstream) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    int id = g_upstreams.begin()->first;
    ASSERT_NO_FATAL_FAILURE(notify_session_error(id, VPN_EC_AUTH_REQUIRED));
    run_event_loop_once();
    ASSERT_TRUE(g_upstreams.empty());
    ASSERT_TRUE(is_raised(SERVER_EVENT_ERROR)) << std::hex << events;
}

// Check that the session error event is raised after an error on a health checking upstream
TEST_F(UpstreamMuxTest, ErrorOnHealthCheckingUpstream) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }

    VpnError error = this->vpn.endpoint_upstream->do_health_check();
    ASSERT_EQ(error.code, VPN_EC_NOERROR) << error.text;
    ASSERT_TRUE(g_health_checking_upstream_id.has_value());

    ASSERT_NO_FATAL_FAILURE(notify_session_error(g_health_checking_upstream_id.value(), VPN_EC_ERROR));
    run_event_loop_once();
    ASSERT_TRUE(g_upstreams.empty());
    ASSERT_TRUE(is_raised(SERVER_EVENT_ERROR)) << std::hex << events;
}

// Check that new upstreams appear instead of closed ones
TEST_F(UpstreamMuxTest, NewUpstreamsInsteadClosed) {
    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }
    ASSERT_EQ(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM);

    // close all but one upstreams
    while (g_upstreams.size() > 1) {
        ASSERT_NO_FATAL_FAILURE(close_upstream(g_upstreams.begin()->first));
    }

    run_event_loop_once();
    ASSERT_FALSE(is_raised(SERVER_EVENT_SESSION_CLOSED)) << std::hex << events;

    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(open_connection());
    }
    ASSERT_EQ(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM);
}

// Check that connections are postponed until upstream session is opened
TEST_F(UpstreamMuxTest, PostponeConnections) {
    // the first upstream has already established session
    ASSERT_EQ(g_upstreams.size(), 1);
    int excluded_id = g_upstreams.begin()->first;

    for (size_t i = 0; i
            < UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD * UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM;
            ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_connection());
    }
    ASSERT_EQ(g_upstreams.size(), UpstreamMultiplexer::DEFAULT_UPSTREAMS_NUM);

    // check that `open_connection` was not called on all but the first upstreams
    for (auto &[id, info] : g_upstreams) {
        if (id != excluded_id) {
            ASSERT_TRUE(info.connections.empty()) << id;
        }
    }

    // check that after the session opened event `open_connection` is called
    for (auto &[id, info] : g_upstreams) {
        if (id != excluded_id) {
            ASSERT_NO_FATAL_FAILURE(notify_session_opened(id));
            ASSERT_FALSE(info.connections.empty()) << id;
        }
    }
}

// Check that connections are postponed if multiplexer falls back to unconnected upstream
TEST_F(UpstreamMuxTest, FallBackToUnconnectedUpstream) {
    int first_upstream_id = g_upstreams.begin()->first;
    // make new unconnected upstream
    for (size_t i = 0; i < 2 * UpstreamMultiplexer::NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD; ++i) {
        ASSERT_NO_FATAL_FAILURE(initiate_connection());
    }
    ASSERT_EQ(g_upstreams.size(), 2);

    // leave only unconnected upstream
    ASSERT_NO_FATAL_FAILURE(close_upstream(first_upstream_id));
    run_event_loop_once();
    ASSERT_EQ(g_upstreams.size(), 1);

    first_upstream_id = g_upstreams.begin()->first;
    int next_expected_upstream_id = first_upstream_id + 1;
    // fail the next `open_session` call
    g_open_session_result = false;

    // new client connection should initiate new upstream creation as current one is at the cap
    // of connections
    uint64_t conn_id = initiate_connection();
    // check new connection is not rejected immediately as the selected upstream is still not connected
    ASSERT_NE(conn_id, NON_ID);
    ASSERT_EQ(g_upstreams.size(), 2);
    ASSERT_EQ(g_upstreams.count(next_expected_upstream_id), 1);
    g_upstreams.erase(next_expected_upstream_id);

    // check that `open_connection` was not called as the upstream is still not connected
    ASSERT_EQ(g_upstreams[first_upstream_id].connections.size(), 0) << first_upstream_id;
}
