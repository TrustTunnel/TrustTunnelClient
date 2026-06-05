#include <unordered_map>
#include <vector>

#include <event2/event.h>
#include <gtest/gtest.h>

#include "common/logger.h"
#include "mock_ping_sockets.h"
#include "net/locations_pinger.h"
#include "vpn/utils.h"

using namespace ag;

struct TestCtx {
    LocationsPingerInfo info = {};
    std::unordered_map<std::string, LocationsPingerResult> results;
    std::unordered_map<std::string, std::string> result_ids;
    DeclPtr<LocationsPinger, &locations_pinger_destroy> pinger;
    VpnEventLoop *loop;
    bool finished = false;
};

static std::vector<std::string> make_ids(size_t size) {
    std::vector<std::string> ids;
    for (size_t i = 0; i < size; ++i) {
        ids.push_back(std::to_string(i));
    }
    return ids;
}

class LocationsPingerOfflineTest : public testing::Test {
public:
    LocationsPingerOfflineTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};

    void SetUp() override {
        test::mock_ping_sockets::reset();
        test::mock_ping_sockets::set_default_tcp_error(ag::utils::AG_ECONNREFUSED);
        test::mock_ping_sockets::set_default_quic_error(ag::utils::AG_ECONNREFUSED);
    }

    void TearDown() override {
        test::mock_ping_sockets::reset();
    }

    void run_event_loop() {
        vpn_event_loop_exit(loop.get(), Millis(2 * DEFAULT_PING_TIMEOUT_MS));
        vpn_event_loop_run(loop.get());
    }

    [[nodiscard]] TestCtx generate_test_ctx() const {
        TestCtx ctx = {};
        ctx.info = {0, {}};
        ctx.loop = this->loop.get();
        return ctx;
    }
};

static const VpnEndpoint *find_endpoint_in_context(const TestCtx *ctx, const VpnEndpoint *needle) {
    if (needle == nullptr) {
        return nullptr;
    }

    for (size_t i = 0; i < ctx->info.locations.size; ++i) {
        const VpnLocation *l = &ctx->info.locations.data[i];
        for (size_t j = 0; j < l->endpoints.size; ++j) {
            const VpnEndpoint *ep = &l->endpoints.data[j];
            if (vpn_endpoint_equals(needle, ep)) {
                return ep;
            }
        }
    }
    return nullptr;
}

TEST_F(LocationsPingerOfflineTest, SingleOffline) {
    VpnEndpoint expected_endpoint = {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"};
    std::vector addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            expected_endpoint,
    };
    VpnLocation location = {"10", {addresses.data(), uint32_t(addresses.size())}};

    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[2].address), 0);

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        vpn_event_loop_exit(ctx->loop, Millis{0});
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_TRUE(vpn_endpoint_equals(test_ctx.results[location.id].endpoint, &expected_endpoint));
}

TEST_F(LocationsPingerOfflineTest, WholeLocationFailedOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("[::42]:12"), "nullptr"},
            {sockaddr_from_str("0.0.0.0:12"), "nullptr"},
            {sockaddr_from_str("[::]:12"), "nullptr"},
    };
    VpnLocation location = {"offline-1", {addresses.data(), uint32_t(addresses.size())}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};
    test_ctx.info.timeout_ms = 300;

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        // waiting all the callbacks
                        if (result == nullptr) {
                            ctx->finished = true;
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                            return;
                        }
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_TRUE(test_ctx.finished);
    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.results[location.id].endpoint, nullptr);
    ASSERT_LT(test_ctx.results[location.id].ping_ms, 0);
}

TEST_F(LocationsPingerOfflineTest, MultipleOffline) {
    std::vector<VpnEndpoint> endpoints_1 = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
    };
    std::vector<VpnEndpoint> endpoints_2 = {
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };

    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints_1[0].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints_1[1].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints_2[0].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints_2[1].address), 0);

    std::vector<VpnLocation> locations = {
            {"10", {endpoints_1.data(), uint32_t(endpoints_1.size())}},
            {"11", {endpoints_2.data(), uint32_t(endpoints_2.size())}},
    };

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        if (ctx->results.size() == ctx->info.locations.size) {
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                        }
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (const auto &l : locations) {
        ASSERT_EQ(test_ctx.result_ids[l.id], l.id);
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.sa_family, AF_INET6);
    }
}

TEST_F(LocationsPingerOfflineTest, TimeoutOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("94.140.14.200:443"), "nullptr"},
            {sockaddr_from_str("94.140.14.222:443"), "nullptr"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "nullptr"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "nullptr"},
    };
    for (const auto &address : addresses) {
        test::mock_ping_sockets::set_tcp_error(SocketAddress(address.address), ag::utils::AG_ETIMEDOUT);
    }
    std::vector<std::string> ids = make_ids(addresses.size());
    std::vector<VpnLocation> locations;
    for (size_t i = 0; i < addresses.size(); ++i) {
        locations.emplace_back(VpnLocation{ids[i].c_str(), {&addresses[i], 1}});
    }

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.timeout_ms = 100;
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        if (ctx->results.size() == ctx->info.locations.size) {
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                        }
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (auto &i : test_ctx.results) {
        ASSERT_EQ(i.second.endpoint, nullptr);
    }
}

TEST_F(LocationsPingerOfflineTest, StopFromCallbackOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };
    for (const auto &address : addresses) {
        test::mock_ping_sockets::set_tcp_error(SocketAddress(address.address), 0);
    }
    std::vector<std::string> ids = make_ids(addresses.size());
    std::vector<VpnLocation> locations;
    locations.reserve(addresses.size());
    for (size_t i = 0; i < addresses.size(); ++i) {
        locations.emplace_back(VpnLocation{ids[i].c_str(), {&addresses[i], 1}});
    }

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        locations_pinger_stop(ctx->pinger.get());
                        vpn_event_loop_exit(ctx->loop, Secs(1));
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_LT(test_ctx.results.size(), locations.size());
}

TEST_F(LocationsPingerOfflineTest, StopNotFromCallbackOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };
    for (const auto &address : addresses) {
        test::mock_ping_sockets::set_tcp_error(SocketAddress(address.address), 0);
    }
    std::vector<std::string> ids = make_ids(addresses.size());
    std::vector<VpnLocation> locations;
    locations.reserve(addresses.size());
    for (size_t i = 0; i < addresses.size(); ++i) {
        locations.emplace_back(VpnLocation{ids[i].c_str(), {&addresses[i], 1}});
    }

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    vpn_event_loop_submit(test_ctx.loop,
            {
                    .arg = test_ctx.pinger.get(),
                    .action =
                            [](void *arg, TaskId) {
                                locations_pinger_stop((LocationsPinger *) arg);
                            },
            });

    vpn_event_loop_exit(test_ctx.loop, Secs(1));
    run_event_loop();

    ASSERT_LT(test_ctx.results.size(), locations.size());
}

TEST_F(LocationsPingerOfflineTest, EmptyLocationsFinishesImmediately) {
    TestCtx test_ctx = generate_test_ctx();

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        if (result == nullptr) {
                            ctx->finished = true;
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                        }
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();

    ASSERT_TRUE(test_ctx.finished);
    ASSERT_TRUE(test_ctx.results.empty());
}

TEST_F(LocationsPingerOfflineTest, DestroyFromCallbackWhenPingStartFails) {
    // name == nullptr causes ping_start to return nullptr (empty name check)
    VpnEndpoint endpoint = {sockaddr_from_str("1.1.1.1:443"), nullptr};
    VpnLocation location = {"1", {&endpoint, 1}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        if (result == nullptr) {
                            // "Done" signal: destroy pinger while still on the call stack of
                            // start_location_ping. Without a fix this causes use-after-free.
                            ctx->pinger.reset();
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                        }
                    },
                    &test_ctx,
            },
            loop.get(), network_manager.get()));

    run_event_loop();
}