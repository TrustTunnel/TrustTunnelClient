#include <atomic>
#include <thread>
#include <unordered_map>
#include <vector>

#include <event2/event.h>
#include <gtest/gtest.h>

#include "common/logger.h"
#include "net/locations_pinger.h"
#include "vpn/utils.h"

using namespace ag;

struct TestCtx {
    LocationsPingerInfo info = {};
    std::unordered_map<std::string, LocationsPingerResult> results;
    std::unordered_map<std::string, std::string> result_ids;
    DeclPtr<LocationsPinger, &locations_pinger_destroy> pinger;
    VpnEventLoop *loop;
};

static std::vector<std::string> make_ids(size_t size) {
    std::vector<std::string> ids;
    for (size_t i = 0; i < size; ++i) {
        ids.push_back(std::to_string(i));
    }
    return ids;
}

class LocationsPingerTest : public testing::Test {
public:
    LocationsPingerTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};

    void SetUp() override {
    }

    void TearDown() override {
        vpn_event_loop_finalize_exit(this->loop.get());
    }

    void run_event_loop() { // NOLINT(readability-make-member-function-const)
        // just not to hang
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

TEST_F(LocationsPingerTest, Single) {
#ifdef IPV6_UNAVAILABLE
    GTEST_SKIP() << "Comment me out if you want to run this test";
#endif

    // Cloudflare DNS servers
    VpnEndpoint expected_endpoint = {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"};
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            expected_endpoint,
    };
    VpnLocation location = {"10", {addresses.data(), uint32_t(addresses.size())}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        vpn_event_loop_exit(ctx->loop, Millis{0});
                    },
                    &test_ctx,
            },
            loop.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_TRUE(vpn_endpoint_equals(test_ctx.results[location.id].endpoint, &expected_endpoint))
            << sockaddr_to_str((sockaddr *) &test_ctx.results[location.id].endpoint->address);
}

TEST_F(LocationsPingerTest, WholeLocationFailed) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("[::42]:12"), "nullptr"},
            {sockaddr_from_str("1.2.3.4:12"), "nullptr"},
            {sockaddr_from_str("[::]:12"), "nullptr"},
            {sockaddr_from_str("0.0.0.0:12"), "nullptr"},
    };
    VpnLocation location = {"10", {addresses.data(), uint32_t(addresses.size())}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};
    test_ctx.info.timeout_ms = 500;

    test_ctx.pinger.reset(locations_pinger_start(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        if (result == nullptr) {
                            return;
                        }
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        vpn_event_loop_exit(ctx->loop, Millis{0});
                    },
                    &test_ctx,
            },
            loop.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_LT(test_ctx.results[location.id].ping_ms, 0);
    ASSERT_EQ(test_ctx.results[location.id].endpoint, nullptr);
}

TEST_F(LocationsPingerTest, Multiple) {
    // Cloudflare DNS servers
    std::vector<VpnEndpoint> endpoints_1 = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
    };
    std::vector<VpnEndpoint> endpoints_2 = {
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };

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
            loop.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), locations.size());

    for (const auto &l : locations) {
        ASSERT_EQ(test_ctx.result_ids[l.id], l.id)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#ifdef IPV6_UNAVAILABLE
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.ss_family, AF_INET)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#else
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.ss_family, AF_INET6)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#endif
    }
}

#ifndef _WIN32
TEST_F(LocationsPingerTest, Timeout) {
#else
// @note: a connection may establish before event loop start and result will be raised even before
//        this tiny timeout
TEST_F(LocationsPingerTest, DISABLED_Timeout) {
#endif
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("94.140.14.200:443"), "nullptr"},
            {sockaddr_from_str("1.2.3.4:443"), "nullptr"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "nullptr"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "nullptr"},
    };
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
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        if (ctx->results.size() == ctx->info.locations.size) {
                            vpn_event_loop_exit(ctx->loop, Millis{0});
                        }
                    },
                    &test_ctx,
            },
            loop.get()));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (auto &i : test_ctx.results) {
        ASSERT_EQ(i.second.endpoint, nullptr) << test_ctx.result_ids[i.first];
    }
}

TEST_F(LocationsPingerTest, StopFromCallback) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
            {sockaddr_from_str("1.2.3.4:443"), "nullptr"},
    };
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
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        locations_pinger_stop(ctx->pinger.get());
                        vpn_event_loop_exit(ctx->loop, Secs(1));
                    },
                    &test_ctx,
            },
            loop.get()));

    run_event_loop();

    ASSERT_LT(test_ctx.results.size(), locations.size());
}

TEST_F(LocationsPingerTest, StopNotFromCallback) {
    // Cloudflare DNS servers
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };
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
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                        locations_pinger_stop(ctx->pinger.get());
                        vpn_event_loop_exit(ctx->loop, Secs(1));
                    },
                    &test_ctx,
            },
            loop.get()));

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
