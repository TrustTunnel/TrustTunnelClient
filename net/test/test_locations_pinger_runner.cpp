#include <atomic>
#include <fstream>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <event2/event.h>
#include <event2/thread.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include "common/logger.h"
#include "net/locations_pinger.h"
#include "net/locations_pinger_runner.h"
#include "vpn/utils.h"

using namespace ag;

extern "C" VpnEventLoop *locations_pinger_runner_get_loop(LocationsPingerRunner *runner);

struct TestCtx {
    LocationsPingerInfo info = {};
    std::unordered_map<std::string, LocationsPingerResult> results;
    std::unordered_map<std::string, std::string> result_ids;
    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
};

static std::vector<std::string> make_ids(size_t size) {
    std::vector<std::string> ids;
    for (size_t i = 0; i < size; ++i) {
        ids.push_back(std::to_string(i));
    }
    return ids;
}

class LocationsPingerRunnerTest : public testing::Test {
public:
    LocationsPingerRunnerTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    void SetUp() override {
    }

    void TearDown() override {
    }

    TestCtx generate_test_ctx() {
        TestCtx ctx = {};
        ctx.info = {0, {}};
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

TEST_F(LocationsPingerRunnerTest, Single) {
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            }));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_TRUE(vpn_endpoint_equals(test_ctx.results[location.id].endpoint, &expected_endpoint))
            << sockaddr_to_str((sockaddr *) &test_ctx.results[location.id].endpoint->address);
}

TEST_F(LocationsPingerRunnerTest, WholeLocationFailed) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.2.3.4:12"), "nullptr"},
            {sockaddr_from_str("0.0.0.0:123"), "nullptr"},
            {sockaddr_from_str("[::42]:123"), "nullptr"},
            {sockaddr_from_str("[::]:123"), "nullptr"},
    };
    VpnLocation location = {"10", {addresses.data(), uint32_t(addresses.size())}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};
    test_ctx.info.timeout_ms = 500;

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            }));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_LT(test_ctx.results[location.id].ping_ms, 0);
    ASSERT_EQ(test_ctx.results[location.id].endpoint, nullptr);
}

TEST_F(LocationsPingerRunnerTest, Multiple) {
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        assert(ctx->results.count(result->id) == 0);
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            }));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), locations.size());

    for (const auto &l : locations) {
        ASSERT_EQ(test_ctx.result_ids[l.id], l.id)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#ifdef IPV6_UNAVAILABLE
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.ss_family, AF_INET)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#else
        // IPv6 should always be preferred
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.ss_family, AF_INET6)
                << sockaddr_to_str((sockaddr *) &test_ctx.results[l.id].endpoint->address);
#endif
    }
}

TEST_F(LocationsPingerRunnerTest, Timeout) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.2.3.4:443"), "nullptr"},
            {sockaddr_from_str("94.140.14.200:443"), "nullptr"},
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            }));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (auto &i : test_ctx.results) {
        ASSERT_EQ(i.second.endpoint, nullptr) << test_ctx.result_ids[i.first];
    }
}

TEST_F(LocationsPingerRunnerTest, StopAnotherThread) {
    // Cloudflare DNS servers
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
    };
    std::vector<std::string> ids = make_ids(addresses.size());
    std::vector<VpnLocation> locations;
    for (size_t i = 0; i < addresses.size(); ++i) {
        locations.emplace_back(VpnLocation{ids[i].c_str(), {&addresses[i], 1}});
    }

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (TestCtx *) arg;
                        ctx->results[result->id] = *result;
                        ctx->results[result->id].endpoint = find_endpoint_in_context(ctx, result->endpoint);
                        ctx->result_ids[result->id] = result->id;
                    },
                    &test_ctx,
            }));

    std::atomic_bool started = false;
    vpn_event_loop_submit(locations_pinger_runner_get_loop(test_ctx.runner.get()), {&started, [](void *arg, TaskId) {
                                                                                        *(std::atomic_bool *) arg =
                                                                                                true;
                                                                                    }});

    std::thread t1 = std::thread([&test_ctx]() {
        locations_pinger_runner_run(test_ctx.runner.get());
    });
    std::thread t2 = std::thread([&test_ctx, &started]() {
        while (!started) {
        }
        test_ctx.runner.reset();
    });
    t1.join();
    t2.join();

    ASSERT_LT(test_ctx.results.size(), locations.size());
}

TEST_F(LocationsPingerRunnerTest, DISABLED_Live) {
    std::ifstream in("locations.json");
    nlohmann::json json;
    in >> json;
    ASSERT_FALSE(in.fail());

    std::vector<VpnLocation> locations;
    locations.reserve(json["locations"].size());

    ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);

    for (auto &json_loc : json["locations"]) {
        VpnLocation &location = locations.emplace_back();
        location.id = safe_strdup(fmt::format(
                "{}/{}", json_loc["country_name"].get<std::string>(), json_loc["city_name"].get<std::string>())
                                          .c_str());
        location.endpoints.data = (VpnEndpoint *) malloc(2 * json_loc["endpoints"].size() * sizeof(VpnEndpoint));
        location.endpoints.size = 0;
        for (auto &ep : json_loc["endpoints"]) {
            for (const char *addr_propname : {"ipv4_address", "ipv6_address"}) {
                auto *endpoint = &location.endpoints.data[location.endpoints.size++];
                endpoint->name = safe_strdup(ep["domain_name"].get<std::string>().c_str());
                endpoint->address = sockaddr_from_str(ep[addr_propname].get<std::string>().c_str());
                sockaddr_set_port((sockaddr *) &endpoint->address, 443);
            }
        }
    }

    struct Result {
        std::string id;
        std::string address;
        int ms;
    };
    struct Ctx {
        std::mutex mtx;
        int num_errs, num, min, max, avg;
        std::vector<Result> results;
    };
    Ctx ctx{.min = INT_MAX};
    std::vector<std::thread> ts;
    ts.reserve(locations.size());

    LocationsPingerInfo info{};
    info.locations.size = locations.size();
    info.locations.data = locations.data();
    auto *runner = locations_pinger_runner_create(&info,
            {
                    .func =
                            [](void *arg, const LocationsPingerResult *result) {
                                auto *ctx = (Ctx *) arg;
                                std::scoped_lock l(ctx->mtx);
                                ++ctx->num;
                                if (result->ping_ms < 0) {
                                    ++ctx->num_errs;
                                    ctx->results.emplace_back(Result{result->id, "error", result->ping_ms});
                                    return;
                                }
                                ctx->avg += (result->ping_ms - ctx->avg) / ctx->num;
                                ctx->min = std::min(ctx->min, result->ping_ms);
                                ctx->max = std::max(ctx->max, result->ping_ms);
                                ctx->results.emplace_back(Result{result->id,
                                        sockaddr_to_str((sockaddr *) &result->endpoint->address), result->ping_ms});
                            },
                    .arg = &ctx,
            });
    locations_pinger_runner_run(runner);
    locations_pinger_runner_free(runner);

    std::sort(ctx.results.begin(), ctx.results.end(), [](const Result &a, const Result &b) {
        return a.ms > b.ms;
    });

    for (auto &res : ctx.results) {
        fmt::print("{:46} {:46} {} ms\n", res.id, res.address, res.ms);
    }
    fmt::print("min: {} ms, avg: {} ms, max: {} ms, errors: {}\n", ctx.min, ctx.avg, ctx.max, ctx.num_errs);

    ASSERT_EQ(locations.size(), ctx.num);
}
