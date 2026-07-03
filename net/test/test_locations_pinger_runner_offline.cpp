#include <atomic>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "mock_ping_sockets.h"
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

class LocationsPingerRunnerOfflineTest : public testing::Test {
public:
    LocationsPingerRunnerOfflineTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    void SetUp() override {
        test::mock_ping_sockets::reset();
        test::mock_ping_sockets::set_default_tcp_error(ag::utils::AG_ECONNREFUSED);
        test::mock_ping_sockets::set_default_quic_error(ag::utils::AG_ECONNREFUSED);
    }

    void TearDown() override {
        test::mock_ping_sockets::reset();
    }

    [[nodiscard]] TestCtx generate_test_ctx() const {
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

static void standard_runner_cb(void *arg, const LocationsPingerResult *result) {
    auto *ctx = (TestCtx *) arg;
    const char *id = result->id;
    const VpnEndpoint *ep = result->endpoint;
    ctx->results[id] = *result;
    ctx->results[id].endpoint = find_endpoint_in_context(ctx, ep);
    ctx->result_ids[id] = id;
}

TEST_F(LocationsPingerRunnerOfflineTest, SingleOffline) {
    VpnEndpoint expected_endpoint = {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"};
    std::vector<VpnEndpoint> addresses = {
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_TRUE(vpn_endpoint_equals(test_ctx.results[location.id].endpoint, &expected_endpoint));
}

TEST_F(LocationsPingerRunnerOfflineTest, WholeLocationFailedOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("0.0.0.0:123"), "nullptr"},
            {sockaddr_from_str("[::]:123"), "nullptr"},
            {sockaddr_from_str("[::42]:123"), "nullptr"},
    };
    VpnLocation location = {"runner-offline-1", {addresses.data(), uint32_t(addresses.size())}};

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {&location, 1};
    test_ctx.info.timeout_ms = 300;

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), 1);
    ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
    ASSERT_EQ(test_ctx.results[location.id].endpoint, nullptr);
    ASSERT_LT(test_ctx.results[location.id].ping_ms, 0);
}

TEST_F(LocationsPingerRunnerOfflineTest, MultipleLocationsFailedOffline) {
    std::vector<VpnEndpoint> endpoints1 = {
            {sockaddr_from_str("0.0.0.0:12"), "nullptr"},
    };
    std::vector<VpnEndpoint> endpoints2 = {
            {sockaddr_from_str("[::]:12"), "nullptr"},
    };
    std::vector<VpnLocation> locations = {
            {"runner-offline-2", {endpoints1.data(), uint32_t(endpoints1.size())}},
            {"runner-offline-3", {endpoints2.data(), uint32_t(endpoints2.size())}},
    };

    TestCtx test_ctx = generate_test_ctx();
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};
    test_ctx.info.timeout_ms = 300;

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (const auto &location : locations) {
        ASSERT_EQ(test_ctx.result_ids[location.id], location.id);
        ASSERT_EQ(test_ctx.results[location.id].endpoint, nullptr);
        ASSERT_LT(test_ctx.results[location.id].ping_ms, 0);
    }
}

TEST_F(LocationsPingerRunnerOfflineTest, MultipleOffline) {
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (const auto &l : locations) {
        ASSERT_EQ(test_ctx.result_ids[l.id], l.id);
        ASSERT_EQ(test_ctx.results[l.id].endpoint->address.sa_family, AF_INET6);
    }
}

TEST_F(LocationsPingerRunnerOfflineTest, TimeoutOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("94.140.14.222:443"), "nullptr"},
            {sockaddr_from_str("94.140.14.200:443"), "nullptr"},
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

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

    locations_pinger_runner_run(test_ctx.runner.get());

    ASSERT_EQ(test_ctx.results.size(), locations.size());
    for (auto &i : test_ctx.results) {
        ASSERT_EQ(i.second.endpoint, nullptr);
    }
}

TEST_F(LocationsPingerRunnerOfflineTest, StopAnotherThreadOffline) {
    std::vector<VpnEndpoint> addresses = {
            {sockaddr_from_str("1.1.1.1:443"), "nullptr"},
            {sockaddr_from_str("1.0.0.1:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1111]:443"), "nullptr"},
            {sockaddr_from_str("[2606:4700:4700::1001]:443"), "nullptr"},
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
    test_ctx.info.locations = {locations.data(), uint32_t(locations.size())};

    test_ctx.runner.reset(locations_pinger_runner_create(&test_ctx.info, {standard_runner_cb, &test_ctx}));

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

TEST_F(LocationsPingerRunnerOfflineTest, RelayAddressesOffline) {
    std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("94.140.14.222:443"), "one.one.one.one"},
            {sockaddr_from_str("94.140.14.200:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "one.one.one.one"},
    };
    std::vector<VpnRelay> relays = {
            {sockaddr_from_str("1.2.3.5:443")},
            {sockaddr_from_str("1.1.1.1:443")},
    };
    for (const auto &endpoint : endpoints) {
        test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[0].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[1].address), 0);

    VpnLocation location{
            .id = "Cloudflare 1.1.1.1",
            .endpoints = {.data = endpoints.data(), .size = (uint32_t) endpoints.size()},
            .relays = {.data = relays.data(), .size = (uint32_t) relays.size()},
    };
    struct RelayCtx {
        AutoVpnEndpoint endpoint{};
        std::string relay_address;
        int count = 0;
    } ctx;

    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
    LocationsPingerInfo info{
            .timeout_ms = 1000,
            .locations = {&location, 1},
            .rounds = 1,
    };
    runner.reset(locations_pinger_runner_create(&info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (RelayCtx *) arg;
                        if (result->endpoint) {
                            ctx->endpoint = vpn_endpoint_clone(result->endpoint);
                        }
                        if (result->relay) {
                            ctx->relay_address = SocketAddress(result->relay->address).str();
                        }
                        ++ctx->count;
                    },
                    &ctx,
            }));
    std::thread t1 = std::thread([&runner]() {
        locations_pinger_runner_run(runner.get());
    });
    t1.join();

    ASSERT_EQ(1, ctx.count);
    ASSERT_STREQ("one.one.one.one", ctx.endpoint->name);
    ASSERT_EQ("1.1.1.1:443", ctx.relay_address);
}

TEST_F(LocationsPingerRunnerOfflineTest, QuicToTlsFallbackOffline) {
    std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("9.9.9.9:443"), "dns.quad9.net"},
            {sockaddr_from_str("149.112.112.112:443"), "dns.quad9.net"},
            {sockaddr_from_str("[2620:fe::fe]:443"), "dns.quad9.net"},
            {sockaddr_from_str("[2620:fe::9]:443"), "dns.quad9.net"},
    };
    for (const auto &endpoint : endpoints) {
        test::mock_ping_sockets::set_quic_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
        test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoint.address), ag::utils::AG_ECONNREFUSED);
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints[2].address), 0);

    VpnLocation location{
            .id = "Quad9",
            .endpoints = {.data = endpoints.data(), .size = (uint32_t) endpoints.size()},
    };
    struct QuicFallbackCtx {
        AutoVpnEndpoint endpoint{};
        std::string relay_address;
        int count = 0;
    } ctx;

    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
    LocationsPingerInfo info{
            .timeout_ms = 1000,
            .locations = {&location, 1},
            .rounds = 1,
            .main_protocol = VPN_UP_HTTP3,
    };
    runner.reset(locations_pinger_runner_create(&info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (QuicFallbackCtx *) arg;
                        if (result->endpoint) {
                            ctx->endpoint = vpn_endpoint_clone(result->endpoint);
                        }
                        if (result->relay) {
                            ctx->relay_address = SocketAddress(result->relay->address).str();
                        }
                        ++ctx->count;
                    },
                    &ctx,
            }));
    std::thread t1 = std::thread([&runner]() {
        locations_pinger_runner_run(runner.get());
    });
    t1.join();

    ASSERT_EQ(1, ctx.count);
    ASSERT_TRUE(vpn_endpoint_equals(ctx.endpoint.get(), &endpoints[2]));
    ASSERT_EQ("", ctx.relay_address);
}

TEST_F(LocationsPingerRunnerOfflineTest, QuicToTlsFallbackAndRelayAddressesOffline) {
    std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("94.140.14.222:443"), "dns.quad9.net"},
            {sockaddr_from_str("94.140.14.200:443"), "dns.quad9.net"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "dns.quad9.net"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "dns.quad9.net"},
    };
    std::vector<VpnRelay> relays = {
            {sockaddr_from_str("94.140.14.222:443")},
            {sockaddr_from_str("[2a10:50c0::42]:443")},
            {sockaddr_from_str("9.9.9.9:443")},
    };
    for (const auto &endpoint : endpoints) {
        test::mock_ping_sockets::set_quic_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
        test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[0].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[1].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[2].address), 0);
    test::mock_ping_sockets::set_quic_error(SocketAddress(relays[0].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_quic_error(SocketAddress(relays[1].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_quic_error(SocketAddress(relays[2].address), ag::utils::AG_ETIMEDOUT);

    VpnLocation location{
            .id = "Quad9",
            .endpoints = {.data = endpoints.data(), .size = (uint32_t) endpoints.size()},
            .relays = {.data = relays.data(), .size = (uint32_t) relays.size()},
    };
    struct RelayFallbackCtx {
        AutoVpnEndpoint endpoint{};
        std::string relay_address;
        int count = 0;
    } ctx;

    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
    LocationsPingerInfo info{
            .timeout_ms = 1000,
            .locations = {&location, 1},
            .rounds = 1,
            .main_protocol = VPN_UP_HTTP3,
    };
    runner.reset(locations_pinger_runner_create(&info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (RelayFallbackCtx *) arg;
                        if (result->endpoint) {
                            ctx->endpoint = vpn_endpoint_clone(result->endpoint);
                        }
                        if (result->relay) {
                            ctx->relay_address = SocketAddress(result->relay->address).str();
                        }
                        ++ctx->count;
                    },
                    &ctx,
            }));
    std::thread t1 = std::thread([&runner]() {
        locations_pinger_runner_run(runner.get());
    });
    t1.join();

    ASSERT_EQ(1, ctx.count);
    ASSERT_STREQ("dns.quad9.net", ctx.endpoint->name);
    ASSERT_EQ("9.9.9.9:443", ctx.relay_address);
}

TEST_F(LocationsPingerRunnerOfflineTest, NoRelayIfAnyAccessibleWithoutRelayQuicOffline) {
    std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("94.140.14.200:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "one.one.one.one"},
            {sockaddr_from_str("[fe80::]:443"), "dns.quad9.net"},
            {sockaddr_from_str("1.1.1.1:443"), "one.one.one.one"},
    };
    std::vector<VpnRelay> relays = {
            {sockaddr_from_str("1.0.0.1:443")},
    };
    for (const auto &endpoint : endpoints) {
        test::mock_ping_sockets::set_quic_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
        test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints[3].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints[4].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[0].address), 0);
    test::mock_ping_sockets::set_quic_error(SocketAddress(relays[0].address), ag::utils::AG_ETIMEDOUT);

    VpnLocation location{
            .id = "OneOneOneOne",
            .endpoints = {.data = endpoints.data(), .size = (uint32_t) endpoints.size()},
            .relays = {.data = relays.data(), .size = (uint32_t) relays.size()},
    };
    struct DirectPreferredCtx {
        AutoVpnEndpoint endpoint{};
        std::string relay_address;
        int count = 0;
    } ctx;

    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
    LocationsPingerInfo info{
            .timeout_ms = 3000,
            .locations = {&location, 1},
            .rounds = 1,
            .main_protocol = VPN_UP_HTTP3,
    };
    runner.reset(locations_pinger_runner_create(&info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (DirectPreferredCtx *) arg;
                        if (result->endpoint) {
                            ctx->endpoint = vpn_endpoint_clone(result->endpoint);
                        }
                        if (result->relay) {
                            ctx->relay_address = SocketAddress(result->relay->address).str();
                        }
                        ++ctx->count;
                    },
                    &ctx,
            }));
    std::thread t1 = std::thread([&runner]() {
        locations_pinger_runner_run(runner.get());
    });
    t1.join();

    ASSERT_EQ(1, ctx.count);
    ASSERT_TRUE(vpn_endpoint_equals(ctx.endpoint.get(), &endpoints[4]));
    ASSERT_TRUE(ctx.relay_address.empty());
}

TEST_F(LocationsPingerRunnerOfflineTest, NoRelayIfAnyAccessibleWithoutRelayOffline) {
    std::vector<VpnEndpoint> endpoints = {
            {sockaddr_from_str("94.140.14.200:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::42]:443"), "one.one.one.one"},
            {sockaddr_from_str("[2a10:50c0::43]:443"), "one.one.one.one"},
            {sockaddr_from_str("[fe80::]:443"), "dns.quad9.net"},
            {sockaddr_from_str("1.1.1.1:443"), "one.one.one.one"},
    };
    std::vector<VpnRelay> relays = {
            {sockaddr_from_str("1.0.0.1:443")},
    };
    for (const auto &endpoint : endpoints) {
        test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoint.address), ag::utils::AG_ETIMEDOUT);
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints[3].address), ag::utils::AG_ECONNREFUSED);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(endpoints[4].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(relays[0].address), 0);

    VpnLocation location{
            .id = "OneOneOneOne",
            .endpoints = {.data = endpoints.data(), .size = (uint32_t) endpoints.size()},
            .relays = {.data = relays.data(), .size = (uint32_t) relays.size()},
    };
    struct NoRelayCtx {
        AutoVpnEndpoint endpoint{};
        std::string relay_address;
        int count = 0;
    } ctx;

    DeclPtr<LocationsPingerRunner, &locations_pinger_runner_free> runner;
    LocationsPingerInfo info{
            .timeout_ms = 3000,
            .locations = {&location, 1},
            .rounds = 1,
            .main_protocol = VPN_UP_HTTP2,
    };
    runner.reset(locations_pinger_runner_create(&info,
            {
                    [](void *arg, const LocationsPingerResult *result) {
                        auto *ctx = (NoRelayCtx *) arg;
                        if (result->endpoint) {
                            ctx->endpoint = vpn_endpoint_clone(result->endpoint);
                        }
                        if (result->relay) {
                            ctx->relay_address = SocketAddress(result->relay->address).str();
                        }
                        ++ctx->count;
                    },
                    &ctx,
            }));
    std::thread t1 = std::thread([&runner]() {
        locations_pinger_runner_run(runner.get());
    });
    t1.join();

    ASSERT_EQ(1, ctx.count);
    ASSERT_TRUE(vpn_endpoint_equals(ctx.endpoint.get(), &endpoints[4]));
    ASSERT_TRUE(ctx.relay_address.empty());
}
