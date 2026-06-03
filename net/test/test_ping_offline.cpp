#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include <event2/util.h>
#include <gtest/gtest.h>

#include "common/logger.h"
#include "mock_ping_sockets.h"
#include "ping.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

using namespace ag;

constexpr uint32_t SHORT_PING_TIMEOUT_MS = 500;
constexpr uint32_t LONG_PING_TIMEOUT_MS = 5000;

struct TestCtx {
    VpnEventLoop *loop = nullptr;
    VpnNetworkManager *network_manager = nullptr;
    event_base *base = nullptr;
    DeclPtr<Ping, &ping_destroy> ping;
    std::unordered_map<std::string, PingResult> results;
    bool finished = false;
    bool cancelled = false;
};

struct TestCtxRounds {
    VpnEventLoop *loop = nullptr;
    VpnNetworkManager *network_manager = nullptr;
    event_base *base = nullptr;
    DeclPtr<Ping, &ping_destroy> ping;
    std::unordered_map<std::string, std::vector<PingResult>> results;
    bool finished = false;
};

class PingOfflineTest : public testing::Test {
public:
    PingOfflineTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};

    void run_event_loop() {
        vpn_event_loop_exit(loop.get(), Millis(2 * DEFAULT_PING_TIMEOUT_MS));
        vpn_event_loop_run(loop.get());
    }

    [[nodiscard]] TestCtx generate_test_ctx() const {
        TestCtx ctx = {};
        ctx.loop = this->loop.get();
        ctx.network_manager = this->network_manager.get();
        ctx.base = vpn_event_loop_get_base(this->loop.get());
        return ctx;
    }

    [[nodiscard]] TestCtxRounds generate_test_ctx_rounds() const {
        TestCtxRounds ctx = {};
        ctx.loop = this->loop.get();
        ctx.network_manager = this->network_manager.get();
        ctx.base = vpn_event_loop_get_base(this->loop.get());
        return ctx;
    }

    void SetUp() override {
        test::mock_ping_sockets::reset();
    }

    void TearDown() override {
        test::mock_ping_sockets::reset();
    }
};

static void standard_ping_cb(void *ctx, PingResult *result) {
    auto *test_ctx = (TestCtx *) ctx;
    if (result->status == PING_FINISHED) {
        test_ctx->finished = true;
        event_base_loopbreak(test_ctx->base);
        return;
    }
    test_ctx->results[SocketAddress(result->endpoint->address).str()] = std::move(*result);
}

TEST_F(PingOfflineTest, Single) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"8.8.8.8:80", PING_TIMEDOUT},
            {"127.0.0.1:12", PING_SOCKET_ERROR},
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i.first), .name = i.first});
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[2].address), ag::utils::AG_ECONNREFUSED);

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = LONG_PING_TIMEOUT_MS,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info, {standard_ping_cb, &test_ctx}));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].status, i.second) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].ping, test_ctx.ping.get()) << i.first;
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingOfflineTest, Timeout) {
    static const char *const TEST_DATA[] = {
            "94.140.14.200:443",
            "94.140.14.222:443",
            "[2a10:50c0::42]:443",
            "[2a10:50c0::43]:443",
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i), .name = i});
        test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses.back().address), ag::utils::AG_ETIMEDOUT);
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = SHORT_PING_TIMEOUT_MS,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info, {standard_ping_cb, &test_ctx}));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i), 1) << i;
        ASSERT_EQ(test_ctx.results[i].status, PING_TIMEDOUT) << i;
        ASSERT_EQ(test_ctx.results[i].ping, test_ctx.ping.get()) << i;
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingOfflineTest, Multiple) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"8.8.8.8:80", PING_TIMEDOUT},
            {"0.0.0.0:12", PING_SOCKET_ERROR},
    };
    static constexpr uint32_t TIMEOUT = 1500;

    std::vector<TestCtx> contexts;
    for (const auto &i : TEST_DATA) {
        VpnEndpoint addr{.address = sockaddr_from_str(i.first), .name = i.first};
        if (i.second == PING_OK) {
            test::mock_ping_sockets::set_tcp_error(SocketAddress(addr.address), 0);
        } else if (i.second == PING_TIMEDOUT) {
            test::mock_ping_sockets::set_tcp_error(SocketAddress(addr.address), ag::utils::AG_ETIMEDOUT);
        } else {
            test::mock_ping_sockets::set_tcp_error(SocketAddress(addr.address), ag::utils::AG_ECONNREFUSED);
        }

        TestCtx &test_ctx = contexts.emplace_back(generate_test_ctx());
        PingInfo info = {
                .loop = test_ctx.loop,
                .network_manager = test_ctx.network_manager,
                .endpoints = {&addr, 1},
                .timeout_ms = TIMEOUT,
                .nrounds = 1,
        };
        test_ctx.ping.reset(ping_start(&info,
                {
                        [](void *ctx, PingResult *result) {
                            auto *contexts = (std::vector<TestCtx> *) ctx;

                            auto found = std::ranges::find_if(*contexts, [ping = result->ping](const TestCtx &item) {
                                return ping == item.ping.get();
                            });
                            assert(found != contexts->end());

                            TestCtx *test_ctx = &*found;
                            if (result->status == PING_FINISHED) {
                                test_ctx->finished = true;
                                if (std::ranges::all_of(*contexts, [](const TestCtx &item) {
                                        return item.finished;
                                    })) {
                                    event_base_loopbreak(test_ctx->base);
                                }
                                return;
                            }

                            test_ctx->results[SocketAddress(result->endpoint->address).str()] = std::move(*result);
                        },
                        &contexts,
                }));
    }

    run_event_loop();

    ASSERT_EQ(contexts.size(), std::size(TEST_DATA));
    for (size_t i = 0; i < std::size(TEST_DATA); ++i) {
        TestCtx &test_ctx = contexts[i];
        std::string addr_str = TEST_DATA[i].first;

        ASSERT_EQ(test_ctx.results.count(addr_str), 1) << addr_str;
        ASSERT_EQ(test_ctx.results[addr_str].status, TEST_DATA[i].second) << addr_str;
        ASSERT_EQ(test_ctx.results[addr_str].ping, test_ctx.ping.get()) << addr_str;
        ASSERT_TRUE(test_ctx.finished) << addr_str;
    }
}

TEST_F(PingOfflineTest, AllAddressesInvalid) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"0.0.0.0:12", PING_SOCKET_ERROR},
            {"[::]:12", PING_SOCKET_ERROR},
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i.first), .name = i.first});
        test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses.back().address), ag::utils::AG_ECONNREFUSED);
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = SHORT_PING_TIMEOUT_MS,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info, {standard_ping_cb, &test_ctx}));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].status, i.second) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].ping, test_ctx.ping.get()) << i.first;
    }
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingOfflineTest, DestroyInProgressPingAfterCallback) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"127.0.0.7:12", PING_SOCKET_ERROR},
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i.first), .name = i.first});
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ECONNREFUSED);

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = SHORT_PING_TIMEOUT_MS,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (!test_ctx->cancelled) {
                            event_loop::submit(test_ctx->loop,
                                    {
                                            .arg = test_ctx,
                                            .action =
                                                    [](void *arg, TaskId) {
                                                        auto *local_ctx = (TestCtx *) arg;
                                                        local_ctx->ping.reset();
                                                        vpn_event_loop_exit(local_ctx->loop, Secs(1));
                                                    },
                                    })
                                    .release();
                            test_ctx->cancelled = true;
                        }

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopexit(test_ctx->base, nullptr);
                            return;
                        }

                        test_ctx->results[SocketAddress(result->endpoint->address).str()] = std::move(*result);
                    },
                    &test_ctx,
            }));

    run_event_loop();

    ASSERT_LE(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_FALSE(test_ctx.finished);
    ASSERT_TRUE(test_ctx.cancelled);
}

TEST_F(PingOfflineTest, DestroyInProgressPing) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"8.8.8.8:80", PING_TIMEDOUT},
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i.first), .name = i.first});
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ETIMEDOUT);

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = SHORT_PING_TIMEOUT_MS,
            .nrounds = 1,
    };

    event_loop::submit(test_ctx.loop,
            {
                    .arg = &test_ctx,
                    .action =
                            [](void *arg, TaskId) {
                                auto *local_ctx = (TestCtx *) arg;
                                local_ctx->ping.reset();
                                vpn_event_loop_exit(local_ctx->loop, Secs(1));
                            },
            })
            .release();

    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (!test_ctx->cancelled) {
                            test_ctx->cancelled = true;
                        }

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                        }

                        test_ctx->results[SocketAddress(result->endpoint->address).str()] = std::move(*result);
                    },
                    &test_ctx,
            }));

    run_event_loop();

    ASSERT_FALSE(test_ctx.cancelled);
    ASSERT_FALSE(test_ctx.finished);
    ASSERT_EQ(0, test_ctx.results.size());
}

TEST_F(PingOfflineTest, MultipleRounds) {
    static const std::pair<const char *, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"8.8.8.8:80", PING_TIMEDOUT},
            {"127.0.0.1:12", PING_SOCKET_ERROR},
    };
    static const int ROUNDS = 3;

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i.first), .name = i.first});
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), 0);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[2].address), ag::utils::AG_ECONNREFUSED);

    TestCtxRounds test_ctx = generate_test_ctx_rounds();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = LONG_PING_TIMEOUT_MS,
            .nrounds = ROUNDS,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, PingResult *result) {
                        auto *test_ctx = (TestCtxRounds *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[SocketAddress(result->endpoint->address).str()].emplace_back(
                                std::move(*result));
                    },
                    &test_ctx,
            }));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].size(), 1) << i.first;
        for (const auto &r : test_ctx.results[i.first]) {
            ASSERT_EQ(r.status, i.second) << i.first;
            ASSERT_EQ(r.ping, test_ctx.ping.get()) << i.first;
        }
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingOfflineTest, LocalhostClosedPortIsNotPingOk) {
    static const char *const TEST_DATA[] = {
            "127.0.0.1:1",
            "[::1]:1",
    };

    std::vector<VpnEndpoint> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(VpnEndpoint{.address = sockaddr_from_str(i), .name = i});
    }
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[0].address), ag::utils::AG_ETIMEDOUT);
    test::mock_ping_sockets::set_tcp_error(SocketAddress(addresses[1].address), ag::utils::AG_ECONNREFUSED);

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .network_manager = test_ctx.network_manager,
            .endpoints = {addresses.data(), addresses.size()},
            .timeout_ms = SHORT_PING_TIMEOUT_MS,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info, {standard_ping_cb, &test_ctx}));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i), 1) << i;
        ASSERT_NE(test_ctx.results[i].status, PING_OK) << i;
    }
    ASSERT_TRUE(test_ctx.finished);
}
