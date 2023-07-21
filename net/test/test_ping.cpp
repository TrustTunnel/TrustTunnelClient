#include <cstdlib>
#include <string>
#include <unordered_map>
#include <vector>

#include <event2/util.h>
#include <gtest/gtest.h>

#include "common/logger.h"
#include "net/utils.h"
#include "ping.h"
#include "vpn/utils.h"

using namespace ag;

struct TestCtx {
    VpnEventLoop *loop = nullptr;
    event_base *base = nullptr;
    DeclPtr<Ping, &ping_destroy> ping;
    std::unordered_map<std::string, PingResult> results;
    bool finished = false;
    bool cancelled = false;
};

struct TestCtxRounds {
    VpnEventLoop *loop = nullptr;
    event_base *base = nullptr;
    DeclPtr<Ping, &ping_destroy> ping;
    std::unordered_map<std::string, std::vector<PingResult>> results;
    bool finished = false;
};

class PingTest : public testing::Test {
public:
    PingTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};

    void run_event_loop() { // NOLINT(readability-make-member-function-const)
        // just not to hang
        vpn_event_loop_exit(loop.get(), Millis(2 * DEFAULT_PING_TIMEOUT_MS));
        vpn_event_loop_run(loop.get());
    }

    [[nodiscard]] TestCtx generate_test_ctx() const {
        TestCtx ctx = {};
        ctx.loop = this->loop.get();
        ctx.base = vpn_event_loop_get_base(this->loop.get());
        return ctx;
    }

    [[nodiscard]] TestCtxRounds generate_test_ctx_rounds() const {
        TestCtxRounds ctx = {};
        ctx.loop = this->loop.get();
        ctx.base = vpn_event_loop_get_base(this->loop.get());
        return ctx;
    }
};

TEST_F(PingTest, Single) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"[::1]:12", PING_SOCKET_ERROR},
            {"1.2.3.4:80", PING_TIMEDOUT},
            {"127.0.0.1:12", PING_SOCKET_ERROR},
    };

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)] = *result;
                    },
                    &test_ctx,
            }));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
#ifndef _WIN32
        ASSERT_EQ(test_ctx.results[i.first].status, i.second) << i.first;
#else
        if (i.second != PING_OK) {
            // on windows refused error returns after about 2 seconds, so depending on configuration
            // here might be PING_TIMEDOUT or PING_SOCKET_ERROR status code
            ASSERT_TRUE(test_ctx.results[i.first].status != PING_OK) << i.first;
        } else {
            ASSERT_EQ(test_ctx.results[i.first].status, i.second) << i.first;
        }
#endif
        ASSERT_EQ(test_ctx.results[i.first].ping, test_ctx.ping.get()) << i.first;
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingTest, Timeout) {
    static const std::string TEST_DATA[] = {
            "94.140.14.200:443",
            "1.2.3.4:443",
#ifndef IPV6_UNAVAILABLE
            "[2a10:50c0::42]:443",
            "[2a10:50c0::43]:443",
#endif
    };

    TestCtx test_ctx = generate_test_ctx();

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.c_str()));
    }

    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)] = *result;
                    },
                    &test_ctx,
            }));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i), 1) << i;
        ASSERT_EQ(test_ctx.results[i].status, PING_TIMEDOUT) << i;
        ASSERT_EQ(test_ctx.results[i].ping, test_ctx.ping.get()) << i;
        ASSERT_TRUE(test_ctx.finished);
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

TEST_F(PingTest, Multiple) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"1.2.3.4:80", PING_TIMEDOUT},
#ifndef _WIN32
            {"[::1]:12", PING_SOCKET_ERROR},
            {"127.0.0.1:12", PING_SOCKET_ERROR},
#endif
            {"0.0.0.0:12", PING_SOCKET_ERROR},
    };

    std::vector<TestCtx> contexts;
    for (const auto &i : TEST_DATA) {
        sockaddr_storage addr = sockaddr_from_str(i.first.c_str());
        TestCtx &test_ctx = contexts.emplace_back(generate_test_ctx());
        PingInfo info = {
                .loop = test_ctx.loop,
                .addrs = {&addr, 1},
                .timeout_ms = 500, /* windows will refuse connection to ::1 after 2 s*/
                .nrounds = 1,
        };
        test_ctx.ping.reset(ping_start(&info,
                {
                        [](void *ctx, const PingResult *result) {
                            auto *contexts = (std::vector<TestCtx> *) ctx;

                            auto i = std::find_if(
                                    contexts->begin(), contexts->end(), [ping = result->ping](const TestCtx &i) {
                                        return ping == i.ping.get();
                                    });
                            assert(i != contexts->end());

                            TestCtx *test_ctx = &*i;
                            if (result->status == PING_FINISHED) {
                                test_ctx->finished = true;
                                if (std::all_of(contexts->begin(), contexts->end(), [](const TestCtx &i) {
                                        return i.finished;
                                    })) {
                                    event_base_loopbreak(test_ctx->base);
                                }
                                return;
                            }

                            test_ctx->results[sockaddr_to_str(result->addr)] = *result;
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

TEST_F(PingTest, AllAddressesInvalid) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"0.0.0.0:12", PING_SOCKET_ERROR},
            {"[::]:12", PING_SOCKET_ERROR},
    };

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)] = *result;
                    },
                    &test_ctx,
            }));

    run_event_loop();

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results[i.first].status, i.second) << i.first;
        ASSERT_EQ(test_ctx.results[i.first].ping, test_ctx.ping.get()) << i.first;
        ASSERT_TRUE(test_ctx.finished) << i.first;
    }
}

TEST_F(PingTest, DestroyInProgressPingAfterCallback) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"[::1]:12", PING_SOCKET_ERROR},
            {"1.2.3.4:80", PING_TIMEDOUT},
            {"127.0.0.7:12", PING_SOCKET_ERROR},
    };

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        if (!test_ctx->cancelled) {
                            event_loop::submit(test_ctx->loop,
                                    {
                                            .arg = test_ctx,
                                            .action =
                                                    [](void *arg, TaskId) {
                                                        auto *ctx = (TestCtx *) arg;
                                                        ctx->ping.reset();
                                                        vpn_event_loop_exit(ctx->loop, Secs(1));
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

                        test_ctx->results[sockaddr_to_str(result->addr)] = *result;
                    },
                    &test_ctx,
            }));

    run_event_loop();

    ASSERT_LE(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_FALSE(test_ctx.finished);
    ASSERT_TRUE(test_ctx.cancelled);
}

TEST_F(PingTest, DestroyInProgressPing) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"[::1]:12", PING_SOCKET_ERROR},
            {"127.0.0.7:12", PING_SOCKET_ERROR},
            {"1.2.3.4:80", PING_TIMEDOUT},
    };

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtx test_ctx = generate_test_ctx();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .nrounds = 1,
    };

    event_loop::submit(test_ctx.loop,
            {
                    .arg = &test_ctx,
                    .action =
                            [](void *arg, TaskId) {
                                auto *ctx = (TestCtx *) arg;
                                ctx->ping.reset();
                                vpn_event_loop_exit(ctx->loop, Secs(1));
                            },
            })
            .release();

    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtx *) ctx;

                        // This means "callback called" for this test
                        if (!test_ctx->cancelled) {
                            test_ctx->cancelled = true;
                        }

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)] = *result;
                    },
                    &test_ctx,
            }));

    run_event_loop();

    ASSERT_FALSE(test_ctx.cancelled);
    ASSERT_FALSE(test_ctx.finished);
    ASSERT_EQ(0, test_ctx.results.size());
}

TEST_F(PingTest, MultipleRounds) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
            {"[::1]:12", PING_SOCKET_ERROR},
            {"1.2.3.4:80", PING_TIMEDOUT},
            {"127.0.0.1:12", PING_SOCKET_ERROR},
    };
    static const int ROUNDS = 3;

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtxRounds test_ctx = generate_test_ctx_rounds();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 5000,
            .nrounds = ROUNDS,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtxRounds *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)].emplace_back(*result);
                    },
                    &test_ctx,
            }));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
        // There multiple rounds but callback is invoked only once for endpoint.
        ASSERT_EQ(test_ctx.results[i.first].size(), 1) << i.first;
        for (const auto &r : test_ctx.results[i.first]) {
#ifndef _WIN32
            ASSERT_EQ(r.status, i.second) << i.first;
#else
            if (i.second != PING_OK) {
                // on windows refused error returns after about 2 seconds, so depending on configuration
                // here might be PING_TIMEDOUT or PING_SOCKET_ERROR status code
                ASSERT_TRUE(r.status != PING_OK) << i.first;
            } else {
                ASSERT_EQ(r.status, i.second) << i.first;
            }
#endif
            ASSERT_EQ(r.ping, test_ctx.ping.get()) << i.first;
        }
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}

#ifdef __MACH__
// Need a machine with more than one usable interface (loopback and tunnels are excluded on purpose)
TEST_F(PingTest, DISABLED_QueryAllInterfaces) {
    static const std::pair<std::string, PingStatus> TEST_DATA[] = {
            {"1.1.1.1:443", PING_OK},
    };

    std::vector<sockaddr_storage> addresses;
    for (const auto &i : TEST_DATA) {
        addresses.push_back(sockaddr_from_str(i.first.c_str()));
    }

    TestCtxRounds test_ctx = generate_test_ctx_rounds();
    std::vector<uint32_t> interfaces = collect_operable_network_interfaces();
    PingInfo info = {
            .loop = test_ctx.loop,
            .addrs = {addresses.data(), addresses.size()},
            .timeout_ms = 500,
            .interfaces_to_query = {interfaces.data(), interfaces.size()},
            .nrounds = 1,
    };
    test_ctx.ping.reset(ping_start(&info,
            {
                    [](void *ctx, const PingResult *result) {
                        auto *test_ctx = (TestCtxRounds *) ctx;

                        if (result->status == PING_FINISHED) {
                            test_ctx->finished = true;
                            event_base_loopbreak(test_ctx->base);
                            return;
                        }

                        test_ctx->results[sockaddr_to_str(result->addr)].emplace_back(*result);
                    },
                    &test_ctx,
            }));

    run_event_loop();

    for (const auto &i : TEST_DATA) {
        ASSERT_EQ(test_ctx.results.count(i.first), 1) << i.first;
        // More than one interface should have been used
        ASSERT_GT(test_ctx.results[i.first].size(), 1) << i.first;
        auto it = std::find_if(
                test_ctx.results[i.first].begin(), test_ctx.results[i.first].end(), [](const PingResult &result) {
                    return result.status == PING_OK;
                });
        // At least one should be successful
        ASSERT_NE(test_ctx.results[i.first].end(), it) << i.first;
    }

    ASSERT_EQ(test_ctx.results.size(), std::size(TEST_DATA));
    ASSERT_TRUE(test_ctx.finished);
}
#endif // __MACH__
