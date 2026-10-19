#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <gtest/gtest.h>

#include "common/logger.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

using namespace ag;

struct TestData {
    std::condition_variable action_cond_var;
    std::condition_variable finalize_cond_var;
    std::mutex guard;
    TaskId id = -1;
    bool executed = false;
    bool finalized = false;
};

class EventLoopTest : public testing::Test {
public:
    EventLoopTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

protected:
    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> m_ev_loop{vpn_event_loop_create()};
    std::thread m_loop_thread;

    void run_event_loop() {
        m_loop_thread = std::thread([loop = m_ev_loop.get()]() {
            vpn_event_loop_run(loop);
        });
    }

    VpnEventLoopTask make_task(TestData &data) {
        return {&data,
                [](void *arg, TaskId task_id) {
                    auto *data = (TestData *) arg;
                    if (task_id == data->id) {
                        std::unique_lock l(data->guard);
                        data->executed = true;
                        data->action_cond_var.notify_one();
                    }
                },
                [](void *arg) {
                    auto *data = (TestData *) arg;
                    std::unique_lock l(data->guard);
                    data->finalized = true;
                    data->finalize_cond_var.notify_one();
                }};
    }

    void SetUp() override {
    }

    void TearDown() override {
        if (m_ev_loop) {
            vpn_event_loop_stop(m_ev_loop.get());
        }

        if (m_loop_thread.joinable()) {
            m_loop_thread.join();
        }
    }
};

TEST_F(EventLoopTest, Submit) {
    constexpr size_t TASKS_NUM = 5;
    TestData tasks[TASKS_NUM];

    for (auto &task : tasks) {
        task.id = vpn_event_loop_submit(m_ev_loop.get(), make_task(task));
    }

    run_event_loop();

    for (size_t i = 0; i < std::size(tasks); ++i) {
        std::unique_lock l(tasks[i].guard);
        ASSERT_TRUE(tasks[i].action_cond_var.wait_for(l, std::chrono::seconds(3),
                [t = &tasks[i]]() {
                    return t->executed;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
        ASSERT_TRUE(tasks[i].finalize_cond_var.wait_for(l, std::chrono::seconds(3),
                [t = &tasks[i]]() {
                    return t->finalized;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
    }
}

TEST_F(EventLoopTest, Schedule) {
    constexpr Millis POSTPONE{1000};
    constexpr size_t TASKS_NUM = 5;
    TestData tasks[TASKS_NUM];

    for (auto &task : tasks) {
        task.id = vpn_event_loop_schedule(m_ev_loop.get(), make_task(task), POSTPONE);
    }

    run_event_loop();

    for (size_t i = 0; i < std::size(tasks); ++i) {
        std::unique_lock l(tasks[i].guard);
        ASSERT_TRUE(tasks[i].action_cond_var.wait_for(l, POSTPONE * 1.3,
                [t = &tasks[i]]() {
                    return t->executed;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
        ASSERT_TRUE(tasks[i].finalize_cond_var.wait_for(l, POSTPONE * 1.3,
                [t = &tasks[i]]() {
                    return t->finalized;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
    }
}

TEST_F(EventLoopTest, CancelSubmitted) {
    TestData task = {};

    task.id = vpn_event_loop_submit(m_ev_loop.get(), make_task(task));
    vpn_event_loop_cancel(m_ev_loop.get(), task.id);

    std::unique_lock l(task.guard);
    ASSERT_FALSE(task.action_cond_var.wait_for(l, std::chrono::seconds(2), [t = &task]() {
        return t->executed;
    }));
    ASSERT_TRUE(task.finalize_cond_var.wait_for(l, std::chrono::seconds(5), [t = &task]() {
        return t->finalized;
    }));
}

TEST_F(EventLoopTest, CancelScheduled) {
    constexpr Millis POSTPONE{1000};
    TestData postponed_task = {};
    postponed_task.id = vpn_event_loop_schedule(m_ev_loop.get(), make_task(postponed_task), POSTPONE);

    struct CancellingTaskCtx {
        VpnEventLoop *loop;
        TaskId id;
    };

    CancellingTaskCtx ctx = {m_ev_loop.get(), postponed_task.id};
    vpn_event_loop_submit(m_ev_loop.get(), {&ctx, [](void *arg, TaskId) {
                                                auto *ctx = (CancellingTaskCtx *) arg;
                                                vpn_event_loop_cancel(ctx->loop, ctx->id);
                                            }});

    run_event_loop();

    std::unique_lock l(postponed_task.guard);
    ASSERT_FALSE(postponed_task.action_cond_var.wait_for(l, POSTPONE * 1.3, [t = &postponed_task]() {
        return t->executed;
    }));
    ASSERT_TRUE(postponed_task.finalize_cond_var.wait_for(l, POSTPONE * 1.3, [t = &postponed_task]() {
        return t->finalized;
    }));
}

TEST_F(EventLoopTest, CancelByStop) {
    constexpr Millis POSTPONE{1000};
    constexpr size_t TASKS_NUM = 6;
    TestData tasks[TASKS_NUM];

    for (size_t i = 0; i < std::size(tasks); ++i) {
        if (i % 2 == 0) {
            tasks[i].id = vpn_event_loop_submit(m_ev_loop.get(), make_task(tasks[i]));
        } else {
            tasks[i].id = vpn_event_loop_schedule(m_ev_loop.get(), make_task(tasks[i]), POSTPONE);
        }
    }

    vpn_event_loop_stop(m_ev_loop.get());

    for (size_t i = 0; i < std::size(tasks); ++i) {
        std::unique_lock l(tasks[i].guard);
        ASSERT_FALSE(tasks[i].action_cond_var.wait_for(l, POSTPONE * 1.3,
                [t = &tasks[i]]() {
                    return t->executed;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
        ASSERT_TRUE(tasks[i].finalize_cond_var.wait_for(l, POSTPONE * 1.3,
                [t = &tasks[i]]() {
                    return t->finalized;
                }))
                << "i=" << i << "task_id=" << tasks[i].id;
    }
}

// Disabled because does not work with asserts enabled
TEST_F(EventLoopTest, DISABLED_CancelAfterStopDoesntCrash) {
    vpn_event_loop_stop(m_ev_loop.get());
    auto task_id = event_loop::submit(m_ev_loop.get(),
            {
                    .action =
                            [](void *, TaskId) {
                                abort();
                            },
            });
    m_ev_loop.reset(vpn_event_loop_create());
    task_id.reset();
}

TEST_F(EventLoopTest, StopSubmitDestroy) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        bool ran;
        bool finalized;
    };
    Ctx ctx{};
    vpn_event_loop_stop(m_ev_loop.get());
    event_loop::AutoTaskId id = event_loop::submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action =
                            [](void *arg, TaskId) {
                                ((Ctx *) arg)->ran = true;
                            },
                    .finalize =
                            [](void *arg) {
                                ((Ctx *) arg)->finalized = true;
                            },
            });
    ASSERT_TRUE(id.has_value());
    ASSERT_FALSE(ctx.finalized);

    m_loop_thread.join();
    id.reset();
    m_ev_loop.reset();
    ASSERT_FALSE(ctx.ran);
    ASSERT_TRUE(ctx.finalized);
}

TEST_F(EventLoopTest, StopSubmitRun) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        bool ran;
        bool finalized;
    };
    Ctx ctx{};
    vpn_event_loop_stop(m_ev_loop.get());
    event_loop::AutoTaskId id = event_loop::submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action =
                            [](void *arg, TaskId) {
                                ((Ctx *) arg)->ran = true;
                            },
                    .finalize =
                            [](void *arg) {
                                ((Ctx *) arg)->finalized = true;
                            },
            });
    ASSERT_TRUE(id.has_value());
    ASSERT_FALSE(ctx.finalized);

    m_loop_thread.join();
    m_loop_thread = std::thread([&] {
        vpn_event_loop_run(m_ev_loop.get());
    });
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());
    m_loop_thread.join();

    id.reset();
    m_ev_loop.reset();
    ASSERT_TRUE(ctx.ran);
    ASSERT_TRUE(ctx.finalized);
}

TEST_F(EventLoopTest, DispatchSyncUnlocksCallerLock) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});

    std::mutex guard;
    bool action_ran = false;
    {
        std::unique_lock l(guard);
        bool executed = event_loop::dispatch_sync(m_ev_loop.get(), l, [&] {
            // The event loop thread must be able to acquire the guard: the caller releases it while waiting.
            std::unique_lock guard_l(guard);
            action_ran = true;
        });
        EXPECT_TRUE(executed);
        EXPECT_TRUE(l.owns_lock());
    }
    EXPECT_TRUE(action_ran);
}

TEST_F(EventLoopTest, DispatchSyncUnlockedOnStoppedLoopReturnsFalse) {
    run_event_loop();
    // Wait for the loop thread to enter the loop before stopping it. Without this handshake the stop may run while
    // the loop is still stopped, leaving the exit request pending and the test hanging.
    ASSERT_TRUE(event_loop::dispatch_sync(m_ev_loop.get(), [] {}));
    vpn_event_loop_stop(m_ev_loop.get());

    std::mutex guard;
    std::unique_lock l(guard);
    EXPECT_FALSE(event_loop::dispatch_sync(m_ev_loop.get(), l, [] {}));
    EXPECT_TRUE(l.owns_lock());
}

TEST_F(EventLoopTest, FinalizeExitCallsFinalizeWithoutLock) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        VpnEventLoop *loop;
        bool finalized = false;
    };
    Ctx ctx{.loop = m_ev_loop.get()};
    vpn_event_loop_submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action = [](void *, TaskId) {},
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (Ctx *) arg;
                                // Finalizers run without `loop->guard`, so re-entering the loop API must not
                                // deadlock.
                                vpn_event_loop_cancel(ctx->loop, -1);
                                ctx->finalized = true;
                            },
            });

    vpn_event_loop_stop(m_ev_loop.get());
    EXPECT_TRUE(ctx.finalized);
}

TEST_F(EventLoopTest, FinalizeCallbackMayReenterStop) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        VpnEventLoop *loop;
        bool reentered = false;
    };
    Ctx ctx{.loop = m_ev_loop.get()};
    vpn_event_loop_submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action = [](void *, TaskId) {},
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (Ctx *) arg;
                                // The loop is already being finalized by this thread: re-entering must not deadlock.
                                vpn_event_loop_stop(ctx->loop);
                                ctx->reentered = true;
                            },
            });

    vpn_event_loop_stop(m_ev_loop.get());
    EXPECT_TRUE(ctx.reentered);
}

TEST_F(EventLoopTest, SubmitDuringFinalizationIsFinalizedImmediately) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        VpnEventLoop *loop;
        bool nested_finalized = false;
    };
    Ctx ctx{.loop = m_ev_loop.get()};
    vpn_event_loop_submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action = [](void *, TaskId) {},
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (Ctx *) arg;
                                // The loop is finalizing, so a new task cannot be queued for a future run: it must be
                                // finalized immediately.
                                vpn_event_loop_submit(ctx->loop,
                                        {
                                                .arg = &ctx->nested_finalized,
                                                .action = [](void *, TaskId) {},
                                                .finalize =
                                                        [](void *arg) {
                                                            *(bool *) arg = true;
                                                        },
                                        });
                            },
            });

    vpn_event_loop_stop(m_ev_loop.get());
    EXPECT_TRUE(ctx.nested_finalized);
}

TEST_F(EventLoopTest, ScheduleWithoutFinalizerDuringFinalization) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        VpnEventLoop *loop;
        TaskId id = 0;
    };
    Ctx ctx{.loop = m_ev_loop.get()};
    vpn_event_loop_submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action = [](void *, TaskId) {},
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (Ctx *) arg;
                                // Scheduling a task without a finalizer while finalizing must not crash.
                                ctx->id = vpn_event_loop_schedule(
                                        ctx->loop, {.arg = nullptr, .action = nullptr, .finalize = nullptr}, Millis{1});
                            },
            });

    vpn_event_loop_stop(m_ev_loop.get());
    EXPECT_EQ(ctx.id, -1);
}

// Check that a concurrent finalize_exit waits for the finalization already in progress
TEST_F(EventLoopTest, FinalizeExitWaitsForConcurrentFinalization) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), [] {});
    vpn_event_loop_stop(m_ev_loop.get());

    std::mutex guard;
    std::condition_variable cv;
    bool finalizer_entered = false;
    bool finalizer_proceed = false;

    struct Ctx {
        std::mutex *guard;
        std::condition_variable *cv;
        bool *entered;
        bool *proceed;
    };
    Ctx ctx{&guard, &cv, &finalizer_entered, &finalizer_proceed};
    vpn_event_loop_submit(m_ev_loop.get(),
            {
                    .arg = &ctx,
                    .action = [](void *, TaskId) {},
                    .finalize =
                            [](void *arg) {
                                auto *ctx = (Ctx *) arg;
                                std::unique_lock l(*ctx->guard);
                                *ctx->entered = true;
                                ctx->cv->notify_all();
                                ctx->cv->wait(l, [&]() {
                                    return *ctx->proceed;
                                });
                            },
            });

    std::thread first([loop = m_ev_loop.get()]() {
        vpn_event_loop_stop(loop);
    });

    bool entered = false;
    {
        std::unique_lock l(guard);
        entered = cv.wait_for(l, std::chrono::seconds(5), [&]() {
            return finalizer_entered;
        });
    }
    if (!entered) {
        {
            std::unique_lock l(guard);
            finalizer_proceed = true;
            cv.notify_all();
        }
        first.join();
        FAIL() << "finalizer was not entered";
        return;
    }

    std::atomic<bool> second_returned{false};
    std::thread second([loop = m_ev_loop.get(), &second_returned]() {
        vpn_event_loop_stop(loop);
        second_returned.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    bool returned_early = second_returned.load();

    {
        std::unique_lock l(guard);
        finalizer_proceed = true;
        cv.notify_all();
    }

    first.join();
    second.join();

    EXPECT_FALSE(returned_early) << "concurrent finalize_exit returned before the first one finished";
    EXPECT_TRUE(second_returned.load());
}
