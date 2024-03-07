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
    TestData tasks[5];

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
    const Millis POSTPONE{1000};
    TestData tasks[5];

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
    const Millis POSTPONE{1000};
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
    const Millis POSTPONE{1000};
    TestData tasks[6];

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
    event_loop::dispatch_sync(m_ev_loop.get(), []{});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        bool ran;
        bool finalized;
    };
    Ctx ctx{};
    vpn_event_loop_stop(m_ev_loop.get());
    event_loop::AutoTaskId id = event_loop::submit(m_ev_loop.get(), {
            .arg = &ctx,
            .action = [](void *arg, TaskId) {
                ((Ctx *) arg)->ran = true;
            },
            .finalize = [](void *arg) {
                ((Ctx *) arg)->finalized = true;
            },
    });
    ASSERT_TRUE(id.has_value());
    ASSERT_FALSE(ctx.finalized);

    id.reset();
    m_ev_loop.reset();
    ASSERT_FALSE(ctx.ran);
    ASSERT_TRUE(ctx.finalized);
}

TEST_F(EventLoopTest, StopSubmitRun) {
    run_event_loop();
    event_loop::dispatch_sync(m_ev_loop.get(), []{});
    vpn_event_loop_stop(m_ev_loop.get());

    struct Ctx {
        bool ran;
        bool finalized;
    };
    Ctx ctx{};
    vpn_event_loop_stop(m_ev_loop.get());
    event_loop::AutoTaskId id = event_loop::submit(m_ev_loop.get(), {
            .arg = &ctx,
            .action = [](void *arg, TaskId) {
                ((Ctx *) arg)->ran = true;
            },
            .finalize = [](void *arg) {
                ((Ctx *) arg)->finalized = true;
            },
    });
    ASSERT_TRUE(id.has_value());
    ASSERT_FALSE(ctx.finalized);

    m_loop_thread.join();
    m_loop_thread = std::thread([&] {
        vpn_event_loop_run(m_ev_loop.get());
    });
    event_loop::dispatch_sync(m_ev_loop.get(), []{});
    vpn_event_loop_stop(m_ev_loop.get());
    m_loop_thread.join();

    id.reset();
    m_ev_loop.reset();
    ASSERT_TRUE(ctx.ran);
    ASSERT_TRUE(ctx.finalized);
}
