#include "src/vpn_controller.h"
#include <deque>
#include <functional>
#include <gtest/gtest.h>

using namespace ag::trusttunnel_linux;

class VpnControllerTest : public ::testing::Test {
protected:
    struct ScheduledTask {
        uint32_t delay_ms;
        std::function<void()> fn;
    };

    std::deque<ScheduledTask> tasks;
    std::vector<VpnState> state_history;
    std::vector<std::string> connection_infos;

    TimerScheduler make_scheduler() {
        return [this](uint32_t delay_ms, std::function<void()> fn) {
            tasks.push_back({delay_ms, std::move(fn)});
        };
    }

    VpnController::Callbacks make_callbacks() {
        return {[this](VpnState s) {
                    state_history.push_back(s);
                },
                [this](const std::string &info) {
                    connection_infos.push_back(info);
                }};
    }

    void run_next_task() {
        ASSERT_FALSE(tasks.empty());
        auto task = std::move(tasks.front());
        tasks.pop_front();
        task.fn();
    }
};

TEST_F(VpnControllerTest, InitialStateIsDisconnected) {
    VpnController controller(make_scheduler(), make_callbacks());
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
}

TEST_F(VpnControllerTest, StartTransitionsToConnectingThenConnected) {
    VpnController controller(make_scheduler(), make_callbacks());

    EXPECT_EQ(controller.start(""), VpnError::INVALID_CONFIG);

    EXPECT_EQ(controller.start("[test_config]"), VpnError::SUCCESS);
    EXPECT_EQ(controller.state(), VpnState::CONNECTING);
    ASSERT_EQ(state_history.size(), 1u);
    EXPECT_EQ(state_history.back(), VpnState::CONNECTING);

    // Run connection delay timer
    ASSERT_FALSE(tasks.empty());
    run_next_task();

    EXPECT_EQ(controller.state(), VpnState::CONNECTED);
    ASSERT_EQ(state_history.size(), 2u);
    EXPECT_EQ(state_history.back(), VpnState::CONNECTED);

    // Run connection info timer
    ASSERT_FALSE(tasks.empty());
    run_next_task();
    EXPECT_FALSE(connection_infos.empty());
}

TEST_F(VpnControllerTest, StopReturnsToDisconnected) {
    VpnController controller(make_scheduler(), make_callbacks());
    controller.start("[test_config]");
    EXPECT_EQ(controller.state(), VpnState::CONNECTING);

    EXPECT_EQ(controller.stop(), VpnError::SUCCESS);
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);

    // Old scheduled tasks should not affect state after stop
    while (!tasks.empty()) {
        run_next_task();
    }
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
}
