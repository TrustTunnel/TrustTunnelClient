#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <toml++/toml.h>

#include "src/vpn_controller.h"

using namespace ag::trusttunnel_linux;
using namespace std::chrono_literals;

/// Generous upper bound: the loopback endpoint refuses the connection quickly, but the number of
/// core-side retries is not part of the test contract.
static constexpr auto STATE_TIMEOUT = 30s;

namespace {

/// Failing configuration: an endpoint on the loopback with nothing listening behind it,
/// so connection attempts fail quickly without any network access.
constexpr std::string_view FAILING_CONFIG = R"(
vpn_mode = "general"

[endpoint]
hostname = "localhost"
addresses = ["127.0.0.1:1"]
username = "user"
password = "pass"
upstream_protocol = "http2"

[listener.socks]
address = "127.0.0.1:0"
)";

std::optional<ag::TrustTunnelConfig> build_config(std::string_view toml_text) {
    toml::parse_result parsed = toml::parse(toml_text);
    if (!parsed) {
        return std::nullopt;
    }
    return ag::TrustTunnelConfig::build_config(parsed.table());
}

std::optional<ag::TrustTunnelConfig> make_failing_config() {
    return build_config(FAILING_CONFIG);
}

/// Collects the events reported by the controller from its internal threads.
struct ControllerObserver {
    std::vector<int> states;
    std::vector<std::string> connection_infos;

    VpnController::Callbacks callbacks() {
        return VpnController::Callbacks{
                .on_state_changed =
                        [this](int state) {
                            std::lock_guard lock(mutex);
                            states.push_back(state);
                        },
                .on_connection_info =
                        [this](const std::string &json) {
                            std::lock_guard lock(mutex);
                            connection_infos.push_back(json);
                        },
        };
    }

    bool saw_state(int state) const {
        std::lock_guard lock(mutex);
        return std::find(states.begin(), states.end(), state) != states.end();
    }

private:
    mutable std::mutex mutex;
};

/// Wait until the controller reports `state`, or fail after `timeout`.
void expect_state(const ControllerObserver &observer, int state) {
    auto deadline = std::chrono::steady_clock::now() + STATE_TIMEOUT;
    while (std::chrono::steady_clock::now() < deadline) {
        if (observer.saw_state(state)) {
            return;
        }
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_TRUE(observer.saw_state(state));
}

} // namespace

TEST(VpnControllerTest, FailedConnectReportsDisconnected) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());

    // The initial connection attempt is asynchronous: the final state arrives via the callback
    auto config = make_failing_config();
    ASSERT_TRUE(config.has_value());
    (void) controller.start(std::move(*config), false);

    expect_state(observer, static_cast<int>(ag::VPN_SS_DISCONNECTED));
}

TEST(VpnControllerTest, StopWithoutSessionIsNoop) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());

    controller.stop();

    EXPECT_FALSE(observer.saw_state(static_cast<int>(ag::VPN_SS_DISCONNECTED)));
}

TEST(VpnControllerTest, RestartAfterFailureIsAllowed) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());

    ASSERT_TRUE(build_config(FAILING_CONFIG).has_value());
    auto config = make_failing_config();
    ASSERT_TRUE(config.has_value());
    (void) controller.start(std::move(*config), false);
    expect_state(observer, static_cast<int>(ag::VPN_SS_DISCONNECTED));

    controller.stop();
    config = make_failing_config();
    ASSERT_TRUE(config.has_value());
    (void) controller.start(std::move(*config), false);
    expect_state(observer, static_cast<int>(ag::VPN_SS_DISCONNECTED));
}
