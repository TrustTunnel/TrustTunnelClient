#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "trusttunnel/trusttunnel.h"
#include "vpn/vpn.h"

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

/// Collects the events reported by the library from its internal threads.
struct Observer {
    std::vector<int> states;
    std::vector<std::string> connection_infos;

    bool saw_state(int state) const {
        return state_count(state) > 0;
    }

    size_t state_count(int state) const {
        std::lock_guard lock(mutex);
        return static_cast<size_t>(std::count(states.begin(), states.end(), state));
    }

    on_state_changed_t state_callback() {
        return on_state_changed;
    }

    on_connection_info_t connection_info_callback() {
        return on_connection_info;
    }

private:
    mutable std::mutex mutex;

    static void on_state_changed(void *arg, int state) {
        auto &self = *static_cast<Observer *>(arg);
        std::lock_guard lock(self.mutex);
        self.states.push_back(state);
    }

    static void on_connection_info(void *arg, const char *json) {
        auto &self = *static_cast<Observer *>(arg);
        std::lock_guard lock(self.mutex);
        self.connection_infos.emplace_back(json != nullptr ? json : "");
    }
};

/// Wait until the library reports `state`, or fail after `timeout`.
void expect_state(const Observer &observer, int state) {
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

TEST(TrusttunnelCapiTest, StartExNullConfigReturnsNull) {
    EXPECT_EQ(trusttunnel_start_ex(nullptr, false, nullptr, nullptr, nullptr, nullptr), nullptr);
}

TEST(TrusttunnelCapiTest, StartExMalformedConfigReturnsNull) {
    EXPECT_EQ(trusttunnel_start_ex("this is [[ not toml", false, nullptr, nullptr, nullptr, nullptr), nullptr);
}

TEST(TrusttunnelCapiTest, StopExNullIsNoop) {
    trusttunnel_stop_ex(nullptr);
}

TEST(TrusttunnelCapiTest, AsyncStopWithoutStartIsNoop) {
    trusttunnel_stop();
}

TEST(TrusttunnelCapiTest, AsyncStartNullConfigThenStopIsNoop) {
    // An invalid configuration must not leave the manager in a half-started state: `start_ex`
    // returns null without creating an instance, so the queued stop has nothing to do.
    trusttunnel_start(nullptr, false, nullptr, nullptr);
    trusttunnel_stop();
}

TEST(TrusttunnelCapiTest, AsyncRestartAfterDisconnected) {
    // Heap-allocated on purpose: the manager keeps the session (and may deliver the final callbacks)
    // after the test body has returned and the local observers would already be destroyed.
    auto first = new Observer();
    auto second = new Observer();

    // Requests are serialized on the manager's event loop, so they run in submission order:
    // start -> DISCONNECTED -> stop -> start again.
    trusttunnel_start(std::string(FAILING_CONFIG).c_str(), false, first->state_callback(), first);
    expect_state(*first, static_cast<int>(ag::VPN_SS_DISCONNECTED));

    // After a self-initiated disconnect the session must be released before a new one can start.
    trusttunnel_stop();

    trusttunnel_start(std::string(FAILING_CONFIG).c_str(), false, second->state_callback(), second);
    // Reaching DISCONNECTED through the *second* observer proves that the first session was torn down
    // and a new one was started: a stale "VPN has been already started" would leave it silent.
    expect_state(*second, static_cast<int>(ag::VPN_SS_DISCONNECTED));

    trusttunnel_stop();
}

TEST(TrusttunnelCapiTest, FailedConnectReportsDisconnected) {
    Observer observer;

    trusttunnel_t *vpn = trusttunnel_start_ex(std::string(FAILING_CONFIG).c_str(), false, observer.state_callback(),
            &observer, observer.connection_info_callback(), &observer);

    // The initial connection attempt is asynchronous: the final state arrives via the callback
    expect_state(observer, static_cast<int>(ag::VPN_SS_DISCONNECTED));
    trusttunnel_stop_ex(vpn);
}
