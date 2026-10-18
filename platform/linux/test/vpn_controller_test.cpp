#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include "src/vpn_controller.h"

using namespace ag::trusttunnel_linux;
using namespace std::chrono_literals;

/// Generous upper bound: a refused local connection is expected to fail in a few seconds,
/// but the number of core-side retries is not a part of the test contract.
static constexpr auto CONNECT_TIMEOUT = 30s;

/// Minimal valid configuration: a SOCKS listener needs no privileges and an endpoint on the
/// loopback keeps the lifecycle test off the network.
static constexpr std::string_view MINIMAL_CONFIG = R"(
vpn_mode = "general"

[endpoint]
hostname = "vpn.example.com"
addresses = ["127.0.0.1:443"]
username = "user"
password = "pass"
upstream_protocol = "http2"

[listener.socks]
address = "127.0.0.1:0"
)";

TEST(ParseDaemonConfigTest, ValidMinimalConfig) {
    std::optional<ag::TrustTunnelConfig> config = parse_daemon_config(MINIMAL_CONFIG);
    ASSERT_TRUE(config.has_value());
    EXPECT_EQ(config->mode, ag::VPN_MODE_GENERAL);
    EXPECT_EQ(config->location.username, "user");
    ASSERT_EQ(config->location.endpoints.size(), 1u);
    EXPECT_EQ(config->location.endpoints[0].address, "127.0.0.1:443");
    const auto *socks = std::get_if<ag::TrustTunnelConfig::SocksListener>(&config->listener);
    ASSERT_NE(socks, nullptr);
    EXPECT_EQ(socks->address, "127.0.0.1:0");
}

TEST(ParseDaemonConfigTest, GarbageYieldsNullopt) {
    EXPECT_FALSE(parse_daemon_config("this is [[ not toml").has_value());
}

TEST(ParseDaemonConfigTest, MissingListenerYieldsNullopt) {
    constexpr std::string_view config = R"(
vpn_mode = "general"

[endpoint]
hostname = "vpn.example.com"
addresses = ["127.0.0.1:443"]
username = "user"
password = "pass"
upstream_protocol = "http2"
)";
    EXPECT_FALSE(parse_daemon_config(config).has_value());
}

/// Records everything the controller reports through its callbacks.
struct ControllerObserver {
    std::vector<VpnState> states;
    std::vector<std::string> connection_infos;
    std::vector<ag::VpnNetworkInfo> network_infos;

    VpnController::Callbacks callbacks() {
        return VpnController::Callbacks{
                .on_state_changed =
                        [this](VpnState state) {
                            states.push_back(state);
                        },
                .on_connection_info =
                        [this](const std::string &json) {
                            connection_infos.push_back(json);
                        },
                .on_network_ready =
                        [this](const ag::VpnNetworkInfo &info) {
                            network_infos.push_back(info);
                        },
        };
    }
};

TEST(VpnControllerTest, InitialStateIsDisconnected) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
    EXPECT_FALSE(controller.running());
}

TEST(VpnControllerTest, EmptyConfigIsRejected) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());

    EXPECT_EQ(controller.start(""), VpnError::INVALID_CONFIG);

    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
    EXPECT_FALSE(controller.running());
    EXPECT_TRUE(observer.states.empty());
}

TEST(VpnControllerTest, FailedConnectEndsDisconnected) {
    // Endpoint on the loopback with nothing listening behind it: the connection attempts
    // fail quickly without any network access, ending the session with DISCONNECTED
    constexpr std::string_view config = R"(
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

    ControllerObserver observer;
    VpnController controller(observer.callbacks());

    EXPECT_EQ(controller.start(std::string(config)), VpnError::SUCCESS);
    EXPECT_EQ(controller.state(), VpnState::CONNECTING);
    ASSERT_EQ(observer.states.size(), 1u);
    EXPECT_EQ(observer.states.back(), VpnState::CONNECTING);

    // Wait for the client thread to finish on its own once the connection fails
    auto deadline = std::chrono::steady_clock::now() + CONNECT_TIMEOUT;
    while (controller.running() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    ASSERT_FALSE(controller.running());

    controller.drain();
    ASSERT_GE(observer.states.size(), 2u);
    EXPECT_EQ(observer.states.back(), VpnState::DISCONNECTED);
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
}

TEST(VpnControllerTest, StopWithoutSessionIsNoop) {
    ControllerObserver observer;
    VpnController controller(observer.callbacks());
    EXPECT_EQ(controller.stop(), VpnError::SUCCESS);
    EXPECT_EQ(controller.state(), VpnState::DISCONNECTED);
}
