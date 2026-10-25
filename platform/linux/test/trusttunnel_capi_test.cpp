#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "trusttunnel/trusttunnel.h"

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

/// Records everything the client reports through the C callbacks.
struct ClientObserver {
    std::vector<int> states;
    std::vector<std::string> connection_infos;
    std::vector<std::string> network_events;

    trusttunnel_callbacks_t callbacks() {
        trusttunnel_callbacks_t callbacks{};
        callbacks.state_changed_arg = this;
        callbacks.on_state_changed = [](void *arg, trusttunnel_vpn_state_t state) {
            static_cast<ClientObserver *>(arg)->states.push_back(state);
        };
        callbacks.connection_info_arg = this;
        callbacks.on_connection_info = [](void *arg, const char *json) {
            static_cast<ClientObserver *>(arg)->connection_infos.push_back(json);
        };
        callbacks.network_ready_arg = this;
        callbacks.on_network_ready = [](void *arg, const trusttunnel_network_info_t *info) {
            std::string record = info->iface_name;
            record += " mtu=";
            record += std::to_string(info->mtu);
            for (size_t i = 0; i < info->dns_servers_count; ++i) {
                record += " dns=";
                record += info->dns_servers[i];
            }
            static_cast<ClientObserver *>(arg)->network_events.push_back(record);
        };
        return callbacks;
    }
};

TEST(TrustTunnelCapiTest, NullCallbacksAreRejected) {
    EXPECT_EQ(trusttunnel_create(nullptr), nullptr);
}

TEST(TrustTunnelCapiTest, NullInstanceArgumentsAreSafe) {
    EXPECT_EQ(trusttunnel_start(nullptr, ""), TRUSTTUNNEL_VPN_INVALID_CONFIG);
    EXPECT_EQ(trusttunnel_stop(nullptr), TRUSTTUNNEL_VPN_SUCCESS);
    EXPECT_EQ(trusttunnel_get_state(nullptr), TRUSTTUNNEL_VPN_DISCONNECTED);
    EXPECT_EQ(trusttunnel_event_fd(nullptr), -1);
    trusttunnel_drain(nullptr);
    trusttunnel_destroy(nullptr);
}

TEST(TrustTunnelCapiTest, InvalidConfigIsRejected) {
    ClientObserver observer;
    trusttunnel_callbacks_t callbacks = observer.callbacks();
    trusttunnel_t *vpn = trusttunnel_create(&callbacks);
    ASSERT_NE(vpn, nullptr);

    EXPECT_EQ(trusttunnel_start(vpn, "this is [[ not toml"), TRUSTTUNNEL_VPN_INVALID_CONFIG);
    EXPECT_EQ(trusttunnel_get_state(vpn), TRUSTTUNNEL_VPN_DISCONNECTED);
    EXPECT_TRUE(observer.states.empty());

    trusttunnel_destroy(vpn);
}

TEST(TrustTunnelCapiTest, FailedConnectEndsDisconnected) {
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

    ClientObserver observer;
    trusttunnel_callbacks_t callbacks = observer.callbacks();
    trusttunnel_t *vpn = trusttunnel_create(&callbacks);
    ASSERT_NE(vpn, nullptr);

    EXPECT_EQ(trusttunnel_start(vpn, std::string(config).c_str()), TRUSTTUNNEL_VPN_SUCCESS);
    EXPECT_EQ(trusttunnel_get_state(vpn), TRUSTTUNNEL_VPN_CONNECTING);
    ASSERT_EQ(observer.states.size(), 1u);
    EXPECT_EQ(observer.states.back(), TRUSTTUNNEL_VPN_CONNECTING);
    EXPECT_GE(trusttunnel_event_fd(vpn), 0);

    // Wait for the client thread to finish on its own once the connection fails
    auto deadline = std::chrono::steady_clock::now() + CONNECT_TIMEOUT;
    while (trusttunnel_get_state(vpn) != TRUSTTUNNEL_VPN_DISCONNECTED && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }

    // The final state may still be queued: drain it through the event fd
    trusttunnel_drain(vpn);
    ASSERT_GE(observer.states.size(), 2u);
    EXPECT_EQ(observer.states.back(), TRUSTTUNNEL_VPN_DISCONNECTED);
    EXPECT_EQ(trusttunnel_get_state(vpn), TRUSTTUNNEL_VPN_DISCONNECTED);

    EXPECT_EQ(trusttunnel_stop(vpn), TRUSTTUNNEL_VPN_SUCCESS);

    trusttunnel_destroy(vpn);
}
