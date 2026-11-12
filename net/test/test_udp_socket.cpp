#include <gtest/gtest.h>

#include "common/logger.h"
#include "common/socket_address.h"
#include "net/network_manager.h"
#include "net/udp_socket.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

using namespace ag;

static constexpr Millis SOCKET_TIMEOUT{200};

class UdpSocketTest : public testing::Test {
public:
    UdpSocketTest() {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    int timeouts = 0;

    [[nodiscard]] UdpSocketParameters make_parameters() {
        return {
                .ev_loop = this->loop.get(),
                .handler = {.func = handler, .arg = this},
                .timeout = SOCKET_TIMEOUT,
                .peer = SocketAddress{sockaddr_from_str("127.0.0.1:443")},
                .socket_manager = this->network_manager->socket,
        };
    }

private:
    static void handler(void *arg, UdpSocketEvent what, void *) {
        if (what == UDP_SOCKET_EVENT_TIMEOUT) {
            ++((UdpSocketTest *) arg)->timeouts;
        }
    }
};

// Each UDP socket gets a new id, also the one that takes over the descriptor of another socket
TEST_F(UdpSocketTest, GetId) {
    UdpSocketParameters parameters = make_parameters();
    DeclPtr<UdpSocket, &udp_socket_destroy> first{udp_socket_create(&parameters)};
    ASSERT_NE(first.get(), nullptr);
    DeclPtr<UdpSocket, &udp_socket_destroy> second{udp_socket_create(&parameters)};
    ASSERT_NE(second.get(), nullptr);
    EXPECT_LT(udp_socket_get_id(first.get()), udp_socket_get_id(second.get()));

    int second_id = udp_socket_get_id(second.get());
    evutil_socket_t fd = udp_socket_release_fd(second.release()); // destroys the socket
    ASSERT_NE(fd, EVUTIL_INVALID_SOCKET);
    DeclPtr<UdpSocket, &udp_socket_destroy> third{udp_socket_acquire_fd(&parameters, fd)};
    ASSERT_NE(third.get(), nullptr);
    EXPECT_LT(second_id, udp_socket_get_id(third.get()));
}

// An idle socket raises the timeout once per timeout period, not on every tick of the shared timer,
// which runs 4 times per period
TEST_F(UdpSocketTest, TimeoutOncePerPeriod) {
    UdpSocketParameters parameters = make_parameters();
    DeclPtr<UdpSocket, &udp_socket_destroy> socket{udp_socket_create(&parameters)};
    ASSERT_NE(socket.get(), nullptr);

    static constexpr int PERIODS = 5;
    vpn_event_loop_exit(this->loop.get(), PERIODS * SOCKET_TIMEOUT + SOCKET_TIMEOUT / 2);
    vpn_event_loop_run(this->loop.get());

    // Without the fix, the timeout comes on every tick after the first period, about 4 times per period.
    // The lower bound is loose, because a busy runner can deliver fewer ticks in the window.
    EXPECT_GE(this->timeouts, 1);
    EXPECT_LE(this->timeouts, PERIODS);
}
