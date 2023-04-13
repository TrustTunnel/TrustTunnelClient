#include "net/udp_socket.h"

#include <atomic>

#include <event2/event.h>
#include <event2/util.h>

#include "common/logger.h"

static ag::Logger g_logger{"UDP_SOCKET"};

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (s_)->log_id, ##__VA_ARGS__)

static std::atomic_int g_next_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

#ifdef __MACH__
static constexpr int MAX_DATAGRAM_PROCESS_DELAY_SECS = 10;
#endif

namespace ag {

struct UdpSocket {
    struct event *event;
    struct timeval timeout_ts;
    UdpSocketParameters parameters;
    int subscribe_id;
    char log_id[11 + SOCKADDR_STR_BUF_SIZE];
};

extern "C" {
int socket_manager_timer_subscribe(SocketManager *manager, VpnEventLoop *loop, uint32_t timeout_ms,
        void (*tick_handler)(void *arg, struct timeval now), void *arg);

void socket_manager_timer_unsubscribe(SocketManager *manager, int id);
}

static struct timeval get_next_timeout_ts(const UdpSocket *sock) {
    struct timeval now;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(sock->parameters.ev_loop), &now);
    struct timeval timeout_tv = ms_to_timeval(uint32_t(sock->parameters.timeout.count()));

    struct timeval next_timeout_ts;
    evutil_timeradd(&now, &timeout_tv, &next_timeout_ts);

    return next_timeout_ts;
}

static void event_handler(evutil_socket_t, short what, void *arg) {
    auto *sock = (UdpSocket *) arg;

    if (what & EV_READ) {
        sock->parameters.handler.func(sock->parameters.handler.arg, UDP_SOCKET_EVENT_READABLE, nullptr);
        sock->timeout_ts = get_next_timeout_ts(sock);
    } else if (what & EV_TIMEOUT) {
        log_sock(sock, dbg, "Timed out");
        sock->parameters.handler.func(sock->parameters.handler.arg, UDP_SOCKET_EVENT_TIMEOUT, nullptr);
    } else {
        log_sock(sock, dbg, "Unknown event {}", (int) what);
    }
}

static void timer_callback(void *arg, struct timeval now) {
    auto *sock = (UdpSocket *) arg;

    if (timercmp(&sock->timeout_ts, &now, <)) {
        log_sock(sock, dbg, "Timed out");
        sock->parameters.handler.func(sock->parameters.handler.arg, UDP_SOCKET_EVENT_TIMEOUT, nullptr);
    }
}

UdpSocket *udp_socket_create(const UdpSocketParameters *parameters) {
    auto sock = (UdpSocket *) calloc(1, sizeof(UdpSocket));
    if (sock == nullptr) {
        return nullptr;
    }

    sock->parameters = *parameters;

    char buf[SOCKADDR_STR_BUF_SIZE];
    sockaddr_to_str((struct sockaddr *) &parameters->peer, buf, sizeof(buf));
    snprintf(sock->log_id, sizeof(sock->log_id), "id=%d/%s", g_next_id.fetch_add(1), buf);

    const struct sockaddr *peer = (struct sockaddr *) &sock->parameters.peer;
    evutil_socket_t fd = socket(peer->sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        int err = evutil_socket_geterror(fd);
        log_sock(sock, err, "Failed to create socket: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }
    {
        if (!sockaddr_is_loopback(peer)) {
            SocketProtectEvent protect_event = {fd, peer, 0};
            parameters->handler.func(parameters->handler.arg, UDP_SOCKET_EVENT_PROTECT, &protect_event);
            if (protect_event.result != 0) {
                log_sock(sock, err, "Failed to protect socket");
                goto fail;
            }
        }

        if (0 != connect(fd, peer, sockaddr_get_size(peer))) {
            int err = evutil_socket_geterror(fd);
            log_sock(sock, err, "Failed to set socket destination: {} ({})", evutil_socket_error_to_string(err), err);
            goto fail;
        }

        if (0 != evutil_make_socket_nonblocking(fd)) {
            int err = evutil_socket_geterror(fd);
            log_sock(sock, err, "Failed to make socket non-blocking: {} ({})", evutil_socket_error_to_string(err), err);
            goto fail;
        }

#ifdef __MACH__
        int enabled = 1;
        if (0 != setsockopt(fd, SOL_SOCKET, SO_TIMESTAMP, &enabled, sizeof(enabled))) {
            int err = evutil_socket_geterror(fd);
            log_sock(
                    sock, warn, "Failed to make socket timestamping: {} ({})", evutil_socket_error_to_string(err), err);
        }
#endif

        sock->event = event_new(
                vpn_event_loop_get_base(sock->parameters.ev_loop), fd, EV_READ | EV_PERSIST, event_handler, sock);
        if (sock->event == nullptr) {
            log_sock(sock, err, "Failed to create event");
            goto fail;
        }

        fd = -1;
        if (0 != event_add(sock->event, nullptr)) {
            log_sock(sock, err, "Failed to add event in event base");
            goto fail;
        }

        sock->subscribe_id = socket_manager_timer_subscribe(sock->parameters.socket_manager, sock->parameters.ev_loop,
                uint32_t(sock->parameters.timeout.count()), timer_callback, sock);
        if (sock->subscribe_id < 0) {
            log_sock(sock, err, "Failed to subscribe for timer events");
            goto fail;
        }

        sock->timeout_ts = get_next_timeout_ts(sock);
    }
    goto exit;

fail:
    udp_socket_destroy(sock);
    sock = nullptr;
    if (fd >= 0) {
        evutil_closesocket(fd);
    }

exit:
    return sock;
}

void udp_socket_destroy(UdpSocket *socket) {
    if (socket == nullptr) {
        return;
    }

    if (socket->event != nullptr) {
        evutil_closesocket(event_get_fd(socket->event));
        event_free(socket->event);
    }
    socket_manager_timer_unsubscribe(socket->parameters.socket_manager, socket->subscribe_id);
    free(socket);
}

VpnError udp_socket_write(UdpSocket *socket, const uint8_t *data, size_t length) {
    VpnError error = {};

    evutil_socket_t fd = event_get_fd(socket->event);
    int r = send(fd, (const char *) data, length, 0);
    if (r < 0) {
        int err_code = evutil_socket_geterror(fd);
        if (AG_ERR_IS_EAGAIN(err_code)) {
            log_sock(socket, dbg, "Dropping packet due to system buffer overflow");
        } else {
            error = make_vpn_error_from_fd(fd);
        }
    }

    if (error.code == 0) {
        socket->timeout_ts = get_next_timeout_ts(socket);
    }

    return error;
}

evutil_socket_t udp_socket_get_fd(const UdpSocket *socket) {
    return event_get_fd(socket->event);
}

ssize_t udp_socket_recv(UdpSocket *socket, uint8_t *buffer, size_t cap) {
    evutil_socket_t fd = udp_socket_get_fd(socket);

    ssize_t ret; // NOLINT(cppcoreguidelines-init-variables)
    while (true) {
#ifndef __MACH__
        ret = recv(fd, (char *) buffer, cap, 0);
#else
        // Check timestamp before passing packet to Quiche.
        iovec vec = {.iov_base = buffer, .iov_len = cap};
        char cmsgspace[CMSG_SPACE(sizeof(struct timeval))] = "";
        struct msghdr msg = {.msg_iov = &vec,
                .msg_iovlen = 1,
                .msg_control = &cmsgspace,
                .msg_controllen = CMSG_LEN(sizeof(struct timeval))};
        ret = recvmsg(fd, &msg, 0);
        if (ret > 0) {
            struct timeval time_receive = {}, time_now = {}, time_diff_receive = {};
            evutil_gettimeofday(&time_now, nullptr);

            for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct timeval))) {
                    time_receive = *(struct timeval *) CMSG_DATA(cmsg);
                    break;
                }
            }
            timersub(&time_now, &time_receive, &time_diff_receive);
            if (time_receive.tv_sec > 0 && time_diff_receive.tv_sec >= MAX_DATAGRAM_PROCESS_DELAY_SECS) {
                log_sock(socket, dbg, "Received datagram is expired, time spent since receive: {}.{}",
                        (int64_t) time_diff_receive.tv_sec, (int) time_diff_receive.tv_usec);
                continue;
            }
        }
#endif

        if (ret < 0 && AG_EINTR == evutil_socket_geterror(fd)) {
            continue;
        }

        break;
    }

    return ret;
}

} // namespace ag
