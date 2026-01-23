#include "libevent_lwip.h"

#ifndef _WIN32
#include <sys/time.h>
#endif

#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <thread>

#include <event2/event.h>
#include <lwip/init.h>
#include <lwip/ip4_frag.h>
#include <lwip/ip6_frag.h>
#include <lwip/nd6.h>
#include <lwip/opt.h>
#include <lwip/priv/tcp_priv.h> // Timeout constants
#include <lwip/sys.h>
#include <lwip/timeouts.h>

#include "common/logger.h"
#include "tcpip/tcpip.h"

namespace ag {

/**
 * Libevent LWIP port context
 */
typedef struct LibeventLwip {
    ag::Logger logger{"TCPIP.LWIP"};
    VpnEventLoop *event_loop;
    int tcp_timer_active;
    struct event *tcp_fasttmr_event;
    struct event *tcp_slowtmr_event;
    struct event *ip_reass_tmr_event;
    struct event *ip6_reass_tmr_event;
    struct event *nd6_tmr_event;
} LibeventLwip;

static std::mutex g_lwip_init_mutex;
static LibeventLwip *g_lwip;

static inline struct event *lwip_timer_new(void (*cb)(evutil_socket_t, short, void *), void *arg) {
    return event_new(vpn_event_loop_get_base(g_lwip->event_loop), -1, EV_TIMEOUT | EV_PERSIST, cb, arg);
}

static inline void lwip_timer_start(struct event *event, int msec) {
    if (event != nullptr) {
        timeval tv = ms_to_timeval(msec);
        event_add(event, &tv);
    }
}

static inline struct event *lwip_timer_new_started(void (*cb)(evutil_socket_t, short, void *), void *arg, int msec) {
    struct event *event = event_new(vpn_event_loop_get_base(g_lwip->event_loop), -1, EV_TIMEOUT | EV_PERSIST, cb, arg);
    if (event) {
        lwip_timer_start(event, msec);
    }
    return event;
}

static inline void lwip_timer_stop(struct event *event) {
    if (event != nullptr) {
        event_del(event);
    }
}

static inline void lwip_timer_destroy(struct event **event) {
    if (*event != nullptr) {
        event_free(*event);
        *event = nullptr;
    }
}

static void run_tcp_timer(evutil_socket_t fd, short events, void *arg);

static void run_lwip_timer(evutil_socket_t fd, short events, void *arg);

int libevent_lwip_init(TcpipCtx *ctx) {
    std::scoped_lock l(g_lwip_init_mutex);
    if (g_lwip != nullptr) {
        return ERR_ALREADY;
    }

    g_lwip = new LibeventLwip{};

    g_lwip->event_loop = ctx->parameters.event_loop;

    g_lwip->tcp_fasttmr_event = lwip_timer_new(run_tcp_timer, (void *) (tcp_fasttmr));
    g_lwip->tcp_slowtmr_event = lwip_timer_new(run_tcp_timer, (void *) tcp_slowtmr);
    g_lwip->ip_reass_tmr_event = lwip_timer_new_started(run_lwip_timer, (void *) ip_reass_tmr, IP_TMR_INTERVAL);
    g_lwip->ip6_reass_tmr_event =
            lwip_timer_new_started(run_lwip_timer, (void *) ip6_reass_tmr, IP6_REASS_TMR_INTERVAL);
    g_lwip->nd6_tmr_event = lwip_timer_new_started(run_lwip_timer, (void *) nd6_tmr, ND6_TMR_INTERVAL);

    lwip_init();

    return ERR_OK;
}

void libevent_lwip_free() {
    if (g_lwip == nullptr) {
        return;
    }

    std::scoped_lock l(g_lwip_init_mutex);
    lwip_timer_destroy(&g_lwip->tcp_fasttmr_event);
    lwip_timer_destroy(&g_lwip->tcp_slowtmr_event);
    lwip_timer_destroy(&g_lwip->ip_reass_tmr_event);
    lwip_timer_destroy(&g_lwip->ip6_reass_tmr_event);
    lwip_timer_destroy(&g_lwip->nd6_tmr_event);

    delete g_lwip;
    g_lwip = nullptr;
}

// NOLINTBEGIN(cert-dcl50-cpp)
void libevent_lwip_log_debug(const char *message, ...) {
    if (g_lwip == nullptr) {
        return;
    }
    va_list args;
    va_start(args, message);
    char fmt_message[1024];
    int len = vsnprintf(fmt_message, 1024, message, args);
    if (fmt_message[len - 1] == '\n') {
        fmt_message[len - 1] = 0;
    }
    errlog(g_lwip->logger, "{}", fmt_message);
    va_end(args);
}
// NOLINTEND(cert-dcl50-cpp)

static void run_lwip_timer(evutil_socket_t fd, short events, void *arg) {
    LWIP_UNUSED_ARG(fd);
    LWIP_UNUSED_ARG(events);
    lwip_cyclic_timer_handler func = (lwip_cyclic_timer_handler) arg;
    func();
}

static void run_tcp_timer(evutil_socket_t fd, short events, void *arg) {
    run_lwip_timer(fd, events, arg);

    if (!tcp_active_pcbs && !tcp_tw_pcbs) {
        lwip_timer_stop(g_lwip->tcp_fasttmr_event);
        lwip_timer_stop(g_lwip->tcp_slowtmr_event);
        g_lwip->tcp_timer_active = 0;
    }
}

/**
 * Called from TCP_REG when registering a new PCB:
 * the reason is to have the TCP timer only running when
 * there are active (or time-wait) PCBs.
 */
extern "C" void tcp_timer_needed() {
    /* timer is off but needed again? */
    if (g_lwip != nullptr && !g_lwip->tcp_timer_active && (tcp_active_pcbs || tcp_tw_pcbs)) {
        /* enable and start timer */
        g_lwip->tcp_timer_active = 1;
        lwip_timer_start(g_lwip->tcp_fasttmr_event, TCP_FAST_INTERVAL);
        lwip_timer_start(g_lwip->tcp_slowtmr_event, TCP_SLOW_INTERVAL);
    }
}

extern "C" uint32_t sys_now() {
    timeval tv;
    if (g_lwip != nullptr) {
        event_base_gettimeofday_cached(vpn_event_loop_get_base(g_lwip->event_loop), &tv);
    } else {
        evutil_gettimeofday(&tv, nullptr);
    }
    return (uint32_t) (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

extern "C" void sys_timeouts_init(void) {
    LWIP_ASSERT("Please don't call lwip_init() directly, use libevent_lwip_init()", g_lwip != nullptr);
}

} // namespace ag
