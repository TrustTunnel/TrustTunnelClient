// Must precede openssl includes to avoid conflicts on Windows
#include "vpn/platform.h"

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <sys/types.h>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/dns.h>
#include <event2/util.h>
#include <openssl/err.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "net/socket_manager.h"
#include "net/tcp_socket.h"
#include "vpn/utils.h"

extern "C" {
struct evdns_getaddrinfo_request *evutil_getaddrinfo_async_(struct evdns_base *dns_base, const char *nodename,
        const char *servname, const struct evutil_addrinfo *hints_in, void (*cb)(int, struct evutil_addrinfo *, void *),
        void *arg);

void evutil_getaddrinfo_cancel_async_(struct evdns_getaddrinfo_request *data);
} // extern "C"

namespace ag {

static Logger g_logger{"TCP_SOCKET"};

#define log_sock(s_, lvl_, fmt_, ...) lvl_##log(g_logger, "[{}] " fmt_, (s_)->log_id, ##__VA_ARGS__)

// TCP_NODELAY has the same value on all platforms
#undef TCP_NODELAY
#define TCP_NODELAY 1

#define UNKNOWN_ADDR_STR "unknown"
#define LOG_ID_PREADDR_FMT "id=%d/"

static const size_t MAX_WRITE_BUFFER_LEN = 128 * 1024;
static const size_t MAX_READ_SIZE = 128 * 1024;

static std::atomic_int g_next_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

typedef enum {
    /**
     * evdns may raise callbacks synchronously, but it's not obvious and error-prone
     * behaviour. This flag is needed to work around it and return an error from `tcp_connect`
     * instead of raising it in a synchronous callback.
     */
    SF_CONNECT_CALLED = 1 << 0,
    /** When set, connection will be closed with RST instead of a graceful shutdown */
    SF_RST_SET = 1 << 1,
} SocketFlags;

struct TcpSocket {
    struct bufferevent *bev;
    TcpSocketParameters parameters;
    char log_id[11 + SOCKADDR_STR_BUF_SIZE];
    int id;
    TaskId complete_read_task_id;
    int flags; // see `socket_flags_t`
    struct timeval timeouts_set_ts;
    struct evdns_getaddrinfo_request *dns_request;
    struct event *resolve_timeout_event;
    SSL *ssl;
    VpnError pending_connect_error; // buffer for synchronously raised error (see `SF_CONNECT_CALLED`)
};

extern "C" bool socket_manager_complete_write(SocketManager *manager, struct bufferevent *bev);
static void on_read(struct bufferevent *, void *);
static void on_write_flush(struct bufferevent *, TcpSocket *ctx);
static void on_event(struct bufferevent *, short, void *);
static void on_sent_event(struct evbuffer *buf, const struct evbuffer_cb_info *info, void *arg);
static struct bufferevent *create_bufferevent(TcpSocket *sock, const struct sockaddr *dst, SSL *ssl);

#ifdef _WIN32

static ULONG turn_on_estats(const TcpSocket *socket);

#endif // _WIN32

static int set_nodelay(evutil_socket_t fd) {
    int value = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &value, sizeof(value));
}

static void set_rst(TcpSocket *socket) {
#ifdef SO_LINGER
    evutil_socket_t fd = bufferevent_getfd(socket->bev);
    struct linger rst_linger = {.l_onoff = 1, .l_linger = 0};
    setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &rst_linger, sizeof(rst_linger));
#endif
}

TcpSocket *tcp_socket_create(const TcpSocketParameters *parameters) {
    auto *socket = (TcpSocket *) calloc(1, sizeof(TcpSocket));
    if (socket == nullptr) {
        return socket;
    }

    socket->parameters = *parameters;

    socket->id = g_next_id.fetch_add(1);
    socket->complete_read_task_id = -1;
    snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT UNKNOWN_ADDR_STR, socket->id);

    return socket;
}

static void socket_clean_up(TcpSocket *socket) {
    if (socket->complete_read_task_id >= 0) {
        vpn_event_loop_cancel(socket->parameters.ev_loop, socket->complete_read_task_id);
        socket->complete_read_task_id = -1;
    }

    if (socket->dns_request != nullptr) {
        evutil_getaddrinfo_cancel_async_(socket->dns_request);
        socket->dns_request = nullptr;
    }

    if (socket->resolve_timeout_event != nullptr) {
        event_free(socket->resolve_timeout_event);
        socket->resolve_timeout_event = nullptr;
    }

    if (socket->bev != nullptr) {
        shutdown(bufferevent_getfd(socket->bev), AG_SHUT_RDWR);
        bufferevent_free(socket->bev);
        socket->bev = nullptr;
    }

    if (socket->ssl != nullptr) {
        SSL_free(socket->ssl);
        socket->ssl = nullptr;
    }

    free(socket);
}

void tcp_socket_destroy(TcpSocket *socket) {
    if (socket == nullptr) {
        return;
    }

    log_sock(socket, trace, "Destroying socket...");

    if (socket->bev == nullptr) {
        goto clean_up;
    }
    log_sock(socket, trace, "Pending to write: {}", evbuffer_get_length(bufferevent_get_output(socket->bev)));

    evbuffer_remove_cb(bufferevent_get_output(socket->bev), &on_sent_event, socket);

    if (socket->flags & SF_RST_SET) {
        set_rst(socket);
        goto clean_up;
    }

    if ((bufferevent_get_enabled(socket->bev) & EV_WRITE)
            && 0 == evbuffer_get_length(bufferevent_get_output(socket->bev))) {
        goto clean_up;
    }

    bufferevent_disable(socket->bev, EV_READ);
    shutdown(bufferevent_getfd(socket->bev), AG_SHUT_RD);

    if (socket->parameters.socket_manager == nullptr) {
        goto clean_up;
    }

    if (!socket_manager_complete_write(socket->parameters.socket_manager, socket->bev)) {
        log_sock(socket, dbg, "Socket manager failed to complete data sending");
        goto clean_up;
    }

    log_sock(socket, trace, "Defer destroying bufferevent until write buffer is flushed");
    socket->bev = nullptr;

clean_up:
    socket_clean_up(socket);
}

void tcp_socket_set_rst(TcpSocket *socket) {
    socket->flags |= SF_RST_SET;
}

static void complete_read(void *arg, TaskId task_id) {
    auto *socket = (TcpSocket *) arg;
    on_read(socket->bev, socket);
}

void tcp_socket_set_read_enabled(TcpSocket *socket, bool flag) {
    struct bufferevent *bev = socket->bev;
    if (!!(bufferevent_get_enabled(bev) & EV_READ) == flag) {
        // nothing to do
        return;
    }

    if (flag) {
        bufferevent_enable(bev, EV_READ);
        // Resume reading if we did not read input fully in `on_read` before.
        // Doing it manually, because bufferevent will not trigger read events, unless
        // new data was received.
        const struct evbuffer *buffer = bufferevent_get_input(bev);
        if (socket->complete_read_task_id < 0 && evbuffer_get_length(buffer) > 0) {
            socket->complete_read_task_id = vpn_event_loop_submit(
                    socket->parameters.ev_loop, {socket, complete_read, nullptr}
            );
            if (0 > socket->complete_read_task_id) {
                log_sock(socket, err, "Failed to schedule manual read complete event");
                socket->complete_read_task_id = -1;
            }
        }
    } else {
        bufferevent_disable(bev, EV_READ);
    }
}

VpnError tcp_socket_write(TcpSocket *socket, const uint8_t *data, size_t length) {
    struct bufferevent *bev = socket->bev;

    VpnError error = {bufferevent_write(bev, data, length), ""};
    if (error.code == 0) {
        tcp_socket_set_timeout(socket, socket->parameters.timeout);
    } else {
        error = make_vpn_error_from_fd(bufferevent_getfd(bev));
    }

    return error;
}

size_t tcp_socket_available_to_write(const TcpSocket *socket) {
    size_t write_queue_size = evbuffer_get_length(bufferevent_get_output(socket->bev));
    return (write_queue_size <= MAX_WRITE_BUFFER_LEN) ? MAX_WRITE_BUFFER_LEN - write_queue_size : 0;
}

static void on_read(struct bufferevent *bev, void *ctx) {
    auto *socket = (TcpSocket *) ctx;

    if (socket->complete_read_task_id >= 0) {
        vpn_event_loop_cancel(socket->parameters.ev_loop, socket->complete_read_task_id);
        socket->complete_read_task_id = -1;
    }

    tcp_socket_set_timeout(socket, socket->parameters.timeout);

    bool readable = bufferevent_get_enabled(bev) & EV_READ;
    if (!readable) {
        // Check if another side switched off the read events before `complete_read` fired
        // (the next `complete_read` will be submitted automatically in `tcp_socket_set_read_enabled`)
        return;
    }

    struct evbuffer *buffer = bufferevent_get_input(bev);

    size_t available_to_read = evbuffer_get_length(buffer);
    int chunks_to_peek = evbuffer_peek(buffer, available_to_read, nullptr, nullptr, 0);

    std::vector<evbuffer_iovec> chunks(chunks_to_peek);
    size_t chunks_peeked = evbuffer_peek(buffer, available_to_read, nullptr, chunks.data(), chunks.size());

    size_t bytes_read = 0u;
    for (size_t i = 0; i < chunks_peeked && readable; ++i) {
        do {
            TcpSocketHandler *callbacks = &socket->parameters.handler;
            TcpSocketReadEvent event = {(const uint8_t *) chunks[i].iov_base, chunks[i].iov_len, 0};
            // `on_read` handler can delete the socket - be careful
            callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_READ, &event);
            // handler doesn't want anymore for now
            if (event.processed == 0) {
                goto loop_exit;
            }

            bytes_read += event.processed;
            chunks[i].iov_base = (void *) ((size_t) chunks[i].iov_base + event.processed);
            chunks[i].iov_len -= event.processed;

            readable = bufferevent_get_enabled(bev) & EV_READ;
        } while (chunks[i].iov_len > 0 && readable);
    }

loop_exit:
    if (bytes_read > 0) {
        evbuffer_drain(buffer, bytes_read);
    }
}

static const VpnError UNKNOWN_ERROR = {-1, "TCP socket error"};

static VpnError get_error(const TcpSocket *socket) {
    VpnError e = {};

    // Try to retrieve the SSL error
    uint32_t ssl_err = bufferevent_get_openssl_error(socket->bev);
    switch (ssl_err) {
    case SSL_ERROR_SYSCALL:
    case SSL_ERROR_SSL:
    case SSL_ERROR_WANT_X509_LOOKUP:
        // Libevent puts these on bufferevent_ssl's error queue,
        // skip it to get to the actual ERR_get_error() result
        ssl_err = (int) bufferevent_get_openssl_error(socket->bev);
        // Fallthrough
    default:
        break;
    }

    if (0 != ssl_err) {
        e.code = (int) ssl_err;
        e.text = ERR_error_string(ssl_err, nullptr);
    } else if (0 != (e.code = bufferevent_socket_get_dns_error(socket->bev))) {
        e.text = evutil_gai_strerror(e.code);
    } else if (0 != (e.code = evutil_socket_geterror(bufferevent_getfd(socket->bev)))) {
        e.text = evutil_socket_error_to_string(e.code);
    } else {
        e = UNKNOWN_ERROR;
    }

    return e;
}

static void on_event(struct bufferevent *bev, short what, void *ctx) {
    auto *socket = (TcpSocket *) ctx;
    TcpSocketHandler *callbacks = &socket->parameters.handler;

    if (what & BEV_EVENT_EOF) {
        log_sock(socket, trace, "Eof event");
        TcpSocketReadEvent e = {nullptr, 0, 0};
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_READ, &e);
    } else if (what & BEV_EVENT_TIMEOUT) {
        struct timeval timeout_tv = ms_to_timeval(uint32_t(socket->parameters.timeout.count()));
        struct timeval expected_timeout_ts;
        evutil_timeradd(&socket->timeouts_set_ts, &timeout_tv, &expected_timeout_ts);
        struct timeval now;
        event_base_gettimeofday_cached(bufferevent_get_base(bev), &now);
        if (evutil_timercmp(&expected_timeout_ts, &now, >)) {
            // timeout event could be scheduled just before `bufferevent_set_timeouts` call
            log_sock(socket, dbg, "Ignoring timeout event raised just after refreshed time outs");
        } else {
            log_sock(socket, dbg, "Timeout event");
            VpnError e = {utils::AG_ETIMEDOUT, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
            callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
        }
    } else if (what & BEV_EVENT_ERROR) {
        log_sock(socket, dbg, "Error event");
        VpnError e = get_error(socket);
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
    } else {
        log_sock(socket, dbg, "Unknown event: {}", (int) what);
    }
}

static void on_write_flush(struct bufferevent *, TcpSocket *ctx) {
    TcpSocket *socket = ctx;
    TcpSocketHandler *callbacks = &socket->parameters.handler;
    callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_WRITE_FLUSH, nullptr);
}

static void on_connect_event(struct bufferevent *, short what, TcpSocket *ctx) {
    TcpSocket *socket = ctx;
    TcpSocketHandler *callbacks = &socket->parameters.handler;

    VpnError e = {};
    if (socket->flags & SF_CONNECT_CALLED) {
        e = {-1, "Unexpected synchronous connect event"};
        // it seems like libevent should always raise callbacks asynchronously
        // with `BEV_OPT_DEFER_CALLBACKS` flag set
        assert(0);
    } else if (what & BEV_EVENT_CONNECTED) {
        bufferevent_enable(socket->bev, EV_WRITE);
        bufferevent_setcb(socket->bev, on_read, (bufferevent_data_cb) on_write_flush, on_event, socket);
        if (socket->parameters.read_threshold > 0) {
            bufferevent_setwatermark(socket->bev, EV_READ, 0, socket->parameters.read_threshold);
        }

        evbuffer_set_max_read(bufferevent_get_input(socket->bev), MAX_READ_SIZE);
        bufferevent_set_max_single_read(socket->bev, MAX_READ_SIZE);
        bufferevent_set_max_single_write(socket->bev, MAX_WRITE_BUFFER_LEN);

#ifdef _WIN32
        if (socket->parameters.record_estats) {
            ULONG status = turn_on_estats(socket);
            if (status != ERROR_SUCCESS) {
                // not fatal
                log_sock(socket, dbg, "Failed to get row from TCP table: status={} ({}) system error={} ({})",
                        sys::strerror(status), status, sys::strerror(sys::last_error()), sys::last_error());
            }
        }
#endif // _WIN32
    } else if (what & BEV_EVENT_TIMEOUT) {
        e = {utils::AG_ETIMEDOUT, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
    } else {
        e = get_error(socket);
        if (e.code == UNKNOWN_ERROR.code && 0 == strcmp(e.text, UNKNOWN_ERROR.text)) {
            e = {utils::AG_ECONNREFUSED, evutil_socket_error_to_string(utils::AG_ECONNREFUSED)};
        }
    }

    if (e.code == 0) {
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_CONNECTED, nullptr);
    } else if (socket->flags & SF_CONNECT_CALLED) {
        socket->pending_connect_error = e;
    } else {
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
    }
}

static void on_host_resolved(int err, struct evutil_addrinfo *resolved, void *arg) {
    if (err == EVUTIL_EAI_CANCEL) {
        // raised manually or socket has already been destroyed
        return;
    }

    auto *socket = (TcpSocket *) arg;
    log_sock(socket, dbg, "Got result");
    socket->dns_request = nullptr; // Request will be freed automatically after exiting from this callback

    if (socket->resolve_timeout_event != nullptr) {
        event_free(socket->resolve_timeout_event);
        socket->resolve_timeout_event = nullptr;
    }

    VpnError e = {};
    if (resolved == nullptr) {
        e.code = err;
        e.text = evutil_gai_strerror(err);
        log_sock(socket, dbg, "Failed to resolve host: {} ({})", e.text, e.code);
    } else {
        if (g_logger.is_enabled(LogLevel::LOG_LEVEL_DEBUG)) {
            char dst[SOCKADDR_STR_BUF_SIZE];
            sockaddr_to_str(resolved->ai_addr, dst, sizeof(dst));
            log_sock(socket, dbg, "Resolved successfully: {}", dst);
        }
        socket->bev = create_bufferevent(socket, resolved->ai_addr, socket->ssl);
        if (socket->bev == nullptr) {
            e = {-1, "Failed to create buffer event after resolve"};
        } else {
            socket->ssl = nullptr;
            bool is_sync_connect = !!(socket->flags & SF_CONNECT_CALLED);
            socket->flags |= SF_CONNECT_CALLED;
            int ret = bufferevent_socket_connect(socket->bev, resolved->ai_addr, (int) resolved->ai_addrlen);
            if (!is_sync_connect) {
                socket->flags &= ~SF_CONNECT_CALLED;
            }
            if (socket->pending_connect_error.code != 0) {
                e = socket->pending_connect_error;
            }
            if (ret != 0) {
                e.code = ret;
                e.text = evutil_socket_error_to_string(e.code);
            }

            if (e.code == 0) {
                log_sock(socket, dbg, "Connecting...");
            } else {
                log_sock(socket, dbg, "Failed to start connection after resolve%s: {} ({})", e.text, e.code,
                        ret == 0 ? "" : " (bufferevent_socket_connect returned error)");
            }
        }
        evutil_freeaddrinfo(resolved);
    }

    if (e.code != 0) {
        if (!(socket->flags & SF_CONNECT_CALLED)) {
            TcpSocketHandler *callbacks = &socket->parameters.handler;
            callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
        } else {
            socket->pending_connect_error = e;
        }
    }
}

static void on_sent_event(struct evbuffer *, const struct evbuffer_cb_info *info, void *arg) {
    auto *socket = (TcpSocket *) arg;

    if (0 < info->n_deleted) {
        TcpSocketHandler *callbacks = &socket->parameters.handler;
        TcpSocketSentEvent event = {info->n_deleted};
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_SENT, &event);
    }
}

static void on_resolve_timeout(evutil_socket_t, short, void *arg) {
    auto *socket = (TcpSocket *) arg;

    if (socket->dns_request != nullptr) {
        log_sock(socket, dbg, "Host resolving timed out");

        evutil_getaddrinfo_cancel_async_(socket->dns_request);
        socket->dns_request = nullptr;

        TcpSocketHandler *callbacks = &socket->parameters.handler;
        VpnError e = {utils::AG_ETIMEDOUT, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
    }
}

static struct bufferevent *wrap_fd(TcpSocket *socket, evutil_socket_t fd) {
    struct bufferevent *bev = nullptr;

    int options = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    struct event_base *base = vpn_event_loop_get_base(socket->parameters.ev_loop);
    bev = bufferevent_socket_new(base, fd, options);
    timeval tv = ms_to_timeval(uint32_t(socket->parameters.timeout.count()));

    if (bev == nullptr) {
        log_sock(socket, err, "Failed to create bufferevent");
        goto fail;
    }

    if (bufferevent_set_timeouts(bev, &tv, &tv) != 0) {
        log_sock(socket, err, "Failed to set bufferevent timeouts");
        bufferevent_setfd(bev, -1);
        goto fail;
    }

    event_base_gettimeofday_cached(base, &socket->timeouts_set_ts);

    return bev;

fail:
    if (bev != nullptr) {
        bufferevent_free(bev);
    }
    return nullptr;
}

static struct bufferevent *create_bufferevent(TcpSocket *sock, const struct sockaddr *dst, SSL *ssl) {
    struct bufferevent *bev = nullptr;
    SocketProtectEvent event;
    const TcpSocketHandler *callbacks = &sock->parameters.handler;
    int options;
    struct event_base *base;
    int err;
    struct timeval tv;

    evutil_socket_t fd = socket(dst->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_sock(sock, err, "Failed to create socket: {}", strerror(errno));
        goto fail;
    }

    if (!sockaddr_is_loopback(dst)) {
        event = {fd, dst, 0};
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_PROTECT, &event);
        if (event.result != 0) {
            log_sock(sock, err, "Failed to protect socket: {}", event.result);
            goto fail;
        }
    }

    if (0 != set_nodelay(fd)) {
        err = evutil_socket_geterror(fd);
        log_sock(sock, err, "Failed to set no delay: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    if (0 != evutil_make_socket_nonblocking(fd)) {
        err = evutil_socket_geterror(fd);
        log_sock(sock, err, "Failed to make socket non-blocking: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    base = vpn_event_loop_get_base(sock->parameters.ev_loop);
    options = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    if (ssl == nullptr) {
        bev = bufferevent_socket_new(base, fd, options);
    } else {
        bev = bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_CONNECTING, options);
    }

    if (bev == nullptr) {
        log_sock(sock, err, "Failed to create bufferevent");
        goto fail;
    }

    tv = ms_to_timeval(uint32_t(sock->parameters.timeout.count()));
    if (bufferevent_set_timeouts(bev, &tv, &tv) != 0) {
        log_sock(sock, err, "Failed to set bufferevent timeouts");
        goto fail;
    }

    event_base_gettimeofday_cached(base, &sock->timeouts_set_ts);
    bufferevent_setcb(bev, nullptr, nullptr, (bufferevent_event_cb) &on_connect_event, sock);
    evbuffer_add_cb(bufferevent_get_output(bev), &on_sent_event, (void *) sock);

    return bev;

fail:
    if (fd >= 0) {
        evutil_closesocket(fd);
    }
    if (bev != nullptr) {
        bufferevent_free(bev);
    }
    return nullptr;
}

VpnError tcp_socket_connect(TcpSocket *socket, const TcpSocketConnectParameters *param) {
    socket->flags |= SF_CONNECT_CALLED;
    socket->ssl = param->ssl;

    VpnError error = {};

    switch (param->connect_by) {
    case TCP_SOCKET_CB_ADDR: {
        if (param->by_addr.addr != nullptr) {
            char buf[SOCKADDR_STR_BUF_SIZE];
            sockaddr_to_str(param->by_addr.addr, buf, sizeof(buf));
            snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT "%s", socket->id, buf);

            socket->bev = create_bufferevent(socket, param->by_addr.addr, param->ssl);
            if (socket->bev != nullptr) {
                socket->ssl = nullptr;
            } else {
                goto fail;
            }
        }
        int ret = bufferevent_socket_connect(socket->bev, param->by_addr.addr, (int) sockaddr_get_size(param->by_addr.addr));
        if (socket->pending_connect_error.code != 0) {
            error = socket->pending_connect_error;
            log_sock(socket, dbg, "Failed to start connection: {} ({})", safe_to_string_view(error.text), error.code);
            goto fail;
        }
        if (ret != 0) {
            error.code = ret;
            error.text = evutil_socket_error_to_string(error.code);
            log_sock(socket, dbg, "Failed to start connection (bufferevent_socket_connect returned error): {} ({})",
                    safe_to_string_view(error.text), error.code);
            goto fail;
        }
        log_sock(socket, dbg, "Connecting...");
        break;
    }
    case TCP_SOCKET_CB_HOSTNAME:
        snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT "%s:%d", socket->id, param->by_name.host,
                param->by_name.port);
        char port_str[6] = {};
        snprintf(port_str, sizeof(port_str), "%d", param->by_name.port);

        // ignore family here, as if ipv6 is unavailable we won't be abe to establish connection
        struct addrinfo hint = {};

        // Work around libevent bug where it malloc's its own addrinfo's when no socktype/proto is specified,
        // leading to a crash in freeaddrinfo on Windows
        hint.ai_socktype = SOCK_STREAM;
        hint.ai_protocol = IPPROTO_TCP;

        socket->dns_request = evutil_getaddrinfo_async_(
                param->by_name.dns_base, param->by_name.host, port_str, &hint, on_host_resolved, socket);
        if (socket->pending_connect_error.code != 0) {
            error = socket->pending_connect_error;
            goto fail;
        }

        // Resolve could finish synchronously
        if (socket->dns_request == nullptr && socket->bev == nullptr) {
            log_sock(socket, err, "Failed to start host name resolving");
            goto fail;
        }

        socket->resolve_timeout_event =
                event_new(vpn_event_loop_get_base(socket->parameters.ev_loop), -1, 0, on_resolve_timeout, socket);
        if (socket->resolve_timeout_event == nullptr) {
            log_sock(socket, err, "Failed to add resolve timeout event");
            goto fail;
        }

        const timeval tv = ms_to_timeval(uint32_t(socket->parameters.timeout.count()));
        event_add(socket->resolve_timeout_event, &tv);

        log_sock(socket, dbg, "Resolving...");
        break;
    }

    goto exit;

fail:
    if (socket->bev != nullptr) {
        bufferevent_free(socket->bev);
        socket->bev = nullptr;
    }
    if (socket->dns_request != nullptr) {
        evutil_getaddrinfo_cancel_async_(socket->dns_request);
        socket->dns_request = nullptr;
    }
    if (error.code == 0) {
        error = {-1, "Internal error"};
    }

exit:
    socket->flags &= ~SF_CONNECT_CALLED;
    socket->pending_connect_error = {};
    return error;
}

VpnError tcp_socket_acquire_fd(TcpSocket *socket, evutil_socket_t fd) {
    struct sockaddr_storage addr = remote_sockaddr_from_fd(fd);

    char buf[SOCKADDR_STR_BUF_SIZE];
    sockaddr_to_str((struct sockaddr *) &addr, buf, sizeof(buf));
    snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT "%s", socket->id, buf);

    socket->bev = wrap_fd(socket, fd);
    if (socket->bev == nullptr) {
        return {-1, "Failed to wrap fd in bufferevent"};
    }

    set_nodelay(fd);
    evutil_make_socket_nonblocking(fd);
    bufferevent_enable(socket->bev, EV_WRITE);
    bufferevent_setcb(socket->bev, on_read, (bufferevent_data_cb) on_write_flush, on_event, socket);
    evbuffer_add_cb(bufferevent_get_output(socket->bev), &on_sent_event, socket);

    return {};
}

evutil_socket_t tcp_socket_get_fd(const TcpSocket *socket) {
    return bufferevent_getfd(socket->bev);
}

void tcp_socket_set_timeout(TcpSocket *socket, Millis x) {
    socket->parameters.timeout = x;
    const timeval tv = ms_to_timeval(uint32_t(x.count()));
    int r = bufferevent_set_timeouts(socket->bev, &tv, &tv);
    event_base_gettimeofday_cached(bufferevent_get_base(socket->bev), &socket->timeouts_set_ts);
    (void) r;
    assert(r == 0);
}

int make_fd_dual_stack(evutil_socket_t fd) {
    int unset = 0;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &unset, sizeof(unset));
}

#ifdef __linux__

#include <linux/tcp.h>

static inline int get_tcp_info(evutil_socket_t fd, struct tcp_info *ti) {
    socklen_t tisize = sizeof(*ti);
    return getsockopt(fd, IPPROTO_TCP, TCP_INFO, ti, &tisize);
}

TcpFlowCtrlInfo tcp_socket_flow_control_info(const TcpSocket *socket) {
    TcpFlowCtrlInfo info = {tcp_socket_available_to_write(socket), DEFAULT_SEND_WINDOW_SIZE};

    struct tcp_info ti = {};
    int r = get_tcp_info(tcp_socket_get_fd(socket), &ti);
    if (r != 0) {
        int err = evutil_socket_geterror(tcp_socket_get_fd(socket));
        log_sock(
                socket, dbg, "Failed to get window size from system: {} ({})", evutil_socket_error_to_string(err), err);
    } else if (sizeof(ti) >= offsetof(struct tcp_info, tcpi_snd_cwnd) + sizeof(ti.tcpi_snd_cwnd)
            && sizeof(ti) >= offsetof(struct tcp_info, tcpi_snd_mss) + sizeof(ti.tcpi_snd_mss)) {
        //        log_sock(socket, trace, "rcv_space={} snd_cwnd={} snd_cwnd*snd_mss={} snd_wscale={} snd_mss={}",
        //                (int)ti.tcpi_rcv_space, (int)ti.tcpi_snd_cwnd, (int)ti.tcpi_snd_cwnd * ti.tcpi_snd_mss,
        //                (int)ti.tcpi_snd_wscale, (int)ti.tcpi_snd_mss);

        // It seems we need tcpi_snd_wnd, which was added only very recently
        // So we may use a bit smaller congestion window rather than flow control window
        info.send_window_size = (size_t) ti.tcpi_snd_cwnd * ti.tcpi_snd_mss;
    } else {
        log_sock(socket, dbg, "Failed to get window size from system: too short tcp_info structure");
    }

    return info;
}

VpnConnectionStats tcp_socket_get_stats(const TcpSocket *socket) {
    VpnConnectionStats stats = {};

    struct tcp_info ti = {};
    int r = get_tcp_info(tcp_socket_get_fd(socket), &ti);
    if (r == 0) {
        stats.rtt_us = ti.tcpi_rtt;
        stats.packet_loss_ratio = (ti.tcpi_segs_out > 0) ? (double) ti.tcpi_lost / ti.tcpi_segs_out : 0;
    } else {
        int err = evutil_socket_geterror(tcp_socket_get_fd(socket));
        log_sock(socket, dbg, "Failed to get TCP socket info from system: {} ({})", evutil_socket_error_to_string(err),
                err);
    }

    log_sock(socket, dbg, "RTT={}us, packets sent={}, lost={}, loss ratio={}, retransmitted={}", stats.rtt_us,
            ti.tcpi_segs_out, ti.tcpi_lost, stats.packet_loss_ratio, ti.tcpi_retrans);

    return stats;
}

#endif // __linux__

#ifdef __MACH__

static inline int get_tcp_connection_info(evutil_socket_t fd, struct tcp_connection_info *ti) {
    socklen_t tisize = sizeof(*ti);
    return getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, ti, &tisize);
}

TcpFlowCtrlInfo tcp_socket_flow_control_info(const TcpSocket *socket) {
    TcpFlowCtrlInfo info = {tcp_socket_available_to_write(socket), DEFAULT_SEND_WINDOW_SIZE};

    struct tcp_connection_info ti = {};
    int r = get_tcp_connection_info(tcp_socket_get_fd(socket), &ti);
    if (r == 0) {
        info.send_window_size = ti.tcpi_snd_wnd;

        // log_sock(socket, trace, "snd_ssthresh={} snd_cwnd={} snd_wscale={} snd_wnd={}",
        //         (int) ti.tcpi_snd_ssthresh, (int) ti.tcpi_snd_cwnd,
        //         (int) ti.tcpi_snd_wscale, (int) ti.tcpi_snd_wnd);
    } else {
        int err = evutil_socket_geterror(tcp_socket_get_fd(socket));
        log_sock(
                socket, dbg, "Failed to get window size from system: {} ({})", evutil_socket_error_to_string(err), err);
    }

    return info;
}

VpnConnectionStats tcp_socket_get_stats(const TcpSocket *socket) {
    VpnConnectionStats stats = {};

    struct tcp_connection_info ti = {};
    int r = get_tcp_connection_info(tcp_socket_get_fd(socket), &ti);
    if (r == 0) {
        // @note: seems like the units of RTT value are milliseconds unlike the linux analogue
        // looks like milliseconds
        // http://gitlab.placoid.cn/facebook/wangle/blob/a676e9d358d72ad908cb51a923ba089b35086fb7/wangle/acceptor/TransportInfo.cpp#L37
        // looks like microseconds
        // http://gitlab.placoid.cn/facebook/wangle/blob/a676e9d358d72ad908cb51a923ba089b35086fb7/wangle/acceptor/TransportInfo.cpp#L135
        stats.rtt_us = ti.tcpi_srtt * 1000;
        stats.packet_loss_ratio = (ti.tcpi_txbytes > 0) ? (double) ti.tcpi_txretransmitbytes / ti.tcpi_txbytes : 0;
    } else if (r < 0) {
        int err = evutil_socket_geterror(tcp_socket_get_fd(socket));
        log_sock(socket, dbg, "Failed to get TCP socket info from system: {} ({})", evutil_socket_error_to_string(err),
                err);
    }

    log_sock(socket, dbg, "RTT={}us, bytes sent={}, retransmitted={}, loss ratio={}", stats.rtt_us, ti.tcpi_txbytes,
            ti.tcpi_txretransmitbytes, stats.packet_loss_ratio);

    return stats;
}

#endif // __MACH__

#ifdef _WIN32

static int get_family(const TcpSocket *socket) {
    return local_sockaddr_from_fd(tcp_socket_get_fd(socket)).ss_family;
}

static ULONG get_tcp_row_(int local_port, int remote_port, PMIB_TCPROW row) {
    ULONG size = 0;
    ULONG status = GetTcpTable(nullptr, &size, false);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return status;
    }

    PMIB_TCPTABLE tcp_table = (PMIB_TCPTABLE) malloc(size);
    if (tcp_table == nullptr) {
        return ERROR_OUTOFMEMORY;
    }

    status = GetTcpTable(tcp_table, &size, false);
    if (status != ERROR_SUCCESS) {
        free(tcp_table);
        return status;
    }

    bool connection_found = false;
    for (DWORD i = 0; i < tcp_table->dwNumEntries; ++i) {
        const PMIB_TCPROW it = &tcp_table->table[i];
        if (it->dwLocalPort == local_port && it->dwRemotePort == remote_port && it->State == MIB_TCP_STATE_ESTAB) {
            connection_found = true;
            *row = *it;
            break;
        }
    }

    free(tcp_table);

    return connection_found ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

static ULONG get_tcp6_row_(int local_port, int remote_port, PMIB_TCP6ROW row) {
    ULONG size = 0;
    ULONG status = GetTcp6Table(nullptr, &size, false);
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        return status;
    }

    PMIB_TCP6TABLE tcp6_table = (PMIB_TCP6TABLE) malloc(size);
    if (tcp6_table == nullptr) {
        return ERROR_OUTOFMEMORY;
    }

    status = GetTcp6Table(tcp6_table, &size, false);
    if (status != ERROR_SUCCESS) {
        free(tcp6_table);
        return status;
    }

    bool connection_found = false;
    for (DWORD i = 0; i < tcp6_table->dwNumEntries; ++i) {
        const PMIB_TCP6ROW it = &tcp6_table->table[i];
        if (it->dwLocalPort == (DWORD) local_port && it->dwRemotePort == (DWORD) remote_port
                && it->State == MIB_TCP_STATE_ESTAB) {
            connection_found = true;
            *row = *it;
            break;
        }
    }

    free(tcp6_table);

    return connection_found ? ERROR_SUCCESS : ERROR_NOT_FOUND;
}

static ULONG get_tcp_row(int family, int local_port, int remote_port, void *row) {
    switch (family) {
    case AF_INET:
        return get_tcp_row_(local_port, remote_port, (PMIB_TCPROW) row);
    case AF_INET6:
        return get_tcp6_row_(local_port, remote_port, (PMIB_TCP6ROW) row);
    default:
        return ERROR_INVALID_PARAMETER;
    }
}

static ULONG get_connection_estats(void *row, int family, TCP_ESTATS_TYPE type, PUCHAR rw, ULONG rw_size, PUCHAR ros,
        ULONG ros_size, PUCHAR rod, ULONG rod_size) {
    switch (family) {
    case AF_INET:
        return GetPerTcpConnectionEStats((PMIB_TCPROW) row, type, rw, 0, rw_size, ros, 0, ros_size, rod, 0, rod_size);
    case AF_INET6:
        return GetPerTcp6ConnectionEStats((PMIB_TCP6ROW) row, type, rw, 0, rw_size, ros, 0, ros_size, rod, 0, rod_size);
    default:
        return ERROR_INVALID_PARAMETER;
    }
}

static ULONG get_estats_(void *row, int family, TCP_ESTATS_TYPE type, void *rod, ULONG rod_size) {
    TCP_ESTATS_DATA_RW_v0 data_rw = {};
    TCP_ESTATS_PATH_RW_v0 path_rw = {};

    ULONG status = ERROR_SUCCESS;
    switch (type) {
    case TcpConnectionEstatsData:
        if (rod_size != sizeof(TCP_ESTATS_DATA_ROD_v0)) {
            assert(0);
            return ERROR_INVALID_PARAMETER;
        }
        status = get_connection_estats(
                row, family, type, (PUCHAR) &data_rw, sizeof(data_rw), nullptr, 0, (PUCHAR) rod, rod_size);
        break;
    case TcpConnectionEstatsPath:
        if (rod_size != sizeof(TCP_ESTATS_PATH_ROD_v0)) {
            assert(0);
            return ERROR_INVALID_PARAMETER;
        }
        status = get_connection_estats(
                row, family, type, (PUCHAR) &path_rw, sizeof(path_rw), nullptr, 0, (PUCHAR) rod, rod_size);
        break;
    default:
        assert(0);
        status = ERROR_INVALID_PARAMETER;
        break;
    }

    return status;
}

static ULONG get_stats(void *row, int family, VpnConnectionStats *stats) {
    TCP_ESTATS_DATA_ROD_v0 data_rod = {};
    ULONG status = get_estats_(row, family, TcpConnectionEstatsData, &data_rod, sizeof(data_rod));
    if (status != ERROR_SUCCESS) {
        return status;
    }

    TCP_ESTATS_PATH_ROD_v0 path_rod = {};
    status = get_estats_(row, family, TcpConnectionEstatsPath, &path_rod, sizeof(path_rod));
    if (status != ERROR_SUCCESS) {
        return status;
    }

    stats->rtt_us = path_rod.SmoothedRtt * 1000;
    stats->packet_loss_ratio = (data_rod.SegsOut > 0) ? (double) path_rod.PktsRetrans / data_rod.SegsOut : 0;

    return ERROR_SUCCESS;
}

static ULONG turn_on_estats_(void *row, int family, TCP_ESTATS_TYPE type) {
    size_t size = 0;
    PUCHAR rw = nullptr;
    TCP_ESTATS_DATA_RW_v0 data_rw = {};
    TCP_ESTATS_PATH_RW_v0 path_rw = {};

    switch (type) {
    case TcpConnectionEstatsData:
        data_rw.EnableCollection = true;
        rw = (PUCHAR) &data_rw;
        size = sizeof(data_rw);
        break;
    case TcpConnectionEstatsPath:
        path_rw.EnableCollection = true;
        rw = (PUCHAR) &path_rw;
        size = sizeof(path_rw);
        break;
    default:
        assert(0);
        return ERROR_INVALID_PARAMETER;
    }

    ULONG status = 0;

    switch (family) {
    case AF_INET:
        status = SetPerTcpConnectionEStats((PMIB_TCPROW) row, type, rw, 0, size, 0);
        break;
    case AF_INET6:
        status = SetPerTcp6ConnectionEStats((PMIB_TCP6ROW) row, type, rw, 0, size, 0);
        break;
    default:
        status = ERROR_INVALID_PARAMETER;
        break;
    }

    return status;
}

static ULONG get_tcp_row_for_socket(const TcpSocket *socket, void **connect_row) {
    int family = get_family(socket);

    evutil_socket_t fd = tcp_socket_get_fd(socket);
    struct sockaddr_storage local_addr = local_sockaddr_from_fd(fd);
    struct sockaddr_storage remote_addr = remote_sockaddr_from_fd(fd);

    size_t row_size = 0;
    switch (family) {
    case AF_INET:
        row_size = sizeof(MIB_TCPROW);
        break;
    case AF_INET6:
        row_size = sizeof(MIB_TCP6ROW);
        break;
    }

    *connect_row = malloc(row_size);
    if (*connect_row == nullptr) {
        return ERROR_OUTOFMEMORY;
    }

    ULONG status = get_tcp_row(family, sockaddr_get_raw_port((struct sockaddr *) &local_addr),
            sockaddr_get_raw_port((struct sockaddr *) &remote_addr), *connect_row);
    if (status != ERROR_SUCCESS) {
        free(*connect_row);
        *connect_row = nullptr;
    }

    return status;
}

static ULONG turn_on_estats(const TcpSocket *socket) {
    int family = get_family(socket);

    void *connect_row = nullptr;
    ULONG status = get_tcp_row_for_socket(socket, &connect_row);
    if (status != ERROR_SUCCESS) {
        goto done;
    }

    status = turn_on_estats_(connect_row, family, TcpConnectionEstatsData);
    if (status != ERROR_SUCCESS) {
        goto done;
    }

    status = turn_on_estats_(connect_row, family, TcpConnectionEstatsPath);
    if (status != ERROR_SUCCESS) {
        goto done;
    }

done:
    free(connect_row);
    return status;
}

TcpFlowCtrlInfo tcp_socket_flow_control_info(const TcpSocket *socket) {
    // @todo: consider using
    // https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getpertcpconnectionestats
    return {tcp_socket_available_to_write(socket), DEFAULT_SEND_WINDOW_SIZE};
}

VpnConnectionStats tcp_socket_get_stats(const TcpSocket *socket) {
    VpnConnectionStats stats = {};
    int family = get_family(socket);

    void *connect_row = nullptr;
    ULONG status = get_tcp_row_for_socket(socket, &connect_row);
    if (status != ERROR_SUCCESS) {
        log_sock(socket, dbg, "Failed to get row from TCP table: status={} ({}) system error={} ({})",
                sys::strerror(status), status, sys::strerror(sys::last_error()), sys::last_error());
        goto done;
    }

    status = get_stats(connect_row, family, &stats);
    if (status != ERROR_SUCCESS) {
        log_sock(socket, dbg, "Failed to get stats: status={} ({}) system error={} ({})", sys::strerror(status), status,
                sys::strerror(sys::last_error()), sys::last_error());
        goto done;
    }

done:
    free(connect_row);
    return stats;
}

#endif // _WIN32

} // namespace ag
