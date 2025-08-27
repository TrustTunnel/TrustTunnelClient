// Must precede openssl includes to avoid conflicts on Windows
#include "vpn/platform.h"

#include <atomic>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <list>
#include <variant>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "net/socket_manager.h"
#include "net/tcp_socket.h"
#include "vpn/utils.h"

namespace ag {

static Logger g_logger{"TCP_SOCKET"};

#define log_sock(s_, lvl_, fmt_, ...)                                                                                  \
    lvl_##log(g_logger, "[{}] [{}] " fmt_, (s_)->parameters.log_prefix, (s_)->log_id, ##__VA_ARGS__)

// TCP_NODELAY has the same value on all platforms
#undef TCP_NODELAY
#define TCP_NODELAY 1

#define UNKNOWN_ADDR_STR "unknown"
#define LOG_ID_PREADDR_FMT "id=%d/"

static const size_t MAX_WRITE_BUFFER_LEN = 128 * 1024;
static const size_t MAX_READ_SIZE = 128 * 1024;

static const size_t SSL_READ_SIZE = 4096;

static std::atomic_int g_next_id = 0; // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

extern "C" {
int socket_manager_timer_subscribe(SocketManager *manager, VpnEventLoop *loop, uint32_t timeout_ms,
        void (*tick_handler)(void *arg, struct timeval now), void *arg);

void socket_manager_timer_unsubscribe(SocketManager *manager, int id);
}

enum SocketFlags : uint32_t {
    /**
     * evdns may raise callbacks synchronously, but it's not obvious and error-prone
     * behaviour. This flag is needed to work around it and return an error from `tcp_connect`
     * instead of raising it in a synchronous callback.
     */
    SF_CONNECT_CALLED = 1 << 0,
    /** When set, connection will be closed with RST instead of a graceful shutdown */
    SF_RST_SET = 1 << 1,
    /** Received */
    SF_GOT_EOF = 1 << 2,
    /** Pause TLS handshake on receipt of the first data chunk from the server */
    SF_PAUSE_TLS = 1 << 3,
};

struct SslBuf {
    uint8_t data[SSL_READ_SIZE];
    size_t size;
};

struct TcpSocket {
    bufferevent *bev = nullptr;
    TcpSocketParameters parameters{};
    char log_id[11 + SOCKADDR_STR_BUF_SIZE]{};
    int id = 0;
    event_loop::AutoTaskId complete_read_task_id;
    uint32_t flags; // see `SocketFlags`
    DeclPtr<SSL, &SSL_free> ssl;
    std::list<SslBuf> ssl_pending;
    VpnError pending_connect_error{}; // buffer for synchronously raised error (see `SF_CONNECT_CALLED`)
    timeval timeout_ts{};
    std::optional<int> subscribe_id;
    std::string_view alpn;
    int kex_group_nid = NID_undef; // NID of group function used for key exchange
};

extern "C" bool socket_manager_complete_write(SocketManager *manager, struct bufferevent *bev);
static void on_read(struct bufferevent *, void *);
static void on_write_flush(struct bufferevent *, TcpSocket *ctx);
static void on_event(struct bufferevent *, short, void *);
static void on_sent_event(struct evbuffer *buf, const struct evbuffer_cb_info *info, void *arg);
static struct bufferevent *create_bufferevent(TcpSocket *sock, const SocketAddress &dst, bool anti_dpi);
static VpnError do_handshake(TcpSocket *socket);
static void tcp_socket_update_timeout(TcpSocket *sock);

#ifdef _WIN32

static ULONG turn_on_estats(const TcpSocket *socket);

static int workaround_sndbuf(evutil_socket_t fd) {
    // This is a workaround for slow upload speeds on high-RTT connections.
    //
    // Source for some of the statements below:
    // https://learn.microsoft.com/en-us/windows/win32/winsock/sio-ideal-send-backlog-query
    //
    // 1. When RTT is high, TCP send performance is capped by the amount of unacked data that can be
    //    buffered on the sender's size.
    // 2. The optimal size for this buffer is called the Ideal Send Backlog (ISB), and is calculated from the
    //    receiver's window, congestion window, and the bandwidth-delay product.
    // 3. Windows _should_, by default, calculate ISB and adjust SO_SNDBUF automatically, but apparently,
    //    it either doesn't, or the the default upper limit on SO_SNDBUF is too low.
    // 4. According to source, the maximum value for ISB is 16 MB.
    // 5. Microsoft proposes applications use this call:
    //    https://learn.microsoft.com/en-us/windows/win32/winsock/sio-ideal-send-backlog-change
    //    to receive notifications about ISB changes, and set SO_SNDBUF accordingly.
    // 6. Since we don't use Overlapped IO, we can't use that strategy (we'd have to start a separate thread
    //    per socket to call the blocking version of that function).
    // 7. Verdict: let's set SO_SNDBUF to 16 MB (allegedly the maximum ISB value) and hope that this doesn't mean
    //    that Windows will always allocate 16 MB of real memory per socket. (It doesn't seem to, as
    //    memory consumption as reported by Task Manager is not higher than before this change).
    DWORD sndbuf = 16 * 1024 * 1024;
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &sndbuf, sizeof(sndbuf));
}

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
    auto socket = std::make_unique<TcpSocket>();

    socket->parameters = *parameters;

    socket->id = g_next_id.fetch_add(1);
    snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT UNKNOWN_ADDR_STR, socket->id);

    return socket.release();
}

static void socket_clean_up(TcpSocket *socket) {
    socket->complete_read_task_id.reset();

    if (socket->bev != nullptr) {
        shutdown(bufferevent_getfd(socket->bev), AG_SHUT_RDWR);
        bufferevent_free(socket->bev);
        socket->bev = nullptr;
    }

    socket->ssl.reset();

    delete socket;
}

void tcp_socket_destroy(TcpSocket *socket) {
    if (socket == nullptr) {
        return;
    }

    log_sock(socket, trace, "Destroying socket...");

    if (socket->parameters.socket_manager != nullptr && socket->subscribe_id.has_value()) {
        socket_manager_timer_unsubscribe(socket->parameters.socket_manager, *socket->subscribe_id);
    }

    if (socket->bev == nullptr) {
        goto clean_up;
    }

    if (SSL *ssl = bufferevent_openssl_get_ssl(socket->bev); ssl && !SSL_is_init_finished(ssl)) {
        // If we keep the bufferevent-openssl alive after the socket is destroyed to "complete pending writes",
        // and a TLS handshake is in progress, it might access the verify callback, which is not guaranteed to
        // stay alive after the socket is destroyed, resulting in a use-after-free.
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

void tcp_socket_set_rst(TcpSocket *socket, bool rst) {
    if (rst) {
        socket->flags |= SF_RST_SET;
    } else {
        socket->flags &= ~SF_RST_SET;
    }
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
        if (!socket->complete_read_task_id.has_value()
                && (evbuffer_get_length(buffer) > 0 || (socket->flags & SF_GOT_EOF)
                        || socket->ssl // Reuse the complete_read task for driving the handshake.
                        || !socket->ssl_pending.empty())) {
            socket->complete_read_task_id =
                    event_loop::submit(socket->parameters.ev_loop, {socket, complete_read, nullptr});
        }
    } else {
        bufferevent_disable(bev, EV_READ);
        socket->complete_read_task_id.reset();
    }
}

bool tcp_socket_is_read_enabled(TcpSocket *self) {
    return bufferevent_get_enabled(self->bev) & EV_READ;
}

VpnError tcp_socket_write(TcpSocket *socket, const uint8_t *data, size_t length) {
    struct bufferevent *bev = socket->bev;

    VpnError error = {bufferevent_write(bev, data, length), ""};
    if (error.code == 0) {
        tcp_socket_update_timeout(socket);
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

    socket->complete_read_task_id.reset();

    tcp_socket_update_timeout(socket);

    const TcpSocketHandler &handler = socket->parameters.handler;
    if (socket->ssl) {
        VpnError error;

        if (!SSL_is_init_finished(socket->ssl.get())) {
            error = do_handshake(socket);
            if (error.code != 0) {
                handler.handler(handler.arg, TCP_SOCKET_EVENT_ERROR, &error);
                return;
            }
            if (!SSL_is_init_finished(socket->ssl.get())) {
                return;
            }
        }

        // Handshake finished, report "connected".
        tcp_socket_set_read_enabled(socket, false);
        log_sock(socket, dbg, "TLS handshake complete. Session reused: {}", SSL_session_reused(socket->ssl.get()));

        for (;;) {
            SslBuf &buf = socket->ssl_pending.emplace_back();
            int ret = SSL_read(socket->ssl.get(), buf.data, sizeof(buf.data));
            if (ret <= 0) {
                socket->ssl_pending.pop_back();
                int ssl_error = SSL_get_error(socket->ssl.get(), ret);
                if (ssl_error != SSL_ERROR_WANT_READ) {
                    error = {.code = ssl_error, .text = ERR_error_string(ssl_error, nullptr)};
                    handler.handler(handler.arg, TCP_SOCKET_EVENT_ERROR, &error);
                    return;
                }
                break;
            }
            buf.size = ret;
        }

        const uint8_t *out = nullptr;
        uint32_t out_len;
        SSL_get0_alpn_selected(socket->ssl.get(), &out, &out_len);
        socket->alpn = {(const char *) out, out_len};

        socket->kex_group_nid = SSL_get_negotiated_group(socket->ssl.get());

        bufferevent *bev_ssl =
                bufferevent_openssl_filter_new(vpn_event_loop_get_base(socket->parameters.ev_loop), socket->bev,
                        socket->ssl.release(), BUFFEREVENT_SSL_OPEN, BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
        if (!bev_ssl) {
            error = {.code = -1, .text = "bufferevent_openssl_filter_new failed"};
            handler.handler(handler.arg, TCP_SOCKET_EVENT_ERROR, &error);
            return;
        }
        socket->bev = bev_ssl;
        bufferevent_setcb(socket->bev, on_read, (bufferevent_data_cb) on_write_flush, on_event, socket);
        evbuffer_add_cb(bufferevent_get_output(socket->bev), &on_sent_event, (void *) socket);
        if (socket->parameters.read_threshold > 0) {
            bufferevent_setwatermark(socket->bev, EV_READ, 0, socket->parameters.read_threshold);
        }

        handler.handler(handler.arg, TCP_SOCKET_EVENT_CONNECTED, nullptr);
        return;
    }

    bool readable = bufferevent_get_enabled(bev) & EV_READ;
    if (!readable) {
        // Check if another side switched off the read events before `complete_read` fired
        // (the next `complete_read` will be submitted automatically in `tcp_socket_set_read_enabled`)
        return;
    }

    handler.handler(handler.arg, TCP_SOCKET_EVENT_READABLE, nullptr);
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
        socket->flags |= SF_GOT_EOF;

        // We don't need to check for EV_READ here because it is unset inside libevent
        // just before firing this callback, and BEV_EVENT_EOF can only be raised when EV_READ is set.
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_READABLE, nullptr);
    } else if (what & BEV_EVENT_TIMEOUT) {
        // We do not expect that timeout disables reads or writes
        bufferevent_enable(bev, (what & BEV_EVENT_WRITING) ? EV_WRITE : 0);
        bufferevent_enable(bev, (what & BEV_EVENT_READING) ? EV_READ : 0);

        abort();
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

        if (socket->ssl) {
            log_sock(socket, dbg, "Starting TLS handshake...");
            SSL_set_connect_state(socket->ssl.get());
            SSL_set0_rbio(socket->ssl.get(), BIO_new(BIO_s_mem()));
            SSL_set0_wbio(socket->ssl.get(), BIO_new(BIO_s_mem()));
            e = do_handshake(socket);
            tcp_socket_set_read_enabled(socket, true);
        }
    } else if (what & BEV_EVENT_TIMEOUT) {
        e = {utils::AG_ETIMEDOUT, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
    } else {
        e = get_error(socket);
        if (e.code == UNKNOWN_ERROR.code && 0 == strcmp(e.text, UNKNOWN_ERROR.text)) {
            e = {utils::AG_ECONNREFUSED, evutil_socket_error_to_string(utils::AG_ECONNREFUSED)};
        }
    }

    if (e.code == 0) {
#ifdef _WIN32
        if (int ret = workaround_sndbuf(bufferevent_getfd(socket->bev))) {
            log_sock(socket, warn, "Failed to set SO_SNBBUF: {}", ret);
        }
#endif
        if (!socket->ssl) {
            log_sock(socket, dbg, "Socket connected"); // without TLS
            callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_CONNECTED, nullptr);
        }
    } else if (socket->flags & SF_CONNECT_CALLED) {
        socket->pending_connect_error = e;
    } else {
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_ERROR, &e);
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

static struct bufferevent *wrap_fd(TcpSocket *socket, evutil_socket_t fd) {
    struct bufferevent *bev = nullptr;

    int options = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    struct event_base *base = vpn_event_loop_get_base(socket->parameters.ev_loop);
    bev = bufferevent_socket_new(base, fd, options);

    if (bev == nullptr) {
        log_sock(socket, err, "Failed to create bufferevent");
        return nullptr;
    }

    tcp_socket_update_timeout(socket);

    return bev;
}

static const std::unique_ptr<ev_token_bucket_cfg, ag::Ftor<&ev_token_bucket_cfg_free>> RATE_LIMIT_ANTIDPI{
        ev_token_bucket_cfg_new(EV_RATE_LIMIT_MAX, EV_RATE_LIMIT_MAX, DPI_SPLIT_SIZE, DPI_SPLIT_SIZE,
                std::array<timeval, 1>{ms_to_timeval(DPI_COOLDOWN_TIME.count())}.data())};

static const std::unique_ptr<ev_token_bucket_cfg, ag::Ftor<&ev_token_bucket_cfg_free>> RATE_LIMIT_UNLIMITED{
        ev_token_bucket_cfg_new(EV_RATE_LIMIT_MAX, EV_RATE_LIMIT_MAX, EV_RATE_LIMIT_MAX, EV_RATE_LIMIT_MAX,
                std::array<timeval, 1>{ms_to_timeval(DPI_COOLDOWN_TIME.count())}.data())};

static void on_rate_limited_write(struct evbuffer *, const struct evbuffer_cb_info *info, void *arg) {
    if (info->n_deleted > 0) {
        auto bev = (bufferevent *) arg;
        // If rate limiter is nullptr, buckets are immediately flushed.
        // To keep next bucket, set unlimited rate limiter, not nullptr
        bufferevent_set_rate_limit(bev, RATE_LIMIT_UNLIMITED.get());
        if (info->orig_size == info->n_deleted) {
            bufferevent_set_rate_limit(bev, nullptr);
            evbuffer_remove_cb(bufferevent_get_output(bev), on_rate_limited_write, (void *) bev);
        }
    }
}

static struct bufferevent *create_bufferevent(TcpSocket *sock, const SocketAddress &dst, bool anti_dpi) {
    struct bufferevent *bev = nullptr;
    SocketProtectEvent event;
    const TcpSocketHandler *callbacks = &sock->parameters.handler;
    int options;
    struct event_base *base;

    evutil_socket_t fd = socket(dst.c_storage()->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        log_sock(sock, err, "Failed to create socket: {}", strerror(errno));
        goto fail;
    }

    if (dst.valid() && dst.is_loopback()) {
        event = {fd, dst.c_sockaddr(), 0};
        callbacks->handler(callbacks->arg, TCP_SOCKET_EVENT_PROTECT, &event);
        if (event.result != 0) {
            log_sock(sock, err, "Failed to protect socket: {}", event.result);
            goto fail;
        }
    }

    if (0 != set_nodelay(fd)) {
        int err = evutil_socket_geterror(fd);
        log_sock(sock, err, "Failed to set no delay: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    if (0 != evutil_make_socket_nonblocking(fd)) {
        int err = evutil_socket_geterror(fd);
        log_sock(sock, err, "Failed to make socket non-blocking: {} ({})", evutil_socket_error_to_string(err), err);
        goto fail;
    }

    if (0 != evutil_make_socket_closeonexec(fd)) {
        int err = evutil_socket_geterror(fd);
        log_sock(sock, warn, "Failed to make socket close-on-exec: {} ({})", evutil_socket_error_to_string(err), err);
    }

    base = vpn_event_loop_get_base(sock->parameters.ev_loop);
    options = BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE;
    bev = bufferevent_socket_new(base, fd, options);
    if (bev == nullptr) {
        log_sock(sock, err, "Failed to create bufferevent");
        goto fail;
    }

    if (anti_dpi) {
        bufferevent_set_rate_limit(bev, RATE_LIMIT_ANTIDPI.get());
        evbuffer_add_cb(bufferevent_get_output(bev), on_rate_limited_write, (void *) bev);
    }

    tcp_socket_update_timeout(sock);

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

    VpnError error = {};
    int ret;
    SocketAddress addr{};
    if (param->peer != nullptr) {
        addr = SocketAddress(*param->peer);
        snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT "%s", socket->id, addr.str().c_str());

        socket->bev = create_bufferevent(socket, addr, (param->ssl && param->anti_dpi));
        if (socket->bev == nullptr) {
            goto fail;
        }
    }
    ret = bufferevent_socket_connect(socket->bev, addr.c_sockaddr(), (int) addr.c_socklen());
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
    goto exit;

fail:
    if (socket->bev != nullptr) {
        bufferevent_free(socket->bev);
        socket->bev = nullptr;
    }
    if (error.code == 0) {
        error = {-1, "Internal error"};
    }

exit:
    if (error.code == 0) {
        socket->ssl.reset(param->ssl);
        if (param->pause_tls) {
            socket->flags |= SF_PAUSE_TLS;
        }
    }
    socket->flags &= ~SF_CONNECT_CALLED;
    socket->pending_connect_error = {};
    return error;
}

VpnError tcp_socket_acquire_fd(TcpSocket *socket, evutil_socket_t fd) {
    SocketAddress addr = remote_socket_address_from_fd(fd);

    snprintf(socket->log_id, sizeof(socket->log_id), LOG_ID_PREADDR_FMT "%s", socket->id, addr.str().c_str());

    socket->bev = wrap_fd(socket, fd);
    if (socket->bev == nullptr) {
        return {-1, "Failed to wrap fd in bufferevent"};
    }

    if (0 != set_nodelay(fd)) {
        int error = evutil_socket_geterror(fd);
        log_sock(socket, warn, "Failed to set TCP_NODELAY: ({}) {}", error,
                 evutil_socket_error_to_string(error));
    }
    if (0 != evutil_make_socket_nonblocking(fd)) {
        int error = evutil_socket_geterror(fd);
        log_sock(socket, err, "Failed to make socket non-blocking: ({}) {}", error,
                 evutil_socket_error_to_string(error));
        return {-1, "Failed to make socket non-blocking"};
    }
    if (0 != evutil_make_socket_closeonexec(fd)) {
        int error = evutil_socket_geterror(fd);
        log_sock(socket, warn, "Failed to make socket close-on-exec: ({}) {}", error,
                 evutil_socket_error_to_string(error));
    }

    bufferevent_enable(socket->bev, EV_WRITE);
    bufferevent_setcb(socket->bev, on_read, (bufferevent_data_cb) on_write_flush, on_event, socket);
    evbuffer_add_cb(bufferevent_get_output(socket->bev), &on_sent_event, socket);

    return {};
}

evutil_socket_t tcp_socket_get_fd(const TcpSocket *socket) {
    return bufferevent_getfd(socket->bev);
}

static struct timeval get_next_timeout_ts(const TcpSocket *sock) {
    struct timeval now;
    event_base_gettimeofday_cached(vpn_event_loop_get_base(sock->parameters.ev_loop), &now);
    struct timeval timeout_tv = ms_to_timeval(uint32_t(sock->parameters.timeout.count()));

    struct timeval next_timeout_ts;
    evutil_timeradd(&now, &timeout_tv, &next_timeout_ts);

    return next_timeout_ts;
}

static void timer_callback(void *arg, struct timeval now) {
    auto *sock = (TcpSocket *) arg;

    if (timercmp(&sock->timeout_ts, &now, <)) {
        log_sock(sock, dbg, "Timeout event");
        VpnError e = {utils::AG_ETIMEDOUT, evutil_socket_error_to_string(utils::AG_ETIMEDOUT)};
        sock->parameters.handler.handler(sock->parameters.handler.arg, TCP_SOCKET_EVENT_ERROR, &e);
    }
}

void tcp_socket_set_timeout(TcpSocket *sock, Millis x) {
    log_sock(sock, dbg, "Timeout set to {} ms", x.count() ? AG_FMT("{}", x.count()) : "Timeout disabled");
    sock->parameters.timeout = x;
    tcp_socket_update_timeout(sock);
}

int make_fd_dual_stack(evutil_socket_t fd) {
    int unset = 0;
    return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &unset, sizeof(unset));
}

tcp_socket::PeekResult tcp_socket_peek(TcpSocket *self) {
    if (!self->ssl_pending.empty()) {
        return tcp_socket::Chunk{self->ssl_pending.front().data, self->ssl_pending.front().size};
    }

    evbuffer_iovec chunk = {};
    if (0 < evbuffer_peek(bufferevent_get_input(self->bev), -1, nullptr, &chunk, 1) && chunk.iov_len > 0) {
        return tcp_socket::Chunk{(uint8_t *) chunk.iov_base, chunk.iov_len};
    }

    if (self->flags & SF_GOT_EOF) {
        return tcp_socket::Eof{};
    }

    return tcp_socket::NoData{};
}

bool tcp_socket_drain(TcpSocket *self, size_t n) {
    while (!self->ssl_pending.empty() && n > 0) {
        SslBuf &buf = self->ssl_pending.front();
        if (n >= buf.size) {
            n -= buf.size;
            self->ssl_pending.pop_front();
        } else {
            buf.size -= n;
            std::memmove(buf.data, buf.data + n, buf.size);
            break;
        }
    }
    return (n == 0) || (self->bev != nullptr && 0 == evbuffer_drain(bufferevent_get_input(self->bev), n));
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
    return local_socket_address_from_fd(tcp_socket_get_fd(socket)).c_storage()->sa_family;
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
    SocketAddress local_addr = local_socket_address_from_fd(fd);
    SocketAddress remote_addr = remote_socket_address_from_fd(fd);

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

    ULONG status = get_tcp_row(family, htons(local_addr.port()), htons(remote_addr.port()), *connect_row);
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

VpnError do_handshake(TcpSocket *socket) {
    auto err_log_wrapper = [socket](const int code, const char* text) -> VpnError {
        if (code != 0) {
            log_sock(socket, dbg, "SSL handshake completed with error: {}", text);
        }

        return {.code=code, .text=text};
    };

    size_t bio_written = 0;
    for (;;) {
        tcp_socket::PeekResult result = tcp_socket_peek(socket);
        if (std::holds_alternative<tcp_socket::NoData>(result)) {
            break;
        }
        if (std::holds_alternative<tcp_socket::Eof>(result)) {
            return err_log_wrapper(-1, "Unexpected EOF during TLS handshake");
        }
        assert(std::holds_alternative<tcp_socket::Chunk>(result));
        auto chunk = std::get<tcp_socket::Chunk>(result);

        int ret = BIO_write(SSL_get_rbio(socket->ssl.get()), chunk.data(), chunk.size());
        if (ret < 0) {
            return err_log_wrapper(-1, "BIO_write failed");
        }
        bio_written += ret;
        tcp_socket_drain(socket, ret);
    }

    if ((socket->flags & SF_PAUSE_TLS) && bio_written) {
        socket->flags &= ~SF_PAUSE_TLS;

        if (socket->parameters.socket_manager && socket->subscribe_id.has_value()) {
            socket_manager_timer_unsubscribe(socket->parameters.socket_manager, *socket->subscribe_id);
        }
        socket->parameters.socket_manager = nullptr;

        tcp_socket_set_read_enabled(socket, false);
        bufferevent_setcb(socket->bev, nullptr, nullptr, nullptr, nullptr);

        const TcpSocketHandler &handler = socket->parameters.handler;
        handler.handler(handler.arg, TCP_SOCKET_EVENT_CONNECTED, nullptr);

        // Let's pass zero code here explicitly
        return err_log_wrapper(0, "");
    }

    if (int ret = SSL_do_handshake(socket->ssl.get()); ret <= 0) {
        int error = SSL_get_error(socket->ssl.get(), ret);
        if ((error != SSL_ERROR_WANT_READ) && (error != SSL_ERROR_WANT_WRITE)) {
            return err_log_wrapper(error, ERR_error_string(error, nullptr));
        }
    }

    for (;;) {
        uint8_t buf[SSL_READ_SIZE];
        int ret = BIO_read(SSL_get_wbio(socket->ssl.get()), buf, sizeof(buf));
        if (ret < 0) {
            if (BIO_should_retry(SSL_get_wbio(socket->ssl.get()))) {
                break;
            }
            return err_log_wrapper(-1,"BIO_read failed");
        }
        if (ret == 0) {
            break;
        }
        VpnError e = tcp_socket_write(socket, buf, ret);
        if (e.code != 0) {
            return err_log_wrapper(e.code, e.text);
        }
    }

    return err_log_wrapper(0, "");
}

void tcp_socket_update_timeout(TcpSocket *sock) {
    if (!sock->parameters.socket_manager) {
        return;
    }
    if (sock->subscribe_id.has_value()) {
        socket_manager_timer_unsubscribe(sock->parameters.socket_manager, *sock->subscribe_id);
    }
    if (sock->parameters.timeout.count()) {
        sock->timeout_ts = get_next_timeout_ts(sock);
        sock->subscribe_id = socket_manager_timer_subscribe(sock->parameters.socket_manager, sock->parameters.ev_loop,
                                                            uint32_t(sock->parameters.timeout.count()), timer_callback, sock);
    }
}

VpnError tcp_socket_connect_continue(TcpSocket *socket, const TcpSocketParameters *params) {
    if (!socket->ssl) {
        return {.code = -1, .text = "Wrong socket state"};
    }

    TcpSocketParameters old_params = socket->parameters;
    socket->parameters = *params;

    evutil_socket_t fd = bufferevent_getfd(socket->bev);
    ag::DeclPtr<bufferevent, &bufferevent_free> bufev{wrap_fd(socket, fd)};
    if (!bufev) {
        socket->parameters = old_params;
        return {.code = -1, .text = "Failed to create a new bufferevent"};
    }

    bufferevent_setfd(socket->bev, -1);
    bufferevent_free(socket->bev);
    socket->bev = bufev.release();

    bufferevent_setcb(socket->bev, on_read, (bufferevent_data_cb) on_write_flush, on_event, socket);
    evbuffer_add_cb(bufferevent_get_output(socket->bev), &on_sent_event, socket);

    if (socket->parameters.read_threshold > 0) {
        bufferevent_setwatermark(socket->bev, EV_READ, 0, socket->parameters.read_threshold);
    }

    tcp_socket_set_read_enabled(socket, true);
    return do_handshake(socket);
}

SSL *tcp_socket_get_ssl(TcpSocket *socket) {
    if (socket->ssl) {
        return socket->ssl.get();
    }
    return bufferevent_openssl_get_ssl(socket->bev);
}

std::string_view tcp_socket_get_selected_alpn(TcpSocket *socket) {
    return socket->alpn;
}

int tcp_socket_get_id(const TcpSocket *socket) {
    return socket->id;
}

int tcp_socket_get_kex_group_nid(const TcpSocket *socket) {
    return socket->kex_group_nid;
}

} // namespace ag
