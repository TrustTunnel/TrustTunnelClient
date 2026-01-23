#include "vpn/platform.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cstring>
#include <errno.h>
#include <limits>
#include <vector>

#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>

#include "common/logger.h"
#include "tcp_conn_manager.h"
#include "tcp_connection.h"
#include "tcp_raw.h"
#include "tcpip_common.h"

namespace ag {

#define log_conn(conn_, lvl_, fmt_, ...)                                                                               \
    do {                                                                                                               \
        TcpipConnection *c = (TcpipConnection *) conn_;                                                                \
        lvl_##log(c->parent_ctx->tcp.log, "[id={}] " fmt_, ((TcpipConnection *) conn_)->id, ##__VA_ARGS__);            \
    } while (0)

typedef struct {
    TcpipCtx *tcpip;
    uint64_t id;
} ConnCtx;

static void tcp_raw_error(void *arg, err_t err);
static err_t tcp_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t tcp_raw_poll(void *arg, struct tcp_pcb *tpcb);
static err_t tcp_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static err_t tcp_raw_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

// NOLINTBEGIN(cppcoreguidelines-no-malloc,hicpp-no-malloc)
static void tcp_raw_error(void *arg, err_t err) {
    auto *ctx = (ConnCtx *) arg;

    auto *conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcpip->tcp.connections, ctx->id);
    if (conn == nullptr) {
        warnlog(ctx->tcpip->tcp.log, "Connection not found: id={}", ctx->id);
        free(ctx);
        return;
    }

    if (err == ERR_RST) {
        log_conn(conn, dbg, "Connection reset by local client");
    }

    // PCB is no longer interactable at this point
    conn->pcb = nullptr;
    tcp_cm_close_descriptor(ctx->tcpip, ctx->id, false);
    free(ctx);
}

static err_t tcp_raw_poll(void *arg, struct tcp_pcb *tpcb) {
    err_t ret_err = ERR_OK;

    auto *ctx = (ConnCtx *) arg;
    TcpConnDescriptor *conn = nullptr;
    if (ctx != nullptr) {
        conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcpip->tcp.connections, ctx->id);
    }

    if (conn != nullptr) {
        log_conn(conn, trace, "");
        if (TCP_CONN_STATE_CLOSING_BY_CLIENT == conn->state) {
            log_conn(conn, dbg, "No more buffers");
            tcp_cm_close_descriptor(ctx->tcpip, ctx->id, false);
        } else {
            tcp_cm_data_sent_notify(conn, 0);
            log_conn(conn, trace, "OK");
        }
    } else {
        warnlog(ctx->tcpip->tcp.log, "Connection not found: id={}", ctx->id);
        tcp_abort(tpcb);
        ret_err = ERR_ABRT;
        free(ctx);
    }

    return ret_err;
}

static err_t tcp_raw_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    auto *ctx = (ConnCtx *) arg;

    auto *conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcpip->tcp.connections, ctx->id);
    if (conn == nullptr) {
        warnlog(ctx->tcpip->tcp.log, "Connection not found: id={}", ctx->id);
        tcp_abort(tpcb);
        return ERR_ABRT;
    }

    log_conn(conn, trace, "{} bytes", len);

    tcp_cm_data_sent_notify(conn, len);
    if (TCP_CONN_STATE_CLOSING_BY_CLIENT == conn->state) {
        log_conn(conn, dbg, "No more buffers");
        tcp_cm_close_descriptor(ctx->tcpip, ctx->id, false);
    }

    return ERR_OK;
}

static err_t process_data(TcpConnDescriptor *conn, const struct pbuf *buffer) {
    log_conn(conn, trace, "send {} bytes", buffer->len);

    size_t chain_length = pbuf_clen(buffer);
    std::vector<evbuffer_iovec> iov;
    iov.reserve(chain_length);

    for (const struct pbuf *iter = buffer; (iov.size() < chain_length) && (iter != nullptr); iter = iter->next) {
        iov.push_back({
                .iov_base = iter->payload,
                .iov_len = iter->len,
        });
    }

    int recv_result = tcp_cm_receive(conn, iov.size(), iov.data());
    if (0 > recv_result) {
        // Negative result means connection is closed during receive
        return ERR_ABRT;
    }

    return ERR_OK;
}

static err_t process_closed_connection(TcpConnDescriptor *conn) {
    if (TCP_CONN_STATE_REQUESTED == conn->state) {
        // not yet accepted
    } else {
        conn->state = TCP_CONN_STATE_CLOSING_BY_CLIENT;
    }

    tcp_cm_close_descriptor(conn->common.parent_ctx, conn->common.id, true);

    return ERR_OK;
}

static err_t process_recv_event(TcpConnDescriptor *conn, struct pbuf *buffer) {
    err_t result;

    switch (conn->state) {
    case TCP_CONN_STATE_ACCEPTED:
    case TCP_CONN_STATE_CLOSING_BY_SERVER:
        if (buffer->flags & PBUF_FLAG_PUSH) {
            tcp_set_flags(conn->pcb, TF_ACK_NOW);
        }
        result = process_data(conn, buffer);
        break;
    case TCP_CONN_STATE_CLOSING_BY_CLIENT:
        // fall-through
    default:
        tcp_recved(conn->pcb, buffer->tot_len);
        result = ERR_OK;
    }

    if (ERR_OK == result) {
        pbuf_free(buffer);
    }

    return result;
}

static err_t tcp_raw_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    auto *ctx = (ConnCtx *) arg;
    auto *tcpip = ctx->tcpip;
    auto id = ctx->id;

    auto *conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&tcpip->tcp.connections, id);
    if (conn == nullptr) {
        warnlog(tcpip->tcp.log, "Connection not found: id={}", id);
        tcp_abort(tpcb);
        return ERR_ABRT;
    }

    LWIP_ASSERT("pcb in entry is not the same as raised one", conn->pcb == tpcb);

    err_t result;
    if (nullptr == p) {
        log_conn(conn, trace, "Connection closed");
        result = process_closed_connection(conn);
    } else if (ERR_OK != err) {
        log_conn(conn, trace, "Error {} ({})", lwip_strerr(err), err);
        result = err;
        pbuf_free(p);
    } else {
        result = process_recv_event(conn, p);
        // Conn may be destructed here
        tracelog(tcpip->tcp.log, "[id={}] Result = {}", id, result);
    }

    return result;
}

static err_t tcp_raw_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    if ((ERR_OK != err) || (nullptr == newpcb)) {
        return ERR_VAL;
    }

    auto *ctx = (TcpipCtx *) arg;
    auto entry = (TcpConnDescriptor *) tcpip_get_connection_by_ip(
            &ctx->tcp.connections, &newpcb->remote_ip, newpcb->remote_port, &newpcb->local_ip, newpcb->local_port);

    if (entry == nullptr) {
        dbglog(ctx->tcp.log, "Connection is already closed or does not exist");
        return ERR_RST;
    }

    if (!tcp_cm_accept(entry, newpcb)) {
        return ERR_RST;
    }

    tcp_setprio(newpcb, TCP_PRIO_MIN);
    tcp_nagle_disable(newpcb);

    static_assert(std::is_trivial_v<ConnCtx>);
    auto *conn_ctx = (ConnCtx *) malloc(sizeof(ConnCtx));
    conn_ctx->tcpip = ctx;
    conn_ctx->id = entry->common.id;

    tcp_arg(newpcb, conn_ctx);
    tcp_recv(newpcb, tcp_raw_recv);
    tcp_err(newpcb, tcp_raw_error);
    tcp_poll(newpcb, tcp_raw_poll, 0);
    tcp_sent(newpcb, tcp_raw_sent);

    return ERR_OK;
}

err_t tcp_raw_init(TcpipCtx *ctx) {
    struct tcp_pcb *tun_pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (nullptr == tun_pcb) {
        errlog(ctx->tcp.log, "Failed to create pcb");
        return ERR_MEM;
    }

    /*
     * SOF_REUSEADDR should be set on listening socket before tcp_bind()
     * because some timewait PCBs with port overlapping with our reserved port number
     * may be left from previous TCP/IP stack run.
     * See https://github.com/AdguardTeam/AdguardForAndroid/issues/1634
     */
    ip_set_option(tun_pcb, SOF_REUSEADDR);

    err_t err = tcp_bind(tun_pcb, IP_ANY_TYPE, CATCH_ANY_PORT);
    if (ERR_OK != err) {
        errlog(ctx->tcp.log, "Failed to bind TUN pcb: {} ({})", lwip_strerr(err), err);
        tcp_raw_destroy(ctx);
        return err;
    }

    tcp_arg(tun_pcb, ctx);
    tun_pcb = tcp_listen(tun_pcb);
    tcp_accept(tun_pcb, tcp_raw_accept);

    ctx->tcp.tun_pcb = tun_pcb;

    dbglog(ctx->tcp.log, "OK");
    return ERR_OK;
}

void tcp_raw_destroy(TcpipCtx *ctx) {
    if (ctx->tcp.tun_pcb != nullptr) {
        tcp_close(ctx->tcp.tun_pcb);
    }
}

err_t tcp_raw_send(struct tcp_pcb *pcb, const uint8_t *data, size_t size) {
    if (nullptr == data) {
        return ERR_ARG;
    }

    int flags = TCP_WRITE_FLAG_COPY;
    return tcp_write(pcb, data, u16_t(size), flags);
}

size_t tcp_raw_get_out_buf_space(const struct tcp_pcb *pcb) {
    return tcp_sndbuf(pcb);
}

void tcp_raw_close(struct tcp_pcb *pcb, bool graceful) {
    if (pcb == nullptr) {
        return;
    }

    free(pcb->callback_arg);

    tcp_arg(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);

    if (graceful) {
        tcp_close(pcb);
    } else {
        tcp_abort(pcb);
    }
}

void tcp_raw_slide_window(struct tcp_pcb *pcb, size_t sent) {
    while (sent > 0) {
        auto to_slide = (u16_t) std::min(sent, (size_t) std::numeric_limits<u16_t>::max());
        tcp_recved(pcb, to_slide);
        sent -= to_slide;
    }
}
// NOLINTEND(cppcoreguidelines-no-malloc,hicpp-no-malloc)

} // namespace ag
