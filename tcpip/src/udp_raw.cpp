#include "vpn/platform.h"

#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/timeouts.h>
#include <lwip/udp.h>

#include <vector>

#include "common/logger.h"
#include "tcpip/tcpip.h"
#include "tcpip_common.h"
#include "udp_conn_manager.h"
#include "udp_raw.h"

namespace ag {

#define log_conn(conn_, lvl_, fmt_, ...)                                                                               \
    do {                                                                                                               \
        TcpipConnection *c = (TcpipConnection *) conn_;                                                                \
        lvl_##log(c->parent_ctx->udp.log, "[id={}] " fmt_, ((TcpipConnection *) conn_)->id, ##__VA_ARGS__);            \
    } while (0)

static void udp_raw_recv(
        void *arg, struct udp_pcb *pcb, struct pbuf *buffer, const ip_addr_t *src_addr, u16_t src_port) {
    auto *tcpip_ctx = (TcpipCtx *) arg;

    size_t chain_length = pbuf_clen(buffer);
    std::vector<evbuffer_iovec> iov;
    iov.reserve(chain_length);

    for (const struct pbuf *iter = buffer; (iov.size() < chain_length) && (iter != nullptr); iter = iter->next) {
        iov.push_back({
                .iov_base = iter->payload,
                .iov_len = iter->len,
        });
    }

    const ip_addr_t *dst_addr = ip_current_dest_addr();
    u16_t dst_port = pcb->local_port;
    udp_cm_receive(tcpip_ctx, src_addr, src_port, dst_addr, dst_port, iov.size(), iov.data());

    pbuf_free(buffer);
}

err_t udp_raw_send(
        UdpConnDescriptor *descriptor, ip_addr_t *from_ip, uint16_t from_port, const uint8_t *data, size_t length) {
    TcpipConnection *common = &descriptor->common;
    struct pbuf *buffer = pbuf_alloc(PBUF_TRANSPORT, u16_t(length), PBUF_RAM);
    if (nullptr == buffer) {
        log_conn(descriptor, err, "Failed to allocate buffer");
        return ERR_MEM;
    }

    err_t result = pbuf_take(buffer, data, u16_t(length));
    if (ERR_OK != result) {
        log_conn(descriptor, err, "Failed to fill buffer: {} ({})", lwip_strerr(result), result);
        return result;
    }

    TcpipCtx *tcpip_ctx = common->parent_ctx;
    UdpCtx *udp_ctx = &tcpip_ctx->udp;
    struct udp_pcb *pcb = udp_ctx->tun_pcb;
    pcb->local_port = from_port;
    result = udp_sendto_if_src(pcb, buffer, &common->addr.src_ip, common->addr.src_port, tcpip_ctx->netif, from_ip);
    pbuf_free(buffer);
    pcb->local_port = CATCH_ANY_PORT;

    return result;
}

err_t udp_raw_init(TcpipCtx *ctx) {
    struct udp_pcb *tun_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (nullptr == tun_pcb) {
        errlog(ctx->udp.log, "Failed to create pcb");
        return ERR_MEM;
    }

    err_t ret = udp_bind(tun_pcb, IP_ANY_TYPE, CATCH_ANY_PORT);
    if (ERR_OK != ret) {
        errlog(ctx->udp.log, "Failed to bind pcb: {} ({})", lwip_strerr(ret), ret);
        udp_raw_close(ctx);
        return ret;
    }

    udp_recv(tun_pcb, udp_raw_recv, ctx);
    ctx->udp.tun_pcb = tun_pcb;

    dbglog(ctx->udp.log, "OK");
    return ERR_OK;
}

void udp_raw_close(TcpipCtx *ctx) {
    if (ctx->udp.tun_pcb != nullptr) {
        udp_remove(ctx->udp.tun_pcb);
    }
}

} // namespace ag
