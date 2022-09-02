#include <cstdlib>

#include "vpn/platform.h"

#include "common/logger.h"
#include "icmp_request_manager.h"
#include "tcpip_common.h"
#include "tcpip_util.h"
#include "vpn/utils.h"

#define log_manager(ctx_, lvl_, fmt_, ...) lvl_##log((ctx_)->icmp.log, fmt_, ##__VA_ARGS__)
#define log_req(ctx_, r_, lvl_, fmt_, ...)                                                                             \
    lvl_##log((ctx_)->icmp.log, "[{}/{}] " fmt_, (r_)->key.id, (r_)->key.seqno, ##__VA_ARGS__)

namespace ag {

static bool register_new_request(TcpipCtx *ctx, IcmpRequestDescriptor *request) {
    int ret = 0;
    khiter_t req_it = kh_put(icmp_requests, ctx->icmp.requests, &request->key, &ret);
    if (ret < 0) {
        log_req(ctx, request, warn, "Failed to put new entry in table");
        return false;
    }
    kh_value(ctx->icmp.requests, req_it) = request;
    return true;
}

bool icmp_rm_init(TcpipCtx *ctx) {
    ctx->icmp.requests = kh_init(icmp_requests);
    return true;
}

void icmp_rm_close(TcpipCtx *ctx) {
    icmp_rm_clean_up(ctx);

    kh_destroy(icmp_requests, ctx->icmp.requests);
    ctx->icmp.requests = NULL;

    log_manager(ctx, dbg, "Closed");
}

void icmp_rm_clean_up(TcpipCtx *ctx) {
    for (khiter_t i = kh_begin(ctx->icmp.requests); i != kh_end(ctx->icmp.requests); ++i) {
        while (kh_exist(ctx->icmp.requests, i)) {
            icmp_rm_close_descriptor(ctx, kh_val(ctx->icmp.requests, i));
        }
    }
}

IcmpRequestDescriptor *icmp_rm_create_descriptor(TcpipCtx *ctx, const ip_addr_t *src, const ip_addr_t *dst, u16_t id,
        u16_t seqno, u16_t ttl, struct pbuf *buffer) {
    if (NULL != icmp_rm_find_descriptor(ctx, id, seqno)) {
        return NULL;
    }

    IcmpRequestDescriptor *request = icmp_request_create(src, dst, id, seqno, u8_t(ttl), buffer);
    if (request != NULL && ctx->icmp.log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
        char dst_ip_str[INET6_ADDRSTRLEN];
        ipaddr_ntoa_r_pretty(dst, dst_ip_str, sizeof(dst_ip_str));
        log_req(ctx, request, trace, "Destination={} ttl={}", dst_ip_str, ttl);
    }

    if (!register_new_request(ctx, request)) {
        log_req(ctx, request, dbg, "Failed to register request");
        icmp_rm_close_descriptor(ctx, request);
        request = NULL;
    }

    return request;
}

IcmpRequestDescriptor *icmp_rm_find_descriptor(const TcpipCtx *ctx, u16_t id, u16_t seqno) {
    IcmpRequestKey key = icmp_request_key_create(id, seqno);
    khiter_t req_it = kh_get(icmp_requests, ctx->icmp.requests, &key);
    if (req_it == kh_end(ctx->icmp.requests)) {
        return NULL;
    }

    return kh_value(ctx->icmp.requests, req_it);
}

void icmp_rm_close_descriptor(TcpipCtx *ctx, IcmpRequestDescriptor *request) {
    khiter_t req_it = kh_get(icmp_requests, ctx->icmp.requests, &request->key);
    if (req_it != kh_end(ctx->icmp.requests)) {
        kh_del(icmp_requests, ctx->icmp.requests, req_it);
    }
    icmp_request_destroy(request);
}

int icmp_rm_start_request(TcpipCtx *ctx, IcmpRequestDescriptor *request) {
    log_req(ctx, request, trace, "...");

    const TcpipHandler *callbacks = &ctx->parameters.handler;
    IcmpEchoRequestEvent event = {{
            ip_addr_to_sockaddr(&request->dst, 0),
            request->key.id,
            request->key.seqno,
            request->ttl,
            request->buffer->len,
    }};
    callbacks->handler(callbacks->arg, TCPIP_EVENT_ICMP_ECHO, &event);
    return event.result;
}

void icmp_rm_process_reply(TcpipCtx *ctx, const IcmpEchoReply *reply) {
    IcmpRequestDescriptor *request = icmp_rm_find_descriptor(ctx, reply->id, reply->seqno);
    if (request == NULL) {
        log_manager(ctx, dbg, "Request is not found");
        return;
    }

    log_req(ctx, request, trace, "...");

    if (reply->type == ICMP_MT_DROP) {
        icmp_rm_close_descriptor(ctx, request);
        return;
    }

    ip_addr_t src_ip;
    uint16_t dummy; // NOLINT(cppcoreguidelines-init-variables)
    sockaddr_to_ip_addr(&reply->peer, sockaddr_get_size((struct sockaddr *) &reply->peer), &src_ip, &dummy);

    ip_addr_copy(request->reply_src, src_ip);
    request->reply_type = reply->type;
    request->reply_code = reply->code;

    pbuf *buf = std::exchange(request->buffer, nullptr);
    const err_t r = netif_input(buf, ctx->netif);
    if (r != ERR_OK) {
        pbuf_free(buf);
        log_manager(ctx, dbg, "netif_input failed: {} ({})", lwip_strerr(r), r);
    }
}

} // namespace ag
