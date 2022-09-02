#include "tcpip/tcpip.h"

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <fcntl.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <event2/util.h>

#include "common/logger.h"
#include "tcp_connection.h"
#include "tcpip_common.h"

namespace ag {

static ag::Logger g_logger{"TCPIP.API"};

TcpipCtx *tcpip_open(const TcpipParameters *params) {

    if (nullptr == params) {
        errlog(g_logger, "open: nullptr pointer to parameters");
        return nullptr;
    }

    if (params->handler.handler == nullptr) {
        errlog(g_logger, "open: bad callbacks");
        return nullptr;
    }

    if (params->tun_fd >= 0 && evutil_make_socket_nonblocking(params->tun_fd) == -1) {
        errlog(g_logger, "open: failed to make tun fd non-blocking");
        return nullptr;
    }

    TcpipCtx *ctx = tcpip_init_internal(params);
    if (nullptr == ctx) {
        errlog(g_logger, "open: failed");
    } else {
        infolog(g_logger, "open: OK");
    }

    return ctx;
}

void tcpip_close(TcpipCtx *ctx) {
    if (nullptr == ctx) {
        return;
    }

    tcpip_close_internal(ctx);

    infolog(g_logger, "close: OK");
}

void tcpip_reset(TcpipCtx *ctx) {
    if (nullptr == ctx) {
        errlog(g_logger, "reset: nullptr context pointer");
        return;
    }

    tcpip_close_connections(ctx);

    infolog(g_logger, "reset");
}

void tcpip_complete_connect_request(TcpipCtx *ctx, uint64_t id, TcpipAction action) {
    auto *tcp_conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcp.connections, id);
    if (tcp_conn != nullptr) {
        tcp_cm_complete_connect_request(ctx, tcp_conn, action);
    } else {
        auto *udp_conn = (UdpConnDescriptor *) tcpip_get_connection_by_id(&ctx->udp.connections, id);
        if (udp_conn != nullptr) {
            udp_cm_complete_connect_request(ctx, udp_conn, action);
        }
    }
}

int tcpip_send_to_client(TcpipCtx *ctx, uint64_t id, const uint8_t *data, size_t length) {
    auto *tcp_conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcp.connections, id);
    if (tcp_conn != nullptr) {
        return tcp_cm_send_data(tcp_conn, data, length);
    }

    auto *udp_conn = (UdpConnDescriptor *) tcpip_get_connection_by_id(&ctx->udp.connections, id);
    if (udp_conn != nullptr) {
        return udp_cm_send_data(udp_conn, data, length);
    }

    return -1;
}

void tcpip_sent_to_remote(TcpipCtx *ctx, uint64_t id, size_t n) {
    auto *tcp_conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcp.connections, id);
    if (tcp_conn != nullptr) {
        tcp_cm_sent_to_remote(tcp_conn, n);
    }
}

void *tcpip_get_arg(const TcpipCtx *ctx) {
    return ctx->parameters.handler.arg;
}

void tcpip_tun_input(TcpipCtx *ctx, VpnPackets *packets) {
    if (ctx->parameters.tun_fd >= 0) {
        errlog(g_logger,
                "tcpip_tun_input: Packets may be passed to tcpip_tun_input only in non-fd mode"
                " (tun_fd == -1, tun_output callback provided)");
        return;
    }

    tcpip_process_input_packets(ctx, packets);
}

void tcpip_close_connection(TcpipCtx *ctx, uint64_t id, bool graceful) {
    auto *tcp_conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcp.connections, id);
    if (tcp_conn != nullptr) {
        tcp_cm_close_descriptor(ctx, id, graceful);
    } else {
        auto *udp_conn = (UdpConnDescriptor *) tcpip_get_connection_by_id(&ctx->udp.connections, id);
        if (udp_conn != nullptr) {
            udp_cm_close_descriptor(ctx, id);
        }
    }
}

TcpFlowCtrlInfo tcpip_flow_ctrl_info(const TcpipCtx *ctx, uint64_t id) {
    const TcpConnDescriptor *tcp_conn = (TcpConnDescriptor *) tcpip_get_connection_by_id(&ctx->tcp.connections, id);
    if (tcp_conn != nullptr) {
        return tcp_cm_flow_ctrl_info(tcp_conn);
    }

    const UdpConnDescriptor *udp_conn = (UdpConnDescriptor *) tcpip_get_connection_by_id(&ctx->udp.connections, id);
    if (udp_conn != nullptr) {
        return udp_cm_flow_ctrl_info(udp_conn);
    }

    return {};
}

void tcpip_process_icmp_echo_reply(TcpipCtx *ctx, const IcmpEchoReply *reply) {
    icmp_rm_process_reply(ctx, reply);
}

} // namespace ag
