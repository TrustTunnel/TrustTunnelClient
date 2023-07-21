#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <event2/buffer.h>
#include <event2/util.h>

#include "common/logger.h"
#include "net/utils.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

// Default size of maximum transfer unit size for TCP packets
#define DEFAULT_MTU_SIZE 1500u

#define TCPIP_DEFAULT_CONNECTION_TIMEOUT_S 30

// 80 seconds for stale local connections (in macOS it's net.inet.tcp.keepinit == 75000,
// in linux it's maybe around 63 seconds)
#define TCPIP_TCP_TIMEOUT_FOR_LOCAL_HANDSHAKE_S 80
#define TCPIP_TCP_TIMEOUT_FOR_ESTABLISHED_S 604800 // 1 week
#define TCPIP_TCP_TIMEOUT_FOR_DROPPED_S (2 * 60)   // 2 minutes
#define TCPIP_TCP_TIMEOUT_FOR_UNREACHABLE_S 5 // 5 seconds for unreachable connection and its possible SYN retransmits

#define TCPIP_UDP_TIMEOUT_S (5 * 60) // 5 minutes

#define ENABLE_STATISTICS 0

#if ENABLE_STATISTICS
#define TCPIP_STAT_NOTIFY_PERIOD_MS 100u
#define TCPIP_STAT_NOTIFY_BYTE_THRESHOLD 100000ull
#endif

typedef struct TcpipCtx TcpipCtx;

/**
 * Enumeration of action identifiers
 */
typedef enum {
    TCPIP_ACT_REJECT,
    TCPIP_ACT_BYPASS,
    TCPIP_ACT_DROP,
    TCPIP_ACT_REJECT_UNREACHABLE,
} TcpipAction;

/**
 * Callback identifiers
 */
typedef enum {
    TCPIP_EVENT_GENERATE_CONN_ID,    /**< Called before registering a new incoming connection (raised with a pointer to
                                        buffer to store the ID) */
    TCPIP_EVENT_CONNECT_REQUEST,     /**< Called when new incoming connection is appeared,
                                          before pass it into the TCP/IP stack to process (raised with
                                        `TcpipConnectRequestEvent`) */
    TCPIP_EVENT_CONNECTION_ACCEPTED, /**< Called when passed connection is accepted (raised with connection id) */
    TCPIP_EVENT_READ,                /**< Called whenever TCP/IP stack got data to be sent to a remote host (raised with
                                        `TcpipReadEvent`) */
    TCPIP_EVENT_DATA_SENT, /**< Called when we sent some data to local client (raised with `TcpipDataSentEvent`) */
    TCPIP_EVENT_CONNECTION_CLOSED, /**< Called whenever connection is closed (raised with connection id) */
    TCPIP_EVENT_STAT_NOTIFY,       /**< Notifies higher layer of number of sent and received bytes
                                        via connection with pointed identifier (raised with `TcpipStatEvent`) */
    TCPIP_EVENT_TUN_OUTPUT, /**< Called whenever TCP/IP stack got data to be sent to a TUN-like device (raised with
                               `TcpipTunOutputEvent`) */
    TCPIP_EVENT_ICMP_ECHO,  /**< Called whenever ICMP echo request is received (raised with `IcmpEchoRequestEvent`)
                             */
} TcpipEvent;

typedef struct {
    uint64_t id;                /**< generated identifier of request for connection */
    int proto;                  /**< connection protocol */
    const struct sockaddr *src; /**< source address of connection */
    const struct sockaddr *dst; /**< destination address of connection */
} TcpipConnectRequestEvent;

typedef struct {
    uint64_t id;                      /**< generated identifier of request for connection */
    size_t iovlen;                    /**< message vector size */
    const struct evbuffer_iovec *iov; /**< message vector */
    int result; /**< operation result - filled by caller: >= 0 if successful, negative otherwise */
} TcpipReadEvent;

typedef struct {
    uint64_t id;   /**< generated identifier of request for connection */
    size_t length; /**< sent bytes number (if 0, then connection polls for send resuming) */
} TcpipDataSentEvent;

typedef struct {
    uint64_t id;             /**< generated identifier of request for connection */
    uint64_t bytes_sent;     /**< number of bytes sent by application */
    uint64_t bytes_received; /**< number of bytes received by application */
} TcpipStatEvent;

typedef struct {
    int family; /**< ip family */
    struct {
        size_t chunks_num;                   /**< message vector size */
        const struct evbuffer_iovec *chunks; /**< message vector */
    } packet;                                /**< note, that it's a single packet which should be sent in one piece */
} TcpipTunOutputEvent;

/**
 * This structure holds user-provided callback functions, needed for
 * TCP/IP connect procedure
 */
typedef struct {
    void (*handler)(void *arg, TcpipEvent id, void *data); /**< Callbacks handler */
    void *arg;                                             /**< User-provided argument */
} TcpipHandler;

/**
 * This structure holds TCP/IP stack configuration parameters
 */
typedef struct {
    evutil_socket_t tun_fd; /**< File descriptor of TUN device */
    VpnEventLoop *event_loop;
    uint32_t mtu_size;         /**< Maximum transfer unit for TCP protocol (if 0 `DEFAULT_MTU_SIZE` will be used) */
    const char *pcap_filename; /**< Pcap file name */
    TcpipHandler handler;      /**< callbacks structure for TCP connection (@see tcpip_callbacks_t) */
} TcpipParameters;

/**
 * Notifies TCPIP stack of action should be done with new incoming connection
 *
 * @param ctx context of connection returned by `tcpip_open`
 * @param connection_id identifier of request for connection
 * @param action action id (@see tcpip_action_t)
 */
void tcpip_complete_connect_request(TcpipCtx *ctx, uint64_t connection_id, TcpipAction action);

/**
 * Initialize TCP/IP stack
 *
 * @param params TCP/IP stack configuration parameters
 *
 * @return     successfully created context of TCP/IP stack, or
 *             NULL if something gone wrong
 */
TcpipCtx *tcpip_open(const TcpipParameters *params);

/**
 * Close TCP/IP stack
 *
 * @param ctx context of TCP/IP stack returned by `tcpip_open`
 */
void tcpip_close(TcpipCtx *ctx);

/**
 * Returns user-provided argument passed to `tcpip_open`
 *
 * @param ctx context of TCP/IP stack returned by `tcpip_open`
 *
 * @return     User-provided argument passed to `tcpip_open`
 */
void *tcpip_get_arg(const TcpipCtx *ctx);

/**
 * Send data from remote host to local client (caller will be notified with
 * `TCPIP_CBID_SENT_TO_CLIENT` callback, when data is actually sent)
 *
 * @param ctx context of TCP/IP stack returned by `tcpip_open`
 * @param id connection id
 * @param data data to send
 * @param length data length
 * @return number of bytes sent (<0 in case of failure)
 */
int tcpip_send_to_client(TcpipCtx *ctx, uint64_t id, const uint8_t *data, size_t length);

/**
 * Notify TCP/IP stack that some data raised with `TCPIP_EVENT_READ` callback was
 * sent to remote host
 *
 * @param ctx context of TCP/IP stack returned by `tcpip_open`
 * @param id connection id
 * @param n number of sent bytes
 */
void tcpip_sent_to_remote(TcpipCtx *ctx, uint64_t id, size_t n);

/**
 * Passes incoming packet to native TCP/IP stack and waits synchronously while they'll be processed
 *
 * @param ctx context of TCP/IP stack
 * @param packets Array of incoming packet's buffers (one buffer - one packet)
 */
void tcpip_tun_input(TcpipCtx *ctx, VpnPackets *packets);

/**
 * Close a connection with given id
 * @note: `TCPIP_EVENT_CONNECTION_CLOSED` event will be fired synchronously
 *
 * @param ctx context of TCP/IP stack
 * @param id connection id
 * @param graceful if true connection will be closed via FIN, otherwise via reset
 */
void tcpip_close_connection(TcpipCtx *ctx, uint64_t id, bool graceful);

/**
 * Get flow control info for connection
 * @param ctx context of TCP/IP stack
 * @param id connection id
 */
TcpFlowCtrlInfo tcpip_flow_ctrl_info(const TcpipCtx *ctx, uint64_t id);

/**
 * Process ICMP echo reply
 * @param ctx context of TCP/IP stack
 * @param reply the reply
 */
void tcpip_process_icmp_echo_reply(TcpipCtx *ctx, const IcmpEchoReply *reply);

} // namespace ag
