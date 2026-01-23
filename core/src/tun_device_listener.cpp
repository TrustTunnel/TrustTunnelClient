#include "tun_device_listener.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <numeric>
#include <span>
#include <utility>

#include <vpn/event_loop.h>
#include <vpn/vpn.h>

#define log_conn(lstnr_, id_, lvl_, fmt_, ...)                                                                         \
    lvl_##log((lstnr_)->m_log, "[L:{}] " fmt_, (uint64_t) (id_), ##__VA_ARGS__)

namespace ag {

enum ConnectionFlags {
    CF_READ_ENABLED = 1 << 0, // `CLIENT_EVENT_READ` can be raised
    CF_CLOSING = 1 << 1,      // a connection was closed on server-side
};

struct CompleteCtx {
    TunListener *listener;
    uint64_t id;
};

struct CloseAsyncCtx {
    TunListener *listener;
    uint64_t id;
    bool graceful;
};

static constexpr TcpipAction CONNECT_RESULT_TO_TCPIP_ACTION[magic_enum::enum_count<TcpipAction>()] = {
        /** CCR_PASS */ TCPIP_ACT_BYPASS,
        /** CCR_DROP */ TCPIP_ACT_DROP,
        /** CCR_REJECT */ TCPIP_ACT_REJECT,
        /** CCR_UNREACH */ TCPIP_ACT_REJECT_UNREACHABLE,
};

static VpnTunListenerConfig clone_config(const VpnTunListenerConfig *config) {
    return VpnTunListenerConfig{
            .fd = config->fd,
            .tunnel = config->tunnel,
            .mtu_size = config->mtu_size,
            .pcap_filename = safe_strdup(config->pcap_filename),
    };
}

static void destroy_cloned_config(VpnTunListenerConfig *config) {
    free((void *) config->pcap_filename); // NOLINT(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    *config = {};
}

TunListener::TunListener(const VpnTunListenerConfig *config)
        : m_config{clone_config(config)} {
    if (m_config.mtu_size == 0) {
        m_config.mtu_size = DEFAULT_MTU_SIZE;
    }
}

TunListener::~TunListener() {
    destroy_cloned_config(&m_config);
#ifdef _WIN32
    for (auto &p : m_recv_packets_queue) {
        p.destructor(p.destructor_arg, p.data);
    }
#endif
}

ClientListener::InitResult TunListener::init(VpnClient *vpn, ClientHandler handler) {
    if (auto result = this->ClientListener::init(vpn, handler); result != InitResult::SUCCESS) {
        return result;
    }

    if (m_config.fd != -1 && m_config.tunnel != nullptr) {
        errlog(m_log, "Passed both fd and tunnel to TUN listener");
        return InitResult::FAILURE;
    }

    TcpipParameters tcpip_params = {
            .tun_fd = m_config.fd,
            .event_loop = this->vpn->parameters.ev_loop,
            .mtu_size = m_config.mtu_size,
            .pcap_filename = m_config.pcap_filename,
            .handler = {tcpip_handler, this},
    };

    m_tcpip = tcpip_open(&tcpip_params);
    if (m_tcpip == nullptr) {
        errlog(m_log, "Failed to initialize TCP/IP stack");
        deinit();
        return InitResult::FAILURE;
    }

#ifdef _WIN32
    if (m_config.tunnel) {
        m_config.tunnel->start_recv_packets(recv_packets_handler, this);
    }
#endif // _WIN32

    return InitResult::SUCCESS;
}

void TunListener::deinit() {
#ifdef _WIN32
    if (m_config.tunnel) {
        m_config.tunnel->stop_recv_packets();
        std::unique_lock l(m_recv_packets_mutex);
        if (m_recv_packets_task.has_value()) {
            tracelog(m_log, "Reset remaining recv_packets task");
            m_recv_packets_task.reset();
        }
    }
#endif // _WIN32
    tcpip_close(m_tcpip);
    m_tcpip = nullptr;
}

int TunListener::read_out_pending_data(uint64_t id, Connection *conn) const {
    std::queue<std::vector<uint8_t>> &pending = conn->unread_data;

    while ((conn->flags & CF_READ_ENABLED) && !pending.empty()) {
        std::vector<uint8_t> &chunk = pending.front();
        ClientRead event = {id, chunk.data(), chunk.size(), 0};
        this->handler.func(this->handler.arg, CLIENT_EVENT_READ, &event);
        if (event.result < 0) {
            return event.result;
        }
        if (conn->proto == IPPROTO_UDP && ssize_t(chunk.size()) != event.result) {
            log_conn(this, id, dbg, "UDP packet wasn't sent or sent partially: length={}, result={}", chunk.size(),
                    event.result);
            chunk.clear();
        } else {
            chunk.erase(chunk.begin(), chunk.begin() + event.result);
        }
        if (chunk.empty()) {
            pending.pop();
        }
    }

    return 0;
}

void TunListener::tcpip_handler(void *arg, TcpipEvent what, void *data) {
    auto *listener = (TunListener *) arg;

    switch (what) {
    case TCPIP_EVENT_GENERATE_CONN_ID: {
        size_t id = listener->vpn->listener_conn_id_generator.get();
        *(uint64_t *) data = id;
        break;
    }
    case TCPIP_EVENT_CONNECT_REQUEST: {
        auto *tcp_event = (TcpipConnectRequestEvent *) data;

        auto [i, ok] = listener->m_connections.emplace(tcp_event->id, Connection{});
        assert(ok);
        i->second.proto = tcp_event->proto;

        TunnelAddress dst(*(SocketAddress *) tcp_event->dst);

        ClientConnectRequest event = {tcp_event->id, tcp_event->proto, tcp_event->src, &dst};
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_CONNECT_REQUEST, &event);
        break;
    }
    case TCPIP_EVENT_CONNECTION_ACCEPTED: {
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_CONNECTION_ACCEPTED, data);
        break;
    }
    case TCPIP_EVENT_READ: {
        auto *tcp_event = (TcpipReadEvent *) data;

        auto i = listener->m_connections.find(tcp_event->id);
        if (i == listener->m_connections.end()) {
            tcp_event->result = -1;
            break;
        }

        Connection *conn = &i->second;
        tcp_event->result = listener->read_out_pending_data(tcp_event->id, conn);
        if (tcp_event->result < 0) {
            break;
        }

        std::queue<std::vector<uint8_t>> &pending = conn->unread_data;
        std::span<evbuffer_iovec> iov = {(evbuffer_iovec *) tcp_event->iov, tcp_event->iovlen};
        int conn_proto = conn->proto; // conn may be freed in the callback
        if ((conn->flags & CF_READ_ENABLED) && pending.empty()) {
            ClientRead event = {tcp_event->id, nullptr, 0, 0};
            while (!iov.empty()) {
                evbuffer_iovec *v = &iov.front();
                do {
                    event.data = (uint8_t *) v->iov_base;
                    event.length = v->iov_len;
                    listener->handler.func(listener->handler.arg, CLIENT_EVENT_READ, &event);
                    if (conn_proto == IPPROTO_UDP && event.result >= 0 && event.length != size_t(event.result)) {
                        goto loop_exit;
                    }
                    if (event.result >= 0) {
                        tcp_event->result += event.result;
                        v->iov_base = (uint8_t *) v->iov_base + event.result;
                        v->iov_len -= event.result;
                        if (!(conn->flags & CF_READ_ENABLED)) {
                            goto loop_exit;
                        }
                    } else {
                        tcp_event->result = event.result;
                        goto loop_exit;
                    }
                } while (v->iov_len > 0);
                iov = iov.subspan(1);
            }
        }

    loop_exit:
        if (iov.empty()) {
            // do nothing
        } else if (conn_proto == IPPROTO_UDP) {
            size_t total_length = std::accumulate(
                    tcp_event->iov, tcp_event->iov + tcp_event->iovlen, 0, [](size_t acc, evbuffer_iovec v) {
                        return acc + v.iov_len;
                    });
            log_conn(listener, tcp_event->id, dbg, "UDP packet sent partially, dropping unsent: total={}, unsent={}",
                    total_length, std::accumulate(iov.begin(), iov.end(), 0, [](size_t acc, evbuffer_iovec v) {
                        return acc + v.iov_len;
                    }));
            tcp_event->result = static_cast<int>(total_length);
        } else if (tcp_event->result >= 0) {
            // not completely sent
            std::for_each(iov.begin(), iov.end(), [&pending](const evbuffer_iovec &vec) {
                pending.emplace((uint8_t *) vec.iov_base, (uint8_t *) vec.iov_base + vec.iov_len);
            });
        }

        break;
    }
    case TCPIP_EVENT_DATA_SENT: {
        auto *tcp_event = (TcpipDataSentEvent *) data;

        auto i = listener->m_connections.find(tcp_event->id);
        if (i == listener->m_connections.end()) {
            break;
        }

        Connection *conn = &i->second;
        conn->sent_since_last_event += tcp_event->length;
        conn->scheduled_to_send -= static_cast<ssize_t>(tcp_event->length);

        ClientDataSentEvent event = {tcp_event->id, conn->sent_since_last_event};
        conn->sent_since_last_event = 0;
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_DATA_SENT, &event);

        if ((conn->flags & CF_CLOSING) && conn->scheduled_to_send == 0) {
            conn->close_task_id = event_loop::submit(listener->vpn->parameters.ev_loop,
                    {new CloseAsyncCtx{listener, tcp_event->id, true},
                            [](void *arg, TaskId) {
                                auto *ctx = (CloseAsyncCtx *) arg;
                                tcpip_close_connection(ctx->listener->m_tcpip, ctx->id, ctx->graceful);
                            },
                            [](void *arg) {
                                delete (CloseAsyncCtx *) arg;
                            }});
        }

        break;
    }
    case TCPIP_EVENT_CONNECTION_CLOSED: {
        uint64_t id = *(uint64_t *) data;
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_CONNECTION_CLOSED, &id);

        if (auto i = listener->m_connections.find(id); i != listener->m_connections.end()) {
            const Connection *conn = &i->second;
            log_conn(listener, id, dbg, "Remaining unsent={} unread={}", conn->scheduled_to_send,
                    conn->unread_data.size());
            listener->m_connections.erase(i);

            dbglog(listener->m_log, "Remaining connections: {}", listener->m_connections.size());
        }
        break;
    }
    case TCPIP_EVENT_STAT_NOTIFY: {
        // do nothing
        break;
    }
    case TCPIP_EVENT_TUN_OUTPUT: {
        const auto *tcpip_event = (TcpipTunOutputEvent *) data;

#ifdef _WIN32
        if (listener->m_config.tunnel) {
            listener->m_config.tunnel->send_packet({tcpip_event->packet.chunks, tcpip_event->packet.chunks_num});
            break;
        }
#endif

        VpnClientOutputEvent vpn_event = {
                .family = tcpip_event->family,
                .packet =
                        {
                                .chunks_num = tcpip_event->packet.chunks_num,
                                .chunks = (iovec *) tcpip_event->packet.chunks,
                        },
        };
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_OUTPUT, &vpn_event);
        break;
    }
    case TCPIP_EVENT_ICMP_ECHO:
        listener->handler.func(listener->handler.arg, CLIENT_EVENT_ICMP_ECHO_REQUEST, data);
        break;
    }
}

void TunListener::complete_connect_request(uint64_t id, ClientConnectResult result) {
    tcpip_complete_connect_request(m_tcpip, id, CONNECT_RESULT_TO_TCPIP_ACTION[result]);
}

void TunListener::complete_read(void *arg, TaskId) {
    auto *ctx = (CompleteCtx *) arg;
    TunListener *listener = ctx->listener;
    auto i = listener->m_connections.find(ctx->id);
    if (i != listener->m_connections.end()) {
        Connection *conn = &i->second;
        conn->complete_read_task_id.release();
        if (0 != listener->read_out_pending_data(ctx->id, conn)) {
            listener->close_connection(ctx->id, false, false);
        }
    }
}

void TunListener::close_connection(uint64_t id, bool graceful, bool async) {
    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        return;
    }

    Connection *conn = &i->second;
    if (graceful && conn->scheduled_to_send > 0) {
        // defer closing until all the pending data is sent to client
        conn->flags |= CF_CLOSING;
    } else {
        if (conn->scheduled_to_send > 0 || !conn->unread_data.empty()) {
            log_conn(this, id, dbg, "Remaining unsent={} unread={}", conn->scheduled_to_send, conn->unread_data.size());
        }

        if (!async) {
            tcpip_close_connection(m_tcpip, id, graceful);
        } else {
            conn->close_task_id = event_loop::submit(this->vpn->parameters.ev_loop,
                    {new CloseAsyncCtx{this, id, true},
                            [](void *arg, TaskId) {
                                auto *ctx = (CloseAsyncCtx *) arg;
                                tcpip_close_connection(ctx->listener->m_tcpip, ctx->id, ctx->graceful);
                            },
                            [](void *arg) {
                                delete (CloseAsyncCtx *) arg;
                            }});
        }
    }
}

ssize_t TunListener::send(uint64_t id, const uint8_t *data, size_t length) {
    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        return -1;
    }

    Connection *conn = &i->second;
    if (conn->flags & CF_CLOSING) {
        return 0;
    }

    int r = tcpip_send_to_client(m_tcpip, id, data, length);
    if (r >= 0) {
        conn->scheduled_to_send += r;
    }

    return r;
}

void TunListener::consume(uint64_t id, size_t n) {
    if (n > 0) {
        log_conn(this, id, trace, "{}", n);
    }

    tcpip_sent_to_remote(m_tcpip, id, n);
}

TcpFlowCtrlInfo TunListener::flow_control_info(uint64_t id) {
    return tcpip_flow_ctrl_info(m_tcpip, id);
}

void TunListener::turn_read(uint64_t id, bool on) {
    auto i = m_connections.find(id);
    if (i == m_connections.end()) {
        return;
    }

    Connection *conn = &i->second;
    if (!!(conn->flags & CF_READ_ENABLED) == on) {
        // nothing to do
        return;
    }

    log_conn(this, id, trace, "{}", on ? "on" : "off");
    if (on) {
        conn->flags |= CF_READ_ENABLED;
    } else {
        conn->flags &= ~CF_READ_ENABLED;
    }

    if (on && !conn->complete_read_task_id.has_value() && !conn->unread_data.empty()) {
        // we have some unread data on the connection - complete it
        conn->complete_read_task_id = event_loop::submit(
                this->vpn->parameters.ev_loop, {new CompleteCtx{this, id}, complete_read, [](void *arg) {
                                                    delete (CompleteCtx *) arg;
                                                }});
    }
}

int TunListener::process_client_packets(VpnPackets packets) {
    tcpip_tun_input(m_tcpip, &packets);
    return 0;
}

void TunListener::process_icmp_reply(const IcmpEchoReply &reply) {
    tcpip_process_icmp_echo_reply(m_tcpip, &reply);
}

#ifdef _WIN32
void TunListener::recv_packets_task(void *arg, ag::TaskId) {
    auto *listener = (TunListener *) arg;

    while (auto packet = listener->m_config.tunnel->recv_packet()) {
        listener->m_recv_packets_queue.emplace_back(std::move(*packet));
    }

    static constexpr int BATCH_SIZE = 64;
    int count = (int) std::min((size_t) listener->m_recv_packets_queue.size(), (size_t) BATCH_SIZE);
    listener->vpn->process_client_packets({.data = listener->m_recv_packets_queue.data(), .size = (unsigned) count});
    listener->m_recv_packets_queue.erase(
            listener->m_recv_packets_queue.begin(), listener->m_recv_packets_queue.begin() + count);

    {
        std::scoped_lock l(listener->m_recv_packets_mutex);
        bool signaled = std::exchange(listener->m_recv_packets_signaled, false);
        listener->m_recv_packets_task.release();
        if (signaled || !listener->m_recv_packets_queue.empty()) {
            listener->m_recv_packets_task = event_loop::submit(listener->vpn->parameters.ev_loop,
                    VpnEventLoopTask{
                            .arg = listener,
                            .action = recv_packets_task,
                            .finalize = nullptr,
                    });
        }
    }
}

void TunListener::recv_packets_handler(void *arg) {
    auto *listener = (TunListener *) arg;
    std::scoped_lock l(listener->m_recv_packets_mutex);
    listener->m_recv_packets_signaled = true;
    if (!listener->m_recv_packets_task.has_value()) {
        listener->m_recv_packets_task = event_loop::submit(listener->vpn->parameters.ev_loop,
                VpnEventLoopTask{
                        .arg = listener,
                        .action = recv_packets_task,
                        .finalize = nullptr,
                });
    }
}
#endif // _WIN32

} // namespace ag
