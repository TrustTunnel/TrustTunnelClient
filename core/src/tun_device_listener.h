#pragma once

#include <queue>
#include <unordered_map>
#include <vector>

#include "tcpip/tcpip.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/vpn_client.h"
#include "vpn/vpn.h"

namespace ag {

class TunListener : public ClientListener {
public:
    explicit TunListener(const VpnTunListenerConfig *config);
    ~TunListener() override;

    TunListener(const TunListener &) = delete;
    TunListener &operator=(const TunListener &) = delete;

    TunListener(TunListener &&) noexcept = delete;
    TunListener &operator=(TunListener &&) noexcept = delete;

private:
    struct Connection {
        size_t sent_since_last_event = 0; // sent bytes since last `CLIENT_EVENT_DATA_SENT`
        // number of bytes passed in send, but still not confirmed by sent event
        // signed because for UDP it's reported immeditely, before the result of send is accumulated
        ssize_t scheduled_to_send = 0;
        uint32_t flags = 0;
        int proto = 0; // connection protocol (TCP/UDP)
        // @todo: consider using `DataBuffer`, but it needs some modifications to guarantee
        // that peeked chunks would be the same as pushed ones
        // buffer for data raised with `TCPIP_EVENT_READ`, but wasn't actaully sent to server
        std::queue<std::vector<uint8_t>> unread_data;
        event_loop::AutoTaskId complete_read_task_id;
        event_loop::AutoTaskId close_task_id;
    };

    TcpipCtx *m_tcpip = nullptr;
    std::unordered_map<uint64_t, Connection> m_connections;
    ag::Logger m_log{"TUN_LISTENER"};
    VpnTunListenerConfig m_config;

    InitResult init(VpnClient *vpn, ClientHandler handler) override;
    void deinit() override;
    void complete_connect_request(uint64_t id, ClientConnectResult result) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t n) override;
    TcpFlowCtrlInfo flow_control_info(uint64_t id) override;
    void turn_read(uint64_t id, bool on) override;
    int process_client_packets(VpnPackets packets) override;
    void process_icmp_reply(const IcmpEchoReply &reply) override;

    static void tcpip_handler(void *arg, TcpipEvent id, void *data);
    static void complete_read(void *arg, TaskId task_id);

    int read_out_pending_data(uint64_t id, Connection *conn) const;
};

} // namespace ag
