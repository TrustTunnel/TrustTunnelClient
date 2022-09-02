#pragma once

#include <chrono>
#include <memory>
#include <unordered_map>
#include <vector>

#include "common/logger.h"
#include "net/tcp_socket.h"
#include "net/udp_socket.h"
#include "vpn/internal/server_upstream.h"

namespace ag {

struct SocketContext;

class DirectUpstream : public ServerUpstream {
public:
    explicit DirectUpstream(int id);
    ~DirectUpstream() override;

    DirectUpstream(const DirectUpstream &) = delete;
    DirectUpstream(DirectUpstream &&) = delete;

    DirectUpstream operator=(const DirectUpstream &) = delete;
    DirectUpstream operator=(DirectUpstream &&) = delete;

private:
    struct Connection {
        std::unique_ptr<SocketContext> sock_ctx;
        event_loop::AutoTaskId close_task_id;
    };

    struct TcpConnection : public Connection {
        TcpSocketPtr socket;
    };

    struct UdpConnection : public Connection {
        UdpSocketPtr socket;
        bool read_enabled = false;
        event_loop::AutoTaskId open_task_id;
    };

    struct IcmpRequestInfo;

    std::unordered_map<uint64_t, TcpConnection> m_tcp_connections;
    std::unordered_map<uint64_t, UdpConnection> m_udp_connections;
    std::map<IcmpRequestKey, std::unique_ptr<IcmpRequestInfo>> m_icmp_requests;

    ag::Logger m_log{"DIRECT_UPSTREAM"};

    bool init(VpnClient *vpn, SeverHandler handler) override;
    void deinit() override;
    bool open_session(std::optional<Millis> timeout) override;
    void close_session() override;
    uint64_t open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t length) override;
    size_t available_to_send(uint64_t id) override;
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override;
    VpnError do_health_check() override;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override;
    void on_icmp_request(IcmpEchoRequestEvent &event) override;

    static void tcp_socket_handler(void *arg, TcpSocketEvent what, void *data);
    static void udp_socket_handler(void *arg, UdpSocketEvent what, void *data);
    static void icmp_socket_handler(void *arg, TcpSocketEvent what, void *data);

    uint64_t open_tcp_connection(const TunnelAddressPair *addr);
    uint64_t open_udp_connection(const TunnelAddressPair *addr);
    void close_connection(uint64_t id, bool graceful);
    void cancel_icmp_request(const IcmpRequestKey &key, uint16_t seqno);
};

} // namespace ag
