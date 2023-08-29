#pragma once

#include <bitset>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/logger.h"
#include "http_icmp_multiplexer.h"
#include "http_udp_multiplexer.h"
#include "multiplexable_upstream.h"
#include "net/http_session.h"
#include "net/tcp_socket.h"
#include "vpn/internal/data_buffer.h"
#include "vpn/internal/id_generator.h"
#include "vpn/utils.h"

namespace ag {

class Http2Upstream : public MultiplexableUpstream {
public:
    static constexpr int DEFAULT_PORT = 443;

    Http2Upstream(const VpnUpstreamProtocolConfig &protocol_config, int id, VpnClient *vpn, ServerHandler handler);
    ~Http2Upstream() override;

    Http2Upstream(const Http2Upstream &) = delete;
    Http2Upstream &operator=(const Http2Upstream &) = delete;

    Http2Upstream(Http2Upstream &&) = delete;
    Http2Upstream &operator=(Http2Upstream &&) = delete;

private:
    struct TcpConnection {
        enum Flag : int;

        uint32_t stream_id = 0;
        std::bitset<width_of<Flag>()> flags;
        std::unique_ptr<DataBuffer> unread_data;
        event_loop::AutoTaskId complete_read_task_id;
        std::optional<ServerError> pending_error; // to store bad HTTP response status until stream processed event
        event_loop::AutoTaskId close_task_id;
    };

    struct HealthCheckInfo {
        uint32_t stream_id = 0;
        VpnError error = {};
    };

    DeclPtr<HttpSession, &http_session_close> m_session;
    TcpSocketPtr m_socket;
    size_t m_in_handler = 0;
    bool m_closed = false;
    bool m_closing = false;
    std::optional<VpnError> m_pending_session_error;
    std::unordered_map<uint64_t, TcpConnection> m_tcp_connections;
    std::unordered_map<uint32_t, uint64_t> m_conn_id_by_stream_id;
    HttpUdpMultiplexer m_udp_mux;
    HttpIcmpMultiplexer m_icmp_mux;
    std::string m_credentials;
    std::optional<HealthCheckInfo> m_health_check_info;
    // For client initiated streams ids are odd numbers
    // https://tools.ietf.org/html/rfc7540#section-5.1.1
    IdGenerator m_stream_id_generator{2};

    ag::Logger m_log{"H2_UPSTREAM"};

    bool open_session(std::optional<Millis> timeout) override;
    void close_session() override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t length) override;
    size_t available_to_send(uint64_t id) override;
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override;
    VpnError do_health_check() override;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override;
    [[nodiscard]] size_t connections_num() const override;
    bool open_connection(uint64_t id, const TunnelAddressPair *addr, int proto, std::string_view app_name) override;
    void on_icmp_request(IcmpEchoRequestEvent &event) override;

    static void http_handler(void *arg, HttpEventId what, void *data);
    static void net_handler(void *arg, TcpSocketEvent what, void *data);
    static void complete_read(void *arg, TaskId task_id);
    static int verify_callback(X509_STORE_CTX *store_ctx, void *arg);

    int establish_http_session();

    /**
     * @param dst_addr destination address
     * @param app_name the name of the appllication that initiated this connection (may be empty)
     * @return a new stream id, or nullopt if unsuccessful
     */
    std::optional<uint32_t> send_connect_request(const TunnelAddress *dst_addr, std::string_view app_name);

    void close_session_inner(std::optional<VpnError> error);
    void clean_tcp_connection_data(uint64_t id);
    int handle_read(uint64_t id, const uint8_t *data, size_t length);
    void handle_response(const HttpHeadersEvent *http_event);
    void close_tcp_connection(uint64_t id, bool graceful);
    [[nodiscard]] std::optional<uint32_t> get_stream_id(uint64_t id) const;
    std::pair<uint64_t, TcpConnection *> get_conn_by_stream_id(uint32_t id);
    int read_out_pending_data(uint64_t id, TcpConnection *conn);
    static std::optional<uint64_t> send_connect_request_callback(
            ServerUpstream *upstream, const TunnelAddress *dst_addr, std::string_view app_name);
    static int send_data_callback(ServerUpstream *upstream, uint64_t stream_id, U8View data);
    static void consume_callback(ServerUpstream *upstream, uint64_t stream_id, size_t size);
};

} // namespace ag
