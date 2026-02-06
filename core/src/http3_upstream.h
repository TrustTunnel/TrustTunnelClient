#pragma once

#include <bitset>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "vpn/platform.h" // Because quiche.h doesn't include the required headers
#include <quiche.h>

#include "common/logger.h"
#include "http_icmp_multiplexer.h"
#include "http_udp_multiplexer.h"
#include "net/quic_connector.h"
#include "net/udp_socket.h"
#include "vpn/internal/data_buffer.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/utils.h"

namespace ag {

class Http3Upstream : public ServerUpstream {
public:
    Http3Upstream(int id, const VpnUpstreamProtocolConfig &protocol_config);
    ~Http3Upstream() override;

    Http3Upstream(const Http3Upstream &) = delete;
    Http3Upstream &operator=(const Http3Upstream &) = delete;
    Http3Upstream(Http3Upstream &&) = delete;
    Http3Upstream &operator=(Http3Upstream &&) = delete;

private:
    enum State : int;
    enum Http3ErrorCode : uint64_t;

    struct SendConnectRequestResult {
        std::optional<uint64_t> stream_id; // stream ID if successful
        bool is_retriable = false;         // true if request failed with non-fatal error
    };

    struct TcpConnection {
        enum Flag : int;

        uint64_t stream_id = 0;
        std::bitset<width_of<Flag>()> flags;
        /**
         * `SERVER_EVENT_GET_AVAILABLE_TO_SEND` is an optimization - not a requirement,
         * some of client listener implementations (particularly TUN device listener) may report
         * the greater number of bytes than it can actually send.
         * So this buffer is a workaround for such cases.
         */
        std::unique_ptr<DataBuffer> unread_data;
        std::optional<ServerError> pending_error;
        size_t sent_bytes_to_notify = 0;

        [[nodiscard]] bool has_unread_data() const;
    };

    struct RetriableTcpConnectRequest {
        TunnelAddress dst_addr;
        std::string app_name;
    };

    struct HealthCheckInfo {
        std::optional<uint64_t> stream_id;
        event_loop::AutoTaskId retry_task_id;
        event_loop::AutoTaskId timeout_task_id;
        VpnError error = {};
    };

    State m_state = (State) 0;
    std::chrono::milliseconds m_max_idle_timeout{};
    UdpSocketPtr m_socket;
    DeclPtr<quiche_conn, &quiche_conn_free> m_quic_conn;
    DeclPtr<quiche_h3_conn, &quiche_h3_conn_free> m_h3_conn;
    std::unordered_map<uint64_t, TcpConnection> m_tcp_connections;
    std::unordered_map<uint64_t, uint64_t> m_tcp_conn_by_stream_id;
    std::unordered_map<uint64_t, RetriableTcpConnectRequest> m_retriable_tcp_requests;
    std::unordered_map<uint64_t, bool> m_closing_connections; // value is graceful flag
    event_loop::AutoTaskId m_complete_read_task_id;
    event_loop::AutoTaskId m_notify_sent_task_id;
    event_loop::AutoTaskId m_close_connections_task_id;
    event_loop::AutoTaskId m_post_receive_task_id;
    event_loop::AutoTaskId m_flush_error_task_id;
    HttpUdpMultiplexer m_udp_mux;
    HttpIcmpMultiplexer m_icmp_mux;
    DeclPtr<event, &event_free> m_quic_timer;
    std::string m_credentials;
    std::optional<HealthCheckInfo> m_health_check_info;
    bool m_in_handler = false;
    bool m_closed = false; // @todo: seems like it can be replaced by a separate state
    std::optional<VpnError> m_pending_session_error;
    ag::Logger m_log{"H3_UPSTREAM"};
    DeclPtr<QuicConnector, &quic_connector_destroy> m_quic_connector;
    void *m_ssl_object = nullptr; // A non-owning pointer to SSL used by QuicConnector and Quiche.
    int m_kex_group_nid = NID_undef;

    /**
     * A point in time when our idle timer expires.
     *
     * We maintain our own idle timer because Quiche doesn't check for idle timeout before sending, leading to
     * erroneus idle timer reset when data is sent after a long period of inactivity, such as system sleep.
     *
     * We assume that idle timeout is equal to `m_max_idle_timeout` and reset the timer whenever
     * we send or receive a packet. Since outdated received packets are discarded by `udp_socket`,
     * idle timeout won't be reset errouneusly when receiving a stale packet after waking from sleep.
     */
    std::optional<int64_t> m_idle_timeout_at_ns;
    event_loop::AutoTaskId m_close_on_idle_task_id;

    bool init(VpnClient *vpn, ServerHandler handler) override;
    void deinit() override;
    bool open_session(std::optional<Millis> timeout) override;
    void close_session() override;
    uint64_t open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t length) override;
    size_t available_to_send(uint64_t id) override;
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override;
    void do_health_check() override;
    void cancel_health_check() override;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override;
    void on_icmp_request(IcmpEchoRequestEvent &event) override;
    void handle_sleep() override;
    void handle_wake() override;
    int kex_group_nid() const override;

    static void quic_timer_callback(evutil_socket_t, short, void *arg);
    static void socket_handler(void *arg, UdpSocketEvent what, void *data);
    static void quic_connector_handler(void *arg, QuicConnectorEvent what, void *data);
    static int verify_callback(X509_STORE_CTX *store_ctx, void *arg);

    bool flush_pending_quic_data();
    void on_udp_packet();
    bool initiate_h3_session();
    std::pair<uint64_t, TcpConnection *> get_tcp_conn_by_stream_id(uint64_t id);
    void handle_h3_event(quiche_h3_event *h3_event, uint64_t stream_id);
    void handle_response(uint64_t stream_id, const HttpHeaders *headers);
    void close_stream(uint64_t stream_id, Http3ErrorCode error);
    ssize_t read_out_h3_data(uint64_t stream_id, const uint8_t *buffer, size_t cap);
    void process_pending_data(uint64_t stream_id);
    void close_session_inner(std::optional<VpnError> error = std::nullopt);
    SendConnectRequestResult send_connect_request(const TunnelAddress *dst_addr, std::string_view app_name);
    void close_tcp_connection(uint64_t id, bool graceful);
    void clean_tcp_connection_data(uint64_t id);
    [[nodiscard]] bool is_health_check_stream(uint64_t stream_id) const;
    [[nodiscard]] std::optional<uint64_t> get_stream_id(uint64_t id) const;
    bool push_unread_data(uint64_t conn_id, TcpConnection *conn, U8View data) const;
    int read_out_pending_data(uint64_t conn_id, TcpConnection *conn);
    int raise_read_event(uint64_t conn_id, U8View data);
    void poll_tcp_connections();
    void poll_connections();
    void retry_connect_requests();
    bool continue_connecting();
    static void complete_read(void *arg, TaskId task_id);
    static std::optional<uint64_t> mux_send_connect_request_callback(
            ServerUpstream *upstream, const TunnelAddress *dst_addr, std::string_view app_name);
    static int mux_send_data_callback(ServerUpstream *upstream, uint64_t stream_id, U8View data);
    static void mux_consume_callback(ServerUpstream *, uint64_t, size_t);
};

} // namespace ag
