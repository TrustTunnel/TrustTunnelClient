#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "common/logger.h"
#include "multiplexable_upstream.h"

namespace ag {

struct UpstreamInfo;

class UpstreamMultiplexer : public ServerUpstream {
public:
    // Maximum number of upstreams
    static constexpr size_t DEFAULT_UPSTREAMS_NUM = 8;
    // Number of connection exceeding which a new upstream will be opened
    static constexpr size_t NEW_UPSTREAM_CONNECTIONS_NUM_THRESHOLD = 5;

    using MakeUpstream = std::unique_ptr<MultiplexableUpstream> (*)(
            const VpnUpstreamProtocolConfig &protocol_config, int id, VpnClient *vpn, ServerHandler handler);

    UpstreamMultiplexer(
            int id, const VpnUpstreamProtocolConfig &protocol_config, size_t upstreams_num, MakeUpstream make_upstream);
    ~UpstreamMultiplexer() override;

    UpstreamMultiplexer() = delete;
    UpstreamMultiplexer(const UpstreamMultiplexer &) = delete;
    UpstreamMultiplexer &operator=(const UpstreamMultiplexer &) = delete;
    UpstreamMultiplexer(UpstreamMultiplexer &&) = delete;
    UpstreamMultiplexer &operator=(UpstreamMultiplexer &&) = delete;

private:
    struct Connection {
        int upstream_id;
    };

    struct PendingConnection : public Connection {
        TunnelAddressPair addr;
        int proto;
        std::string app_name;
    };

    std::unordered_map<uint64_t, Connection> m_connections;
    std::unordered_map<int, std::unique_ptr<UpstreamInfo>> m_upstreams_pool;
    size_t m_max_upstreams_num = DEFAULT_UPSTREAMS_NUM;
    std::unordered_map<uint64_t, PendingConnection> m_pending_connections;
    std::unordered_map<int, std::unique_ptr<UpstreamInfo>> m_closed_upstreams; // Upstreams waiting to be deleted
    std::optional<int> m_health_check_upstream_id; // id of an upstream which performs health check
    MakeUpstream m_make_upstream;
    std::optional<VpnError> m_pending_error;
    DeclPtr<event, &event_free> m_timeout_timer;

    ag::Logger m_log{"UPSTREAM_MUX"};

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
    VpnError do_health_check() override;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const override;
    void on_icmp_request(IcmpEchoRequestEvent &event) override;

    static void child_upstream_handler(void *arg, ServerEvent what, void *data);

    [[nodiscard]] MultiplexableUpstream *get_upstream_by_conn(uint64_t id) const;
    [[nodiscard]] std::optional<int> select_existing_upstream(
            std::optional<int> ignored_upstream, bool allow_underflow) const;
    int select_upstream_for_connection();
    bool open_new_upstream(int id, std::optional<Millis> timeout);
    bool open_connection(
            int upstream_id, uint64_t conn_id, const TunnelAddressPair *addr, int proto, std::string_view app_name);
    void proceed_pending_connection(int upstream_id, uint64_t conn_id, const PendingConnection *conn);
    [[nodiscard]] size_t connections_num_by_upstream(int upstream_id) const;
    void mark_closed_upstream(int upstream_id, event_loop::AutoTaskId task_id);
    void finalize_closed_upstream(int upstream_id, bool async);
    void handle_sleep() override;
    void handle_wake() override;

    void timer_update();
    void timer_stop();
    static void timer_callback(evutil_socket_t, short, void *);
};

} // namespace ag
