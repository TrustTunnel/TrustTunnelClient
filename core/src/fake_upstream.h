#pragma once

#include <unordered_set>

#include "vpn/internal/server_upstream.h"

namespace ag {

class FakeUpstream : public ServerUpstream {
public:
    explicit FakeUpstream(int id);
    ~FakeUpstream() override;

    FakeUpstream(const FakeUpstream &) = delete;
    FakeUpstream &operator=(const FakeUpstream &) = delete;
    FakeUpstream(FakeUpstream &&) = delete;
    FakeUpstream &operator=(FakeUpstream &&) = delete;

private:
    std::unordered_set<uint64_t> m_opening_connections;
    std::unordered_set<uint64_t> m_closing_connections;
    event_loop::AutoTaskId m_async_task;
    bool m_session_open = false;

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

    static void on_async_task(void *, TaskId);
};

} // namespace ag
