#pragma once

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <magic_enum/magic_enum.hpp>

#include "common/logger.h"
#include "net/dns_manager.h"
#include "plain_dns_message_handler.h"
#include "vpn/event_loop.h"
#include "vpn/internal/client_listener.h"
#include "vpn/internal/dns_proxy_accessor.h"
#include "vpn/internal/server_upstream.h"
#include "vpn/internal/utils.h"

namespace ag {

/** See `PlainDnsManager` description */
class PlainDnsClientSideAdapter : public ServerUpstream {
public:
    explicit PlainDnsClientSideAdapter(int id);
    ~PlainDnsClientSideAdapter() override;

protected:
    virtual void close_client_side_connection(uint64_t id, VpnError error, bool async) = 0;
    virtual ssize_t send_outgoing_packet(uint64_t id, const uint8_t *data, size_t length) = 0;
    virtual void consume_outgoing_flow(uint64_t id, size_t length) = 0;

private:
    void close_connection(uint64_t id, bool graceful, bool async) final;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) final;
    void consume(uint64_t id, size_t length) final;
    VpnError do_health_check() final;
    [[nodiscard]] VpnConnectionStats get_connection_stats() const final;
    void on_icmp_request(IcmpEchoRequestEvent &event) final;
};

/** See `PlainDnsManager` description */
class PlainDnsServerSideAdapter : public ClientListener {
public:
    PlainDnsServerSideAdapter();
    ~PlainDnsServerSideAdapter() override;

protected:
    virtual void close_upstream_side_connection(uint64_t id, VpnError error, bool async) = 0;
    virtual ssize_t send_incoming_packet(uint64_t id, const uint8_t *data, size_t length) = 0;
    virtual void consume_incoming_flow(uint64_t id, size_t n) = 0;

private:
    void close_connection(uint64_t id, bool graceful, bool async) final;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) final;
    void consume(uint64_t id, size_t n) final;
};

/**
 * This entity is responsible for handling DNS queries. It may:
 *      * route a query to the specific upstream
 *      * pass only the queries conforming to some conditions, dropping the others
 *      * peek into messages to look for exclusion suspects
 *        (see `DomainFilter::add_exclusion_suspect`)
 *
 * It acts as both `ServerUpstream` and `ClientListener` making a chain-like
 * connection processing:
 *      ```
 *      DNS client <-> ClientListener
 *      <-> Tunnel <-> PlainDnsManager as ServerUpstream (PlainDnsClientSideAdapter)
 *      <-> Tunnel <-> PlainDnsManager as ClientListener (PlainDnsServerSideAdapter)
 *      <-> ServerUpstream <-> Network
 *      ```
 *
 * From the other point of view it acts like a multiplexer/demultiplexer of
 * DNS connections. That is, a single transport connection (either UDP or TCP)
 * carrying several concurrent DNS requests may be demultiplexed into several
 * fictive connections in case the domain names follow different routing policies.
 * Those connection would be multiplexed back into a single one in the incoming
 * traffic flow direction.
 */
class PlainDnsManager : public PlainDnsClientSideAdapter, public PlainDnsServerSideAdapter {
public:
    explicit PlainDnsManager(int upstream_id);
    ~PlainDnsManager() override;

    bool init(VpnClient *vpn, ClientHandler upstream_side_handler, ServerHandler client_side_handler,
            const VpnDnsResolver *dns_resolver);

    void deinit() override;

    /**
     * Get the routing policy of the corresponding connection
     * @param us_conn_id the upstream-side connection ID
     * @return Some policy (see `PlainDnsMessageHandler::RoutingPolicy`) if the connection was found
     */
    [[nodiscard]] std::optional<PlainDnsMessageHandler::RoutingPolicy> get_routing_policy(uint64_t us_conn_id) const;

    /**
     * Notify that the connection was initiated by the library request
     * (i.e. it's our own request)
     * @param cs_conn_id the client-side connection ID
     */
    void notify_library_request(uint64_t cs_conn_id);

    /**
     * Check whether the connection was initiated by the library request
     * (i.e. it's our own request)
     * @param us_conn_id the upstream-side connection ID
     */
    [[nodiscard]] bool is_library_request(uint64_t us_conn_id) const;

    /**
     * Notify that which action the application applied to the connection
     * @param cs_conn_id the client-side connection ID
     * @param action the action
     */
    void notify_connect_action(uint64_t cs_conn_id, VpnConnectAction action);

private:
    struct ClientSideConnection;
    struct UdpClientSideConnection;
    struct TcpClientSideConnection;
    struct UpstreamSideConnection;

    event_loop::AutoTaskId m_async_task;
    std::unordered_map<uint64_t, std::unique_ptr<ClientSideConnection>> m_client_side_connections;
    std::unordered_map<uint64_t, std::unique_ptr<UpstreamSideConnection>> m_upstream_side_connections;
    PlainDnsMessageHandler m_message_handler;
    // client-side only
    std::unordered_set<uint64_t> m_opening_connections;
    std::unordered_set<uint64_t> m_closing_client_side_connections;
    std::unordered_set<uint64_t> m_closing_upstream_side_connections;
    std::optional<DnsChangeSubscriptionId> m_dns_change_subscription_id;
    std::unique_ptr<DnsProxyAccessor> m_system_dns_proxy;
    std::vector<sockaddr_storage> m_system_dns_servers;
    Logger m_log{"PLAIN_DNS_MANAGER"};

    bool init(VpnClient *vpn, ServerHandler handler) override;
    ClientListener::InitResult init(VpnClient *vpn, ClientHandler handler) override;
    bool open_session(std::optional<Millis> timeout) override;
    void close_session() override;
    uint64_t open_connection(const TunnelAddressPair *addr, int proto, std::string_view app_name) override;
    void close_client_side_connection(uint64_t id, VpnError error, bool async) override;
    ssize_t send_outgoing_packet(uint64_t conn_id, const uint8_t *data, size_t length) override;
    void consume_outgoing_flow(uint64_t conn_id, size_t length) override;
    size_t available_to_send(uint64_t id) override;
    void update_flow_control(uint64_t id, TcpFlowCtrlInfo info) override;

    void complete_connect_request(uint64_t id, ClientConnectResult result) override;
    void close_upstream_side_connection(uint64_t id, VpnError error, bool async) override;
    ssize_t send_incoming_packet(uint64_t id, const uint8_t *data, size_t length) override;
    void consume_incoming_flow(uint64_t id, size_t n) override;
    TcpFlowCtrlInfo flow_control_info(uint64_t id) override;
    void turn_read(uint64_t id, bool on) override;

    static void on_async_task(void *arg, TaskId);
    static void on_dns_updated(void *arg);
    void complete_read(uint64_t id);
    void close_connection_sync(uint64_t id, ClientSideConnection &conn, bool closed_by_opposite, VpnError error);
    void close_connection_sync(uint64_t id, UpstreamSideConnection &conn, bool closed_by_opposite, VpnError error);
    ssize_t send_outgoing_tcp_packet(uint64_t conn_id, ClientSideConnection &cs_conn, Uint8View data);
    ssize_t send_outgoing_query(uint64_t conn_id, ClientSideConnection &cs_conn,
            PlainDnsMessageHandler::RoutingPolicy routing_policy, Uint8View data);
    [[nodiscard]] bool start_dns_proxy(SystemDnsServers servers);
    [[nodiscard]] std::optional<sockaddr_storage> get_redirect_address(uint64_t cs_conn_id,
            const ClientSideConnection &cs_conn, PlainDnsMessageHandler::RoutingPolicy routing_policy) const;
};

} // namespace ag
