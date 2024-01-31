#pragma once

#include <bitset>
#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "vpn/event_loop.h"
#include "vpn/internal/domain_lookuper.h"
#include "vpn/internal/utils.h"
#include "vpn/utils.h"

namespace ag {

enum VpnConnectionState {
    /// Waiting until an application gives connect result
    CONNS_WAITING_ACTION,
    /// Waiting for the target domain name resolve result
    CONNS_WAITING_RESOLVE,
    /// Waiting for server side response for connection open request
    CONNS_WAITING_RESPONSE,
    /// Waiting for server side response while migrating to another upstream
    CONNS_WAITING_RESPONSE_MIGRATING,
    /// Waiting for connection accept on the client side
    CONNS_WAITING_ACCEPT,
    /// Complete state of a normal data exchange
    CONNS_CONNECTED,
    /// Established connection waiting for migration completion
    CONNS_CONNECTED_MIGRATING,
};

enum VpnConnectionFlags {
    /// Set until the first packet from a client is received
    CONNF_FIRST_PACKET,
    /// Connection is routed to the target host directly unconditionally
    CONNF_FORCIBLY_BYPASSED,
    /// Connection is routed through the VPN endpoint unconditionally
    CONNF_FORCIBLY_REDIRECTED,
    /// Trying to find the destination host name to check if the connection should be excluded
    CONNF_LOOKINGUP_DOMAIN,
    /// Session with the endpoint is already terminated for some reason
    /// (no need to wait for server side close event)
    CONNF_SESSION_CLOSED,
    /// Connection is potentially targets the domain which is excluded
    CONNF_SUSPECT_EXCLUSION,
    /// Connection is established via the fake upstream to check if the host name is in exclusions
    CONNF_FAKE_CONNECTION,
    /// Connection traffic is plain DNS data
    CONNF_PLAIN_DNS_CONNECTION,
    /// Connection is routed through the local DNS proxy
    CONNF_ROUTE_TO_DNS_PROXY,
    /// Connection's statistics is being monitored
    CONNF_MONITOR_STATS,
};

class ClientListener;
class ServerUpstream;

struct VpnConnection {
    uint64_t client_id = NON_ID;
    uint64_t server_id = NON_ID;
    std::weak_ptr<ClientListener> listener;
    std::weak_ptr<ServerUpstream> upstream;
    VpnConnectionState state = CONNS_WAITING_ACTION;
    TunnelAddressPair addr;
    int proto = 0;
    std::bitset<width_of<VpnConnectionFlags>()> flags;
    int uid = 0;
    DomainLookuper domain_lookuper;
    DomainLookuperResult domain_lookuper_result;
    uint64_t migrating_client_id = NON_ID;
    std::string app_name;
    event_loop::AutoTaskId complete_connect_request_task;
    // This pair of counters is used to make it visible in the logs whether
    // any traffic has passed through the connection.
    // The statistics monitor does not replace them because it only operates
    // on the connections that have been routed through an endpoint.
    size_t incoming_bytes = 0;
    size_t outgoing_bytes = 0;
    std::list<std::vector<uint8_t>> buffered_packets;
    event_loop::AutoTaskId send_buffered_task;
    int lookup_attempts_num = 0;

    static VpnConnection *make(uint64_t client_id, TunnelAddressPair addr, int proto);

    VpnConnection(const VpnConnection &) = delete;
    VpnConnection(VpnConnection &&) = delete;
    VpnConnection &operator=(const VpnConnection &) = delete;
    VpnConnection &operator=(VpnConnection &&) = delete;

    VpnConnection() = delete;
    virtual ~VpnConnection() = default;
    [[nodiscard]] SockAddrTag make_tag() const;

protected:
    explicit VpnConnection(TunnelAddressPair);
};

struct UdpVpnConnection : public VpnConnection {
    explicit UdpVpnConnection(TunnelAddressPair);
};

struct TcpVpnConnection : public VpnConnection {
    explicit TcpVpnConnection(TunnelAddressPair);
};

} // namespace ag
