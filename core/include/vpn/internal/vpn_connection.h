#pragma once

#include <bitset>
#include <cstdint>

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
    /// Drop all the DNS queries except those which resolve domains of the requests
    /// made by an application
    CONNF_DROP_NON_APP_DNS_QUERIES,
    /// Connection is routed through the local DNS proxy
    CONNF_ROUTE_TO_DNS_PROXY,
};

enum PacketDirection {
    PD_OUTGOING,
    PD_INCOMING,
};

class ClientListener;
class ServerUpstream;

struct VpnConnection {
    uint64_t client_id = NON_ID;
    uint64_t server_id = NON_ID;
    ClientListener *listener = nullptr;
    ServerUpstream *upstream = nullptr;
    VpnConnectionState state = CONNS_WAITING_ACTION;
    TunnelAddressPair addr;
    int proto = 0;
    std::bitset<width_of<VpnConnectionFlags>()> flags;
    int uid = 0;
    std::string app_name;
    event_loop::AutoTaskId complete_connect_request_task;
    size_t incoming_bytes = 0;
    size_t outgoing_bytes = 0;

    static VpnConnection *make(uint64_t client_id, TunnelAddressPair addr, int proto);

    VpnConnection(const VpnConnection &) = delete;
    VpnConnection(VpnConnection &&) = delete;
    VpnConnection &operator=(const VpnConnection &) = delete;
    VpnConnection &operator=(VpnConnection &&) = delete;

    VpnConnection() = default;
    virtual ~VpnConnection() = default;
    [[nodiscard]] SockAddrTag make_tag() const;
};

struct UdpVpnConnection : public VpnConnection {
    bool check_dns_queries_completed(PacketDirection dir);

    void count_dns_message(PacketDirection type);

private:
    uint32_t m_dns_query_counter = 0;

    [[nodiscard]] bool are_dns_queries_completed() const;
};

struct TcpVpnConnection : public VpnConnection {
    DomainLookuper domain_lookuper;
    uint64_t migrating_client_id = NON_ID;
};

} // namespace ag
