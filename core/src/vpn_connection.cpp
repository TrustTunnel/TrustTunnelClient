#include "vpn/internal/vpn_connection.h"
#include "net/dns_utils.h"

namespace ag {

VpnConnection::VpnConnection(TunnelAddressPair addr)
        : addr(std::move(addr)) {
}

UdpVpnConnection::UdpVpnConnection(TunnelAddressPair addr)
        : VpnConnection(std::move(addr)) {
}

TcpVpnConnection::TcpVpnConnection(TunnelAddressPair addr)
        : VpnConnection(std::move(addr)) {
}

VpnConnection *VpnConnection::make(uint64_t client_id, TunnelAddressPair addr, int proto) {
    VpnConnection *self;                                    // NOLINT(cppcoreguidelines-init-variables)
    switch (ipproto_to_transport_protocol(proto).value()) { // NOLINT(bugprone-unchecked-optional-access)
    case utils::TP_TCP:
        self = new TcpVpnConnection{addr};
        break;
    case utils::TP_UDP:
        self = new UdpVpnConnection{addr};
        break;
    }

    self->client_id = client_id;
    self->addr = std::move(addr);
    self->proto = proto;

    const SocketAddress *dst = std::get_if<SocketAddress>(&self->addr.dst);
    self->flags.set(
            CONNF_PLAIN_DNS_CONNECTION, dst != nullptr && dns_utils::PLAIN_DNS_PORT_NUMBER == dst->port());

    return self;
}

SockAddrTag VpnConnection::make_tag() const {
    const SocketAddress *dst = std::get_if<SocketAddress>(&this->addr.dst);
    return {(dst != nullptr) ? *dst : SocketAddress{}, this->app_name};
}

} // namespace ag
