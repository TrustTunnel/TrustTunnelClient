#pragma once

#include "vpn/internal/endpoint_connector.h"

namespace ag {

class SingleUpstreamConnector : public EndpointConnector {
public:
    SingleUpstreamConnector(const EndpointConnectorParameters &parameters, std::unique_ptr<ServerUpstream> upstream);
    ~SingleUpstreamConnector() override = default;

    SingleUpstreamConnector(const SingleUpstreamConnector &) = delete;
    SingleUpstreamConnector &operator=(const SingleUpstreamConnector &) = delete;
    SingleUpstreamConnector(SingleUpstreamConnector &&) = delete;
    SingleUpstreamConnector &operator=(SingleUpstreamConnector &&) = delete;

private:
    struct Impl;
    friend struct Impl;
    static void delete_impl(Impl *);
    DeclPtr<Impl, &delete_impl> m_impl;

    VpnError connect(std::optional<Millis> timeout) override;
    void disconnect() override;
    void handle_sleep() override;
    void handle_wake() override;
};

} // namespace ag
