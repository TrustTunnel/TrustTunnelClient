#pragma once

#include <memory>
#include <optional>
#include <variant>

#include "common/defs.h"
#include "vpn/event_loop.h"
#include "vpn/internal/server_upstream.h"

namespace ag {

class VpnClient;

using EndpointConnectorResult = std::variant<
        /// Successfully connected upstream
        std::unique_ptr<ServerUpstream>,
        /// Disconnected for some reason (`code` may be `VPN_EC_NOERROR` in case
        /// it is disconnected gracefully)
        VpnError>;

struct EndpointConnectorHandler {
    void (*func)(void *arg, EndpointConnectorResult result) = nullptr;
    void *arg = nullptr;
};

struct EndpointConnectorParameters {
    /// An event loop for operation
    VpnEventLoop *ev_loop = nullptr;
    /// Parent VPN client
    VpnClient *vpn_client = nullptr;
    /// Upstream handler which will be set to the upstream in case of successful connection
    SeverHandler upstream_handler = {};
    /// Connector handler
    EndpointConnectorHandler connector_handler = {};
};

/**
 * The endpoint connector is intended to encapsulate the process of establishing
 * a connection to the endpoint
 */
class EndpointConnector {
public:
    const EndpointConnectorParameters PARAMETERS = {};

    explicit EndpointConnector(const EndpointConnectorParameters &parameters)
            : PARAMETERS(parameters) {
    }

    virtual ~EndpointConnector() = default;

    EndpointConnector(const EndpointConnector &) = delete;
    EndpointConnector &operator=(const EndpointConnector &) = delete;
    EndpointConnector(EndpointConnector &&) = delete;
    EndpointConnector &operator=(EndpointConnector &&) = delete;

    /**
     * Initiate the connection
     * @param timeout the procedure timeout
     * @return some error if failed to start
     */
    virtual VpnError connect(std::optional<Millis> timeout) = 0;

    /**
     * Interrupt the connection procedure
     */
    virtual void disconnect() = 0;

    /**
     * Handle a system sleep event. The system is going to sleep after this function returns.
     */
    virtual void handle_sleep() = 0;

    /**
     * Handle a system wake up event.
     */
    virtual void handle_wake() = 0;
};

} // namespace ag
