#pragma once

#include <chrono>

#include "common/logger.h"
#include "vpn/internal/endpoint_connector.h"

namespace ag {

class FallbackableUpstreamConnector : public EndpointConnector {
public:
    FallbackableUpstreamConnector(const EndpointConnectorParameters &parameters, std::unique_ptr<ServerUpstream> main,
            std::unique_ptr<ServerUpstream> fallback, Millis fallback_delay);
    ~FallbackableUpstreamConnector() override = default;

    FallbackableUpstreamConnector(const FallbackableUpstreamConnector &) = delete;
    FallbackableUpstreamConnector &operator=(const FallbackableUpstreamConnector &) = delete;
    FallbackableUpstreamConnector(FallbackableUpstreamConnector &&) = delete;
    FallbackableUpstreamConnector &operator=(FallbackableUpstreamConnector &&) = delete;

private:
    struct MainInfo {
        std::unique_ptr<EndpointConnector> connector;
        bool has_result = false;
        std::chrono::time_point<std::chrono::steady_clock> start_ts;
        event_loop::AutoTaskId result_task;
    };

    struct FallbackInfo {
        std::unique_ptr<EndpointConnector> connector;
        Millis delay{};
        bool tried = false;
        bool has_result = false;
        event_loop::AutoTaskId delay_task;
        event_loop::AutoTaskId result_task;
    };

    MainInfo m_main;
    FallbackInfo m_fallback;
    std::optional<Millis> m_connect_timeout;
    int m_id;
    ag::Logger m_log{"FBUCONNECTOR"};

    VpnError connect(std::optional<Millis> timeout) override;
    void disconnect() override;
    void handle_sleep() override;
    void handle_wake() override;

    [[nodiscard]] EndpointConnectorParameters make_connector_parameters(EndpointConnectorHandler h) const;
    void handle_connect_result(const EndpointConnector *connector, EndpointConnectorResult result);
    VpnEventLoopTask make_deferred_handle_task(const EndpointConnector *c, EndpointConnectorResult result) const;
    void start_fallback_connection();

    static void main_connector_handler(void *arg, EndpointConnectorResult result);
    static void fallback_connector_handler(void *arg, EndpointConnectorResult result);
};

} // namespace ag
