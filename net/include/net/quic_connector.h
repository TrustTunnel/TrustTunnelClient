#pragma once

#include <cstdint>
#include <optional>
#include <span>

#include <event2/util.h>

#ifndef DISABLE_HTTP3
#include <quiche.h>
#endif

#include "common/defs.h"
#include "net/socket_manager.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

#include "vpn/platform.h"

#include <openssl/ssl.h>

namespace ag {

/**
 * A QUIC connector sets up a QUIC connection object and starts establishing the connection.
 * When it receives the first UDP payload from the server, it pauses and raises a "ready" event.
 * The connection state can then be retrieved and the connection process can be continued elsewhere.
 * This way, a half-open connection can be handed off from the locations pinger to the upstream
 * to save some network round trips.
 * If the connector encounters an error, it aborts the connection and raises an event.
 */
struct QuicConnector;

enum QuicConnectorEvent {
    QUIC_CONNECTOR_EVENT_READY,   // Raised with a null pointer.
    QUIC_CONNECTOR_EVENT_ERROR,   // Raised with a `VpnError` pointer.
    QUIC_CONNECTOR_EVENT_PROTECT, // Raised with a `SocketProtectEvent` pointer.
};

struct QuicConnectorHandler {
    void (*handler)(void *arg, QuicConnectorEvent id, void *data);
    void *arg;
};

struct QuicConnectorParameters {
    VpnEventLoop *ev_loop;         // event loop
    QuicConnectorHandler handler;  // events handler
    SocketManager *socket_manager; // socket manager
    std::string log_prefix;        // prefix to the main log message
};

struct QuicConnectorConnectParameters {
    const SocketAddress *peer;
    SSL *ssl;
    Millis timeout;          // How long to wait for server response before giving up.
    Millis max_idle_timeout; // QUIC connection's maximum idle timeout.
    uint32_t quic_version;
};

#ifndef DISABLE_HTTP3
struct QuicConnectorResult {
    evutil_socket_t fd;                               // UDP socket's file descriptor.
    ag::DeclPtr<quiche_conn, &quiche_conn_free> conn; // Owning pointer to a QUIC connection object.
    SSL *ssl;       // Non-owning pointer to the SSL object owned by the QUIC connection object.
    Uint8Span data; // The first UDP payload received from the server. Valid until the connector is destroyed.
};
#else
struct QuicConnectorResult {};
#endif

QuicConnector *quic_connector_create(const QuicConnectorParameters *parameters);

/**
 * Start a QUIC connection.
 * This function ALWAYS takes ownership of `parameters->ssl`, even when the call fails with an error.
 */
VpnError quic_connector_connect(QuicConnector *connector, const QuicConnectorConnectParameters *parameters);

/**
 * Return the result object.
 * Return `nullopt` if not ready or if the result object has already been returned once.
 */
std::optional<QuicConnectorResult> quic_connector_get_result(QuicConnector *connector);

/**
 * Return the log prefix.
 */
std::string quic_connector_get_log_prefix(QuicConnector *connector);

void quic_connector_destroy(QuicConnector *connector);

}; // namespace ag
