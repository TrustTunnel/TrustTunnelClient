#pragma once

#include <map>
#include <optional>
#include <unordered_map>
#include <vector>

#include <event2/event.h>

#include "common/clock.h"
#include "net/tcp_socket.h"
#include "net/udp_socket.h"
#include "vpn/event_loop.h"
#include "vpn/utils.h"

namespace ag {

struct DnsClientResponse {
    uint16_t id;
    U8View data;
};

enum DnsClientEvent {
    DNS_CLIENT_RESPONSE, // Response available. `data` points to `DnsProxyClientResponse`.
    DNS_CLIENT_PROTECT,  // FD needs to be protected. `data` points to `ag::SocketProtectEvent`.
};

struct DnsClientHandler {
    void (*func)(void *arg, DnsClientEvent id, void *data);
    void *arg;
};

struct DnsClientParameters {
    VpnEventLoop *ev_loop;
    SocketManager *socket_manager;
    DnsClientHandler handler;
    SocketAddress tcp_server_address;
    SocketAddress udp_server_address;
    Millis request_timeout;
    std::string tag; // A string to include in each log message.
};

/** A simple TCP DNS client intended for communication with the local DNS proxy. */
class DnsClient {
public:
    DnsClient(DnsClient &&) noexcept = delete;
    DnsClient &operator=(DnsClient &&) noexcept = delete;

    DnsClient(const DnsClient &) = delete;
    DnsClient &operator=(const DnsClient &) = delete;

    ~DnsClient() = default;

    /** Construct a new client. */
    explicit DnsClient(DnsClientParameters parameters);

    /** Must be called exactly once during DnsClient lifetime, before any other functions. */
    bool init();

    /**
     * Send a request.
     *
     * When a response becomes available, or an error occurs, the response callback will
     * be called with the returned ID as its first argument. The second argument will be either the
     * response body, or `std::nullopt` in case of an error.
     *
     * The request must be in DNS wire format (https://datatracker.ietf.org/doc/html/rfc1035#section-4.1).
     * The ID field of the request is carried over to the reported response, although the ID of the request
     * actually sent over the network might be different.
     *
     * @param tcp If `true`, use TCP instead of UDP.
     */
    std::optional<uint16_t> send(U8View request, bool tcp);

private:
    DnsClientParameters m_parameters;
    uint16_t m_next_request_id = 0;
    std::unordered_map<uint16_t, uint16_t> m_original_id_by_request_id; // Key in host order, value in network order.
    std::multimap<SteadyClock::time_point, uint16_t> m_request_id_by_deadline;
    std::multimap<SteadyClock::time_point, uint16_t> m_deferred_request_id_by_deadline;
    std::unordered_map<uint16_t, std::vector<uint8_t>> m_deferred_request_by_request_id;

    UniquePtr<UdpSocket, &udp_socket_destroy> m_udp_socket;
    UniquePtr<TcpSocket, &tcp_socket_destroy> m_tcp_socket;
    bool m_tcp_socket_is_connecting = false;

    UniquePtr<event, &event_free> m_timer;

    std::optional<uint16_t> m_response_size;
    std::vector<uint8_t> m_response_buffer;

    // Socket handler functions.
    void on_tcp_read(U8View data);
    void on_udp_read(Uint8Span data);
    void on_write_flush();
    void on_connected(VpnError error);

    static void tcp_socket_handler(void *arg, TcpSocketEvent what, void *data);
    static void udp_socket_handler(void *arg, UdpSocketEvent what, void *data);
    static void timer_handler(evutil_socket_t, short, void *);

    void timer_handler();
    void send_deferred_requests();

    // If the socket is connected and can write, then send the request and return `true`, otherwise return `false`.
    // If socket is not connected, start connection.
    // If the request was sent, put the original ID in the map.
    bool send_request(U8View request, uint16_t id, bool tcp);

    void connect_socket();
};

} // namespace ag
