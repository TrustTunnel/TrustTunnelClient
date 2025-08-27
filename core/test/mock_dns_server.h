#pragma once

#include <cstdint>
#include <functional>
#include <list>
#include <optional>
#include <string>
#include <vector>

#include <event2/listener.h>
#include <event2/util.h>

#include "common/defs.h"
#include "common/socket_address.h"
#include "net/tcp_socket.h"
#include "net/udp_socket.h"

namespace ag {

class MockDnsServer {
public:
    MockDnsServer() = default;
    ~MockDnsServer();

    MockDnsServer(const MockDnsServer &other) = delete;
    MockDnsServer &operator=(const MockDnsServer &other) = delete;

    MockDnsServer(MockDnsServer &&other) noexcept = delete;
    MockDnsServer &operator=(MockDnsServer &&other) noexcept = delete;

    struct Request {
        bool tcp = false;
        int qtype = 0;
        std::string qname;

        friend bool operator==(const Request &lhs, const Request &rhs) {
            return lhs.tcp == rhs.tcp && lhs.qtype == rhs.qtype && lhs.qname == rhs.qname;
        }

        friend bool operator!=(const Request &lhs, const Request &rhs) {
            return !(lhs == rhs);
        }
    };

    struct Response {
        int rcode = 0;
        std::vector<std::string> answer; // RRs in `ldns_rr_new_frm_str()` format.
    };

    struct Spec {
        Request request;
        std::optional<Response> response; // If nullopt, don't respond.
    };

    /** Called on unexpected request. Return value determines how to respond. */
    using UnexpectedHandler = std::function<std::optional<Response>(std::optional<Request> expected, Request actual)>;

    /** Called when no more requests are expected. */
    using CompleteHandler = std::function<void()>;

    /**
     * Start listening for TCP/UDP on `listen_addr`, port should be zero.
     * Return the listened-on address (including port) or `std::nullopt` in case of an error.
     * This class is not thread-safe -- it must be used on the same event loop that is passed to `start()`.
     * On an unexpected request, `unexpected_handler` is called.
     * When all expected requests are exhausted, `complete_handler` is called.
     */
    std::optional<SocketAddress> start(SocketAddress listen_addr, VpnEventLoop *event_loop,
            SocketManager *socket_manager, CompleteHandler complete_handler, UnexpectedHandler unexpected_handler);

    /** Specify a request to expect and how to respond. The order of expected requests is not checked. */
    void expect(Spec expect);

private:
    struct TcpConn {
        MockDnsServer *server = nullptr;
        UniquePtr<TcpSocket, &tcp_socket_destroy> socket;
        SocketAddress from;
        std::vector<uint8_t> buf;
    };

    VpnEventLoop *m_event_loop = nullptr;
    SocketManager *m_socket_manager = nullptr;

    std::list<Spec> m_expected;

    UnexpectedHandler m_unexpected_handler;
    CompleteHandler m_complete_handler;

    UniquePtr<event, &event_free> m_udp_event;

    UniquePtr<evconnlistener, &evconnlistener_free> m_listener;
    std::list<TcpConn> m_tcp_conns;

    std::vector<uint8_t> m_rcv_buf;

    static void udp_handler(evutil_socket_t, short, void *);
    static void listener_handler(evconnlistener *, evutil_socket_t, sockaddr *, int, void *);
    static void tcp_handler(void *arg, TcpSocketEvent id, void *data);

    std::optional<std::vector<uint8_t>> on_dns_message(U8View message, bool tcp);
    std::optional<Response> on_dns_message(Request request);
};

} // namespace ag
