#pragma once

#ifdef VPNLIBS_LIVE_TEST
#error "mock_ping_sockets.h must not be included in live tests"
#endif

#include <memory>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#undef max
#undef min
#endif

#include <openssl/ssl.h>

#include "common/socket_address.h"
#include "net/quic_connector.h"
#include "net/tcp_socket.h"
#include "vpn/event_loop.h"

namespace ag::test::mock_ping_sockets {

class MockState {
public:
    static MockState &instance() {
        static MockState state;
        return state;
    }

    void reset() {
        tcp_connect_errors.clear();
        quic_connect_errors.clear();
        default_tcp_connect_error = ag::utils::AG_ECONNREFUSED;
        default_quic_connect_error = ag::utils::AG_ECONNREFUSED;
    }

    void set_tcp_error(const SocketAddress &addr, int error) {
        tcp_connect_errors[addr.str()] = error;
    }

    void set_quic_error(const SocketAddress &addr, int error) {
        quic_connect_errors[addr.str()] = error;
    }

    int get_tcp_error(const SocketAddress &addr) const {
        auto it = tcp_connect_errors.find(addr.str());
        return it == tcp_connect_errors.end() ? default_tcp_connect_error : it->second;
    }

    int get_quic_error(const SocketAddress &addr) const {
        auto it = quic_connect_errors.find(addr.str());
        return it == quic_connect_errors.end() ? default_quic_connect_error : it->second;
    }

    void set_default_tcp_error(int error) {
        default_tcp_connect_error = error;
    }

    void set_default_quic_error(int error) {
        default_quic_connect_error = error;
    }

private:
    std::unordered_map<std::string, int> tcp_connect_errors;
    std::unordered_map<std::string, int> quic_connect_errors;
    int default_tcp_connect_error = ag::utils::AG_ECONNREFUSED;
    int default_quic_connect_error = ag::utils::AG_ECONNREFUSED;
};

inline void reset() {
    MockState::instance().reset();
}

inline void set_tcp_error(const SocketAddress &addr, int error) {
    MockState::instance().set_tcp_error(addr, error);
}

inline void set_quic_error(const SocketAddress &addr, int error) {
    MockState::instance().set_quic_error(addr, error);
}

inline void set_default_tcp_error(int error) {
    MockState::instance().set_default_tcp_error(error);
}

inline void set_default_quic_error(int error) {
    MockState::instance().set_default_quic_error(error);
}

inline int get_tcp_error(const SocketAddress &addr) {
    return MockState::instance().get_tcp_error(addr);
}

inline int get_quic_error(const SocketAddress &addr) {
    return MockState::instance().get_quic_error(addr);
}

} // namespace ag::test::mock_ping_sockets

namespace ag {

struct TcpSocket {
    TcpSocketParameters parameters;
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);
    SSL *ssl = nullptr;
};

TcpSocket *tcp_socket_create(const TcpSocketParameters *parameters) {
    auto *socket = new TcpSocket{};
    socket->parameters = *parameters;
    return socket;
}

void tcp_socket_destroy(TcpSocket *socket) {
    if (socket->ssl != nullptr) {
        SSL_free(socket->ssl);
    }
    *socket->alive = false;
    delete socket;
}

void tcp_socket_set_rst(TcpSocket *, bool) {
}

struct MockTcpConnectedTask {
    std::weak_ptr<bool> alive;
    TcpSocketHandler handler;
};

VpnError tcp_socket_connect(TcpSocket *socket, const TcpSocketConnectParameters *param) {
    int error = test::mock_ping_sockets::get_tcp_error(*param->peer);
    if (error != 0) {
        return {.code = error, .text = "mock tcp connect failed"};
    }

    if (socket->ssl != nullptr) {
        SSL_free(socket->ssl);
    }
    socket->ssl = param->ssl;

    vpn_event_loop_submit(socket->parameters.ev_loop,
            {
                    .arg = new MockTcpConnectedTask{socket->alive, socket->parameters.handler},
                    .action =
                            [](void *arg, TaskId) {
                                auto *task = static_cast<MockTcpConnectedTask *>(arg);
                                auto alive = task->alive.lock();
                                if (alive && *alive && task->handler.handler != nullptr) {
                                    task->handler.handler(task->handler.arg, TCP_SOCKET_EVENT_CONNECTED, nullptr);
                                }
                            },
                    .finalize =
                            [](void *arg) {
                                delete static_cast<MockTcpConnectedTask *>(arg);
                            },
            });
    return {.code = 0, .text = "mock tcp connect started"};
}

struct QuicConnector {
    QuicConnectorParameters parameters;
    std::shared_ptr<bool> alive = std::make_shared<bool>(true);
};

QuicConnector *quic_connector_create(const QuicConnectorParameters *parameters) {
    auto *connector = new QuicConnector{};
    connector->parameters = *parameters;
    return connector;
}

struct MockQuicReadyTask {
    std::weak_ptr<bool> alive;
    QuicConnectorHandler handler;
};

VpnError quic_connector_connect(QuicConnector *connector, const QuicConnectorConnectParameters *parameters) {
    if (parameters->ssl != nullptr) {
        SSL_free(parameters->ssl);
    }
    int error = test::mock_ping_sockets::get_quic_error(*parameters->peer);
    if (error != 0) {
        return {.code = error, .text = "mock quic connect failed"};
    }

    vpn_event_loop_submit(connector->parameters.ev_loop,
            {
                    .arg = new MockQuicReadyTask{connector->alive, connector->parameters.handler},
                    .action =
                            [](void *arg, TaskId) {
                                auto *task = static_cast<MockQuicReadyTask *>(arg);
                                auto alive = task->alive.lock();
                                if (alive && *alive && task->handler.handler != nullptr) {
                                    task->handler.handler(task->handler.arg, QUIC_CONNECTOR_EVENT_READY, nullptr);
                                }
                            },
                    .finalize =
                            [](void *arg) {
                                delete static_cast<MockQuicReadyTask *>(arg);
                            },
            });
    return {.code = 0, .text = "mock quic connect started"};
}

void quic_connector_destroy(QuicConnector *connector) {
    *connector->alive = false;
    delete connector;
}

std::unique_ptr<QuicConnectorResult> quic_connector_get_result(QuicConnector *) {
    // The mock never produces a handoff result.
    return nullptr;
}

} // namespace ag
