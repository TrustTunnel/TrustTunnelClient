#pragma once

#include <set>

#include "common/logger.h"
#include "common/socket_address.h"
#include "net/socks5_listener.h"
#include "vpn/internal/client_listener.h"

namespace ag {

class SocksListener : public ClientListener {
public:
    explicit SocksListener(const VpnSocksListenerConfig *config);
    ~SocksListener() override;

    SocksListener(const SocksListener &) = delete;
    SocksListener &operator=(const SocksListener &) = delete;

    SocksListener(SocksListener &&) noexcept = delete;
    SocksListener &operator=(SocksListener &&) noexcept = delete;

    /**
     * Get the address the listener is listening on
     */
    [[nodiscard]] const SocketAddress &get_listen_address() const;

private:
    Socks5Listener *m_socks5_listener = nullptr;
    std::set<event_loop::AutoTaskId> m_deferred_tasks;
    VpnSocksListenerConfig m_config = {};

    ag::Logger m_log{"SOCKS_LISTENER"};

    InitResult init(VpnClient *vpn, ClientHandler handler) override;
    void deinit() override;
    void complete_connect_request(uint64_t id, ClientConnectResult result) override;
    void close_connection(uint64_t id, bool graceful, bool async) override;
    ssize_t send(uint64_t id, const uint8_t *data, size_t length) override;
    void consume(uint64_t id, size_t n) override;
    TcpFlowCtrlInfo flow_control_info(uint64_t id) override;
    void turn_read(uint64_t id, bool on) override;

    static void socks_handler(void *arg, Socks5ListenerEvent what, void *data);
};

} // namespace ag
