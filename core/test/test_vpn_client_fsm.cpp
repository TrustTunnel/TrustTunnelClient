#include <thread>

#include <gtest/gtest.h>

#include "direct_upstream.h"
#include "socks_listener.h"
#include "upstream_multiplexer.h"
#include "vpn/internal/vpn_client.h"

using namespace ag;

static vpn_client::Event last_raised_vpn_event;
static std::optional<ClientConnectResult> last_client_connect_result;
static std::optional<VpnConnectAction> last_tunnel_connect_action;

static void vpn_handler(void *, vpn_client::Event what, void *) {
    last_raised_vpn_event = what;
}

class VpnClientTest : public testing::Test {
public:
    VpnClientTest()
            : vpn(vpn_client::Parameters{}) {
        ag::Logger::set_log_level(ag::LOG_LEVEL_TRACE);
    }

    friend class DirectUpstream;
    friend class UpstreaMultiplexer;
    friend class SocksListener;

    DeclPtr<VpnEventLoop, &vpn_event_loop_destroy> ev_loop{vpn_event_loop_create()};
    DeclPtr<VpnNetworkManager, &vpn_network_manager_destroy> network_manager{vpn_network_manager_get()};
    VpnClient vpn;
    ServerUpstream *redirect_upstream = nullptr;
    ClientListener *client_listener = nullptr;

    void SetUp() override {
        vpn.parameters = {this->ev_loop.get()};
        vpn.parameters.handler = {&vpn_handler, this};
        vpn.parameters.network_manager = this->network_manager.get();

        VpnSettings settings = {};
        VpnError error = vpn.init(&settings);
        ASSERT_EQ(error.code, VPN_EC_NOERROR) << error.text;

        vpn_client::EndpointConnectionConfig upstream_config = {};
        error = vpn.connect(upstream_config);
        ASSERT_EQ(error.code, VPN_EC_NOERROR) << error.text;

        this->redirect_upstream->handler.func(
                this->redirect_upstream->handler.arg, SERVER_EVENT_SESSION_OPENED, nullptr);
        run_event_loop_once();
        this->redirect_upstream->handler.func(
                this->redirect_upstream->handler.arg, SERVER_EVENT_HEALTH_CHECK_RESULT, nullptr);
        run_event_loop_once();
        ASSERT_EQ(last_raised_vpn_event, vpn_client::EVENT_CONNECTED);

        VpnListenerConfig listener_config = {};
        VpnSocksListenerConfig socks_listener_config = {};
        error = vpn.listen(std::make_unique<SocksListener>(&socks_listener_config), &listener_config, true);
        ASSERT_EQ(error.code, VPN_EC_NOERROR) << error.text;
    }

    void TearDown() override {
        vpn.disconnect();
        vpn.finalize_disconnect();
        vpn.deinit();

        vpn.kill_switch_on = false;
        last_client_connect_result.reset();
        last_tunnel_connect_action.reset();
    }

    void run_event_loop_once() { // NOLINT(readability-make-member-function-const)
        vpn_event_loop_exit(ev_loop.get(), Millis{0});
        vpn_event_loop_run(ev_loop.get());
    }
};

namespace ag {
struct SocketContext {};
struct DirectUpstream::IcmpRequestInfo {};
DirectUpstream::DirectUpstream(int id)
        : ServerUpstream(id) {
}
DirectUpstream::~DirectUpstream() = default;
bool DirectUpstream::init(VpnClient *vpn, SeverHandler handler) {
    ServerUpstream::init(vpn, handler);
    return true;
}
void DirectUpstream::deinit() {
}
bool DirectUpstream::open_session(std::optional<Millis>) {
    return true;
}
void DirectUpstream::close_session() {
}
uint64_t DirectUpstream::open_connection(const TunnelAddressPair *, int, std::string_view) {
    return 0;
}
void DirectUpstream::close_connection(uint64_t id, bool graceful, bool async) {
}
ssize_t DirectUpstream::send(uint64_t, const uint8_t *, size_t length) {
    return length;
}
void DirectUpstream::consume(uint64_t id, size_t length) {
}
size_t DirectUpstream::available_to_send(uint64_t) {
    return 0;
}
void DirectUpstream::update_flow_control(uint64_t id, TcpFlowCtrlInfo info) {
}
VpnError DirectUpstream::do_health_check() {
    return {};
}
VpnConnectionStats DirectUpstream::get_connection_stats() const {
    return {};
}
void DirectUpstream::tcp_socket_handler(void *, TcpSocketEvent, void *) {
}
void DirectUpstream::udp_socket_handler(void *, UdpSocketEvent, void *) {
}
uint64_t DirectUpstream::open_tcp_connection(const TunnelAddressPair *) {
    return 0;
}
uint64_t DirectUpstream::open_udp_connection(const TunnelAddressPair *) {
    return 0;
}
void DirectUpstream::close_connection(uint64_t, bool) {
}
void DirectUpstream::on_icmp_request(IcmpEchoRequestEvent &) {
}
void DirectUpstream::cancel_icmp_request(const IcmpRequestKey &, uint16_t) {
}

struct UpstreamInfo {};
class Http2Upstream {};
UpstreamMultiplexer::UpstreamMultiplexer(int id, const VpnUpstreamProtocolConfig &, size_t, MakeUpstream)
        : ServerUpstream(id) {
}
UpstreamMultiplexer::~UpstreamMultiplexer() = default;
bool UpstreamMultiplexer::init(VpnClient *vpn, SeverHandler handler) {
    ServerUpstream::init(vpn, handler);
    auto *test = (VpnClientTest *) vpn->parameters.handler.arg;
    test->redirect_upstream = this;
    return true;
}
void UpstreamMultiplexer::deinit() {
}
bool UpstreamMultiplexer::open_session(std::optional<Millis>) {
    return true;
}
void UpstreamMultiplexer::close_session() {
}
uint64_t UpstreamMultiplexer::open_connection(const TunnelAddressPair *, int, std::string_view) {
    return 0;
}
void UpstreamMultiplexer::close_connection(uint64_t id, bool graceful, bool async) {
}
ssize_t UpstreamMultiplexer::send(uint64_t, const uint8_t *, size_t length) {
    return length;
}
void UpstreamMultiplexer::consume(uint64_t id, size_t length) {
}
size_t UpstreamMultiplexer::available_to_send(uint64_t) {
    return 0;
}
void UpstreamMultiplexer::update_flow_control(uint64_t, TcpFlowCtrlInfo) {
}
VpnError UpstreamMultiplexer::do_health_check() {
    return {};
}
VpnConnectionStats UpstreamMultiplexer::get_connection_stats() const {
    return {};
}
void UpstreamMultiplexer::child_upstream_handler(void *, ServerEvent, void *) {
}
MultiplexableUpstream *UpstreamMultiplexer::get_upstream_by_conn(uint64_t) const {
    return nullptr;
}
std::optional<int> UpstreamMultiplexer::select_existing_upstream(std::optional<int>, bool) const {
    return std::nullopt;
}
int UpstreamMultiplexer::select_upstream_for_connection() {
    return 0;
}
bool UpstreamMultiplexer::open_new_upstream(int, std::optional<Millis>) {
    return true;
}
bool UpstreamMultiplexer::open_connection(int, uint64_t, const TunnelAddressPair *, int, std::string_view) {
    return true;
}
void UpstreamMultiplexer::proceed_pending_connection(int, uint64_t, const PendingConnection *) {
}
size_t UpstreamMultiplexer::connections_num_by_upstream(int) const {
    return 0;
}
void UpstreamMultiplexer::on_icmp_request(IcmpEchoRequestEvent &) {
}

SocksListener::SocksListener(const VpnSocksListenerConfig *) {
}
SocksListener::~SocksListener() = default;
const sockaddr_storage &SocksListener::get_listen_address() const {
    static const sockaddr_storage ADDR = sockaddr_from_str("127.0.0.1:1111");
    return ADDR;
}
ClientListener::InitResult SocksListener::init(VpnClient *vpn, ClientHandler handler) {
    if (auto result = this->ClientListener::init(vpn, handler); result != InitResult::SUCCESS) {
        return result;
    }
    auto *test = (VpnClientTest *) vpn->parameters.handler.arg;
    test->client_listener = this;
    return InitResult::SUCCESS;
}
void SocksListener::deinit() {
}
void SocksListener::complete_connect_request(uint64_t, ClientConnectResult result) {
    last_client_connect_result = result;
}
void SocksListener::close_connection(uint64_t id, bool graceful, bool async) {
}
ssize_t SocksListener::send(uint64_t, const uint8_t *, size_t length) {
    return length;
}
void SocksListener::consume(uint64_t id, size_t n) {
}
TcpFlowCtrlInfo SocksListener::flow_control_info(uint64_t) {
    return {};
}
void SocksListener::turn_read(uint64_t id, bool on) {
}
void SocksListener::socks_handler(void *arg, Socks5ListenerEvent what, void *data) {
}

Tunnel::Tunnel() = default;
Tunnel::~Tunnel() = default;
bool Tunnel::init(VpnClient *) {
    return true;
}
void Tunnel::deinit() {
}
void Tunnel::upstream_handler(ServerUpstream *, ServerEvent, void *) {
}
void Tunnel::listener_handler(ClientListener *, ClientEvent, void *) {
}
void Tunnel::complete_connect_request(uint64_t, std::optional<VpnConnectAction> action) {
    last_tunnel_connect_action = action;
}
void Tunnel::reset_connections(int) {
}
void Tunnel::reset_connection(uint64_t) {
}
std::optional<VpnConnectAction> Tunnel::finalize_connect_action(ConnectRequestResult &request_result, bool) const {
    return request_result.action;
}
void Tunnel::on_before_endpoint_disconnect(ServerUpstream *) {
}
void Tunnel::on_after_endpoint_disconnect(ServerUpstream *) {
}
void Tunnel::on_exclusions_updated() {
}
} // namespace ag

// Check that client raises error event on an error
TEST_F(VpnClientTest, Error) {
    ServerError error = {NON_ID, {VPN_EC_ERROR, "test"}};
    redirect_upstream->handler.func(redirect_upstream->handler.arg, SERVER_EVENT_ERROR, &error);

    run_event_loop_once();

    ASSERT_EQ(last_raised_vpn_event, vpn_client::EVENT_ERROR);
}
