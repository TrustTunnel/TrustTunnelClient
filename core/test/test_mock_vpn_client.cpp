#include "test_mock_vpn_client.h"

using namespace ag;

namespace test_mock {
MockedVpnClient g_client = {};
}

VpnClient::VpnClient(vpn_client::Parameters parameters)
        : fsm({})
        , parameters(parameters) {
}
VpnClient::~VpnClient() = default;
VpnError VpnClient::init(const VpnSettings *) {
    return {};
}
VpnError VpnClient::connect(vpn_client::EndpointConnectionConfig config, std::optional<Millis>) {
    this->upstream_config = std::move(config);
    test_mock::g_client.notify_called(test_mock::CMID_CONNECT);
    return test_mock::g_client.error;
}
VpnError VpnClient::listen(std::unique_ptr<ClientListener>, const VpnListenerConfig *, bool) {
    return {};
}
void VpnClient::disconnect() {
    test_mock::g_client.notify_called(test_mock::CMID_DISCONNECT);
}
void VpnClient::finalize_disconnect() {
}
void VpnClient::deinit() {
}
void VpnClient::process_client_packets(VpnPackets) {
}
std::optional<VpnConnectAction> VpnClient::finalize_connect_action(ConnectRequestResult &request_result, bool) const {
    return request_result.action;
}
void VpnClient::complete_connect_request(uint64_t id, std::optional<VpnConnectAction> action) {
    test_mock::g_client.completed_connect_requests.emplace_back(id, action);
    test_mock::g_client.notify_called(test_mock::CMID_COMPLETE_CONNECT_REQUEST);
}
void VpnClient::reject_connect_request(uint64_t id) {
    test_mock::g_client.rejected_connect_requests.emplace_back(id);
    test_mock::g_client.notify_called(test_mock::CMID_REJECT_CONNECT_REQUEST);
}
void VpnClient::update_exclusions(VpnMode, std::string_view) {
}
void VpnClient::reset_connections(int) {
}
void VpnClient::reset_connection(uint64_t id) {
    test_mock::g_client.reset_connections.emplace_back(id);
    test_mock::g_client.notify_called(test_mock::CMID_RESET_CONNECTION);
}
void VpnClient::update_parameters(vpn_client::Parameters) {
}
void VpnClient::do_health_check() {
    test_mock::g_client.notify_called(test_mock::CMID_DO_HEALTH_CHECK);
}
VpnConnectionStats VpnClient::get_connection_stats() const {
    return {};
}
bool VpnClient::may_send_icmp_request() const {
    return true;
}
void VpnClient::handle_sleep() {
}
void VpnClient::handle_wake() {
}
int VpnClient::next_upstream_id() {
    static int id = 42;
    return id++;
}
