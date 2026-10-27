#include "trusttunnel/trusttunnel.h"

#include <string>
#include <vector>

#include "src/vpn_controller.h"

using namespace ag::trusttunnel_linux;

/// C-to-C++ callback bridge held by the instance
struct trusttunnel_s {
    VpnController controller;

    explicit trusttunnel_s(VpnController::Callbacks callbacks)
            : controller(std::move(callbacks)) {
    }
};

/// Convert C callbacks into the controller's std::function-based callbacks
static VpnController::Callbacks make_controller_callbacks(const trusttunnel_callbacks_t &c) {
    VpnController::Callbacks callbacks;
    if (c.on_state_changed != nullptr) {
        void *arg = c.state_changed_arg;
        auto on_state_changed = c.on_state_changed;
        callbacks.on_state_changed = [arg, on_state_changed](VpnState state) {
            on_state_changed(arg, static_cast<trusttunnel_vpn_state_t>(state));
        };
    }
    if (c.on_connection_info != nullptr) {
        void *arg = c.connection_info_arg;
        auto on_connection_info = c.on_connection_info;
        callbacks.on_connection_info = [arg, on_connection_info](const std::string &json) {
            on_connection_info(arg, json.c_str());
        };
    }
    if (c.on_network_ready != nullptr) {
        void *arg = c.network_ready_arg;
        auto on_network_ready = c.on_network_ready;
        callbacks.on_network_ready = [arg, on_network_ready](const ag::VpnNetworkInfo &info) {
            // Pointers into these containers stay valid for the duration of the callback
            std::vector<std::string> dns_servers(info.dns_servers.begin(), info.dns_servers.end());
            std::vector<const char *> dns_ptrs;
            dns_ptrs.reserve(dns_servers.size());
            for (const std::string &server : dns_servers) {
                dns_ptrs.push_back(server.c_str());
            }

            trusttunnel_network_info_t network_info{};
            network_info.iface_name = info.iface_name.c_str();
            network_info.ipv4_address = info.ipv4_address.c_str();
            network_info.ipv4_prefix = info.ipv4_prefix;
            network_info.ipv6_address = info.ipv6_address.c_str();
            network_info.ipv6_prefix = info.ipv6_prefix;
            network_info.mtu = info.mtu;
            network_info.dns_servers = dns_ptrs.data();
            network_info.dns_servers_count = dns_ptrs.size();
            on_network_ready(arg, &network_info);
        };
    }
    return callbacks;
}

trusttunnel_t *trusttunnel_create(const trusttunnel_callbacks_t *callbacks) {
    if (callbacks == nullptr) {
        return nullptr;
    }
    return new trusttunnel_s(make_controller_callbacks(*callbacks));
}

trusttunnel_vpn_error_t trusttunnel_start(trusttunnel_t *vpn, const char *toml_config) {
    if (vpn == nullptr) {
        return TRUSTTUNNEL_VPN_INVALID_CONFIG;
    }
    return static_cast<trusttunnel_vpn_error_t>(vpn->controller.start(toml_config != nullptr ? toml_config : ""));
}

trusttunnel_vpn_error_t trusttunnel_stop(trusttunnel_t *vpn) {
    if (vpn == nullptr) {
        return TRUSTTUNNEL_VPN_SUCCESS;
    }
    return static_cast<trusttunnel_vpn_error_t>(vpn->controller.stop());
}

trusttunnel_vpn_state_t trusttunnel_get_state(trusttunnel_t *vpn) {
    if (vpn == nullptr) {
        return TRUSTTUNNEL_VPN_DISCONNECTED;
    }
    return static_cast<trusttunnel_vpn_state_t>(vpn->controller.state());
}

int trusttunnel_event_fd(trusttunnel_t *vpn) {
    if (vpn == nullptr) {
        return -1;
    }
    return vpn->controller.event_fd();
}

void trusttunnel_drain(trusttunnel_t *vpn) {
    if (vpn != nullptr) {
        vpn->controller.drain();
    }
}

void trusttunnel_destroy(trusttunnel_t *vpn) {
    delete vpn;
}
