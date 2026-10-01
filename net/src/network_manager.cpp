#include <net/network_manager.h>

#include <atomic>
#include <mutex>
#include <unordered_set>
#include <utility>

#include "common/cache.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOCRYPT
#include <netioapi.h>
#else
#include <net/if.h>
#endif

namespace ag {

static Logger g_logger{"NETWORK_MANAGER"};

static struct NetworkManagerHolder {
    static constexpr auto DEFAULT_CACHE_SIZE = 100;
    VpnNetworkManager manager = {
            .dns = dns_manager_create(), // single DNS manager for all VPN clients
            .socket = nullptr,           // each VPN client has its own socket manager
    };
    std::mutex guard;
    ag::LruTimeoutCache<std::string, bool> app_domain_cache;
    std::atomic<uint32_t> outbound_interface = 0;
    std::mutex tunnel_activity_guard;
    std::unordered_set<VpnTunnelActivityToken> tunnel_activity_tokens;
    VpnTunnelActivityToken next_tunnel_activity_token = 1;
    std::atomic_size_t tunnel_activity_count = 0;

    NetworkManagerHolder()
            : app_domain_cache(DEFAULT_CACHE_SIZE, std::chrono::minutes(10)) {
    }

    ~NetworkManagerHolder() {
        clear();
    }

    void clear() {
        dns_manager_destroy(std::exchange(this->manager.dns, nullptr));
        socket_manager_destroy(std::exchange(this->manager.socket, nullptr));
    }
} g_network_manager_holder;

VpnNetworkManager *vpn_network_manager_get() {
    return new VpnNetworkManager{g_network_manager_holder.manager.dns, socket_manager_create()};
}

void vpn_network_manager_destroy(VpnNetworkManager *m) {
    socket_manager_destroy(std::exchange(m->socket, nullptr));
    delete m;
}

bool vpn_network_manager_update_system_dns(SystemDnsServers servers) {
    return dns_manager_set_system_servers(g_network_manager_holder.manager.dns, std::move(servers));
}

void vpn_network_manager_notify_app_request_domain(const char *domain, int timeout_ms) {
    std::scoped_lock l(g_network_manager_holder.guard);
    if (timeout_ms >= 0) {
        g_network_manager_holder.app_domain_cache.insert(domain, false, std::chrono::milliseconds(timeout_ms));
    } else {
        g_network_manager_holder.app_domain_cache.insert(domain, false);
    }
}

bool vpn_network_manager_check_app_request_domain(const char *domain) {
    std::scoped_lock l(g_network_manager_holder.guard);
    return (bool) g_network_manager_holder.app_domain_cache.get(domain);
}

void vpn_network_manager_set_outbound_interface(uint32_t idx) {
    char buf[IF_NAMESIZE + 1];
    char *name = if_indextoname(idx, buf);
    dbglog(g_logger, "Interface name {} with index {}", name ? name : "(unknown)", idx);
    g_network_manager_holder.outbound_interface = idx;
}

uint32_t vpn_network_manager_get_outbound_interface() {
    return g_network_manager_holder.outbound_interface;
}

VpnTunnelActivityToken vpn_network_manager_acquire_tunnel_activity() {
    std::scoped_lock l(g_network_manager_holder.tunnel_activity_guard);
    VpnTunnelActivityToken token;
    do {
        token = g_network_manager_holder.next_tunnel_activity_token++;
    } while (token == VPN_TUNNEL_ACTIVITY_TOKEN_INVALID
            || g_network_manager_holder.tunnel_activity_tokens.contains(token));

    g_network_manager_holder.tunnel_activity_tokens.insert(token);
    g_network_manager_holder.tunnel_activity_count = g_network_manager_holder.tunnel_activity_tokens.size();
    dbglog(g_logger, "Tunnel activity acquired, active owners: {}",
            g_network_manager_holder.tunnel_activity_tokens.size());
    return token;
}

void vpn_network_manager_release_tunnel_activity(VpnTunnelActivityToken token) {
    std::scoped_lock l(g_network_manager_holder.tunnel_activity_guard);
    if (token == VPN_TUNNEL_ACTIVITY_TOKEN_INVALID
            || g_network_manager_holder.tunnel_activity_tokens.erase(token) == 0) {
        warnlog(g_logger, "Ignoring invalid or already released tunnel activity token");
        return;
    }

    g_network_manager_holder.tunnel_activity_count = g_network_manager_holder.tunnel_activity_tokens.size();
    dbglog(g_logger, "Tunnel activity released, active owners: {}",
            g_network_manager_holder.tunnel_activity_tokens.size());
}

bool vpn_network_manager_get_tunnel_active() {
    return g_network_manager_holder.tunnel_activity_count != 0;
}

} // namespace ag
