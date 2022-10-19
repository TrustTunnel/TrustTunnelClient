#include <algorithm>
#include <mutex>

#include "net/dns_manager.h"
#include "net/utils.h"
#include "vpn/platform.h"

namespace ag {

struct DnsManager {
    std::mutex mutex;
    std::vector<std::string> servers;
    std::vector<evdns_base *> bases;
};

DnsManager *dns_manager_create() {
    auto *manager = new DnsManager{};
    return manager;
}

void dns_manager_destroy(DnsManager *manager) {
    delete manager;
}

static void add_servers_to_base(DnsManager *manager, struct evdns_base *base) {
    if (manager->servers.empty()) {
        int success = false;
#ifdef _WIN32
        int r = evdns_base_config_windows_nameservers(base);
        success = r == 0;
#elif !defined(ANDROID)
        int r = evdns_base_resolv_conf_parse(base, DNS_OPTIONS_ALL, "/etc/resolv.conf");
        if (r == 0) {
            success = true;
        } else {
            evdns_base_clear_nameservers_and_suspend(base);
        }
#endif
        if (!success) {
            evdns_base_nameserver_ip_add(base, AG_UNFILTERED_DNS_IPS_V4[0].data());
        }
    } else {
        for (const std::string &server : manager->servers) {
            evdns_base_nameserver_ip_add(base, server.c_str());
        }
    }
}

bool dns_manager_set_servers(DnsManager *manager, std::vector<std::string> servers) {
    std::unique_lock l(manager->mutex);

    manager->servers = std::move(servers);

    for (auto *base : manager->bases) {
        evdns_base_clear_nameservers_and_suspend(base);
        add_servers_to_base(manager, base);
        evdns_base_resume(base);
    }

    return true;
}

static void register_base(DnsManager *manager, struct evdns_base *base) {
    std::unique_lock l(manager->mutex);
    manager->bases.emplace_back(base);
    add_servers_to_base(manager, base);
}

static void unregister_base(DnsManager *manager, struct evdns_base *base) {
    std::unique_lock l(manager->mutex);
    manager->bases.erase(std::remove_if(manager->bases.begin(), manager->bases.end(),
                                 [base](evdns_base *b) {
                                     return b == base;
                                 }),
            manager->bases.end());
}

struct evdns_base *dns_manager_create_base(DnsManager *manager, struct event_base *base) {
// For iOS we use synchronous resolving
#if TARGET_OS_IPHONE
    return nullptr;
#endif

    if (base == nullptr) {
        return nullptr;
    }
    struct evdns_base *dns_base = evdns_base_new(base, 0);
    if (dns_base == nullptr) {
        return nullptr;
    }

    evdns_base_set_option(dns_base, "randomize-case:", "0");

    register_base(manager, dns_base);

    return dns_base;
}

void dns_manager_delete_base(DnsManager *manager, struct evdns_base *base) {
    if (base == nullptr) {
        return;
    }

    unregister_base(manager, base);
    evdns_base_free(base, true);
}

} // namespace ag
