#pragma once

#include <string>
#include <vector>

#include <event2/dns.h>
#include <event2/event.h>

namespace ag {

struct DnsManager;

/**
 * Create a DNS manager
 */
DnsManager *dns_manager_create();

/**
 * Destroy a DNS manager
 */
void dns_manager_destroy(DnsManager *manager);

/**
 * Set DNS servers to be used by the manager
 * @param manager DNS manager
 * @param servers DNS servers
 * @return true if set successfully, false otherwise
 */
bool dns_manager_set_servers(DnsManager *manager, std::vector<std::string> servers);

/**
 * Create a DNS base for domain names resolving
 * @param manager DNS manager
 * @param base event loop of the DNS base
 * @return DNS base, or null if failed
 */
struct evdns_base *dns_manager_create_base(DnsManager *manager, struct event_base *base);

/**
 * Delete a DNS base
 * @param manager DNS manager
 * @param base DNS base
 */
void dns_manager_delete_base(DnsManager *manager, struct evdns_base *base);

} // namespace ag
