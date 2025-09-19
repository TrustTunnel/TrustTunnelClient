#pragma once

#include <bitset>
#include <chrono>
#include <set>
#include <string>
#include <string_view>
#include <unordered_set>
#include <variant>
#include <vector>

#include "common/cache.h"
#include "common/logger.h"
#include "common/socket_address.h"
#include "vpn/internal/utils.h"
#include "vpn/vpn.h"

namespace ag {

enum DomainFilterValidationStatus {
    DFVS_OK_ADDR,
    DFVS_OK_CIDR,
    DFVS_OK_DOMAIN,
    DFVS_MALFORMED,
};

enum DomainFilterMatchStatus {
    /// Connection is not matched
    DFMS_DEFAULT,
    /// Connection targets the excluded host
    DFMS_EXCLUSION,
    /// Connection is not matched, but it potentially targets the excluded host
    DFMS_SUSPECT_EXCLUSION,
};

struct DomainFilterMatchResult {
    DomainFilterMatchStatus status;
    std::optional<std::string> domain;
};

class DomainFilter {
public:
    static constexpr size_t DEFAULT_CACHE_SIZE = 512;
    static constexpr std::chrono::seconds DEFAULT_TAG_TTL{60};

    DomainFilter();
    ~DomainFilter();

    DomainFilter(const DomainFilter &) = delete;
    DomainFilter &operator=(const DomainFilter &) = delete;
    DomainFilter(DomainFilter &&) = delete;
    DomainFilter &operator=(DomainFilter &&) = delete;

    static DomainFilterValidationStatus validate_entry(std::string_view entry);

    /**
     * Update current filtering settings
     * @param vpn VPN client
     * @param mode the VPN mode
     * @return true if updated successfully, false otherwise
     */
    bool update_exclusions(VpnMode mode, std::string_view exclusions);

    /**
     * Match domain name against exclusion list. Logic of matching is explained in
     * `VpnSettings.exclusions` description.
     * @note Always returns some value (not `DFMS_NONE`) as we are sure what to do with the
     * connection with known domain name.
     * @param domain domain name
     */
    [[nodiscard]] DomainFilterMatchStatus match_domain(std::string_view domain) const;

    /**
     * Match address tag against exclusion list. Logic of matching is explained in
     * `VpnSettings.exclusions` description.
     * @param tag address tag
     */
    [[nodiscard]] DomainFilterMatchResult match_tag(const SockAddrTag &tag) const;

    /**
     * Add resolved tag in cache
     * @param tag address tag
     * @param domain domain name
     */
    void add_resolved_tag(SockAddrTag tag, std::string domain);

    /**
     * Add an IP address which is suspected to belong to an exclusion
     * @param addr the IP address
     * @param ttl record TTL
     */
    void add_exclusion_suspect(const SocketAddress &addr, std::chrono::seconds ttl);

    /**
     * Get list of the DNS-resolvable exclusions
     */
    [[nodiscard]] std::vector<std::string_view> get_resolvable_exclusions() const;

    /**
     * Get the current VPN mode
     */
    [[nodiscard]] VpnMode get_mode() const;

private:
    enum MatchFlags : uint32_t;
    using MatchFlagsSet = std::bitset<width_of<MatchFlags>()>;
    struct DomainEntryInfo {
        std::string text;
        MatchFlagsSet flags;
    };
    struct DomainEntryMalformed{};
    using ParseResult = std::variant<SocketAddress, CidrRange, DomainEntryInfo, DomainEntryMalformed>;

    VpnMode m_mode = VPN_MODE_GENERAL;
    std::unordered_map<std::string, MatchFlagsSet> m_domains; // key - domain name / value - set of `MatchFlags`
    std::unordered_set<SocketAddress> m_addresses;
    ag::CidrRangeSet m_cidr_ranges;
    ag::LruTimeoutCache<ag::SockAddrTag, std::string> m_resolved_tags{DEFAULT_CACHE_SIZE, DEFAULT_TAG_TTL};
    ag::LruTimeoutCache<SocketAddress, uint8_t> m_exclusion_suspects{DEFAULT_CACHE_SIZE, DEFAULT_TAG_TTL};
    ag::Logger m_log{"DOMAIN_FILTER"};

    static ParseResult parse_entry(std::string_view entry);
};

} // namespace ag
