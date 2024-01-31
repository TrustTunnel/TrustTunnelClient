#include "vpn/internal/domain_filter.h"

#include "common/defs.h"
#include "vpn/internal/utils.h"
#include "vpn/utils.h"

#define log_filter(f_, lvl_, fmt_, ...) lvl_##log((f_)->m_log, fmt_, ##__VA_ARGS__)

namespace ag {

static constexpr std::string_view WWW_PREFIX = "www.";
static constexpr std::string_view WILDCARD_PREFIX = "*.";

enum DomainFilter::MatchFlags : uint32_t {
    DFMM_EXACT,      // match the domain itself and www. + the domain
    DFMM_SUBDOMAINS, // match only subdomains and www. + the domain, but not the domain itself
};

DomainFilter::DomainFilter() = default;

DomainFilter::~DomainFilter() = default;

DomainFilterValidationStatus DomainFilter::validate_entry(const std::string &entry) {
    ParseResult result = parse_entry(entry);
    if (const auto *status = std::get_if<DomainFilterValidationStatus>(&result);
            status != nullptr && *status != DFVS_OK) {
        return *status;
    }

    return DFVS_OK;
}

DomainFilter::ParseResult DomainFilter::parse_entry(const std::string &entry) {
    if (sockaddr_storage addr = sockaddr_from_str(entry.c_str()); addr.ss_family != AF_UNSPEC) {
        return addr;
    }
    
    if (auto range = ag::CidrRange(entry); range.valid()) {
        return range;
    }

    if (entry.npos == entry.find_first_of(":/")) {
        MatchFlagsSet match_flags;

        std::string_view prepared_entry = entry;
        if (starts_with(prepared_entry, WILDCARD_PREFIX)) {
            prepared_entry.remove_prefix(WILDCARD_PREFIX.length());
            match_flags.set(DFMM_SUBDOMAINS);
        } else {
            match_flags.set(DFMM_EXACT);
            if (starts_with(prepared_entry, WWW_PREFIX)) {
                prepared_entry.remove_prefix(WWW_PREFIX.length());
            }
        }

        return DomainEntryInfo{std::string(prepared_entry), match_flags};
    }

    return DFVS_MALFORMED;
}

bool DomainFilter::update_exclusions(VpnMode mode_, std::string_view exclusions) {
    m_mode = mode_;
    m_domains.clear();
    m_addresses.clear();
    m_exclusion_suspects.clear();
    m_cidr_ranges.clear();

    auto add_entry = [this](const std::string &entry) {
        ParseResult result = parse_entry(entry);
        if (const auto *addr = std::get_if<sockaddr_storage>(&result); addr != nullptr) {
            log_filter(this, trace, "Entry added in address table: {}", entry);
            m_addresses.insert(*addr);
        } else if (auto *domain_info = std::get_if<DomainEntryInfo>(&result); domain_info != nullptr) {
            log_filter(this, trace, "Entry added in domain table: {}", domain_info->text);
            m_domains[std::move(domain_info->text)] |= domain_info->flags;
        } else if (auto *range = std::get_if<CidrRange>(&result); range != nullptr) {
            log_filter(this, trace, "Entry added in CIDR ranges table: {}", range->to_string());
            m_cidr_ranges.insert(*range);
        } else {
            auto status = std::get<DomainFilterValidationStatus>(result);
            log_filter(this, warn, "Malformed entry detected in exceptions list: {} ({})", entry,
                    magic_enum::enum_name(status));
        }
    };

    std::string buffer;

    for (char ch : exclusions) {
        if (!isspace(ch)) {
            buffer.push_back(ch);
        } else if (!buffer.empty()) {
            add_entry(buffer);
            buffer.clear();
        }
    }

    if (!buffer.empty()) {
        add_entry(buffer);
    }

    return true;
}

DomainFilterMatchStatus DomainFilter::match_domain(std::string_view domain) const {
    bool www_prefixed = starts_with(domain, WWW_PREFIX);
    std::string seek = !www_prefixed ? std::string(domain) : std::string(domain.substr(WWW_PREFIX.length()));

    while (true) {
        auto i = m_domains.find(seek);
        if (i != m_domains.end()) {
            MatchFlagsSet flags = i->second;

            bool found = (flags.test(DFMM_EXACT)
                                 && (seek.length() == domain.length()
                                         || (www_prefixed && seek.length() + WWW_PREFIX.length() == domain.length())))
                    || (flags.test(DFMM_SUBDOMAINS) && (seek.length() < domain.length()));
            if (found) {
                log_filter(this, dbg, "Matched domain: {}", seek);
                return DFMS_EXCLUSION;
            }
        }

        size_t next_dot = seek.find('.');
        if (next_dot == std::string::npos || next_dot + 1 == seek.length()) {
            break;
        }

        seek.erase(0, next_dot + 1);
    }

    return DFMS_DEFAULT;
}

DomainFilterMatchStatus DomainFilter::match_tag(const SockAddrTag &tag) const {
    DomainFilterMatchStatus result = DFMS_DEFAULT;

    char addr_str[SOCKADDR_STR_BUF_SIZE];
    if (m_log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
        sockaddr_to_str((sockaddr *) &tag.addr, addr_str, sizeof(addr_str));
    }

    sockaddr_storage addr_no_port = tag.addr;
    sockaddr_set_port((sockaddr *) &addr_no_port, 0);

    bool found = m_addresses.end() != m_addresses.find(tag.addr);
    if (!found) {
        found = m_addresses.end() != m_addresses.find(addr_no_port);
    }

    if (!found) {
        auto addr_size = sockaddr_get_ip_size((sockaddr *) &tag.addr);
        ag::CidrRange addr_cidr = ag::CidrRange(
                Uint8View((uint8_t *) sockaddr_get_ip_ptr((sockaddr *) &tag.addr), addr_size), addr_size * 8);
        found = std::any_of(m_cidr_ranges.begin(), m_cidr_ranges.upper_bound(addr_cidr), [&](const auto &range) {
            return range.contains(addr_cidr);
        });
    }

    if (found) {
        log_filter(this, trace, "Address matched against exclusion list: {}", addr_str);
        result = DFMS_EXCLUSION;
    } else if (auto domain = m_resolved_tags.get(tag)) {
        log_filter(this, dbg, "Cache hit: {}#{} -> {}", addr_str, tag.appname, *domain);
        result = match_domain(*domain);
    } else if (m_exclusion_suspects.get(addr_no_port)) {
        result = DFMS_SUSPECT_EXCLUSION;
    }

    return result;
}

void DomainFilter::add_resolved_tag(SockAddrTag tag, std::string domain) {
    log_filter(this, dbg, "{}#{} -> {}", sockaddr_to_str((sockaddr *) &tag.addr), tag.appname, domain);

    m_resolved_tags.insert(std::move(tag), std::move(domain));
}

void DomainFilter::add_exclusion_suspect(const sockaddr_storage &addr_, std::chrono::seconds ttl) {
    sockaddr_storage addr = addr_;
    sockaddr_set_port((sockaddr *) &addr, 0);
    log_filter(this, dbg, "{} / {}", sockaddr_ip_to_str((sockaddr *) &addr), ttl);

    // @todo: fix TTL reduction caused by overwriting it by an entry with a smaller TTL
    m_exclusion_suspects.insert(addr, 0, ttl);
}

std::vector<std::string_view> DomainFilter::get_resolvable_exclusions() const {
    std::vector<std::string_view> names;
    for (const auto &[name, flags] : m_domains) {
        if (flags.test(DFMM_EXACT)) {
            names.emplace_back(name);
        }
    }

    return names;
}

VpnMode DomainFilter::get_mode() const {
    return m_mode;
}

} // namespace ag
