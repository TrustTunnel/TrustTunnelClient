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

DomainFilterValidationStatus DomainFilter::validate_entry(std::string_view entry) {
    ParseResult result = parse_entry(entry);
    static_assert(std::is_same_v<typename std::variant_alternative<DFVS_OK_ADDR, ParseResult>::type, SocketAddress>);
    static_assert(std::is_same_v<typename std::variant_alternative<DFVS_OK_CIDR, ParseResult>::type, CidrRange>);
    static_assert(std::is_same_v<typename std::variant_alternative<DFVS_OK_DOMAIN, ParseResult>::type, DomainEntryInfo>);
    static_assert(std::is_same_v<typename std::variant_alternative<DFVS_MALFORMED, ParseResult>::type, DomainEntryMalformed>);
    static_assert(std::variant_size<ParseResult>::value == 4);

    return DomainFilterValidationStatus(result.index());
}

DomainFilter::ParseResult DomainFilter::parse_entry(std::string_view entry) {
    SocketAddress addr{};
    Result split = utils::split_host_port(entry);
    if (!split.has_error()) {
        std::optional port = utils::to_integer<uint64_t>(split->second);
        if (port.has_value() && !split->second.empty()) {
            if (port > 0 && port <= USHRT_MAX) {
                addr = SocketAddress(split->first, port.value());
            }
        } else {
            addr = SocketAddress(split->first);
        }
        if (addr.valid()) {
            return addr;
        }
    }

    if (auto range = ag::CidrRange(entry); range.valid()) {
        return range;
    }

    std::string_view domain = entry;
    if (domain.starts_with("*.")) {
        domain.remove_prefix(2);
    }
    if (domain.empty()) {
        return DomainEntryMalformed{};
    }
    for (char last_ch = '.'; char ch : domain) {
        if (!isalnum(ch) && ch != '-' && ch != '_' && ch != '.') {
            return DomainEntryMalformed{};
        }
        if (ch == '.' && last_ch == '.') {
            return DomainEntryMalformed{};
        }
        last_ch = ch;
    }

    MatchFlagsSet match_flags;

    if (starts_with(entry, WILDCARD_PREFIX)) {
        entry.remove_prefix(WILDCARD_PREFIX.length());
        match_flags.set(DFMM_SUBDOMAINS);
    } else {
        match_flags.set(DFMM_EXACT);
        if (starts_with(entry, WWW_PREFIX)) {
            entry.remove_prefix(WWW_PREFIX.length());
        }
    }

    return DomainEntryInfo{std::string(entry), match_flags};
}

bool DomainFilter::update_exclusions(VpnMode mode_, std::string_view exclusions) {
    m_mode = mode_;
    m_domains.clear();
    m_addresses.clear();
    m_exclusion_suspects.clear();
    m_cidr_ranges.clear();

    auto add_entry = [this](const std::string &entry) {
        ParseResult result = parse_entry(entry);
        if (const auto *addr = std::get_if<SocketAddress>(&result); addr != nullptr) {
            log_filter(this, trace, "Entry added in address table: {}", entry);
            m_addresses.insert(*addr);
        } else if (auto *domain_info = std::get_if<DomainEntryInfo>(&result); domain_info != nullptr) {
            log_filter(this, trace, "Entry added in domain table: {}", domain_info->text);
            m_domains[std::move(domain_info->text)] |= domain_info->flags;
        } else if (auto *range = std::get_if<CidrRange>(&result); range != nullptr) {
            log_filter(this, trace, "Entry added in CIDR ranges table: {}", range->to_string());
            m_cidr_ranges.insert(*range);
        } else {
            auto status = std::get<DomainEntryMalformed>(result);
            (void) status;
            log_filter(this, warn, "Malformed entry detected in exceptions list: {}", entry);
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

DomainFilterMatchResult DomainFilter::match_tag(const SockAddrTag &tag) const {
    DomainFilterMatchResult result{.status = DFMS_DEFAULT};

    SocketAddress addr_no_port = tag.addr;
    addr_no_port.set_port(0);

    bool found = m_addresses.end() != m_addresses.find(tag.addr);
    if (!found) {
        found = m_addresses.end() != m_addresses.find(addr_no_port);
    }

    if (!found) {
        const Uint8View addr = tag.addr.addr();
        ag::CidrRange addr_cidr(addr, addr.size() * 8);
        found = m_cidr_ranges.includes(addr_cidr);
    }

    if (found) {
        log_filter(this, trace, "Address matched against exclusion list: {}", tag.addr);
        result.status = DFMS_EXCLUSION;
    } else if (auto domain = m_resolved_tags.get(tag)) {
        log_filter(this, dbg, "Cache hit: {}#{} -> {}", tag.addr, tag.appname, *domain);
        result.status = match_domain(*domain);
        result.domain = *domain;
    } else if (m_exclusion_suspects.get(addr_no_port)) {
        result.status = DFMS_SUSPECT_EXCLUSION;
    }

    return result;
}

void DomainFilter::add_resolved_tag(SockAddrTag tag, std::string domain) {
    log_filter(this, dbg, "{}#{} -> {}", tag.addr, tag.appname, domain);

    m_resolved_tags.insert(std::move(tag), std::move(domain));
}

void DomainFilter::add_exclusion_suspect(const SocketAddress &addr_, std::chrono::seconds ttl) {
    SocketAddress addr = addr_;
    addr.set_port(0);
    log_filter(this, dbg, "{} / {}", addr.host_str(/*ipv6_brackets=*/true), ttl);

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
