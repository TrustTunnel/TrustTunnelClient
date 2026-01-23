#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

#include <event2/util.h>

#include "common/socket_address.h"
#include "dns/dnsstamp/dns_stamp.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

#include "default_settings.h"

namespace ag {

static std::atomic_bool g_handler_profiling_enabled = VPN_DEFAULT_HANDLER_PROFILING_ENABLED;
static std::atomic_bool g_post_quantum_group_enabled = VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED;

static constexpr uint32_t DEFAULT_HANDLER_PROFILING_THRESHOLD_NS = 5'000'000; // 5 milliseconds

#ifndef IN6_IS_ADDR_UNIQUE_LOCAL
inline bool IN6_IS_ADDR_UNIQUE_LOCAL(const struct in6_addr *addr) {
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    return ((addr->s6_addr[0] == 0xfc) || (addr->s6_addr[0] == 0xfd));
}
#endif

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
uint64_t hash_pair_combine(uint64_t h1, uint64_t h2) {
    uint64_t hash = 17;
    hash = hash * 31 + h1;
    hash = hash * 31 + h2;
    return hash;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

uint64_t ip_addr_hash(sa_family_t family, const void *addr) {
    uint64_t hash = 0;

    switch (family) {
    case AF_INET:
        memcpy(&hash, addr, sizeof(uint32_t));
        break;
    case AF_INET6: {
        uint64_t ip_1; // NOLINT(cppcoreguidelines-init-variables)
        uint64_t ip_2; // NOLINT(cppcoreguidelines-init-variables)
        memcpy(&ip_1, addr, sizeof(ip_1));
        memcpy(&ip_2, (uint8_t *) addr + sizeof(ip_1), sizeof(ip_2));
        hash = hash_pair_combine(ip_1, ip_2);
        break;
    }
    }

    return hash;
}

uint64_t socket_address_hash(const SocketAddress &addr) {
    return std::hash<SocketAddress>{}(addr);
}

SocketAddressStorage sockaddr_from_str(const char *str) {
    SocketAddress addr(str);
    return *addr.c_storage();
}

void sockaddr_from_str_out(const char *str, struct SocketAddressStorage *result) {
    SocketAddressStorage local_result = sockaddr_from_str(str);
    std::memcpy(result, &local_result, sizeof(SocketAddressStorage));
}

SocketAddress local_socket_address_from_fd(evutil_socket_t fd) {
    SocketAddressStorage addr = {};
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        std::memset(&addr, 0, sizeof(addr));
    }
    return SocketAddress(addr);
}

SocketAddress remote_socket_address_from_fd(evutil_socket_t fd) {
    SocketAddressStorage addr{};
    socklen_t addrlen = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        std::memset(&addr, 0, sizeof(addr));
    }
    return SocketAddress(addr);
}

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
uint32_t str_hash32(const char *str, size_t length) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < length; ++i) {
        hash = (hash * 33) ^ (uint32_t) str[i];
    }
    return hash;
}
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)

// NOLINTBEGIN(cert-dcl50-cpp)
std::string str_format(const char *fmt, ...) {
    int r;
    std::string s;
    va_list va;

    va_start(va, fmt);
    r = vsnprintf(nullptr, 0, fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }
    s.resize(r + 1);

    va_start(va, fmt);
    r = vsnprintf(s.data(), s.capacity(), fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }
    s.resize(r);

    return s;
}
// NOLINTEND(cert-dcl50-cpp)

std::string encode_to_hex(U8View data) {
    static constexpr char TABLE[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.length() * 2);
    for (uint8_t c : data) {
        out.push_back(TABLE[(c >> 4) // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                & 0xf]);             // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
        out.push_back(TABLE[c        // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
                & 0xf]);             // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
    }
    return out;
}

char *safe_strdup(const char *s) {
    return (s != nullptr) ? strdup(s) : nullptr;
}

VpnError make_vpn_error_from_fd([[maybe_unused]] evutil_socket_t fd) {
    return make_vpn_from_socket_error(evutil_socket_geterror(fd));
}

VpnError make_vpn_from_socket_error(int code) {
    return {code, evutil_socket_error_to_string(code)};
}

std::string escape_non_print(U8View data) {
    std::string s;
    s.reserve(data.size());
    for (uint8_t b : data) {
        if (std::isprint((unsigned char) b)) {
            s.push_back((char) b);
        } else {
            s.push_back('?');
        }
    }
    return s;
}

int64_t get_time_monotonic_nanos() {
    static constexpr int64_t NSEC_PER_SEC = 1'000'000'000;

#ifdef _WIN32

    LARGE_INTEGER count; // ticks
    LARGE_INTEGER freq;  // ticks * second ^ -1

    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);

    count.QuadPart *= NSEC_PER_SEC;
    count.QuadPart /= freq.QuadPart;

    return count.QuadPart;

#else // _WIN32

    timespec ts{};

#ifdef __linux__
    clock_gettime(CLOCK_BOOTTIME, &ts);
#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

    return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

#endif // _WIN32
}

bool case_equals(std::string_view a, std::string_view b) {
    return a.size() == b.size() && 0 == evutil_ascii_strncasecmp(a.data(), b.data(), b.size());
}

static const char *marshal_str(const std::string &str) {
    return str.empty() ? nullptr : strdup(str.c_str());
}

// NOLINTBEGIN(cppcoreguidelines-no-malloc,hicpp-no-malloc)
static VpnBuffer marshal_buffer(U8View v) {
    VpnBuffer c_buffer;
    c_buffer.size = v.size();
    c_buffer.data = (uint8_t *) std::malloc(c_buffer.size);
    std::memcpy((void *) c_buffer.data, v.data(), c_buffer.size);
    return c_buffer;
}

VpnDnsStamp *vpn_dns_stamp_from_str(const char *stamp_str, const char **error) {
    auto res = dns::ServerStamp::from_string(stamp_str);
    if (res.has_error()) {
        *error = marshal_str(res.error()->str());
        return nullptr;
    }
    const dns::ServerStamp &stamp = res.value();
    static_assert(std::is_trivial_v<VpnDnsStamp>);
    auto *c_result = (VpnDnsStamp *) std::calloc(1, sizeof(VpnDnsStamp));
    c_result->proto = (VpnDnsStampProtocol) stamp.proto;
    c_result->path = marshal_str(stamp.path);
    c_result->server_addr = marshal_str(stamp.server_addr_str);
    c_result->provider_name = marshal_str(stamp.provider_name);
    if (const auto &key = stamp.server_pk; !key.empty()) {
        c_result->server_public_key = marshal_buffer({key.data(), key.size()});
    }
    if (const auto &hashes = stamp.hashes; !hashes.empty()) {
        c_result->hashes = {(VpnBuffer *) std::malloc(hashes.size() * sizeof(VpnBuffer)), (uint32_t) hashes.size()};
        for (size_t i = 0; i < hashes.size(); ++i) {
            const auto &h = hashes[i];
            c_result->hashes.data[i] = marshal_buffer({h.data(), h.size()});
        }
    }
    if (stamp.props.has_value()) {
        c_result->properties = (VpnDnsStampInformalProperties *) calloc(1, sizeof(VpnDnsStampInformalProperties));
        *c_result->properties = (VpnDnsStampInformalProperties) stamp.props.value();
    }
    return c_result;
}

void vpn_dns_stamp_free(VpnDnsStamp *stamp) {
    if (!stamp) {
        return;
    }
    std::free((void *) stamp->path);
    std::free((void *) stamp->server_addr);
    std::free((void *) stamp->provider_name);
    std::free(stamp->server_public_key.data);
    for (uint32_t i = 0; i < stamp->hashes.size; ++i) {
        std::free(stamp->hashes.data[i].data);
    }
    std::free((void *) stamp->hashes.data);
    std::free(stamp->properties);
    std::free(stamp);
}

static dns::ServerStamp marshal_stamp(const VpnDnsStamp *c_stamp) {
    dns::ServerStamp stamp{};
    stamp.proto = (dns::StampProtoType) c_stamp->proto;
    if (c_stamp->path) {
        stamp.path = c_stamp->path;
    }
    if (c_stamp->server_addr) {
        stamp.server_addr_str = c_stamp->server_addr;
    }
    if (c_stamp->provider_name) {
        stamp.provider_name = c_stamp->provider_name;
    }
    stamp.server_pk.assign(
            c_stamp->server_public_key.data, c_stamp->server_public_key.data + c_stamp->server_public_key.size);
    stamp.hashes.reserve(c_stamp->hashes.size);
    for (size_t i = 0; i < c_stamp->hashes.size; ++i) {
        const VpnBuffer &hash = c_stamp->hashes.data[i];
        stamp.hashes.emplace_back(hash.data, hash.data + hash.size);
    }
    if (c_stamp->properties) {
        stamp.props = (dns::ServerInformalProperties) *c_stamp->properties;
    }
    return stamp;
}

const char *vpn_dns_stamp_to_str(VpnDnsStamp *c_stamp) {
    dns::ServerStamp stamp = marshal_stamp(c_stamp);
    return marshal_str(stamp.str());
}

const char *vpn_dns_stamp_pretty_url(VpnDnsStamp *c_stamp) {
    dns::ServerStamp stamp = marshal_stamp(c_stamp);
    return marshal_str(stamp.pretty_url(false));
}

const char *vpn_dns_stamp_prettier_url(VpnDnsStamp *c_stamp) {
    dns::ServerStamp stamp = marshal_stamp(c_stamp);
    return marshal_str(stamp.pretty_url(true));
}

void vpn_string_free(const char *s) {
    std::free((void *) s);
}

VpnDefaultSettings *vpn_get_default_settings() {
    auto *settings = (VpnDefaultSettings *) std::malloc(sizeof(VpnDefaultSettings));
    if (settings == nullptr) {
        return nullptr;
    }
    settings->post_quantum_group_enabled = VPN_DEFAULT_POST_QUANTUM_GROUP_ENABLED;
    settings->handler_profiling_enabled = VPN_DEFAULT_HANDLER_PROFILING_ENABLED;
    return settings;
}

void vpn_free_default_settings(VpnDefaultSettings *settings) {
    if (settings == nullptr) {
        return;
    }
    std::free(settings);
}
// NOLINTEND(cppcoreguidelines-no-malloc,hicpp-no-malloc)

uint32_t ntoh_24(uint32_t x) {
    const auto *b = (uint8_t *) &x;
    return (b[0] << 16) | (b[1] << 8) | b[2]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

void vpn_handler_profiling_set_enabled(bool enabled) {
    g_handler_profiling_enabled.store(enabled, std::memory_order_relaxed);
}

bool vpn_handler_profiling_enabled() {
    return g_handler_profiling_enabled.load(std::memory_order_relaxed);
}

uint32_t vpn_handler_profiling_threshold_ns() {
    return DEFAULT_HANDLER_PROFILING_THRESHOLD_NS;
}

void vpn_post_quantum_group_set_enabled(bool enabled) {
    g_post_quantum_group_enabled.store(enabled, std::memory_order_relaxed);
}

bool vpn_post_quantum_group_enabled() {
    return g_post_quantum_group_enabled.load(std::memory_order_relaxed);
}

} // namespace ag
