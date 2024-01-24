#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

#include <event2/util.h>

#include "dns/dnsstamp/dns_stamp.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

#ifndef IN6_IS_ADDR_UNIQUE_LOCAL
inline bool IN6_IS_ADDR_UNIQUE_LOCAL(const struct in6_addr *addr) {
    return ((addr->s6_addr[0] == 0xfc) || (addr->s6_addr[0] == 0xfd));
}
#endif

size_t sockaddr_get_size(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return sizeof(struct sockaddr_in);
    case AF_INET6:
        return sizeof(struct sockaddr_in6);
    default:
        return 0;
    }
}

bool sockaddr_is_any(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return htonl(INADDR_ANY) == ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    case AF_INET6:
        // in6addr_any is already in network order
        return 0 == memcmp(&((struct sockaddr_in6 *) addr)->sin6_addr, &in6addr_any, sizeof(in6addr_any));
    default:
        return false;
    }
}

bool sockaddr_is_loopback(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return (INADDR_LOOPBACK & 0xff000000) == (ntohl(((struct sockaddr_in *) addr)->sin_addr.s_addr) & 0xff000000);
    case AF_INET6:
        // in6addr_loopback is already in network order
        return 0 == memcmp(&((struct sockaddr_in6 *) addr)->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback));
    default:
        return false;
    }
}

uint16_t sockaddr_get_raw_port(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return ((struct sockaddr_in *) addr)->sin_port;
    case AF_INET6:
        return ((struct sockaddr_in6 *) addr)->sin6_port;
    default:
        return 0;
    }
}

uint16_t sockaddr_get_port(const struct sockaddr *addr) {
    return ntohs(sockaddr_get_raw_port(addr));
}

void sockaddr_set_port(struct sockaddr *addr, int port) {
    switch (addr->sa_family) {
    case AF_INET:
        ((struct sockaddr_in *) addr)->sin_port = htons(port);
        break;
    case AF_INET6:
        ((struct sockaddr_in6 *) addr)->sin6_port = htons(port);
        break;
    }
}

void *sockaddr_get_ip_ptr(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return &((struct sockaddr_in *) addr)->sin_addr;
    case AF_INET6:
        return &((struct sockaddr_in6 *) addr)->sin6_addr;
    default:
        return NULL;
    }
}

size_t sockaddr_get_ip_size(const struct sockaddr *addr) {
    switch (addr->sa_family) {
    case AF_INET:
        return sizeof(((struct sockaddr_in *) addr)->sin_addr);
    case AF_INET6:
        return sizeof(((struct sockaddr_in6 *) addr)->sin6_addr);
    default:
        return 0;
    }
}

bool sockaddr_equals(const struct sockaddr *lh, const struct sockaddr *rh) {
    ev_socklen_t len = sockaddr_get_size(lh);
    return lh->sa_family == rh->sa_family && (len == 0 || 0 == memcmp(lh->sa_data, rh->sa_data, len - offsetof(sockaddr, sa_data)));
}

ssize_t sockaddr_ip_to_str(const struct sockaddr *addr, char *buf, size_t buf_size) {
    const char *orig_buf = buf;
    if (addr->sa_family == AF_INET6 && buf_size > 0) {
        *buf++ = '[';
        --buf_size;
    }

    if (NULL == evutil_inet_ntop(addr->sa_family, sockaddr_get_ip_ptr(addr), buf, buf_size)) {
        snprintf(buf, buf_size, "__conversion error__");
        return -1;
    }

    size_t addr_len = strlen(buf);
    buf += addr_len;
    buf_size -= addr_len;

    if (addr->sa_family == AF_INET6 && buf_size > 0) {
        *buf++ = ']';
        *buf = '\0';
        --buf_size;
    }

    return buf - orig_buf;
}

bool sockaddr_to_str(const struct sockaddr *addr, char *buf, size_t buf_size) {
    ssize_t size = sockaddr_ip_to_str(addr, buf, buf_size);
    if (size < 0) {
        return false;
    }

    snprintf(&buf[size], buf_size - size, ":%d", sockaddr_get_port(addr));
    return true;
}

uint64_t hash_pair_combine(uint64_t h1, uint64_t h2) {
    uint64_t hash = 17;
    hash = hash * 31 + h1;
    hash = hash * 31 + h2;
    return hash;
}

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

uint64_t sockaddr_hash(const struct sockaddr *addr) {
    return hash_pair_combine(ip_addr_hash(addr->sa_family, sockaddr_get_ip_ptr(addr)), sockaddr_get_port(addr));
}

uint64_t sockaddr_pair_hash(const struct sockaddr *src, const struct sockaddr *dst) {
    return hash_pair_combine(sockaddr_hash(src), sockaddr_hash(dst));
}

struct sockaddr_storage sockaddr_from_raw(const uint8_t *src, size_t size, uint16_t port) {
    struct sockaddr_storage result = {};

    switch (size) {
    case 4: {
        struct sockaddr_in *sin = (struct sockaddr_in *) &result;
        sin->sin_family = AF_INET;
        sin->sin_port = port;
        sin->sin_addr.s_addr = *(uint32_t *) src;
#ifdef SIN6_LEN
        sin->sin_len = sizeof(struct sockaddr_in);
#endif
        break;
    }
    case 16: {
        struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &result;
        sin->sin6_family = AF_INET6;
        sin->sin6_port = port;
        memcpy(sin->sin6_addr.s6_addr, src, size);
#ifdef SIN6_LEN
        sin->sin6_len = sizeof(struct sockaddr_in6);
#endif
        break;
    }
    }

    return result;
}

void sockaddr_from_str_out(const char *str, struct sockaddr_storage *result) {
    sockaddr_storage local_result = sockaddr_from_str(str);
    std::memcpy(result, &local_result, sizeof(sockaddr_storage));
}

struct sockaddr_storage sockaddr_to_storage(const struct sockaddr *addr) {
    void *ip = sockaddr_get_ip_ptr(addr);
    return (ip != nullptr)
            ? sockaddr_from_raw((uint8_t *) ip, (addr->sa_family == AF_INET) ? 4 : 16, htons(sockaddr_get_port(addr)))
            : sockaddr_storage{};
}

struct sockaddr_storage sockaddr_from_str(const char *str) {
    struct sockaddr_storage addr = {};
    int addr_len = sizeof(addr);

    if (str != NULL && 0 != evutil_parse_sockaddr_port(str, (struct sockaddr *) &addr, &addr_len)) {
        std::memset(&addr, 0, sizeof(addr));
    }

    return addr;
}

struct sockaddr_storage local_sockaddr_from_fd(evutil_socket_t fd) {
    struct sockaddr_storage addr = {};
    socklen_t addrlen = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        std::memset(&addr, 0, sizeof(addr));
    }
    return addr;
}

struct sockaddr_storage remote_sockaddr_from_fd(evutil_socket_t fd) {
    struct sockaddr_storage addr = {};
    socklen_t addrlen = sizeof(addr);
    if (getpeername(fd, (struct sockaddr *) &addr, &addrlen) != 0) {
        std::memset(&addr, 0, sizeof(addr));
    }
    return addr;
}

uint32_t str_hash32(const char *str, size_t length) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < length; ++i) {
        hash = (hash * 33) ^ (uint32_t) str[i];
    }
    return hash;
}

std::string sockaddr_ip_to_str(const struct sockaddr *addr) {
    char buf[SOCKADDR_STR_BUF_SIZE];
    sockaddr_ip_to_str(addr, buf, sizeof(buf));
    return buf;
}

std::string sockaddr_to_str(const struct sockaddr *addr) {
    char buf[SOCKADDR_STR_BUF_SIZE];
    sockaddr_to_str(addr, buf, sizeof(buf));
    return buf;
}

std::string str_format(const char *fmt, ...) {
    int r;
    std::string s;
    va_list va;

    va_start(va, fmt);
    r = vsnprintf(NULL, 0, fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }
    s.resize(r + 1);

    va_start(va, fmt);
    r = vsnprintf(&s[0], s.capacity(), fmt, va);
    va_end(va);
    if (r < 0) {
        return {};
    }
    s.resize(r);

    return s;
}

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
    c_result->properties = (VpnDnsStampInformalProperties) stamp.props;
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
    stamp.server_pk.assign(c_stamp->server_public_key.data,
            c_stamp->server_public_key.data + c_stamp->server_public_key.size);
    stamp.hashes.reserve(c_stamp->hashes.size);
    for (size_t i = 0; i < c_stamp->hashes.size; ++i) {
        const VpnBuffer &hash = c_stamp->hashes.data[i];
        stamp.hashes.emplace_back(hash.data, hash.data + hash.size);
    }
    stamp.props = (dns::ServerInformalProperties) c_stamp->properties;
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

uint32_t ntoh_24(uint32_t x) {
    const auto *b = (uint8_t *)&x;
    return (b[0] << 16) | (b[1] << 8) | b[2]; // NOLINT(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers)
}

} // namespace ag
