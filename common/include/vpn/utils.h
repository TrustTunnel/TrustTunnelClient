#pragma once

#include <bitset>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>

#include <event2/util.h>

#include "common/defs.h"
#include "common/socket_address.h"
#include "vpn/platform.h"

namespace ag {

struct VpnError {
    int code;
    const char *text;
};

/**
 * Communication protocols between a VPN client and an endpoint
 */
typedef enum {
    VPN_UP_HTTP2, // HTTP/2 only.
    VPN_UP_HTTP3, // HTTP/3, with mandatory fallback to HTTP/2.
    VPN_UP_AUTO,  // VpnEndpoint: Try HTTP/2 and HTTP/3 simultaneously, use the first successful connection.
                  // VpnUpstreamConfig: Use endpoints' preferred protocol.
} VpnUpstreamProtocol;

struct VpnConnectionStats {
    uint32_t rtt_us;          // RTT in microseconds
    double packet_loss_ratio; // the ratio of the number of lost packets to the total number of sent packets
};

// The longest ipv6 address len (45) + brackets (2) + port delimiter (1) + maximum port length (5) + null (1)
#define SOCKADDR_STR_BUF_SIZE (INET6_ADDRSTRLEN + 8)

struct TcpFlowCtrlInfo {
    size_t send_buffer_size; // free space in a connection write buffer
    size_t send_window_size; // size of a connection send window
};

// Default values for `TcpFlowCtrlInfo` if there is no way to get real values
#define DEFAULT_SEND_BUFFER_SIZE (8 * 1024 * 1024)
#define DEFAULT_SEND_WINDOW_SIZE (8 * 1024 * 1024)

// For use in C interfaces. `uint32_t` to make it easier for C# bindings.
#define AG_ARRAY_OF(T)                                                                                                 \
    struct {                                                                                                           \
        T *data;                                                                                                       \
        uint32_t size;                                                                                                 \
    }

// May be owning or non-owning depending on context
typedef AG_ARRAY_OF(const char) VpnStr;
#define VPNSTR_INIT(c_string) {c_string, (c_string) ? uint32_t(strlen(c_string)) : 0}

// QUIC defaults
static constexpr size_t QUIC_LOCAL_CONN_ID_LEN = 16;
static constexpr uint64_t QUIC_CONNECTION_WINDOW_SIZE = 100ul * 1024 * 1024;
static constexpr uint64_t QUIC_STREAM_WINDOW_SIZE = 1ul * 1024 * 1024;
static constexpr uint64_t QUIC_MAX_STREAMS_NUM = 4ul * 1024;
static constexpr size_t QUIC_MAX_UDP_PAYLOAD_SIZE = 1350;
static constexpr uint8_t QUIC_H3_ALPN_PROTOS[] = {2, 'h', '3'};

// TCP defaults
static constexpr size_t TCP_READ_THRESHOLD = 0;
#ifdef _WIN32
static constexpr bool TCP_RECORD_ESTATS = true;
#endif
static constexpr uint8_t TCP_TLS_ALPN_PROTOS[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

typedef enum {
    VDSP_PLAIN,
    VDSP_DNSCRYPT,
    VDSP_DOH,
    VDSP_TLS,
    VDSP_DOQ,
} VpnDnsStampProtocol;

typedef enum {
    /** Resolver does DNSSEC validation */
    VDSIP_DNSSEC = 1 << 0,
    /** Resolver does not record logs */
    VDSIP_NO_LOG = 1 << 1,
    /** Resolver doesn't intentionally block domains */
    VDSIP_NO_FILTER = 1 << 2,
} VpnDnsStampInformalProperties;

typedef AG_ARRAY_OF(uint8_t) VpnBuffer;

typedef struct {
    /** Protocol */
    VpnDnsStampProtocol proto;
    /** IP address and/or port */
    const char *server_addr;
    /**
     * Provider means different things depending on the stamp type
     * DNSCrypt: the DNSCrypt provider name
     * DOH and DOT: server's hostname
     * Plain DNS: not specified
     */
    const char *provider_name;
    /** (For DoH) absolute URI path, such as /dns-query */
    const char *path;
    /** The DNSCrypt provider’s Ed25519 public key, as 32 raw bytes. Empty for other types. */
    VpnBuffer server_public_key;
    /**
     * Hash is the SHA256 digest of one of the TBS certificate found in the validation chain, typically
     * the certificate used to sign the resolver’s certificate. Multiple hashes can be provided for seamless
     * rotations.
     */
    AG_ARRAY_OF(VpnBuffer) hashes;
    /** Server properties */
    VpnDnsStampInformalProperties *properties;
} VpnDnsStamp;

typedef struct {
    uint8_t *data;
    size_t size;
    void (*destructor)(void *destructor_arg, uint8_t *data);
    void *destructor_arg;
} VpnPacket;

typedef AG_ARRAY_OF(VpnPacket) VpnPackets;

class VpnPacketsHolder {
public:
    VpnPacketsHolder() = default;
    explicit VpnPacketsHolder(VpnPackets packets)
            : m_packets(packets.data, packets.data + packets.size) {
    }
    ~VpnPacketsHolder() {
        for (auto p : m_packets) {
            if (p.destructor) {
                p.destructor(p.destructor_arg, p.data);
            }
        }
    }
    std::vector<VpnPacket> release() {
        std::vector<VpnPacket> ret = std::move(m_packets);
        return ret;
    }
    void add(VpnPacket packet) {
        m_packets.push_back(packet);
    }
    void add(VpnPackets packets) {
        std::copy(packets.data, packets.data + packets.size, std::back_inserter(m_packets));
    }

    VpnPacketsHolder(const VpnPacketsHolder &) = delete;
    void operator=(const VpnPacketsHolder &) = delete;
    VpnPacketsHolder(VpnPacketsHolder &&other) noexcept {
        *this = std::move(other);
    }
    VpnPacketsHolder &operator=(VpnPacketsHolder &&other) noexcept {
        std::swap(m_packets, other.m_packets);
        return *this;
    }

private:
    std::vector<VpnPacket> m_packets;
};

/**
 * Default settings for vpn
 */
struct VpnDefaultSettings {
    bool post_quantum_group_enabled; /**< Default state for post-quantum group in TLS handshakes */
    bool handler_profiling_enabled;  /**< Default state for handler profiling */
};

/**
 * Convert milliseconds to timeval structure
 */
static inline struct timeval ms_to_timeval(uint32_t ms) {
    struct timeval tv{}; // NOLINT(cppcoreguidelines-pro-type-member-init)
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return tv;
}

/**
 * Convert timeval structure to milliseconds
 */
static inline uint64_t timeval_to_ms(struct timeval tv) {
    return (uint64_t) tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/**
 * Combine 2 hash codes into a single one
 */
uint64_t hash_pair_combine(uint64_t h1, uint64_t h2);

/**
 * Get hash of IP address
 */
uint64_t ip_addr_hash(sa_family_t family, const void *addr);

/**
 * Get hash of address:port
 */
uint64_t socket_address_hash(const SocketAddress &addr);

/**
 * Get hash of a pair of address:port
 */
uint64_t socket_address_pair_hash(const SocketAddress &src, const SocketAddress &dst);

/**
 * Parse an IPv4 or IPv6 address, with optional port, from a string
 *
 * Recognized formats are:
 *   - [IPv6Address]:port
 *   - [IPv6Address]
 *   - IPv6Address
 *   - IPv4Address:port
 *   - IPv4Address
 *
 * If no port is specified, the port in the output is set to 0
 *
 * @param str string to parse
 * @return parsed socket address storage
 */
SocketAddressStorage sockaddr_from_str(const char *str);

/**
 * Get bound socket address storage from file descriptor
 * @param fd descriptor
 * @return composed socket address
 */
SocketAddress local_socket_address_from_fd(evutil_socket_t fd);

/**
 * Get connected peer socket address storage from file descriptor
 * @param fd descriptor
 * @return composed socket address
 */
SocketAddress remote_socket_address_from_fd(evutil_socket_t fd);

/**
 * 32-bit hash of string by djb2 algorithm
 */
uint32_t str_hash32(const char *str, size_t length);

/**
 * Do `strdup` if non-null, return null otherwise
 */
char *safe_strdup(const char *s);

/**
 * Make `VpnError` from socket descriptor
 */
VpnError make_vpn_error_from_fd(evutil_socket_t fd);

/**
 * Make `VpnError` from `errno` (or `WSAGetLastError`)
 */
VpnError make_vpn_from_socket_error(int code);

/**
 * Return the amount of time, in nanoseconds, including the time the system was asleep,
 * that has passed since an arbitrary point that may change between program runs.
 * Suitable e.g. for determining the amount of real time between two events in a single program run.
 */
int64_t get_time_monotonic_nanos();

template <typename T, auto FUNC>
using DeclPtr = std::unique_ptr<T, Ftor<FUNC>>;

using U8View = ag::Uint8View;

/** %-formatted string output. */
std::string str_format(const char *fmt, ...)
#if defined __GNUC__ && !defined __MINGW64__                                                                           \
        && !defined __MINGW32__ // disable warnings on mingw due to the unsupported "%zu" format
        __attribute((format(printf, 1, 2)))
#endif
        ;

/**
 * Encode input data to hex string
 * @param data Input buffer
 * @return Hex representation of input data
 */
std::string encode_to_hex(U8View data);

/**
 * Return a string where all non-printable bytes from `data` are replaced with '?'.
 */
std::string escape_non_print(U8View data);

/**
 * Convert a C string to std::string_view, accepting nullptr.
 */
static inline std::string_view safe_to_string_view(const char *c_str) {
    return c_str ? std::string_view{c_str} : std::string_view{};
}

/** Return whether the two strings are equal ignoring case. */
bool case_equals(std::string_view a, std::string_view b);

/** Convert the unsigned 24-bit wide integer from network byte order to host byte order */
uint32_t ntoh_24(uint32_t x);

/**
 * Just like `std::remove_if()`, but swaps elements to the tail instead of moving them
 */
template <typename Iterator, typename Predicate>
Iterator swap_remove_if(Iterator begin, Iterator end, Predicate p) {
    begin = std::find_if(begin, end, p);
    if (begin != end) {
        for (Iterator i = begin; ++i != end;) {
            if (!p(*i)) {
                std::swap(*begin++, *i);
            }
        }
    }
    return begin;
}

extern "C" {

/**
 * Parse an IPv4 or IPv6 address, with optional port, from a string
 *
 * Recognized formats are:
 *   - [IPv6Address]:port
 *   - [IPv6Address]
 *   - IPv6Address
 *   - IPv4Address:port
 *   - IPv4Address
 *
 * If no port is specified, the port in the output is set to 0
 *
 * @param str string to parse
 * @param result (out) parsed sockaddr
 */
WIN_EXPORT void sockaddr_from_str_out(const char *str, struct SocketAddressStorage *result);

/**
 * Parse a DNS stamp string. The caller is responsible for freeing
 * the result with `vpn_dns_stamp_free()`.
 * @param stamp_str "sdns://..." string
 * @param error on output, if an error occurred, contains the error description (free with `vpn_string_free()`)
 * @return a parsed stamp, or NULL if an error occurred.
 */
WIN_EXPORT VpnDnsStamp *vpn_dns_stamp_from_str(const char *stamp_str, const char **error);

/**
 * Free a ag_parse_dns_stamp_result pointer.
 */
WIN_EXPORT void vpn_dns_stamp_free(VpnDnsStamp *stamp);

/**
 * Convert a DNS stamp to a "sdns://..." string.
 * Free the returned string with `vpn_string_free()`
 */
WIN_EXPORT const char *vpn_dns_stamp_to_str(VpnDnsStamp *stamp);

/**
 * Convert a DNS stamp to a string that can be used as a DNS upstream URL.
 * Free the returned string with `vpn_string_free()`
 */
WIN_EXPORT const char *vpn_dns_stamp_pretty_url(VpnDnsStamp *stamp);

/**
 * Convert a DNS stamp to a string that can NOT be used as a DNS upstream URL, but may be prettier.
 * Free the returned string with `vpn_string_free()`
 */
WIN_EXPORT const char *vpn_dns_stamp_prettier_url(VpnDnsStamp *stamp);

/**
 * Free a string allocated by VPN.
 */
WIN_EXPORT void vpn_string_free(const char *s);

/**
 * Enable or disable profiling of VPN handlers.
 * This function should be called before any VPN instances have been created.
 */
WIN_EXPORT void vpn_handler_profiling_set_enabled(bool enabled);

/** Return `true` if handler profiling is enabled, `false` otherwise. */
WIN_EXPORT bool vpn_handler_profiling_enabled();

/** Return the handler profiling threshold in nanoseconds. */
WIN_EXPORT uint32_t vpn_handler_profiling_threshold_ns();

/** Enable or disable the use of a post-quantum group for key exchange in TLS handshakes initiated by the library. */
WIN_EXPORT void vpn_post_quantum_group_set_enabled(bool enabled);

/** Return `true` if a post-quantum group can be used in TLS handshakes initiated by the library, `false` otherwise. */
WIN_EXPORT bool vpn_post_quantum_group_enabled();

/**
 * Get default VPN settings.
 * @return Pointer to allocated VpnDefaultSettings structure
 */
WIN_EXPORT VpnDefaultSettings *vpn_get_default_settings();

/**
 * Free VpnDefaultSettings structure
 * @param settings Pointer to VpnDefaultSettings structure to free
 */
WIN_EXPORT void vpn_free_default_settings(VpnDefaultSettings *settings);

} // extern "C"
} // namespace ag
