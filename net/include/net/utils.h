#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "vpn/platform.h" // Unbreak Windows build

#include <event2/event.h>
#include <event2/util.h>
#include <fmt/format.h>
#include <openssl/x509.h>

#include "common/error.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "net/http_header.h"
#include "vpn/utils.h"
#include <openssl/ssl.h>

namespace ag {

struct SocketProtectEvent {
    evutil_socket_t fd;   // file descriptor
    const sockaddr *peer; // destination address
    int result;           // FILLED BY HANDLER: operation result (0 in case of success)
};

struct CertVerifyCtx {
    X509 *cert = nullptr;
    STACK_OF(X509) *chain = nullptr;
    SSL *ssl = nullptr;
};

struct CertVerifyHandler {
    // server certificate verify callback
    int (*func)(const char *host_name, const sockaddr *host_ip, const CertVerifyCtx &ctx, void *arg);
    void *arg; // will be set to SSL object as app data (like `SSL_set_app_data(ssl, cert_verify_arg)`)
};

struct VpnEndpoint {
    sockaddr_storage address; // endpoint address
    const char *name;         // endpoint host name (used, for example, for TLS handshake)
    const char *remote_id;    // if not NULL or empty, used for server TLS certificate verification instead of `name`
    AG_ARRAY_OF(uint8_t) additional_data; // additional data about the endpoint
};

typedef AG_ARRAY_OF(VpnEndpoint) VpnEndpoints;

struct VpnRelay {
    sockaddr_storage address; // relay address
    AG_ARRAY_OF(uint8_t) additional_data; // additional data about the relay
};

typedef AG_ARRAY_OF(VpnRelay) VpnRelays;

struct VpnLocation {
    const char *id;         // location id
    VpnEndpoints endpoints; // location endpoints
    VpnRelays relays; // location relays
};

struct NameValue {
    std::vector<uint8_t> name;
    std::vector<uint8_t> value;
};

enum IcmpMessageType {
    ICMP_MT_ECHO_REPLY = 0,              // Echo Reply Message
    ICMP_MT_DESTINATION_UNREACHABLE = 3, // Destination Unreachable Message
    ICMP_MT_ECHO = 8,                    // Echo Message
    ICMP_MT_TIME_EXCEEDED = 11,          // Time Exceeded Message
};

enum IcmpDestUnreachCode {
    ICMP_DUC_NET_UNREACH,  // net unreachable
    ICMP_DUC_HOST_UNREACH, // host unreachable
};

enum IcmpTimeExceededCode {
    ICMP_TEC_TTL, // time to live exceeded in transit
};

enum Icmpv6MessageType {
    ICMPV6_MT_DESTINATION_UNREACHABLE = 1, // Destination Unreachable Message
    ICMPV6_MT_TIME_EXCEEDED = 3,           // Time Exceeded Message
    ICMPV6_MT_ECHO_REQUEST = 128,          // Echo Request Message
    ICMPV6_MT_ECHO_REPLY = 129,            // Echo Reply Message
};

enum Icmpv6DestUnreachCode {
    ICMPV6_DUC_NO_ROUTE = 0,        // No route to destination
    ICMPV6_DUC_ADDRESS_UNREACH = 3, // Address unreachable
};

enum Icmpv6TimeExceededCode {
    ICMPV6_TEC_HOP, // Hop limit exceeded in transit
};

struct IcmpEchoRequest {
    sockaddr_storage peer; /**< destination address of connection */
    uint16_t id;           /**< an identifier to aid in matching echos and replies */
    uint16_t seqno;        /**< a sequence number to aid in matching echos and replies */
    uint8_t ttl;           /**< a carrying IP packet TTL */
    uint16_t data_size;    /**< the size of data of the echo message */
};

struct IcmpEchoReply {
    /** source address of the reply (essentially equals to `dst` in corresponding `tcpip_icmp_echo_t`) */
    sockaddr_storage peer;
    uint16_t id;    /**< an identifier to aid in matching echos and replies */
    uint16_t seqno; /**< a sequence number to aid in matching echos and replies */
    uint8_t type;   /**< a type of the reply message */
    uint8_t code;   /**< a code of the reply message */
};

struct IcmpEchoRequestEvent {
    IcmpEchoRequest request;
    int result; /**< operation result - filled by caller: 0 if successful, non-zero otherwise */
};

/**
 * A system DNS server descriptor. Based on Windows 11 model as the most comprehensive among
 * the supported platforms.
 */
struct SystemDnsServer {
    /** URL of the DNS server. The syntax corresponds to the one used in the DNS proxy. */
    std::string address;
    /**
     * The network address of the hostname from the URL in `address` field.
     * @note The library does not check whether the address matches the hostname.
     */
    std::optional<SocketAddress> resolved_host;
};

struct SystemDnsServers {
    std::vector<SystemDnsServer> main;
    std::vector<std::string> fallback;
    std::vector<std::string> bootstrap;
};

/**
 * Special message type used as a marker for dropping a pending request.
 * The value must not match any of the standard codes from
 * https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml.
 */
constexpr uint8_t ICMP_MT_DROP = 84;
constexpr size_t UDP_MAX_DATAGRAM_SIZE = 65535;

constexpr int DEFAULT_PING_TIMEOUT_MS = 3333;
constexpr int DEFAULT_PING_ROUNDS = 3;

constexpr std::string_view HTTP_METHOD_CONNECT = "CONNECT";
constexpr std::string_view HTTP_METHOD_GET = "GET";

constexpr std::string_view AG_UNFILTERED_DNS_IPS_V4[] = {
        "46.243.231.30",
        "46.243.231.31",
};
constexpr std::string_view AG_UNFILTERED_DNS_IPS_V6[] = {
        "2a10:50c0::1:ff",
        "2a10:50c0::2:ff",
};

constexpr auto DPI_COOLDOWN_TIME = Millis{25}; // Time after the first part of the ClientHello is sent
constexpr size_t DPI_SPLIT_SIZE = 1; // Size of the first part of the ClientHello

/**
 * Serializes HTTP headers structure to valid HTTP/1.1 message (request or response)
 * @param headers Pointer to HTTP headers structure
 * @return Non-null-terminated byte array containing HTTP/1.1 message
 */
std::string http_headers_to_http1_message(const HttpHeaders *headers, bool one_line);

/**
 * Converts HTTP headers structure to a list of name-value pairs representing the given headers
 * including pseudo-headers.
 * @param headers Pointer to HTTP headers structure
 * @return A list of name-value pairs (must be ffarr_free'd by caller)
 */
std::vector<NameValue> http_headers_to_nv_list(const HttpHeaders *headers);

/**
 * Destroy endpoint's inner resources
 */
void vpn_endpoint_destroy(VpnEndpoint *endpoint);

using AutoVpnEndpoint = AutoPod<VpnEndpoint, vpn_endpoint_destroy>;

/**
 * Make a deep copy of an endpoint
 */
AutoVpnEndpoint vpn_endpoint_clone(const VpnEndpoint *src);

/**
 * Check if 2 endpoints are equal
 */
bool vpn_endpoint_equals(const VpnEndpoint *lh, const VpnEndpoint *rh);

/**
 * Destroy endpoints inner resources
 */
void vpn_endpoints_destroy(VpnEndpoints *endpoints);

/**
 * Destroy relay's inner resources
 */
void vpn_relay_destroy(VpnRelay *relay);

using AutoVpnRelay = AutoPod<VpnRelay, vpn_relay_destroy>;

/**
 * Make a deep copy of the relay
 */
AutoVpnRelay vpn_relay_clone(const VpnRelay *src);

/**
 * Destroy location's inner resources
 */
void vpn_location_destroy(VpnLocation *location);

using AutoVpnLocation = AutoPod<VpnLocation, vpn_location_destroy>;

/**
 * Make a deep copy of a location
 */
AutoVpnLocation vpn_location_clone(const VpnLocation *src);

/**
 * Return the length of varint-encoded value
 */
static inline size_t varint_len(uint64_t varint_value) {
    if (varint_value <= 63) {
        return 1;
    } else if (varint_value <= 16383) {
        return 2;
    } else if (varint_value <= 1073741823) {
        return 4;
    }
    return 8;
}

using SslPtr = ag::DeclPtr<SSL, SSL_free>;

/**
 * Dumps SSL sessions cache on disk
 * @param path Path to a directory where cache should be dumped
 */
void dump_session_cache(const std::string &path);

/**
 * Loads SSL sessions cache from disk
 * @param path Path to a directory where cache was dumped
 */
void load_session_cache(const std::string &path);

std::variant<SslPtr, std::string> make_ssl(int (*verification_callback)(X509_STORE_CTX *, void *), void *arg,
        ag::U8View alpn_protos, const char *sni, bool quic, ag::U8View endpoint_data = ag::U8View{});

/**
 * Return name of the group function used in key exchange from OpenSSL NID
 * @param kex_group OpenSSL NID of the group
 */
std::string kex_group_name_by_nid(int kex_group_nid);

/**
 * Check if the specified IPv4 address is a private address as defined by RFC 1918
 * and link-local address as defined by RFC 3927
 */
bool is_private_or_linklocal_ipv4_address(const in_addr *ip_ptr);

#ifdef __MACH__

/**
 * Collect the currently operable network interfaces
 */
std::vector<uint32_t> collect_operable_network_interfaces();

#endif // ifdef __MACH__

#ifdef _WIN32

enum RetrieveInterfaceDnsError {
    AE_ADAPTERS_ADDRESSES,
    AE_IF_NOT_FOUND,
    AE_LUID_TO_GUID,
};

template <>
struct ErrorCodeToString<RetrieveInterfaceDnsError> {
    std::string operator()(RetrieveInterfaceDnsError code) {
        // clang-format off
        switch (code) {
        case AE_ADAPTERS_ADDRESSES: return "GetAdaptersAddresses()";
        case AE_IF_NOT_FOUND: return "Interface not found";
        case AE_LUID_TO_GUID: return "ConvertInterfaceLuidToGuid()";
        }
        // clang-format on
    }
};

/**
 * Retrieve DNS servers of the specified interface
 */
Result<SystemDnsServers, RetrieveInterfaceDnsError> retrieve_interface_dns_servers(uint32_t if_index);

/**
 * Populate `physical_ifs` with the interface indices of physical network adapters.
 * @return An error code, or `ERROR_SUCCESS`.
 */
DWORD get_physical_interfaces(std::unordered_set<NET_IFINDEX> &physical_ifs);

/**
 * Return the network interface which is currently active.
 * May return 0 in case it is not found.
 */
extern "C" WIN_EXPORT uint32_t vpn_win_detect_active_if();

#elif !defined(__ANDROID__)

enum RetrieveSystemDnsError {
    AE_INIT,
};

template <>
struct ErrorCodeToString<RetrieveSystemDnsError> {
    std::string operator()(RetrieveSystemDnsError code) {
        // clang-format off
        switch (code) {
        case AE_INIT: return "res_ninit()";
        }
        // clang-format on
    }
};

/**
 * Retrieve DNS servers
 */
Result<SystemDnsServers, RetrieveSystemDnsError> retrieve_system_dns_servers();

#endif // ifdef __ANDROID__

enum IpVersion {
    IPV4,
    IPV6,
};

using IpVersionSet = EnumSet<IpVersion>;

constexpr std::optional<IpVersion> sa_family_to_ip_version(int family) {
    switch (family) {
    case AF_INET:
        return IPV4;
    case AF_INET6:
        return IPV6;
    default:
        return std::nullopt;
    }
}

constexpr int ip_version_to_sa_family(IpVersion v) {
    switch (v) {
    case IPV4:
        return AF_INET;
    case IPV6:
        return AF_INET6;
    }
}

} // namespace ag

template <>
struct fmt::formatter<ag::IcmpEchoRequest> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::IcmpEchoRequest &request, FormatContext &ctx) {
        return fmt::format_to(ctx.out(), "peer={}, id={}, seqno={}, ttl={}, data_size={}",
                ag::sockaddr_ip_to_str((sockaddr *) &request.peer), request.id, request.seqno, request.ttl,
                request.data_size);
    }
};

template <>
struct fmt::formatter<ag::IcmpEchoReply> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::IcmpEchoReply &reply, FormatContext &ctx) {
        return fmt::format_to(ctx.out(), "peer={}, id={}, seqno={}, type={}, code={}",
                ag::sockaddr_ip_to_str((sockaddr *) &reply.peer), reply.id, reply.seqno, reply.type, reply.code);
    }
};

template <>
struct fmt::formatter<ag::VpnEndpoint> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::VpnEndpoint &endpoint, FormatContext &ctx) {
        return fmt::format_to(
                ctx.out(), "name={}, address={}", endpoint.name, ag::sockaddr_to_str((sockaddr *) &endpoint.address));
    }
};

template <>
struct fmt::formatter<ag::SystemDnsServer> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::SystemDnsServer &s, FormatContext &ctx) const {
        return fmt::format_to(ctx.out(), "address={}, resolved_host={}", s.address,
                s.resolved_host.has_value() ? s.resolved_host->host_str() : "<none>");
    }
};

template <>
struct fmt::formatter<ag::SystemDnsServers> {
    template <typename ParseContext>
    constexpr auto parse(ParseContext &ctx) {
        return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const ag::SystemDnsServers &s, FormatContext &ctx) const {
        return fmt::format_to(ctx.out(), "main=[{}], fallback={}", fmt::join(s.main, "; "), s.fallback);
    }
};
