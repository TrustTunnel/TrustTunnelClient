#pragma once

#include <cassert>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <event2/event.h>
#include <magic_enum/magic_enum.hpp>

#include "common/net_utils.h"
#include "common/utils.h"
#include "common/socket_address.h"
#include "net/tcp_socket.h"
#include "net/udp_socket.h"
#include "vpn/platform.h"
#include "vpn/utils.h"
#include "vpn/vpn.h"

#include <filesystem>
namespace fs = std::filesystem;

#define CONN_BUFFER_FILE_NAME_FMT "cbuf-%" PRIu64 "-%" PRIu64 ".dat"

namespace ag {

static constexpr uint64_t NON_ID = UINT64_MAX;
static constexpr size_t HTTP_OK_STATUS = 200;
static constexpr size_t HTTP_AUTH_REQUIRED_STATUS = 407;
static constexpr char HTTP_AUTH_REQUIRED_MSG[] = "Authorization Required";

struct ConnectRequestResult {
    uint64_t id = NON_ID;
    // nullopt means we aren't completely sure if a connection should be redirected
    std::optional<ag::VpnConnectAction> action;
    std::string appname;
    int uid = 0;

    [[nodiscard]] std::string to_string() const {
        return str_format("ID=%" PRIu64 " action=%s appname=%s", this->id,
                magic_enum::enum_name(this->action.value_or(ag::VPN_CA_DEFAULT)).data(), this->appname.c_str());
    }
};

struct NamePort {
    std::string name;
    int port = 0;
};

inline bool operator==(const NamePort &lh, const NamePort &rh) {
    return lh.port == rh.port && lh.name == rh.name;
}

inline bool operator!=(const NamePort &lh, const NamePort &rh) {
    return !(lh == rh);
}

using TunnelAddress = std::variant<SocketAddress, NamePort>;

struct TunnelAddressPair {
    SocketAddress src;
    TunnelAddress dst;

    TunnelAddressPair() = delete;

    TunnelAddressPair(const SocketAddress *s, TunnelAddress d)
            : src(s ? *s : SocketAddress{})
            , dst(std::move(d)) {
    }

    TunnelAddressPair(const SocketAddress &s, TunnelAddress d)
            : src(s)
            , dst(std::move(d)) {
    }

    TunnelAddressPair(const SocketAddress *s, const SocketAddress *d)
            : src(s ? *s : SocketAddress{})
            , dst(d ? *d : SocketAddress{}) {
    }

    TunnelAddressPair(const SocketAddress &s, const SocketAddress &d)
            : src(s)
            , dst(d) {
    }

    uint16_t dstport() const {
        if (const auto *ss = std::get_if<SocketAddress>(&dst)) {
            return ss->port();
        }
        if (const auto *np = std::get_if<NamePort>(&dst)) {
            return np->port;
        }
        assert(0);
        return 0;
    }
};

inline bool operator==(const TunnelAddressPair &lh, const TunnelAddressPair &rh) {
    if (lh.src != rh.src) {
        return false;
    }
    if (lh.dst.index() != rh.dst.index()) {
        return false;
    }
    if (const SocketAddress *ld = std::get_if<SocketAddress>(&lh.dst),
            *rd = std::get_if<SocketAddress>(&rh.dst);
            ld && rd) {
        return *ld == *rd;
    }
    if (const NamePort *ld = std::get_if<NamePort>(&lh.dst), *rd = std::get_if<NamePort>(&rh.dst); ld && rd) {
        return *ld == *rd;
    }
    return false;
}

inline bool operator!=(const TunnelAddressPair &lh, const TunnelAddressPair &rh) {
    return !(lh == rh);
}

static const TunnelAddress HEALTH_CHECK_HOST(NamePort{"_check", 0});

std::string tunnel_addr_to_str(const TunnelAddress *addr);

/**
 * Get pointer value and null it
 */
template <typename T, typename = std::enable_if_t<std::is_pointer<T>::value>>
T load_and_null(T &x) {
    return std::exchange(x, nullptr);
}

using TcpSocketPtr = ag::DeclPtr<TcpSocket, &tcp_socket_destroy>;
using UdpSocketPtr = ag::DeclPtr<UdpSocket, &udp_socket_destroy>;
using EventPtr = ag::DeclPtr<event, &event_free>;

struct SockAddrTag {
    SocketAddress addr = {};
    std::string appname;
};

inline bool operator==(const SockAddrTag &lh, const SockAddrTag &rh) {
    return (lh.addr == rh.addr) && lh.appname == rh.appname;
}

/**
 * Check if string starts with prefix
 */
static inline constexpr bool starts_with(std::string_view str, std::string_view prefix) {
    return str.substr(0, prefix.length()) == prefix;
}

/**
 * Contruct full path for connection buffer file
 * @param base_path directory path
 * @param id connection id
 */
std::string make_buffer_file_path(const char *base_path, uint64_t id);

/**
 * Remove connection buffer files which had not been removed at the end of VPN run for some reason
 * @param base_path directory path to scan
 */
void clean_up_buffer_files(const char *base_path);

void vpn_upstream_config_destroy(ag::VpnUpstreamConfig *config);

ag::AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> vpn_upstream_config_clone(const ag::VpnUpstreamConfig *src);

template <std::size_t N, std::size_t... IS>
constexpr std::array<const char *, N> cpp_to_cstr_array(
        const std::array<std::string_view, N> &arr, std::index_sequence<IS...>) {
    return {{arr[IS].data()...}};
}

template <std::size_t N, std::size_t... IS>
constexpr std::array<const char *, N> cpp_to_cstr_array(const std::array<std::string_view, N> &arr) {
    return cpp_to_cstr_array(arr, std::make_index_sequence<N>());
}

template <typename E, std::size_t N = magic_enum::enum_count<E>()>
constexpr std::array<const char *, N> make_enum_names_array() {
    return cpp_to_cstr_array<N>(magic_enum::enum_names<E>());
}

std::string headers_to_log_str(const HttpHeaders &headers);

ag::VpnError bad_http_response_to_connect_error(const HttpHeaders *response);

HttpHeaders make_http_connect_request(
        HttpVersion version, const TunnelAddress *dst_addr, std::string_view app_name, std::string_view creds);

std::string make_credentials(std::string_view username, std::string_view password);

using SslPtr = ag::DeclPtr<SSL, SSL_free>;

constexpr std::optional<utils::TransportProtocol> ipproto_to_transport_protocol(int ipproto) {
    switch (ipproto) {
    case IPPROTO_UDP:
        return utils::TP_UDP;
    case IPPROTO_TCP:
        return utils::TP_TCP;
    default:
        return std::nullopt;
    }
}

} // namespace ag

namespace std {

template <>
struct hash<ag::TunnelAddress> {
    size_t operator()(const ag::TunnelAddress &addr) const {
        size_t hash = 0;
        if (const auto *a = std::get_if<ag::SocketAddress>(&addr); a != nullptr) {
            hash = size_t(ag::socket_address_hash(*a));
        } else {
            const auto &np = std::get<ag::NamePort>(addr);
            hash = size_t(ag::hash_pair_combine(ag::str_hash32(np.name.c_str(), np.name.length()), np.port));
        }
        return hash;
    }
};

template <>
struct hash<ag::TunnelAddressPair> {
    size_t operator()(const ag::TunnelAddressPair &addr) const {
        return size_t(
                ag::hash_pair_combine(ag::socket_address_hash(addr.src), hash<ag::TunnelAddress>{}(addr.dst)));
    }
};

template <>
struct hash<ag::SockAddrTag> {
    size_t operator()(const ag::SockAddrTag &k) const {
        return size_t(
                ag::hash_pair_combine(ag::socket_address_hash(k.addr), std::hash<std::string>()(k.appname)));
    }
};

} // namespace std
