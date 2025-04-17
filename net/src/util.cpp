#include "util.h"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstring>
#include <fstream>
#include <span>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <filesystem>
#include <set>

#ifndef _WIN32
#include <ifaddrs.h>
#include <net/if.h>
#include <resolv.h>
#else
#include "vpn/platform.h" // Unbreak build
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOCRYPT
#include <iphlpapi.h>
#include <netioapi.h>
#include <winreg.h>

#include "vpn/guid_utils.h"
#endif

#include <brotli/decode.h>
#include <magic_enum/magic_enum.hpp>
#include <openssl/ssl.h>

#include "common/logger.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "common/cache.h"
#include "net/dns_utils.h"
#include "net/http_header.h"
#include "net/http_session.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

static const Logger g_logger("NET_UTILS");

#ifdef _WIN32

static void *retrieve_func_pointer(HMODULE module, const char *name) {
    void *func = GetProcAddress(module, name);
    if (func == nullptr) {
        int err = sys::last_error();
        dbglog(g_logger, "GetProcAddress(): name={}, error='{}' ({})", name, sys::strerror(err), err);
    }
    return func;
}

using GetInterfaceDnsSettingsFunc = DWORD(WINAPI *)(GUID, DNS_INTERFACE_SETTINGS *);
static GetInterfaceDnsSettingsFunc GetInterfaceDnsSettings_func = (GetInterfaceDnsSettingsFunc) retrieve_func_pointer(
        GetModuleHandleA("iphlpapi.dll"), "GetInterfaceDnsSettings");

using FreeInterfaceDnsSettingsFunc = void(WINAPI *)(DNS_INTERFACE_SETTINGS *);
static FreeInterfaceDnsSettingsFunc FreeInterfaceDnsSettings_func =
        (FreeInterfaceDnsSettingsFunc) retrieve_func_pointer(
                GetModuleHandleA("iphlpapi.dll"), "FreeInterfaceDnsSettings");

#endif // _WIN32

std::string http_headers_to_http1_message(const HttpHeaders *headers, bool one_line) {
    if (headers == nullptr) {
        return "";
    }

    std::string out = {};
    const char *line_delimiter = !one_line ? "\r\n" : " ";

    std::string http_version =
            AG_FMT("HTTP/{}.{}", http_version_get_major(headers->version), http_version_get_minor(headers->version));

    if (!headers->status_string.empty() && headers->status_code != 0) {
        out += AG_FMT("{} {} {}{}", http_version, headers->status_code, headers->status_string, line_delimiter);
    } else if (headers->status_code != 0) {
        out += AG_FMT("{} {}{}", http_version, headers->status_code, line_delimiter);
    } else {
        std::string_view url = !headers->path.empty() ? headers->path : std::string_view{"*"};
        std::string_view method = !headers->method.empty() ? headers->method : std::string_view{"OPTIONS"};
        out += AG_FMT("{} {} {}{}", method, url, http_version, line_delimiter);
    }

    if (!headers->authority.empty() && !headers->contains_field("Host")) {
        out += AG_FMT("Host: {}{}", headers->authority, line_delimiter);
    }

    for (const HttpHeaderField &f : headers->fields) {
        out += AG_FMT("{}: {}{}", f.name, f.value, line_delimiter);
    }

    out += line_delimiter;
    return out;
}

static void nv_list_add_header(std::vector<NameValue> &nva, std::string_view name, std::string_view value) {
    nva.emplace_back(NameValue{{(uint8_t *) name.data(), (uint8_t *) name.data() + name.size()},
            {(uint8_t *) value.data(), (uint8_t *) value.data() + value.size()}});
}

#ifdef __clang__
/* Workaround for clang optimization bug in NDK 15 */
__attribute((optnone))
#endif //__clang__
std::vector<NameValue>
http_headers_to_nv_list(const HttpHeaders *headers) {
    size_t max_field_count = headers->fields.size() + 4;
    std::vector<NameValue> nva;
    nva.reserve(max_field_count);

    if (headers->status_code != 0) {
        nv_list_add_header(nva, STATUS_PH_FIELD, std::to_string(headers->status_code));
    } else {
        if (!headers->method.empty()) {
            nv_list_add_header(nva, METHOD_PH_FIELD, headers->method);
        }
        if (!headers->scheme.empty()) {
            nv_list_add_header(nva, SCHEME_PH_FIELD, headers->scheme);
        }
        if (!headers->authority.empty()) {
            nv_list_add_header(nva, AUTHORITY_PH_FIELD, headers->authority);
        }
        if (!headers->path.empty()) {
            nv_list_add_header(nva, PATH_PH_FIELD, headers->path);
        }
    }

    for (const HttpHeaderField &field : headers->fields) {
        if (case_equals(field.name, "connection") || case_equals(field.name, "transfer-encoding")) {
            // Ignore deprecated header fields
            continue;
        }
        nv_list_add_header(nva, field.name, field.value);
    }

    return nva;
}

HttpVersion http_make_version(int major, int minor) {
    return (HttpVersion) (((major & 0xff) << 8) | (minor & 0xff));
}

int http_version_get_major(HttpVersion v) {
    return (v >> 8) & 0xff;
}

int http_version_get_minor(HttpVersion v) {
    return v & 0xff;
}

AutoVpnEndpoint vpn_endpoint_clone(const VpnEndpoint *src) {
    AutoVpnEndpoint dst;
    std::memcpy(dst.get(), src, sizeof(*src));
    dst->name = safe_strdup(src->name);
    dst->remote_id = safe_strdup(src->remote_id);

    auto data_len = src->additional_data.size;
    dst->additional_data.data = static_cast<uint8_t *>(std::malloc(data_len));
    std::memcpy(dst->additional_data.data, src->additional_data.data, data_len);
    dst->additional_data.size = data_len;
    return dst;
}

void vpn_endpoint_destroy(VpnEndpoint *endpoint) {
    if (endpoint == nullptr) {
        return;
    }

    free((char *) endpoint->name);
    free((char *) endpoint->remote_id);
    free(endpoint->additional_data.data);
    std::memset(endpoint, 0, sizeof(*endpoint));
}

bool vpn_endpoint_equals(const VpnEndpoint *lh, const VpnEndpoint *rh) {
    return sockaddr_equals((struct sockaddr *) &lh->address, (struct sockaddr *) &rh->address)
            && ((lh->name == nullptr && rh->name == lh->name) || 0 == strcmp(lh->name, rh->name))
            && ((lh->remote_id == nullptr && rh->remote_id == nullptr) || 0 == strcmp(lh->remote_id, rh->remote_id));
}

AutoVpnLocation vpn_location_clone(const VpnLocation *src) {
    AutoVpnLocation dst;
    std::memcpy(dst.get(), src, sizeof(*src));
    dst->id = safe_strdup(src->id);

    dst->endpoints = {};
    static_assert(std::is_trivial_v<VpnEndpoint>);
    dst->endpoints.data = (VpnEndpoint *) malloc(src->endpoints.size * sizeof(VpnEndpoint));

    for (size_t i = 0; i < src->endpoints.size; ++i) {
        AutoVpnEndpoint e = vpn_endpoint_clone(&src->endpoints.data[i]);
        std::memcpy(&dst->endpoints.data[dst->endpoints.size++], e.get(), sizeof(*e.get()));
        e.release();
    }

    size_t relay_addresses_size = dst->relay_addresses.size * sizeof(sockaddr_storage);
    dst->relay_addresses.data = (sockaddr_storage *) malloc(relay_addresses_size);
    std::memcpy(dst->relay_addresses.data, src->relay_addresses.data, relay_addresses_size);

    return dst;
}

void vpn_endpoints_destroy(VpnEndpoints *endpoints) {
    if (endpoints == nullptr) {
        return;
    }

    for (size_t i = 0; i < endpoints->size; ++i) {
        vpn_endpoint_destroy(&endpoints->data[i]);
    }
    free(endpoints->data);
    std::memset(endpoints, 0, sizeof(*endpoints));
}

void vpn_location_destroy(VpnLocation *location) {
    if (location == nullptr) {
        return;
    }

    free((char *) location->id);
    vpn_endpoints_destroy(&location->endpoints);
    free(location->relay_addresses.data);

    std::memset(location, 0, sizeof(*location));
}

#ifdef __MACH__
std::vector<uint32_t> collect_operable_network_interfaces() {
    std::unordered_set<uint32_t> ifs;
    ifaddrs *addrs = nullptr;
    getifaddrs(&addrs);
    for (ifaddrs *it = addrs; it; it = it->ifa_next) {
        if (!(it->ifa_flags & IFF_UP)) {
            continue;
        }
        if (std::string_view name = safe_to_string_view(it->ifa_name); name.empty() || name.starts_with("lo")
                || name.starts_with("utun") || name.starts_with("tun") || name.starts_with("ipsec")) {
            continue;
        }
        if (it->ifa_addr == nullptr || (it->ifa_addr->sa_family != AF_INET && it->ifa_addr->sa_family != AF_INET6)) {
            continue;
        }
        if (it->ifa_addr->sa_family == AF_INET6) {
            uint16_t first_group = ntohs(((uint16_t *) &((sockaddr_in6 *) it->ifa_addr)->sin6_addr)[0]);
            // Skip interfaces without unicast and ULA addresses:
            // 2000::/3 Global unicast
            // fc00::/7 ULA
            if ((first_group & ~(uint16_t(~0) >> 3)) != 0x2000 && (first_group & ~(uint16_t(~0) >> 7)) != 0xfc00) {
                continue;
            }
        }
        uint32_t ifindex = if_nametoindex(it->ifa_name);
        ifs.insert(ifindex);
    }
    freeifaddrs(addrs);
    return {ifs.begin(), ifs.end()};
}
#endif // ifdef __MACH__

#ifdef _WIN32

static std::unordered_map<std::string, std::string> load_doh_well_known_servers() {
    constexpr const char *DOH_WELL_KNOWN_SERVERS_PATH =
            R"(SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DohWellKnownServers)";
    constexpr const char *DOH_SERVER_TEMPLATE_VALUE_NAME = "Template";
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    constexpr size_t MAX_KEY_LENGTH = 255;
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-element-size-limits
    constexpr size_t MAX_VALUE_NAME = 16383;

    HKEY key{};
    DWORD ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, DOH_WELL_KNOWN_SERVERS_PATH, 0, KEY_ENUMERATE_SUB_KEYS, &key);
    if (ret != ERROR_SUCCESS) {
        warnlog(g_logger, "RegOpenKeyEx({}): {} ({})", DOH_WELL_KNOWN_SERVERS_PATH, sys::strerror(ret), ret);
        return {};
    }

    std::unordered_map<std::string, std::string> result;
    for (DWORD index = 0;; ++index) {
        char name[MAX_KEY_LENGTH];
        DWORD name_len = std::size(name);
        ret = RegEnumKeyExA(key, index, name, &name_len, nullptr, nullptr, nullptr, nullptr);
        if (ret == ERROR_NO_MORE_ITEMS) {
            break;
        }
        if (ret != ERROR_SUCCESS) {
            warnlog(g_logger, "RegEnumKeyEx(): {} ({})", sys::strerror(ret), ret);
            break;
        }

        std::string subkey_path = AG_FMT("{}\\{}", DOH_WELL_KNOWN_SERVERS_PATH, std::string_view{name, name_len});
        HKEY subkey{};
        ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey_path.c_str(), 0, KEY_QUERY_VALUE, &subkey);
        if (ret != ERROR_SUCCESS) {
            warnlog(g_logger, "RegOpenKeyEx({}): {} ({})", subkey_path, sys::strerror(ret), ret);
            continue;
        }

        DWORD value_type = 0;
        uint8_t data[MAX_VALUE_NAME];
        DWORD data_len = std::size(data);
        ret = RegQueryValueExA(subkey, DOH_SERVER_TEMPLATE_VALUE_NAME, nullptr, &value_type, data, &data_len);
        if (ret != ERROR_SUCCESS) {
            warnlog(g_logger, "RegQueryValueExA(): {} ({})", sys::strerror(ret), ret);
            goto continue_loop;
        }
        if (value_type != REG_SZ) {
            dbglog(g_logger, "Skipping value of unexpected type: name={}, type={} (expected={}), data={}",
                    std::string_view{name, name_len}, value_type, REG_SZ, encode_to_hex({data, data_len}));
            goto continue_loop;
        }

        result.emplace(std::piecewise_construct, std::forward_as_tuple(name, name_len),
                std::forward_as_tuple((char *) data, data_len - 1));

    continue_loop:
        RegCloseKey(subkey);
    }

    RegCloseKey(key);

    dbglog(g_logger, "Found well-known servers: {}", result);
    return result;
}

static std::optional<SystemDnsServers> retrieve_interface_dns_servers_with_doh(const GUID &guid, int ip_family) {
    if (GetInterfaceDnsSettings_func == nullptr || FreeInterfaceDnsSettings_func == nullptr) {
        return std::nullopt;
    }

    DNS_INTERFACE_SETTINGS3 settings = {
            .Version = DNS_INTERFACE_SETTINGS_VERSION3,
            .Flags = (ip_family == AF_INET) ? ULONG64(0) : DNS_SETTING_IPV6,
    };
    DWORD ret = GetInterfaceDnsSettings_func(guid, (DNS_INTERFACE_SETTINGS *) &settings);
    if (ret != ERROR_SUCCESS) {
        warnlog(g_logger, "GetInterfaceDnsSettings(): {} ({})", sys::strerror(ret), ret);
        return std::nullopt;
    }

    std::string server_list = utils::from_wstring((settings.NameServer != nullptr) ? settings.NameServer : L"");
    std::vector<std::string_view> server_views = utils::split_by_any_of(server_list, " ,");
    assert(server_views.size() >= settings.cServerProperties);

    SystemDnsServers servers;
    servers.main.reserve(server_views.size());
    std::transform(server_views.begin(), server_views.end(), std::back_inserter(servers.main),
            [](std::string_view s) -> SystemDnsServer {
                return {
                        .address = std::string{s},
                };
            });

    std::vector<std::pair<size_t, std::string>> resolved_hosts;
    resolved_hosts.reserve(settings.cServerProperties);
    for (ULONG i = 0; i < settings.cServerProperties; ++i) {
        const DNS_SERVER_PROPERTY *server_property = &settings.ServerProperties[i];
        switch (server_property->Type) {
        case DnsServerDohProperty: {
            const DNS_DOH_SERVER_SETTINGS *doh_settings = server_property->Property.DohSettings;
            SystemDnsServer &server = servers.main.at(server_property->ServerIndex);
            if (doh_settings->Flags & DNS_DOH_SERVER_SETTINGS_ENABLE_AUTO) {
                static const std::unordered_map<std::string, std::string> WELL_KNOWN_DOH_SERVERS =
                        load_doh_well_known_servers();

                auto it = WELL_KNOWN_DOH_SERVERS.find(server.address);
                if (it != WELL_KNOWN_DOH_SERVERS.end()) {
                    resolved_hosts.emplace_back(std::piecewise_construct,
                            std::forward_as_tuple(server_property->ServerIndex),
                            std::forward_as_tuple(std::exchange(server.address, it->second)));
                } else {
                    warnlog(g_logger, "Found non-well-known server without template: {}", server.address);
                }
            } else if (doh_settings->Flags & DNS_DOH_SERVER_SETTINGS_ENABLE) {
                resolved_hosts.emplace_back(std::piecewise_construct,
                        std::forward_as_tuple(server_property->ServerIndex),
                        std::forward_as_tuple(
                                std::exchange(server.address, utils::from_wstring(doh_settings->Template))));
            }
            if (doh_settings->Flags & DNS_DOH_SERVER_SETTINGS_FALLBACK_TO_UDP) {
                servers.fallback.emplace_back(resolved_hosts.at(resolved_hosts.size() - 1).second);
            }
            break;
        }
        default:
            warnlog(g_logger, "Server has unexpected property type, assuming it's plain UDP: type={}, server={}",
                    magic_enum::enum_name(server_property->Type), servers.main.at(server_property->ServerIndex).address);
            break;
        }
    }

    FreeInterfaceDnsSettings_func((DNS_INTERFACE_SETTINGS *) &settings);

    for (auto &[idx, resolved_host] : resolved_hosts) {
        if (!(servers.main.at(idx).resolved_host = SocketAddress(resolved_host, 0))->valid()) {
            warnlog(g_logger, "Skipping server due to resolved address is malformed: url={}, resolved={}",
                    servers.main.at(idx).address, resolved_host);
            continue;
        }
    }

    std::erase_if(servers.main, [](const SystemDnsServer &s) {
        return s.resolved_host.has_value() && !s.resolved_host->valid();
    });

    return servers;
}

Result<SystemDnsServers, RetrieveInterfaceDnsError> retrieve_interface_dns_servers(uint32_t if_index) {
    constexpr ULONG FLAGS =
            GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;

    ULONG buffer_size = 0;
    DWORD ret = GetAdaptersAddresses(AF_UNSPEC, FLAGS, nullptr, nullptr, &buffer_size);
    if (ret != ERROR_BUFFER_OVERFLOW) {
        return make_error(RetrieveInterfaceDnsError::AE_ADAPTERS_ADDRESSES, AG_FMT("{} ({})", sys::strerror(ret), ret));
    }

    std::vector<uint8_t> buffer(buffer_size);
    ret = GetAdaptersAddresses(AF_UNSPEC, FLAGS, nullptr, (IP_ADAPTER_ADDRESSES *) buffer.data(), &buffer_size);
    if (ret != NO_ERROR) {
        return make_error(RetrieveInterfaceDnsError::AE_ADAPTERS_ADDRESSES, AG_FMT("{} ({})", sys::strerror(ret), ret));
    }

    const IP_ADAPTER_ADDRESSES *adapter = nullptr;
    for (const auto *i = (IP_ADAPTER_ADDRESSES *) buffer.data(); i != nullptr; i = i->Next) {
        if (i->IfIndex == if_index) {
            adapter = i;
            break;
        }
    }

    if (adapter == nullptr) {
        return make_error(RetrieveInterfaceDnsError::AE_IF_NOT_FOUND);
    }

    GUID guid;
    ret = ConvertInterfaceLuidToGuid(&adapter->Luid, &guid);
    if (ret != ERROR_SUCCESS) {
        return make_error(RetrieveInterfaceDnsError::AE_LUID_TO_GUID, AG_FMT("{} ({})", sys::strerror(ret), ret));
    }

    SystemDnsServers servers;
    static const bool IS_WINDOWS_11_OR_GREATER = sys::is_windows_11_or_greater();
    if (IS_WINDOWS_11_OR_GREATER) {
        for (int family : {AF_INET, AF_INET6}) {
            if ((family == AF_INET && !adapter->Ipv4Enabled) || (family == AF_INET6 && !adapter->Ipv6Enabled)) {
                continue;
            }

            std::optional r = retrieve_interface_dns_servers_with_doh(guid, family);
            if (!r.has_value()) {
                continue;
            }

            SystemDnsServers &s = r.value();
            servers.main.insert(
                    servers.main.end(), std::make_move_iterator(s.main.begin()), std::make_move_iterator(s.main.end()));
            servers.fallback.insert(servers.fallback.end(), std::make_move_iterator(s.fallback.begin()),
                    std::make_move_iterator(s.fallback.end()));
        }
    }

    if (!servers.main.empty()) {
        return servers;
    }
    assert(servers.fallback.empty());
    servers.fallback.clear();

    // `GetInterfaceDnsSettings` does not return automatically configured (via DHCP) servers,
    // so empty servers at this point mean that the found `IP_ADAPTER_ADDRESSES` contains them
    for (const IP_ADAPTER_DNS_SERVER_ADDRESS *i = adapter->FirstDnsServerAddress; i != nullptr; i = i->Next) {
        servers.main.emplace_back(SystemDnsServer{
                .address = SocketAddress(i->Address.lpSockaddr).host_str(),
        });
    }

    return servers;
}

DWORD get_physical_interfaces(std::unordered_set<NET_IFINDEX> &physical_ifs) {
    static constexpr const char *WINREG_NETWORK_CARDS_PATH =
            R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards)";

    HKEY current_key{};
    if (DWORD error = RegOpenKeyExA(
                HKEY_LOCAL_MACHINE, WINREG_NETWORK_CARDS_PATH, 0, KEY_READ | KEY_ENUMERATE_SUB_KEYS, &current_key);
            error != ERROR_SUCCESS) {
        dbglog(g_logger, "RegOpenKeyExA failed with result: {}", error);
        return error;
    }

    DWORD key_index = 0;
    char subkey[BUFSIZ];
    DWORD name_length;
    while (RegEnumKeyExA(current_key, key_index++, subkey, &(name_length = std::size(subkey)), nullptr, nullptr,
                   nullptr, nullptr)
            != ERROR_NO_MORE_ITEMS) {
        DWORD data_size = 0;
        // get buffer size
        RegGetValueA(current_key, subkey, "ServiceName", RRF_RT_REG_SZ, nullptr, nullptr, &data_size);
        std::string buffer;
        buffer.resize(data_size);
        auto get_value_result =
                RegGetValueA(current_key, subkey, "ServiceName", RRF_RT_REG_SZ, nullptr, buffer.data(), &data_size);
        if (get_value_result == ERROR_SUCCESS) {
            buffer.resize(data_size - 1);
            if (auto guid = string_to_guid(buffer); guid.has_value()) {
                NET_LUID luid{};
                NET_IFINDEX index = 0;
                ConvertInterfaceGuidToLuid(&guid.value(), &luid);
                ConvertInterfaceLuidToIndex(&luid, &index);
                physical_ifs.insert(index);
            }
        } else {
            // Single error in previous operation is not critical for obtaining list of interfaces
            dbglog(g_logger, "RegGetValueA failed for key index {} with result: {}", key_index - 1,
                    sys::strerror(get_value_result));
        }
    }

    RegCloseKey(current_key);
    dbglog(g_logger, "Physical interfaces: {}", physical_ifs);
    return ERROR_SUCCESS;
}

static DWORD get_default_route_ifs(
        std::unordered_set<NET_IFINDEX> &net_ifs_v4, std::unordered_set<NET_IFINDEX> &net_ifs_v6) {
    PMIB_IPFORWARD_TABLE2 table_v4{};
    PMIB_IPFORWARD_TABLE2 table_v6{};
    DWORD error = ERROR_SUCCESS;
    if (error = GetIpForwardTable2(AF_INET, &table_v4); error != ERROR_SUCCESS) {
        errlog(g_logger, "Ipv4 GetIpForwardTable2(): {}", sys::strerror(error));
        return error;
    }
    if (error = GetIpForwardTable2(AF_INET6, &table_v6); error != ERROR_SUCCESS) {
        errlog(g_logger, "Ipv6 GetIpForwardTable2(): {}", sys::strerror(error));
        return error;
    }
    for (size_t i = 0; i < table_v4->NumEntries; i++) {
        if (sockaddr_is_any((sockaddr *) &table_v4->Table[i].DestinationPrefix.Prefix.Ipv4)
                && table_v4->Table[i].DestinationPrefix.PrefixLength == 0) {
            net_ifs_v4.insert(table_v4->Table[i].InterfaceIndex);
        }
    }
    for (size_t i = 0; i < table_v6->NumEntries; i++) {
        if (sockaddr_is_any((sockaddr *) &table_v6->Table[i].DestinationPrefix.Prefix.Ipv6)
                && table_v6->Table[i].DestinationPrefix.PrefixLength == 0) {
            net_ifs_v6.insert(table_v6->Table[i].InterfaceIndex);
        }
    }
    dbglog(g_logger, "Default route interfaces: ipv4 = {}, ipv6 = {}", net_ifs_v4, net_ifs_v6);
    return error;
}

/// return interface with minimal metric: <index, min_metric>
static std::pair<uint32_t, uint32_t> get_min_metric_if(std::unordered_set<NET_IFINDEX> &net_ifs, bool ipv6 = false) {
    auto ip_family = AF_INET;
    if (ipv6) {
        ip_family = AF_INET6;
    }
    uint32_t result_idx = 0;
    uint32_t min_metric = NL_MAX_METRIC_COMPONENT;
    for (const auto &index : net_ifs) {
        MIB_IPINTERFACE_ROW row;
        InitializeIpInterfaceEntry(&row);
        row.Family = ip_family;
        row.InterfaceIndex = index;
        if (DWORD error = GetIpInterfaceEntry(&row); error != ERROR_SUCCESS) {
            errlog(g_logger, "GetIpInterfaceEntry(): {}", sys::strerror(error));
        } else if (row.Connected && row.Metric < min_metric) {
            result_idx = row.InterfaceIndex;
            min_metric = row.Metric;
        }
    }
    return {result_idx, min_metric};
}

uint32_t vpn_win_detect_active_if() {
    // first find physical network cards interfaces
    std::unordered_set<NET_IFINDEX> physical_ifs;
    DWORD error = get_physical_interfaces(physical_ifs);
    if (physical_ifs.empty()) {
        SetLastError(error);
        errlog(g_logger, "get_physical_interfaces: {}", sys::strerror(error));
        return 0;
    }
    // get interfaces with default route from routing table
    std::unordered_set<NET_IFINDEX> net_ifs_v4;
    std::unordered_set<NET_IFINDEX> net_ifs_v6;
    error = get_default_route_ifs(net_ifs_v4, net_ifs_v6);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        errlog(g_logger, "get_default_route_ifs: {}", sys::strerror(error));
        return 0;
    }
    // exclude non-physical interfaces
    std::erase_if(net_ifs_v4, [&](auto net_if) {
        return !physical_ifs.contains(net_if);
    });
    std::erase_if(net_ifs_v6, [&](auto net_if) {
        return !physical_ifs.contains(net_if);
    });

    // Then choose operational one with minimal metric
    // handle ipv4
    auto [index_v4, min_metric_v4] = get_min_metric_if(net_ifs_v4, false);
    dbglog(g_logger, "min_metric_v4 = {} with if_index = {}", min_metric_v4, index_v4);
    // handle ipv6
    auto [index_v6, min_metric_v6] = get_min_metric_if(net_ifs_v6, true);
    dbglog(g_logger, "min_metric_v6 = {} with if_index = {}", min_metric_v6, index_v6);
    // both checks failed
    if (min_metric_v4 == min_metric_v6 && min_metric_v4 == NL_MAX_METRIC_COMPONENT) {
        errlog(g_logger, "Both metric checks failed");
        return 0;
    }
    if (min_metric_v4 < min_metric_v6) {
        return index_v4;
    }
    return index_v6;
}

#elif defined(__MACH__)

Result<SystemDnsServers, RetrieveSystemDnsError> retrieve_system_dns_servers() {
    struct __res_state res = {};
    if (0 != res_ninit(&res)) {
        return make_error(RetrieveSystemDnsError::AE_INIT);
    }

    std::vector<uint8_t> addrs_buf(res.nscount * sizeof(res_sockaddr_union));
    res_getservers(&res, (res_sockaddr_union *) addrs_buf.data(), res.nscount);

    SystemDnsServers servers;
    servers.main.reserve(res.nscount);
    for (const res_sockaddr_union &addr : std::span{(res_sockaddr_union *) addrs_buf.data(), size_t(res.nscount)}) {
        SocketAddress sock_addr((sockaddr *) &addr);
        if (!sock_addr.valid()) {
            warnlog(g_logger, "Skipping invalid address: {}", ag::encode_to_hex({(uint8_t *) &addr, sizeof(addr)}));
            continue;
        }

        servers.main.emplace_back(SystemDnsServer{
                .address = sock_addr.host_str(),
        });
    }

    res_ndestroy(&res);
    return servers;
}

#elif defined(__GLIBC__)

Result<SystemDnsServers, RetrieveSystemDnsError> retrieve_system_dns_servers() {
    struct __res_state res = {};
    if (0 != res_ninit(&res)) {
        return make_error(RetrieveSystemDnsError::AE_INIT);
    }

    SystemDnsServers servers;
    servers.main.reserve(res.nscount);
    for (int i = 0; i < res.nscount; ++i) {
        SocketAddress addr;
        if (res.nsaddr_list[i].sin_family == AF_INET) {
            addr = SocketAddress((sockaddr *) &res.nsaddr_list[i]);
        } else if (res._u._ext.nsaddrs[i]->sin6_family == AF_INET6) {
            addr = SocketAddress((sockaddr *) res._u._ext.nsaddrs[i]);
        }

        if (!addr.valid()) {
            warnlog(g_logger, "Skipping invalid address: {}", ag::encode_to_hex({(uint8_t *) &res, sizeof(res)}));
            continue;
        }

#if defined __linux__
        auto host_str = addr.host_str();
        static const SocketAddress UNFILTERED_IPS[] = {
                SocketAddress{AG_UNFILTERED_DNS_IPS_V4[0], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V4[1], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V6[0], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V6[1], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
        };
        if (addr.is_loopback()
                || std::find(std::begin(UNFILTERED_IPS), std::end(UNFILTERED_IPS), addr) != std::end(UNFILTERED_IPS)) {
            warnlog(g_logger, "Skipping potential route loop address: {}", addr.str());
            continue;
        }
#endif // __linux__

        servers.main.emplace_back(SystemDnsServer{
                .address = addr.host_str(),
        });
    }

    res_nclose(&res);
    return servers;
}

#elif defined(__ANDROID__)
//
// Android retrieves system DNS servers in Java code
//
#else

Result<SystemDnsServers, RetrieveSystemDnsError> retrieve_system_dns_servers() {
    SystemDnsServers servers;
    std::ifstream ifs{"/etc/resolv.conf"};
    std::string line;
    while (std::getline(ifs, line)) {
        std::string_view line_view = line;
        constexpr std::string_view NAMESERVER = "nameserver";
        if (line_view.starts_with(NAMESERVER)) {
            line_view.remove_prefix(NAMESERVER.size());
        }
        line_view = ag::utils::ltrim(line_view);
        line_view = line_view.substr(0,
                std::distance(line_view.begin(),
                        std::find_if(line_view.begin(), line_view.end(), (int (*)(int)) std::isspace)));
        SocketAddress addr{line_view, ag::dns_utils::PLAIN_DNS_PORT_NUMBER};

        if (!addr.valid()) {
            warnlog(g_logger, "Skipping invalid address: {}", line_view);
            continue;
        }

#if defined __linux__
        auto host_str = addr.host_str();
        static const SocketAddress UNFILTERED_IPS[] = {
                SocketAddress{AG_UNFILTERED_DNS_IPS_V4[0], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V4[1], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V6[0], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
                SocketAddress{AG_UNFILTERED_DNS_IPS_V6[1], ag::dns_utils::PLAIN_DNS_PORT_NUMBER},
        };
        if (addr.is_loopback()
                || std::find(std::begin(UNFILTERED_IPS), std::end(UNFILTERED_IPS), addr) != std::end(UNFILTERED_IPS)) {
            warnlog(g_logger, "Skipping potential route loop address: {}", addr.str());
            continue;
        }
#endif // __linux__

        servers.main.emplace_back(SystemDnsServer{std::string(line_view), std::nullopt});
    };
    return servers;
}

#endif

bool is_private_or_linklocal_ipv4_address(const in_addr *ip_ptr) {
    const uint32_t ip_int = ntohl(ip_ptr->s_addr);
    return ((ip_int & 0xFF000000) == 0x0A000000)      // 10.0.0.0/8
            || ((ip_int & 0xFFFF0000) == 0xA9FE0000)  // 169.254.0.0/12
            || ((ip_int & 0xFFF00000) == 0xAC100000)  // 172.16.0.0/12
            || ((ip_int & 0xFFFF0000) == 0xC0A80000); // 192.168.0.0/16
}

static constexpr auto SESSION_LIFETIME = std::chrono::hours(24);

static bool check_session_timings(SSL_SESSION *session) {
    auto session_created = std::chrono::seconds(SSL_SESSION_get_time(session));
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto session_timeout = std::chrono::seconds(SSL_SESSION_get_timeout(session));
    if (now > session_created + SESSION_LIFETIME) {
        return false;
    }
    return now < session_created + session_timeout;
}

/**
 * Helper class that allows to store
 * multiple SSL sessions as a single unit.
 */
class SessionAccumulator {
private:
    size_t m_max_size;
    mutable std::list<DeclPtr<SSL_SESSION, &SSL_SESSION_free>> m_list;
    static constexpr auto DEFAULT_MAX_SIZE = 9;

public:
    explicit SessionAccumulator(size_t max_size = DEFAULT_MAX_SIZE)
        : m_max_size(max_size) {
    }
    void insert(DeclPtr<SSL_SESSION, &SSL_SESSION_free> session) const {
        if (m_list.size() >= m_max_size && !m_list.empty()) {
            m_list.pop_back();
        }
        m_list.emplace_front(std::move(session));
    }
    DeclPtr<SSL_SESSION, &SSL_SESSION_free> pop() const {
        while (!m_list.empty()) {
            auto session = std::move(m_list.front());
            m_list.pop_front();
            if (session && check_session_timings(session.get())) {
                return session;
            }
        }
        return nullptr;
    }
    const auto &list() const {
        return m_list;
    }
    size_t size() const {
        return m_list.size();
    }
};

static std::mutex m_session_cache_mutex;
static ag::LruCache<std::string, SessionAccumulator> m_session_cache;

static std::string hash_sha256(std::string_view str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hashstr[SHA256_DIGEST_LENGTH * 2 + 1];
    SHA256((unsigned char*)str.data(), str.length(), hash);
    static constexpr char hex[] = "0123456789ABCDEF";
    size_t k = 0;
    for (size_t i = 0;  i != sizeof(hash);  i++) {
        hashstr[k++] = hex[hash[i] >> 4];
        hashstr[k++] = hex[hash[i] & 0x0f];
    }
    hashstr[k++] = '\0';
    return hashstr;
}

static int cache_session_cb(SSL *ssl, SSL_SESSION *session) {
    std::lock_guard l{m_session_cache_mutex};
    if (const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) {
        auto hash = hash_sha256(hostname);
        if (auto accum = m_session_cache.get(hash)) {
            accum->insert(DeclPtr<SSL_SESSION, &SSL_SESSION_free>{session});
        } else {
            SessionAccumulator session_accum;
            session_accum.insert(DeclPtr<SSL_SESSION, &SSL_SESSION_free>{session});
            m_session_cache.insert(hash, std::move(session_accum));
        }
        return 1;
    }
    return 0;
}

static DeclPtr<SSL_SESSION, &SSL_SESSION_free> pop_session_from_cache(const std::string &sni) {
    auto hash = hash_sha256(sni);
    std::lock_guard l{m_session_cache_mutex};
    if (auto it = m_session_cache.get(hash)) {
        auto session = it->pop();
        if (it->size() == 0) {
            m_session_cache.erase(hash);
        }
        return session;
    }
    return nullptr;
}

class SessionStorage {
public:
    explicit SessionStorage(std::filesystem::path path)
        : m_dir(std::move(path)) {
    }
    void load_ssl_cache() {
        if (!exists(m_dir)) {
            warnlog(g_logger, "SSL sessions won't be loaded and stored on disk because provided path doesn't exists: {}", m_dir.string());
            return;
        }
        std::lock_guard l{m_session_cache_mutex};
        std::map<size_t, std::pair<std::string, std::map<size_t, DeclPtr<SSL_SESSION, &SSL_SESSION_free>>>> sorted_cache;
        std::set<std::filesystem::path> files_to_remove;
        size_t sessions_counter = 0;

        for (const auto &entry: std::filesystem::directory_iterator(m_dir)) {
            auto filename = entry.path().filename().string();
            auto parsed_filename = parse_filename(filename);
            if (!parsed_filename) {
                continue;
            }
            files_to_remove.emplace(entry.path());
            auto session = read_session(entry.path());
            if (session && check_session_timings(session.get())) {
                sessions_counter++;
                auto entry = sorted_cache.find(parsed_filename->index);
                if (entry == sorted_cache.end()) {
                    entry = sorted_cache.insert(std::pair{parsed_filename->index, std::pair{parsed_filename->hash, std::map<size_t, DeclPtr<SSL_SESSION, &SSL_SESSION_free>>{}}}).first;
                    entry->second.first = parsed_filename->hash;
                }
                entry->second.second.insert({parsed_filename->session_index, std::move(session)});
            }
        }
        dbglog(g_logger, "Loaded {} SSL sessions for {} domains from disk cache", sessions_counter, sorted_cache.size());
        for (const auto &file: files_to_remove) {
            std::error_code ec;
            std::filesystem::remove(file, ec);
        }
        // Reversly build cache so last inserted session will become MRU
        for (auto itr = sorted_cache.rbegin(); itr != sorted_cache.rend(); itr++) {
            auto &[sni, sessions] = itr->second;
            SessionAccumulator session_accum;
            for (auto s_itr = sessions.rbegin(); s_itr != sessions.rend(); s_itr++) {
                session_accum.insert(std::move(s_itr->second));
            }
            m_session_cache.insert(sni, std::move(session_accum));
        }
    }

    void save_ssl_cache() {
        if (!exists(m_dir)) {
            return;
        }
        std::lock_guard l{m_session_cache_mutex};
        size_t sessions_counter = 0;
        size_t hash_index = 0;
        m_session_cache.iterate_values([&](const std::string &hash, const SessionAccumulator &accum) {
            size_t session_index = 0;
            for (const auto &session : accum.list()) {
                if (session && check_session_timings(session.get())) {
                    auto key = std::string(FILE_PREFIX) + std::to_string(hash_index) + INDEX_DELIMETER + std::to_string(session_index) + INDEX_DELIMETER + hash;
                    write_session(m_dir/key, session.get());
                    session_index++;
                }
            }
            hash_index++;
            sessions_counter += session_index;
            return true;
        });
        dbglog(g_logger, "Cached {} SSL sessions for {} domains on disk", sessions_counter, hash_index);
    }

private:
    static constexpr std::string_view FILE_PREFIX = "cache_";
    static constexpr char INDEX_DELIMETER = '_';

    struct FileNameEntry {
        size_t index;
        size_t session_index;
        std::string_view hash;
    };
    std::optional<FileNameEntry> parse_filename(std::string_view filename) {
        if (!filename.starts_with(FILE_PREFIX)) {
            return std::nullopt;
        }
        filename.remove_prefix(FILE_PREFIX.size());
        auto index_str = filename.substr(0, filename.find_first_of(INDEX_DELIMETER));
        size_t index = 0;
        auto ec = std::from_chars(index_str.data(), index_str.data() + index_str.size(), index).ec;
        if (ec != std::errc()) {
            return std::nullopt;
        }
        filename.remove_prefix(index_str.size() + 1);
        auto session_index_str = filename.substr(0, filename.find_first_of(INDEX_DELIMETER));
        size_t session_index = 0;
        ec = std::from_chars(session_index_str.data(), session_index_str.data() + session_index_str.size(), session_index).ec;
        if (ec != std::errc()) {
            return std::nullopt;
        }
        auto hash= filename.substr(session_index_str.size() + 1);
        return FileNameEntry{
            index,
            session_index,
            hash
        };
    }

    DeclPtr<SSL_SESSION, &SSL_SESSION_free> read_session(const std::filesystem::path &path) {
        if (!exists(path)) {
            return nullptr;
        }
        auto path_str = path.string();
        ag::UniquePtr<FILE, &fclose> f (fopen(path_str.c_str(), "r"));
        if (!f) {
            return nullptr;
        }
        SSL_SESSION *session = nullptr;
        if (PEM_read_SSL_SESSION(f.get(), &session, nullptr, nullptr)) {
            return DeclPtr<SSL_SESSION, &SSL_SESSION_free>{session};
        }
        return nullptr;
    }
    void write_session(const std::filesystem::path &path, SSL_SESSION *session) {
        auto path_str = path.string();
        ag::UniquePtr<FILE, &fclose> f (fopen(path_str.c_str(), "w"));
        if (!f) {
            return;
        }
        if (!PEM_write_SSL_SESSION(f.get(), session)) {
            remove(path);
        }
    }

    std::filesystem::path m_dir;
};

void dump_session_cache(const std::string &path) {
    SessionStorage(path).save_ssl_cache();
}

void load_session_cache(const std::string& path) {
    SessionStorage(path).load_ssl_cache();
}

#ifdef OPENSSL_IS_BORINGSSL
static int DecompressBrotliCert(SSL *ssl, CRYPTO_BUFFER **out, size_t uncompressed_len,
        const uint8_t *in, size_t in_len) {
    uint8_t *data;
    CRYPTO_BUFFER *decompressed = CRYPTO_BUFFER_alloc(&data, uncompressed_len);
    if (!decompressed) {
        return 0;
    }

    size_t output_size = uncompressed_len;
    if (BROTLI_DECODER_RESULT_SUCCESS != BrotliDecoderDecompress(in_len, in, &output_size, data)
            || output_size != uncompressed_len) {
        CRYPTO_BUFFER_free(decompressed);
        return 0;
    }

    *out = decompressed;
    return 1;
}
#endif

/* Converts group NID in library-independent way */
std::string kex_group_name_by_nid(int kex_group_nid) {
    switch (kex_group_nid) {
    case NID_secp224r1:
        return "P-224";
    case NID_X9_62_prime256v1:
        return "P-256";
    case NID_secp384r1:
        return "P-384";
    case NID_secp521r1:
        return "P-521";
    case NID_X25519:
        return "X25519";
#ifdef NID_X25519MLKEM768
    case NID_X25519MLKEM768:
        return "X25519MLKEM768";
#endif
    case NID_undef:
        return "None (TLS session ticket used)";
    default:
        return AG_FMT("Unknown {:04x}", kex_group_nid);
    }
}

std::variant<SslPtr, std::string> make_ssl(int (*verification_callback)(X509_STORE_CTX *, void *), void *arg,
        U8View alpn_protos, const char *sni, bool quic, U8View endpoint_data) {
    DeclPtr<SSL_CTX, SSL_CTX_free> ctx{SSL_CTX_new(TLS_client_method())};
    if (verification_callback && arg) {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_cert_verify_callback(ctx.get(), verification_callback, arg);
    }
    if (0 != SSL_CTX_set_alpn_protos(ctx.get(), alpn_protos.data(), alpn_protos.size())) {
        return "Failed to set ALPN protocols";
    }

    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(ctx.get(), cache_session_cb);

// Mimic Chrome's ClientHello if we are using BoringSSL.
#ifdef OPENSSL_IS_BORINGSSL
    if (SSL_CTX_add_cert_compression_alg(ctx.get(), TLSEXT_cert_compression_brotli, nullptr, DecompressBrotliCert) != 1) {
        return "Failed to add certificate compression algorithm";
    }

    SSL_CTX_set_permute_extensions(ctx.get(), true);

    if (!quic) {
        SSL_CTX_set_grease_enabled(ctx.get(), 1);
    }
#endif // OPENSSL_IS_BORINGSSL

    SslPtr ssl{SSL_new(ctx.get())};
    if (!SocketAddress{sni}.valid()) {
        if (0 == SSL_set_tlsext_host_name(ssl.get(), sni)) {
            return "Failed to set SNI";
        }
    }

#ifdef SSL_set_user_data
    if (!endpoint_data.empty()) {
        SSL_set_user_data(ssl.get(), endpoint_data.data(), endpoint_data.size());
    }
#endif

// Mimic Chrome's ClientHello if we are using BoringSSL.
#ifdef OPENSSL_IS_BORINGSSL
    SSL_set_enable_ech_grease(ssl.get(), 1);

    if (SSL_add_application_settings(ssl.get(), (uint8_t *)"h2", 2, nullptr, 0) != 1) {
        return "Failed to add ALPS extension";
    }
    SSL_set_alps_use_new_codepoint(ssl.get(), 1);

    // Use the BoringSSL defaults, but disable 3DES and SHA1 HMAC
    if (!SSL_set_strict_cipher_list(ssl.get(), "ALL:!aPSK:!ECDSA+SHA1:!3DES")) {
        return "Failed to set strict cipher list";
    }

    if (!SSL_set_min_proto_version(ssl.get(), TLS1_2_VERSION)
            || !SSL_set_max_proto_version(ssl.get(), TLS1_3_VERSION)) {
        return "Failed to set SSL versions";
    }

    static constexpr uint16_t GROUPS[] = {
            SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
    if (vpn_post_quantum_group_enabled() && !SSL_set1_group_ids(ssl.get(), GROUPS, std::size(GROUPS))) {
        return "Failed to set groups";
    }

    if (!quic) {
        SSL_enable_signed_cert_timestamps(ssl.get());

        // Request OCSP stapling.
        if (SSL_set_tlsext_status_type(ssl.get(), TLSEXT_STATUSTYPE_ocsp) != 1) {
            return "Failed to set OCSP state extension";
        }

        // Disable the SHA1 signature algorithm.
        // clang-format off
        static constexpr uint16_t SIGALGS[] = { SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_RSA_PSS_RSAE_SHA256,
                                        SSL_SIGN_RSA_PKCS1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
                                        SSL_SIGN_RSA_PSS_RSAE_SHA384, SSL_SIGN_RSA_PKCS1_SHA384,
                                        SSL_SIGN_RSA_PSS_RSAE_SHA512, SSL_SIGN_RSA_PKCS1_SHA512, };
        // clang-format on
        if (!SSL_set_verify_algorithm_prefs(ssl.get(), SIGALGS, std::size(SIGALGS))) {
            return "Failed to set signature algorithms";
        }
    }
#endif

    SSL_set_connect_state(ssl.get());

    if (auto session = pop_session_from_cache(sni)) {
        SSL_set_session(ssl.get(), session.get()); // Callee uprefs session.
    }

#ifdef __mips__
    if (!SSL_set_cipher_list(ssl.get(), "CHACHA20") || !SSL_set_ciphersuites(ssl.get(), "TLS_CHACHA20_POLY1305_SHA256")) {
        return "Failed to set CHACHA20 cipher";
    }
#endif

#if 0
    if (char *ssl_keylog_file = getenv("SSLKEYLOGFILE"); ssl_keylog_file != nullptr) {
        static DeclPtr<std::FILE, &std::fclose> handle{ std::fopen(ssl_keylog_file, "a") };
        SSL_CTX_set_keylog_callback(ctx.get(),
                [] (const SSL *, const char *line) {
                    fprintf(handle.get(), "%s\n", line);
                    fflush(handle.get());
                });
    }
#endif

    return ssl;
}

} // namespace ag
