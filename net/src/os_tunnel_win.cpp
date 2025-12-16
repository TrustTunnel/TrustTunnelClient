#include "os_tunnel_win.h"

#include <cstdarg>
#include <utility>

#include <openssl/sha.h>

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <winreg.h>
#include <winsock2.h>
#include <winternl.h>
#include <ws2ipdef.h>
#include <netioapi.h>

#include "common/utils.h"
#include "common/socket_address.h"
#include "net/network_manager.h"
#include "net/os_tunnel.h"
#include "vpn/guid_utils.h"
#include "vpn/utils.h"

// Need to link with Iphlpapi.lib and Ws2_32.lib
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static const ag::Logger logger("OS_TUNNEL_WIN");
static const ag::Logger wintun_logger("WINTUN");

static constexpr std::string_view WINREG_INTERFACES_PATH_V4 =
        R"(SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces)";
static constexpr std::string_view WINREG_INTERFACES_PATH_V6 =
        R"(SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces)";

static constexpr DWORD WINTUN_RING_CAPACITY = 0x1000000; // 16 MiB
static constexpr DWORD WINTUN_RING_CAPACITY_ZEROCOPY = WINTUN_MAX_RING_CAPACITY;

struct WintunThreadParams {
    HANDLE recv_event;
    HANDLE quit_event;
    void (*read_callback)(void *arg);
    void *read_callback_arg;
};

static void CALLBACK log_wintun(WINTUN_LOGGER_LEVEL level, DWORD64 /*timestamp*/, LPCWSTR log_line)
{
    switch (level) {
    case WINTUN_LOG_INFO:
        infolog(wintun_logger, "{}", ag::utils::from_wstring(log_line));
        break;
    case WINTUN_LOG_WARN:
        warnlog(wintun_logger, "{}", ag::utils::from_wstring(log_line));
        break;
    case WINTUN_LOG_ERR:
        errlog(wintun_logger, "{}", ag::utils::from_wstring(log_line));
        break;
    default:
        return;
    }
}

static bool initialize_wintun(HMODULE wintun) {
    if (!wintun) {
        return false;
    }
#define X(name) ((*(FARPROC *) &name = GetProcAddress(wintun, #name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID)
            || X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession)
            || X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket)
            || X(WintunReleaseReceivePacket) || X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD last_error = GetLastError();
        FreeLibrary(wintun);
        SetLastError(last_error);
        return false;
    }
    WintunSetLogger(log_wintun);
    return true;
}

static GUID uuid_v5(std::string_view uuid_namespace, std::string_view uuid_data) {
    SHA_CTX ctx;
    uint8_t hash[SHA_DIGEST_LENGTH];
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, uuid_namespace.data(), uuid_namespace.size());
    SHA1_Update(&ctx, uuid_data.data(), uuid_data.size());
    SHA1_Final(hash, &ctx);
    GUID guid;
    memcpy(&guid, hash, sizeof(guid));
    guid.Data3 = (guid.Data3 & 0x0FFF) | 0x5000;
    return guid;
}

static WINTUN_ADAPTER_HANDLE create_wintun_adapter(std::string_view adapter_name, std::string_view tunnel_type) {
    std::wstring adapter_name_wide = ag::utils::to_wstring(adapter_name);
    std::wstring tunnel_type_wide = ag::utils::to_wstring(tunnel_type);
    WINTUN_ADAPTER_HANDLE adapter = WintunOpenAdapter(adapter_name_wide.c_str());
    if (!adapter) {
        dbglog(logger, "WintunOpenAdapter: {}", ag::sys::strerror(ag::sys::last_error()));
        GUID guid = uuid_v5("VpnLibsTunnels", adapter_name);
        adapter = WintunCreateAdapter(adapter_name_wide.c_str(), tunnel_type_wide.c_str(), &guid);
        if (!adapter) {
            errlog(logger, "WintunCreateAdapter: {}", ag::sys::strerror(ag::sys::last_error()));
            return nullptr;
        }
    }
    return adapter;
}

static void WINAPI send_wintun_packet(WINTUN_SESSION_HANDLE session, std::span<const evbuffer_iovec> chunks) {
    size_t sum_chunks_len = 0;
    for (size_t i = 0; i < chunks.size();) {
        sum_chunks_len += chunks[i++].iov_len;
    }
    BYTE *packet = WintunAllocateSendPacket(session, sum_chunks_len);
    if (packet) {
        BYTE *pos = packet;
        for (size_t i = 0; i < chunks.size(); pos += chunks[i++].iov_len) {
            std::memcpy(pos, chunks[i].iov_base, chunks[i].iov_len);
        }
        WintunSendPacket(session, packet);
    } else {
        warnlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
    }
}

static void receive_wintun_packets(std::unique_ptr<WintunThreadParams> params) {
    HANDLE wait_handles[] = {params->quit_event, params->recv_event};
    while (WaitForMultipleObjects(std::size(wait_handles), wait_handles, false, INFINITE) != WAIT_OBJECT_0) {
        params->read_callback(params->read_callback_arg);
    }
}

static uint32_t get_wintun_adapter_index(WINTUN_ADAPTER_HANDLE Adapter) {
    NET_LUID_LH interface_luid;
    WintunGetAdapterLUID(Adapter, &interface_luid);
    NET_IFINDEX if_idx = 0;
    ConvertInterfaceLuidToIndex(&interface_luid, &if_idx);
    return if_idx;
}

static WINTUN_SESSION_HANDLE create_wintun_session(const ag::CidrRange &addr_v4, const ag::CidrRange &addr_v6,
        WINTUN_ADAPTER_HANDLE adapter, DWORD ring_capacity) {
    if (!addr_v4.valid()) {
        errlog(logger, "ipv4 address not specified");
        return nullptr;
    }
    ag::SocketAddress saddr_v4{{addr_v4.get_address().begin(), addr_v4.get_address().end()}, 0};
    MIB_UNICASTIPADDRESS_ROW address_v4_row;
    InitializeUnicastIpAddressEntry(&address_v4_row);
    WintunGetAdapterLUID(adapter, &address_v4_row.InterfaceLuid);
    address_v4_row.Address.Ipv4.sin_family = AF_INET;
    address_v4_row.Address.Ipv4.sin_addr = ((sockaddr_in *) saddr_v4.c_sockaddr())->sin_addr;
    address_v4_row.DadState = IpDadStatePreferred;
    auto last_error = CreateUnicastIpAddressEntry(&address_v4_row);
    if (last_error != ERROR_SUCCESS && last_error != ERROR_OBJECT_ALREADY_EXISTS) {
        SetLastError(last_error);
        errlog(logger, "Set ipv4: {}", ag::sys::strerror(ag::sys::last_error()));
        return nullptr;
    }
    if (addr_v6.valid()) {
        ag::SocketAddress saddr_v6{{addr_v6.get_address().begin(), addr_v6.get_address().end()}, 0};
        MIB_UNICASTIPADDRESS_ROW address_v6_row;
        InitializeUnicastIpAddressEntry(&address_v6_row);
        WintunGetAdapterLUID(adapter, &address_v6_row.InterfaceLuid);
        address_v6_row.Address.Ipv6.sin6_family = AF_INET6;
        address_v6_row.Address.Ipv6.sin6_addr = ((sockaddr_in6 *) saddr_v6.c_sockaddr())->sin6_addr;
        address_v6_row.DadState = IpDadStatePreferred;
        last_error = CreateUnicastIpAddressEntry(&address_v6_row);
        if (last_error != ERROR_SUCCESS && last_error != ERROR_OBJECT_ALREADY_EXISTS) {
            SetLastError(last_error);
            warnlog(logger, "Set ipv6: {}", ag::sys::strerror(ag::sys::last_error()));
        }
    }
    WINTUN_SESSION_HANDLE session = WintunStartSession(adapter, ring_capacity);
    if (!session) {
        errlog(logger, "Init session: {}", ag::sys::strerror(ag::sys::last_error()));
        return nullptr;
    }
    return session;
}

static void close_wintun(WINTUN_SESSION_HANDLE session, WINTUN_ADAPTER_HANDLE adapter) {
    if (session) {
        WintunEndSession(session);
    }
    if (adapter) {
        WintunCloseAdapter(adapter);
    }
}

ag::VpnError ag::VpnWinTunnel::init(
        const ag::VpnOsTunnelSettings *settings, const ag::VpnWinTunnelSettings *win_settings) {
    init_settings(settings);
    init_win_settings(win_settings);
    bool wintun_init_success = initialize_wintun(win_settings->wintun_lib);
    if (!wintun_init_success) {
        return {-1, "Unable to init wintun library"};
    }
    m_wintun_adapter = create_wintun_adapter(win_settings->adapter_name, win_settings->tunnel_type);
    if (m_wintun_adapter == nullptr) {
        return {-1, "Unable to create wintun adapter"};
    }
    m_wintun_quit_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (m_wintun_quit_event == nullptr) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to create wintun quit event"};
    }
    m_if_index = get_wintun_adapter_index(m_wintun_adapter);
    CidrRange ipv4_address = tunnel_utils::get_address_for_index(settings->ipv4_address, m_if_index);
    CidrRange ipv6_address = tunnel_utils::get_address_for_index(settings->ipv6_address, m_if_index);
    m_wintun_session = create_wintun_session(ipv4_address, ipv6_address, m_wintun_adapter,
            win_settings->zerocopy ? WINTUN_RING_CAPACITY_ZEROCOPY : WINTUN_RING_CAPACITY);
    if (m_wintun_session == nullptr) {
        return {-1, "Unable to create wintun session"};
    }
    if (!setup_mtu()) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to set mtu for wintun session"};
    }
    m_system_dns_setup_success = setup_dns();
    if (!m_system_dns_setup_success) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to set dns for wintun session"};
    }
    if (m_win_settings->block_ipv6) {
        if (auto error = m_firewall.block_ipv6()) {
            errlog(logger, "Failed to block IPv6: {}", error->str());
            return {-1, "Failed to block IPv6"};
        }
    }
    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);
    if (!setup_routes(ipv4_routes, ipv6_routes)) {
        errlog(logger, "{}", ag::sys::strerror(ag::sys::last_error()));
        return {-1, "Unable to setup routes for wintun session"};
    }
    if (win_settings->block_untunneled) {
        std::vector<uint16_t> excl_ports;
        if (win_settings->block_untunneled_exclude_ports) {
            for (std::string_view port_str : utils::split_by(win_settings->block_untunneled_exclude_ports, '|')) {
                if (auto port = utils::to_integer<uint16_t>(port_str)) {
                    excl_ports.emplace_back(*port);
                }
            }
        }
        if (auto err = m_firewall.block_untunneled(ipv4_address, ipv6_address, ipv4_routes, ipv6_routes, excl_ports)) {
            errlog(logger, "Failed to block incoming: {}", err->str());
            return {-1, "Failed to block incoming"};
        }
    }
    return {};
}

bool ag::VpnWinTunnel::setup_mtu() {
    MIB_IPINTERFACE_ROW row{};
    row.InterfaceIndex = m_if_index;
    // set mtu for ipv4 and ipv6
    row.Family = AF_INET;
    if (DWORD error = GetIpInterfaceEntry(&row); error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    // needed on ipv4 for correct work
    row.SitePrefixLength = 0;
    row.NlMtu = m_settings->mtu;
    if (DWORD error = SetIpInterfaceEntry(&row); error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    row.Family = AF_INET6;
    if (DWORD error = GetIpInterfaceEntry(&row); error == ERROR_SUCCESS) {
        row.NlMtu = m_settings->mtu;
        error = SetIpInterfaceEntry(&row);
        if (error != ERROR_SUCCESS) {
            SetLastError(error);
            return false;
        }
    }
    return true;
}

static DWORD set_dns_via_registry(std::string_view dns_list, std::string_view if_guid, bool ipv6 = false) {
    HKEY current_key{};
    DWORD error = ERROR_SUCCESS;
    std::string_view interfaces_path;
    if (ipv6) {
        interfaces_path = WINREG_INTERFACES_PATH_V6;
    } else {
        interfaces_path = WINREG_INTERFACES_PATH_V4;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, interfaces_path.data(), 0, KEY_ALL_ACCESS, &current_key)
            == ERROR_SUCCESS) {
        // set dns for specified interface
        error = RegSetKeyValueA(current_key, if_guid.data(), "NameServer", REG_SZ, dns_list.data(), dns_list.size());
        RegCloseKey(current_key);
    }
    return error;
}

static IP_ADDRESS_PREFIX ip_address_prefix_from_cidr_range(const ag::CidrRange &route) {
    IP_ADDRESS_PREFIX value{};
    ag::SocketAddress addr({route.get_address().data(), route.get_address().size()}, 0);
    std::memcpy(&value.Prefix, addr.c_storage(), sizeof(SOCKADDR_INET));
    value.PrefixLength = route.get_prefix_len();
    return value;
}

static bool add_adapter_route(const ag::CidrRange &route, uint32_t if_index) {
    MIB_IPFORWARD_ROW2 row{};
    InitializeIpForwardEntry(&row);

    row.DestinationPrefix = ip_address_prefix_from_cidr_range(route);
    row.InterfaceIndex = if_index;

    DWORD error = CreateIpForwardEntry2(&row);
    if (error != ERROR_SUCCESS) {
        errlog(logger, "Cannot create route {}: {} ({})", route.to_string(), ag::sys::strerror(error), error);
        SetLastError(error);
        return false;
    }
    return true;
}

bool ag::VpnWinTunnel::setup_dns() {
    std::string dns_nameserver_list_v4;
    std::string dns_nameserver_list_v6;
    ag::tunnel_utils::get_setup_dns(dns_nameserver_list_v4, dns_nameserver_list_v6, m_settings->dns_servers);

    NET_LUID_LH interface_luid;
    WintunGetAdapterLUID(m_wintun_adapter, &interface_luid);
    GUID interface_guid;
    DWORD error = ConvertInterfaceLuidToGuid(&interface_luid, &interface_guid);
    if (error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    auto str_if_guid = guid_to_string(interface_guid);
    if (error = set_dns_via_registry(dns_nameserver_list_v4, str_if_guid, false); error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }
    if (error = set_dns_via_registry(dns_nameserver_list_v6, str_if_guid, true); error != ERROR_SUCCESS) {
        SetLastError(error);
        return false;
    }

    std::vector<ag::SocketAddress> dns_servers;
    dns_servers.reserve(m_settings->dns_servers.size);
    for (size_t i = 0; i != m_settings->dns_servers.size; i++) {
        dns_servers.emplace_back(ag::SocketAddress(m_settings->dns_servers.data[i]));
    }

    std::vector<ag::CidrRange> ipv4_routes;
    std::vector<ag::CidrRange> ipv6_routes;
    ag::tunnel_utils::get_setup_routes(
            ipv4_routes, ipv6_routes, m_settings->included_routes, m_settings->excluded_routes);

    // Add adapter DNS addresses to the list of destinations to restrict DNS traffic to,
    // to make sure that they are accessible even if not explicitly in the "included_routes" list.
    for (const ag::SocketAddress &dns_server : dns_servers) {
        std::vector<CidrRange> *routes;
        if (dns_server.is_ipv4()) {
            routes = &ipv4_routes;
        } else if (dns_server.is_ipv6()) {
            routes = &ipv6_routes;
        } else {
            continue;
        }
        routes->emplace_back(dns_server.addr(), dns_server.c_socklen());
    }

    if (auto error = m_firewall.restrict_dns_to(ipv4_routes, ipv6_routes)) {
        errlog(logger, "Failed to restrict DNS traffic: {}", error->str());
        return false;
    }

    for (const ag::SocketAddress &dns_server : dns_servers) {
        ag::CidrRange route{dns_server.addr(), dns_server.addr().length() * CHAR_BIT};
        if (!add_adapter_route(route, m_if_index)) {
            return false;
        }
    }

    return true;
}

bool ag::VpnWinTunnel::setup_routes(std::span<const CidrRange> ipv4_routes, std::span<const CidrRange> ipv6_routes) {
    for (auto &route : ipv4_routes) {
        if (!add_adapter_route(route, m_if_index)) {
            auto splitted = route.split();
            if (!splitted
                    || !add_adapter_route(splitted->first, m_if_index)
                    || !add_adapter_route(splitted->second, m_if_index)) {
                return false;
            }
        }
    }

    if (MIB_IPINTERFACE_ROW row{.Family = AF_INET6, .InterfaceIndex = m_if_index};
            ERROR_SUCCESS == GetIpInterfaceEntry(&row)) {
        for (auto &route : ipv6_routes) {
            if (!add_adapter_route(route, m_if_index)) {
                auto splitted = route.split();
                if (!splitted
                        || !add_adapter_route(splitted->first, m_if_index)
                        || !add_adapter_route(splitted->second, m_if_index)) {
                    return false;
                }
            }
        }
    }
    return true;
}

void ag::VpnWinTunnel::deinit() {
    stop_recv_packets(); // for case when it wasn't called manually
    close_wintun(m_wintun_session, m_wintun_adapter);
    m_wintun_session = nullptr;
    m_wintun_adapter = nullptr;
    m_system_dns_setup_success = false;
}

evutil_socket_t ag::VpnWinTunnel::get_fd() {
    return EVUTIL_INVALID_SOCKET;
}

std::string ag::VpnWinTunnel::get_name() {
    char buf[IF_NAMESIZE + 1] = "";
    char *res = if_indextoname(m_if_index, buf);
    return res ? res : "";
}

bool ag::VpnWinTunnel::get_system_dns_setup_success() const {
    return m_system_dns_setup_success;
}

std::optional<ag::VpnPacket> ag::VpnWinTunnel::recv_packet() {
    DWORD size;
    BYTE *data = WintunReceivePacket(m_wintun_session, &size);
    if (data == nullptr) {
        if (DWORD last_error = GetLastError(); last_error != ERROR_NO_MORE_ITEMS) {
            warnlog(logger, "WintunReceivePacket(): ({}) {}", last_error, ag::sys::strerror(last_error));
        }
        return std::nullopt;
    }
    if (m_win_settings->zerocopy) {
        return VpnPacket{
            .data = (uint8_t *) data,
            .size = (size_t) size,
            .destructor = [](void *arg, uint8_t *data) {
                WintunReleaseReceivePacket((WINTUN_SESSION_HANDLE) arg, data);
            },
            .destructor_arg = m_wintun_session,
        };
    }
    VpnPacket packet{
        .data = (uint8_t *) std::malloc(size),
        .size = (size_t) size,
        .destructor = [](void *, uint8_t *data) {
            std::free(data);
        },
    };
    std::memcpy(packet.data, data, packet.size);
    WintunReleaseReceivePacket(m_wintun_session, data);
    return packet;
}

void ag::VpnWinTunnel::start_recv_packets(void (*read_callback)(void *arg), void *read_callback_arg) {
    ResetEvent(m_wintun_quit_event);
    std::unique_ptr<WintunThreadParams> pass_params(new WintunThreadParams{
            WintunGetReadWaitEvent(m_wintun_session), m_wintun_quit_event, read_callback, read_callback_arg});
    m_recv_thread_handle = std::make_unique<std::thread>(receive_wintun_packets, std::move(pass_params));
}

void ag::VpnWinTunnel::send_packet(std::span<const evbuffer_iovec> chunks) {
    send_wintun_packet(m_wintun_session, chunks);
}

void ag::VpnWinTunnel::stop_recv_packets() {
    if (m_recv_thread_handle) {
        dbglog(logger, "Stopping receiving packets");
        SetEvent(m_wintun_quit_event);
        m_recv_thread_handle->join();
        m_recv_thread_handle.reset();
        dbglog(logger, "Stopped receiving packets");
    }
}
ag::VpnWinTunnel::~VpnWinTunnel() {
    close_wintun(m_wintun_session, m_wintun_adapter);
    CloseHandle(m_wintun_quit_event);
}

void *ag::vpn_win_tunnel_create(ag::VpnOsTunnelSettings *settings, ag::VpnWinTunnelSettings *win_settings) {
    auto *tunnel = new ag::VpnWinTunnel{};
    auto res = tunnel->init(settings, win_settings);
    if (res.code != 0) {
        dbglog(logger, "Error initializing tunnel: {}", res.text ? res.text : "(null)");
        delete tunnel;
        return nullptr;
    }
    return tunnel;
}

void ag::vpn_win_tunnel_destroy(void *win_tunnel) {
    delete (VpnWinTunnel *) win_tunnel;
}

static bool protect_with_bind(evutil_socket_t fd, const ag::SocketAddress *addr, uint32_t bound_if) {
    SOCKADDR_INET source_best{};
    MIB_IPFORWARD_ROW2 row{};

    if (int error = GetBestRoute2(
                nullptr, bound_if, nullptr, (const SOCKADDR_INET *) addr->c_storage(), 0, &row, &source_best);
            error != ERROR_SUCCESS) {
        dbglog(logger, "GetBestRoute2(): {}", ag::sys::strerror(error));
        return false;
    }

    ag::SocketAddress src_best((sockaddr *) &source_best);
    if (0 != bind(fd, src_best.c_sockaddr(), src_best.c_socklen())) {
        dbglog(logger, "Failed to bind socket to interface: {}", ag::sys::strerror(WSAGetLastError()));
        return false;
    }

    return true;
}

static bool protect_with_unicast_if(evutil_socket_t fd, const ag::SocketAddress *addr, uint32_t bound_if) {
    if (addr->is_ipv4()) {
        // WinSock expects IPv4 address in network byte order
        bound_if = htonl(bound_if);
        if (0 != setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (char *) &bound_if, sizeof(bound_if))) {
            dbglog(logger, "setsockopt(IP_UNICAST_IF): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
    } else if (addr->is_ipv6()) {
        // IPV6_UNICAST_IF is 32-bit int in host byte order
        if (0 != setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_IF, (char *) &bound_if, sizeof(bound_if))) {
            dbglog(logger, "setsockopt(IPV6_UNICAST_IF): {}", ag::sys::strerror(WSAGetLastError()));
            return false;
        }
    } else {
        dbglog(logger, "Unexpected address family: {}", addr->c_storage()->sa_family);
        return false;
    }
    return true;
}

bool ag::vpn_win_socket_protect(evutil_socket_t fd, const sockaddr *addr) {
    uint32_t bound_if = vpn_network_manager_get_outbound_interface();
    if (bound_if == 0) {
        return true;
    }

    ag::SocketAddress sa(addr);
    const bool bind_protect_success = protect_with_bind(fd, &sa, bound_if);
    const bool unicast_protect_success = protect_with_unicast_if(fd, &sa, bound_if);
    if (!bind_protect_success && !unicast_protect_success) {
        warnlog(logger, "Failed to protect socket");
        return false;
    }

    return true;
}
