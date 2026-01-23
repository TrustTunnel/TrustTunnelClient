#include <numeric>

#include "common/base64.h"
#include "common/net_utils.h"
#include "common/socket_address.h"
#include "common/utils.h"
#include "http_udp_multiplexer.h"
#include "vpn/internal/utils.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

std::string tunnel_addr_to_str(const TunnelAddress *tun_addr) {
    std::string out;

    if (const auto *addr = std::get_if<SocketAddress>(tun_addr)) {
        out = addr->str();
    } else {
        const auto &domain = std::get<NamePort>(*tun_addr);
        out = (domain.port == 0) ? domain.name : AG_FMT("{}:{}", domain.name, domain.port);
    }

    return out;
}

std::string make_buffer_file_path(const char *base_path, uint64_t id) {
    return str_format("%s/" CONN_BUFFER_FILE_NAME_FMT, base_path, (uint64_t) time(nullptr), id);
}

static bool is_conn_buffer_file(const char *fname) {
    uint64_t tmp;
    // NOLINTNEXTLINE(cert-err34-c)
    return 2 == std::sscanf(fname, CONN_BUFFER_FILE_NAME_FMT, &tmp, &tmp);
}

void clean_up_buffer_files(const char *dir) {
    std::error_code fs_err;
    if (!fs::exists(dir, fs_err) || fs_err) {
        return;
    }

    std::vector<fs::path> to_remove;
    fs::directory_iterator diter(dir, fs_err);
    while (!fs_err && diter != fs::directory_iterator()) {
        if (!diter->is_directory(fs_err) && !fs_err && is_conn_buffer_file(diter->path().filename().string().c_str())) {
            to_remove.push_back(diter->path());
        }
        diter = diter.increment(fs_err);
    }

    for (auto &i : to_remove) {
        fs::remove(i, fs_err);
    }
}

AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> vpn_upstream_config_clone(const VpnUpstreamConfig *src) {
    AutoPod<VpnUpstreamConfig, vpn_upstream_config_destroy> dst;
    std::memcpy(dst.get(), src, sizeof(*src));

    AutoPod location = vpn_location_clone(&src->location);
    std::memcpy(&dst->location, location.get(), sizeof(dst->location));
    location.release();

    dst->username = safe_strdup(src->username);
    dst->password = safe_strdup(src->password);

    return dst;
}

void vpn_upstream_config_destroy(VpnUpstreamConfig *config) {
    vpn_location_destroy(&config->location);
    // NOLINTBEGIN(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    free((void *) config->username);
    free((void *) config->password);
    // NOLINTEND(cppcoreguidelines-no-malloc,hicpp-no-malloc)
    *config = {};
}

static void set_auth_info(HttpHeaders *headers, std::string_view creds);

std::string headers_to_log_str(const HttpHeaders &headers) {
    std::string ret;
    if (headers.status_code == 0) {
        HttpHeaders sheaders = headers;
        sheaders.remove_field("proxy-authorization");
        set_auth_info(&sheaders, "__stripped__");
        ret = http_headers_to_http1_message(&sheaders, false);
    } else {
        ret = http_headers_to_http1_message(&headers, false);
    }

    return ret;
}

// Connection errors

// DNS resolution failed (reasons see below)
// HTTP/1.1 502 Bad Gateway
// X-Adguard-Vpn-Error: <hostname>
// X-Warning: <warn-code> - <warn-text>

// For other reasons:
// HTTP/1.1 502 Bad Gateway
// X-Warning: <warn-code> - <warn-text>

// Warn codes:
enum VpnWarnCode {
    CONNECTION_FAILED = 300,   // Connection failed for some reasons
    HOST_UNREACHABLE = 301,    // Remote host is unreachable
    CONNECTION_TIMEDOUT = 302, // Connection timed out
    DNS_NONROUTABLE = 310,     // DNS: resolved address in non-routable network
    DNS_LOOPBACK = 311,        // DNS: resolved address in loopback
    DNS_BLOCKED = 312,         // DNS: blocked by Adguard DNS
};

VpnError bad_http_response_to_connect_error(const HttpHeaders *response) {
    VpnError err = {ag::utils::AG_ECONNREFUSED, "Bad response status"};
    if (response->status_code != HTTP_STATUS_502_BAD_GATEWAY) {
        return err;
    }

    if (auto vpn_error = response->get_field("X-Adguard-Vpn-Error")) {
        // do nothing - DNS resolution error, just return refused
    } else if (auto warning = response->get_field("X-Warning")) {
        if (auto code = ag::utils::to_integer<int>(*warning)) {
            switch (*code) {
            case HOST_UNREACHABLE:
                err.code = AG_ENETUNREACH;
                break;
            case CONNECTION_TIMEDOUT:
                err.code = ag::utils::AG_ETIMEDOUT;
                break;
            default:
                break;
            }
        }
    }

    return err;
}

// Put `user-agent: <platform> <app_name>`, e.g. `user-agent: Windows chrome.exe`
static void put_user_agent(HttpHeaders *headers, std::string_view app_name) {
    char buf[2 * UDPPKT_APP_MAXSIZE];
    int r = snprintf(buf, sizeof(buf), "%s %.*s", AG_PLATFORM, (int) app_name.size(), app_name.data());
    headers->put_field("user-agent", std::string{buf, size_t(r)});
}

static void set_auth_info(HttpHeaders *headers, std::string_view creds) {
    headers->put_field("proxy-authorization", AG_FMT("Basic {}", creds));
}

HttpHeaders make_http_connect_request(
        HttpVersion version, const TunnelAddress *dst_addr, std::string_view app_name, std::string_view creds) {
    HttpHeaders headers{.version = version};
    headers.method = HTTP_METHOD_CONNECT;
    headers.authority = tunnel_addr_to_str(dst_addr);
    put_user_agent(&headers, app_name.empty() ? "unknown" : app_name);
    set_auth_info(&headers, creds);
    return headers;
}

std::string make_credentials(std::string_view username, std::string_view password) {
    std::string creds =
            str_format("%.*s:%.*s", (int) username.length(), username.data(), (int) password.length(), password.data());
    return ag::encode_to_base64({(uint8_t *) creds.data(), creds.size()}, false);
}

} // namespace ag
