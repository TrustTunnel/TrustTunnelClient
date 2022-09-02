#include <numeric>

#include "common/base64.h"
#include "common/net_utils.h"
#include "common/utils.h"
#include "http_udp_multiplexer.h"
#include "vpn/internal/utils.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

std::string tunnel_addr_to_str(const TunnelAddress *tun_addr) {
    std::string out = {};

    if (const sockaddr_storage *addr = std::get_if<sockaddr_storage>(tun_addr)) {
        out = sockaddr_to_str((sockaddr *) addr);
    } else if (const NamePort *domain = std::get_if<NamePort>(tun_addr)) {
        out.reserve(domain->name.length() + 6);
        out += domain->name;
        if (domain->port > 0) {
            out += ":";
            out += std::to_string(domain->port);
        }
    }

    return out;
}

std::string make_buffer_file_path(const char *base_path, uint64_t id) {
    return str_format("%s/" CONN_BUFFER_FILE_NAME_FMT, base_path, (uint64_t) time(nullptr), id);
}

static bool is_conn_buffer_file(const char *fname) {
    uint64_t tmp;
    return 2 == std::sscanf(fname, CONN_BUFFER_FILE_NAME_FMT, &tmp, &tmp);
}

void clean_up_buffer_files(const char *dir) {
    if (!fs::exists(dir)) {
        return;
    }

    std::vector<fs::path> to_remove;
    for (const auto &i : fs::directory_iterator{ dir }) {
        if (!i.is_directory() && is_conn_buffer_file(i.path().filename().string().c_str())) {
            to_remove.push_back(i);
        }
    }

    for (auto &i : to_remove) {
        fs::remove(i);
    }
}

VpnUpstreamConfig vpn_upstream_config_clone(const VpnUpstreamConfig *src) {
    VpnUpstreamConfig dst = *src;

    vpn_location_clone(&dst.location, &src->location);
    dst.username = safe_strdup(src->username);
    dst.password = safe_strdup(src->password);

    return dst;
}

void vpn_upstream_config_destroy(VpnUpstreamConfig *config) {
    vpn_location_destroy(&config->location);
    free((char *) config->username);
    free((char *) config->password);

    *config = {};
}

static void set_auth_info(HttpHeaders *headers, std::string_view creds);

void log_headers(const ag::Logger &log, uint64_t stream_id, const HttpHeaders *headers, const char *msg) {
    if (log.is_enabled(ag::LOG_LEVEL_DEBUG)) {
        std::string hdr_str;
        if (headers->status_code == 0) {
            HttpHeaders sheaders = *headers;
            sheaders.remove_field("proxy-authorization");
            set_auth_info(&sheaders, "__stripped__");
            hdr_str = http_headers_to_http1_message(&sheaders, false);
        } else {
            hdr_str = http_headers_to_http1_message(headers, false);
        }
        hdr_str = http_headers_to_http1_message(headers, false);
        dbglog(log, "[SID:{}] {}:\n{}", stream_id, msg, hdr_str);
    }
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
    if (response->status_code != 502) {
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

std::variant<SslPtr, std::string> make_ssl(
        int (*verification_callback)(X509_STORE_CTX *, void *), void *arg, U8View alpn_protos, const char *sni) {
    DeclPtr<SSL_CTX, SSL_CTX_free> ctx{SSL_CTX_new(TLS_client_method())};
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx.get(), verification_callback, arg);
    if (0 != SSL_CTX_set_alpn_protos(ctx.get(), alpn_protos.data(), alpn_protos.size())) {
        return "Failed to set ALPN protocols";
    }

    SslPtr ssl{SSL_new(ctx.get())};
    if (0 == SSL_set_tlsext_host_name(ssl.get(), sni)) {
        return "Failed to set SNI";
    }

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
