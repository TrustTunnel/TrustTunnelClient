#include "util.h"

#include <cctype>
#include <cstdio>
#include <cstring>

#include "common/utils.h"
#include "net/http_header.h"
#include "net/http_session.h"
#include "vpn/platform.h"
#include "vpn/utils.h"

namespace ag {

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
    return dst;
}

void vpn_endpoint_destroy(VpnEndpoint *endpoint) {
    if (endpoint == nullptr) {
        return;
    }

    free((char *) endpoint->name);
    std::memset(endpoint, 0, sizeof(*endpoint));
}

bool vpn_endpoint_equals(const VpnEndpoint *lh, const VpnEndpoint *rh) {
    return sockaddr_equals((struct sockaddr *) &lh->address, (struct sockaddr *) &rh->address)
            && 0 == strcmp(lh->name, rh->name);
}

AutoVpnLocation vpn_location_clone(const VpnLocation *src) {
    AutoVpnLocation dst;
    std::memcpy(dst.get(), src, sizeof(*src));
    dst->id = safe_strdup(src->id);

    dst->endpoints = {};
    dst->endpoints.data = (VpnEndpoint *) malloc(src->endpoints.size * sizeof(VpnEndpoint));

    for (size_t i = 0; i < src->endpoints.size; ++i) {
        AutoVpnEndpoint e = vpn_endpoint_clone(&src->endpoints.data[i]);
        std::memcpy(&dst->endpoints.data[dst->endpoints.size++], e.get(), sizeof(*e.get()));
        e.release();
    }

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

    std::memset(location, 0, sizeof(*location));
}

} // namespace ag
