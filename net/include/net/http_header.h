#pragma once

#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ag {

enum HttpVersion {
    HTTP_VER_1_1 = 0x0101,
    HTTP_VER_2_0 = 0x0200,
    HTTP_VER_3_0 = 0x0300,
};

enum HttpStatusCode {
    HTTP_STATUS_100_CONTINUE = 100,
    HTTP_STATUS_103_EARLY_HINTS = 103,
    HTTP_STATUS_200_OK = 200,
    HTTP_STATUS_204_NO_CONTENT = 204,
    HTTP_STATUS_205_RESET_CONTENT = 205,
    HTTP_STATUS_304_NOT_MODIFIED = 304,
    HTTP_STATUS_502_BAD_GATEWAY = 502,
};

struct HttpHeaderField {
    std::string name;
    std::string value;

    HttpHeaderField();
    HttpHeaderField(std::string name, std::string value);
};

static constexpr std::string_view METHOD_PH_FIELD = ":method";
static constexpr std::string_view SCHEME_PH_FIELD = ":scheme";
static constexpr std::string_view AUTHORITY_PH_FIELD = ":authority";
static constexpr std::string_view PATH_PH_FIELD = ":path";
static constexpr std::string_view STATUS_PH_FIELD = ":status";

/**
 * List of HTTP headers
 * Pseudo-header fields are first
 * HTTP/1.1 status line fields are represented with the following pseudo-header fields:
 * Request: <:method> <:path> HTTP/1.1
 * Response: HTTP/1.1 <:status> <:status-message>
 */
struct HttpHeaders {
    HttpVersion version;
    bool has_body;
    int status_code;
    std::string path;
    std::string status_string;
    std::string method;
    std::string scheme;
    std::string authority;
    std::vector<HttpHeaderField> fields;

    [[nodiscard]] bool contains_field(std::string_view name) const;
    [[nodiscard]] std::optional<std::string_view> get_field(std::string_view name) const;
    void put_field(std::string name, std::string value);
    void remove_field(std::string_view name);
};

} // namespace ag
