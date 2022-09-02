#pragma once

#include <cstdlib>
#include <cstring>

#include "net/http_header.h"

namespace ag {

/**
 * Convert a pair of major and minor version digits to `http_version_t` enum
 * @param major major digit
 * @param minor minor digit
 * @return see `http_version_t` enum
 */
HttpVersion http_make_version(int major, int minor);

/**
 * Returns major digit of HTTP protocol version
 * @param v see `http_version_t` enum
 * @return major digit
 */
int http_version_get_major(HttpVersion v);

/**
 * Returns minor digit of HTTP protocol version
 * @param v see `http_version_t` enum
 * @return minor digit
 */
int http_version_get_minor(HttpVersion v);

} // namespace ag
