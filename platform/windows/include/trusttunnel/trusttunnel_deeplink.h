#pragma once

#include "vpn/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Decode a `tt://` deep-link URI into a NULL-terminated `[endpoint]` TOML section string.
 * @param uri The `tt://` deep-link URI to decode.
 * @return On success, a heap-allocated string the caller MUST free with
 *         `trusttunnel_free_deeplink_string()`. On failure, NULL; the reason is logged by the
 *         adapter.
 */
WIN_EXPORT char *trusttunnel_decode_deeplink(const char *uri);

/**
 * Encode an `[endpoint]` TOML section string into a `tt://` deep-link URI. The input must use
 * the same `[endpoint]` TOML layout that `trusttunnel_decode_deeplink()` produces.
 * @param endpoint_toml The `[endpoint]` TOML section to encode.
 * @return On success, a heap-allocated string the caller MUST free with
 *         `trusttunnel_free_deeplink_string()`. On failure, NULL; the reason is logged by the
 *         adapter.
 */
WIN_EXPORT char *trusttunnel_encode_deeplink(const char *endpoint_toml);

/**
 * Free a string returned by `trusttunnel_decode_deeplink()` or `trusttunnel_encode_deeplink()`.
 * Passing NULL is safe and has no effect.
 */
WIN_EXPORT void trusttunnel_free_deeplink_string(char *str);

#ifdef __cplusplus
} // extern "C"
#endif
