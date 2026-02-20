#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque error object. Always free with `trusttunnel_deeplink_error_free`.
 */
typedef struct DeepLinkError DeepLinkError;

/**
 * Free an error returned by any `trusttunnel_deeplink_*` function.
 * Passing NULL is safe and has no effect.
 */
void trusttunnel_deeplink_error_free(DeepLinkError *);

/**
 * Return the NULL-terminated error message.
 * The pointer is valid until `trusttunnel_deeplink_error_free` is called.
 */
const char *trusttunnel_deeplink_error_message(const DeepLinkError *);

/**
 * Decode a `tt://` URI into a NULL-terminated `[endpoint]` TOML section string.
 *
 * On success returns a heap-allocated string the caller MUST free with
 * `trusttunnel_deeplink_string_free`.
 * On failure returns NULL and, if `error` is non-NULL, writes a newly
 * allocated `DeepLinkError` into `*error`; free it with
 * `trusttunnel_deeplink_error_free`.
 */
char *trusttunnel_deeplink_decode(const char *, DeepLinkError **);

/**
 * Free a string returned by `trusttunnel_deeplink_decode`.
 * Passing NULL is safe and has no effect.
 */
void trusttunnel_deeplink_string_free(char *);

#ifdef __cplusplus
} // extern "C"
#endif
