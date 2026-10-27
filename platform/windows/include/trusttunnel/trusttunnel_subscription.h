#pragma once

#include "vpn/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fetch the subscription document from the URL stored in the `[endpoint.subscription]` table of the
 * given `[endpoint]` TOML fragment and merge it back into the fragment, the same way the
 * `trusttunnel_client --refresh` flow updates a full config.
 * @param endpoint_toml The `[endpoint]` TOML section holding the subscription URL.
 * @return On success, a heap-allocated updated `[endpoint]` TOML section the caller MUST free with
 *         `trusttunnel_free_subscription_string()`. On failure, NULL. Blocks for the duration of
 *         the request.
 */
WIN_EXPORT char *trusttunnel_fetch_and_apply_subscription(const char *endpoint_toml);

/**
 * Free a string returned by `trusttunnel_fetch_and_apply_subscription()`. Passing NULL is safe and
 * has no effect.
 */
WIN_EXPORT void trusttunnel_free_subscription_string(char *str);

#ifdef __cplusplus
} // extern "C"
#endif
