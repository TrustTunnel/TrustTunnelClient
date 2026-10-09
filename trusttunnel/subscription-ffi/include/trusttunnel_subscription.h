#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque error object returned in the error out-parameter. */
typedef struct SubscriptionFfiError SubscriptionFfiError;

/**
 * Fetch the subscription document at `url` and hand back the raw validated
 * JSON body.
 * @param url NUL-terminated https URL, optionally with embedded credentials.
 * @param certificate_host when non-NULL, the pin applies only if the URL's
 *        host matches it; when NULL, the pin always applies.
 * @param certificate_pem optional NUL-terminated PEM pinning the server
 *        certificate; may be NULL.
 * @param skip_verification non-zero disables server certificate verification.
 * @param out_json receives a heap-allocated string on success; free with
 *        trusttunnel_subscription_string_free.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free. The message never
 *        contains the subscription URL or credentials.
 * @return 0 on success, 1 on any failure. Blocks for the request duration.
 */
int trusttunnel_subscription_fetch(const char *url, const char *certificate_host, const char *certificate_pem,
        int skip_verification, char **out_json, SubscriptionFfiError **error);

/**
 * Fetch the subscription document for the endpoint described by the endpoint
 * TOML fragment (a document with an [endpoint] table) and hand back the raw
 * validated JSON body. The subscription URL, the certificate pin (gated by
 * the endpoint hostname) and the verification policy are read from the
 * endpoint.
 * @param endpoint_toml NUL-terminated TOML endpoint fragment.
 * @param out_json receives a heap-allocated string on success; free with
 *        trusttunnel_subscription_string_free.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free. The message never
 *        contains the subscription URL or credentials.
 * @return 0 on success, 1 on any failure. Blocks for the request duration.
 */
int trusttunnel_subscription_fetch_for_endpoint(
        const char *endpoint_toml, char **out_json, SubscriptionFfiError **error);

/**
 * Merge the subscription document (as returned by
 * trusttunnel_subscription_fetch) into the endpoint TOML fragment and hand
 * back the updated fragment. Comments, key order and unknown keys are
 * preserved.
 * @param endpoint_toml NUL-terminated TOML endpoint fragment.
 * @param subscription_json NUL-terminated subscription document.
 * @param out_endpoint receives a heap-allocated string on success; free with
 *        trusttunnel_subscription_string_free.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free.
 * @return 0 on success, 1 on any failure.
 */
int trusttunnel_subscription_apply_endpoint(
        const char *endpoint_toml, const char *subscription_json, char **out_endpoint, SubscriptionFfiError **error);

/**
 * Extract the [endpoint] subtree of the config text as a standalone TOML
 * document. The subtree keeps its comments and unknown keys.
 * @param config_text NUL-terminated TOML config.
 * @param out_endpoint receives a heap-allocated string on success; free with
 *        trusttunnel_subscription_string_free.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free.
 * @return 0 on success, 1 on any failure.
 */
int trusttunnel_subscription_extract_endpoint(
        const char *config_text, char **out_endpoint, SubscriptionFfiError **error);

/**
 * Replace the config's [endpoint] subtree with the one from the endpoint
 * fragment and hand back the updated config. Everything else in the config —
 * comments, key order, unknown keys — is preserved.
 * @param config_text NUL-terminated TOML config.
 * @param endpoint_toml NUL-terminated TOML endpoint fragment.
 * @param out_config receives a heap-allocated string on success; free with
 *        trusttunnel_subscription_string_free.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free.
 * @return 0 on success, 1 on any failure.
 */
int trusttunnel_subscription_replace_endpoint(
        const char *config_text, const char *endpoint_toml, char **out_config, SubscriptionFfiError **error);

/**
 * Replace the file at `path` with `content` atomically, preserving the
 * original permission mode. The file must already exist — it is never
 * created.
 * @param path NUL-terminated file path.
 * @param content NUL-terminated new file content.
 * @param error if non-null, receives a heap-allocated diagnostic on failure;
 *        free it with trusttunnel_subscription_error_free.
 * @return 0 on success, 1 on any failure.
 */
int trusttunnel_subscription_replace_file_atomic(const char *path, const char *content, SubscriptionFfiError **error);

/**
 * Free a string returned in out_json, out_endpoint or out_config. Safe to
 * call with NULL.
 */
void trusttunnel_subscription_string_free(char *string);

/**
 * Borrow the diagnostic of an error object. Valid until the error is freed.
 */
const char *trusttunnel_subscription_error_message(const SubscriptionFfiError *error);

/**
 * Free an error object. Safe to call with NULL.
 */
void trusttunnel_subscription_error_free(SubscriptionFfiError *error);

#ifdef __cplusplus
} // extern "C"
#endif
