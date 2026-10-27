#include "trusttunnel/trusttunnel_deeplink.h"

#include "common/logger.h"
#include "trusttunnel_deeplink.h"

static ag::Logger g_logger{"DEEPLINK"};

/// Return the message of `error`, or a fallback when the error object was not created.
static const char *error_text(const DeepLinkError *error) {
    return error != nullptr ? trusttunnel_deeplink_error_message(error) : "unknown error";
}

char *trusttunnel_decode_deeplink(const char *uri) {
    DeepLinkError *error = nullptr;
    char *result = trusttunnel_deeplink_decode(uri, &error);
    if (result == nullptr) {
        errlog(g_logger, "Failed to decode a deep-link: {}", error_text(error));
        trusttunnel_deeplink_error_free(error);
    }
    return result;
}

char *trusttunnel_encode_deeplink(const char *endpoint_toml) {
    DeepLinkError *error = nullptr;
    char *result = trusttunnel_deeplink_encode(endpoint_toml, &error);
    if (result == nullptr) {
        errlog(g_logger, "Failed to encode a deep-link: {}", error_text(error));
        trusttunnel_deeplink_error_free(error);
    }
    return result;
}

void trusttunnel_free_deeplink_string(char *str) {
    trusttunnel_deeplink_string_free(str);
}
