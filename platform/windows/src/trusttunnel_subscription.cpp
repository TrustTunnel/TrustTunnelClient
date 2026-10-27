#include "trusttunnel/trusttunnel_subscription.h"

#include <memory>

#include "common/logger.h"
#include "trusttunnel_subscription.h"

static ag::Logger g_logger{"SUBSCRIPTION"};

using FfiString = std::unique_ptr<char, decltype(&trusttunnel_subscription_string_free)>;

/// Return the message of `error`, or a fallback when the error object was not created.
static const char *error_text(const SubscriptionFfiError *error) {
    return error != nullptr ? trusttunnel_subscription_error_message(error) : "unknown error";
}

char *trusttunnel_fetch_and_apply_subscription(const char *endpoint_toml) {
    SubscriptionFfiError *error = nullptr;
    char *json_raw = nullptr;
    if (trusttunnel_subscription_fetch_for_endpoint(endpoint_toml, &json_raw, &error) != 0) {
        errlog(g_logger, "Failed to fetch a subscription: {}", error_text(error));
        trusttunnel_subscription_error_free(error);
        return nullptr;
    }
    FfiString json(json_raw, &trusttunnel_subscription_string_free);

    char *updated_endpoint_raw = nullptr;
    if (trusttunnel_subscription_apply_endpoint(endpoint_toml, json.get(), &updated_endpoint_raw, &error) != 0) {
        errlog(g_logger, "Failed to apply a subscription: {}", error_text(error));
        trusttunnel_subscription_error_free(error);
        return nullptr;
    }

    return updated_endpoint_raw;
}

void trusttunnel_free_subscription_string(char *str) {
    trusttunnel_subscription_string_free(str);
}
