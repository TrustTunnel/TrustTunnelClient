#import "Subscription.h"

#include "common/logger.h"
#include "trusttunnel_subscription.h"

static ag::Logger g_logger{"SUBSCRIPTION"};

/// Return the message of `error`, or a fallback when the error object was not created.
static const char *error_text(const SubscriptionFfiError *error) {
    return error != nullptr ? trusttunnel_subscription_error_message(error) : "unknown error";
}

@implementation TrustTunnelSubscription

+ (nullable NSString *)fetchAndApplySubscription:(NSString *)endpointToml {
    if (endpointToml == nil) {
        errlog(g_logger, "Failed to fetch a subscription: endpoint TOML is nil");
        return nil;
    }

    SubscriptionFfiError *cError = nullptr;
    char *jsonResult = NULL;
    if (trusttunnel_subscription_fetch_for_endpoint([endpointToml UTF8String], &jsonResult, &cError) != 0) {
        errlog(g_logger, "Failed to fetch a subscription: {}", error_text(cError));
        trusttunnel_subscription_error_free(cError);
        return nil;
    }

    char *result = NULL;
    if (trusttunnel_subscription_apply_endpoint([endpointToml UTF8String], jsonResult, &result, &cError) != 0) {
        errlog(g_logger, "Failed to apply a subscription: {}", error_text(cError));
        trusttunnel_subscription_error_free(cError);
        trusttunnel_subscription_string_free(jsonResult);
        return nil;
    }
    trusttunnel_subscription_string_free(jsonResult);

    NSString *toml = [NSString stringWithUTF8String:result];
    trusttunnel_subscription_string_free(result);
    return toml;
}

@end
