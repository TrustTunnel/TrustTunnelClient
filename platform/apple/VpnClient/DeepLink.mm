#import "DeepLink.h"

#include "trusttunnel_deeplink.h"

@implementation TrustTunnelDeepLink

+ (nullable NSString *)decodeDeeplink:(NSString *)uri
                                error:(NSError *_Nullable *_Nullable)error {
    if (uri == nil) {
        if (error) {
            *error = [NSError errorWithDomain:@"com.adguard.TrustTunnel.DeepLink"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"URI must not be nil"}];
        }
        return nil;
    }

    DeepLinkError *cError = nullptr;
    char *result = trusttunnel_deeplink_decode([uri UTF8String], &cError);
    if (result == NULL) {
        if (error) {
            const char *msg = cError ? trusttunnel_deeplink_error_message(cError) : nullptr;
            NSString *description = msg
                ? [NSString stringWithUTF8String:msg]
                : @"Unknown deep-link decode error";
            *error = [NSError errorWithDomain:@"com.adguard.TrustTunnel.DeepLink"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: description}];
        }
        trusttunnel_deeplink_error_free(cError);
        return nil;
    }

    NSString *toml = [NSString stringWithUTF8String:result];
    trusttunnel_deeplink_string_free(result);
    return toml;
}

+ (nullable NSString *)encodeDeeplink:(NSString *)endpointToml
                                error:(NSError *_Nullable *_Nullable)error {
    if (endpointToml == nil) {
        if (error) {
            *error = [NSError errorWithDomain:@"com.adguard.TrustTunnel.DeepLink"
                                         code:1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Endpoint TOML must not be nil"}];
        }
        return nil;
    }

    DeepLinkError *cError = nullptr;
    char *result = trusttunnel_deeplink_encode([endpointToml UTF8String], &cError);
    if (result == NULL) {
        if (error) {
            const char *msg = cError ? trusttunnel_deeplink_error_message(cError) : nullptr;
            NSString *description = msg
                ? [NSString stringWithUTF8String:msg]
                : @"Unknown deep-link encode error";
            *error = [NSError errorWithDomain:@"com.adguard.TrustTunnel.DeepLink"
                                         code:2
                                     userInfo:@{NSLocalizedDescriptionKey: description}];
        }
        trusttunnel_deeplink_error_free(cError);
        return nil;
    }

    NSString *uri = [NSString stringWithUTF8String:result];
    trusttunnel_deeplink_string_free(result);
    return uri;
}

@end
