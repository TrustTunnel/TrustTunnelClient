#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Provides subscription refresh for TrustTunnel endpoint configurations.
 */
@interface TrustTunnelSubscription : NSObject

/**
 * Fetch the subscription document from the URL stored in the `[endpoint.subscription]`
 * table of the given endpoint configuration and merge it back into it.
 *
 * @param endpointToml A TOML string beginning with `[endpoint]` that holds an
 *                     `[endpoint.subscription]` section with the subscription URL.
 * @return The updated TOML string beginning with `[endpoint]`, with the fetched
 *         subscription parameters applied, or nil on any failure. Blocks for the
 *         duration of the request.
 */
+ (nullable NSString *)fetchAndApplySubscription:(NSString *)endpointToml;

@end

NS_ASSUME_NONNULL_END
