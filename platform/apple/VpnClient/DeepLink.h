#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * Provides deep-link decoding and encoding for TrustTunnel endpoint
 * configurations.
 */
@interface TrustTunnelDeepLink : NSObject

/**
 * Decode a `tt://` deep-link URI into a `[endpoint]` TOML section string.
 *
 * @param uri   The `tt://...` deep-link URI to decode.
 * @param error On failure, populated with a descriptive error.
 * @return A TOML string beginning with `[endpoint]` ready to be embedded in
 *         the full client configuration, or nil on error.
 */
+ (nullable NSString *)decodeDeeplink:(NSString *)uri error:(NSError *_Nullable *_Nullable)error;

/**
 * Encode an `[endpoint]` TOML section string into a `tt://` deep-link URI.
 *
 * @param endpointToml A TOML string beginning with `[endpoint]`, in the same
 *                     layout that `decodeDeeplink:error:` produces.
 * @param error        On failure, populated with a descriptive error.
 * @return The `tt://...` deep-link URI, or nil on error.
 */
+ (nullable NSString *)encodeDeeplink:(NSString *)endpointToml error:(NSError *_Nullable *_Nullable)error;

@end

NS_ASSUME_NONNULL_END
