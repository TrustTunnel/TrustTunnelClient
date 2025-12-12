#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^StateChangeHandler)(int state);
typedef void (^ConnectionInfoHandler)(NSString *state);

@interface VpnClient : NSObject

- (instancetype)initWithConfig:(NSString *)config
         connectionInfoHandler:(ConnectionInfoHandler)connectionInfoHandler
            stateChangeHandler:(StateChangeHandler)stateChangeHandler;
- (instancetype)init NS_UNAVAILABLE;
- (bool)start:(NEPacketTunnelFlow *)tunnelFlow;
- (bool)stop;
- (void)notify_sleep;
- (void)notify_wake;
+ (NSArray<NSString *> *)excludeCidr:(NSArray<NSString *> *)includeRoutes
                       excludeRoutes:(NSArray<NSString *> *)excludeRoutes;

@end

NS_ASSUME_NONNULL_END
