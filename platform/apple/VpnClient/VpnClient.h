#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^StateChangeHandler)(int state);

@interface VpnClient : NSObject

- (instancetype)initWithConfig:(NSString *)config
            stateChangeHandler:(StateChangeHandler)stateChangeHandler;
- (instancetype)init NS_UNAVAILABLE;
- (bool)start:(NEPacketTunnelFlow *)tunnelFlow;
- (bool)stop;
- (void)notify_sleep;
- (void)notify_wake;

@end

NS_ASSUME_NONNULL_END
