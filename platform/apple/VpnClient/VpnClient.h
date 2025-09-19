//
//  VpnClient.h
//  Network Extension MacOS
//
//  Created by Andrey Yakushin on 31.07.2025.
//

//#import <vpn/standalone/client.h>

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

@interface VpnClient : NSObject

- (instancetype)initWithConfig:(NSString *)config;
- (instancetype)init NS_UNAVAILABLE;
- (bool)start:(NEPacketTunnelFlow *)tunnelFlow;
- (bool)stop;
- (void)notify_sleep;
- (void)notify_wake;

@end

NS_ASSUME_NONNULL_END
