#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LogLevel) {
    LogLevelError = 0,
    LogLevelWarn = 1,
    LogLevelInfo = 2,
    LogLevelDebug = 3,
    LogLevelTrace = 4,
};

typedef void (^NativeLoggerCallback)(LogLevel log_level, NSString *message);

@interface NativeLogger : NSObject

+ (void)setCallback:(nullable NativeLoggerCallback)callback;

@end

NS_ASSUME_NONNULL_END