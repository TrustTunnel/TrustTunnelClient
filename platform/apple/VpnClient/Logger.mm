#import "Logger.h"

#include <mutex>

#include "common/logger.h"

#import <os/log.h>

namespace {

std::mutex g_callback_guard;
NativeLoggerCallback g_callback = nil;

LogLevel to_log_level(ag::LogLevel level) {
    switch (level) {
    case ag::LOG_LEVEL_ERROR:
        return LogLevelError;
    case ag::LOG_LEVEL_WARN:
        return LogLevelWarn;
    case ag::LOG_LEVEL_INFO:
        return LogLevelInfo;
    case ag::LOG_LEVEL_DEBUG:
        return LogLevelDebug;
    case ag::LOG_LEVEL_TRACE:
        return LogLevelTrace;
    }

    return LogLevelInfo;
}

NSString *to_ns_string(std::string_view message) {
    NSString *string = [[NSString alloc] initWithBytes:message.data()
                                                length:message.size()
                                              encoding:NSUTF8StringEncoding];
    return string ?: @"";
}

void log_to_default_sink(ag::LogLevel level, std::string_view message) {
    static const char *const levels[] = {
            [ag::LOG_LEVEL_ERROR] = "ERROR", [ag::LOG_LEVEL_WARN] = "WARN",   [ag::LOG_LEVEL_INFO] = "INFO",
            [ag::LOG_LEVEL_DEBUG] = "DEBUG", [ag::LOG_LEVEL_TRACE] = "TRACE",
    };
    static os_log_t log_handle = os_log_create("com.adguard.TrustTunnel.VpnClientFramework", "VpnClient");
    os_log(log_handle, "[%{public}s]\t%{public}.*s", levels[level], (int)message.size(), message.data());
}

void dispatch_log(ag::LogLevel level, std::string_view message) {
    NativeLoggerCallback callback = nil;
    {
        std::scoped_lock lock(g_callback_guard);
        callback = g_callback;
    }

    if (callback != nil) {
        callback(to_log_level(level), to_ns_string(message));
        return;
    }

    log_to_default_sink(level, message);
}

void install_native_callback() {
    ag::Logger::set_callback([](ag::LogLevel level, std::string_view message) { dispatch_log(level, message); });
}

__attribute__((constructor)) static void initialize_native_logger() { install_native_callback(); }

} // namespace

@implementation NativeLogger

+ (void)setCallback:(NativeLoggerCallback)callback {
    std::scoped_lock lock(g_callback_guard);
    g_callback = [callback copy];
}

@end