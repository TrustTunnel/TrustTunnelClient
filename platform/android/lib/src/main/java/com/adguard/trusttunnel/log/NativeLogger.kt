package com.adguard.trusttunnel.log

import com.adguard.trusttunnel.Logger

/**
 * This class bridges native logging into the public Logger callback.
 */
class NativeLogger {
    companion object {
        init {
            setupSlf4j()
            Logger.dispatch(Logger.LogLevel.INFO, "Logging initialized")
        }

        var defaultLogLevel: NativeLoggerLevel
            get() = NativeLoggerLevel.getByCode(getDefaultLogLevel0())
            set(level) = setDefaultLogLevel(level.code)


        @JvmStatic
        private external fun setDefaultLogLevel(level: Int)
        @JvmStatic
        private external fun getDefaultLogLevel0(): Int
        @JvmStatic
        private external fun setupSlf4j()

        @JvmStatic
        fun log(level: Int, message: String?) {
            Logger.dispatch(Logger.LogLevel.fromCode(level), message.orEmpty())
        }
    }
}
