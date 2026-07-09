package com.adguard.trusttunnel.log

import com.adguard.trusttunnel.Logger

/**
 * This class bridges native logging into the public Logger callback.
 */
class NativeLogger {
    companion object {
        private val logger = Logger.getLogger("TrustTunnel_Native")

        init {
            setupSlf4j()
            // Read the level live from native so config-driven changes (ag::Logger::set_log_level)
            // are respected by platform-side logs without an explicit Kotlin-side update.
            Logger.setLogLevelProvider { Logger.LogLevel.fromCode(getDefaultLogLevel0()) }
            logger.info("Logging initialized")
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
            Logger.dispatchNative(Logger.LogLevel.fromCode(level), message.orEmpty())
        }
    }
}
