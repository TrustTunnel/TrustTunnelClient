package com.adguard.trusttunnel.log

import org.slf4j.Logger
import org.slf4j.LoggerFactory

/**
 * This class is used to setup SLF4J output for native logger
 */
class NativeLogger {
    companion object {
        private val LOG: Logger = LoggerFactory.getLogger("TrustTunnel_Native")

        init {
            setupSlf4j()
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
            val logLevel = NativeLoggerLevel.getByCode(level)
            when (logLevel) {
                NativeLoggerLevel.ERROR -> LOG.error(message)
                NativeLoggerLevel.WARN -> LOG.warn(message)
                NativeLoggerLevel.INFO -> LOG.info(message)
                NativeLoggerLevel.DEBUG -> LOG.debug(message)
                NativeLoggerLevel.TRACE -> LOG.trace(message)
            }
        }
    }
}
