package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import java.util.concurrent.atomic.AtomicReference

class Logger {
    enum class LogLevel(val code: Int) {
        ERROR(0),
        WARN(1),
        INFO(2),
        DEBUG(3),
        TRACE(4);

        companion object {
            private val byCode = entries.associateBy(LogLevel::code)

            fun fromCode(code: Int): LogLevel {
                return requireNotNull(byCode[code]) { "Invalid log level code $code" }
            }
        }
    }

    fun interface Callback {
        fun log(logLevel: LogLevel, message: String)
    }

    companion object {
        private val nativeLogger = LoggerManager.getLogger("TrustTunnel_Native")
        private val callback = AtomicReference<Callback>(defaultCallback())

        @JvmStatic
        fun setCallback(callback: Callback?) {
            this.callback.set(callback ?: defaultCallback())
        }

        internal fun dispatch(logLevel: LogLevel, message: String) {
            callback.get().log(logLevel, message)
        }

        private fun defaultCallback(): Callback {
            return Callback { logLevel, message ->
                when (logLevel) {
                    LogLevel.ERROR -> nativeLogger.error(message)
                    LogLevel.WARN -> nativeLogger.warn(message)
                    LogLevel.INFO -> nativeLogger.info(message)
                    LogLevel.DEBUG -> nativeLogger.debug(message)
                    LogLevel.TRACE -> nativeLogger.trace(message)
                }
            }
        }
    }
}
