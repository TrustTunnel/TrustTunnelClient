package com.adguard.trusttunnel

import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicReference

class Logger(private val name: String) {
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

    private val backend = LoggerFactory.getLogger(name)

    fun error(message: String, throwable: Throwable? = null) {
        log(LogLevel.ERROR, message, throwable)
    }

    fun warn(message: String, throwable: Throwable? = null) {
        log(LogLevel.WARN, message, throwable)
    }

    fun info(message: String, throwable: Throwable? = null) {
        log(LogLevel.INFO, message, throwable)
    }

    fun debug(message: String, throwable: Throwable? = null) {
        log(LogLevel.DEBUG, message, throwable)
    }

    fun trace(message: String, throwable: Throwable? = null) {
        log(LogLevel.TRACE, message, throwable)
    }

    private fun log(logLevel: LogLevel, message: String, throwable: Throwable?) {
        if (dispatch(logLevel, formatMessage(name, message, throwable))) {
            return
        }

        logToBackend(backend, logLevel, message, throwable)
    }

    companion object {
        private val nativeBackend = LoggerFactory.getLogger("TrustTunnel_Native")
        private val callback = AtomicReference<Callback?>(null)

        @JvmStatic
        fun getLogger(name: String): Logger {
            return Logger(name)
        }

        @JvmStatic
        fun setCallback(callback: Callback?) {
            this.callback.set(callback)
        }

        internal fun dispatch(logLevel: LogLevel, message: String): Boolean {
            val callback = callback.get() ?: return false
            callback.log(logLevel, message)
            return true
        }

        internal fun dispatchNative(logLevel: LogLevel, message: String) {
            if (dispatch(logLevel, message)) {
                return
            }

            logToBackend(nativeBackend, logLevel, message, null)
        }

        private fun formatMessage(name: String, message: String, throwable: Throwable? = null): String {
            val formattedMessage = "$name $message"
            return if (throwable != null) {
                "$formattedMessage\n${throwable.stackTraceToString()}"
            } else {
                formattedMessage
            }
        }

        private fun logToBackend(
            backend: org.slf4j.Logger,
            logLevel: LogLevel,
            message: String,
            throwable: Throwable?,
        ) {
            when (logLevel) {
                LogLevel.ERROR -> if (throwable != null) backend.error(message, throwable) else backend.error(message)
                LogLevel.WARN -> if (throwable != null) backend.warn(message, throwable) else backend.warn(message)
                LogLevel.INFO -> if (throwable != null) backend.info(message, throwable) else backend.info(message)
                LogLevel.DEBUG -> if (throwable != null) backend.debug(message, throwable) else backend.debug(message)
                LogLevel.TRACE -> if (throwable != null) backend.trace(message, throwable) else backend.trace(message)
            }
        }
    }
}
