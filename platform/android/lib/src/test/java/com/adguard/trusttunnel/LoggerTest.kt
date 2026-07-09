package com.adguard.trusttunnel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LoggerTest {
    @Test
    fun setCallback_routesNamedLogs() {
        var capturedLevel: Logger.LogLevel? = null
        var capturedMessage: String? = null
        val logger = Logger("TestLogger")

        try {
            Logger.setLogLevelProvider { Logger.LogLevel.DEBUG }
            Logger.setCallback(Logger.Callback { logLevel, message ->
                capturedLevel = logLevel
                capturedMessage = message
            })

            logger.debug("test message")
        } finally {
            Logger.setCallback(null)
            Logger.setLogLevelProvider { Logger.LogLevel.INFO }
        }

        assertEquals(Logger.LogLevel.DEBUG, capturedLevel)
        assertEquals("TestLogger test message", capturedMessage)
    }

    @Test
    fun log_respectsCurrentLogLevel() {
        var dispatched = false
        val logger = Logger("TestLogger")

        try {
            Logger.setLogLevelProvider { Logger.LogLevel.INFO }
            Logger.setCallback(Logger.Callback { _, _ ->
                dispatched = true
            })

            logger.debug("suppressed message")
            assertFalse(dispatched)

            logger.info("visible message")
            assertTrue(dispatched)
        } finally {
            Logger.setCallback(null)
            Logger.setLogLevelProvider { Logger.LogLevel.INFO }
        }
    }

    @Test
    fun log_readsLogLevelLiveFromProvider() {
        var dispatched = false
        var level = Logger.LogLevel.INFO
        val logger = Logger("TestLogger")

        try {
            Logger.setLogLevelProvider { level }
            Logger.setCallback(Logger.Callback { _, _ ->
                dispatched = true
            })

            logger.debug("suppressed at INFO")
            assertFalse(dispatched)

            // Simulate a native-side level change (e.g. applied from config via
            // ag::Logger::set_log_level) without any Kotlin setter call.
            level = Logger.LogLevel.DEBUG
            logger.debug("visible at DEBUG")
            assertTrue(dispatched)
        } finally {
            Logger.setCallback(null)
            Logger.setLogLevelProvider { Logger.LogLevel.INFO }
        }
    }

    @Test
    fun nativeLogs_keepTheirOriginalMessage() {
        var capturedLevel: Logger.LogLevel? = null
        var capturedMessage: String? = null

        try {
            Logger.setCallback(Logger.Callback { logLevel, message ->
                capturedLevel = logLevel
                capturedMessage = message
            })

            Logger.dispatchNative(Logger.LogLevel.INFO, "VPN_CLIENT Connected")
        } finally {
            Logger.setCallback(null)
        }

        assertEquals(Logger.LogLevel.INFO, capturedLevel)
        assertEquals("VPN_CLIENT Connected", capturedMessage)
    }
}
