package com.adguard.trusttunnel

import org.junit.Assert.assertEquals
import org.junit.Test

class LoggerTest {
    @Test
    fun setCallback_routesNamedLogs() {
        var capturedLevel: Logger.LogLevel? = null
        var capturedMessage: String? = null
        val logger = Logger("TestLogger")

        try {
            Logger.setCallback(Logger.Callback { logLevel, message ->
                capturedLevel = logLevel
                capturedMessage = message
            })

            logger.debug("test message")
        } finally {
            Logger.setCallback(null)
        }

        assertEquals(Logger.LogLevel.DEBUG, capturedLevel)
        assertEquals("TestLogger test message", capturedMessage)
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
