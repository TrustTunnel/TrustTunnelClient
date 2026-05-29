package com.adguard.trusttunnel

import org.junit.Assert.assertEquals
import org.junit.Test

class LoggerTest {
    @Test
    fun setCallback_routesNativeLogs() {
        var capturedLevel: Logger.LogLevel? = null
        var capturedMessage: String? = null

        try {
            Logger.setCallback(Logger.Callback { logLevel, message ->
                capturedLevel = logLevel
                capturedMessage = message
            })

            Logger.dispatch(Logger.LogLevel.DEBUG, "test message")
        } finally {
            Logger.setCallback(null)
        }

        assertEquals(Logger.LogLevel.DEBUG, capturedLevel)
        assertEquals("test message", capturedMessage)
    }
}