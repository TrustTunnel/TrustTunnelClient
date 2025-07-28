package com.adguard.trusttunnel.log

import android.content.Context
import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import com.adguard.trusttunnel.utils.concurrent.thread.ThreadManager
import org.slf4j.LoggerFactory
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicLong

object LoggerManager {
    fun getLogger(name: String): org.slf4j.Logger {
        return LoggerFactory.getLogger(name)
    }
}