package com.adguard.trusttunnel.utils.concurrent.thread

import com.adguard.trusttunnel.log.LoggerManager

class ThreadPoolExceptionHandler : Thread.UncaughtExceptionHandler {

    companion object {
        private val LOG = LoggerManager.getLogger("ThreadPoolExceptionHandler")
    }

    override fun uncaughtException(thread: Thread, throwable: Throwable) {
        val handler = Thread.getDefaultUncaughtExceptionHandler()
        if (handler != null) {
            handler.uncaughtException(thread, throwable)
        } else {
            LOG.error("Uncaught exception in thread ${thread.name}\n$throwable")
        }
    }
}