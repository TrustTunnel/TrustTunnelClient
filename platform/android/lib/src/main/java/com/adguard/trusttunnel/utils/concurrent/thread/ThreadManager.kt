package com.adguard.trusttunnel.utils.concurrent.thread

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService

object ThreadManager {

    private var cachedThreadService: ExecutorService? = null

    fun create(namePrefix: String, threadsCount: Int): ScheduledExecutorService {
        return when (threadsCount) {
            1       -> Executors.newSingleThreadScheduledExecutor(ThreadFactory(namePrefix))
            else    -> Executors.newScheduledThreadPool(threadsCount, ThreadFactory(namePrefix))
        }
    }

    @Synchronized
    fun getThreadService(): ExecutorService {
        if (cachedThreadService == null) {
            synchronized(this) {
                if (cachedThreadService == null) {
                    cachedThreadService = Executors.newCachedThreadPool(ThreadFactory("threadmanager-cached"))
                }
            }
        }
        return cachedThreadService!!
    }
}


