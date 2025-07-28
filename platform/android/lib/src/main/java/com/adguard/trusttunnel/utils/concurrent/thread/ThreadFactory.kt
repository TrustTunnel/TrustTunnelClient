package com.adguard.trusttunnel.utils.concurrent.thread

import java.util.concurrent.Executors

class ThreadFactory(private val namePrefix: String, private val daemon: Boolean = false) : java.util.concurrent.ThreadFactory {

    private val defaultFactory = Executors.defaultThreadFactory()
    private val handler = ThreadPoolExceptionHandler()


    override fun newThread(r: Runnable?): Thread {
        defaultFactory.newThread(r).let {
            it.isDaemon = daemon
            it.uncaughtExceptionHandler = handler
            it.name = namePrefix + '-' + it.name
            return it
        }
    }
}
