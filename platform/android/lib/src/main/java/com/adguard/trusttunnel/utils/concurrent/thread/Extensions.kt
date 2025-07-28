package com.adguard.trusttunnel.utils.concurrent.thread

import java.util.concurrent.ScheduledExecutorService

fun ScheduledExecutorService.execute(sync: Any, command: Runnable) = execute { synchronized(sync) { command.run() } }