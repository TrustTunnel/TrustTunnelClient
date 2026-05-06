package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import java.io.Closeable
import java.io.File

class PersistentRingBuffer(
    file: File
) : Closeable {
    companion object {
        init {
            System.loadLibrary("trusttunnel_android")
        }

        private val LOG = LoggerManager.getLogger("PrefixedLenRingProto")
    }

    private val sync = Any()
    private var nativePtr = nativeCreate(file.absolutePath)

    init {
        if (nativePtr == 0L) {
            LOG.warn("Failed to create native persistent ring buffer for ${file.absolutePath}")
        }
    }

    fun append(data: String): Boolean = synchronized(sync) {
        if (nativePtr == 0L) {
            LOG.warn("Can't append, native persistent ring buffer is not initialized")
            return false
        }

        return nativeAppend(nativePtr, data)
    }

    fun readAll(): List<String>? = synchronized(sync) {
        if (nativePtr == 0L) {
            LOG.warn("Can't read, native persistent ring buffer is not initialized")
            return null
        }

        return nativeReadAll(nativePtr)?.toList()
    }

    fun clear() = synchronized(sync) {
        if (nativePtr == 0L) {
            LOG.warn("Can't clear, native persistent ring buffer is not initialized")
            return
        }

        nativeClear(nativePtr)
    }

    override fun close() = synchronized(sync) {
        if (nativePtr != 0L) {
            nativeDestroy(nativePtr)
            nativePtr = 0L
        }
    }

    private external fun nativeCreate(path: String): Long
    private external fun nativeAppend(nativePtr: Long, record: String): Boolean
    private external fun nativeReadAll(nativePtr: Long): Array<String>?
    private external fun nativeClear(nativePtr: Long)
    private external fun nativeDestroy(nativePtr: Long)
}