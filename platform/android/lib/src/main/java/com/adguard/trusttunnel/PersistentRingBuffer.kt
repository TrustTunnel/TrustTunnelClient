package com.adguard.trusttunnel

import com.adguard.trusttunnel.log.LoggerManager
import java.io.File

class PersistentRingBuffer(
    file: File
) {
    companion object {
        init {
            System.loadLibrary("trusttunnel_android")
        }

        private val LOG = LoggerManager.getLogger("PersistentRingBuffer")

        @JvmStatic
        private external fun nativeAppend(path: String, record: String): Boolean
        @JvmStatic
        private external fun nativeReadAll(path: String): Array<String>?
        @JvmStatic
        private external fun nativeClear(path: String)
    }

    private val path = file.absolutePath

    fun append(data: String): Boolean {
        return nativeAppend(path, data)
    }

    fun readAll(): List<String>? {
        return nativeReadAll(path)?.toList()
    }

    fun clear() {
        nativeClear(path)
    }
}