package com.adguard.trusttunnel.log

import com.adguard.trusttunnel.Logger
import com.adguard.trusttunnel.utils.concurrent.thread.ThreadManager
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.Charsets

/**
 * A rotating file logger that installs itself as the global [Logger] callback.
 *
 * Once [install] is called, all log messages from both Kotlin and the native C++ layer
 * converge into `<directory>/<baseName>.log`. When the file exceeds [maxFileSize] bytes,
 * it is rotated to `<baseName>.1.log` (overwriting any prior archive) and a fresh file
 * is started.
 *
 * Total disk budget ≈ `maxFileSize * (archiveCount + 1)`.
 *
 * Writes are lock-free appends on a single-thread executor for performance.
 * Rotation and [snapshotTo] are synchronized against each other via [rotationLock].
 * A trailing line may be truncated in a snapshot if a write is in progress —
 * this is the same documented trade-off as the Apple implementation.
 */
class FileLogger(
    private val directory: File,
    private val baseName: String,
    private val maxFileSize: Int = 2_500_000,
    private val archiveCount: Int = 1
) {
    companion object {
        /** Base name used for the VPN process log files. */
        const val VPN_BASE_NAME = "vpn"
    }

    private val rotationLock = Any()
    private val writeExecutor = ThreadManager.create("file-logger-$baseName", 1)

    private var file: RandomAccessFile? = null
    private var currentSize: Long = 0

    /**
     * Register this logger as the global log sink.
     *
     * Call once, before any log-producing work begins (e.g., in
     * [com.adguard.trusttunnel.VpnService.initialize]).
     */
    fun install() {
        writeExecutor.execute { openOrCreateFile() }
        Logger.setCallback { level, message ->
            writeExecutor.execute { appendLine(level, message) }
        }
    }

    /**
     * Snapshot current log files to [destDir] (synchronized against rotation).
     *
     * Returns absolute paths of successfully copied files.
     * Non-existent files are silently skipped.
     */
    fun snapshotTo(destDir: File): List<String> = synchronized(rotationLock) {
        destDir.mkdirs()
        val result = mutableListOf<String>()
        val candidates = (0..archiveCount).map { idx ->
            if (idx == 0) File(directory, "$baseName.log")
            else File(directory, "$baseName.$idx.log")
        }
        for (source in candidates) {
            if (!source.exists()) continue
            val dest = File(destDir, source.name)
            try {
                source.copyTo(dest, overwrite = true)
                result.add(dest.absolutePath)
            } catch (_: IOException) {
                // Skip — file may have been rotated away
            }
        }
        result
    }

    // ---- private ----

    /** Lock-free append (runs on single-thread executor). */
    private fun appendLine(level: Logger.LogLevel, message: String) {
        val raf = file ?: return
        val escaped = message.replace("\u001E", "\\x1E")
        val line = "${timestamp()} [${levelTag(level)}] $escaped\n\u001E"
        try {
            val bytes = line.toByteArray(Charsets.UTF_8)
            raf.write(bytes)
            currentSize += bytes.size.toLong()
            if (currentSize >= maxFileSize) {
                rotate()
            }
        } catch (_: IOException) {
            // Nothing actionable
        }
    }

    /** Rotation — synchronized against snapshot. */
    private fun rotate() = synchronized(rotationLock) {
        closeFile()
        // Shift archives: (n) → (n+1), drop oldest
        for (idx in (archiveCount - 1 downTo 1)) {
            val src = File(directory, "$baseName.$idx.log")
            val dst = File(directory, "$baseName.${idx + 1}.log")
            dst.delete()
            src.renameTo(dst)
        }
        // Rotate current → .1
        val current = File(directory, "$baseName.log")
        val archived = File(directory, "$baseName.1.log")
        archived.delete()
        current.renameTo(archived)
        openOrCreateFile()
    }

    private fun openOrCreateFile() {
        directory.mkdirs()
        val logFile = File(directory, "$baseName.log")
        try {
            val raf = RandomAccessFile(logFile, "rw")
            raf.seek(raf.length())
            file = raf
            currentSize = raf.length()
        } catch (_: IOException) {
            file = null
            currentSize = 0
        }
    }

    private fun closeFile() {
        try {
            file?.close()
        } catch (_: IOException) {
        }
        file = null
        currentSize = 0
    }

    // ---- format helpers ----

    private val dateFormatter: DateTimeFormatter = DateTimeFormatter.ISO_INSTANT

    private fun timestamp(): String = dateFormatter.format(Instant.now())

    private fun levelTag(level: Logger.LogLevel): String = when (level) {
        Logger.LogLevel.ERROR -> "ERROR"
        Logger.LogLevel.WARN -> "WARN"
        Logger.LogLevel.INFO -> "INFO"
        Logger.LogLevel.DEBUG -> "DEBUG"
        Logger.LogLevel.TRACE -> "TRACE"
    }
}
