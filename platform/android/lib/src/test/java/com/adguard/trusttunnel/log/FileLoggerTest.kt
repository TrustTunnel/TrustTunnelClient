package com.adguard.trusttunnel.log

import com.adguard.trusttunnel.Logger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class FileLoggerTest {
    private lateinit var tempDir: File
    private lateinit var logDir: File

    @Before
    fun setUp() {
        tempDir = File(System.getProperty("java.io.tmpdir"), "filelogger-test-${System.nanoTime()}")
        logDir = File(tempDir, "logs")
        logDir.mkdirs()
    }

    @After
    fun tearDown() {
        tempDir.deleteRecursively()
        Logger.setCallback(null)
    }

    // ---- basic writing ----

    @Test
    fun install_createsLogFileOnFirstWrite() {
        val logger = FileLogger(logDir, "test")
        logger.install()
        // snapshotTo blocks until all prior executor tasks complete, so it
        // serves as a drain point as well as a verification step.
        logger.snapshotTo(File(tempDir, "drain"))

        Logger.dispatchNative(Logger.LogLevel.INFO, "hello")
        logger.snapshotTo(File(tempDir, "drain2"))

        val logFile = File(logDir, "test.log")
        assertTrue("Log file should exist", logFile.exists())
        assertTrue("Log file should contain text", logFile.readText().contains("hello"))
    }

    @Test
    fun appendLine_escapesRecordSeparator() {
        val logger = FileLogger(logDir, "test")
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        Logger.dispatchNative(Logger.LogLevel.INFO, "before\u001Eafter")
        logger.snapshotTo(File(tempDir, "drain2"))

        val content = File(logDir, "test.log").readText()
        assertTrue("Should escape RS character", content.contains("\\x1E"))
    }

    @Test
    fun appendLine_includesLevelTag() {
        val logger = FileLogger(logDir, "test")
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        Logger.dispatchNative(Logger.LogLevel.WARN, "warning message")
        logger.snapshotTo(File(tempDir, "drain2"))

        val content = File(logDir, "test.log").readText()
        assertTrue("Should include WARN tag", content.contains("[WARN]"))
    }

    // ---- rotation ----

    @Test
    fun rotate_movesCurrentToArchive() {
        // Each formatted line is ~60 bytes (timestamp + level + message + delimiters).
        // maxFileSize = 200 allows ~3 lines per file, so 5 lines trigger exactly
        // one rotation. Lines 0-2 go to the archive, lines 3-4 stay in current.
        val logger = FileLogger(logDir, "rotate", maxFileSize = 200)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        repeat(5) {
            Logger.dispatchNative(Logger.LogLevel.INFO, "line $it")
        }
        logger.snapshotTo(File(tempDir, "drain2"))

        val current = File(logDir, "rotate.log")
        val archive = File(logDir, "rotate.1.log")
        assertTrue("Current log should exist", current.exists())
        assertTrue("Archive log should exist after rotation", archive.exists())
        assertTrue("Archive should contain earlier lines", archive.readText().contains("line 0"))
    }

    @Test
    fun rotate_shiftsArchivesWhenArchiveCountGreaterThanOne() {
        // maxFileSize = 200 allows ~3 lines per file. With archiveCount = 2,
        // writing 15 lines produces enough rotations to populate both .1 and .2.
        val logger = FileLogger(logDir, "shift", maxFileSize = 200, archiveCount = 2)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        repeat(15) {
            Logger.dispatchNative(Logger.LogLevel.INFO, "line $it")
        }
        logger.snapshotTo(File(tempDir, "drain2"))

        val archive1 = File(logDir, "shift.1.log")
        val archive2 = File(logDir, "shift.2.log")
        assertTrue("Archive .1 should exist", archive1.exists())
        assertTrue("Archive .2 should exist after second rotation", archive2.exists())
    }

    // ---- snapshot ----

    @Test
    fun snapshotTo_copiesExistingFiles() {
        val logger = FileLogger(logDir, "snap")
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        Logger.dispatchNative(Logger.LogLevel.INFO, "snapshot test")
        val destDir = File(tempDir, "snapshot-dest")
        val paths = logger.snapshotTo(destDir)

        assertTrue("Should return at least one path", paths.isNotEmpty())
        val copiedFile = File(destDir, "snap.log")
        assertTrue("Copied log file should exist", copiedFile.exists())
        assertTrue("Copied content should match", copiedFile.readText().contains("snapshot test"))
    }

    @Test
    fun snapshotTo_skipsNonExistentFiles() {
        val logger = FileLogger(logDir, "nosnap", archiveCount = 2)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        Logger.dispatchNative(Logger.LogLevel.INFO, "minimal")
        val destDir = File(tempDir, "snapshot-dest2")
        val paths = logger.snapshotTo(destDir)

        // Only the current file should be copied, not the nonexistent archives
        assertEquals("Should copy only existing files", 1, paths.size)
        assertTrue(paths[0].endsWith("nosnap.log"))
    }

    @Test
    fun snapshotTo_capturesConsistentStateDuringActiveLogging() {
        val logger = FileLogger(logDir, "concurrent")
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        // Start a thread that continuously writes logs
        val writeLatch = CountDownLatch(1)
        val writerThread = Thread {
            var counter = 0
            while (!Thread.currentThread().isInterrupted) {
                Logger.dispatchNative(Logger.LogLevel.INFO, "concurrent line ${counter++}")
                if (counter >= 200) {
                    writeLatch.countDown()
                }
                try {
                    Thread.sleep(1)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        writerThread.start()

        // Wait for some writes to happen
        assertTrue("Writes should start", writeLatch.await(5, TimeUnit.SECONDS))

        // Take a snapshot while writes are still happening — the snapshot
        // runs on the same executor as writes, so it sees a consistent state.
        val destDir = File(tempDir, "snapshot-concurrent")
        val paths = logger.snapshotTo(destDir)

        // Stop the writer
        writerThread.interrupt()
        writerThread.join(1000)

        assertTrue("Snapshot should copy files", paths.isNotEmpty())
        val copiedFile = File(destDir, "concurrent.log")
        assertTrue("Copied file should exist", copiedFile.exists())

        // The copied file should have valid content — every line that was
        // fully written before the snapshot should be present.
        val content = copiedFile.readText()
        assertTrue("Copied file should contain log lines", content.contains("[INFO]"))
    }

    @Test
    fun snapshotTo_includesArchivesAfterRotation() {
        val logger = FileLogger(logDir, "snaparchive", maxFileSize = 200)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        // Write enough to trigger at least one rotation
        repeat(5) {
            Logger.dispatchNative(Logger.LogLevel.INFO, "line $it")
        }
        val destDir = File(tempDir, "snapshot-archive")
        val paths = logger.snapshotTo(destDir)

        // Should have both current and archive
        assertTrue("Should have at least 2 files", paths.size >= 2)
        val archiveNames = paths.map { File(it).name }
        assertTrue("Should include current log", archiveNames.contains("snaparchive.log"))
        assertTrue("Should include archive log", archiveNames.contains("snaparchive.1.log"))
    }

    // ---- clearLogs ----

    @Test
    fun clearLogs_removesCurrentAndArchiveFiles() {
        val logger = FileLogger(logDir, "clear", maxFileSize = 200)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        // Trigger a rotation so both current and archive files exist.
        repeat(5) {
            Logger.dispatchNative(Logger.LogLevel.INFO, "line $it")
        }
        logger.snapshotTo(File(tempDir, "drain2"))

        val current = File(logDir, "clear.log")
        val archive = File(logDir, "clear.1.log")
        assertTrue("Current file should exist before clear", current.exists())
        assertTrue("Current file is not empty", current.length().toInt() != 0)
        assertTrue("Archive file should exist before clear", archive.exists())
        assertTrue("Archive file is not empty", archive.length().toInt() != 0)

        logger.clearLogs()

        // `clearLogs` reopens the file so logging could proceed after
        assertTrue("Current file exists", current.exists())
        assertEquals("Current file is empty (clean), ${current.length()}", current.length(), 0)
        assertFalse("Archive file should be removed", archive.exists())
    }

    @Test
    fun clearLogs_resetsWriterForNewOutput() {
        val logger = FileLogger(logDir, "reset", maxFileSize = 200)
        logger.install()
        logger.snapshotTo(File(tempDir, "drain"))

        repeat(5) {
            Logger.dispatchNative(Logger.LogLevel.INFO, "before clear $it")
        }
        logger.snapshotTo(File(tempDir, "drain2"))

        val current = File(logDir, "reset.log")
        assertTrue("Current file should have content before clear", current.length() > 0)

        logger.clearLogs()

        // New writes must land in a freshly created (empty) file.
        Logger.dispatchNative(Logger.LogLevel.INFO, "after clear")
        logger.snapshotTo(File(tempDir, "drain3"))

        assertTrue("Current file should exist after clear", current.exists())
        val content = current.readText()
        assertFalse("Old content should be gone", content.contains("before clear"))
        assertTrue("New content should be present", content.contains("after clear"))
        assertFalse("Archive should remain removed", File(logDir, "reset.1.log").exists())
    }
}
