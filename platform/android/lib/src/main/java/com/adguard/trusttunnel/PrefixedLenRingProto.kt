package com.adguard.trusttunnel

import android.content.Context
import com.adguard.trusttunnel.log.LoggerManager
import java.io.File
import java.io.RandomAccessFile

class PrefixedLenRingProto (
    private val file: File
) {
    companion object {
        private const val MAGIC_BYTE = 0x2f
        private const val MAX_RECORDS = 500
        private const val MAX_CONTENT_SIZE = 1024
        private const val RECORD_SIZE =
            1 /*MAGIC_BYTE*/ + Int.SIZE_BYTES /*LENGTH*/ + MAX_CONTENT_SIZE
        private const val HEADER_SIZE = Int.SIZE_BYTES /*write index*/ + Int.SIZE_BYTES /*count*/
        private val LOG = LoggerManager.getLogger("PrefixedLenRingProto")
    }

    fun append(data: String): Boolean {
        try {
            if (!file.exists()) {
                val totalSize = HEADER_SIZE + RECORD_SIZE * MAX_RECORDS
                file.writeBytes(ByteArray(totalSize))
            }
            RandomAccessFile(file, "rw").use { raf ->
                raf.seek(0)
                val writeIndex = raf.readInt()
                val count = raf.readInt()
                val dataToWrite = data.toByteArray(Charsets.UTF_8)
                if (dataToWrite.size > MAX_CONTENT_SIZE) {
                    LOG.warn("Data is too long, max size is $MAX_CONTENT_SIZE, got ${dataToWrite.size}")
                    return false
                }
                raf.writeByte(MAGIC_BYTE)
                val recordOffset = (HEADER_SIZE + (writeIndex * RECORD_SIZE)).toLong()
                raf.seek(recordOffset)
                raf.writeByte(MAGIC_BYTE)
                raf.writeInt(dataToWrite.size)
                raf.write(dataToWrite)
                val newIndex = (writeIndex + 1) % MAX_RECORDS
                val newCount = minOf(count + 1, MAX_RECORDS)

                raf.seek(0)
                raf.writeInt(newIndex)
                raf.writeInt(newCount)
                return true
            }
        } catch (e: Exception) {
            LOG.warn("Failed to append data to file: $e")
            return false
        }
    }

    fun read_all(): List<String>? {
        try {
            val records = mutableListOf<String>()
            if (!file.exists()) {
                return records
            }
            RandomAccessFile(file, "r").use { raf ->
                raf.seek(0)
                val writeIndex = raf.readInt()
                val count = raf.readInt()
                if (count == 0) return@use
                val startIndex = if (count == MAX_RECORDS) writeIndex else 0
                for (i in 0 until count) {
                    val index = (startIndex + i) % MAX_RECORDS
                    val recordOffset = (HEADER_SIZE + (index * RECORD_SIZE)).toLong()
                    raf.seek(recordOffset)
                    val magicByte = raf.readByte().toInt()
                    if (magicByte != MAGIC_BYTE) {
                        LOG.warn("Data corruption detected at offset $recordOffset. Invalid Magic Byte: $magicByte")
                        return null
                    }
                    val length = raf.readInt()
                    if (length !in 1..MAX_CONTENT_SIZE) {
                        LOG.warn("Failed to read content, invalid length $length")
                        return null
                    }
                    val buf = ByteArray(length)
                    raf.readFully(buf)
                    records.add(String(buf, Charsets.UTF_8))
                }
            }
            return records
        } catch (e: Exception) {
            LOG.warn("Failed to read file: $e")
            return null
        }
    }

    fun clear() {
        try {
            if (file.exists()) {
                file.delete()
            }
        } catch (e: Exception) {
            LOG.warn("Failed to delete file: $e")
        }
    }
}