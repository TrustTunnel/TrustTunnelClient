package com.adguard.trusttunnel.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "connection_logs")
data class ConnectionLog(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val timestamp: Long = System.currentTimeMillis(),
    val data: String
)
