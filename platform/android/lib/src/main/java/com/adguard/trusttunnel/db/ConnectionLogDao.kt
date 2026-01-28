package com.adguard.trusttunnel.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ConnectionLogDao {
    @Insert
    suspend fun insert(log: ConnectionLog)

    @Query("SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT 500")
    fun getAll(): Flow<List<ConnectionLog>>

    @Query("SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT 500")
    suspend fun getAllSnapshot(): List<ConnectionLog>

    @Query("DELETE FROM connection_logs")
    suspend fun clear()

    @Query("DELETE FROM connection_logs WHERE id NOT IN (SELECT id FROM connection_logs ORDER BY timestamp DESC LIMIT 500)")
    suspend fun prune()
}
