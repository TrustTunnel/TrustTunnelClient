package com.adguard.trusttunnel.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [ConnectionLog::class], version = 1, exportSchema = false)
abstract class ConnectionLogDatabase : RoomDatabase() {
    abstract fun connectionLogDao(): ConnectionLogDao

    companion object {
        @Volatile
        private var INSTANCE: ConnectionLogDatabase? = null

        fun getDatabase(context: Context): ConnectionLogDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ConnectionLogDatabase::class.java,
                    "connection_log_database"
                )
                    .fallbackToDestructiveMigration() // Strategy for now as per plan
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
