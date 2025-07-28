package com.adguard.trusttunnel.log

enum class NativeLoggerLevel(val code: Int) {
    ERROR(0),
    WARN(1),
    INFO(2),
    DEBUG(3),
    TRACE(4);

    companion object {
        private val map: MutableMap<Int, NativeLoggerLevel> = HashMap()

        init {
            for (value in entries) {
                map[value.code] = value
            }
        }

        fun getByCode(code: Int): NativeLoggerLevel {
            val level = map[code]
            requireNotNull(level) { "Invalid log level code $code" }
            return level
        }
    }
}
