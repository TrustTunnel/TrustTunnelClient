package com.adguard.trusttunnel

enum class VpnState (val code: Int) {
    DISCONNECTED(0),
    CONNECTING(1),
    CONNECTED(2),
    WAITING_RECOVERY(3),
    RECOVERING(4),
    WAITING_FOR_NETWORK(5);

    companion object {
        private val map: MutableMap<Int, VpnState> = HashMap()

        init {
            for (value in VpnState.entries) {
                map[value.code] = value
            }
        }

        fun getByCode(code: Int): VpnState {
            val state = map[code]
            requireNotNull(state) { "Invalid VpnState code $code" }
            return state
        }
    }
}