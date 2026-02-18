package com.adguard.trusttunnel

import android.content.Context
import android.content.SharedPreferences
import com.adguard.trusttunnel.log.LoggerManager

class VpnConfigStorage(context: Context) {

    companion object {
        private val LOG = LoggerManager.getLogger("VpnConfigStorage")
        private const val PREFS_NAME = "trusttunnel_vpn"
        private const val KEY_CONFIG = "vpn_config"
    }

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun save(config: String) {
        LOG.debug("Persisting VPN config")
        prefs.edit().putString(KEY_CONFIG, config).apply()
    }

    fun load(): String? {
        val config = prefs.getString(KEY_CONFIG, null)
        if (config != null) {
            LOG.debug("Loaded persisted VPN config")
        } else {
            LOG.debug("No persisted VPN config found")
        }
        return config
    }

    fun clear() {
        LOG.debug("Clearing persisted VPN config")
        prefs.edit().remove(KEY_CONFIG).apply()
    }
}
