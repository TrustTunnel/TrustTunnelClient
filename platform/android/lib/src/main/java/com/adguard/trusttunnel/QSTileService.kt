package com.adguard.trusttunnel

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.adguard.trusttunnel.log.LoggerManager

class QSTileService : TileService() {

    companion object {
        private val LOG = LoggerManager.getLogger("QSTileService")
    }

    private var mMsgReceive: BroadcastReceiver? = null

    override fun onStartListening() {
        super.onStartListening()
        
        updateTile(VpnService.isRunning())

        mMsgReceive = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                if (intent?.action == VpnService.ACTION_VPN_STATE_CHANGED) {
                    val stateCode = intent.getIntExtra(VpnService.EXTRA_VPN_STATE, VpnState.DISCONNECTED.code)
                    val isRunning = stateCode == VpnState.CONNECTED.code || stateCode == VpnState.CONNECTING.code
                    updateTile(isRunning)
                }
            }
        }
        
        val filter = IntentFilter(VpnService.ACTION_VPN_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.registerReceiver(this, mMsgReceive, filter, ContextCompat.RECEIVER_EXPORTED)
        } else {
            ContextCompat.registerReceiver(this, mMsgReceive, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        }
    }

    override fun onStopListening() {
        super.onStopListening()
        try {
            mMsgReceive?.let {
                applicationContext.unregisterReceiver(it)
            }
            mMsgReceive = null
        } catch (e: Exception) {
            LOG.error("Failed to unregister receiver", e)
        }
    }

    override fun onClick() {
        super.onClick()
        if (qsTile.state == Tile.STATE_INACTIVE) {
            val config = VpnService.getLastConfig(this)
            if (config != null) {
                if (!VpnService.isPrepared(this)) {
                    // Try to start prepare activity if possible
                    val intent = Intent(this, VpnPrepareActivity::class.java)
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    try {
                        startActivityAndCollapse(intent)
                    } catch (e: Exception) {
                        LOG.error("Failed to start prepare activity", e)
                    }
                } else {
                    VpnService.start(this, config)
                }
            } else {
                LOG.warn("No previous config found to start VPN from Quick Settings")
            }
        } else if (qsTile.state == Tile.STATE_ACTIVE) {
            VpnService.stop(this)
        }
    }

    private fun updateTile(isRunning: Boolean) {
        val iconId = resources.getIdentifier("ic_qs_tile", "drawable", packageName)
        if (iconId == 0) {
            throw IllegalStateException("Missing 'ic_qs_tile' drawable resource. A monochromatic icon is strictly required for the Quick Settings Tile.")
        }
        qsTile?.icon = Icon.createWithResource(this, iconId)
        if (isRunning) {
            qsTile?.state = Tile.STATE_ACTIVE
            qsTile?.label = "TrustTunnel"
        } else {
            qsTile?.state = Tile.STATE_INACTIVE
            qsTile?.label = "TrustTunnel"
        }
        qsTile?.updateTile()
    }
}
