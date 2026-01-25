package com.adguard.trusttunnel

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import com.adguard.trusttunnel.log.LoggerManager

/**
 * A simple invisible Activity that delegates VPN preparation to the system dialog.
 * Usage: Start this Activity. It will finish with RESULT_OK if VPN is permitted, or RESULT_CANCELED otherwise.
 */
class VpnPrepareActivity : ComponentActivity() {

    private val prepareVpnLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            LOG.info("VPN permission granted by user")
            setResult(Activity.RESULT_OK)
        } else {
            LOG.warn("VPN permission denied or cancelled")
            setResult(Activity.RESULT_CANCELED)
        }
        finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // No UI needed
        
        LOG.info("Checking VPN permission")
        val intent = VpnService.prepare(this)
        if (intent != null) {
            LOG.info("Launching VPN permission dialog")
            try {
                prepareVpnLauncher.launch(intent)
            } catch (e: Exception) {
                LOG.error("Failed to launch VPN prepare intent", e)
                setResult(Activity.RESULT_CANCELED)
                finish()
            }
        } else {
            LOG.info("VPN already prepared")
            setResult(Activity.RESULT_OK)
            finish()
        }
    }

    companion object {
        private val LOG = LoggerManager.getLogger("VpnPrepareActivity")
    }
}