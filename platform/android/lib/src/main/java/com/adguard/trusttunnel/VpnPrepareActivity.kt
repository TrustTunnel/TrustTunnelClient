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

    private val requestPermissionLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted: Boolean ->
        if (isGranted) {
            LOG.info("Notification permission granted")
        } else {
            LOG.warn("Notification permission denied")
        }
        // Proceed to VPN prepare even if notification denied (service can still run, just invisible)
        prepareVpn()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // No UI needed
        
        // Check for Notification Permission on Android 13+
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                LOG.info("Requesting POST_NOTIFICATIONS permission")
                requestPermissionLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
            } else {
                prepareVpn()
            }
        } else {
             prepareVpn()
        }
    }

    private fun prepareVpn() {
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