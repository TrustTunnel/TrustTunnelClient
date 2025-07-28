package com.adguard.trusttunnel

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.net.VpnService
import android.os.Bundle
import android.view.Surface
import com.adguard.trusttunnel.log.LoggerManager
import java.util.concurrent.TimeoutException

/**
 * The only purpose of this activity is to prepare the VPN
 */
class VpnPrepareActivity : Activity() {

    @SuppressLint("SourceLockedOrientationActivity")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // We lock an activity orientation to save the state of previous activity
        try {
            when (windowManager.defaultDisplay.rotation) {
                Surface.ROTATION_180 -> requestedOrientation =
                    ActivityInfo.SCREEN_ORIENTATION_REVERSE_PORTRAIT

                Surface.ROTATION_270 -> requestedOrientation =
                    ActivityInfo.SCREEN_ORIENTATION_REVERSE_LANDSCAPE

                Surface.ROTATION_0 -> requestedOrientation =
                    ActivityInfo.SCREEN_ORIENTATION_PORTRAIT

                Surface.ROTATION_90 -> requestedOrientation =
                    ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
            }
        } catch (th: Throwable) {
            LOG.error("Cannot request orientation", th)
        }
    }

    override fun onStart() {
        super.onStart()

        LOG.info("Start preparing the VpnService")

        try {
            val localIntent = VpnService.prepare(this)
            if (localIntent != null) {
                // Save the activity
                RESULT.activity = this

                LOG.info("Showing the VPN preparation dialog")
                startActivityForResult(localIntent, PREPARE_VPN_REQUEST_CODE)
            } else {
                finish(true, null)
            }
        } catch (ex: Exception) {
            LOG.error("Error while preparing the VpnService", ex)
            finish(false, ex)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        LOG.info("onActivityResult requestCode=$requestCode resultCode=$resultCode")
        val success = requestCode == PREPARE_VPN_REQUEST_CODE && resultCode == RESULT_OK
        finish(success, null)
    }

    private fun finish(success: Boolean, exception: Exception?) {
        synchronized(RESULT) {
            RESULT.inProgress = false
            RESULT.success = success
            RESULT.exception = exception
            RESULT.activity = null
            (RESULT as Object).notifyAll()
            finish()
        }
    }

    private class PreparationResult {
        var inProgress: Boolean = false
        var success: Boolean = false
        var exception: Exception? = null
        var activity: VpnPrepareActivity? = null

        fun prepareForInProgress() {
            inProgress = true
            success = false
            exception = null
            activity = null
        }
    }

    companion object {
        private const val WAIT_TIMEOUT = 1000
        private const val MAX_WAIT_TIME = 60 * 1000
        private const val PREPARE_VPN_REQUEST_CODE = 1234

        private val LOG = LoggerManager.getLogger("VpnPrepareActivity")

        /**
         * This object acts as a wait handle. The algorithm is:
         *
         *
         * 1. VpnPrepareActivity is started within the [.start] method.
         * 2. RESULT.wait() is then called. Thread is blocked until the VpnPrepareActivity finishes its work
         * 3. Regular VpnService.prepare activity is shown.
         * 4. Once onActivityResult is received, RESULT fields are populated and RESULT.notifyAll() is called
         * 5. The original thread wakes up and handles the result
         */
        private val RESULT: VpnPrepareActivity.PreparationResult = PreparationResult()

        /**
         * Starts this activity and waits for it to finish its work.
         *
         * @param context Starting context
         * @throws IllegalStateException   thrown if it was called from the UI thread
         * @throws VpnNotPreparedException thrown if VPN could not be prepared
         */
        @Throws(VpnNotPreparedException::class)
        fun start(context: Context) {
            synchronized(RESULT) {
                RESULT.prepareForInProgress()
                val intent = Intent(context, VpnPrepareActivity::class.java)
                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_HISTORY)

                try {
                    context.startActivity(intent)
                } catch (throwable: Throwable) {
                    LOG.error("Failed to execute the 'startActivity' method", throwable)
                }

                val startTime = System.currentTimeMillis()
                while (RESULT.inProgress) {
                    /*
                        It appears that on some devices onActivityResult method is not getting called when user confirms the VPN access:
                        In order to handle this we periodically check if VPN is prepared while waiting for onActivityResult to be called.
                     */
                    try {
                        (RESULT as Object).wait(
                            WAIT_TIMEOUT.toLong()
                        )
                    } catch (e: InterruptedException) {
                        LOG.error("Error occurred while waiting for VPN service for prepare", e)
                    }
                    checkAndFinishIfNeeded(context, startTime)
                }
                if (!RESULT.success) {
                    throw VpnNotPreparedException(RESULT.exception)
                }
            }
        }

        private fun checkAndFinishIfNeeded(context: Context, startTime: Long) {
            var isVpnPrepared = false
            try {
                isVpnPrepared = VpnService.prepare(context) == null
            } catch (throwable: Throwable) {
                LOG.error("Error occurred while getting VPN service status", throwable)
            }
            if (RESULT.activity != null && isVpnPrepared) {
                RESULT.activity?.finish(true, null)
                return
            }

            val elapsed = System.currentTimeMillis() - startTime
            if (elapsed > MAX_WAIT_TIME) {
                if (RESULT.activity != null) {
                    RESULT.activity?.finish(
                        false,
                        TimeoutException("VPN was not prepared for " + MAX_WAIT_TIME + "ms")
                    )
                }
            }
        }
    }
}

class VpnNotPreparedException(reason: Exception?) : Exception(reason)