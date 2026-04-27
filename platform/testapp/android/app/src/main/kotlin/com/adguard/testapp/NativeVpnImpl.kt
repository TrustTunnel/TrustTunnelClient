package com.adguard.testapp

import NativeVpnInterface
import android.content.Context
import com.adguard.trusttunnel.VpnPrepareActivity
import com.adguard.trusttunnel.VpnService
import com.adguard.trusttunnel.utils.concurrent.thread.ThreadManager

class NativeVpnImpl (
    private val context: Context
) : NativeVpnInterface {
    private val singleThread = ThreadManager.create("core-manager", 1)
    // TODO: this is dirty because this method should not use threadpool but
    //       `VpnPrepareActivity.start` blocks the caller thread that is main. Remove it from here
    //       and implement the correct vpn preparing with `onActivityResult` outside of this class
    override fun start(config: String) = singleThread.execute {
        // TODO: socks5
        if (!VpnService.isPrepared(context)) {
            VpnPrepareActivity.start(context);
        }
        VpnService.start(context, config);
    }

    override fun stop() {
        VpnService.stop(context);
    }
}