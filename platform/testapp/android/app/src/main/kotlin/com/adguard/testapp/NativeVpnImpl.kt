package com.adguard.testapp

import NativeVpnInterface
import android.content.Context
import com.adguard.trusttunnel.VpnPrepareActivity
import com.adguard.trusttunnel.VpnService

class NativeVpnImpl (
    private val context: Context
) : NativeVpnInterface {
    override fun start(config: String) {
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