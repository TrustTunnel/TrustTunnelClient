package com.adguard.testapp

import FlutterCallbacks
import NativeVpnInterface
import com.adguard.trusttunnel.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import java.io.File

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        val binaryMessenger = flutterEngine.dartExecutor.binaryMessenger

        // Register implementation for native vpn interface
        NativeVpnInterface.setUp(binaryMessenger, NativeVpnImpl(activity))
        val connectionInfoFile = File(applicationContext.filesDir, "connection_info.dat")
        val appNotifier = AppNotifierImpl(FlutterCallbacks(binaryMessenger), this)
        VpnService.setAppNotifier(connectionInfoFile, appNotifier)
        VpnService.startNetworkManager(activity)
    }
}
