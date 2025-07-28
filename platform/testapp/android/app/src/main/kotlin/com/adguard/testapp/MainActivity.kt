package com.adguard.testapp

import FlutterCallbacks
import NativeVpnInterface
import com.adguard.trusttunnel.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        val binaryMessenger = flutterEngine.dartExecutor.binaryMessenger

        // Register implementation for native vpn interface
        NativeVpnInterface.setUp(binaryMessenger, NativeVpnImpl(activity))
        VpnService.setStateNotifier(StateNotifierImpl(FlutterCallbacks(binaryMessenger), this))
        VpnService.startNetworkManager(activity)
    }
}
