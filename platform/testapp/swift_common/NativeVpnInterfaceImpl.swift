//
//  NativeVpnInterfaceImpl.swift
//  Runner
//
//  Created by Andrey Yakushin on 28.07.2025.
//

import TrustTunnel
import Foundation

class NativeVpnInterfaceImpl : NativeVpnInterface {
    private let vpnManager: VpnManager
    init(callbacks: FlutterCallbacks) {
        self.vpnManager = VpnManager(bundleIdentifier: "com.trusttunnel.testapp.Network-Extension") { state in
            DispatchQueue.main.async {
                callbacks.onStateChanged(state: Int64(state)) { _ in }
            }
        }
    }
    func start(config: String) throws {
        self.vpnManager.start(config: config)
    }
    func stop() throws {
        self.vpnManager.stop()
    }
}
