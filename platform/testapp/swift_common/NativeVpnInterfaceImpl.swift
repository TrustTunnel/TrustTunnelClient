import TrustTunnelClient
import Foundation

class NativeVpnInterfaceImpl : NativeVpnInterface {
    private let vpnManager: VpnManager
    init(callbacks: FlutterCallbacks) {
        self.vpnManager = VpnManager(
            bundleIdentifier: "com.trusttunnel.testapp.Network-Extension",
            appGroup: "group.com.adguard.testapp",
            stateChangeCallback: { state in
                DispatchQueue.main.async {
                    callbacks.onStateChanged(state: Int64(state)) { _ in }
                }
            },
            connectionInfoCallback: { info in
                DispatchQueue.main.async {
                    callbacks.onConnectionInfo(info: info) { _ in }
                }
            }
        )
    }
    func start(config: String) throws {
        self.vpnManager.start(config: config, fallIntoRecovery: false) { _ in }
    }
    func stop() throws {
        self.vpnManager.stop { _ in }
    }
    func exportLogs() throws -> [String] {
        return vpnManager.exportLogs()
    }
    func clearLogs() throws {
        _ = vpnManager.clearLogs()
    }
}
