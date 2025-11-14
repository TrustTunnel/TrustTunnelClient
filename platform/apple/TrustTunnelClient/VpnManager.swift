import Foundation
import NetworkExtension

enum VpnSessionState: Int {
    case disconnected;
    case connecting;
    case connected;
    case waiting_recovery;
    case recovering;
    case waiting_for_network;
}

func convertVpnState(_ status: NEVPNStatus) -> Int {
    switch status {
    case .disconnected, .invalid:
        return VpnSessionState.disconnected.rawValue
    case .connecting:
        return VpnSessionState.connecting.rawValue
    case .connected:
        return VpnSessionState.connected.rawValue
    case .reasserting:
        return VpnSessionState.recovering.rawValue
    default:
        return -1
    }
}

public final class VpnManager {
    private var queue: DispatchQueue
    private var vpnManager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private let stateChangeCallback: (Int) -> Void
    private var readyContinuation: CheckedContinuation<NETunnelProviderManager, Never>?
    private var bundleIdentifier: String

    public init(bundleIdentifier: String, stateChangeCallback: @escaping (Int) -> Void) {
        self.queue = DispatchQueue(label: "com.adguard.TrustTunnel.TrustTunnelClient.VpnManager");
        self.bundleIdentifier = bundleIdentifier
        self.stateChangeCallback = stateChangeCallback
        Task {
            startObservingStatus(manager: await self.getManager())
        }
    }
    
    deinit {
        stopObservingStatus()
    }
    
    func getManager() async -> NETunnelProviderManager {
        if let manager = (queue.sync { self.vpnManager }) {
            return manager
        }

        let managers = try! await NETunnelProviderManager.loadAllFromPreferences()

        // Try to find an existing configuration
        let existingManager = managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?
                .providerBundleIdentifier == bundleIdentifier
        }

        return queue.sync {
            if let manager = self.vpnManager {
                return manager
            }
            self.vpnManager = existingManager ?? NETunnelProviderManager()
            return self.vpnManager!
        }
    }

    private func startObservingStatus(manager: NETunnelProviderManager) {
        // Avoid duplicate observers
        guard statusObserver == nil else { return }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.logCurrentStatus(prefix: "status change", manager: manager)
        }
        // Log initial status immediately
        logCurrentStatus(prefix: "initial", manager: manager)
    }

    private func stopObservingStatus() {
        if let token = statusObserver {
            NotificationCenter.default.removeObserver(token)
            statusObserver = nil
        }
    }

    private func logCurrentStatus(prefix: String, manager: NETunnelProviderManager) {
        let status = manager.connection.status
        NSLog("VPN \(prefix): \(string(for: status))")
        if let state = Optional(convertVpnState(manager.connection.status)), state >= 0 {
            stateChangeCallback(state)
        }
    }

    private func string(for status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown(\(status.rawValue))"
        }
    }

    public func start(config: (String)) {
        Task {
            let manager = await getManager()
            do {
                try await manager.loadFromPreferences()
            } catch {
                NSLog("Failed to load preferences: \(error)")
                return
            }

            var configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol) ??
                        NETunnelProviderProtocol()
            configuration.providerBundleIdentifier = bundleIdentifier
            configuration.providerConfiguration = ["config": config as NSObject]
            configuration.serverAddress = "Trust Tunnel"
            manager.protocolConfiguration = configuration
            manager.localizedDescription = "TrustTunnel VPN"
            manager.isEnabled = true
            do {
                try await manager.saveToPreferences()
            } catch {
                NSLog("Failed to save preferences: \(error)")
                return
            }

            // Reload fresh preferences
            do {
                try await manager.loadFromPreferences()
            } catch {
                NSLog("Failed to load preferences: \(error)")
                return
            }

            try manager.connection.startVPNTunnel()
            NSLog("VPN started")
        }
    }

    public func stop() {
        Task {
            let manager = await getManager()
            // Log current status before stopping
            logCurrentStatus(prefix: "pre-stop", manager: manager)
            
            manager.connection.stopVPNTunnel()
        }
    }
}
