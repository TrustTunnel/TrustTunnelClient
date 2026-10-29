//
//  ConsoleService.swift
//  TrustTunnel CLI System Extension Manager
//
//  Headless (console) mode orchestration. The CLI spawns this app per subcommand and
//  reads the process exit status (0 = success, 1 = failure) with progress lines relayed
//  from stdout.
//
//  Tunnel lifecycle (start/stop/configuration) is driven exclusively through the
//  `VpnManager` from the TrustTunnelClient pod; `loadManager` is read-only
//  introspection used to sequence the commands, since `VpnManager` reports results
//  only through its callbacks. The main thread must never block: the manager loads
//  and `VpnManager`'s status observations deliver on the main queue.
//

import Foundation
import NetworkExtension
import TrustTunnelClient
import VpnClientFramework

enum ConsoleService {

    enum Command: String {
        case install
        case start
        case stop
        case status
        case uninstall
    }

    /// Must match the extension target and the provider configuration written by
    /// `VpnManager`.
    static let extensionBundleIdentifier = "com.adguard.TrustTunnel.SystemExtension"
    static let appGroup = "group.com.adguard.TrustTunnel"

    /// Name of the config copy inside the app group container, written by the CLI.
    private static let configFileName = "config.toml"
    /// Must stay in sync with `ConnectionInfoParams.fileName` in the TrustTunnelClient pod.
    private static let connectionInfoFileName = "connection_info.dat"
    /// Blocking waits mirror the 15 s guards used inside `VpnManager`.
    private static let operationTimeout: TimeInterval = 15
    /// Delay between two manager state polls while waiting for an operation to finish.
    private static let pollInterval: TimeInterval = 0.25
    /// Names for the states reported by `VpnManager`'s callback; the values must stay in
    /// sync with `VpnSessionState` in `platform/apple/TrustTunnelClient/VpnManager.swift`.
    private static let stateNames = [
        "disconnected", "connecting", "connected", "waiting for recovery", "recovering",
        "waiting for network",
    ]

    /// Run the given subcommand and report the outcome through `completion`
    /// (0 = success, 1 = failure).
    static func run(_ command: Command, configPath: String?, completion: @escaping (Int32) -> Void) {
        switch command {
        case .install:
            install(completion)
        case .start:
            start(configPath: configPath, completion)
        case .stop:
            stop(completion)
        case .status:
            status(completion)
        case .uninstall:
            uninstall(completion)
        }
    }

    // MARK: - Commands

    /// Activate the system extension, waiting until macOS completes the request —
    /// including the user approval, which blocks with no timeout by design.
    private static func install(_ completion: @escaping (Int32) -> Void) {
        activate { activated in
            completion(activated ? EXIT_SUCCESS : EXIT_FAILURE)
        }
    }

    /// Ensure the extension is activated, then submit the tunnel start. Fire-and-forget:
    /// only immediate failures (the manager never leaving the disconnected state) are
    /// reported; the connection outcome is observable via the `status` command and
    /// System Settings.
    private static func start(configPath: String?, _ completion: @escaping (Int32) -> Void) {
        guard let configPath else {
            print("No config path was handed over, cannot start the tunnel")
            completion(EXIT_FAILURE)
            return
        }
        guard let config = readFile(configPath) else {
            print("Failed to read the config at \(configPath)")
            completion(EXIT_FAILURE)
            return
        }
        activate { activated in
            guard activated else {
                completion(EXIT_FAILURE)
                return
            }
            startTunnel(config: config, completion)
        }
    }

    /// Stop the tunnel and keep the (disabled) configuration installed. A stopped or
    /// missing tunnel is a success, mirroring `VpnManager` idempotency.
    private static func stop(_ completion: @escaping (Int32) -> Void) {
        loadManager { manager in
            guard let manager, !isIdle(manager) else {
                print("The tunnel is not running")
                completion(EXIT_SUCCESS)
                return
            }
            print("Stopping the tunnel…")
            makeVpnManager().stop()
            waitFor(deadline: Date().addingTimeInterval(operationTimeout)) { manager in
                // A manager that disappeared entirely counts as stopped as well.
                manager.map { $0.connection.status == .disconnected } ?? true
            } onDone: { stopped in
                if stopped {
                    print("The tunnel has been stopped, the configuration stays installed")
                } else {
                    print("The tunnel did not stop in time")
                }
                completion(stopped ? EXIT_SUCCESS : EXIT_FAILURE)
            }
        }
    }

    /// Report the tunnel state. Always succeeds, regardless of the state.
    private static func status(_ completion: @escaping (Int32) -> Void) {
        loadManager { manager in
            guard let manager else {
                print("The system extension is not installed")
                completion(EXIT_SUCCESS)
                return
            }
            print("The VPN configuration is installed")
            if manager.isEnabled {
                print("Connection status: \(string(for: manager.connection.status))")
            } else {
                print("The VPN configuration is disabled in System Settings")
            }
            if let info = lastConnectionInfo() {
                print("Last connection info: \(info)")
            } else {
                print("No connection info has been recorded yet")
            }
            if UserDefaults.standard.bool(forKey: SystemExtensionManager.rebootRequiredKey) {
                print("Note: a reboot may be required to finish a system extension update")
            }
            completion(EXIT_SUCCESS)
        }
    }

    /// Stop the tunnel, delete the manager configuration and deactivate the extension.
    /// The CLI removes the app bundle from /Applications afterwards.
    static func uninstall(_ completion: @escaping (Int32) -> Void) {
        removeConfiguration { removed in
            guard removed else {
                completion(EXIT_FAILURE)
                return
            }
            SystemExtensionManager.shared.deinstall { result in
                switch result {
                case .success:
                    print("The system extension has been uninstalled")
                    completion(EXIT_SUCCESS)
                case .failure(let error):
                    print("Failed to uninstall the system extension: \(error.localizedDescription)")
                    completion(EXIT_FAILURE)
                }
            }
        }
    }

    // MARK: - Activation

    /// Ensure the system extension is activated. Idempotent: activation of an
    /// already-active extension completes right away.
    private static func activate(_ completion: @escaping (Bool) -> Void) {
        print("Installing system extension…")
        SystemExtensionManager.shared.install { result in
            switch result {
            case .success:
                print("System extension installed")
                completion(true)
            case .failure(let error):
                print("Failed to install the system extension: \(error.localizedDescription)")
                completion(false)
            }
        }
    }

    // MARK: - Tunnel control

    /// Submit the tunnel start. When the tunnel is already up (or coming up) this is a
    /// no-op success.
    private static func startTunnel(config: String, _ completion: @escaping (Int32) -> Void) {
        loadManager { manager in
            if let manager, isRunning(manager) {
                print("The tunnel is already \(string(for: manager.connection.status))")
                completion(EXIT_SUCCESS)
                return
            }
            print("Starting the tunnel…")
            // Kept alive for the lifetime of the process; the tunnel itself is owned by
            // macOS and keeps running after this app exits.
            makeVpnManager().start(config: config, fallIntoRecovery: false)
            waitFor(deadline: Date().addingTimeInterval(operationTimeout)) { manager in
                // The start is submitted once the manager leaves the disconnected state;
                // immediate failures (config errors, extension launch failures) leave it
                // disconnected or turn it invalid.
                manager.map { $0.connection.status != .disconnected && $0.connection.status != .invalid } ?? false
            } onDone: { started in
                if started {
                    print("The tunnel start has been submitted, check the state with --sysext status")
                } else {
                    print("Failed to start the tunnel, check the logs")
                }
                completion(started ? EXIT_SUCCESS : EXIT_FAILURE)
            }
        }
    }

    /// Stop the tunnel (if any) and delete the manager configuration, keeping the
    /// extension itself activated — deactivation is the caller's next step.
    private static func removeConfiguration(_ completion: @escaping (Bool) -> Void) {
        loadManager { manager in
            guard manager != nil else {
                completion(true)
                return
            }
            print("Removing the VPN configuration…")
            // The calls are serialized on VpnManager's internal queue: the configuration
            // is deleted after the tunnel stops.
            let vpnManager = makeVpnManager()
            vpnManager.stop()
            vpnManager.updateConfiguration(config: nil)
            waitFor(deadline: Date().addingTimeInterval(operationTimeout)) { manager in
                manager == nil
            } onDone: { removed in
                if removed {
                    print("The VPN configuration has been deleted")
                    completion(true)
                    return
                }
                // deleteConfiguration refuses invalid managers; fall back to a direct
                // removal so that uninstall can also clean up a broken configuration.
                loadManager { manager in
                    guard let manager else {
                        print("The VPN configuration has been deleted")
                        completion(true)
                        return
                    }
                    manager.removeFromPreferences { error in
                        if let error {
                            print("Failed to delete the VPN configuration: \(error.localizedDescription)")
                            completion(false)
                        } else {
                            print("The VPN configuration has been deleted")
                            completion(true)
                        }
                    }
                }
            }
        }
    }

    // MARK: - Helpers

    private static func makeVpnManager() -> VpnManager {
        VpnManager(
            bundleIdentifier: extensionBundleIdentifier,
            appGroup: appGroup,
            stateChangeCallback: { state in
                print("Tunnel state: \(stateName(state))")
            },
            connectionInfoCallback: { _ in })
    }

    /// Load the tunnel provider manager belonging to our system extension, or nil when
    /// no configuration is installed. `loadAllFromPreferences` delivers on the main
    /// queue, so the main thread must stay free — hence the completion-based API.
    private static func loadManager(_ onLoaded: @escaping (NETunnelProviderManager?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            let manager = managers?.first {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == extensionBundleIdentifier
            }
            onLoaded(manager)
        }
    }

    /// Poll the manager state until `condition` holds or the deadline passes. `manager`
    /// is nil when no configuration is installed.
    private static func waitFor(
        deadline: Date,
        _ condition: @escaping (NETunnelProviderManager?) -> Bool,
        onDone: @escaping (Bool) -> Void
    ) {
        loadManager { manager in
            if condition(manager) {
                onDone(true)
                return
            }
            guard Date() < deadline else {
                onDone(false)
                return
            }
            DispatchQueue.global(qos: .default).asyncAfter(deadline: .now() + pollInterval) {
                waitFor(deadline: deadline, condition, onDone: onDone)
            }
        }
    }

    /// True when nothing is running: the manager is disconnected (or invalid), and no
    /// connect-on-demand rules keep it alive.
    private static func isIdle(_ manager: NETunnelProviderManager) -> Bool {
        let status = manager.connection.status
        return (status == .disconnected || status == .invalid) && !manager.isOnDemandEnabled
    }

    /// True when the tunnel is up or coming up and no start is needed.
    private static func isRunning(_ manager: NETunnelProviderManager) -> Bool {
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            return true
        default:
            return false
        }
    }

    /// The most recent record from the connection info ring buffer in the app group.
    private static func lastConnectionInfo() -> String? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup) else {
            print("Failed to resolve the app group container")
            return nil
        }
        let buffer = PersistentRingBuffer(
            path: container.appendingPathComponent(connectionInfoFileName).path)
        guard let result = buffer.readAll() else {
            return nil
        }
        return result.records.last
    }

    private static func readFile(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path),
              let content = String(data: data, encoding: .utf8) else {
            return nil
        }
        return content
    }

    private static func stateName(_ state: Int) -> String {
        // `VpnManager` reports -1 for statuses it does not map, currently .disconnecting.
        guard state >= 0 else { return "disconnecting" }
        guard state < stateNames.count else { return "unknown(\(state))" }
        return stateNames[state]
    }

    private static func string(for status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }
}
