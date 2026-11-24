//
//  ConsoleService.swift
//  TrustTunnel CLI System Extension Manager
//
//  Headless (console) mode orchestration. The CLI spawns this app per subcommand and
//  reads the process exit status (0 = success, 1 = failure) with progress lines relayed
//  from stdout.
//
//  Tunnel lifecycle (start/stop/configuration) is driven exclusively through the
//  `VpnManager` from the TrustTunnelClient pod: it owns the Network Extension
//  configuration and validates the tunnel state. Its start/stop completions only report
//  whether the request was accepted, so the commands below decide the exit status from
//  the states reported after it. The main thread must never block: the manager loads
//  and `VpnManager`'s status observations deliver asynchronously.
//

import Foundation
import Security
import TrustTunnelClient

enum ConsoleService {

    enum Command: String, CaseIterable {
        case install
        case start
        case stop
        case status
        case uninstall
    }

    /// Bundle identifier of the embedded system extension; the single place it is spelled out,
    /// used for activation requests and for the configuration written by `VpnManager`.
    static let extensionBundleIdentifier = "com.adguard.TrustTunnel.SystemExtension"

    /// The app group to share logs and connection info with the extension.
    ///
    /// Read from the app's own signature instead of duplicating the string: the signed
    /// value must equal an entry of `com.apple.security.application-groups`, and it
    /// differs between development and Developer ID builds (the latter is prefixed with
    /// the team id, see the entitlements file).
    static let appGroup: String = {
        guard let task = SecTaskCreateFromSelf(nil),
              let groups = SecTaskCopyValueForEntitlement(
                  task, "com.apple.security.application-groups" as CFString, nil) as? [String],
              let group = groups.first else {
            print("No application groups entitlement, logs and connection info will not be shared")
            return ""
        }
        return group
    }()

    /// Human-readable names keyed by the canonical `VpnSessionState`.
    private static let stateNames: [VpnSessionState: String] = [
        .disconnected: "disconnected",
        .connecting: "connecting",
        .connected: "connected",
        .waiting_recovery: "waiting for recovery",
        .recovering: "recovering",
        .waiting_for_network: "waiting for network",
    ]

    /// Created by each command and retained for the lifetime of the headless process:
    /// `VpnManager` owns the state observation, so it must not be deallocated while a
    /// command is waiting for a state change.
    private static var vpnManager: VpnManager?

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
        print("Installing system extension…")
        print("Approve the system extension in System Settings -> General -> Login Items -> Network Extensions.")
        activate { activated in
            if activated {
                print("System extension installed")
            }
            completion(activated ? EXIT_SUCCESS : EXIT_FAILURE)
        }
    }

    /// Start the tunnel and wait until it connects or disconnects.
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
        startTunnel(config: config, completion)
    }

    /// Stop the tunnel and keep the (disabled) configuration installed. A stopped or
    /// missing tunnel is a success: `VpnManager.stop` treats both as already stopped.
    private static func stop(_ completion: @escaping (Int32) -> Void) {
        stopTunnel { stopped in
            guard stopped else {
                completion(EXIT_FAILURE)
                return
            }
            print("The tunnel is stopped, the configuration stays installed")
            completion(EXIT_SUCCESS)
        }
    }

    /// Report the tunnel state. Always succeeds, regardless of the state.
    private static func status(_ completion: @escaping (Int32) -> Void) {
        makeVpnManager { state in
            print("Connection status: \(stateName(state))")
            if UserDefaults.standard.bool(forKey: SystemExtensionManager.rebootRequiredKey) {
                print("Note: a reboot may be required to finish a system extension update")
            }
            completion(EXIT_SUCCESS)
        }
    }

    /// Stop the tunnel, delete the manager configuration and deactivate the extension.
    /// The CLI removes the app bundle from /Applications afterwards.
    static func uninstall(_ completion: @escaping (Int32) -> Void) {
        stopTunnel { stopped in
            guard stopped else {
                completion(EXIT_FAILURE)
                return
            }
            removeConfiguration(completion)
        }
    }

    // MARK: - Activation

    /// Ensure the system extension is activated. Idempotent: activation of an
    /// already-active extension completes right away.
    private static func activate(_ completion: @escaping (Bool) -> Void) {
        SystemExtensionManager.shared.install { result in
            switch result {
            case .success:
                completion(true)
            case .failure(let error):
                print("Failed to install the system extension: \(error.localizedDescription)")
                completion(false)
            }
        }
    }

    // MARK: - Tunnel control

    /// Start the tunnel and wait for the outcome. `VpnManager.start` only reports whether the
    /// request was accepted, and every state reported after an accepted request is caused by
    /// it, so the states before acceptance are ignored: `connected` or `recovering` then means
    /// started, `disconnected` means failed.
    private static func startTunnel(config: String, _ completion: @escaping (Int32) -> Void) {
        var armed = false
        makeVpnManager { state in
            guard armed, let vpnState = VpnSessionState(rawValue: state) else {
                return
            }
            switch vpnState {
            case .connected, .recovering:
                armed = false
                print("The tunnel is connected")
                completion(EXIT_SUCCESS)
            case .disconnected:
                armed = false
                print("Failed to start the tunnel, check the logs")
                completion(EXIT_FAILURE)
            default:
                break
            }
        }
        print("Starting the tunnel…")
        vpnManager?.start(config: config, fallIntoRecovery: false) { error in
            DispatchQueue.main.async {
                if error != nil {
                    print("Failed to start the tunnel, check the logs")
                    completion(EXIT_FAILURE)
                } else {
                    armed = true
                }
            }
        }
    }

    /// Stop the tunnel and wait until it is disconnected, reporting whether it stopped.
    private static func stopTunnel(_ completion: @escaping (Bool) -> Void) {
        var armed = false
        var lastState: VpnSessionState?
        makeVpnManager { state in
            guard let vpnState = VpnSessionState(rawValue: state) else {
                return
            }
            lastState = vpnState
            guard armed, vpnState == .disconnected else {
                return
            }
            armed = false
            completion(true)
        }
        print("Stopping the tunnel…")
        vpnManager?.stop { error in
            DispatchQueue.main.async {
                if error != nil {
                    print("Failed to stop the tunnel, check the logs")
                    completion(false)
                } else if lastState == .disconnected {
                    completion(true)
                } else {
                    armed = true
                }
            }
        }
    }

    /// Delete the manager configuration, keeping the extension itself activated —
    /// deactivation is the caller's next step.
    private static func removeConfiguration(_ completion: @escaping (Int32) -> Void) {
        print("Removing the VPN configuration…")
        vpnManager?.updateConfiguration(config: nil) { error in
            // `VpnManager` reports on its own queue, while the extension requests are main-actor.
            DispatchQueue.main.async {
                if let error {
                    print("Failed to remove the VPN configuration: \(error.localizedDescription)")
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
    }

    // MARK: - Helpers

    /// Create the process-wide `VpnManager` and route its state changes to `onStateChange` on
    /// the main queue. `VpnManager` calls its completions and state callback on one serial
    /// queue, so hopping both to the main queue keeps their order and serializes all command
    /// logic.
    private static func makeVpnManager(onStateChange: @escaping (Int) -> Void) {
        vpnManager = VpnManager(
            bundleIdentifier: extensionBundleIdentifier,
            appGroup: appGroup,
            stateChangeCallback: { state in
                DispatchQueue.main.async {
                    onStateChange(state)
                }
            },
            connectionInfoCallback: { _ in })
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
        guard let vpnState = VpnSessionState(rawValue: state) else {
            return state >= 0 ? "unknown(\(state))" : "disconnecting"
        }
        return stateNames[vpnState] ?? "unknown(\(state))"
    }
}
