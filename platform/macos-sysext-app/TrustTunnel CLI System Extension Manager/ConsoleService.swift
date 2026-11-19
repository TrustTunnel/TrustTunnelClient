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
//  configuration and reports every state change through its callback, so the commands
//  below only wait for the state they need before exiting. The main thread must never
//  block: the manager loads and `VpnManager`'s status observations deliver asynchronously.
//

import Foundation
import TrustTunnelClient

enum ConsoleService {

    enum Command: String, CaseIterable {
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

    /// Names for the states reported by `VpnManager`'s callback; the values must stay in
    /// sync with `VpnSessionState` in `platform/apple/TrustTunnelClient/VpnManager.swift`.
    private static let stateNames = [
        "disconnected", "connecting", "connected", "waiting for recovery", "recovering",
        "waiting for network",
    ]

    /// State values used by the commands. See `stateNames`.
    private enum VpnState {
        static let disconnected = 0
        static let connected = 2
    }

    /// Created by each command and retained for the lifetime of the headless process:
    /// `VpnManager` owns the state observation, so it must not be deallocated while a
    /// command is waiting for a state change.
    private static var vpnManager: VpnManager?
    /// Set by `makeVpnManager`; called on the main queue for every state change.
    private static var onStateChange: ((Int) -> Void)?

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
    /// missing tunnel is a success, mirroring `VpnManager` idempotency.
    private static func stop(_ completion: @escaping (Int32) -> Void) {
        var receivedInitialState = false
        var stopping = false
        makeVpnManager { state in
            guard receivedInitialState else {
                receivedInitialState = true
                guard state != VpnState.disconnected else {
                    print("The tunnel is not running")
                    completion(EXIT_SUCCESS)
                    return
                }
                stopping = true
                print("Stopping the tunnel…")
                vpnManager?.stop()
                return
            }
            guard stopping, state == VpnState.disconnected else {
                return
            }
            print("The tunnel has been stopped, the configuration stays installed")
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
        var receivedInitialState = false
        var stopping = false
        makeVpnManager { state in
            guard receivedInitialState else {
                receivedInitialState = true
                guard state != VpnState.disconnected else {
                    removeConfiguration(completion)
                    return
                }
                stopping = true
                print("Stopping the tunnel…")
                vpnManager?.stop()
                return
            }
            guard stopping, state == VpnState.disconnected else {
                return
            }
            stopping = false
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

    /// Start the tunnel; `VpnManager.start` resolves the completion once the tunnel
    /// is connected or disconnected, so this only maps the outcome to the process
    /// exit status. An already connected tunnel is reported without a redundant start.
    private static func startTunnel(config: String, _ completion: @escaping (Int32) -> Void) {
        makeVpnManager { state in
            guard state != VpnState.connected else {
                print("The tunnel is already connected")
                completion(EXIT_SUCCESS)
                return
            }
            // Already connecting, recovering, etc.: wait for the final state.
            guard state == VpnState.disconnected else {
                return
            }
            print("Starting the tunnel…")
            vpnManager?.start(config: config, fallIntoRecovery: false) { error in
                if error != nil {
                    print("Failed to start the tunnel, check the logs")
                    completion(EXIT_FAILURE)
                } else {
                    print("The tunnel is connected")
                    completion(EXIT_SUCCESS)
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

    /// Create the process-wide `VpnManager` and route its state changes to `handler` on
    /// the main queue. `VpnManager` reports changes from its own queues, so the main
    /// queue hop serializes all command logic.
    private static func makeVpnManager(onStateChange handler: @escaping (Int) -> Void) {
        onStateChange = handler
        vpnManager = VpnManager(
            bundleIdentifier: extensionBundleIdentifier,
            appGroup: appGroup,
            stateChangeCallback: { state in
                DispatchQueue.main.async {
                    onStateChange?(state)
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
        guard state >= 0 else { return "disconnecting" }
        guard state < stateNames.count else { return "unknown(\(state))" }
        return stateNames[state]
    }
}
