//
//  SystemExtensionManager.swift
//  TrustTunnel CLI System Extension Manager
//
//  Ported from the "AdGuard CLI Filtering Engine" reference app. Drives activation and
//  deactivation of the bundled network system extension; shared by the GUI and the
//  headless (console) mode.
//

import Combine
import Foundation
import SystemExtensions

/// Drives activation / deactivation of the bundled network system extension.
@MainActor
final class SystemExtensionManager: NSObject, ObservableObject {

    static let shared = SystemExtensionManager()

    /// Bundle identifier of the embedded system extension target.
    static let extensionIdentifier = "com.adguard.TrustTunnel.SystemExtension"

    /// Set when macOS completes an activation request with `.willCompleteAfterReboot`,
    /// reported by the `status` command until a regular activation clears it.
    static let rebootRequiredKey = "sysextRebootRequired"

    enum State: Equatable {
        case idle
        case installing
        case uninstalling
        case installed
        case failed(String)
    }

    @Published private(set) var state: State = .idle

    /// Invoked once when the in-flight request finishes (success or failure).
    private var completion: ((Result<Void, Error>) -> Void)?

    /// True while a request is in flight, used to disable the buttons.
    var isBusy: Bool {
        state == .installing || state == .uninstalling
    }

    /// Requests activation of the system extension.
    /// - Parameter completion: Optional callback invoked when activation finishes.
    func install(completion: ((Result<Void, Error>) -> Void)? = nil) {
        guard !isBusy else { return }
        self.completion = completion
        state = .installing
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Requests deactivation of the system extension.
    /// - Parameter completion: Optional callback invoked when deactivation finishes.
    func deinstall(completion: ((Result<Void, Error>) -> Void)? = nil) {
        guard !isBusy else { return }
        self.completion = completion
        state = .uninstalling
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.extensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Invoke and clear the pending completion callback.
    private func finish(_ result: Result<Void, Error>) {
        let completion = self.completion
        self.completion = nil
        completion?(result)
    }
}

extension SystemExtensionManager: OSSystemExtensionRequestDelegate {

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always replace the previously installed extension with the bundled one.
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // The user must approve the extension in System Settings > Privacy & Security.
    }

    nonisolated func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            if self.state == .uninstalling {
                self.state = .idle
            } else {
                // .willCompleteAfterReboot also lands here; treat as installed and note
                // that a reboot may be required to finish the update.
                UserDefaults.standard.set(result == .willCompleteAfterReboot, forKey: Self.rebootRequiredKey)
                self.state = .installed
            }
            self.finish(.success(()))
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in
            self.state = .failed(error.localizedDescription)
            self.finish(.failure(error))
        }
    }
}
