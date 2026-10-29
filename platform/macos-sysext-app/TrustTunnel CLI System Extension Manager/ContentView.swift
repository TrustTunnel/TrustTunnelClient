//
//  ContentView.swift
//  TrustTunnel CLI System Extension Manager
//
//  Ported from the "AdGuard CLI Filtering Engine" reference app: Install / Uninstall
//  buttons plus a status label, sharing the SystemExtensionManager code path with the
//  headless mode. The GUI offers no tunnel control.
//

import SwiftUI

struct ContentView: View {
    @ObservedObject private var systemManager = SystemExtensionManager.shared

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "shield.lefthalf.filled")
                .imageScale(.large)
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("TrustTunnel CLI System Extension Manager")
                .font(.headline)

            Text(statusText)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            HStack(spacing: 12) {
                Button("Install") {
                    systemManager.install()
                }
                .disabled(systemManager.isBusy)

                Button("Uninstall") {
                    // Full uninstall: stop the tunnel, delete the configuration and
                    // deactivate the extension.
                    ConsoleService.uninstall { _ in }
                }
                .disabled(systemManager.isBusy)
            }

            if systemManager.isBusy {
                ProgressView()
                    .controlSize(.small)
            }
        }
        .padding(40)
        .frame(minWidth: 360, minHeight: 280)
    }

    private var statusText: String {
        switch systemManager.state {
        case .idle:
            return "The system extension is not installed."
        case .installing:
            return "Installing… approve the extension in System Settings if prompted."
        case .uninstalling:
            return "Uninstalling…"
        case .installed:
            return "The system extension is installed and active."
        case .failed(let message):
            return "Operation failed: \(message)"
        }
    }
}

#Preview {
    ContentView()
}
