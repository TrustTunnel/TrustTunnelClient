//
//  main.swift
//  TrustTunnel CLI System Extension Manager
//
//  Dual-mode entry point: with a subcommand the app runs headless (spawned by the CLI
//  per command), without one it shows the install/uninstall GUI. Headless dispatch
//  happens before any GUI comes up.
//

import AppKit
import SwiftUI

let arguments = CommandLine.arguments
let tokens = Array(arguments.dropFirst())

/// Returns the value following `flag` on the command line, if present.
func value(for flag: String, in tokens: [String]) -> String? {
    guard let index = tokens.firstIndex(of: flag), index + 1 < tokens.count else {
        return nil
    }
    return tokens[index + 1]
}

if let command = ConsoleService.Command(rawValue: tokens.first ?? "") {
    // Headless runs show no window and must not bounce the Dock icon.
    NSApplication.shared.setActivationPolicy(.accessory)
    ConsoleService.run(command, configPath: value(for: "--config", in: tokens)) { exit($0) }
    // Run the loop instead of dispatchMain because otherwise the app icon keeps bouncing.
    RunLoop.current.run()
} else {
    TrustTunnel_CLI_System_Extension_ManagerApp.main()
}
