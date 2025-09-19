//
//  VpnConfig.swift
//  trusttunnel
//
//  Created by Andrey Yakushin on 13.08.2025.
//

internal import TOMLDecoder

internal struct TunConfig: Codable {
    let mtu_size: Int
    let included_routes: [String]
    let excluded_routes: [String]
}

private struct TunnelConfig: Codable {
    struct Listener: Codable {
        let tun: TunConfig
    }
    let listener: Listener
}

internal func parseTunnelConfig(from config: String) throws -> TunConfig {
    let decoder = TOMLDecoder()
    return try decoder.decode(TunnelConfig.self, from: config).listener.tun
}
