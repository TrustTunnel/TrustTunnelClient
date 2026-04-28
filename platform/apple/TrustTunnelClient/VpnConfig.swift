internal import TOMLDecoder

internal struct TunConfig: Codable {
    let mtu_size: Int
    let included_routes: [String]
    let excluded_routes: [String]
}

internal struct Endpoint: Codable {
    let addresses: [String]
    let dns_upstreams: [String]?
    let name: String
}

internal struct VpnConfig: Codable {
    struct Listener: Codable {
        let tun: TunConfig
    }
    let listener: Listener
    let endpoint: Endpoint
    let killswitch_enabled: Bool
}

internal func parseVpnConfig(from config: String) throws -> VpnConfig {
    let decoder = TOMLDecoder()
    return try decoder.decode(VpnConfig.self, from: config)
}
