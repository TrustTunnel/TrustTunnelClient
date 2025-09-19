//
//  Utils.swift
//  trusttunnel
//
//  Created by Andrey Yakushin on 13.08.2025.
//

import NetworkExtension

func configureIPv4AndIPv6Settings(from config: TunConfig) -> (NEIPv4Settings, NEIPv6Settings) {
    let ipv4Settings = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.0"])
    let ipv6Settings = NEIPv6Settings(addresses: ["fd00::1"], networkPrefixLengths: [64])

    
    func parseCIDR(_ cidr: String) -> (ip: String, prefixLength: Int)? {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2,
              let prefixLength = Int(parts[1]) else { return nil }
        return (String(parts[0]), prefixLength)
    }
    
    func isIPv6Address(_ ip: String) -> Bool {
        ip.contains(":")
    }
    
    var v4Included: [NEIPv4Route] = []
    var v4Excluded: [NEIPv4Route] = []
    var v6Included: [NEIPv6Route] = []
    var v6Excluded: [NEIPv6Route] = []
    
    for route in config.included_routes {
        guard let (ip, prefix) = parseCIDR(route) else { continue }
        if isIPv6Address(ip) {
            v6Included.append(NEIPv6Route(destinationAddress: ip, networkPrefixLength: NSNumber(value: prefix)))
        } else {
            let mask = ipv4PrefixLengthToMask(prefix)
            v4Included.append(NEIPv4Route(destinationAddress: ip, subnetMask: mask))
        }
    }
    
    for route in config.excluded_routes {
        guard let (ip, prefix) = parseCIDR(route) else { continue }
        if isIPv6Address(ip) {
            v6Excluded.append(NEIPv6Route(destinationAddress: ip, networkPrefixLength: NSNumber(value: prefix)))
        } else {
            let mask = ipv4PrefixLengthToMask(prefix)
            v4Excluded.append(NEIPv4Route(destinationAddress: ip, subnetMask: mask))
        }
    }
    
    ipv4Settings.includedRoutes = v4Included
    ipv4Settings.excludedRoutes = v4Excluded
    
    ipv6Settings.includedRoutes = v6Included
    ipv6Settings.excludedRoutes = v6Excluded
    
    return (ipv4Settings, ipv6Settings)
}

private func ipv4PrefixLengthToMask(_ length: Int) -> String {
    let mask: UInt32 = length == 0 ? 0 : ~UInt32(0) << (32 - length)
    return "\(mask >> 24 & 0xff).\(mask >> 16 & 0xff).\(mask >> 8 & 0xff).\(mask & 0xff)"
}
