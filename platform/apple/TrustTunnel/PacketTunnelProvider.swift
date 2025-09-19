//
//  PacketTunnelProvider.swift
//  Network Extension MacOS
//
//  Created by Andrey Yakushin on 28.07.2025.
//

import NetworkExtension
import VpnClientFramework

enum TunnelError : Error {
    case parse_config_failed;
    case create_failed;
    case start_failed;
}

open class AGPacketTunnelProvider: NEPacketTunnelProvider {
    private let clientQueue = DispatchQueue(label: "packet.tunnel.queue", qos: .userInitiated)
    private var vpnClient: VpnClient? = nil

    open override func startTunnel(options: [String : NSObject]? = nil) async throws {
        var config: String?
        if let configuration = protocolConfiguration as? NETunnelProviderProtocol {
            if let conf = configuration.providerConfiguration?["config"] as? String {
                config = conf
            }
        }
        if (config == nil) {
            throw TunnelError.parse_config_failed
        }
        var tunConfig: TunConfig!
        
        do {
            tunConfig = try parseTunnelConfig(from: config!)
        } catch {
            throw TunnelError.parse_config_failed
        }
        
        let (ipv4Settings, ipv6Settings) = configureIPv4AndIPv6Settings(from: tunConfig)
        // Set `tunnelRemoteAddress` to a placeholder because it is not principal
        // and there could be multiple endpoint addresses in a real config
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        networkSettings.ipv4Settings = ipv4Settings
        networkSettings.ipv6Settings = ipv6Settings
        let dnsSettings =
                NEDNSSettings(servers: ["94.140.14.140", "94.140.14.141"])
        networkSettings.dnsSettings = dnsSettings
        networkSettings.mtu = NSNumber(value: tunConfig.mtu_size)
        try await setTunnelNetworkSettings(networkSettings)
        
        try self.clientQueue.sync {
            self.vpnClient = VpnClient(config: config!)
            if (self.vpnClient == nil) {
                throw TunnelError.create_failed
            }
            if (!self.vpnClient!.start(self.packetFlow)) {
                throw TunnelError.start_failed
            }
        }
    }
    
    open override func stopTunnel(with reason: NEProviderStopReason) async {
        self.clientQueue.sync {
            if (self.vpnClient != nil) {
                self.vpnClient!.stop()
                self.vpnClient = nil
            }
        }
    }
    
    open override func handleAppMessage(_ messageData: Data) async -> Data {
        // Add code here to handle the message.
        return messageData
    }
    
    open override func sleep() async {
        self.clientQueue.async {
            if (self.vpnClient != nil) {
                self.vpnClient!.notify_sleep()
            }
        }
    }
    
    open override func wake() {
        self.clientQueue.async {
            if (self.vpnClient != nil) {
                self.vpnClient!.notify_wake()
            }
        }
    }
}
