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
    private var startProcessed = false

    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping ((any Error)?) -> Void) {
        self.startProcessed = false
        var config: String?
        if let configuration = protocolConfiguration as? NETunnelProviderProtocol {
            if let conf = configuration.providerConfiguration?["config"] as? String {
                config = conf
            }
        }
        if (config == nil) {
            completionHandler(TunnelError.parse_config_failed)
            return
        }
        var tunConfig: TunConfig!
        
        do {
            tunConfig = try parseTunnelConfig(from: config!)
        } catch {
            completionHandler(TunnelError.parse_config_failed)
            return
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
        setTunnelNetworkSettings(networkSettings) { error in
            if let error = error {
                completionHandler(error)
                return
            }

            self.clientQueue.async {
                self.vpnClient = VpnClient(config: config!) { state in
                    switch (VpnState(rawValue: Int(state))) {
                    case .disconnected:
                        self.clientQueue.async {
                            self.stopVpnClient()
                            if (!self.startProcessed) {
                                completionHandler(TunnelError.start_failed)
                                self.startProcessed = true
                            } else {
                                self.cancelTunnelWithError(nil)
                            }
                        }
                        break
                    case .connected:
                        if (!self.startProcessed) {
                            completionHandler(nil)
                            self.startProcessed = true
                        }
                        self.reasserting = false
                        break
                    case .waiting_for_recovery:
                        fallthrough
                    case .recovering:
                        self.reasserting = true
                        break
                    default:
                        break
                    }
                }
                if (self.vpnClient == nil) {
                    completionHandler(TunnelError.create_failed)
                    return
                }
                if (!self.vpnClient!.start(self.packetFlow)) {
                    completionHandler(TunnelError.start_failed)
                    return
                }
            }
        }
    }
    
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        self.clientQueue.async {
            self.stopVpnClient()
            completionHandler()
        }
    }
    
    open override func handleAppMessage(_ messageData: Data) async -> Data {
        // Add code here to handle the message.
        return messageData
    }
    
    open override func sleep(completionHandler: @escaping () -> Void) {
        self.clientQueue.async {
            if (self.vpnClient != nil) {
                self.vpnClient!.notify_sleep()
            }
            completionHandler()
        }
    }
    
    open override func wake() {
        self.clientQueue.async {
            if (self.vpnClient != nil) {
                self.vpnClient!.notify_wake()
            }
        }
    }

    private func stopVpnClient() {
        if (self.vpnClient != nil) {
            self.vpnClient!.stop()
            self.vpnClient = nil
        }
    }
}
