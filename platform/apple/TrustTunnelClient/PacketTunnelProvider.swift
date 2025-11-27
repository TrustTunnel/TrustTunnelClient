import NetworkExtension
import VpnClientFramework
import Darwin.C

enum TunnelError : Error {
    case parse_config_failed;
    case create_failed;
    case start_failed;
}

open class AGPacketTunnelProvider: NEPacketTunnelProvider {
    private let clientQueue = DispatchQueue(label: "packet.tunnel.queue", qos: .userInitiated)
    private var vpnClient: VpnClient? = nil
    private var bundleIdentifier = ""
    private var appGroup: String = ""
    private var startProcessed = false
    private let logger = Logger(category: "PacketTunnel")

    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping ((any Error)?) -> Void) {
        self.startProcessed = false
        var config: String?
        if let configuration = protocolConfiguration as? NETunnelProviderProtocol {
            if let conf = configuration.providerConfiguration?["config"] as? String {
                config = conf
            }
            let appGroup = configuration.providerConfiguration?["appGroup"] as? String
            let bundleIdentifier = configuration.providerConfiguration?["bundleIdentifier"] as? String
            if (appGroup != nil && bundleIdentifier != nil && !appGroup!.isEmpty && !bundleIdentifier!.isEmpty) {
                self.appGroup = appGroup!
                self.bundleIdentifier = bundleIdentifier!
            } else {
                logger.warn("Query log processing is disabled because either application group or bundle identifier are not provided")
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
                self.vpnClient = VpnClient(
                    config: config!,
                    connectionInfoHandler: { [weak self] info in
                        if self != nil && !self!.appGroup.isEmpty && !self!.bundleIdentifier.isEmpty {
                            self!.processConnectionInfo(json: info)
                        }
                    },
                    stateChangeHandler: { state in
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
                )
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

    private func processConnectionInfo(json: String) {
        logger.debug("Connection info is being processed!: (\(json))")
        var fileURL: URL? {
                return FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: appGroup
                )?.appendingPathComponent(ConnectionInfoParams.fileName)
            }
        guard let fileURL else {
            logger.warn("Failed to get an url for connection info file")
            return
        }
        let fileCoordinator = NSFileCoordinator()
        var coordinatorError: NSError?
        var result = true
        fileCoordinator.coordinate(writingItemAt: fileURL, options: .forReplacing, error: &coordinatorError) { (writeUrl) in
            guard PrefixedLenProto.append(fileUrl: writeUrl, record: json) else {
                logger.warn("Failed to append connection info to file")
                result = false
                return
            }
        }
        if let coordinatorError = coordinatorError {
            logger.warn("Failed to coordinate file access: \(coordinatorError)")
            return
        }
        if result {
            self.notifyAppOnConnectionInfo()
        }
    }
    func notifyAppOnConnectionInfo() {
        let notification_title = "\(bundleIdentifier).\(ConnectionInfoParams.notificationName)"
        let notificationName = CFNotificationName(notification_title as CFString)

        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            notificationName,
            nil, nil, true
        )
        logger.debug("notifyAppOnConnectionInfo done")
    }
}
