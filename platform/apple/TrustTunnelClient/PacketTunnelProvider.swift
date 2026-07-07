import NetworkExtension
import VpnClientFramework
import Darwin.C

enum TunnelError : Error {
    case parse_config_failed;
    case create_failed;
    case start_failed;
}

/// Logs emitted by this base class respect Logger.setCallback.
/// A `FileLogger` is installed automatically inside `startTunnel`, so subclass
/// `init` logs are not captured to file unless the subclass calls
/// `Logger.setCallback` in its initializer.
open class AGPacketTunnelProvider: NEPacketTunnelProvider {
    private let clientQueue = DispatchQueue(label: "packet.tunnel.queue", qos: .userInitiated)
    private var vpnClient: VpnClient? = nil
    private var bundleIdentifier = ""
    private var appGroup: String = ""
    private var startProcessed = false
    private let logger = Logger(category: "PacketTunnel")
    private var fileLogger: FileLogger?

    private let ADGUARD_DNS_SERVERS = ["46.243.231.30", "46.243.231.31", "2a10:50c0::2:ff", "2a10:50c0::1:ff"]
    private let FAKE_DNS_SERVER = ["198.18.53.53"]

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
        if !self.appGroup.isEmpty, let logsDir = FileLogger.logsDirectory(appGroup: self.appGroup) {
            let fileLog = FileLogger(directory: logsDir, baseName: FileLogger.extensionBaseName)
            fileLog.install()
            self.fileLogger = fileLog
        } else {
            self.fileLogger = nil
        }
        // Register the app's clear-logs request handler.
        if !self.bundleIdentifier.isEmpty {
            self.setupClearLogsListener()
        }
        if (config == nil) {
            completionHandler(TunnelError.parse_config_failed)
            return
        }
        var vpnConfig: VpnConfig!
        
        do {
            vpnConfig = try parseVpnConfig(from: config!)
        } catch {
            completionHandler(TunnelError.parse_config_failed)
            return
        }
        
        let tunConfig = vpnConfig.listener.tun

        let (ipv4Settings, ipv6Settings) = configureIPv4AndIPv6Settings(from: tunConfig)

        var tunnelAddress = vpnConfig.endpoint.addresses.first ?? "127.0.0.1"
        if let lastColonIndex = tunnelAddress.lastIndex(of: ":") {
            let ipPart = String(tunnelAddress[..<lastColonIndex])
            // Clean up brackets if they exist (e.g., "[2001:db8::1]" -> "2001:db8::1")
            tunnelAddress = ipPart.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        }

        if (Network.IPv4Address(tunnelAddress) == nil && Network.IPv6Address(tunnelAddress) == nil) {
            tunnelAddress = "127.0.0.1"
        }

        logger.debug("Trying to set tunnel address to \(tunnelAddress)")
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelAddress)
        networkSettings.ipv4Settings = ipv4Settings
        networkSettings.ipv6Settings = ipv6Settings
        let dnsServers = (vpnConfig.endpoint.dns_upstreams ?? []).isEmpty
            ? ADGUARD_DNS_SERVERS
            : FAKE_DNS_SERVER
        let dnsSettings = NEDNSSettings(servers: dnsServers)
        // Long story short: it provides a tunnel to filter DNS traffic in the "split" mode.
        // Read more here: https://developer.apple.com/forums/thread/35027
        dnsSettings.matchDomains = [""]
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
                            self.clientQueue.async {
                                if (!self.startProcessed) {
                                    completionHandler(nil)
                                    self.startProcessed = true
                                }
                                self.reasserting = false
                            }
                            break
                        case .waiting_for_network:
                            fallthrough
                        case .waiting_for_recovery:
                            fallthrough
                        case .recovering:
                            self.clientQueue.async {
                                self.reasserting = true
                            }
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
            self.stopClearLogsListener()
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
        self.clientQueue.async {
            self.logger.debug("Connection info is being processed!: (\(json))")
            var fileURL: URL? {
                    return FileManager.default.containerURL(
                        forSecurityApplicationGroupIdentifier: self.appGroup
                    )?.appendingPathComponent(ConnectionInfoParams.fileName)
                }
            guard let fileURL else {
                self.logger.warn("Failed to get an url for connection info file")
                return
            }
            let fileCoordinator = NSFileCoordinator()
            var coordinatorError: NSError?
            var result = true
            fileCoordinator.coordinate(writingItemAt: fileURL, options: .forReplacing, error: &coordinatorError) { (writeUrl) in
                let bridge = PersistentRingBuffer(path: writeUrl.path)
                guard bridge.appendRecord(json) else {
                    self.logger.warn("Failed to append connection info to file")
                    result = false
                    return
                }
            }
            if let coordinatorError = coordinatorError {
                self.logger.warn("Failed to coordinate file access: \(coordinatorError)")
                return
            }
            if result {
                self.notifyAppOnConnectionInfo()
            }
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

    // MARK: - Clear logs (App → Network Extension)

    /// Registers a Darwin notification observer so the app can ask a running NE
    /// to clear its own log file. Idempotent: removes any prior registration.
    private func setupClearLogsListener() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()
        let name = "\(bundleIdentifier).\(ClearLogsParams.notificationName)" as CFString

        CFNotificationCenterRemoveObserver(center, observer, CFNotificationName(name), nil)

        CFNotificationCenterAddObserver(
            center,
            observer,
            { _, observer, _, _, _ in
                guard let observer else { return }
                let provider = Unmanaged<AGPacketTunnelProvider>.fromOpaque(observer).takeUnretainedValue()
                provider.handleClearLogsNotification()
            },
            name,
            nil,
            .deliverImmediately
        )
    }

    /// No-op if not registered.
    private func stopClearLogsListener() {
        let name = "\(bundleIdentifier).\(ClearLogsParams.notificationName)" as CFString
        CFNotificationCenterRemoveObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            Unmanaged.passUnretained(self).toOpaque(),
            CFNotificationName(name),
            nil
        )
    }

    private func handleClearLogsNotification() {
        fileLogger?.clearLogs()
    }

    deinit {
        stopClearLogsListener()
    }
}
