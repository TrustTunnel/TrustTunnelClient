import Foundation
import VpnClientFramework
import os

public class Logger {
    public enum LogLevel: Int {
        case error = 0
        case warn = 1
        case info = 2
        case debug = 3
        case trace = 4
    }

    public typealias Callback = (LogLevel, String) -> Void

    private let category: String
    private let logger: os.Logger

    private static let callbackGuard = NSLock()
    private static var callback: Callback?

    public init(category: String) {
        self.category = category
        logger = os.Logger(subsystem: "com.adguard.TrustTunnel.TrustTunnelClient", category: category)
    }

    public func info(_ message: String) {
        if Self.dispatch(.info, message: Self.formatMessage(category: category, message: message)) {
            return
        }

        logger.notice("\(message, privacy: .public)")
    }

    public func warn(_ message: String) {
        if Self.dispatch(.warn, message: Self.formatMessage(category: category, message: message)) {
            return
        }

        logger.warning("\(message, privacy: .public)")
    }

    public func error(_ message: String) {
        if Self.dispatch(.error, message: Self.formatMessage(category: category, message: message)) {
            return
        }

        logger.error("\(message, privacy: .public)")
    }

    public func debug(_ message: String) {
        if Self.dispatch(.debug, message: Self.formatMessage(category: category, message: message)) {
            return
        }

        logger.debug("\(message, privacy: .public)")
    }

    /// Set the logging callback for both TrustTunnelClient and VpnClientFramework logs.
    ///
    /// Call this as early as possible if you want to capture initialization logs.
    /// In particular, subclasses of AGPacketTunnelProvider should call it from their initializer,
    /// and applications should set it before creating VpnManager if they expect to see logs emitted there.
    public static func setCallback(_ callback: Callback?) {
        callbackGuard.lock()
        self.callback = callback
        callbackGuard.unlock()

        let bridgedCallback = callback.map { clientCallback in
            { (logLevel: VpnClientFramework.LogLevel, message: String) in
                clientCallback(LogLevel(vpnClientLogLevel: logLevel), message)
            }
        }

        VpnClientFramework.NativeLogger.setCallback(bridgedCallback)
    }

    static func dispatch(_ logLevel: LogLevel, message: String) -> Bool {
        callbackGuard.lock()
        let callback = self.callback
        callbackGuard.unlock()

        guard let callback else {
            return false
        }

        callback(logLevel, message)
        return true
    }

    private static func formatMessage(category: String, message: String) -> String {
        return "\(category) \(message)"
    }
}

private extension Logger.LogLevel {
    init(vpnClientLogLevel: VpnClientFramework.LogLevel) {
        self = Logger.LogLevel(rawValue: vpnClientLogLevel.rawValue) ?? .info
    }
}
