import Foundation
import VpnClientFramework
import os

final class SystemLogger {
    private let logger: os.Logger

    init(category: String) {
        logger = os.Logger(subsystem: "com.adguard.TrustTunnel.TrustTunnelClient", category: category)
    }

    func info(_ message: String) {
        if Logger.dispatch(.info, message: message) {
            return
        }

        logger.notice("\(message, privacy: .public)")
    }

    func warn(_ message: String) {
        if Logger.dispatch(.warn, message: message) {
            return
        }

        logger.warning("\(message, privacy: .public)")
    }

    func error(_ message: String) {
        if Logger.dispatch(.error, message: message) {
            return
        }

        logger.error("\(message, privacy: .public)")
    }

    func debug(_ message: String) {
        if Logger.dispatch(.debug, message: message) {
            return
        }

        logger.debug("\(message, privacy: .public)")
    }
}

public final class Logger {
    public enum LogLevel: Int {
        case error = 0
        case warn = 1
        case info = 2
        case debug = 3
        case trace = 4
    }

    public typealias Callback = (LogLevel, String) -> Void

    private static let callbackGuard = NSLock()
    private static var callback: Callback?

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
}

private extension Logger.LogLevel {
    init(vpnClientLogLevel: VpnClientFramework.LogLevel) {
        self = Logger.LogLevel(rawValue: vpnClientLogLevel.rawValue) ?? .info
    }
}
