import os

class Logger {
    private let logger: os.Logger

    init(category: String) {
        logger = os.Logger(subsystem: "com.adguard.TrustTunnel.TrustTunnelClient", category: category)
    }

    func info(_ message: String) {
        logger.notice("\(message, privacy: .public)")
    }

    func warn(_ message: String) {
        logger.warning("\(message, privacy: .public)")
    }

    func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }

    func debug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }
}
