import Foundation
import VpnClientFramework
import os

/// A rotating file logger that installs itself as the global `Logger` callback.
///
/// Once `install()` is called, all log messages from both the Swift `Logger`
/// and the native C++ layer (via `VpnClientFramework.NativeLogger`) converge
/// into `<directory>/<baseName>.log`. When the file exceeds `maxFileSize`
/// bytes, it is rotated to `<baseName>.1.log` (overwriting any prior archive)
/// and a fresh file is started.
///
/// Total disk budget ≈ `maxFileSize * (archiveCount + 1)`.
///
/// There is exactly one writer per file (a single `FileLogger` per process).
/// Writes are lock-free appends; rotation and `snapshot(...)` are
/// coordinated via `NSFileCoordinator` for cross-process safety.
///
/// Reading (snapshotting) is done through the **static** `snapshot(...)` method
/// keyed by `directory + baseName`, so the same code path serves both the
/// current process's own files and another process's files.
///
public final class FileLogger {
    // MARK: - Base-name constants
    public static let appBaseName = "app"
    public static let extensionBaseName = "extension"
    private let directory: URL
    private let baseName: String
    private let maxFileSize: Int
    private let archiveCount: Int

    private let queue = DispatchQueue(label: "com.adguard.FileLogger", qos: .utility)
    private var fileHandle: FileHandle?
    private var currentSize: Int = 0

    private static let fallbackLogger = os.Logger(subsystem: "com.adguard.TrustTunnel.TrustTunnelClient",
                                                  category: "FileLogger")

    // MARK: - Public API

    /// Create a logger that writes to `directory` with the given `baseName`.
    /// The directory is created if it does not exist.
    public init(directory: URL, baseName: String, maxFileSize: Int = 2_500_000, archiveCount: Int = 1) {
        self.directory = directory
        self.baseName = baseName
        self.maxFileSize = maxFileSize
        self.archiveCount = archiveCount
        queue.async { self.openOrCreateFile() }
    }

    deinit {
        queue.sync { self.closeFile() }
    }

    /// Register this logger as the global log sink.
    ///
    /// Call this once, **before** any log-producing work begins (e.g., in the
    /// initializer of `VpnManager` or inside `startTunnel` before creating
    /// the `VpnClient`), to capture as much output as possible.
    public func install() {
        Logger.setCallback { [weak self] level, message in
            self?.write(level: level, message: message)
        }
    }

    /// Produce point-in-time copies of the `<baseName>.log` family in
    /// `directory` into `destDir`, without needing a live `FileLogger`
    /// instance for them.
    ///
    /// This is the **single** snapshot entry point, used for BOTH the current
    /// process's own files and another process's files. The caller specifies
    /// the `directory` (normally the shared App Group `logs/` directory) and
    /// `baseName` (`"app"` or `"extension"`). The copy is read-only — the
    /// source files are never opened for writing.
    ///
    /// Returns the URLs of successfully copied files. Files that do not exist
    /// (e.g. a process that never ran) or cannot be copied (e.g. a file
    /// rotated away mid-copy) are silently skipped rather than failing the
    /// export.
    public static func snapshot(directory: URL, baseName: String, archiveCount: Int = 1, into destDir: URL) -> [URL] {
        var result: [URL] = []
        let fileManager = FileManager.default
        let fileCoordinator = NSFileCoordinator(filePresenter: nil)

        let candidates = (0 ... archiveCount).map { idx -> URL in
            idx == 0
                ? directory.appendingPathComponent("\(baseName).log")
                : directory.appendingPathComponent("\(baseName).\(idx).log")
        }

        for source in candidates {
            let dest = destDir.appendingPathComponent(source.lastPathComponent)
            var coordinatorError: NSError?

            fileCoordinator.coordinate(readingItemAt: source,
                                       options: .withoutChanges,
                                       error: &coordinatorError)
            { (actualSource) in
                do {
                    try fileManager.copyItem(at: actualSource, to: dest)
                    result.append(dest)
                } catch {
                    // File may have been rotated away between listing and copy – skip.
                }
            }

            if let error = coordinatorError {
                Self.fallbackLogger.debug("FileLogger snapshot skipped \(source.lastPathComponent): \(error.localizedDescription)")
            }
        }

        return result
    }

    /// Resolve the `logs/` directory inside the App Group container.
    ///
    /// Returns `nil` if the app group identifier yields no container URL.
    public static func logsDirectory(appGroup: String) -> URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent("logs", isDirectory: true)
    }

    // MARK: - Private implementation

    private func write(level: Logger.LogLevel, message: String) {
        queue.async { [weak self] in
            guard let self else { return }
            self.appendLine(level: level, message: message)
        }
    }

    private func appendLine(level: Logger.LogLevel, message: String) {
        guard let handle = fileHandle else { return }

        let timestamp = Self.now()
        let levelTag = Self.tag(for: level)
        let line = "\(timestamp) [\(levelTag)] \(message)\n"

        guard let data = line.data(using: .utf8) else { return }

        do {
            try handle.write(contentsOf: data)
            currentSize += data.count

            if currentSize >= maxFileSize {
                rotate()
            }
        } catch {
            // Write failed — nothing actionable; could log to os_log but skip
            // to avoid infinite recursion.
        }
    }

    private func rotate() {
        closeFile()

        let fileManager = FileManager.default
        let fileCoordinator = NSFileCoordinator(filePresenter: nil)

        // Shift archives: base.(n).log → base.(n+1).log, oldest dropped
        // We only keep archiveCount archives, so start from the oldest.
        for idx in (1 ..< archiveCount).reversed() {
            let src = directory.appendingPathComponent("\(baseName).\(idx).log")
            let dst = directory.appendingPathComponent("\(baseName).\(idx + 1).log")
            coordinateMove(from: src, to: dst, coordinator: fileCoordinator)
        }

        // Rotate current → .1.log (overwrite)
        let current = directory.appendingPathComponent("\(baseName).log")
        let archived = directory.appendingPathComponent("\(baseName).1.log")
        coordinateMove(from: current, to: archived, coordinator: fileCoordinator)

        openOrCreateFile()
    }

    private func coordinateMove(from src: URL, to dst: URL, coordinator: NSFileCoordinator) {
        var coordinatorError: NSError?
        coordinator.coordinate(writingItemAt: src,
                               options: .forMoving,
                               writingItemAt: dst,
                               options: .forReplacing,
                               error: &coordinatorError)
        { (actualSrc, actualDst) in
            try? FileManager.default.moveItem(at: actualSrc, to: actualDst)
        }
        if let error = coordinatorError {
            Self.fallbackLogger.debug("FileLogger coordinateMove failed for \(src.lastPathComponent): \(error.localizedDescription)")
        }
    }

    private func openOrCreateFile() {
        let fileManager = FileManager.default

        // Ensure directory exists
        try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)

        let url = directory.appendingPathComponent("\(baseName).log")

        if !fileManager.fileExists(atPath: url.path) {
            fileManager.createFile(atPath: url.path, contents: nil)
        }

        do {
            let handle = try FileHandle(forWritingTo: url)
            handle.seekToEndOfFile()
            self.fileHandle = handle
            currentSize = Int(handle.offsetInFile)
        } catch {
            self.fileHandle = nil
            currentSize = 0
        }
    }

    private func closeFile() {
        try? fileHandle?.close()
        fileHandle = nil
        currentSize = 0
    }

    // MARK: - Formatting helpers

    private static let dateFormatter: ISO8601DateFormatter = {
        let df = ISO8601DateFormatter()
        df.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return df
    }()

    private static func now() -> String {
        dateFormatter.string(from: Date())
    }

    private static func tag(for level: Logger.LogLevel) -> String {
        switch level {
        case .error: return "ERROR"
        case .warn: return "WARN"
        case .info: return "INFO"
        case .debug: return "DEBUG"
        case .trace: return "TRACE"
        }
    }
}
