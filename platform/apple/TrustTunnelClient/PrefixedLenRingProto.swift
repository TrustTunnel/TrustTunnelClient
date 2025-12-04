import Foundation

internal class PrefixedLenRingProto {
    private static let RecordPrefix: UInt8 = 0xfe
    typealias RecordLength = UInt32
    static let maxRecords: Int = 500
    static let maxContentSize: Int = 1024
    static let recordSize = maxContentSize + MemoryLayout<UInt8>.size + MemoryLayout<RecordLength>.size
    static let headerSize = MemoryLayout<BufferHeader>.size
    private static let logger = Logger(category: "PrefixedLenProto")

    struct BufferHeader {
        // Current next write position (0 to 499)
        var writeIndex: UInt32
        // Total valid records in the buffer (0 to 500)
        var count: UInt32
    }

    public static func append(fileUrl: URL, record: String) -> Bool {
        guard let recordData = record.data(using: .utf8),
              recordData.count < maxContentSize else {
            logger.warn("Can't write data to file: record too long")
            return false
        }
        let length = RecordLength(recordData.count)
        let lengthData = withUnsafeBytes(of: length.littleEndian) { Data($0) }
        do {
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: fileUrl.path) {
                logger.info("Creating a file for ring buffer at \(fileUrl.path)")
                let totalSize = headerSize + recordSize * maxRecords
                let emptyData = Data(count: totalSize)
                if !fileManager.createFile(atPath: fileUrl.path, contents: emptyData, attributes: nil) {
                    logger.warn("Failed to create file for connection info")
                    return false
                }
            }
            let fileHandle = try FileHandle(forUpdating: fileUrl)
            fileHandle.seek(toFileOffset: 0)

            let headerData = fileHandle.readData(ofLength: headerSize)
            var header = headerData.toStruct(type: BufferHeader.self) ?? BufferHeader(writeIndex: 0, count: 0)

            let recordOffset = UInt64(headerSize + (Int(header.writeIndex) * recordSize))
            fileHandle.seek(toFileOffset: recordOffset)

            fileHandle.write(Data([RecordPrefix]))
            fileHandle.write(lengthData)
            fileHandle.write(recordData)
            header.writeIndex = (header.writeIndex + 1) % UInt32(maxRecords)
            header.count = min(header.count + 1, UInt32(maxRecords))

            fileHandle.seek(toFileOffset: 0)
            fileHandle.write(header.toData())

            try fileHandle.close()
            return true
        } catch {
            logger.warn("Failed to append connection info to file: \(error)")
            return false
        }
    }

    public static func read_all(fileUrl: URL, startIndex: UInt32?) -> ([String]?, UInt32) {
        var result: [String] = []
        let prefixSize = MemoryLayout<UInt8>.size
        let lengthSize = MemoryLayout<RecordLength>.size
        do {
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: fileUrl.path) {
                return ([], 0)
            }
            let fileHandle = try FileHandle(forReadingFrom: fileUrl)

            let headerData = fileHandle.readData(ofLength: headerSize)
            guard let header = headerData.toStruct(type: BufferHeader.self), header.count > 0 else { return (nil, 0) }
            let isFull = (header.count == maxRecords)
            // `writeIndex` is the next record to write.
            // So it is the last written record if file is full
            let start = startIndex ?? (isFull ? header.writeIndex : 0)
            // Process all records if there is no `startIndex` and only
            // remaining if it is present
            let count: UInt32
            if (start <= header.writeIndex) {
                count = header.writeIndex - start
            } else {
                if start >= maxRecords {
                    logger.warn("Requested index to start is too big. Got \(start), max is \(maxRecords)")
                    // Try to recover and return writeIndex
                    return ([], header.writeIndex)
                }
                count = (UInt32(maxRecords) - start) + header.writeIndex
            }

            for i in 0..<count {
                let index = (start + i) % UInt32(maxRecords)
                let recordOffset = UInt64(headerSize + (Int(index) * recordSize))
                fileHandle.seek(toFileOffset: recordOffset)
                let prefixData = fileHandle.readData(ofLength: prefixSize)
                let prefix = prefixData.withUnsafeBytes { $0.load(as: UInt8.self) }
                guard prefix == RecordPrefix else {
                    logger.warn("Data corruption detected at offset \(recordOffset). Invalid Magic Byte (\(prefix)). Stopping.")
                    return (nil,0)
                }
                let lengthData = fileHandle.readData(ofLength: lengthSize)
                let length = lengthData.withUnsafeBytes { $0.load(as: RecordLength.self).littleEndian }
                if length <= 0 || length > maxContentSize {
                    logger.warn("Failed to read content, invalid length (\(length)) at offset \(recordOffset).");
                    return (nil, 0)
                }
                let recordData = fileHandle.readData(ofLength: Int(length))
                if let record = String(data: recordData, encoding: .utf8) {
                    result.append(record)
                }
            }
            logger.debug("Successfully decoded \(result.count) records.")
            return (result, header.writeIndex)
        } catch {
            logger.warn("File read/decode failed: \(error)")
            return (nil, 0)
        }
    }

    public static func clear(fileUrl: URL) -> Void {
        logger.info("Deleting file for ring buffer: \(fileUrl.path)")
        do {
            let fileManager = FileManager.default
            if fileManager.fileExists(atPath: fileUrl.path) {
                try FileManager.default.removeItem(at: fileUrl)
            }
        } catch {
            logger.warn("Failed to delete file: \(error)")
        }
    }
}

extension Data {
    func toStruct<T>(type: T.Type) -> T? {
        guard count >= MemoryLayout<T>.size else { return nil }
        return withUnsafeBytes { $0.load(as: T.self) }
    }
}

extension PrefixedLenRingProto.BufferHeader {
    func toData() -> Data {
        var header = self
        return Data(bytes: &header, count: MemoryLayout<PrefixedLenRingProto.BufferHeader>.size)
    }
}
