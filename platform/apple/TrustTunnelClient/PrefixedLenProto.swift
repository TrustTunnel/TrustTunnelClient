import Foundation

internal class PrefixedLenProto {
    private static let RecordPrefix: UInt8 = 0xfe
    typealias RecordLength = UInt32
    private static let logger = Logger(category: "PrefixedLenProto")

    public static func append(fileUrl: URL, record: String) -> Bool {
        guard let recordData = record.data(using: .utf8) else { return false }
        let length = RecordLength(recordData.count)
        let lengthData = withUnsafeBytes(of: length.littleEndian) { Data($0) }
        do {
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: fileUrl.path) {
                if !fileManager.createFile(atPath: fileUrl.path, contents: nil, attributes: nil) {
                    logger.warn("Failed to create file for connection info")
                    return false
                }
            }
            let fileHandle = try FileHandle(forWritingTo: fileUrl)
            fileHandle.seekToEndOfFile()

            fileHandle.write(Data([RecordPrefix]))
            fileHandle.write(lengthData)
            fileHandle.write(recordData)

            try fileHandle.close()
            return true
        } catch {
            logger.warn("Failed to append connection info to file: \(error)")
            return false
        }
    }

    public static func read_all(fileUrl: URL) -> [String]? {
        var result: [String] = []
        let prefixSize = MemoryLayout<UInt8>.size
        let lengthSize = MemoryLayout<RecordLength>.size
        do {
            let fileManager = FileManager.default
            if !fileManager.fileExists(atPath: fileUrl.path) {
                return []
            }
            let fileData = try Data(contentsOf: fileUrl)
            var cursor = 0

            while cursor < fileData.count {
                guard cursor + prefixSize + lengthSize <= fileData.count else {
                    logger.warn("Reached end of file before fully decoding a record.")
                    return nil
                }

                let prefixData = fileData.subdata(in: cursor..<(cursor + prefixSize))
                let prefix = prefixData.withUnsafeBytes { $0.load(as: UInt8.self) }
                cursor += prefixSize

                guard prefix == RecordPrefix else {
                    logger.warn("Data corruption detected at offset \(cursor - prefixSize). Invalid Magic Byte (\(prefix)). Stopping.")
                    return nil
                }

                let lengthData = fileData.subdata(in: cursor..<(cursor + lengthSize))
                let length = lengthData.withUnsafeBytes { $0.load(as: RecordLength.self).littleEndian }
                cursor += lengthSize

                guard cursor + Int(length) <= fileData.count else {
                    logger.warn("Data corruption detected at offset \(cursor). Record length (\(length)) exceeds file size.")
                    return nil
                }

                let recordData = fileData.subdata(in: cursor..<(cursor + Int(length)))
                cursor += Int(length)

                if let record = String(data: recordData, encoding: .utf8) {
                    result.append(record)
                }
            }
            logger.debug("Successfully decoded \(result.count) records.")
            return result
        } catch {
            logger.warn("File read/decode failed: \(error)")
            return nil
        }
    }

    public static func clear(fileUrl: URL) -> Void {
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
