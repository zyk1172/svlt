import Foundation

public enum FileRecordStoreError: Error, Equatable, Sendable {
    case invalidID
    case invalidVersion
    case symlinkRejected
    case versionAlreadyExists
    case noVersions
    case verificationFailed
    case latestVersionCorrupt(version: Int)
}

public struct FileRecordStore: RecordStore, RecordListing, RecordDeleting, Sendable {
    private let baseDirectory: URL

    private static let privateDirectoryPermissions: NSNumber = 0o700
    private static let privateFilePermissions: NSNumber = 0o600

    public init(baseDirectory: URL) {
        self.baseDirectory = baseDirectory
    }

    private var fileManager: FileManager {
        .default
    }

    public func save(_ record: EncryptedRecord) async throws {
        try validate(id: record.id)
        guard record.recordVersion > 0 else {
            throw FileRecordStoreError.invalidVersion
        }

        let directory = recordDirectory(id: record.id)
        try createDirectoryRejectingSymlinks(directory)

        let finalURL = versionURL(id: record.id, version: record.recordVersion)
        guard !fileManager.fileExists(atPath: finalURL.path) else {
            throw FileRecordStoreError.versionAlreadyExists
        }

        let temporaryURL = directory.appendingPathComponent(".\(UUID().uuidString).tmp")

        do {
            let encoded = try Self.encode(record)
            try encoded.write(to: temporaryURL, options: [.atomic])
            try rejectSymlink(at: temporaryURL)
            try setPrivateFilePermissions(at: temporaryURL)

            let verified = try Self.decode(Data(contentsOf: temporaryURL))
            guard verified == record else {
                throw FileRecordStoreError.verificationFailed
            }

            try fileManager.moveItem(at: temporaryURL, to: finalURL)
            try rejectSymlink(at: finalURL)
            try setPrivateFilePermissions(at: finalURL)
        } catch {
            try? fileManager.removeItem(at: temporaryURL)
            throw error
        }
    }

    public func latest(id: String) async throws -> EncryptedRecord {
        let discoveredVersions = try discoveredVersionNumbers(id: id)
        guard let latestVersion = discoveredVersions.last else {
            throw FileRecordStoreError.noVersions
        }

        do {
            return try loadValidRecord(id: id, version: latestVersion)
        } catch FileRecordStoreError.symlinkRejected {
            throw FileRecordStoreError.symlinkRejected
        } catch {
            throw FileRecordStoreError.latestVersionCorrupt(version: latestVersion)
        }
    }

    public func versions(id: String) async throws -> [Int] {
        let discoveredVersions = try discoveredVersionNumbers(id: id)

        return discoveredVersions.filter { version in
            (try? loadValidRecord(id: id, version: version)) != nil
        }
    }

    public func recordIDs() async throws -> [String] {
        let directory = recordsDirectory()
        guard fileManager.fileExists(atPath: directory.path) else {
            return []
        }
        try rejectSymlink(at: directory)

        let contents = try fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey],
            options: [.skipsSubdirectoryDescendants]
        )

        return try contents.compactMap { url in
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true,
                  values.isSymbolicLink != true
            else {
                return nil
            }

            let id = url.lastPathComponent
            return (try? SecretReference("secret://\(id)")).map(\.id)
        }
        .sorted()
    }

    public func delete(id: String) async throws {
        try validate(id: id)
        let directory = recordDirectory(id: id)
        guard fileManager.fileExists(atPath: directory.path) else {
            return
        }
        try rejectSymlink(at: directory)
        let values = try directory.resourceValues(forKeys: [.isDirectoryKey])
        guard values.isDirectory == true else {
            throw FileRecordStoreError.symlinkRejected
        }
        try fileManager.removeItem(at: directory)
    }

    private func discoveredVersionNumbers(id: String) throws -> [Int] {
        try validate(id: id)
        let directory = recordDirectory(id: id)
        guard fileManager.fileExists(atPath: directory.path) else {
            return []
        }
        try rejectSymlink(at: directory)

        let contents = try fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsSubdirectoryDescendants]
        )

        return contents.compactMap(Self.versionNumber(from:)).sorted()
    }

    private func loadValidRecord(id: String, version: Int) throws -> EncryptedRecord {
        let url = versionURL(id: id, version: version)
        try rejectSymlink(at: url)

        let values = try url.resourceValues(forKeys: [.isRegularFileKey])
        guard values.isRegularFile == true else {
            throw FileRecordStoreError.verificationFailed
        }

        let record = try Self.decode(Data(contentsOf: url))
        guard record.id == id, record.recordVersion == version else {
            throw FileRecordStoreError.verificationFailed
        }

        return record
    }

    private func validate(id: String) throws {
        guard (try? SecretReference("secret://\(id)")).map(\.id) == id else {
            throw FileRecordStoreError.invalidID
        }
    }

    private func recordDirectory(id: String) -> URL {
        recordsDirectory()
            .appendingPathComponent(id, isDirectory: true)
    }

    private func recordsDirectory() -> URL {
        baseDirectory
            .appendingPathComponent(".agent-secret-vault", isDirectory: true)
            .appendingPathComponent("records", isDirectory: true)
    }

    private func versionURL(id: String, version: Int) -> URL {
        recordDirectory(id: id)
            .appendingPathComponent(Self.versionFileName(version: version))
    }

    private func createDirectoryRejectingSymlinks(_ directory: URL) throws {
        let sidecarDirectory = baseDirectory
            .appendingPathComponent(".agent-secret-vault", isDirectory: true)
        let recordsDirectory = sidecarDirectory
            .appendingPathComponent("records", isDirectory: true)

        try createSingleDirectoryRejectingSymlink(sidecarDirectory)
        try createSingleDirectoryRejectingSymlink(recordsDirectory)
        try createSingleDirectoryRejectingSymlink(directory)
    }

    private func createSingleDirectoryRejectingSymlink(_ directory: URL) throws {
        if fileManager.fileExists(atPath: directory.path) {
            try rejectSymlink(at: directory)

            let values = try directory.resourceValues(forKeys: [.isDirectoryKey])
            guard values.isDirectory == true else {
                throw CocoaError(.fileWriteFileExists)
            }
            try setPrivateDirectoryPermissions(at: directory)
        } else {
            try fileManager.createDirectory(
                at: directory,
                withIntermediateDirectories: false,
                attributes: [.posixPermissions: Self.privateDirectoryPermissions]
            )
            try rejectSymlink(at: directory)
            try setPrivateDirectoryPermissions(at: directory)
        }
    }

    private func setPrivateDirectoryPermissions(at url: URL) throws {
        try fileManager.setAttributes(
            [.posixPermissions: Self.privateDirectoryPermissions],
            ofItemAtPath: url.path
        )
    }

    private func setPrivateFilePermissions(at url: URL) throws {
        try fileManager.setAttributes(
            [.posixPermissions: Self.privateFilePermissions],
            ofItemAtPath: url.path
        )
    }

    private func rejectSymlink(at url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            throw FileRecordStoreError.symlinkRejected
        }
    }

    private static func versionFileName(version: Int) -> String {
        String(format: "%08d.json", version)
    }

    private static func versionNumber(from url: URL) -> Int? {
        let name = url.lastPathComponent
        guard name.count == 13,
              name.hasSuffix(".json")
        else {
            return nil
        }

        let prefix = String(name.prefix(8))
        guard prefix.allSatisfy(\.isNumber) else {
            return nil
        }

        return Int(prefix)
    }

    private static func encode(_ record: EncryptedRecord) throws -> Data {
        try makeEncoder().encode(record)
    }

    private static func decode(_ data: Data) throws -> EncryptedRecord {
        try makeDecoder().decode(EncryptedRecord.self, from: data)
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(date.timeIntervalSinceReferenceDate.bitPattern)
        }
        return encoder
    }

    private static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let bitPattern = try container.decode(UInt64.self)
            return Date(timeIntervalSinceReferenceDate: Double(bitPattern: bitPattern))
        }
        return decoder
    }
}
