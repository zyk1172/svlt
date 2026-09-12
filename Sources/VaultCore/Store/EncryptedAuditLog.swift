import CryptoKit
import Foundation
import Security

public enum EncryptedAuditLogError: Error, Equatable, Sendable {
    case integrityFailed
    case randomGenerationFailed
    case auditKeyUnavailable
}

public struct EncryptedAuditLog: Sendable {
    private static let legacyAuditEventAssociatedData = Data("AgentSecretVault.AuditEvent.v1".utf8)
    private static let authenticatedAuditEventMetadataVersion = 2
    private static let recentIndexMetadataVersion = 1
    private static let recentIndexCapacity = 128
    private static let recentIndexFileName = "recent-index.json"
    private static let recentIndexAssociatedData = Data("AgentSecretVault.AuditRecentIndex.v1".utf8)

    private let directoryURL: URL
    private let auditKeyProvider: (@Sendable () async throws -> SymmetricKey)?
    private let now: @Sendable () -> Date
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        directoryURL: URL,
        auditKeyProvider: (@Sendable () async throws -> SymmetricKey)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.directoryURL = directoryURL
        self.auditKeyProvider = auditKeyProvider
        self.now = now

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        self.encoder = encoder
        decoder = JSONDecoder()
    }

    /// Production path. The supplied key is independent from the vault
    /// master key and is loaded without `.userPresence`, so status requests
    /// cannot trigger a vault unlock.
    public func append(_ event: AuditEvent) async throws {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try await append(event, auditKey: auditKeyProvider())
    }

    /// Compatibility path for explicit audit export/migration callers that
    /// already hold a master key. VaultAppServices never calls this to record
    /// routine activity.
    public func append(_ event: AuditEvent, masterKey: SymmetricKey) async throws {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        try await append(event, auditKey: auditKey)
    }

    public func export() async throws -> [AuditEvent] {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        let key = try await auditKeyProvider()
        return try export(auditKey: key)
    }

    public func export(masterKey: SymmetricKey) async throws -> [AuditEvent] {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        return try export(auditKey: auditKey)
    }

    /// Returns only the bounded recent window used by the local App. Full
    /// audit export remains unavailable on the App-control protocol.
    public func recent(limit: Int = 100) async throws -> [AuditEvent] {
        try await recentWithDiagnostics(limit: limit).events
    }

    /// Returns the bounded recent window together with diagnostics captured by
    /// the last full integrity scan plus failures encountered in the indexed
    /// window. Historical records are not re-read on every recent query.
    public func recentWithDiagnostics(limit: Int = 100) async throws -> AuditReadResult {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try prepareDirectory()
        let key = try await auditKeyProvider()
        return try recent(limit: limit, auditKey: key)
    }

    public func recent(limit: Int = 100, masterKey: SymmetricKey) async throws -> [AuditEvent] {
        try await recentWithDiagnostics(limit: limit, masterKey: masterKey).events
    }

    public func recentWithDiagnostics(limit: Int = 100, masterKey: SymmetricKey) async throws -> AuditReadResult {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        return try recent(limit: limit, auditKey: auditKey)
    }

    /// Performs the intentionally expensive full-history integrity pass and
    /// refreshes the authenticated recent index used by bounded App reads.
    public func integrityDiagnostics() async throws -> AuditReadDiagnostics {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try prepareDirectory()
        let key = try await auditKeyProvider()
        return try integrityDiagnostics(auditKey: key)
    }

    public func integrityDiagnostics(masterKey: SymmetricKey) async throws -> AuditReadDiagnostics {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        return try integrityDiagnostics(auditKey: auditKey)
    }

    /// Production retention path using the independent audit key.
    public func prune(retentionDays: Int) async throws {
        guard let auditKeyProvider else {
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
        try prepareDirectory()
        let key = try await auditKeyProvider()
        try prune(retentionDays: retentionDays, auditKey: key)
    }

    public func prune(retentionDays: Int, masterKey: SymmetricKey) async throws {
        try prepareDirectory()
        let auditKey = try auditDataKey(masterKey: masterKey)
        try prune(retentionDays: retentionDays, auditKey: auditKey)
    }

    private func append(_ event: AuditEvent, auditKey: SymmetricKey) async throws {
        try prepareDirectory()
        let eventData = try encoder.encode(event)
        let recordID = UUID().uuidString
        let createdAt = now()
        let sealed = try AES.GCM.seal(
            eventData,
            using: auditKey,
            authenticating: Self.authenticatedAuditEventAssociatedData(
                id: recordID,
                createdAt: createdAt
            )
        )
        let record = EncryptedAuditEventRecord(
            id: recordID,
            createdAt: createdAt,
            metadataVersion: Self.authenticatedAuditEventMetadataVersion,
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        let url = directoryURL.appending(path: "\(record.id).audit.json")
        try encoder.encode(record).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )

        // The index is derivative. A failed index update must never turn a
        // successfully persisted audit event into an append failure. A later
        // recent read detects a stale record count and rebuilds it safely.
        try? updateRecentIndexAfterAppend(
            fileName: url.lastPathComponent,
            event: event,
            auditKey: auditKey
        )
    }

    private func export(auditKey: SymmetricKey) throws -> [AuditEvent] {
        try prepareDirectory()
        let records = try eventRecords()
        let events = try records.map { _, record in
            try open(record, using: auditKey)
        }
        return events.sorted { $0.timestamp < $1.timestamp }
    }

    private func recent(limit: Int, auditKey: SymmetricKey) throws -> AuditReadResult {
        let boundedLimit = min(max(limit, 1), 100)
        let urls = try auditEventURLs()

        if let index = try? readRecentIndex(using: auditKey),
           index.totalRecordCount == urls.count {
            let result = readRecentWindow(
                from: index,
                limit: boundedLimit,
                auditKey: auditKey
            )
            let expectedCount = min(boundedLimit, index.healthyRecordCount)
            if result.events.count == expectedCount {
                return result
            }
        }

        return try rebuildRecentIndex(
            limit: boundedLimit,
            auditKey: auditKey,
            urls: urls
        )
    }

    private func integrityDiagnostics(auditKey: SymmetricKey) throws -> AuditReadDiagnostics {
        let urls = try auditEventURLs()
        return try rebuildRecentIndex(
            limit: 100,
            auditKey: auditKey,
            urls: urls
        ).diagnostics
    }

    private func prune(retentionDays: Int, auditKey: SymmetricKey) throws {
        let cutoff = now().addingTimeInterval(-Double(retentionDays) * 24 * 60 * 60)

        for (url, record) in try eventRecords() {
            let event = try open(record, using: auditKey)
            if event.timestamp < cutoff {
                try FileManager.default.removeItem(at: url)
            }
        }

        let urls = try auditEventURLs()
        _ = try rebuildRecentIndex(limit: 100, auditKey: auditKey, urls: urls)
    }

    private func rebuildRecentIndex(
        limit: Int,
        auditKey: SymmetricKey,
        urls: [URL]
    ) throws -> AuditReadResult {
        let scan = try scanAllAuditEvents(auditKey: auditKey, urls: urls)
        let sorted = scan.events.sorted(by: Self.isNewerAuditEvent)
        let index = AuditRecentIndex(
            metadataVersion: Self.recentIndexMetadataVersion,
            totalRecordCount: urls.count,
            healthyRecordCount: sorted.count,
            diagnostics: scan.diagnostics,
            entries: sorted.prefix(Self.recentIndexCapacity).map {
                AuditRecentIndexEntry(
                    fileName: $0.fileName,
                    eventTimestamp: $0.event.timestamp
                )
            }
        )
        try? writeRecentIndex(index, using: auditKey)

        return AuditReadResult(
            events: Array(sorted.prefix(limit).map(\.event)),
            diagnostics: scan.diagnostics
        )
    }

    private func scanAllAuditEvents(
        auditKey: SymmetricKey,
        urls: [URL]
    ) throws -> AuditScanResult {
        let recordResult = try readEventRecords(urls: urls)
        var accumulator = AuditDiagnosticAccumulator(recordResult.diagnostics)
        var events: [ScannedAuditEvent] = []

        for (url, record) in recordResult.records {
            do {
                events.append(ScannedAuditEvent(
                    fileName: url.lastPathComponent,
                    event: try open(record, using: auditKey)
                ))
            } catch let error as AuditRecordOpenFailure {
                accumulator.record(error)
            } catch {
                accumulator.recordUnknownFailure()
            }
        }

        return AuditScanResult(events: events, diagnostics: accumulator.value)
    }

    private func readRecentWindow(
        from index: AuditRecentIndex,
        limit: Int,
        auditKey: SymmetricKey
    ) -> AuditReadResult {
        let targetCount = min(limit, index.healthyRecordCount)
        var events: [AuditEvent] = []
        var accumulator = AuditDiagnosticAccumulator(index.diagnostics)

        for entry in index.entries {
            guard events.count < targetCount else { break }
            guard Self.isValidAuditFileName(entry.fileName) else {
                accumulator.recordUnknownFailure()
                continue
            }

            let url = directoryURL.appending(path: entry.fileName)
            let record: EncryptedAuditEventRecord
            do {
                record = try decoder.decode(
                    EncryptedAuditEventRecord.self,
                    from: Data(contentsOf: url)
                )
            } catch {
                accumulator.recordDecodeFailure()
                continue
            }

            guard Self.isSupportedMetadataVersion(record.metadataVersion) else {
                accumulator.recordUnsupportedMetadataVersion()
                continue
            }

            do {
                let event = try open(record, using: auditKey)
                guard event.timestamp == entry.eventTimestamp else {
                    accumulator.recordUnknownFailure()
                    continue
                }
                events.append(event)
            } catch let error as AuditRecordOpenFailure {
                accumulator.record(error)
            } catch {
                accumulator.recordUnknownFailure()
            }
        }

        return AuditReadResult(events: events, diagnostics: accumulator.value)
    }

    private func updateRecentIndexAfterAppend(
        fileName: String,
        event: AuditEvent,
        auditKey: SymmetricKey
    ) throws {
        guard var index = try? readRecentIndex(using: auditKey) else {
            return
        }

        index = AuditRecentIndex(
            metadataVersion: index.metadataVersion,
            totalRecordCount: index.totalRecordCount + 1,
            healthyRecordCount: index.healthyRecordCount + 1,
            diagnostics: index.diagnostics,
            entries: Array(
                (index.entries + [AuditRecentIndexEntry(
                    fileName: fileName,
                    eventTimestamp: event.timestamp
                )])
                .sorted(by: Self.isNewerIndexEntry)
                .prefix(Self.recentIndexCapacity)
            )
        )
        try writeRecentIndex(index, using: auditKey)
    }

    private func readRecentIndex(using auditKey: SymmetricKey) throws -> AuditRecentIndex {
        let url = directoryURL.appending(path: Self.recentIndexFileName)
        let envelope = try decoder.decode(
            AuditRecentIndexEnvelope.self,
            from: Data(contentsOf: url)
        )
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: envelope.ciphertext,
            tag: envelope.tag
        )
        let plaintext = try AES.GCM.open(
            box,
            using: auditKey,
            authenticating: Self.recentIndexAssociatedData
        )
        let index = try decoder.decode(AuditRecentIndex.self, from: plaintext)

        guard index.metadataVersion == Self.recentIndexMetadataVersion,
              index.totalRecordCount >= 0,
              index.healthyRecordCount >= 0,
              index.entries.count <= Self.recentIndexCapacity,
              index.healthyRecordCount >= index.entries.count,
              index.healthyRecordCount + index.diagnostics.skippedRecordCount == index.totalRecordCount,
              Set(index.entries.map(\.fileName)).count == index.entries.count,
              index.entries.allSatisfy({ Self.isValidAuditFileName($0.fileName) })
        else {
            throw EncryptedAuditLogError.integrityFailed
        }

        return index
    }

    private func writeRecentIndex(_ index: AuditRecentIndex, using auditKey: SymmetricKey) throws {
        let plaintext = try encoder.encode(index)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: auditKey,
            authenticating: Self.recentIndexAssociatedData
        )
        let envelope = AuditRecentIndexEnvelope(
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        let url = directoryURL.appending(path: Self.recentIndexFileName)
        try encoder.encode(envelope).write(to: url, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func prepareDirectory() throws {
        try FileManager.default.createDirectory(
            at: directoryURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: directoryURL.path
        )
    }

    private func auditDataKey(masterKey: SymmetricKey) throws -> SymmetricKey {
        let keyURL = directoryURL.appending(path: "audit-key.json")
        if FileManager.default.fileExists(atPath: keyURL.path) {
            let record = try decoder.decode(
                WrappedAuditDataKey.self,
                from: Data(contentsOf: keyURL)
            )
            return SymmetricKey(data: try open(record, masterKey: masterKey))
        }

        let keyData = try randomBytes(count: 32)
        let sealed = try AES.GCM.seal(
            keyData,
            using: masterKey,
            authenticating: Data("AgentSecretVault.AuditDataKey.v1".utf8)
        )
        let record = WrappedAuditDataKey(
            ciphertext: sealed.ciphertext,
            nonce: sealed.nonce.data,
            tag: sealed.tag
        )
        try encoder.encode(record).write(to: keyURL, options: [.atomic])
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: keyURL.path
        )
        return SymmetricKey(data: keyData)
    }

    private func eventRecords() throws -> [(URL, EncryptedAuditEventRecord)] {
        let result = try readEventRecords(urls: auditEventURLs())
        guard !result.diagnostics.hasIssues else {
            throw EncryptedAuditLogError.integrityFailed
        }
        return result.records.sorted { lhs, rhs in
            lhs.1.createdAt < rhs.1.createdAt
        }
    }

    private func auditEventURLs() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(
            at: directoryURL,
            includingPropertiesForKeys: nil
        )
        .filter { $0.lastPathComponent.hasSuffix(".audit.json") }
    }

    private func readEventRecords(urls: [URL]) throws -> AuditRecordReadResult {
        var records: [(URL, EncryptedAuditEventRecord)] = []
        var unreadableRecordCount = 0
        var unsupportedMetadataVersionCount = 0
        for url in urls {
            do {
                let record = try decoder.decode(
                    EncryptedAuditEventRecord.self,
                    from: Data(contentsOf: url)
                )
                guard Self.isSupportedMetadataVersion(record.metadataVersion) else {
                    unsupportedMetadataVersionCount += 1
                    continue
                }
                records.append((url, record))
            } catch {
                unreadableRecordCount += 1
            }
        }
        return AuditRecordReadResult(
            records: records,
            diagnostics: AuditReadDiagnostics(
                recordDecodeFailureCount: unreadableRecordCount,
                unsupportedMetadataVersionCount: unsupportedMetadataVersionCount
            )
        )
    }

    private func open(_ record: EncryptedAuditEventRecord, using auditKey: SymmetricKey) throws -> AuditEvent {
        let associatedData: Data
        switch record.metadataVersion {
        case 1:
            associatedData = Self.legacyAuditEventAssociatedData
        case Self.authenticatedAuditEventMetadataVersion:
            associatedData = Self.authenticatedAuditEventAssociatedData(
                id: record.id,
                createdAt: record.createdAt
            )
        default:
            throw AuditRecordOpenFailure.unsupportedMetadataVersion
        }

        let data: Data
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )
            data = try AES.GCM.open(
                box,
                using: auditKey,
                authenticating: associatedData
            )
        } catch {
            throw AuditRecordOpenFailure.authenticationFailure
        }

        do {
            return try decoder.decode(AuditEvent.self, from: data)
        } catch {
            if record.metadataVersion == 1 {
                throw AuditRecordOpenFailure.legacyCompatibilityFailure
            }
            throw AuditRecordOpenFailure.eventDecodeFailure
        }
    }

    private static func isSupportedMetadataVersion(_ version: Int) -> Bool {
        version == 1 || version == authenticatedAuditEventMetadataVersion
    }

    private func open(_ record: WrappedAuditDataKey, masterKey: SymmetricKey) throws -> Data {
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )
            return try AES.GCM.open(
                box,
                using: masterKey,
                authenticating: Data("AgentSecretVault.AuditDataKey.v1".utf8)
            )
        } catch {
            throw EncryptedAuditLogError.integrityFailed
        }
    }

    private func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw EncryptedAuditLogError.randomGenerationFailed
        }
        return Data(bytes)
    }

    private static func authenticatedAuditEventAssociatedData(id: String, createdAt: Date) -> Data {
        var data = Data("AgentSecretVault.AuditEvent.v2\n".utf8)
        data.append(contentsOf: id.utf8)
        data.append(0)
        data.append(contentsOf: createdAt.timeIntervalSince1970.description.utf8)
        return data
    }

    private static func isNewerAuditEvent(_ lhs: ScannedAuditEvent, _ rhs: ScannedAuditEvent) -> Bool {
        if lhs.event.timestamp != rhs.event.timestamp {
            return lhs.event.timestamp > rhs.event.timestamp
        }
        return lhs.fileName < rhs.fileName
    }

    private static func isNewerIndexEntry(_ lhs: AuditRecentIndexEntry, _ rhs: AuditRecentIndexEntry) -> Bool {
        if lhs.eventTimestamp != rhs.eventTimestamp {
            return lhs.eventTimestamp > rhs.eventTimestamp
        }
        return lhs.fileName < rhs.fileName
    }

    private static func isValidAuditFileName(_ name: String) -> Bool {
        !name.isEmpty &&
            name.count <= 255 &&
            name.hasSuffix(".audit.json") &&
            !name.contains("/") &&
            !name.contains("\\") &&
            URL(fileURLWithPath: name).lastPathComponent == name
    }
}

private struct WrappedAuditDataKey: Codable, Sendable {
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}

private struct EncryptedAuditEventRecord: Codable, Sendable {
    let id: String
    let createdAt: Date
    let metadataVersion: Int
    let ciphertext: Data
    let nonce: Data
    let tag: Data

    init(
        id: String,
        createdAt: Date,
        metadataVersion: Int = 2,
        ciphertext: Data,
        nonce: Data,
        tag: Data
    ) {
        self.id = id
        self.createdAt = createdAt
        self.metadataVersion = metadataVersion
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case createdAt
        case metadataVersion
        case ciphertext
        case nonce
        case tag
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        // Records written before metadata binding have no version field and
        // remain readable with the legacy event associated data.
        metadataVersion = try container.decodeIfPresent(Int.self, forKey: .metadataVersion) ?? 1
        ciphertext = try container.decode(Data.self, forKey: .ciphertext)
        nonce = try container.decode(Data.self, forKey: .nonce)
        tag = try container.decode(Data.self, forKey: .tag)
    }
}

private struct AuditRecentIndexEnvelope: Codable, Sendable {
    let ciphertext: Data
    let nonce: Data
    let tag: Data
}

private struct AuditRecentIndex: Codable, Sendable {
    let metadataVersion: Int
    let totalRecordCount: Int
    let healthyRecordCount: Int
    let diagnostics: AuditReadDiagnostics
    let entries: [AuditRecentIndexEntry]
}

private struct AuditRecentIndexEntry: Codable, Sendable {
    let fileName: String
    let eventTimestamp: Date
}

private struct ScannedAuditEvent: Sendable {
    let fileName: String
    let event: AuditEvent
}

private struct AuditScanResult: Sendable {
    let events: [ScannedAuditEvent]
    let diagnostics: AuditReadDiagnostics
}

private struct AuditRecordReadResult: Sendable {
    let records: [(URL, EncryptedAuditEventRecord)]
    let diagnostics: AuditReadDiagnostics
}

private struct AuditDiagnosticAccumulator {
    var recordDecodeFailureCount: Int
    var authenticationFailureCount: Int
    var eventDecodeFailureCount: Int
    var unsupportedMetadataVersionCount: Int
    var legacyCompatibilityFailureCount: Int

    init(_ diagnostics: AuditReadDiagnostics = .none) {
        recordDecodeFailureCount = diagnostics.recordDecodeFailureCount
        authenticationFailureCount = diagnostics.authenticationFailureCount
        eventDecodeFailureCount = diagnostics.eventDecodeFailureCount
        unsupportedMetadataVersionCount = diagnostics.unsupportedMetadataVersionCount
        legacyCompatibilityFailureCount = diagnostics.legacyCompatibilityFailureCount
    }

    mutating func record(_ error: AuditRecordOpenFailure) {
        switch error {
        case .authenticationFailure:
            authenticationFailureCount += 1
        case .eventDecodeFailure:
            eventDecodeFailureCount += 1
        case .unsupportedMetadataVersion:
            unsupportedMetadataVersionCount += 1
        case .legacyCompatibilityFailure:
            legacyCompatibilityFailureCount += 1
        }
    }

    mutating func recordDecodeFailure() {
        recordDecodeFailureCount += 1
    }

    mutating func recordUnsupportedMetadataVersion() {
        unsupportedMetadataVersionCount += 1
    }

    mutating func recordUnknownFailure() {
        authenticationFailureCount += 1
    }

    var value: AuditReadDiagnostics {
        AuditReadDiagnostics(
            recordDecodeFailureCount: recordDecodeFailureCount,
            authenticationFailureCount: authenticationFailureCount,
            eventDecodeFailureCount: eventDecodeFailureCount,
            unsupportedMetadataVersionCount: unsupportedMetadataVersionCount,
            legacyCompatibilityFailureCount: legacyCompatibilityFailureCount
        )
    }
}

private enum AuditRecordOpenFailure: Error {
    case authenticationFailure
    case eventDecodeFailure
    case unsupportedMetadataVersion
    case legacyCompatibilityFailure
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}
