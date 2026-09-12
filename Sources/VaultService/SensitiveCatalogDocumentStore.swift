import CryptoKit
import Darwin
import Foundation
import VaultAuthorization
import VaultCore

private let svltPosixFileReaderMaximumBytes = 64 * 1024 * 1024
private let svltCatalogLockWaitNanoseconds: UInt64 = 1_000_000_000
private let svltCatalogLockRetryMicroseconds: useconds_t = 10_000

public enum SensitiveCatalogDocumentStoreError: Error, Equatable, Sendable {
    case noSelectedDocument
    case malformedDocument
    case legacyCatalogUnsupported
    case symlinkRejected
    case integrityMissing
    case externalModification
    case pendingExternalChange
    case formatRepairConflict
    case invalidIntegrity
    case revisionConflict
    case invalidOperation
    case referenceSetChanged
    case writeFailed
    /// A recovery journal backup failed its recorded SHA-256 check. The
    /// current Catalog is never overwritten with an unverified backup.
    case recoveryRollbackBackupInvalid
}

public enum SensitiveCatalogIntegrityStatus: String, Codable, Equatable, Sendable {
    case uninitialized
    case verified
    case legacyCatalogUnsupported = "LEGACY_CATALOG_UNSUPPORTED"
    case integrityMissing = "INTEGRITY_MISSING"
    case externalModification = "EXTERNAL_CATALOG_MODIFICATION"
    case pendingExternalChange = "PENDING_EXTERNAL_CHANGE"
    case invalid = "CATALOG_INVALID"
}

/// Accepted state is semantic. rawSHA256 is retained only as an optimistic
/// concurrency aid and is never used as the integrity/security decision.
public struct CatalogAcceptedState: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let semanticSHA256: String
    public let acceptedDocument: SecretCatalogDocument
    public let rawSHA256: String
    public let updatedAt: String

    public init(
        schemaVersion: Int = SecretCatalogDocument.currentSchemaVersion,
        revision: UInt64,
        semanticSHA256: String,
        acceptedDocument: SecretCatalogDocument,
        rawSHA256: String,
        updatedAt: String
    ) {
        self.schemaVersion = schemaVersion
        self.revision = revision
        self.semanticSHA256 = semanticSHA256
        self.acceptedDocument = acceptedDocument
        self.rawSHA256 = rawSHA256
        self.updatedAt = updatedAt
    }
}

public struct CatalogIntegrityRecord: Codable, Equatable, Sendable {
    public let acceptedState: CatalogAcceptedState
    public let hmac: String

    public init(acceptedState: CatalogAcceptedState, hmac: String) {
        self.acceptedState = acceptedState
        self.hmac = hmac
    }

    public var schemaVersion: Int { acceptedState.schemaVersion }
    public var revision: UInt64 { acceptedState.revision }
    /// Compatibility name for callers that used the old raw sidecar field.
    public var canonicalSHA256: String { acceptedState.rawSHA256 }
    public var semanticSHA256: String { acceptedState.semanticSHA256 }
    public var acceptedDocument: SecretCatalogDocument { acceptedState.acceptedDocument }
    public var rawSHA256: String { acceptedState.rawSHA256 }
    public var updatedAt: String { acceptedState.updatedAt }
}

/// Flat sidecar emitted by the PR #13 Catalog v2 implementation.  It must be
/// decoded separately because the v3 accepted-state sidecar intentionally has
/// a different schema and HMAC payload.
private struct LegacyCatalogIntegrityRecordV2: Codable, Equatable {
    let schemaVersion: Int
    let revision: UInt64
    let canonicalSHA256: String
    let hmac: String
    let updatedAt: String
}

private struct CatalogMigrationJournal: Codable, Equatable {
    enum Phase: String, Codable {
        case prepared
        case committing
        case completed
    }

    let schemaVersion: Int
    let phase: Phase
    let documentPath: String
    let integrityPath: String
    let previousIntegrityPath: String?
    let documentBackupPath: String
    let integrityBackupPath: String?
    let targetRevision: UInt64?
    let expectedDocumentSHA256: String
    let expectedIntegritySHA256: String

    init(
        phase: Phase,
        documentPath: String,
        integrityPath: String,
        previousIntegrityPath: String?,
        documentBackupPath: String,
        integrityBackupPath: String?,
        targetRevision: UInt64?,
        expectedDocumentSHA256: String,
        expectedIntegritySHA256: String
    ) {
        self.schemaVersion = 1
        self.phase = phase
        self.documentPath = documentPath
        self.integrityPath = integrityPath
        self.previousIntegrityPath = previousIntegrityPath
        self.documentBackupPath = documentBackupPath
        self.integrityBackupPath = integrityBackupPath
        self.targetRevision = targetRevision
        self.expectedDocumentSHA256 = expectedDocumentSHA256
        self.expectedIntegritySHA256 = expectedIntegritySHA256
    }

    func changingPhase(to phase: Phase) -> Self {
        Self(
            phase: phase,
            documentPath: documentPath,
            integrityPath: integrityPath,
            previousIntegrityPath: previousIntegrityPath,
            documentBackupPath: documentBackupPath,
            integrityBackupPath: integrityBackupPath,
            targetRevision: targetRevision,
            expectedDocumentSHA256: expectedDocumentSHA256,
            expectedIntegritySHA256: expectedIntegritySHA256
        )
    }
}

/// Recovery journal payload. The journal is the rollback authority, so it is
/// stored inside a domain-separated HMAC envelope (see
/// `CatalogRecoveryJournalEnvelope`). Paths only locate files; the security
/// identity of every backup is its recorded SHA-256 plus this MAC.
private struct CatalogRecoveryJournal: Codable, Equatable {
    enum Phase: String, Codable {
        case prepared
        case committing
        case completed
    }

    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let phase: Phase
    let planID: String
    let documentPath: String
    let integrityPath: String
    let documentBackupPath: String?
    let integrityBackupPath: String?
    let hadDocument: Bool
    let hadIntegrity: Bool
    /// SHA-256 of the pre-recovery document bytes captured at journal
    /// creation. Required whenever `hadDocument` is true; rollback refuses to
    /// restore unless the on-disk backup still matches.
    let originalDocumentSHA256: String?
    /// Same binding for the pre-recovery integrity sidecar bytes.
    let originalIntegritySHA256: String?
    let targetRevision: UInt64
    let expectedDocumentSHA256: String
    let expectedIntegritySHA256: String
    let createdAt: String

    init(
        phase: Phase,
        planID: String,
        documentPath: String,
        integrityPath: String,
        documentBackupPath: String?,
        integrityBackupPath: String?,
        hadDocument: Bool,
        hadIntegrity: Bool,
        originalDocumentSHA256: String?,
        originalIntegritySHA256: String?,
        targetRevision: UInt64,
        expectedDocumentSHA256: String,
        expectedIntegritySHA256: String,
        createdAt: String
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.phase = phase
        self.planID = planID
        self.documentPath = documentPath
        self.integrityPath = integrityPath
        self.documentBackupPath = documentBackupPath
        self.integrityBackupPath = integrityBackupPath
        self.hadDocument = hadDocument
        self.hadIntegrity = hadIntegrity
        self.originalDocumentSHA256 = originalDocumentSHA256
        self.originalIntegritySHA256 = originalIntegritySHA256
        self.targetRevision = targetRevision
        self.expectedDocumentSHA256 = expectedDocumentSHA256
        self.expectedIntegritySHA256 = expectedIntegritySHA256
        self.createdAt = createdAt
    }

    func changingPhase(to phase: Phase) -> Self {
        Self(
            phase: phase,
            planID: planID,
            documentPath: documentPath,
            integrityPath: integrityPath,
            documentBackupPath: documentBackupPath,
            integrityBackupPath: integrityBackupPath,
            hadDocument: hadDocument,
            hadIntegrity: hadIntegrity,
            originalDocumentSHA256: originalDocumentSHA256,
            originalIntegritySHA256: originalIntegritySHA256,
            targetRevision: targetRevision,
            expectedDocumentSHA256: expectedDocumentSHA256,
            expectedIntegritySHA256: expectedIntegritySHA256,
            createdAt: createdAt
        )
    }
}

/// Authenticated envelope around the recovery journal. Every journal write
/// recomputes the HMAC over the full payload (including the current phase),
/// and every read verifies it before the journal can drive a rollback.
private struct CatalogRecoveryJournalEnvelope: Codable {
    let journal: CatalogRecoveryJournal
    let hmac: String
}

/// Durable compensation state for secret records created before a Catalog
/// commit. It deliberately contains only opaque record IDs; plaintext is
/// never journaled or persisted by this store. This file is an authenticated
/// recovery hint, never an independent deletion authority.
private struct CatalogSecretCleanupRecord: Codable, Equatable {
    static let currentSchemaVersion = 2

    let schemaVersion: Int
    let documentIdentity: String
    let transactionID: String
    let referenceIDs: [String]
    let createdAt: String
    let hmac: String

    init(
        documentIdentity: String,
        transactionID: String,
        referenceIDs: [String],
        createdAt: String,
        hmac: String
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.documentIdentity = documentIdentity
        self.transactionID = transactionID
        self.referenceIDs = referenceIDs
        self.createdAt = createdAt
        self.hmac = hmac
    }
}

private struct CatalogSecretCleanupMACPayload: Codable {
    let schemaVersion: Int
    let documentIdentity: String
    let transactionID: String
    let referenceIDs: [String]
    let createdAt: String
}

/// Test-only fault injection is intentionally limited to the atomic commit
/// boundary. It lets the migration tests prove rollback without weakening the
/// production file-system implementation.
internal protocol CatalogAtomicWriteFaultInjecting: Sendable {
    func beforeAtomicReplace(to url: URL) throws
}

private enum CatalogFileIOStage: String {
    case readDocument = "document-read"
    case readIntegrity = "integrity-read"
    case acquireLock = "lock-acquire"
    case createTemporary = "temp-create"
    case writeTemporary = "temp-write"
    case fsyncTemporary = "temp-fsync"
    case closeTemporary = "temp-close"
    case replaceDocument = "document-replace"
    case fsyncDocumentDirectory = "document-directory-fsync"
    case replaceIntegrity = "integrity-replace"
    case fsyncIntegrityDirectory = "integrity-directory-fsync"
    case keychainIntegrity = "integrity-keychain"
    case preflightRead = "preflight-read"
    case preflightTempCreate = "preflight-temp-create"
    case preflightTempFsync = "preflight-temp-fsync"
    case preflightTempClose = "preflight-temp-close"
    case preflightRename = "preflight-rename"
    case preflightDirectoryFsync = "preflight-directory-fsync"
}

private enum CatalogIOOperation: String {
    case catalogRead = "catalog-read"
    case catalogValidate = "catalog-validate"
    case catalogMutation = "catalog-mutation"
    case catalogMigration = "catalog-migration"
    case catalogCleanup = "catalog-cleanup"
}

private enum CatalogWriteTarget: Equatable {
    case document
    case integrity
    case cleanup
    case internalState
}

private struct POSIXFileWriteError: Error {
    let stage: CatalogFileIOStage
    let status: Int32
}

/// The POSIX probes run off the Catalog actor because File Provider can block
/// directory operations. These boxes make the timeout boundary race-free and
/// ensure a late read result is freed instead of leaking or mutating a local
/// tuple after the caller has returned.
private final class CatalogDirectoryFsyncResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Int32?
    private var timedOut = false

    func complete(_ status: Int32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !timedOut else { return false }
        result = status
        return true
    }

    func resultAfterTimeout() -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        if let result { return result }
        timedOut = true
        return ETIMEDOUT
    }
}

private final class CatalogReadFileResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var result: (status: Int32, bytes: UnsafeMutableRawPointer?, length: Int)?
    private var timedOut = false

    func complete(
        status: Int32,
        bytes: UnsafeMutableRawPointer?,
        length: Int
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !timedOut else { return false }
        result = (status, bytes, length)
        return true
    }

    func resultAfterTimeout() -> (status: Int32, bytes: UnsafeMutableRawPointer?, length: Int) {
        lock.lock()
        defer { lock.unlock() }
        if let result { return result }
        timedOut = true
        return (ETIMEDOUT, nil, 0)
    }
}

/// POSIX Catalog probes may block behind a File Provider overlay. Keep them
/// off both the actor executor and the process-wide utility pool: a slow
/// provider operation must not starve unrelated Catalog reads or test/IPC
/// handlers that are waiting for their bounded result.
private enum CatalogPOSIXIO {
    // File Provider syscalls cannot always be cancelled after the caller's
    // three-second deadline. Admit only a small fixed number of probes so a
    // wedged provider cannot turn repeated health checks into an unbounded
    // backlog of blocked work items.
    static let permits = DispatchSemaphore(value: 2)
    static let queue = DispatchQueue(
        label: "com.agent-secret-vault.catalog-posix-io",
        qos: .userInitiated,
        attributes: .concurrent,
        autoreleaseFrequency: .workItem
    )
}

public struct CatalogExternalChange: Codable, Equatable, Sendable {
    public let rawSHA256: String
    public let semanticSHA256: String
    public let acceptedRevision: UInt64
    public let candidateDocument: SecretCatalogDocument
    public let semanticDiff: CatalogSemanticDiff

    public init(
        rawSHA256: String,
        semanticSHA256: String,
        acceptedRevision: UInt64,
        candidateDocument: SecretCatalogDocument,
        semanticDiff: CatalogSemanticDiff
    ) {
        self.rawSHA256 = rawSHA256
        self.semanticSHA256 = semanticSHA256
        self.acceptedRevision = acceptedRevision
        self.candidateDocument = candidateDocument
        self.semanticDiff = semanticDiff
    }
}

public struct SensitiveCatalogSnapshot: Equatable, Sendable {
    public let document: SecretCatalogDocument
    public let revision: UInt64
    public let integrity: SensitiveCatalogIntegrityStatus

    public init(document: SecretCatalogDocument, revision: UInt64, integrity: SensitiveCatalogIntegrityStatus) {
        self.document = document
        self.revision = revision
        self.integrity = integrity
    }
}

/// Persistent catalog coordinator. App/MCP and external writers share the
/// sidecar flock; external Markdown changes are reconciled by semantic diff.
public actor SensitiveCatalogDocumentStore {
    private let fileManager: FileManager
    private let keyStore: any CatalogIntegrityKeyStoring
    private let suppliedIntegrityURL: URL?
    private let suppliedIntegrityDirectoryURL: URL?
    private let atomicWriteFaultInjector: (any CatalogAtomicWriteFaultInjecting)?
    private let secretReferenceExists: (@Sendable (String) async -> Bool)?
    private var documentURL: URL?

    public init(
        documentURL: URL? = nil,
        integrityURL: URL? = nil,
        keyStore: any CatalogIntegrityKeyStoring = KeychainCatalogIntegrityKeyStore(),
        fileManager: FileManager = .default,
        secretReferenceExists: (@Sendable (String) async -> Bool)? = nil
    ) {
        self.documentURL = documentURL?.standardizedFileURL
        self.suppliedIntegrityURL = integrityURL?.standardizedFileURL
        self.suppliedIntegrityDirectoryURL = nil
        self.keyStore = keyStore
        self.fileManager = fileManager
        self.atomicWriteFaultInjector = nil
        self.secretReferenceExists = secretReferenceExists
    }

    internal init(
        documentURL: URL? = nil,
        integrityURL: URL? = nil,
        keyStore: any CatalogIntegrityKeyStoring = KeychainCatalogIntegrityKeyStore(),
        fileManager: FileManager = .default,
        atomicWriteFaultInjector: (any CatalogAtomicWriteFaultInjecting)?,
        integrityDirectoryURL: URL? = nil,
        secretReferenceExists: (@Sendable (String) async -> Bool)? = nil
    ) {
        self.documentURL = documentURL?.standardizedFileURL
        self.suppliedIntegrityURL = integrityURL?.standardizedFileURL
        self.suppliedIntegrityDirectoryURL = integrityDirectoryURL?.standardizedFileURL
        self.keyStore = keyStore
        self.fileManager = fileManager
        self.atomicWriteFaultInjector = atomicWriteFaultInjector
        self.secretReferenceExists = secretReferenceExists
    }

    public func selectDocument(at url: URL?) throws {
        if let url {
            guard url.pathExtension.lowercased() == "md" else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
            try assertSafeParent(url)
            if fileManager.fileExists(atPath: url.path) { try assertSafeFile(url) }
            documentURL = url.standardizedFileURL
        } else {
            documentURL = nil
        }
    }

    public func selectedDocumentURL() -> URL? { documentURL }

    /// Reloads the on-disk journal before compensating a failed recovery.
    /// This closes the gap where an attacker changes the journal after it was
    /// written: an HMAC failure stops rollback rather than trusting the local
    /// in-memory copy.
    private func rollbackPersistedRecoveryUnlocked(
        _ fallback: CatalogRecoveryJournal,
        journalURL: URL
    ) throws {
        if fileManager.fileExists(atPath: journalURL.path) {
            let persisted = try readRecoveryJournal(at: journalURL)
            guard persisted.planID == fallback.planID else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
            try rollbackRecoveryUnlocked(persisted)
        } else {
            // If the journal was never durably created, no persisted recovery
            // authority exists. The local prepared payload is safe to use for
            // cleaning up a transaction that has not acquired authority.
            try rollbackRecoveryUnlocked(fallback)
        }
    }

    private func writeBackupData(_ data: Data, to url: URL) throws {
        do {
            try data.write(to: url, options: [.withoutOverwriting])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            try fsyncFile(at: url)
        } catch {
            try? fileManager.removeItem(at: url)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func recoveryJournalURL() throws -> URL {
        try recoveryDirectory().appendingPathComponent("recovery-journal.json")
    }

    private func writeRecoveryJournal(_ journal: CatalogRecoveryJournal, at url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do {
            let hmac: String
            do {
                hmac = try recoveryJournalHMAC(journal)
            } catch {
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            try atomicWrite(try encoder.encode(CatalogRecoveryJournalEnvelope(journal: journal, hmac: hmac)), to: url)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    /// Domain-separated HMAC binding every authority field of the journal.
    /// Paths are bound for locating files only; the security identity is the
    /// combination of hashes plus this MAC under the Catalog integrity key.
    private func recoveryJournalHMAC(_ journal: CatalogRecoveryJournal) throws -> String {
        var payload = Data("SVLT-CATALOG-RECOVERY-JOURNAL-V1\n".utf8)
        payload.append(Data("\(journal.schemaVersion)\n\(journal.phase.rawValue)\n\(journal.planID)\n".utf8))
        payload.append(Data("\(journal.documentPath)\n\(journal.integrityPath)\n".utf8))
        payload.append(Data("\(journal.hadDocument ? (journal.originalDocumentSHA256 ?? "?") : "-")\n\(journal.hadIntegrity ? (journal.originalIntegritySHA256 ?? "?") : "-")\n".utf8))
        payload.append(Data("\(journal.expectedDocumentSHA256)\n\(journal.expectedIntegritySHA256)\n".utf8))
        payload.append(Data("\(journal.targetRevision)\n\(journal.createdAt)\n".utf8))
        let key = try keyStore.loadOrCreateKey()
        let mac = HMAC<SHA256>.authenticationCode(for: payload, using: SymmetricKey(data: key))
        return Data(mac).base64EncodedString()
    }

    private func removeRecoveryJournal(at url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else { return }
        try assertSafeFile(url)
        do {
            try fileManager.removeItem(at: url)
            try fsyncDirectory(at: url.deletingLastPathComponent())
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    /// Recovery backups are temporary transaction material. They are removed
    /// only after the completed journal is durably removed; interrupted
    /// transactions therefore retain every byte needed for rollback.
    private func removeRecoveryBackups(documentPath: String?, integrityPath: String?) {
        for path in [documentPath, integrityPath].compactMap({ $0 }) {
            let url = URL(fileURLWithPath: path).standardizedFileURL
            guard (try? assertSafeFile(url)) != nil else { continue }
            try? fileManager.removeItem(at: url)
        }
    }

    private func readRecoveryJournal(at url: URL) throws -> CatalogRecoveryJournal {
        guard fileManager.fileExists(atPath: url.path) else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
        try assertSafeFile(url)
        do {
            let envelope = try JSONDecoder().decode(
                CatalogRecoveryJournalEnvelope.self,
                from: readFileData(from: url)
            )
            // A journal is the rollback authority; an unauthenticated or
            // tampered journal must never drive a restore.
            let expectedMAC = Data(base64Encoded: envelope.hmac) ?? Data()
            let computedMAC = Data(base64Encoded: try recoveryJournalHMAC(envelope.journal)) ?? Data()
            guard !expectedMAC.isEmpty, constantTimeEqual(computedMAC, expectedMAC) else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
            try validateRecoveryJournal(envelope.journal, journalURL: url)
            return envelope.journal
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func validateRecoveryJournal(
        _ journal: CatalogRecoveryJournal,
        journalURL: URL
    ) throws {
        guard let documentURL,
              journal.schemaVersion == CatalogRecoveryJournal.currentSchemaVersion,
              !journal.planID.isEmpty,
              journalURL.standardizedFileURL.path == (try recoveryJournalURL()).standardizedFileURL.path,
              journal.documentPath == documentURL.standardizedFileURL.path,
              journal.integrityPath == (try integrityURL()).standardizedFileURL.path,
              journal.targetRevision > 0,
              !journal.expectedDocumentSHA256.isEmpty,
              !journal.expectedIntegritySHA256.isEmpty,
              journal.hadDocument == (journal.documentBackupPath != nil),
              journal.hadIntegrity == (journal.integrityBackupPath != nil),
              journal.hadDocument == (journal.originalDocumentSHA256 != nil),
              journal.hadDocument == ((journal.originalDocumentSHA256 ?? "").isEmpty == false),
              journal.hadIntegrity == (journal.originalIntegritySHA256 != nil),
              journal.hadIntegrity == ((journal.originalIntegritySHA256 ?? "").isEmpty == false)
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let directory = try recoveryDirectory()
        if let documentBackupPath = journal.documentBackupPath {
            let backup = URL(fileURLWithPath: documentBackupPath).standardizedFileURL
            guard backup.deletingLastPathComponent().standardizedFileURL.path == directory.path,
                  backup.lastPathComponent.hasPrefix("recovery-document-backup-"),
                  fileManager.fileExists(atPath: backup.path)
            else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
        }
        if let integrityBackupPath = journal.integrityBackupPath {
            let backup = URL(fileURLWithPath: integrityBackupPath).standardizedFileURL
            guard backup.deletingLastPathComponent().standardizedFileURL.path == directory.path,
                  backup.lastPathComponent.hasPrefix("recovery-integrity-backup-"),
                  fileManager.fileExists(atPath: backup.path)
            else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
        }
    }

    private func recoveryCommitMatches(_ journal: CatalogRecoveryJournal) -> Bool {
        guard let documentURL,
              fileManager.fileExists(atPath: documentURL.path),
              (try? assertSafeFile(documentURL)) != nil,
              let raw = try? readFileData(from: documentURL),
              sha256Hex(raw) == journal.expectedDocumentSHA256,
              let integrityURL = try? integrityURL(),
              fileManager.fileExists(atPath: integrityURL.path),
              (try? assertSafeFile(integrityURL)) != nil,
              let integrityData = try? readFileData(from: integrityURL),
              sha256Hex(integrityData) == journal.expectedIntegritySHA256,
              let document = try? decodeV3(raw),
              let record = try? JSONDecoder().decode(CatalogIntegrityRecord.self, from: integrityData),
              (try? verify(record)) != nil
        else {
            return false
        }
        return record.revision == journal.targetRevision
            && record.rawSHA256 == journal.expectedDocumentSHA256
            && record.acceptedDocument == document
    }

    private func rollbackRecoveryUnlocked(_ journal: CatalogRecoveryJournal) throws {
        try validateRecoveryJournal(journal, journalURL: try recoveryJournalURL())
        guard let documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }

        // Validate every backup before changing either target. This prevents
        // a tampered integrity backup from still allowing the document backup
        // to overwrite the current Catalog (and vice versa).
        let integrityBackupData: Data?
        if let integrityBackupPath = journal.integrityBackupPath {
            integrityBackupData = try readVerifiedBackupData(
                from: URL(fileURLWithPath: integrityBackupPath),
                expectedSHA256: journal.originalIntegritySHA256
            )
        } else {
            integrityBackupData = nil
        }
        let documentBackupData: Data?
        if let documentBackupPath = journal.documentBackupPath {
            documentBackupData = try readVerifiedBackupData(
                from: URL(fileURLWithPath: documentBackupPath),
                expectedSHA256: journal.originalDocumentSHA256
            )
        } else {
            documentBackupData = nil
        }

        do {
            if let integrityBackupData {
                try atomicWrite(integrityBackupData, to: try integrityURL())
            } else {
                try removeFileIfPresentUnlocked(try integrityURL())
            }
            if let documentBackupData {
                try atomicWrite(documentBackupData, to: documentURL)
            } else {
                try removeFileIfPresentUnlocked(documentURL)
            }
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        try removeRecoveryJournal(at: try recoveryJournalURL())
    }

    /// Reads a journaled backup and verifies its SHA-256 before any target is
    /// touched. The returned bytes are the exact bytes that get restored,
    /// avoiding a validation/read/restore TOCTOU window.
    private func readVerifiedBackupData(from backupURL: URL, expectedSHA256: String?) throws -> Data {
        guard let expectedSHA256, !expectedSHA256.isEmpty else {
            throw SensitiveCatalogDocumentStoreError.recoveryRollbackBackupInvalid
        }
        do {
            try assertSafeFile(backupURL)
            let data = try readFileData(from: backupURL)
            guard sha256Hex(data) == expectedSHA256 else {
                throw SensitiveCatalogDocumentStoreError.recoveryRollbackBackupInvalid
            }
            return data
        } catch let error as SensitiveCatalogDocumentStoreError {
            if error == .recoveryRollbackBackupInvalid {
                throw error
            }
            throw SensitiveCatalogDocumentStoreError.recoveryRollbackBackupInvalid
        } catch {
            throw SensitiveCatalogDocumentStoreError.recoveryRollbackBackupInvalid
        }
    }

    private func recoverInterruptedRecoveryUnlocked() throws {
        let journalURL = try recoveryJournalURL()
        guard fileManager.fileExists(atPath: journalURL.path) else { return }
        let journal = try readRecoveryJournal(at: journalURL)

        switch journal.phase {
        case .completed:
            try removeRecoveryJournal(at: journalURL)
        case .prepared, .committing:
            if recoveryCommitMatches(journal) {
                try removeRecoveryJournal(at: journalURL)
            } else {
                try rollbackRecoveryUnlocked(journal)
            }
        }
    }

    /// Runs a non-destructive probe in the selected document's parent from
    /// the process that owns this Store. The probe never opens the document
    /// for writing and never returns its path or contents.
    public func preflightFileAccess() throws -> CatalogFilePreflight {
        guard let documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        let parent = documentURL.deletingLastPathComponent().standardizedFileURL
        let read = preflightReadStatus(documentURL)
        let temporary = parent.appendingPathComponent(".svlt-write-probe-\(UUID().uuidString)")
        let renamed = parent.appendingPathComponent(".svlt-write-probe-\(UUID().uuidString)")

        var tempCreate = "PARENT_TEMP_CREATE_SKIPPED"
        var tempFsync = "PARENT_TEMP_FSYNC_SKIPPED"
        var rename = "PARENT_RENAME_SKIPPED"
        var parentFsync = "PARENT_FSYNC_SKIPPED"
        var descriptor: Int32 = -1
        var temporaryExists = false
        var renamedExists = false

        let createStatus = temporary.path.withCString { path in
            svlt_create_file(path, &descriptor)
        }
        if createStatus == 0 {
            temporaryExists = true
            tempCreate = "PARENT_TEMP_CREATE_OK"
            let fsyncStatus = svlt_fsync_file_descriptor(descriptor)
            if fsyncStatus == 0 {
                tempFsync = "PARENT_TEMP_FSYNC_OK"
            } else {
                tempFsync = preflightFailure(stage: .preflightTempFsync, errno: fsyncStatus)
            }
            let closeStatus = svlt_close_file_descriptor(descriptor)
            descriptor = -1
            if closeStatus != 0 && tempFsync == "PARENT_TEMP_FSYNC_OK" {
                tempFsync = preflightFailure(stage: .preflightTempClose, errno: closeStatus)
            }
        } else {
            tempCreate = preflightFailure(stage: .preflightTempCreate, errno: createStatus)
        }

        if temporaryExists {
            let renameStatus = temporary.path.withCString { source in
                renamed.path.withCString { destination in
                    svlt_rename_file(source, destination)
                }
            }
            if renameStatus == 0 {
                renamedExists = true
                temporaryExists = false
                rename = "PARENT_RENAME_OK"
            } else {
                rename = preflightFailure(stage: .preflightRename, errno: renameStatus)
            }
        }

        let parentFsyncStatus = directoryFsyncStatus(parent.path)
        parentFsync = parentFsyncStatus == 0
            ? "PARENT_FSYNC_OK"
            : preflightFailure(stage: .preflightDirectoryFsync, errno: parentFsyncStatus)

        if descriptor >= 0 {
            _ = svlt_close_file_descriptor(descriptor)
        }
        if temporaryExists {
            _ = temporary.path.withCString { path in svlt_unlink_file(path) }
        }
        if renamedExists {
            _ = renamed.path.withCString { path in svlt_unlink_file(path) }
        }

        return CatalogFilePreflight(
            read: read,
            parentTempCreate: tempCreate,
            parentTempFsync: tempFsync,
            parentRename: rename,
            parentFsync: parentFsync
        )
    }

    /// Records opaque secret IDs whose best-effort deletion failed while a
    /// Catalog transaction was being compensated. This state is intentionally
    /// separate from the integrity authority and can be reconciled later.
    public func recordPendingSecretCleanup(referenceIDs: [String]) throws {
        let normalized = try normalizedCleanupReferenceIDs(referenceIDs)
        guard !normalized.isEmpty else { return }
        try withCatalogLock(exclusive: true) {
            let current = try readCleanupReferenceIDsUnlocked()
            try writeCleanupReferenceIDsUnlocked(current + normalized)
        }
    }

    public func pendingSecretCleanupReferenceIDs() throws -> [String] {
        try withCatalogLock(exclusive: false) {
            try readCleanupReferenceIDsUnlocked()
        }
    }

    public func clearPendingSecretCleanup(referenceIDs: [String]) throws {
        let normalized = try normalizedCleanupReferenceIDs(referenceIDs)
        guard !normalized.isEmpty else { return }
        try withCatalogLock(exclusive: true) {
            let remaining = try readCleanupReferenceIDsUnlocked().filter { !normalized.contains($0) }
            try writeCleanupReferenceIDsUnlocked(remaining)
        }
    }

    public func snapshot() throws -> SensitiveCatalogSnapshot {
        // Reconciliation may update raw auxiliary data or accepted state.
        try withCatalogLock(exclusive: true) { try snapshotUnlocked() }
    }

    public func validate() throws -> SensitiveCatalogSnapshot { try snapshot() }

    /// Read-only Catalog validation for editor integrations. Unlike
    /// `snapshot()`, this path never reconciles accepted state, writes an
    /// integrity sidecar, creates a recovery archive, or runs the parent
    /// directory write probe. Interrupted recovery is deliberately left for
    /// the next exclusive snapshot/mutation; validation fails closed against
    /// whatever durable pair exists without mutating it.
    public func validationReport() throws -> CatalogValidationReport {
        try withCatalogLock(exclusive: false) {
            try validationReportUnlocked()
        }
    }

    /// Returns a bounded, source-safe format repair plan. The candidate bytes
    /// are recomputed inside the Store only when the user explicitly repairs.
    public func formatRepairPlan() throws -> CatalogFormatRepairPlan? {
        try withCatalogLock(exclusive: true) {
            try recoverInterruptedRecoveryUnlocked()
            guard let documentURL, fileManager.fileExists(atPath: documentURL.path) else {
                return nil
            }
            try assertSafeFile(documentURL)
            let raw = try readFileData(from: documentURL, stage: .readDocument, operation: .catalogValidate)
            guard var plan = SensitiveCatalogDocumentCodec.formatRepairPlan(raw) else {
                return nil
            }

            guard plan.canRepair else { return plan }
            guard let stateURL = try? integrityURL(), fileManager.fileExists(atPath: stateURL.path),
                  let record = try? readIntegrityRecord(at: stateURL), (try? verify(record)) != nil,
                  let candidate = try? SensitiveCatalogDocumentCodec.applyingFormatRepair(to: raw),
                  let candidateDocument = try? decodeV3(candidate),
                  candidateDocument == record.acceptedDocument
            else {
                let diagnostic = CatalogValidationDiagnostic(
                    code: "FORMAT_REPAIR_REQUIRES_ACCEPTED_STATE",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "目录没有可用于格式修复的已接受状态。",
                    hint: "先完成目录接纳或处理外部语义修改。"
                )
                plan = CatalogFormatRepairPlan(
                    id: plan.id,
                    currentRawSHA256: plan.currentRawSHA256,
                    diagnostics: plan.diagnostics + [diagnostic],
                    repairableDiagnostics: plan.repairableDiagnostics,
                    unrepairableDiagnostics: plan.unrepairableDiagnostics + [diagnostic],
                    proposedRawSHA256: plan.proposedRawSHA256,
                    semanticSHA256: plan.semanticSHA256
                )
                return plan
            }
            return plan
        }
    }

    /// Applies only a previously displayed, semantic-preserving formatting
    /// plan. The raw hash is checked again under the catalog lock before any
    /// write, so a concurrent edit produces FORMAT_REPAIR_CONFLICT.
    @discardableResult
    public func repairFormat(expectedRawSHA256: String) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            try recoverInterruptedRecoveryUnlocked()
            guard let documentURL, fileManager.fileExists(atPath: documentURL.path) else {
                throw SensitiveCatalogDocumentStoreError.noSelectedDocument
            }
            try assertSafeFile(documentURL)
            let raw = try readFileData(from: documentURL, stage: .readDocument, operation: .catalogValidate)
            guard sha256Hex(raw) == expectedRawSHA256 else {
                throw SensitiveCatalogDocumentStoreError.formatRepairConflict
            }
            guard let plan = SensitiveCatalogDocumentCodec.formatRepairPlan(raw), plan.canRepair,
                  plan.currentRawSHA256 == expectedRawSHA256,
                  let proposedSHA256 = plan.proposedRawSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let candidate = try SensitiveCatalogDocumentCodec.applyingFormatRepair(to: raw)
            guard sha256Hex(candidate) == proposedSHA256,
                  let repairedDocument = try? decodeV3(candidate)
            else {
                throw SensitiveCatalogDocumentStoreError.referenceSetChanged
            }

            let stateURL = try integrityURL()
            guard fileManager.fileExists(atPath: stateURL.path) else {
                throw SensitiveCatalogDocumentStoreError.integrityMissing
            }
            let accepted = try readIntegrityRecord(at: stateURL)
            try verify(accepted)
            guard accepted.acceptedDocument == repairedDocument,
                  referenceSet(accepted.acceptedDocument) == referenceSet(repairedDocument)
            else {
                throw SensitiveCatalogDocumentStoreError.pendingExternalChange
            }

            // Formatting-only repair keeps the semantic revision unchanged;
            // the accepted raw digest is refreshed under the same journaled
            // document/sidecar transaction.
            let updatedRecord = try makeRecord(
                document: repairedDocument,
                revision: accepted.revision,
                raw: candidate
            )
            return try commitCatalogPairWithRecoveryUnlocked(
                raw: candidate,
                document: repairedDocument,
                record: updatedRecord
            )
        }
    }

    public func integrityStatus() -> SensitiveCatalogIntegrityStatus {
        do { return try snapshot().integrity }
        catch SensitiveCatalogDocumentStoreError.legacyCatalogUnsupported { return .legacyCatalogUnsupported }
        catch SensitiveCatalogDocumentStoreError.integrityMissing { return .integrityMissing }
        catch SensitiveCatalogDocumentStoreError.pendingExternalChange { return .pendingExternalChange }
        catch SensitiveCatalogDocumentStoreError.externalModification { return .externalModification }
        catch { return .invalid }
    }

    @discardableResult
    public func canonicalWrite(_ document: SecretCatalogDocument, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try document.validate()
        return try withCatalogLock(exclusive: true) {
            let current = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            return try writeUnlocked(document, previous: current.revision, basedOn: current.document)
        }
    }

    /// Creates a brand-new canonical empty Catalog v3 at the selected URL.
    /// The target must not exist; an existing file is never overwritten. Both
    /// the Markdown and its accepted integrity state are committed inside a
    /// journaled transaction, so a failure leaves no partial files behind.
    @discardableResult
    public func createEmptyCatalog() throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try assertSafeParent(url)
            if fileManager.fileExists(atPath: url.path) {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            try recoverInterruptedRecoveryUnlocked()
            // Recovery may have restored a previously existing document. Do
            // not let a stale journal turn that recovered file into a template
            // target or let the compensation path delete it.
            guard !fileManager.fileExists(atPath: url.path) else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            let stateURL = try integrityURL()
            let hadIntegrity = fileManager.fileExists(atPath: stateURL.path)
            let raw = try SensitiveCatalogDocumentCodec.canonicalData(SecretCatalogDocument())
            let reparsed = try decodeV3(raw)
            guard reparsed == SecretCatalogDocument(), referenceSet(reparsed).isEmpty else {
                throw SensitiveCatalogDocumentStoreError.malformedDocument
            }
            let record = try makeRecord(document: reparsed, revision: 1, raw: raw)
            let integrityData = try encodedIntegrityData(record)
            var originalIntegritySHA256: String?
            var integrityBackupPath: String?
            let recoveryDirectory = try recoveryDirectory()
            if hadIntegrity {
                let backupData = try readFileData(from: stateURL)
                let backup = recoveryDirectory.appendingPathComponent("recovery-integrity-backup-\(UUID().uuidString.lowercased()).bin")
                try writeBackupData(backupData, to: backup)
                integrityBackupPath = backup.path
                originalIntegritySHA256 = sha256Hex(backupData)
            }
            let prepared = CatalogRecoveryJournal(
                phase: .prepared,
                planID: UUID().uuidString,
                documentPath: url.standardizedFileURL.path,
                integrityPath: stateURL.standardizedFileURL.path,
                documentBackupPath: nil,
                integrityBackupPath: integrityBackupPath,
                hadDocument: false,
                hadIntegrity: hadIntegrity,
                originalDocumentSHA256: nil,
                originalIntegritySHA256: originalIntegritySHA256,
                targetRevision: 1,
                expectedDocumentSHA256: sha256Hex(raw),
                expectedIntegritySHA256: sha256Hex(integrityData),
                createdAt: iso8601String(Date())
            )
            let committing = prepared.changingPhase(to: .committing)
            let journalURL = try recoveryJournalURL()
            do {
                try writeRecoveryJournal(prepared, at: journalURL)
                try writeRecoveryJournal(committing, at: journalURL)
                guard !fileManager.fileExists(atPath: url.path) else {
                    throw SensitiveCatalogDocumentStoreError.invalidOperation
                }
                try atomicWrite(raw, to: url, operation: .catalogMutation, target: .document)
                try atomicWrite(integrityData, to: stateURL, operation: .catalogMutation, target: .integrity)
                guard recoveryCommitMatches(committing) else {
                    throw SensitiveCatalogDocumentStoreError.writeFailed
                }
                try writeRecoveryJournal(committing.changingPhase(to: .completed), at: journalURL)
                try removeRecoveryJournal(at: journalURL)
                removeRecoveryBackups(documentPath: nil, integrityPath: integrityBackupPath)
                return SensitiveCatalogSnapshot(document: reparsed, revision: 1, integrity: .verified)
            } catch {
                // Failure-atomic: remove the half-created pair (or restore a
                // pre-existing sidecar) so no accepted-state remnant survives.
                do {
                    try rollbackPersistedRecoveryUnlocked(prepared, journalURL: journalURL)
                } catch let rollbackError as SensitiveCatalogDocumentStoreError {
                    throw rollbackError
                } catch {
                    throw SensitiveCatalogDocumentStoreError.writeFailed
                }
                throw error
            }
        }
    }

    @discardableResult
    public func applyBatch(_ mutation: CatalogBatchMutation, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            let current = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            let document: SecretCatalogDocument
            do { document = try mutation.applying(to: current.document) }
            catch { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return try writeUnlocked(document, previous: current.revision, basedOn: current.document)
        }
    }

    @discardableResult
    public func createIndex(title: String, aliases: [String] = [], tags: [String] = [], expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        let index = try SecretCatalogIndex.generated(title: title, aliases: aliases, tags: tags)
        return try createIndex(index, expectedRevision: expectedRevision)
    }

    @discardableResult
    public func createIndex(_ index: SecretCatalogIndex, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        return try mutate(expectedRevision: expectedRevision) { document in
            guard !document.indexes.contains(where: { $0.id == index.id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes + [index], entries: document.entries)
        }
    }

    @discardableResult
    public func updateIndex(_ index: SecretCatalogIndex, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.indexes.firstIndex(where: { $0.id == index.id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var indexes = document.indexes
            indexes[offset] = index
            return SecretCatalogDocument(indexes: indexes, entries: document.entries)
        }
    }

    @discardableResult
    public func deleteIndex(id: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.indexes.contains(where: { $0.id == id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes.filter { $0.id != id }, entries: document.entries.filter { $0.indexId != id })
        }
    }

    @discardableResult
    public func createEntry(_ entry: SecretCatalogEntry, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            do {
                return try document.insertingEntryInSourceOrder(entry)
            } catch {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
        }
    }

    @discardableResult
    public func updateEntry(_ entry: SecretCatalogEntry, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entry.id }), document.indexes.contains(where: { $0.id == entry.indexId }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries
            entries[offset] = entry
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func moveEntry(id: String, toIndexID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            do {
                return try document.movingEntryInSourceOrder(id: id, toIndexID: toIndexID)
            } catch {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
        }
    }

    @discardableResult
    public func deleteEntry(id: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard document.entries.contains(where: { $0.id == id }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return SecretCatalogDocument(indexes: document.indexes, entries: document.entries.filter { $0.id != id })
        }
    }

    @discardableResult
    public func addField(_ field: SecretCatalogFieldValue, toEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let offset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[offset]
            guard !old.fields.contains(where: { $0.key == field.key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries
            entries[offset] = replacingFields(old, old.fields + [field])
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func updateField(_ field: SecretCatalogFieldValue, inEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == field.key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var fields = old.fields; fields[fieldOffset] = field
            var entries = document.entries; entries[entryOffset] = replacingFields(old, fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func removeField(key: String, fromEntryID entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard old.fields.contains(where: { $0.key == key }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            var entries = document.entries; entries[entryOffset] = replacingFields(old, old.fields.filter { $0.key != key })
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    @discardableResult
    public func bindSecret(_ secretRef: String, toFieldKey key: String, entryID: String, expectedRevision: UInt64? = nil) throws -> SensitiveCatalogSnapshot {
        guard (try? SecretReference(secretRef)) != nil else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
        return try mutate(expectedRevision: expectedRevision) { document in
            guard let entryOffset = document.entries.firstIndex(where: { $0.id == entryID }) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let old = document.entries[entryOffset]
            guard let fieldOffset = old.fields.firstIndex(where: { $0.key == key }), old.fields[fieldOffset].type.isSecret else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let oldField = old.fields[fieldOffset]
            var fields = old.fields
            fields[fieldOffset] = SecretCatalogFieldValue(key: oldField.key, label: oldField.label, type: oldField.type, agentVisible: oldField.agentVisible, searchable: oldField.searchable, secretRef: secretRef)
            var entries = document.entries; entries[entryOffset] = replacingFields(old, fields)
            return SecretCatalogDocument(indexes: document.indexes, entries: entries)
        }
    }

    public func pendingExternalChange() throws -> CatalogExternalChange {
        try withCatalogLock(exclusive: true) {
            guard let candidate = try externalCandidateUnlocked(), candidate.semanticDiff.requiresApproval else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            return candidate
        }
    }

    @discardableResult
    public func acceptPendingExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let candidate = try externalCandidateUnlocked(), candidate.semanticDiff.requiresApproval else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            guard candidate.acceptedRevision == expectedRevision,
                  candidate.rawSHA256 == expectedRawSHA256,
                  candidate.semanticSHA256 == expectedSemanticSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            let raw = try readDocumentData()
            guard sha256Hex(raw) == expectedRawSHA256,
                  semanticDigest(candidate.candidateDocument) == expectedSemanticSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            let record = try makeRecord(document: candidate.candidateDocument, revision: candidate.acceptedRevision + 1, raw: raw)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: candidate.candidateDocument, revision: record.revision, integrity: .verified)
        }
    }

    /// Explicit v2 to v3 migration. Parsing, re-encoding, re-parsing and
    /// secret-reference equality are completed before the source is touched.
    @discardableResult
    public func adoptExternalV2() throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try recoverInterruptedV2MigrationUnlocked()
            try assertSafeFile(url)
            let raw = try readFileData(from: url)
            guard SensitiveCatalogDocumentCodec.format(raw) == .managedV2 else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let decodedV2 = try decodeV2(raw)
            let migration: SensitiveCatalogDocumentCodec.V2MigrationResult
            do {
                migration = try SensitiveCatalogDocumentCodec.migrateV2DocumentForV3WithNotes(decodedV2)
            } catch {
                // An ambiguous legacy policy-shaped index must fail closed;
                // do not silently delete business data during migration.
                throw SensitiveCatalogDocumentStoreError.malformedDocument
            }
            let document = migration.document
            let rendered = try SensitiveCatalogDocumentCodec.canonicalData(
                document,
                unmanagedMarkdown: migration.unmanagedMarkdown
            )
            let reparsed = try SensitiveCatalogDocumentCodec.decode(rendered)
            guard reparsed == document, referenceSet(document) == referenceSet(reparsed) else { throw SensitiveCatalogDocumentStoreError.referenceSetChanged }
            let stateURL = try integrityURL()
            let sourceIntegrityURL = try v2IntegritySourceURL(activeURL: stateURL)
            var legacyRevision: UInt64?
            if let sourceIntegrityURL {
                try assertSafeFile(sourceIntegrityURL)
                let legacy = try readLegacyIntegrityRecordV2(at: sourceIntegrityURL)
                try verifyLegacyIntegrityV2(legacy, data: raw)
                legacyRevision = legacy.revision
            }
            let targetRevision = try migrationRevision(after: legacyRevision)
            let record = try makeRecord(document: reparsed, revision: targetRevision, raw: rendered)
            let integrityData = try encodedIntegrityData(record)
            guard let documentBackup = try backupCurrentDocumentUnlocked() else {
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            let integrityBackup: URL?
            if let sourceIntegrityURL {
                guard let backup = try backupFileUnlocked(sourceIntegrityURL) else {
                    throw SensitiveCatalogDocumentStoreError.writeFailed
                }
                integrityBackup = backup
            } else {
                integrityBackup = nil
            }
            let journalURL = try migrationJournalURL()
            let prepared = CatalogMigrationJournal(
                phase: .prepared,
                documentPath: url.standardizedFileURL.path,
                integrityPath: stateURL.standardizedFileURL.path,
                previousIntegrityPath: sourceIntegrityURL?.standardizedFileURL.path,
                documentBackupPath: documentBackup.standardizedFileURL.path,
                integrityBackupPath: sourceIntegrityURL == nil ? nil : integrityBackup?.standardizedFileURL.path,
                targetRevision: targetRevision,
                expectedDocumentSHA256: sha256Hex(rendered),
                expectedIntegritySHA256: sha256Hex(integrityData)
            )
            let committing = prepared.changingPhase(to: .committing)

            do {
                try writeMigrationJournal(prepared, at: journalURL)
                try writeMigrationJournal(committing, at: journalURL)
                try atomicWrite(rendered, to: url)
                try atomicWrite(integrityData, to: stateURL)

                // If the process dies before the completed marker is written,
                // the next locked operation can still recognize a fully
                // committed pair by these expected hashes.
                guard migrationCommitMatches(committing) else {
                    throw SensitiveCatalogDocumentStoreError.writeFailed
                }
                if let sourceIntegrityURL, sourceIntegrityURL.standardizedFileURL != stateURL.standardizedFileURL {
                    try? removeFileIfPresentUnlocked(sourceIntegrityURL)
                }
                try writeMigrationJournal(committing.changingPhase(to: .completed), at: journalURL)
                try removeMigrationJournal(at: journalURL)
                return SensitiveCatalogSnapshot(document: reparsed, revision: targetRevision, integrity: .verified)
            } catch {
                // A failure while writing the completed marker or deleting the
                // journal must not roll back a pair that is already complete.
                if migrationCommitMatches(committing) {
                    try? removeMigrationJournal(at: journalURL)
                    return SensitiveCatalogSnapshot(document: reparsed, revision: targetRevision, integrity: .verified)
                }

                do {
                    try rollbackV2MigrationUnlocked(committing, journalURL: journalURL)
                } catch {
                    throw SensitiveCatalogDocumentStoreError.writeFailed
                }
                if let error = error as? SensitiveCatalogDocumentStoreError {
                    throw error
                }
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
        }
    }

    /// Explicit adoption for a hand-created v3 file with no accepted state.
    @discardableResult
    public func externalV3AdoptionCandidate() throws -> CatalogExternalChange {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try assertSafeFile(url)
            let raw = try readFileData(from: url)
            guard SensitiveCatalogDocumentCodec.format(raw) == .managedV3 else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let document = try decodeV3(raw)
            let stateURL = try integrityURL()
            guard !fileManager.fileExists(atPath: stateURL.path) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let baseline = SecretCatalogDocument()
            let diff = CatalogSemanticDiff.between(old: baseline, new: document)
            return CatalogExternalChange(
                rawSHA256: sha256Hex(raw),
                semanticSHA256: semanticDigest(document),
                acceptedRevision: 0,
                candidateDocument: document,
                semanticDiff: diff
            )
        }
    }

    @discardableResult
    public func adoptExternalV3(
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
            try assertSafeFile(url)
            let raw = try readFileData(from: url)
            guard SensitiveCatalogDocumentCodec.format(raw) == .managedV3 else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            let document = try decodeV3(raw)
            let stateURL = try integrityURL()
            guard !fileManager.fileExists(atPath: stateURL.path) else { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            guard sha256Hex(raw) == expectedRawSHA256,
                  semanticDigest(document) == expectedSemanticSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            let record = try makeRecord(document: document, revision: 1, raw: raw)
            try atomicWriteIntegrity(record)
            return SensitiveCatalogSnapshot(document: document, revision: 1, integrity: .verified)
        }
    }

    private func mutate(expectedRevision: UInt64?, _ transform: (SecretCatalogDocument) throws -> SecretCatalogDocument) throws -> SensitiveCatalogSnapshot {
        try withCatalogLock(exclusive: true) {
            let base = try mutationBaseUnlocked(expectedRevision: expectedRevision)
            let document: SecretCatalogDocument
            do { document = try transform(base.document); try document.validate() }
            catch let error as SensitiveCatalogDocumentStoreError { throw error }
            catch { throw SensitiveCatalogDocumentStoreError.invalidOperation }
            return try writeUnlocked(document, previous: base.revision, basedOn: base.document)
        }
    }

    private func mutationBaseUnlocked(expectedRevision: UInt64?) throws -> SensitiveCatalogSnapshot {
        let value = try snapshotUnlocked()
        if let expectedRevision, expectedRevision != value.revision { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        return value
    }

    private func validationReportUnlocked() throws -> CatalogValidationReport {
        guard let url = documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        guard fileManager.fileExists(atPath: url.path) else {
            return CatalogValidationReport(status: .notFound)
        }
        try assertSafeFile(url)

        let raw: Data
        do {
            raw = try readFileData(from: url, stage: .readDocument, operation: .catalogValidate)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        let parsed = SensitiveCatalogDocumentCodec.validateDetailed(raw)
        guard parsed.status == .found else { return parsed }

        let stateURL = try integrityURL()
        guard fileManager.fileExists(atPath: stateURL.path) else {
            return CatalogValidationReport(
                status: .integrityMissing,
                rawSHA256: parsed.rawSHA256,
                diagnostics: [CatalogValidationDiagnostic(
                    code: "INTEGRITY_MISSING",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "目录内容有效，但没有已接受的完整性状态。",
                    hint: "请在 SVLT App 中完成目录初始化或迁移。"
                )]
            )
        }

        let record: CatalogIntegrityRecord
        do {
            record = try readIntegrityRecord(at: stateURL)
            try verify(record)
        } catch let error as SensitiveCatalogDocumentStoreError {
            let diagnostic = CatalogValidationDiagnostic(
                code: "INTEGRITY_INVALID",
                line: 1,
                column: 1,
                scope: .document,
                message: "目录完整性状态验证失败。",
                hint: "请在 SVLT App 中检查完整性状态或使用 Recovery。"
            )
            switch error {
            case .integrityMissing, .invalidIntegrity, .externalModification:
                return CatalogValidationReport(
                    status: .invalidCatalog,
                    rawSHA256: parsed.rawSHA256,
                    diagnostics: [diagnostic]
                )
            default:
                throw error
            }
        }

        let document: SecretCatalogDocument
        do {
            document = try SensitiveCatalogDocumentCodec.decode(raw)
        } catch {
            return parsed
        }
        let rawSHA256 = sha256Hex(raw)
        guard document != record.acceptedDocument else {
            return CatalogValidationReport(
                status: .found,
                revision: record.revision,
                rawSHA256: rawSHA256
            )
        }

        let diff = CatalogSemanticDiff.between(old: record.acceptedDocument, new: document)
        guard diff.requiresApproval else {
            // Safe external metadata changes are deliberately reported as
            // syntactically valid. Accepted-state reconciliation remains in
            // the App/store mutation path, not in this validator.
            return CatalogValidationReport(
                status: .found,
                revision: record.revision,
                rawSHA256: rawSHA256
            )
        }
        let semanticSHA256 = semanticDigest(document)
        return CatalogValidationReport(
            status: .pendingExternalChange,
            revision: record.revision,
            rawSHA256: rawSHA256,
            pendingExternalChange: CatalogPendingExternalChange(
                acceptedRevision: record.revision,
                rawSHA256: rawSHA256,
                semanticSHA256: semanticSHA256
            ),
            diagnostics: [CatalogValidationDiagnostic(
                code: "PENDING_EXTERNAL_CHANGE",
                line: 1,
                column: 1,
                scope: .document,
                message: "目录存在尚未批准的高风险外部修改。",
                hint: "请在 SVLT App 中查看语义差异并完成独立审批。"
            )]
        )
    }

    private func snapshotUnlocked() throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try recoverInterruptedRecoveryUnlocked()
        try recoverInterruptedV2MigrationUnlocked()
        guard fileManager.fileExists(atPath: url.path) else {
            return SensitiveCatalogSnapshot(document: SecretCatalogDocument(), revision: 0, integrity: .uninitialized)
        }
        try assertSafeFile(url)
        let raw = try readFileData(from: url)
        switch SensitiveCatalogDocumentCodec.format(raw) {
        case .managedV2:
            // A valid v2 document is an explicit migration candidate. Do not
            // collapse it into the unsupported legacy-v1 state, otherwise the
            // App cannot offer the backup-and-migrate path.
            _ = try decodeV2(raw)
            throw SensitiveCatalogDocumentStoreError.integrityMissing
        case .legacy, .unmanaged:
            throw SensitiveCatalogDocumentStoreError.legacyCatalogUnsupported
        case .managedV3:
            break
        }
        let candidate = try decodeV3(raw)
        let stateURL = try integrityURL()
        try migrateLegacyV3IntegrityIfMatching(
            candidate: candidate,
            raw: raw,
            activeURL: stateURL
        )
        try migrateRenamedV3IntegrityIfMatching(
            candidate: candidate,
            raw: raw,
            activeURL: stateURL
        )
        guard fileManager.fileExists(atPath: stateURL.path) else {
            // A hand-created v3 document containing only ordinary metadata is
            // safe to initialize without rewriting the user's Markdown. A
            // document that introduces opaque references still needs the
            // explicit local App adoption path because it has no accepted
            // baseline against which to classify the binding.
            guard referenceSet(candidate).isEmpty else {
                throw SensitiveCatalogDocumentStoreError.integrityMissing
            }
            let initialized = try makeRecord(document: candidate, revision: 1, raw: raw)
            try atomicWriteIntegrity(initialized)
            return SensitiveCatalogSnapshot(document: candidate, revision: 1, integrity: .verified)
        }
        let record = try readIntegrityRecord()
        try verify(record)
        let diff = CatalogSemanticDiff.between(old: record.acceptedDocument, new: candidate)
        if diff.requiresApproval {
            throw SensitiveCatalogDocumentStoreError.pendingExternalChange
        }
        if candidate != record.acceptedDocument || record.rawSHA256 != sha256Hex(raw) {
            let revision = candidate == record.acceptedDocument ? record.revision : record.revision + 1
            let updated = try makeRecord(document: candidate, revision: revision, raw: raw)
            try atomicWriteIntegrity(updated)
            return SensitiveCatalogSnapshot(document: candidate, revision: revision, integrity: .verified)
        }
        return SensitiveCatalogSnapshot(document: candidate, revision: record.revision, integrity: .verified)
    }

    private func externalCandidateUnlocked() throws -> CatalogExternalChange? {
        guard let url = documentURL, fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try assertSafeFile(url)
        let raw = try readFileData(from: url)
        guard SensitiveCatalogDocumentCodec.format(raw) == .managedV3 else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        let record = try readIntegrityRecord()
        try verify(record)
        let candidate = try decodeV3(raw)
        let diff = CatalogSemanticDiff.between(old: record.acceptedDocument, new: candidate)
        guard !diff.isEmpty else { return nil }
        return CatalogExternalChange(
            rawSHA256: sha256Hex(raw),
            semanticSHA256: semanticDigest(candidate),
            acceptedRevision: record.revision,
            candidateDocument: candidate,
            semanticDiff: diff
        )
    }

    private enum CatalogMergePath: Hashable {
        case indexOrder
        case entryOrder
        case fieldOrder(String)
        case index(String, String)
        case entry(String, String)
        case field(String, String, String)
    }

    private func writeUnlocked(
        _ document: SecretCatalogDocument,
        previous: UInt64,
        basedOn baseDocument: SecretCatalogDocument
    ) throws -> SensitiveCatalogSnapshot {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try document.validate()
        guard previous < UInt64.max else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        var targetDocument = document
        var sourceDocument = baseDocument

        for _ in 0..<3 {
            if fileManager.fileExists(atPath: url.path) {
                try assertSafeFile(url)
                let before = try readFileData(from: url)
                let currentDocument = try decodeV3(before)
                if currentDocument != sourceDocument {
                    guard let rebased = try safelyRebase(
                        base: sourceDocument,
                        local: targetDocument,
                        external: currentDocument
                    ) else {
                        throw SensitiveCatalogDocumentStoreError.revisionConflict
                    }
                    targetDocument = rebased
                    sourceDocument = currentDocument
                }

                let raw = try SensitiveCatalogDocumentCodec.minimalPatch(
                    before,
                    from: currentDocument,
                    to: targetDocument
                )
                let justBeforeWrite = try readFileData(from: url)
                guard sha256Hex(before) == sha256Hex(justBeforeWrite) else {
                    // The external writer won this read/patch window. Keep
                    // the desired semantic change and rebase it on the fresh
                    // source during the next pass instead of overwriting it.
                    sourceDocument = currentDocument
                    continue
                }
                guard try decodeV3(raw) == targetDocument else {
                    throw SensitiveCatalogDocumentStoreError.malformedDocument
                }
                let revision = previous + 1
                let record = try makeRecord(document: targetDocument, revision: revision, raw: raw)
                return try commitCatalogPairWithRecoveryUnlocked(
                    raw: raw,
                    document: targetDocument,
                    record: record
                )
            } else {
                guard sourceDocument == SecretCatalogDocument() else {
                    throw SensitiveCatalogDocumentStoreError.revisionConflict
                }
                let raw = try SensitiveCatalogDocumentCodec.canonicalData(targetDocument)
                guard !fileManager.fileExists(atPath: url.path) else { continue }
                let revision = previous + 1
                let record = try makeRecord(document: targetDocument, revision: revision, raw: raw)
                return try commitCatalogPairWithRecoveryUnlocked(
                    raw: raw,
                    document: targetDocument,
                    record: record
                )
            }
        }

        throw SensitiveCatalogDocumentStoreError.revisionConflict
    }

    /// Atomically commits a document and its accepted integrity sidecar under
    /// an authenticated transaction journal. If either replacement fails,
    /// both pre-commit files are restored only from hash-verified backups.
    private func commitCatalogPairWithRecoveryUnlocked(
        raw: Data,
        document: SecretCatalogDocument,
        record: CatalogIntegrityRecord
    ) throws -> SensitiveCatalogSnapshot {
        guard let documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        let stateURL = try integrityURL()
        let integrityData = try encodedIntegrityData(record)
        let recoveryDirectory = try recoveryDirectory()
        let hadDocument = fileManager.fileExists(atPath: documentURL.path)
        let hadIntegrity = fileManager.fileExists(atPath: stateURL.path)
        let documentBackupPath: String?
        let integrityBackupPath: String?
        let originalDocumentSHA256: String?
        let originalIntegritySHA256: String?

        if hadDocument {
            let backupData = try readFileData(from: documentURL)
            let backup = recoveryDirectory.appendingPathComponent("recovery-document-backup-\(UUID().uuidString.lowercased()).bin")
            try writeBackupData(backupData, to: backup)
            documentBackupPath = backup.path
            originalDocumentSHA256 = sha256Hex(backupData)
        } else {
            documentBackupPath = nil
            originalDocumentSHA256 = nil
        }
        if hadIntegrity {
            let backupData = try readFileData(from: stateURL)
            let backup = recoveryDirectory.appendingPathComponent("recovery-integrity-backup-\(UUID().uuidString.lowercased()).bin")
            try writeBackupData(backupData, to: backup)
            integrityBackupPath = backup.path
            originalIntegritySHA256 = sha256Hex(backupData)
        } else {
            integrityBackupPath = nil
            originalIntegritySHA256 = nil
        }

        let prepared = CatalogRecoveryJournal(
            phase: .prepared,
            planID: UUID().uuidString,
            documentPath: documentURL.standardizedFileURL.path,
            integrityPath: stateURL.standardizedFileURL.path,
            documentBackupPath: documentBackupPath,
            integrityBackupPath: integrityBackupPath,
            hadDocument: hadDocument,
            hadIntegrity: hadIntegrity,
            originalDocumentSHA256: originalDocumentSHA256,
            originalIntegritySHA256: originalIntegritySHA256,
            targetRevision: record.revision,
            expectedDocumentSHA256: sha256Hex(raw),
            expectedIntegritySHA256: sha256Hex(integrityData),
            createdAt: iso8601String(Date())
        )
        let committing = prepared.changingPhase(to: .committing)
        let journalURL = try recoveryJournalURL()

        do {
            try writeRecoveryJournal(prepared, at: journalURL)
            try writeRecoveryJournal(committing, at: journalURL)
            try atomicWrite(raw, to: documentURL, operation: .catalogMutation, target: .document)
            try atomicWrite(integrityData, to: stateURL, operation: .catalogMutation, target: .integrity)
            guard recoveryCommitMatches(committing) else {
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            try writeRecoveryJournal(committing.changingPhase(to: .completed), at: journalURL)
            try removeRecoveryJournal(at: journalURL)
            removeRecoveryBackups(documentPath: documentBackupPath, integrityPath: integrityBackupPath)
            return SensitiveCatalogSnapshot(document: document, revision: record.revision, integrity: .verified)
        } catch {
            // A complete pair must not be rolled back merely because the
            // completed marker cleanup failed.
            if recoveryCommitMatches(committing) {
                try? writeRecoveryJournal(committing.changingPhase(to: .completed), at: journalURL)
                try? removeRecoveryJournal(at: journalURL)
                removeRecoveryBackups(documentPath: documentBackupPath, integrityPath: integrityBackupPath)
                return SensitiveCatalogSnapshot(document: document, revision: record.revision, integrity: .verified)
            }
            do {
                try rollbackPersistedRecoveryUnlocked(prepared, journalURL: journalURL)
            } catch let rollbackError as SensitiveCatalogDocumentStoreError {
                throw rollbackError
            } catch {
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            throw error
        }
    }

    private func safelyRebase(
        base: SecretCatalogDocument,
        local: SecretCatalogDocument,
        external: SecretCatalogDocument
    ) throws -> SecretCatalogDocument? {
        let externalDiff = CatalogSemanticDiff.between(old: base, new: external)
        guard !externalDiff.requiresApproval else {
            throw SensitiveCatalogDocumentStoreError.pendingExternalChange
        }

        let baseValues = mergeValues(for: base)
        let localValues = mergeValues(for: local)
        let externalValues = mergeValues(for: external)
        let paths = Set(baseValues.keys)
            .union(localValues.keys)
            .union(externalValues.keys)
        var mergedValues: [CatalogMergePath: Data] = [:]

        for path in paths {
            let baseValue = baseValues[path]
            let localValue = localValues[path]
            let externalValue = externalValues[path]
            let localChanged = localValue != baseValue
            let externalChanged = externalValue != baseValue

            if localChanged && externalChanged && localValue != externalValue {
                return nil
            }
            if localChanged {
                if let localValue { mergedValues[path] = localValue }
            } else if let externalValue {
                mergedValues[path] = externalValue
            }
        }

        return try materializeMergeValues(
            mergedValues,
            base: base,
            local: local,
            external: external
        )
    }

    private func mergeValues(for document: SecretCatalogDocument) -> [CatalogMergePath: Data] {
        var values: [CatalogMergePath: Data] = [
            .indexOrder: mergeEncoded(document.indexes.map(\.id)),
            .entryOrder: mergeEncoded(document.entries.map(\.id))
        ]
        for index in document.indexes {
            values[.index(index.id, "exists")] = mergeEncoded(true)
            values[.index(index.id, "title")] = mergeEncoded(index.title)
            values[.index(index.id, "aliases")] = mergeEncoded(index.aliases)
            values[.index(index.id, "tags")] = mergeEncoded(index.tags)
        }
        for entry in document.entries {
            values[.entry(entry.id, "exists")] = mergeEncoded(true)
            values[.entry(entry.id, "indexId")] = mergeEncoded(entry.indexId)
            values[.entry(entry.id, "title")] = mergeEncoded(entry.title)
            values[.entry(entry.id, "type")] = mergeEncoded(entry.type)
            values[.entry(entry.id, "aliases")] = mergeEncoded(entry.aliases)
            values[.entry(entry.id, "endpoints")] = mergeEncoded(entry.endpoints)
            values[.entry(entry.id, "notes")] = mergeEncoded(entry.notes)
            values[.entry(entry.id, "tags")] = mergeEncoded(entry.tags)
            values[.fieldOrder(entry.id)] = mergeEncoded(entry.fields.map(\.key))
            for field in entry.fields {
                values[.field(entry.id, field.key, "exists")] = mergeEncoded(true)
                values[.field(entry.id, field.key, "label")] = mergeEncoded(field.label)
                values[.field(entry.id, field.key, "type")] = mergeEncoded(field.type)
                values[.field(entry.id, field.key, "agentVisible")] = mergeEncoded(field.agentVisible)
                values[.field(entry.id, field.key, "searchable")] = mergeEncoded(field.searchable)
                values[.field(entry.id, field.key, "value")] = mergeEncoded(field.value)
                values[.field(entry.id, field.key, "secretRef")] = mergeEncoded(field.secretRef)
            }
        }
        return values
    }

    private func materializeMergeValues(
        _ values: [CatalogMergePath: Data],
        base: SecretCatalogDocument,
        local: SecretCatalogDocument,
        external: SecretCatalogDocument
    ) throws -> SecretCatalogDocument? {
        let allIndexIDs = Set(
            base.indexes.map(\.id) + local.indexes.map(\.id) + external.indexes.map(\.id)
        )
        let indexOrder = try mergeOrder(
            values[.indexOrder],
            allIDs: allIndexIDs
        )
        var indexes: [SecretCatalogIndex] = []
        for id in indexOrder where try mergeBool(values[.index(id, "exists")]) {
            indexes.append(SecretCatalogIndex(
                id: id,
                title: try mergeValue(values, path: .index(id, "title"), as: String.self),
                aliases: try mergeValue(values, path: .index(id, "aliases"), as: [String].self),
                tags: try mergeValue(values, path: .index(id, "tags"), as: [String].self)
            ))
        }

        let indexIDSet = Set(indexes.map(\.id))
        let allEntryIDs = Set(
            base.entries.map(\.id) + local.entries.map(\.id) + external.entries.map(\.id)
        )
        let entryOrder = try mergeOrder(values[.entryOrder], allIDs: allEntryIDs)
        var entries: [SecretCatalogEntry] = []
        for id in entryOrder where try mergeBool(values[.entry(id, "exists")]) {
            let indexID = try mergeValue(values, path: .entry(id, "indexId"), as: String.self)
            guard indexIDSet.contains(indexID) else { return nil }
            let allFieldKeys = Set(
                (base.entries + local.entries + external.entries)
                    .filter { $0.id == id }
                    .flatMap { $0.fields.map(\.key) }
            )
            let fieldOrder = try mergeOrder(values[.fieldOrder(id)], allIDs: allFieldKeys)
            var fields: [SecretCatalogFieldValue] = []
            for key in fieldOrder where try mergeBool(values[.field(id, key, "exists")]) {
                fields.append(SecretCatalogFieldValue(
                    key: key,
                    label: try mergeValue(values, path: .field(id, key, "label"), as: String.self),
                    type: try mergeValue(values, path: .field(id, key, "type"), as: SecretCatalogFieldType.self),
                    agentVisible: try mergeValue(values, path: .field(id, key, "agentVisible"), as: Bool.self),
                    searchable: try mergeValue(values, path: .field(id, key, "searchable"), as: Bool.self),
                    value: try mergeValue(values, path: .field(id, key, "value"), as: SecretCatalogValue?.self),
                    secretRef: try mergeValue(values, path: .field(id, key, "secretRef"), as: String?.self)
                ))
            }
            entries.append(SecretCatalogEntry(
                id: id,
                indexId: indexID,
                title: try mergeValue(values, path: .entry(id, "title"), as: String.self),
                type: try mergeValue(values, path: .entry(id, "type"), as: String.self),
                aliases: try mergeValue(values, path: .entry(id, "aliases"), as: [String].self),
                endpoints: try mergeValue(values, path: .entry(id, "endpoints"), as: [CatalogEndpoint].self),
                fields: fields,
                notes: try mergeValue(values, path: .entry(id, "notes"), as: String?.self),
                tags: try mergeValue(values, path: .entry(id, "tags"), as: [String].self)
            ))
        }

        let merged = SecretCatalogDocument(indexes: indexes, entries: entries)
        guard (try? merged.validate()) != nil else { return nil }
        return merged
    }

    private func mergeOrder(_ data: Data?, allIDs: Set<String>) throws -> [String] {
        guard let data else { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        let order = try mergeDecode([String].self, from: data)
        var result: [String] = []
        for id in order where allIDs.contains(id) && !result.contains(id) {
            result.append(id)
        }
        for id in allIDs.subtracting(result).sorted() {
            result.append(id)
        }
        return result
    }

    private func mergeBool(_ data: Data?) throws -> Bool {
        guard let data else { return false }
        return try mergeDecode(Bool.self, from: data)
    }

    private func mergeValue<T: Decodable>(
        _ values: [CatalogMergePath: Data],
        path: CatalogMergePath,
        as type: T.Type
    ) throws -> T {
        guard let data = values[path] else { throw SensitiveCatalogDocumentStoreError.revisionConflict }
        return try mergeDecode(type, from: data)
    }

    private func mergeDecode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) }
        catch { throw SensitiveCatalogDocumentStoreError.revisionConflict }
    }

    private func mergeEncoded<T: Encodable>(_ value: T) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return (try? encoder.encode(value)) ?? Data()
    }

    private func decodeV3(_ data: Data) throws -> SecretCatalogDocument {
        do { return try SensitiveCatalogDocumentCodec.decode(data) }
        catch { throw SensitiveCatalogDocumentStoreError.malformedDocument }
    }

    private func decodeV2(_ data: Data) throws -> SecretCatalogDocument {
        do { return try SensitiveCatalogDocumentCodec.decode(data) }
        catch { throw SensitiveCatalogDocumentStoreError.malformedDocument }
    }

    private func readDocumentData() throws -> Data {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        try assertSafeFile(url)
        return try readFileData(from: url, stage: .readDocument, operation: .catalogRead)
    }

    /// Reads the managed document through a descriptor rather than
    /// Foundation's URL overlay open path. The latter can remain blocked for
    /// a background launchd Agent when the selected file is an Obsidian vault
    /// document. The descriptor is opened without following the final
    /// symlink and is revalidated as a regular file before any bytes are
    /// consumed. Integrity/CAS checks still happen at the existing call
    /// sites.
    private func readFileData(
        from url: URL,
        stage: CatalogFileIOStage = .readDocument,
        operation: CatalogIOOperation = .catalogRead
    ) throws -> Data {
        try assertSafeFile(url)
        var bytes: UnsafeMutableRawPointer?
        var length = 0
        let observed = readFileStatus(url.path)
        let status = observed.status
        bytes = observed.bytes
        length = observed.length
        guard status == 0,
              let bytes,
              length <= svltPosixFileReaderMaximumBytes
        else {
            if let bytes { svlt_free_file(bytes) }
            logIOFailure(stage: stage, status: status, operation: operation)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        defer { svlt_free_file(bytes) }
        return Data(bytes: bytes, count: length)
    }

    private func recoveryDirectory() throws -> URL {
        guard let documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        let root = try integrityURL().deletingLastPathComponent()
        let directory = root
            .appendingPathComponent("Recovery", isDirectory: true)
            .appendingPathComponent(sha256Hex(Data(documentURL.standardizedFileURL.path.utf8)), isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try assertSafeDirectory(directory)
        return directory
    }

    private func directoryFsyncStatus(_ path: String) -> Int32 {
        guard !path.isEmpty else { return EINVAL }
        guard case .success = CatalogPOSIXIO.permits.wait(timeout: .now()) else {
            return ETIMEDOUT
        }
        let semaphore = DispatchSemaphore(value: 0)
        let queue = CatalogPOSIXIO.queue
        let resultBox = CatalogDirectoryFsyncResultBox()
        queue.async {
            defer { CatalogPOSIXIO.permits.signal() }
            let observed = path.withCString { svlt_fsync_directory($0) }
            _ = resultBox.complete(observed)
            semaphore.signal()
        }
        guard case .success = semaphore.wait(timeout: .now() + .seconds(3)) else {
            return resultBox.resultAfterTimeout()
        }
        return resultBox.resultAfterTimeout()
    }

    private func readFileStatus(_ path: String) -> (status: Int32, bytes: UnsafeMutableRawPointer?, length: Int) {
        guard CatalogPOSIXIO.permits.wait(timeout: .now()) == .success else {
            return (ETIMEDOUT, nil, 0)
        }
        let semaphore = DispatchSemaphore(value: 0)
        let queue = CatalogPOSIXIO.queue
        let resultBox = CatalogReadFileResultBox()
        queue.async {
            defer { CatalogPOSIXIO.permits.signal() }
            var observedBytes: UnsafeMutableRawPointer?
            var observedLength = 0
            let status = path.withCString { svlt_read_file($0, &observedBytes, &observedLength) }
            if !resultBox.complete(status: status, bytes: observedBytes, length: observedLength),
               let observedBytes {
                svlt_free_file(observedBytes)
            }
            semaphore.signal()
        }
        guard case .success = semaphore.wait(timeout: .now() + .seconds(3)) else {
            return resultBox.resultAfterTimeout()
        }
        return resultBox.resultAfterTimeout()
    }

    private func makeRecord(document: SecretCatalogDocument, revision: UInt64, raw: Data) throws -> CatalogIntegrityRecord {
        let state = CatalogAcceptedState(
            revision: revision,
            semanticSHA256: semanticDigest(document),
            acceptedDocument: document,
            rawSHA256: sha256Hex(raw),
            updatedAt: iso8601String(Date())
        )
        let key: Data
        do { key = try keyStore.loadOrCreateKey() }
        catch {
            logIOFailure(stage: .keychainIntegrity, status: -1, operation: .catalogMutation)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        let mac = HMAC<SHA256>.authenticationCode(for: integrityPayload(state), using: SymmetricKey(data: key))
        return CatalogIntegrityRecord(acceptedState: state, hmac: Data(mac).base64EncodedString())
    }

    private func verify(_ record: CatalogIntegrityRecord) throws {
        guard record.schemaVersion == SecretCatalogDocument.currentSchemaVersion, record.revision > 0, let expected = Data(base64Encoded: record.hmac) else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
        do { try record.acceptedDocument.validate() } catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        guard semanticDigest(record.acceptedDocument) == record.semanticSHA256 else { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let key: Data
        do { key = try keyStore.loadOrCreateKey() } catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let computed = Data(HMAC<SHA256>.authenticationCode(for: integrityPayload(record.acceptedState), using: SymmetricKey(data: key)))
        guard constantTimeEqual(computed, expected) else { throw SensitiveCatalogDocumentStoreError.externalModification }
    }

    private func integrityPayload(_ state: CatalogAcceptedState) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let document = (try? encoder.encode(state.acceptedDocument)).map { String(data: $0, encoding: .utf8) ?? "{}" } ?? "{}"
        return Data("SVLT-CATALOG-ACCEPTED-V3\n\(state.revision)\n\(state.semanticSHA256)\n\(document)".utf8)
    }

    private func semanticDigest(_ document: SecretCatalogDocument) -> String {
        CatalogSemanticDigest.sha256(document)
    }

    private func referenceSet(_ document: SecretCatalogDocument) -> Set<String> {
        Set(document.entries.flatMap { $0.fields.compactMap(\.secretRef) })
    }

    private func readIntegrityRecord() throws -> CatalogIntegrityRecord {
        try readIntegrityRecord(at: try integrityURL())
    }

    private func readIntegrityRecord(at url: URL) throws -> CatalogIntegrityRecord {
        guard fileManager.fileExists(atPath: url.path) else { throw SensitiveCatalogDocumentStoreError.integrityMissing }
        try assertSafeFile(url)
        do {
            return try JSONDecoder().decode(
                CatalogIntegrityRecord.self,
                from: readFileData(from: url, stage: .readIntegrity, operation: .catalogRead)
            )
        }
        catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
    }

    private func v2IntegritySourceURL(activeURL: URL) throws -> URL? {
        if fileManager.fileExists(atPath: activeURL.path) {
            return activeURL
        }
        guard suppliedIntegrityURL == nil,
              let legacyURL = try legacyIntegrityURL(),
              legacyURL.standardizedFileURL != activeURL.standardizedFileURL,
              fileManager.fileExists(atPath: legacyURL.path)
        else {
            return nil
        }

        // Only a sidecar with the PR #13 flat schema can be a v2 migration
        // source. A v3 sidecar belonging to another selected document must
        // not block adoption of this document.
        guard (try? readLegacyIntegrityRecordV2(at: legacyURL)) != nil else {
            return nil
        }
        return legacyURL
    }

    private func migrateLegacyV3IntegrityIfMatching(
        candidate: SecretCatalogDocument,
        raw _: Data,
        activeURL: URL
    ) throws {
        guard !fileManager.fileExists(atPath: activeURL.path),
              suppliedIntegrityURL == nil,
              let legacyURL = try legacyIntegrityURL(),
              legacyURL.standardizedFileURL != activeURL.standardizedFileURL,
              fileManager.fileExists(atPath: legacyURL.path)
        else {
            return
        }

        do {
            let legacy = try readIntegrityRecord(at: legacyURL)
            try verify(legacy)
            guard legacy.acceptedDocument == candidate else { return }
            try atomicWrite(readFileData(from: legacyURL), to: activeURL)
        } catch let error as SensitiveCatalogDocumentStoreError {
            // A global pre-v3 sidecar is not bound to a document path. If it
            // cannot be proven to describe this exact semantic document,
            // leave it untouched and let the normal explicit adoption path
            // establish a new per-document accepted state.
            guard error == .writeFailed else { return }
            throw error
        } catch {
            return
        }
    }

    /// A path-scoped sidecar cannot follow an Obsidian rename by itself. When
    /// the active path has no sidecar, conservatively rebind exactly one
    /// already-authenticated sidecar whose accepted semantic document is an
    /// exact match. Ambiguous matches fail closed and leave all old sidecars
    /// intact for recovery.
    private func migrateRenamedV3IntegrityIfMatching(
        candidate: SecretCatalogDocument,
        raw: Data,
        activeURL: URL
    ) throws {
        guard !fileManager.fileExists(atPath: activeURL.path),
              suppliedIntegrityURL == nil,
              documentURL != nil
        else {
            return
        }
        let directory = try catalogIntegrityDirectoryURL()
        let files = try fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey],
            options: [.skipsHiddenFiles]
        ).filter { url in
            let name = url.lastPathComponent
            return name.hasPrefix("catalog-integrity-")
                && name.hasSuffix(".json")
                && name != activeURL.lastPathComponent
                && name.dropFirst("catalog-integrity-".count).dropLast(".json".count).count == 64
                && name.dropFirst("catalog-integrity-".count).dropLast(".json".count).allSatisfy { $0.isHexDigit }
        }

        var matches: [(url: URL, record: CatalogIntegrityRecord)] = []
        for file in files {
            do {
                let record = try readIntegrityRecord(at: file)
                try verify(record)
                if record.acceptedDocument == candidate {
                    matches.append((file, record))
                }
            } catch {
                // An unrelated, malformed, or unverifiable sidecar must not
                // become a migration source for a different document.
                continue
            }
        }
        guard matches.count == 1 else { return }
        let source = matches[0].record
        let rebound = try makeRecord(document: candidate, revision: source.revision, raw: raw)
        try atomicWriteIntegrity(rebound)
    }

    private func readLegacyIntegrityRecordV2(at url: URL) throws -> LegacyCatalogIntegrityRecordV2 {
        do {
            return try JSONDecoder().decode(
                LegacyCatalogIntegrityRecordV2.self,
                from: readFileData(from: url)
            )
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func verifyLegacyIntegrityV2(
        _ record: LegacyCatalogIntegrityRecordV2,
        data: Data
    ) throws {
        guard record.schemaVersion == 2,
              record.revision > 0,
              let expectedMAC = Data(base64Encoded: record.hmac)
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let hash = sha256Hex(data)
        guard hash == record.canonicalSHA256 else {
            throw SensitiveCatalogDocumentStoreError.externalModification
        }

        let key: Data
        do { key = try keyStore.loadOrCreateKey() }
        catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let computedMAC = Data(HMAC<SHA256>.authenticationCode(
            for: legacyIntegrityPayloadV2(data: data, revision: record.revision, hash: hash),
            using: SymmetricKey(data: key)
        ))
        guard constantTimeEqual(computedMAC, expectedMAC) else {
            throw SensitiveCatalogDocumentStoreError.externalModification
        }
    }

    private func migrationRevision(after legacyRevision: UInt64?) throws -> UInt64 {
        guard let legacyRevision else { return 1 }
        guard legacyRevision < UInt64.max else {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        return legacyRevision + 1
    }

    private func normalizedCleanupReferenceIDs(_ referenceIDs: [String]) throws -> [String] {
        var normalized = Set<String>()
        for id in referenceIDs {
            guard !id.isEmpty, (try? SecretReference("secret://\(id)")) != nil else {
                throw SensitiveCatalogDocumentStoreError.invalidOperation
            }
            normalized.insert(id)
        }
        return normalized.sorted()
    }

    private func cleanupDocumentIdentity() throws -> String {
        guard let documentURL else {
            throw SensitiveCatalogDocumentStoreError.noSelectedDocument
        }
        return documentURL.standardizedFileURL.path
    }

    private func cleanupRecordURL() throws -> URL {
        let integrity = try integrityURL()
        return integrity.deletingLastPathComponent()
            .appendingPathComponent("\(integrity.lastPathComponent).cleanup.json")
    }

    private func readCleanupReferenceIDsUnlocked() throws -> [String] {
        let url = try cleanupRecordURL()
        guard fileManager.fileExists(atPath: url.path) else { return [] }
        try assertSafeFile(url)
        do {
            let record = try JSONDecoder().decode(
                CatalogSecretCleanupRecord.self,
                from: readFileData(from: url)
            )
            try verifyCleanupRecord(record)
            return record.referenceIDs
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func verifyCleanupRecord(_ record: CatalogSecretCleanupRecord) throws {
        guard record.schemaVersion == CatalogSecretCleanupRecord.currentSchemaVersion,
              record.documentIdentity == (try cleanupDocumentIdentity()),
              UUID(uuidString: record.transactionID) != nil,
              !record.createdAt.isEmpty,
              let expectedMAC = Data(base64Encoded: record.hmac),
              expectedMAC.count == 32
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let normalized = try normalizedCleanupReferenceIDs(record.referenceIDs)
        guard normalized == record.referenceIDs else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let key: Data
        do { key = try keyStore.loadOrCreateKey() }
        catch { throw SensitiveCatalogDocumentStoreError.invalidIntegrity }
        let computedMAC = Data(HMAC<SHA256>.authenticationCode(
            for: cleanupMACPayload(record),
            using: SymmetricKey(data: key)
        ))
        guard constantTimeEqual(computedMAC, expectedMAC) else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func writeCleanupReferenceIDsUnlocked(_ referenceIDs: [String]) throws {
        let url = try cleanupRecordURL()
        let normalized = try normalizedCleanupReferenceIDs(referenceIDs)
        if normalized.isEmpty {
            try removeFileIfPresentUnlocked(url)
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do {
            let documentIdentity = try cleanupDocumentIdentity()
            let transactionID = UUID().uuidString.lowercased()
            let createdAt = iso8601String(Date())
            let unsigned = CatalogSecretCleanupMACPayload(
                schemaVersion: CatalogSecretCleanupRecord.currentSchemaVersion,
                documentIdentity: documentIdentity,
                transactionID: transactionID,
                referenceIDs: normalized,
                createdAt: createdAt
            )
            let key = try keyStore.loadOrCreateKey()
            let mac = HMAC<SHA256>.authenticationCode(
                for: cleanupMACPayload(unsigned),
                using: SymmetricKey(data: key)
            )
            let data = try encoder.encode(CatalogSecretCleanupRecord(
                documentIdentity: documentIdentity,
                transactionID: transactionID,
                referenceIDs: normalized,
                createdAt: createdAt,
                hmac: Data(mac).base64EncodedString()
            ))
            try atomicWrite(data, to: url, operation: .catalogCleanup, target: .cleanup)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func cleanupMACPayload(_ record: CatalogSecretCleanupRecord) -> Data {
        cleanupMACPayload(CatalogSecretCleanupMACPayload(
            schemaVersion: record.schemaVersion,
            documentIdentity: record.documentIdentity,
            transactionID: record.transactionID,
            referenceIDs: record.referenceIDs,
            createdAt: record.createdAt
        ))
    }

    private func cleanupMACPayload(_ payload: CatalogSecretCleanupMACPayload) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = (try? encoder.encode(payload)) ?? Data()
        return Data("SVLT-CATALOG-CLEANUP-V1\n".utf8) + encoded
    }

    private func legacyIntegrityPayloadV2(data: Data, revision: UInt64, hash: String) -> Data {
        var payload = Data("SVLT-CATALOG-INTEGRITY-V2\n\(revision)\n\(hash)\n".utf8)
        payload.append(data)
        return payload
    }

    private func encodedIntegrityData(_ record: CatalogIntegrityRecord) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do { return try encoder.encode(record) }
        catch { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func atomicWriteIntegrity(_ record: CatalogIntegrityRecord) throws {
        do {
            try atomicWrite(
                try encodedIntegrityData(record),
                to: try integrityURL(),
                operation: .catalogMutation,
                target: .integrity
            )
        }
        catch let error as SensitiveCatalogDocumentStoreError { throw error }
        catch { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func migrationJournalURL() throws -> URL {
        let integrity = try integrityURL()
        let name = suppliedIntegrityURL == nil
            ? "\(integrity.lastPathComponent).migration.json"
            : "catalog-migration-state.json"
        return integrity.deletingLastPathComponent().appendingPathComponent(name)
    }

    private func writeMigrationJournal(_ journal: CatalogMigrationJournal, at url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        do {
            try atomicWrite(try encoder.encode(journal), to: url)
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func removeMigrationJournal(at url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else { return }
        try assertSafeFile(url)
        do {
            try fileManager.removeItem(at: url)
            try fsyncDirectory(at: url.deletingLastPathComponent())
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func readMigrationJournal(at url: URL) throws -> CatalogMigrationJournal {
        guard fileManager.fileExists(atPath: url.path) else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
        try assertSafeFile(url)
        do {
            let journal = try JSONDecoder().decode(
                CatalogMigrationJournal.self,
                from: readFileData(from: url)
            )
            try validateMigrationJournal(journal, journalURL: url)
            return journal
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw error
        } catch {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func validateMigrationJournal(
        _ journal: CatalogMigrationJournal,
        journalURL: URL
    ) throws {
        guard journal.schemaVersion == 1,
              let documentURL,
              journalURL.standardizedFileURL.path == (try migrationJournalURL()).standardizedFileURL.path,
              journal.documentPath == documentURL.standardizedFileURL.path,
              journal.integrityPath == (try integrityURL()).standardizedFileURL.path,
              (journal.targetRevision ?? 1) > 0,
              !journal.expectedDocumentSHA256.isEmpty,
              !journal.expectedIntegritySHA256.isEmpty
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        let activeIntegrity = try integrityURL()
        let previousIntegrity: URL?
        if let previousIntegrityPath = journal.previousIntegrityPath {
            let candidate = URL(fileURLWithPath: previousIntegrityPath).standardizedFileURL
            guard isAllowedPreviousIntegrityPath(candidate, activeURL: activeIntegrity) else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
            previousIntegrity = candidate
        } else {
            previousIntegrity = nil
        }

        let documentBackup = URL(fileURLWithPath: journal.documentBackupPath).standardizedFileURL
        guard isMigrationBackup(documentBackup, for: documentURL),
              fileManager.fileExists(atPath: documentBackup.path)
        else {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }

        if let integrityBackupPath = journal.integrityBackupPath {
            let integrityBackup = URL(fileURLWithPath: integrityBackupPath).standardizedFileURL
            let backupTarget = previousIntegrity ?? activeIntegrity
            guard isMigrationBackup(integrityBackup, for: backupTarget),
                  fileManager.fileExists(atPath: integrityBackup.path)
            else {
                throw SensitiveCatalogDocumentStoreError.invalidIntegrity
            }
        } else if previousIntegrity != nil {
            throw SensitiveCatalogDocumentStoreError.invalidIntegrity
        }
    }

    private func isAllowedPreviousIntegrityPath(_ candidate: URL, activeURL: URL) -> Bool {
        if candidate.standardizedFileURL == activeURL.standardizedFileURL {
            return true
        }
        guard suppliedIntegrityURL == nil else {
            return false
        }
        guard let legacy = try? legacyIntegrityURL() else {
            return false
        }
        return candidate.standardizedFileURL == legacy.standardizedFileURL
    }

    private func isMigrationBackup(_ backup: URL, for target: URL) -> Bool {
        backup.deletingLastPathComponent().standardizedFileURL.path == target.deletingLastPathComponent().standardizedFileURL.path
            && backup.lastPathComponent.hasPrefix("\(target.lastPathComponent).bak-")
    }

    private func recoverInterruptedV2MigrationUnlocked() throws {
        let journalURL = try migrationJournalURL()
        guard fileManager.fileExists(atPath: journalURL.path) else { return }
        let journal = try readMigrationJournal(at: journalURL)

        switch journal.phase {
        case .completed:
            try removeMigrationJournal(at: journalURL)
        case .prepared, .committing:
            if migrationCommitMatches(journal) {
                // Both target files reached the prepared commit. The only
                // missing step was journal cleanup, so keep the migration.
                try removeMigrationJournal(at: journalURL)
            } else {
                try rollbackV2MigrationUnlocked(journal, journalURL: journalURL)
            }
        }
    }

    private func migrationCommitMatches(_ journal: CatalogMigrationJournal) -> Bool {
        guard let documentURL,
              fileManager.fileExists(atPath: documentURL.path),
              (try? assertSafeFile(documentURL)) != nil,
              let raw = try? readFileData(from: documentURL),
              sha256Hex(raw) == journal.expectedDocumentSHA256,
              let integrityURL = try? integrityURL(),
              fileManager.fileExists(atPath: integrityURL.path),
              (try? assertSafeFile(integrityURL)) != nil,
              let integrityData = try? readFileData(from: integrityURL),
              sha256Hex(integrityData) == journal.expectedIntegritySHA256,
              let document = try? decodeV3(raw),
              let record = try? JSONDecoder().decode(CatalogIntegrityRecord.self, from: integrityData)
        else {
            return false
        }
        return record.revision == (journal.targetRevision ?? 1)
            && record.rawSHA256 == journal.expectedDocumentSHA256
            && record.acceptedDocument == document
    }

    private func rollbackV2MigrationUnlocked(
        _ journal: CatalogMigrationJournal,
        journalURL: URL
    ) throws {
        try validateMigrationJournal(journal, journalURL: journalURL)
        guard let documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        let activeIntegrity = try integrityURL()
        let previousIntegrity = journal.previousIntegrityPath.map { URL(fileURLWithPath: $0).standardizedFileURL }
        var failed = false

        do {
            if let integrityBackupPath = journal.integrityBackupPath {
                try restoreFileUnlocked(
                    from: URL(fileURLWithPath: integrityBackupPath),
                    to: previousIntegrity ?? activeIntegrity
                )
            } else {
                try removeFileIfPresentUnlocked(activeIntegrity)
            }
            if let previousIntegrity, previousIntegrity != activeIntegrity {
                try removeFileIfPresentUnlocked(activeIntegrity)
            }
        } catch {
            failed = true
        }

        do {
            try restoreFileUnlocked(
                from: URL(fileURLWithPath: journal.documentBackupPath),
                to: documentURL
            )
        } catch {
            failed = true
        }

        guard !failed else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        try removeMigrationJournal(at: journalURL)
    }

    private func restoreFileUnlocked(from backupURL: URL, to targetURL: URL) throws {
        try assertSafeFile(backupURL)
        let data = try readFileData(from: backupURL)
        try atomicWrite(data, to: targetURL)
    }

    private func removeFileIfPresentUnlocked(_ url: URL) throws {
        guard fileManager.fileExists(atPath: url.path) else { return }
        try assertSafeFile(url)
        do {
            try fileManager.removeItem(at: url)
            try fsyncDirectory(at: url.deletingLastPathComponent())
        } catch {
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func backupCurrentDocumentUnlocked() throws -> URL? {
        guard let url = documentURL else { throw SensitiveCatalogDocumentStoreError.noSelectedDocument }
        return try backupFileUnlocked(url)
    }

    private func backupFileUnlocked(_ url: URL) throws -> URL? {
        guard fileManager.fileExists(atPath: url.path) else { return nil }
        try assertSafeFile(url)
        let backup = url.deletingLastPathComponent().appendingPathComponent("\(url.lastPathComponent).bak-\(backupTimestampString(Date()))-\(UUID().uuidString.lowercased())")
        do {
            try readFileData(from: url).write(to: backup, options: [.withoutOverwriting])
            try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
            try fsyncFile(at: backup)
            return backup
        } catch {
            try? fileManager.removeItem(at: backup)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func integrityURL() throws -> URL {
        if let suppliedIntegrityURL { return suppliedIntegrityURL }
        let directory = try catalogIntegrityDirectoryURL()
        guard let documentURL else {
            return directory.appendingPathComponent("catalog-integrity.json")
        }
        let documentKey = sha256Hex(Data(documentURL.standardizedFileURL.path.utf8))
        return directory.appendingPathComponent("catalog-integrity-\(documentKey).json")
    }

    private func catalogIntegrityDirectoryURL() throws -> URL {
        if let suppliedIntegrityDirectoryURL {
            try fileManager.createDirectory(
                at: suppliedIntegrityDirectoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try assertSafeDirectory(suppliedIntegrityDirectoryURL)
            return suppliedIntegrityDirectoryURL
        }
        let appSupport = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = appSupport
            .appendingPathComponent("AgentSecretVault", isDirectory: true)
            .appendingPathComponent("CatalogIntegrity", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try assertSafeDirectory(directory)
        return directory
    }

    private func legacyIntegrityURL() throws -> URL? {
        guard suppliedIntegrityURL == nil else { return nil }
        if let suppliedIntegrityDirectoryURL {
            return suppliedIntegrityDirectoryURL.appendingPathComponent("catalog-integrity.json")
        }
        let appSupport = try fileManager.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = appSupport.appendingPathComponent("AgentSecretVault", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try assertSafeDirectory(directory)
        return directory.appendingPathComponent("catalog-integrity.json")
    }

    private func withCatalogLock<T>(exclusive: Bool, _ operation: () throws -> T) throws -> T {
        let lockURL = try integrityURL().appendingPathExtension("lock")
        let parent = lockURL.deletingLastPathComponent()
        do {
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            logFoundationIOFailure(stage: .acquireLock, error: error, operation: .catalogValidate)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        if fileManager.fileExists(atPath: lockURL.path) { try assertSafeFile(lockURL) }
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR, mode_t(0o600))
        guard descriptor >= 0 else {
            let status = errno
            logIOFailure(stage: .acquireLock, status: status, operation: .catalogMutation)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        defer { close(descriptor) }

        let requestedLock = (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB
        let deadline = DispatchTime.now().uptimeNanoseconds + svltCatalogLockWaitNanoseconds
        while flock(descriptor, requestedLock) != 0 {
            let status = errno
            let isContention = status == EWOULDBLOCK || status == EAGAIN
            if !isContention && status != EINTR {
                logIOFailure(
                    stage: .acquireLock,
                    status: status,
                    operation: exclusive ? .catalogMutation : .catalogRead
                )
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            if DispatchTime.now().uptimeNanoseconds >= deadline {
                logIOFailure(
                    stage: .acquireLock,
                    status: ETIMEDOUT,
                    operation: exclusive ? .catalogMutation : .catalogRead
                )
                throw SensitiveCatalogDocumentStoreError.writeFailed
            }
            usleep(svltCatalogLockRetryMicroseconds)
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try operation()
    }

    private func atomicWrite(
        _ data: Data,
        to url: URL,
        operation: CatalogIOOperation = .catalogMutation,
        target: CatalogWriteTarget = .internalState
    ) throws {
        let parent = url.deletingLastPathComponent()
        try assertSafeParent(url)
        do {
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            logFoundationIOFailure(stage: .createTemporary, error: error, operation: operation)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        let temporary = parent.appendingPathComponent(".svlt-catalog-\(UUID().uuidString).tmp")
        var descriptor: Int32 = -1
        var temporaryExists = false
        do {
            let createStatus = temporary.path.withCString { path in
                svlt_create_file(path, &descriptor)
            }
            guard createStatus == 0 else {
                throw POSIXFileWriteError(stage: .createTemporary, status: createStatus)
            }
            temporaryExists = true

            let writeStatus = data.withUnsafeBytes { buffer in
                svlt_write_file_descriptor(descriptor, buffer.baseAddress, buffer.count)
            }
            guard writeStatus == 0 else {
                throw POSIXFileWriteError(stage: .writeTemporary, status: writeStatus)
            }
            let fsyncStatus = svlt_fsync_file_descriptor(descriptor)
            guard fsyncStatus == 0 else {
                throw POSIXFileWriteError(stage: .fsyncTemporary, status: fsyncStatus)
            }
            let closeStatus = svlt_close_file_descriptor(descriptor)
            descriptor = -1
            guard closeStatus == 0 else {
                throw POSIXFileWriteError(stage: .closeTemporary, status: closeStatus)
            }

            try atomicWriteFaultInjector?.beforeAtomicReplace(to: url)
            if fileManager.fileExists(atPath: url.path) {
                try assertSafeFile(url)
            }
            let replaceStatus = temporary.path.withCString { source in
                url.path.withCString { destination in
                    svlt_replace_file(source, destination)
                }
            }
            guard replaceStatus == 0 else {
                throw POSIXFileWriteError(
                    stage: target == .integrity ? .replaceIntegrity : .replaceDocument,
                    status: replaceStatus
                )
            }
            temporaryExists = false
            let directoryStatus = directoryFsyncStatus(parent.path)
            if directoryStatus == ETIMEDOUT, target == .document {
                // File Provider may complete the atomic rename but cannot
                // service a parent-directory fsync. The rename is still
                // accepted only after an immediate read-back hash check; the
                // pair journal and final semantic/integrity verification keep
                // the accepted Catalog failure-atomic. The integrity sidecar
                // remains strict because it is local SVLT state.
                let readBackMatches = (try? readFileData(
                    from: url,
                    stage: .readDocument,
                    operation: operation
                )).map { sha256Hex($0) == sha256Hex(data) } == true
                guard readBackMatches else {
                    throw POSIXFileWriteError(
                        stage: .fsyncDocumentDirectory,
                        status: directoryStatus
                    )
                }
                NSLog(
                    "SVLT Catalog document directory fsync deferred: errno=%d symbol=%@ operation=%@",
                    directoryStatus,
                    errnoSymbol(directoryStatus),
                    operation.rawValue
                )
            } else {
                guard directoryStatus == 0 else {
                    throw POSIXFileWriteError(
                        stage: target == .integrity ? .fsyncIntegrityDirectory : .fsyncDocumentDirectory,
                        status: directoryStatus
                    )
                }
            }
        } catch {
            if descriptor >= 0 {
                _ = svlt_close_file_descriptor(descriptor)
                descriptor = -1
            }
            if temporaryExists {
                _ = temporary.path.withCString { path in svlt_unlink_file(path) }
            }
            if let error = error as? POSIXFileWriteError {
                logIOFailure(stage: error.stage, status: error.status, operation: operation)
            } else if !(error is SensitiveCatalogDocumentStoreError) {
                logFoundationIOFailure(stage: .replaceDocument, error: error, operation: operation)
            }
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func assertSafeParent(_ url: URL) throws {
        let parent = url.deletingLastPathComponent()
        guard fileManager.fileExists(atPath: parent.path) else { return }
        let values = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        guard values.isSymbolicLink != true else { throw SensitiveCatalogDocumentStoreError.symlinkRejected }
    }

    private func assertSafeDirectory(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        guard values.isSymbolicLink != true else { throw SensitiveCatalogDocumentStoreError.symlinkRejected }
    }

    private func assertSafeFile(_ url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true else { throw SensitiveCatalogDocumentStoreError.malformedDocument }
        guard values.isSymbolicLink != true else { throw SensitiveCatalogDocumentStoreError.symlinkRejected }
    }

    private func fsyncFile(at url: URL) throws {
        let descriptor = open(url.path, O_RDONLY)
        guard descriptor >= 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else { throw SensitiveCatalogDocumentStoreError.writeFailed }
    }

    private func fsyncDirectory(at url: URL) throws {
        let descriptor = open(url.path, O_RDONLY | O_DIRECTORY)
        guard descriptor >= 0 else {
            let status = errno
            logIOFailure(stage: .fsyncDocumentDirectory, status: status, operation: .catalogMigration)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
        defer { close(descriptor) }
        guard fsync(descriptor) == 0 else {
            let status = errno
            logIOFailure(stage: .fsyncDocumentDirectory, status: status, operation: .catalogMigration)
            throw SensitiveCatalogDocumentStoreError.writeFailed
        }
    }

    private func preflightReadStatus(_ url: URL) -> String {
        guard fileManager.fileExists(atPath: url.path) else {
            return preflightFailure(stage: .preflightRead, errno: ENOENT)
        }
        do {
            try assertSafeFile(url)
        } catch {
            return preflightFailure(stage: .preflightRead, errno: EINVAL)
        }

        let observed = readFileStatus(url.path)
        let status = observed.status
        let length = observed.length
        if let bytes = observed.bytes {
            svlt_free_file(bytes)
        }
        guard status == 0, length <= svltPosixFileReaderMaximumBytes else {
            return preflightFailure(stage: .preflightRead, errno: status == 0 ? EIO : status)
        }
        return "READ_OK"
    }

    private func preflightFailure(stage: CatalogFileIOStage, errno status: Int32) -> String {
        logIOFailure(stage: stage, status: status, operation: .catalogValidate)
        return "FAILED errno=\(status) symbol=\(errnoSymbol(status))"
    }

    private func logIOFailure(
        stage: CatalogFileIOStage,
        status: Int32,
        operation: CatalogIOOperation
    ) {
        NSLog(
            "SVLT Catalog IO failure: stage=%@ errno=%d symbol=%@ operation=%@",
            stage.rawValue,
            status,
            errnoSymbol(status),
            operation.rawValue
        )
    }

    private func logFoundationIOFailure(
        stage: CatalogFileIOStage,
        error: Error,
        operation: CatalogIOOperation
    ) {
        let nsError = error as NSError
        let status: Int32 = nsError.domain == NSPOSIXErrorDomain ? Int32(nsError.code) : -1
        logIOFailure(stage: stage, status: status, operation: operation)
    }

    private func errnoSymbol(_ status: Int32) -> String {
        switch status {
        case EACCES: return "EACCES"
        case EPERM: return "EPERM"
        case ENOENT: return "ENOENT"
        case EEXIST: return "EEXIST"
        case EIO: return "EIO"
        case EINVAL: return "EINVAL"
        case ENOTDIR: return "ENOTDIR"
        case EFBIG: return "EFBIG"
        case ENOMEM: return "ENOMEM"
        case EBUSY: return "EBUSY"
        case ETIMEDOUT: return "ETIMEDOUT"
        case ENOTSUP: return "ENOTSUP"
        case EROFS: return "EROFS"
        case EINTR: return "EINTR"
        case -1: return "UNKNOWN"
        default: return "ERRNO_\(status)"
        }
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }

    private func iso8601String(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter(); formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    private func backupTimestampString(_ date: Date) -> String {
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }
}

private func replacingFields(_ entry: SecretCatalogEntry, _ fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(id: entry.id, indexId: entry.indexId, title: entry.title, type: entry.type, aliases: entry.aliases, endpoints: entry.endpoints, fields: fields, notes: entry.notes, tags: entry.tags, schema: entry.schema)
}