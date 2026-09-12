import Foundation
import os

/// Non-sensitive, sticky audit-channel health. This is deliberately kept
/// outside the encrypted event stream so the daemon can report an audit gap
/// without acquiring a vault or audit key. The record contains no paths,
/// payloads, references, or credentials.
struct CatalogAuditHealthRecord: Codable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let lastFailureAt: Date?
    let gapDetected: Bool
    let lastSuccessfulSequence: UInt64
    let lastIntegrityScanAttemptAt: Date?
    let lastIntegrityScanAt: Date?

    init(
        schemaVersion: Int,
        lastFailureAt: Date?,
        gapDetected: Bool,
        lastSuccessfulSequence: UInt64,
        lastIntegrityScanAttemptAt: Date? = nil,
        lastIntegrityScanAt: Date? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.lastFailureAt = lastFailureAt
        self.gapDetected = gapDetected
        self.lastSuccessfulSequence = lastSuccessfulSequence
        self.lastIntegrityScanAttemptAt = lastIntegrityScanAttemptAt
        self.lastIntegrityScanAt = lastIntegrityScanAt
    }
}

/// Owns the non-sensitive audit-health sidecar and the state persisted in it.
/// `VaultAppServices` reports append outcomes; this value keeps the sticky gap,
/// first-failure timestamp, monotonic success sequence, integrity-maintenance
/// cadence, and filesystem policy in one independently testable boundary.
struct CatalogAuditHealthStore: Sendable {
    private let url: URL?
    private(set) var lastFailureAt: Date?
    private(set) var gapDetected: Bool
    private(set) var lastSuccessfulSequence: UInt64
    private(set) var lastIntegrityScanAttemptAt: Date?
    private(set) var lastIntegrityScanAt: Date?

    init(url: URL?) {
        let standardizedURL = url?.standardizedFileURL
        self.url = standardizedURL
        let record = Self.load(from: standardizedURL)
        self.lastFailureAt = record?.lastFailureAt
        self.gapDetected = record?.gapDetected ?? false
        self.lastSuccessfulSequence = record?.lastSuccessfulSequence ?? 0
        self.lastIntegrityScanAttemptAt = record?.lastIntegrityScanAttemptAt
        self.lastIntegrityScanAt = record?.lastIntegrityScanAt
    }

    var healthSignal: String? {
        gapDetected ? "AUDIT_APPEND_FAILED" : nil
    }

    func isIntegrityScanDue(
        at date: Date,
        successInterval: TimeInterval,
        retryInterval: TimeInterval
    ) -> Bool {
        if let lastIntegrityScanAt,
           date.timeIntervalSince(lastIntegrityScanAt) < successInterval {
            return false
        }
        if let lastIntegrityScanAttemptAt,
           date.timeIntervalSince(lastIntegrityScanAttemptAt) < retryInterval {
            return false
        }
        return true
    }

    mutating func recordAppendFailure(at date: Date) {
        gapDetected = true
        if lastFailureAt == nil {
            lastFailureAt = date
        }
        persist()
    }

    mutating func recordAppendSuccess() {
        lastSuccessfulSequence &+= 1
        persist()
    }

    mutating func recordIntegrityScanAttempt(at date: Date) {
        lastIntegrityScanAttemptAt = date
        persist()
    }

    mutating func recordIntegrityScanSuccess(at date: Date) {
        lastIntegrityScanAt = date
        persist()
    }

    private func persist() {
        guard let url else { return }
        let record = CatalogAuditHealthRecord(
            schemaVersion: CatalogAuditHealthRecord.currentSchemaVersion,
            lastFailureAt: lastFailureAt,
            gapDetected: gapDetected,
            lastSuccessfulSequence: lastSuccessfulSequence,
            lastIntegrityScanAttemptAt: lastIntegrityScanAttemptAt,
            lastIntegrityScanAt: lastIntegrityScanAt
        )
        do {
            let parentURL = url.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: parentURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: parentURL.path
            )
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(record)
            try data.write(to: url, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: url.path
            )
        } catch {
            Logger(subsystem: "com.agent-secret-vault.SVLT", category: "audit")
                .error("AUDIT_HEALTH_PERSIST_FAILED")
        }
    }

    private static func load(from url: URL?) -> CatalogAuditHealthRecord? {
        guard let url,
              let data = try? Data(contentsOf: url),
              let record = try? JSONDecoder().decode(CatalogAuditHealthRecord.self, from: data),
              record.schemaVersion == CatalogAuditHealthRecord.currentSchemaVersion
        else {
            return nil
        }
        return record
    }
}
