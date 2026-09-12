import CryptoKit
import Foundation
import Testing
import VaultCore
import VaultIPC
@testable import VaultService

@Test func statusAuditUsesIndependentKeyAndNeverRequestsVaultMasterKey() async throws {
    let auditDirectory = FileManager.default.temporaryDirectory
        .appending(path: "svlt-audit-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: auditDirectory)
    }

    let masterCalls = AuditCallCounter()
    let auditCalls = AuditCallCounter()
    let auditKey = SymmetricKey(data: Data(repeating: 0xA7, count: 32))
    let auditLog = EncryptedAuditLog(
        directoryURL: auditDirectory,
        auditKeyProvider: {
            await auditCalls.increment()
            return auditKey
        }
    )
    let service = VaultAppServices(
        textEncryptor: AuditTestTextEncryptor(),
        activeRoot: nil,
        masterKeyProvider: { _, _ in
            await masterCalls.increment()
            return SymmetricKey(data: Data(repeating: 0xB8, count: 32))
        },
        auditLog: auditLog
    )

    await service.recordPluginActivity()
    _ = await service.status()

    #expect(await masterCalls.count == 0)
    #expect(await auditCalls.count == 0)

    try await auditLog.append(AuditEvent(
        timestamp: Date(),
        integration: "test",
        referenceID: nil,
        operation: .status,
        risk: 0,
        authorizationOutcome: .notRequired,
        declaredTarget: "status",
        status: .completed,
        exitCode: nil
    ))
    #expect(await masterCalls.count == 0)
    #expect(await auditCalls.count == 1)
    #expect((try await auditLog.export()).count == 1)
}

@Test func auditHealthStorePersistsStickyGapAndSuccessSequence() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-health-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let healthURL = root.appendingPathComponent("audit-health.json")
    let firstFailureAt = Date(timeIntervalSinceReferenceDate: 42_000)
    var store = CatalogAuditHealthStore(url: healthURL)

    #expect(store.healthSignal == nil)
    #expect(store.lastSuccessfulSequence == 0)

    store.recordAppendFailure(at: firstFailureAt)
    store.recordAppendFailure(at: firstFailureAt.addingTimeInterval(30))
    store.recordAppendSuccess()
    store.recordAppendSuccess()

    #expect(store.healthSignal == "AUDIT_APPEND_FAILED")
    #expect(store.lastFailureAt == firstFailureAt)
    #expect(store.lastSuccessfulSequence == 2)

    let restored = CatalogAuditHealthStore(url: healthURL)
    #expect(restored.healthSignal == "AUDIT_APPEND_FAILED")
    #expect(restored.lastFailureAt == firstFailureAt)
    #expect(restored.lastSuccessfulSequence == 2)

    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: healthURL.path)
    #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test func auditHealthStoreRejectsUnknownSchema() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-health-schema-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let healthURL = root.appendingPathComponent("audit-health.json")
    let unsupported = CatalogAuditHealthRecord(
        schemaVersion: CatalogAuditHealthRecord.currentSchemaVersion + 1,
        lastFailureAt: Date(timeIntervalSinceReferenceDate: 10),
        gapDetected: true,
        lastSuccessfulSequence: 99
    )
    try JSONEncoder().encode(unsupported).write(to: healthURL, options: [.atomic])

    let store = CatalogAuditHealthStore(url: healthURL)

    #expect(store.healthSignal == nil)
    #expect(store.lastFailureAt == nil)
    #expect(store.lastSuccessfulSequence == 0)
}

private struct AuditTestTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private actor AuditCallCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}
