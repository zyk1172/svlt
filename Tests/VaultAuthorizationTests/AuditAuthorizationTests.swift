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

@Test func auditHealthStorePersistsStickyGapSuccessSequenceAndMaintenanceCadence() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-health-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let healthURL = root.appendingPathComponent("audit-health.json")
    let firstFailureAt = Date(timeIntervalSinceReferenceDate: 42_000)
    let scanAttemptAt = Date(timeIntervalSinceReferenceDate: 43_000)
    let scanCompletedAt = Date(timeIntervalSinceReferenceDate: 43_010)
    var store = CatalogAuditHealthStore(url: healthURL)

    #expect(store.healthSignal == nil)
    #expect(store.lastSuccessfulSequence == 0)
    #expect(store.lastIntegrityScanAttemptAt == nil)
    #expect(store.lastIntegrityScanAt == nil)

    store.recordAppendFailure(at: firstFailureAt)
    store.recordAppendFailure(at: firstFailureAt.addingTimeInterval(30))
    store.recordAppendSuccess()
    store.recordAppendSuccess()
    store.recordIntegrityScanAttempt(at: scanAttemptAt)
    store.recordIntegrityScanSuccess(at: scanCompletedAt)

    #expect(store.healthSignal == "AUDIT_APPEND_FAILED")
    #expect(store.lastFailureAt == firstFailureAt)
    #expect(store.lastSuccessfulSequence == 2)
    #expect(store.lastIntegrityScanAttemptAt == scanAttemptAt)
    #expect(store.lastIntegrityScanAt == scanCompletedAt)

    let restored = CatalogAuditHealthStore(url: healthURL)
    #expect(restored.healthSignal == "AUDIT_APPEND_FAILED")
    #expect(restored.lastFailureAt == firstFailureAt)
    #expect(restored.lastSuccessfulSequence == 2)
    #expect(restored.lastIntegrityScanAttemptAt == scanAttemptAt)
    #expect(restored.lastIntegrityScanAt == scanCompletedAt)

    let directoryAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
    let fileAttributes = try FileManager.default.attributesOfItem(atPath: healthURL.path)
    #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
}

@Test func auditHealthStoreLoadsLegacySchemaWithoutMaintenanceFields() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-health-legacy-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    let healthURL = root.appendingPathComponent("audit-health.json")
    let legacyObject: [String: Any] = [
        "schemaVersion": CatalogAuditHealthRecord.currentSchemaVersion,
        "lastFailureAt": NSNull(),
        "gapDetected": false,
        "lastSuccessfulSequence": 7
    ]
    try JSONSerialization.data(withJSONObject: legacyObject, options: [.sortedKeys])
        .write(to: healthURL, options: [.atomic])

    let store = CatalogAuditHealthStore(url: healthURL)

    #expect(store.healthSignal == nil)
    #expect(store.lastSuccessfulSequence == 7)
    #expect(store.lastIntegrityScanAttemptAt == nil)
    #expect(store.lastIntegrityScanAt == nil)
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
    #expect(store.lastIntegrityScanAttemptAt == nil)
    #expect(store.lastIntegrityScanAt == nil)
}

@Test func auditIntegrityMaintenanceIsLowFrequencyAcrossCoordinatorRestart() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-maintenance-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditDirectory = root.appendingPathComponent("audit", isDirectory: true)
    let healthURL = root.appendingPathComponent("audit-health.json")
    let clock = AuditMaintenanceClock(Date(timeIntervalSinceReferenceDate: 50_000))
    let keyCalls = AuditCallCounter()
    let auditKey = SymmetricKey(data: Data(repeating: 0xC9, count: 32))
    let auditLog = EncryptedAuditLog(
        directoryURL: auditDirectory,
        auditKeyProvider: {
            await keyCalls.increment()
            return auditKey
        }
    )

    var coordinator: CatalogAuditPersistenceCoordinator? = CatalogAuditPersistenceCoordinator(
        auditLog: auditLog,
        auditHealthURL: healthURL,
        fallbackMasterKey: nil,
        now: { clock.now() },
        integrityScanInterval: 86_400,
        integrityScanRetryInterval: 3_600
    )

    #expect(await coordinator?.healthSignal() == nil)
    #expect(await waitForIntegrityScan(healthURL: healthURL, expectedAt: clock.now()))
    #expect(await keyCalls.count == 1)

    // Recreate the coordinator to verify that the success timestamp persisted
    // across daemon lifetime rather than existing only in actor memory.
    coordinator = nil
    clock.advance(by: 3_600)
    coordinator = CatalogAuditPersistenceCoordinator(
        auditLog: auditLog,
        auditHealthURL: healthURL,
        fallbackMasterKey: nil,
        now: { clock.now() },
        integrityScanInterval: 86_400,
        integrityScanRetryInterval: 3_600
    )
    #expect(await coordinator?.healthSignal() == nil)
    try? await Task.sleep(for: .milliseconds(30))
    #expect(await keyCalls.count == 1)
    #expect(CatalogAuditHealthStore(url: healthURL).lastIntegrityScanAttemptAt == Date(timeIntervalSinceReferenceDate: 50_000))

    clock.advance(by: 82_801)
    let secondScanAt = clock.now()
    #expect(await coordinator?.healthSignal() == nil)
    #expect(await waitForIntegrityScan(healthURL: healthURL, expectedAt: secondScanAt))
    #expect(await keyCalls.count == 2)
}

@Test func auditIntegrityMaintenanceBacksOffAfterFailure() async throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-audit-maintenance-failure-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let auditDirectory = root.appendingPathComponent("audit", isDirectory: true)
    let healthURL = root.appendingPathComponent("audit-health.json")
    let clock = AuditMaintenanceClock(Date(timeIntervalSinceReferenceDate: 60_000))
    let keyCalls = AuditCallCounter()
    let auditLog = EncryptedAuditLog(
        directoryURL: auditDirectory,
        auditKeyProvider: {
            await keyCalls.increment()
            throw EncryptedAuditLogError.auditKeyUnavailable
        }
    )
    let coordinator = CatalogAuditPersistenceCoordinator(
        auditLog: auditLog,
        auditHealthURL: healthURL,
        fallbackMasterKey: nil,
        now: { clock.now() },
        integrityScanInterval: 86_400,
        integrityScanRetryInterval: 3_600
    )

    _ = await coordinator.healthSignal()
    #expect(await waitForAuditCallCount(keyCalls, atLeast: 1))
    #expect(CatalogAuditHealthStore(url: healthURL).lastIntegrityScanAttemptAt == clock.now())
    #expect(CatalogAuditHealthStore(url: healthURL).lastIntegrityScanAt == nil)

    clock.advance(by: 1_800)
    _ = await coordinator.healthSignal()
    try? await Task.sleep(for: .milliseconds(30))
    #expect(await keyCalls.count == 1)

    clock.advance(by: 1_801)
    _ = await coordinator.healthSignal()
    #expect(await waitForAuditCallCount(keyCalls, atLeast: 2))
    #expect(CatalogAuditHealthStore(url: healthURL).lastIntegrityScanAttemptAt == clock.now())
}

private func waitForIntegrityScan(healthURL: URL, expectedAt: Date) async -> Bool {
    for _ in 0..<100 {
        if CatalogAuditHealthStore(url: healthURL).lastIntegrityScanAt == expectedAt {
            return true
        }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
}

private func waitForAuditCallCount(_ counter: AuditCallCounter, atLeast expected: Int) async -> Bool {
    for _ in 0..<100 {
        if await counter.count >= expected {
            return true
        }
        try? await Task.sleep(for: .milliseconds(10))
    }
    return false
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

private final class AuditMaintenanceClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date

    init(_ value: Date) {
        self.value = value
    }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by interval: TimeInterval) {
        lock.lock()
        value = value.addingTimeInterval(interval)
        lock.unlock()
    }
}
