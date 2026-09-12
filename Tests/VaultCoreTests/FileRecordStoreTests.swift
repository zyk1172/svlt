import Foundation
import Testing
@testable import VaultCore

private let validRecordID = "01JABCDEF0123456789ABCDEFG"

@Test func savingCreatesFirstVersionSidecar() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let record = makeRecord(version: 1)

    try await store.save(record)

    let expectedURL = baseDirectory
        .appendingPathComponent(".agent-secret-vault")
        .appendingPathComponent("records")
        .appendingPathComponent(validRecordID)
        .appendingPathComponent("00000001.json")
    #expect(FileManager.default.fileExists(atPath: expectedURL.path))
    #expect(try permissions(of: baseDirectory.appendingPathComponent(".agent-secret-vault")) == 0o700)
    #expect(try permissions(of: baseDirectory.appendingPathComponent(".agent-secret-vault/records")) == 0o700)
    #expect(try permissions(of: expectedURL.deletingLastPathComponent()) == 0o700)
    #expect(try permissions(of: expectedURL) == 0o600)
    #expect(try await store.versions(id: validRecordID) == [1])
}

@Test func loadingLatestFailsWhenHighestDiscoveredVersionIsCorrupt() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let first = makeRecord(version: 1)
    let second = makeRecord(version: 2)

    try await store.save(first)
    try await store.save(second)
    try Data("not json".utf8).write(to: versionURL(baseDirectory: baseDirectory, version: 3))

    do {
        _ = try await store.latest(id: validRecordID)
        Issue.record("Expected the corrupt highest version to make latest unavailable.")
    } catch let error as FileRecordStoreError {
        #expect(error == .latestVersionCorrupt(version: 3))
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    #expect(try await store.versions(id: validRecordID) == [1, 2])
}

@Test func corruptingSavedLatestVersionDoesNotFallBackToPriorVersion() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)

    try await store.save(makeRecord(version: 1))
    try await store.save(makeRecord(version: 2))
    try Data("truncated".utf8).write(to: versionURL(baseDirectory: baseDirectory, version: 2))

    do {
        _ = try await store.latest(id: validRecordID)
        Issue.record("Expected latest to fail instead of silently returning version 1.")
    } catch let error as FileRecordStoreError {
        #expect(error == .latestVersionCorrupt(version: 2))
    } catch {
        Issue.record("Unexpected error: \(error)")
    }

    #expect(try await store.versions(id: validRecordID) == [1])
}

@Test func failedReplacementDoesNotSilentlyFallBackToPriorVersion() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let prior = makeRecord(version: 1)

    try await store.save(prior)
    try FileManager.default.createDirectory(
        at: versionURL(baseDirectory: baseDirectory, version: 2),
        withIntermediateDirectories: false
    )

    do {
        try await store.save(makeRecord(version: 2))
        Issue.record("Expected save to fail when final version path cannot be replaced.")
    } catch {
        #expect(try await store.versions(id: validRecordID) == [1])
    }

    do {
        _ = try await store.latest(id: validRecordID)
        Issue.record("Expected invalid version 2 path to make latest unavailable.")
    } catch let error as FileRecordStoreError {
        #expect(error == .latestVersionCorrupt(version: 2))
    } catch {
        Issue.record("Unexpected error: \(error)")
    }
}

@Test func deleteRemovesAllVersionsAndReference() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)

    try await store.save(makeRecord(version: 1))
    try await store.save(makeRecord(version: 2))
    try await store.delete(id: validRecordID)

    #expect(try await store.versions(id: validRecordID).isEmpty)
    #expect(try await store.recordIDs().isEmpty)
    do {
        _ = try await store.latest(id: validRecordID)
        Issue.record("Expected deleted record to be unavailable.")
    } catch {
        #expect(true)
    }
}

@Test func pathTraversalIDsAreRejected() async throws {
    let baseDirectory = try makeTemporaryDirectory()
    let store = FileRecordStore(baseDirectory: baseDirectory)
    let traversalRecord = makeRecord(id: "../outside", version: 1)

    do {
        try await store.save(traversalRecord)
        Issue.record("Expected path traversal ID to be rejected.")
    } catch {
        #expect(!FileManager.default.fileExists(
            atPath: baseDirectory.appendingPathComponent("outside").path
        ))
    }
}

private func makeTemporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("FileRecordStoreTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

private func versionURL(baseDirectory: URL, version: Int) -> URL {
    baseDirectory
        .appendingPathComponent(".agent-secret-vault")
        .appendingPathComponent("records")
        .appendingPathComponent(validRecordID)
        .appendingPathComponent(String(format: "%08d.json", version))
}

private func permissions(of url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1
}

private func makeRecord(
    id: String = validRecordID,
    version: Int
) -> EncryptedRecord {
    EncryptedRecord(
        formatVersion: VaultFormat.current,
        id: id,
        recordVersion: version,
        ciphertext: Data([0x01, UInt8(version)]),
        nonce: Data([0x02, UInt8(version)]),
        tag: Data([0x03, UInt8(version)]),
        wrappedDataKey: Data([0x04, UInt8(version)]),
        wrappedDataKeyNonce: Data([0x05, UInt8(version)]),
        wrappedDataKeyTag: Data([0x06, UInt8(version)]),
        label: "label-\(version)",
        policy: .credential,
        createdAt: Date(timeIntervalSinceReferenceDate: 1_234_567.25),
        updatedAt: Date(timeIntervalSinceReferenceDate: 1_234_567.5 + Double(version))
    )
}
