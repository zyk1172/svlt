import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import AgentSecretVaultApp

@Test func resolverDecryptsInternallyByReference() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 7, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_RESOLVER".utf8),
        id: "0123456789ABCDEFGHJKMNPQRS",
        version: 1,
        label: nil,
        policy: .credential,
        masterKey: key
    )
    try await store.save(record)

    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let plaintext = try await resolver.resolve(
        reference: "secret://0123456789ABCDEFGHJKMNPQRS",
        masterKey: key
    )
    #expect(String(decoding: plaintext, as: UTF8.self) == "ASV_CANARY_RESOLVER")
}

@Test func resolverReturnsReferenceMetadataWithoutDecrypting() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 9, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_METADATA_SHOULD_NOT_RETURN".utf8),
        id: "01J55555555555555555555555",
        version: 1,
        label: "NAS password",
        policy: .read,
        masterKey: key
    )
    try await store.save(record)

    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let metadata = try await resolver.metadata(reference: "secret://01J55555555555555555555555")

    #expect(metadata.reference == "secret://01J55555555555555555555555")
    #expect(metadata.policy == .read)
    #expect(metadata.label == "NAS password")
    #expect(metadata.createdAt == record.createdAt)
    #expect(metadata.updatedAt == record.updatedAt)
    #expect(String(describing: metadata).contains("ASV_CANARY_METADATA_SHOULD_NOT_RETURN") == false)
}

@Test func resolverBindsDestinationByResealingTheExistingRecord() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x2A, count: 32))
    let reference = try SecretReference("secret://01J55555555555555555555555")
    let record = try cipher.encrypt(
        Data("ASV_CANARY_BINDING_SECRET".utf8),
        id: reference.id,
        version: 1,
        label: "QNAP credential",
        policy: .credential,
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["ssh"],
        masterKey: key
    )
    try await store.save(record)

    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let reboundAt = Date(timeIntervalSinceReferenceDate: 4_000)
    let metadata = try await resolver.bindDestination(
        reference: reference.description,
        destination: "http://192.168.2.240:3000",
        protocolType: .http,
        masterKey: key,
        now: reboundAt
    )
    let rebound = try await store.latest(id: reference.id)

    #expect(metadata.allowedDestinations == ["qnap.local", "http://192.168.2.240:3000"])
    #expect(metadata.allowedProtocols == ["ssh", "http"])
    #expect(metadata.allowedBindings == [
        SecretDestinationBinding(protocolType: .ssh, destination: "qnap.local"),
        SecretDestinationBinding(protocolType: .http, destination: "http://192.168.2.240:3000")
    ])
    #expect(metadata.updatedAt == reboundAt)
    #expect(rebound.recordVersion == 2)
    #expect(try cipher.decrypt(rebound, masterKey: key) == Data("ASV_CANARY_BINDING_SECRET".utf8))

    let duplicate = try await resolver.bindDestination(
        reference: reference.description,
        destination: "192.168.2.240:3000",
        protocolType: .http,
        masterKey: key,
        now: Date(timeIntervalSinceReferenceDate: 5_000)
    )
    let afterDuplicate = try await store.latest(id: reference.id)
    #expect(duplicate == metadata)
    #expect(afterDuplicate.recordVersion == rebound.recordVersion)
    #expect(afterDuplicate.updatedAt == rebound.updatedAt)
}

@Test func resolverPreservesAndExplicitlyReplacesAnSSHHostKeyPin() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }

    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 0x3C, count: 32))
    let reference = try SecretReference("secret://01J55555555555555555555555")
    let record = try cipher.encrypt(
        Data("resolver pin metadata regression".utf8),
        id: reference.id,
        version: 1,
        label: "QNAP credential",
        policy: .credential,
        allowedDestinations: ["nas.local"],
        allowedProtocols: ["ssh"],
        masterKey: key
    )
    try await store.save(record)

    let firstPin = try resolverTestSSHHostKeyPin(seed: 0x40)
    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let pinned = try await resolver.bindDestination(
        reference: reference.description,
        destination: "nas.local",
        protocolType: .ssh,
        masterKey: key,
        port: 2222,
        hostKeyPin: firstPin
    )
    let pinnedRecord = try await store.latest(id: reference.id)
    let pinnedBinding = try #require(pinned.allowedBindings.first(where: {
        $0.port == 2222 && $0.hostKeyPin == firstPin
    }))
    #expect(pinnedBinding.destination == "nas.local")
    #expect(pinnedRecord.recordVersion == 2)

    let unchanged = try await resolver.bindDestination(
        reference: reference.description,
        destination: "nas.local",
        protocolType: .ssh,
        masterKey: key,
        port: 2222
    )
    let unchangedRecord = try await store.latest(id: reference.id)
    #expect(unchanged.allowedBindings == pinned.allowedBindings)
    #expect(unchangedRecord.recordVersion == pinnedRecord.recordVersion)

    let replacementPin = try resolverTestSSHHostKeyPin(seed: 0x41)
    let replaced = try await resolver.bindDestination(
        reference: reference.description,
        destination: "nas.local",
        protocolType: .ssh,
        masterKey: key,
        port: 2222,
        hostKeyPin: replacementPin
    )
    let replacedRecord = try await store.latest(id: reference.id)
    #expect(replaced.allowedBindings.contains {
        $0.port == 2222 && $0.hostKeyPin == replacementPin
    })
    #expect(!replaced.allowedBindings.contains {
        $0.port == 2222 && $0.hostKeyPin == firstPin
    })
    #expect(replacedRecord.recordVersion == 3)
}

private func resolverTestSSHHostKeyPin(seed: UInt8) throws -> SSHHostKeyPin {
    let digest = Data(SHA256.hash(data: Data(repeating: seed, count: 32)))
    let fingerprint = "SHA256:" + digest.base64EncodedString().replacingOccurrences(of: "=", with: "")
    return try SSHHostKeyPin(algorithm: "ssh-ed25519", sha256: fingerprint)
}

@Test func resolverRequestsMasterKeyForStoredRecordPolicy() async throws {
    let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    let store = FileRecordStore(baseDirectory: directory)
    let cipher = VaultCipher()
    let key = SymmetricKey(data: Data(repeating: 8, count: 32))
    let record = try cipher.encrypt(
        Data("ASV_CANARY_LOW_PROTECTION".utf8),
        id: "ABCDEFGHJKMNPQRSTVWXYZ0123",
        version: 1,
        label: nil,
        policy: .read,
        masterKey: key
    )
    try await store.save(record)

    let policies = PolicyRecorder()
    let resolver = VaultRecordResolver(recordStore: store, cipher: cipher)
    let plaintext = try await resolver.resolve(reference: "secret://ABCDEFGHJKMNPQRSTVWXYZ0123") { policy in
        await policies.append(policy)
        return key
    }

    #expect(String(decoding: plaintext, as: UTF8.self) == "ASV_CANARY_LOW_PROTECTION")
    #expect(await policies.values == [.read])
}

private actor PolicyRecorder {
    private(set) var values: [SecretPolicy] = []

    func append(_ policy: SecretPolicy) {
        values.append(policy)
    }
}
