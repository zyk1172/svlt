import Foundation
import LocalAuthentication
import Testing
@testable import VaultAuthorization
import VaultCore
@testable import AgentSecretVaultApp

@Test func lowProtectionKeyIsUnlockedOnceAndReused() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x41, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    let first = try await protectionKeyStore.deviceKey(for: .read, reason: "Restore low protection")
    let second = try await protectionKeyStore.deviceKey(for: .read, reason: "Encrypt low protection")

    #expect(first == Data(repeating: 0x41, count: 32))
    #expect(second == Data(repeating: 0x41, count: 32))
    #expect(await deviceKeyStore.reasons == ["打开知识库密文保险箱"])
    #expect(await protectionKeyStore.isLowProtectionUnlocked)
}

@Test func clearingLowProtectionUnlockRelocksReadAccess() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x43, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    #expect(await protectionKeyStore.isLowProtectionUnlocked)
    await protectionKeyStore.clearLowProtectionUnlock()
    #expect(!(await protectionKeyStore.isLowProtectionUnlocked))

    _ = try await protectionKeyStore.deviceKey(for: .read, reason: "Unlock read after clearing")
    #expect(await deviceKeyStore.reasons == [
        "打开知识库密文保险箱",
        "打开知识库密文保险箱"
    ])
}

@Test func highProtectionStillRequestsFreshDeviceAuthorization() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x42, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    try await protectionKeyStore.unlockLowProtection()
    _ = try await protectionKeyStore.deviceKey(for: .credential, reason: "Reveal credential")
    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "Send externally")

    #expect(await deviceKeyStore.reasons == [
        "打开知识库密文保险箱",
        "Reveal credential",
        "Send externally"
    ])
}

@Test func externalSendWrappingKeyCacheWorksWithoutDestination() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x46, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(
        deviceKeyStore: deviceKeyStore,
        externalSendTTL: 60
    )

    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "first external send")
    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "second external send")

    #expect(await deviceKeyStore.reasons == ["first external send"])

    await protectionKeyStore.clearAll()
    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "after security invalidation")

    #expect(await deviceKeyStore.reasons == [
        "first external send",
        "after security invalidation"
    ])
}

@Test func freshExternalSendBypassesAndClearsTheWrappingKeyCache() async throws {
    let deviceKeyStore = CountingDeviceKeyStore(keyData: Data(repeating: 0x47, count: 32))
    let protectionKeyStore = AppProtectionKeyStore(
        deviceKeyStore: deviceKeyStore,
        externalSendTTL: 60
    )

    _ = try await protectionKeyStore.deviceKey(for: .externalSend, reason: "ordinary")
    _ = try await protectionKeyStore.freshDeviceKey(for: .externalSend, reason: "high risk")

    #expect(await deviceKeyStore.reasons == ["ordinary", "high risk"])
}

@Test func protectionKeyStoreCachesOnlyTheCandidateSelectedByVaultVerification() async throws {
    let rejectedKey = Data(repeating: 0x51, count: 32)
    let acceptedKey = Data(repeating: 0x52, count: 32)
    let deviceKeyStore = CandidateDeviceKeyStore(candidates: [rejectedKey, acceptedKey])
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)

    #expect(try await protectionKeyStore.deviceKeyCandidates(
        for: .read,
        reason: "Open vault"
    ) == [rejectedKey, acceptedKey])
    await protectionKeyStore.rememberDeviceKey(acceptedKey, for: .read)

    #expect(try await protectionKeyStore.deviceKey(
        for: .read,
        reason: "Open vault"
    ) == acceptedKey)
    #expect(await deviceKeyStore.candidateRequestCount == 1)
}

@Test func protectionKeyStoreForwardsTheCurrentOperationAuthenticationContext() async throws {
    let expectedKey = Data(repeating: 0x53, count: 32)
    let deviceKeyStore = ContextRecordingDeviceKeyStore(keyData: expectedKey)
    let protectionKeyStore = AppProtectionKeyStore(deviceKeyStore: deviceKeyStore)
    let context = LocalAuthenticationContext(rawContext: LAContext())

    #expect(try await protectionKeyStore.deviceKeyCandidates(
        for: .credential,
        reason: "运行 SSH 命令",
        authenticationContext: context
    ) == [expectedKey])
    #expect(await deviceKeyStore.receivedContext === context)
}

private actor CountingDeviceKeyStore: DeviceKeyStoring {
    private let keyData: Data
    private(set) var reasons: [String] = []

    init(keyData: Data) {
        self.keyData = keyData
    }

    func deviceKey(reason: String) async throws -> Data {
        reasons.append(reason)
        return keyData
    }
}

private actor CandidateDeviceKeyStore: DeviceKeyStoring {
    private let candidates: [Data]
    private(set) var candidateRequestCount = 0

    init(candidates: [Data]) {
        self.candidates = candidates
    }

    func deviceKey(reason: String) async throws -> Data {
        candidates[0]
    }

    func deviceKeyCandidates(reason: String) async throws -> [Data] {
        candidateRequestCount += 1
        return candidates
    }
}

private actor ContextRecordingDeviceKeyStore: DeviceKeyStoring {
    private let keyData: Data
    private(set) var receivedContext: LocalAuthenticationContext?

    init(keyData: Data) {
        self.keyData = keyData
    }

    func deviceKey(reason _: String) async throws -> Data {
        keyData
    }

    func deviceKeyCandidates(
        reason _: String,
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        receivedContext = authenticationContext
        return [keyData]
    }
}
