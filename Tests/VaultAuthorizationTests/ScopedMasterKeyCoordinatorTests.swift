import CryptoKit
import Foundation
import Testing
import VaultAuthorization
import VaultService

private let coordinatorTestScope = ExecutionAuthorizationScope(
    principal: "agent",
    secretReferenceIDs: ["secret://0123456789ABCDEFGHJKMNPQRS"],
    normalizedDestination: "qnap.local",
    port: 22,
    protocolType: "ssh",
    actionFamily: "sshCommand",
    generation: 1
)

@Test func scopedMasterKeyCoordinatorReusesOnlyAnActiveCapturedKey() async throws {
    let invalidations = InvalidationRecorder()
    let coordinator = ScopedMasterKeyCoordinator { scope in
        await invalidations.record(scope)
    }
    let lease = LeaseState(active: true)
    let capturedKey = SymmetricKey(data: Data(repeating: 0x31, count: 32))
    let replacementKey = SymmetricKey(data: Data(repeating: 0x32, count: 32))

    await coordinator.storeAuthorizedKey(
        capturedKey,
        for: coordinatorTestScope,
        duration: 60
    )
    let reused = try await coordinator.resolveKey(
        for: coordinatorTestScope,
        isLeaseActive: { await lease.isActive },
        load: { replacementKey }
    )
    #expect(keyData(reused) == keyData(capturedKey))
    #expect(await invalidations.count == 0)

    await lease.setActive(false)
    let refreshed = try await coordinator.resolveKey(
        for: coordinatorTestScope,
        isLeaseActive: { await lease.isActive },
        load: { replacementKey }
    )
    #expect(keyData(refreshed) == keyData(replacementKey))
    #expect(await invalidations.count == 1)
    #expect(await coordinator.hasAuthorization(for: coordinatorTestScope) == false)
}

@Test func scopedMasterKeyCoordinatorSharesOneInFlightLoad() async throws {
    let coordinator = ScopedMasterKeyCoordinator { _ in }
    let gate = KeyLoadGate()
    let key = SymmetricKey(data: Data(repeating: 0x33, count: 32))

    let first = Task {
        try await coordinator.resolveKey(
            for: coordinatorTestScope,
            isLeaseActive: { false },
            load: {
                try await gate.load(key)
            }
        )
    }
    await gate.waitForStart()

    let second = Task {
        try await coordinator.resolveKey(
            for: coordinatorTestScope,
            isLeaseActive: { false },
            load: {
                try await gate.load(key)
            }
        )
    }
    await gate.release()

    let firstKey = try await first.value
    let secondKey = try await second.value
    #expect(keyData(firstKey) == keyData(key))
    #expect(keyData(secondKey) == keyData(key))
    #expect(await gate.loadCount == 1)
}

@Test func scopedMasterKeyCoordinatorExpiresAndInvalidatesTheMatchingLease() async throws {
    let invalidations = InvalidationRecorder()
    let coordinator = ScopedMasterKeyCoordinator { scope in
        await invalidations.record(scope)
    }
    let key = SymmetricKey(data: Data(repeating: 0x34, count: 32))

    await coordinator.storeAuthorizedKey(
        key,
        for: coordinatorTestScope,
        duration: 0.01
    )
    try await Task.sleep(for: .milliseconds(100))

    #expect(await coordinator.hasAuthorization(for: coordinatorTestScope) == false)
    #expect(await invalidations.count == 1)
}

private func keyData(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes { Data($0) }
}

private actor LeaseState {
    private(set) var isActive: Bool

    init(active: Bool) {
        self.isActive = active
    }

    func setActive(_ active: Bool) {
        isActive = active
    }
}

private actor InvalidationRecorder {
    private(set) var scopes: [ExecutionAuthorizationScope] = []

    var count: Int { scopes.count }

    func record(_ scope: ExecutionAuthorizationScope) {
        scopes.append(scope)
    }
}

private actor KeyLoadGate {
    private(set) var loadCount = 0
    private var released = false
    private var startContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func load(_ key: SymmetricKey) async throws -> SymmetricKey {
        loadCount += 1
        startContinuation?.resume()
        startContinuation = nil
        if !released {
            await withCheckedContinuation { continuation in
                releaseContinuation = continuation
            }
        }
        return key
    }

    func waitForStart() async {
        guard loadCount == 0 else { return }
        await withCheckedContinuation { continuation in
            startContinuation = continuation
        }
    }

    func release() {
        released = true
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}
