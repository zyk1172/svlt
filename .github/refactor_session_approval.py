from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 occurrence, found {count}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, repl: str, label: str) -> str:
    out, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected 1 match, found {count}")
    return out


Path("Sources/VaultAuthorization/AuthorizationSession.swift").write_text(r'''import Foundation

/// In-memory authorization state owned by one running Agent. Reusable Agent
/// execution authorization is scoped to the current security session rather
/// than a timer: elapsed time alone never forces another owner approval.
/// The daemon clears it on sleep, screen lock, user/session changes, explicit
/// lock, security-state invalidation, and process restart.
public actor AuthorizationSession {
    private let readTTL: TimeInterval?
    private let credentialTTL: TimeInterval
    private let externalSendTTL: TimeInterval
    private let now: @Sendable () -> Date

    private var readAuthorized = false
    private var readExpiresAt: Date?
    private var credentialAuthorized = false
    private var credentialExpiresAt: Date?
    private var externalSendExpiresAt: [String: Date] = [:]
    private var executionAuthorizations: Set<ExecutionAuthorizationScope> = []
    private var singleUseAuthorizations: Set<RiskClass> = []

    public init(
        readTTL: TimeInterval? = nil,
        credentialTTL: TimeInterval = 600,
        externalSendTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.readTTL = readTTL
        self.credentialTTL = credentialTTL
        self.externalSendTTL = externalSendTTL
        self.now = now
    }

    public func authorizeRead() async {
        readAuthorized = true
        readExpiresAt = readTTL.map { now().addingTimeInterval($0) }
    }

    public func authorizeCredential() async {
        guard credentialTTL > 0 else {
            credentialAuthorized = false
            credentialExpiresAt = nil
            return
        }
        credentialAuthorized = true
        credentialExpiresAt = now().addingTimeInterval(credentialTTL)
    }

    public func authorizeExternalSend(destination: String) async {
        guard !destination.isEmpty, externalSendTTL > 0 else {
            return
        }
        externalSendExpiresAt[destination] = now().addingTimeInterval(externalSendTTL)
    }

    /// Grants one exact execution scope for the current Agent security
    /// session. There is intentionally no TTL and no sliding timer.
    public func authorizeExecution(for scope: ExecutionAuthorizationScope) {
        executionAuthorizations.insert(scope)
    }

    public func hasActiveExecutionAuthorization(for scope: ExecutionAuthorizationScope) -> Bool {
        executionAuthorizations.contains(scope)
    }

    public func invalidateExecutionAuthorization(for scope: ExecutionAuthorizationScope) {
        executionAuthorizations.remove(scope)
    }

    public func authorizeSingleUse(for risk: RiskClass) async {
        guard risk != .read else {
            await authorizeRead()
            return
        }
        singleUseAuthorizations.insert(risk)
    }

    public func consumeAuthorization(for risk: RiskClass) async -> Bool {
        switch risk {
        case .read:
            return consumeRead()
        case .writeOrExternalSend, .deleteOrCredentialChange:
            return singleUseAuthorizations.remove(risk) != nil
        }
    }

    public func consumeCredential() async -> Bool {
        guard credentialAuthorized else {
            return false
        }
        guard let credentialExpiresAt, now() < credentialExpiresAt else {
            credentialAuthorized = false
            self.credentialExpiresAt = nil
            return false
        }
        return true
    }

    public func consumeExternalSend(destination: String) async -> Bool {
        guard !destination.isEmpty,
              let expiresAt = externalSendExpiresAt[destination]
        else {
            return singleUseAuthorizations.remove(.writeOrExternalSend) != nil
        }
        guard now() < expiresAt else {
            externalSendExpiresAt[destination] = nil
            return false
        }
        return true
    }

    public func invalidate() async {
        readAuthorized = false
        readExpiresAt = nil
        credentialAuthorized = false
        credentialExpiresAt = nil
        externalSendExpiresAt.removeAll()
        executionAuthorizations.removeAll()
        singleUseAuthorizations.removeAll()
    }

    private func consumeRead() -> Bool {
        guard readAuthorized else {
            return false
        }
        if let readExpiresAt, now() >= readExpiresAt {
            readAuthorized = false
            self.readExpiresAt = nil
            return false
        }
        return true
    }
}
''', encoding="utf-8")

Path("Sources/VaultService/ScopedMasterKeyCoordinator.swift").write_text(r'''import CryptoKit
import Foundation
import VaultAuthorization

/// Coordinates the in-memory master-key capability that backs one scoped
/// execution authorization for the current Agent security session.
///
/// The coordinator owns only transient key material. It has no timer: a key
/// remains reusable only while the matching session authorization exists, and
/// is cleared on scope or wider security-state invalidation.
public actor ScopedMasterKeyCoordinator {
    private struct Authorization: Sendable {
        let key: SymmetricKey
    }

    private struct Flight: Sendable {
        let task: Task<SymmetricKey, Error>
    }

    private let invalidateExecutionAuthorization:
        @Sendable (ExecutionAuthorizationScope) async -> Void
    private var authorizations: [ExecutionAuthorizationScope: Authorization] = [:]
    private var flights: [ExecutionAuthorizationScope: Flight] = [:]

    public init(
        invalidateExecutionAuthorization: @escaping @Sendable (ExecutionAuthorizationScope) async -> Void
    ) {
        self.invalidateExecutionAuthorization = invalidateExecutionAuthorization
    }

    public func hasAuthorization(for scope: ExecutionAuthorizationScope) -> Bool {
        authorizations[scope] != nil
    }

    public func resolveKey(
        for scope: ExecutionAuthorizationScope,
        isAuthorizationActive: @escaping @Sendable () async -> Bool,
        load: @escaping @Sendable () async throws -> SymmetricKey
    ) async throws -> SymmetricKey {
        if await isAuthorizationActive(), let authorization = authorizations[scope] {
            return authorization.key
        }

        if let flight = flights[scope] {
            return try await flight.task.value
        }

        clearAuthorization(for: scope)
        let invalidateExecutionAuthorization = self.invalidateExecutionAuthorization
        let task = Task<SymmetricKey, Error> {
            await invalidateExecutionAuthorization(scope)
            try Task.checkCancellation()
            return try await load()
        }
        flights[scope] = Flight(task: task)
        do {
            let key = try await task.value
            // Retain the completed flight until the caller commits the matching
            // session authorization so concurrent callers share one approval.
            return key
        } catch {
            flights.removeValue(forKey: scope)
            throw error
        }
    }

    public func storeAuthorizedKey(
        _ key: SymmetricKey,
        for scope: ExecutionAuthorizationScope
    ) {
        clearAuthorization(for: scope)
        authorizations[scope] = Authorization(key: key)
        flights.removeValue(forKey: scope)
    }

    public func invalidateAll() {
        for flight in flights.values {
            flight.task.cancel()
        }
        flights.removeAll()
        for authorization in authorizations.values {
            wipe(authorization.key)
        }
        authorizations.removeAll()
    }

    public func abandon(scope: ExecutionAuthorizationScope) async {
        flights.removeValue(forKey: scope)?.task.cancel()
        clearAuthorization(for: scope)
        await invalidateExecutionAuthorization(scope)
    }

    private func clearAuthorization(for scope: ExecutionAuthorizationScope) {
        if let authorization = authorizations.removeValue(forKey: scope) {
            wipe(authorization.key)
        }
    }

    private func wipe(_ key: SymmetricKey) {
        var keyData = key.withUnsafeBytes { Data($0) }
        keyData.resetBytes(in: 0..<keyData.count)
    }
}
''', encoding="utf-8")

# Production daemon no longer exposes or wires an execution TTL.
p = Path("Sources/VaultService/VaultDaemonCore.swift")
s = p.read_text(encoding="utf-8")
s = replace_once(s, "    public let executionAuthorizationTTL: TimeInterval\n", "", "daemon execution TTL property")
s = replace_once(s, "        executionAuthorizationTTL: TimeInterval = 300,\n", "", "daemon execution TTL parameter")
s = replace_once(s, "        self.executionAuthorizationTTL = executionAuthorizationTTL\n", "", "daemon execution TTL assignment")
s = replace_once(
    s,
    "            authorizationSession: AuthorizationSession(\n                readTTL: configuration.readAuthorizationTTL,\n                credentialTTL: configuration.credentialAuthorizationTTL,\n                externalSendTTL: configuration.externalSendAuthorizationTTL,\n                executionTTL: configuration.executionAuthorizationTTL\n            ),",
    "            authorizationSession: AuthorizationSession(\n                readTTL: configuration.readAuthorizationTTL,\n                credentialTTL: configuration.credentialAuthorizationTTL,\n                externalSendTTL: configuration.externalSendAuthorizationTTL\n            ),",
    "daemon AuthorizationSession wiring",
)
p.write_text(s, encoding="utf-8")

# Keep the established reusable/fresh policy model and audit wire enum. Only
# remove the time-window mechanics from VaultAppServices.
p = Path("Sources/VaultService/VaultAppServices.swift")
s = p.read_text(encoding="utf-8")
s = s.replace("isExecutionLeaseEligible", "isExecutionReuseEligible")
s = regex_once(
    s,
    r"        let executorAction = isExecutionReuseEligible\(descriptor\.actionType\)\n(.*?)        let executionWindowEnabled: Bool\n        if executorAction \{\n            executionWindowEnabled = await authorizationSession\.executionAuthorizationWindowEnabled\(\)\n        \} else \{\n            executionWindowEnabled = false\n        \}\n        var executionScope: ExecutionAuthorizationScope\? = decision\.authorizationRequirement == \.reusableApproval && executionWindowEnabled\n            \? scopedAuthorizationScope\(for: descriptor, generation: operationGeneration\)\n            : nil\n",
    r"        let executionReuseEligible = isExecutionReuseEligible(descriptor.actionType)\n\1        var executionScope: ExecutionAuthorizationScope? = decision.authorizationRequirement == .reusableApproval && executionReuseEligible\n            ? scopedAuthorizationScope(for: descriptor, generation: operationGeneration)\n            : nil\n",
    "execution scope gating",
)
s = regex_once(
    s,
    r"        let executionWindowEnabled = await authorizationSession\.executionAuthorizationWindowEnabled\(\)\n        var scope: ExecutionAuthorizationScope\? = decision\.authorizationRequirement == \.reusableApproval && executionWindowEnabled\n            \? scopedAuthorizationScope\(for: descriptor, generation: operationGeneration\)\n            : nil\n",
    "        var scope: ExecutionAuthorizationScope? = decision.authorizationRequirement == .reusableApproval\n            ? scopedAuthorizationScope(for: descriptor, generation: operationGeneration)\n            : nil\n",
    "export scope gating",
)
s = replace_once(
    s,
    "            let executionWindowDuration = await authorizationSession.executionAuthorizationWindowDuration()\n            let summary = approvalSummary(\n                descriptor: descriptor,\n                metadata: metadata,\n                decision: decision,\n                executionWindowDuration: executionWindowDuration,\n                hostKeyReview: hostKeyReview\n            )",
    "            let summary = approvalSummary(\n                descriptor: descriptor,\n                metadata: metadata,\n                decision: decision,\n                hostKeyReview: hostKeyReview\n            )",
    "fresh execution approval summary",
)
s = replace_once(
    s,
    "        executionWindowDuration: TimeInterval? = nil,\n        hostKeyReview: SSHHostKeyReview? = nil",
    "        hostKeyReview: SSHHostKeyReview? = nil",
    "approvalSummary signature",
)
s = replace_once(
    s,
    "        guard let executionWindowDuration else {\n            return base\n        }\n        let seconds = executionWindowDuration.formatted(.number.precision(.fractionLength(0...3)))\n        return \"\\(base)；本次审批可在同一调用主体、同一凭据、同一目标、同一端口、同一协议及执行类型下复用最多 \\(seconds) 秒；不会授权其他凭据、目标或协议\"",
    "        guard decision.authorizationRequirement == .reusableApproval else {\n            return base\n        }\n        return \"\\(base)；本次审批可在当前 Agent 授权会话内，按同一调用主体、同一凭据、同一目标、同一端口、同一协议及执行类型复用；不设固定时间超时；锁屏、睡眠、用户会话切换、显式锁定、Agent 重启或安全状态变化后失效；不会授权其他凭据、目标或协议\"",
    "approvalSummary session wording",
)
s = s.replace("isLeaseActive:", "isAuthorizationActive:")
s = regex_once(
    s,
    r"    private func commitExecutionAuthorization\(\n        scope: ExecutionAuthorizationScope,\n        generation: UInt64,\n        masterKey: SymmetricKey\n    \) async throws -> ExecutionAuthorizationCommit \{.*?\n    \}\n\n    private func abandonExecutionAuthorization\(",
    '''    private func commitExecutionAuthorization(
        scope: ExecutionAuthorizationScope,
        generation: UInt64,
        masterKey: SymmetricKey
    ) async throws -> ExecutionAuthorizationCommit {
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(scope: scope) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard let flight = await secretOperationService.executionApprovalFlight(for: scope),
              flight.generation == generation
        else {
            return .needsFreshApproval
        }

        do {
            _ = try await flight.task.value
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }

        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(
                scope: scope,
                matching: flight.id
            ) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard await secretOperationService.executionApprovalFlight(for: scope)?.id == flight.id else {
            return .needsFreshApproval
        }

        await authorizationSession.authorizeExecution(for: scope)
        guard generation == securityGeneration else {
            await authorizationSession.invalidateExecutionAuthorization(for: scope)
            throw SecretOperationError.authorizationCancelled
        }

        await scopedMasterKeyCoordinator.storeAuthorizedKey(masterKey, for: scope)

        if await secretOperationService.removeExecutionApprovalFlight(
            scope: scope,
            matching: flight.id
        ) {
            await statusObserver?(status())
        }
        return .leaseEstablished
    }

    private func abandonExecutionAuthorization(''',
    "commit session authorization",
)
s = s.replace("case .leaseEstablished, .approvedWithoutLease:", "case .leaseEstablished:")
s = s.replace("    case approvedWithoutLease\n", "")
s = s.replace('action: "执行授权窗口复用"', 'action: "会话授权复用"')
s = s.replace(
    "/// Scoped Agent operations may reuse only the key material captured when\n    /// that exact scope acquired device-owner authorization. Falling back to\n    /// the broader credential cache here would let its independent TTL extend\n    /// an Agent authorization lease.",
    "/// Scoped Agent operations may reuse only the key material captured when\n    /// that exact scope acquired device-owner authorization. Falling back to\n    /// the broader credential cache here would bypass the Agent session\n    /// authorization boundary.",
)
p.write_text(s, encoding="utf-8")

# Preserve raw audit compatibility, update the human-facing label.
p = Path("Sources/VaultCore/Models/AuditEvent.swift")
s = p.read_text(encoding="utf-8")
s = replace_once(s, '        case .executionWindowReuse: return "执行授权窗口复用"', '        case .executionWindowReuse: return "会话授权复用"', "audit mode display")
p.write_text(s, encoding="utf-8")

# AuthorizationSession unit tests now prove elapsed time never revokes a grant.
Path("Tests/VaultAuthorizationTests/AuthorizationSessionTests.swift").write_text(r'''import Foundation
import Testing
@testable import VaultAuthorization

private let testExecutionScope = ExecutionAuthorizationScope(
    principal: "agent",
    secretReferenceIDs: ["secret://0123456789ABCDEFGHJKMNPQRS"],
    normalizedDestination: "qnap.local",
    port: 22,
    protocolType: "ssh",
    actionFamily: "sshCommand",
    generation: 7
)

@Test func readAuthorizationExpiresAtConfiguredTTL() async {
    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 1_000))
    let session = AuthorizationSession(readTTL: 300, now: { clock.now })
    await session.authorizeRead()
    #expect(await session.consumeAuthorization(for: .read))
    clock.now = Date(timeIntervalSinceReferenceDate: 1_300)
    #expect(await session.consumeAuthorization(for: .read) == false)
}

@Test func externalSendAuthorizationIsSingleUse() async {
    let session = AuthorizationSession()
    await session.authorizeSingleUse(for: .writeOrExternalSend)
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend))
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
}

@Test func executionAuthorizationDoesNotExpireWithElapsedTime() async {
    let clock = TestClock(Date(timeIntervalSinceReferenceDate: 2_000))
    let session = AuthorizationSession(now: { clock.now })
    await session.authorizeExecution(for: testExecutionScope)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
    clock.now = clock.now.addingTimeInterval(7 * 86_400)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
}

@Test func executionAuthorizationEndsOnScopeInvalidation() async {
    let session = AuthorizationSession()
    await session.authorizeExecution(for: testExecutionScope)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
    await session.invalidateExecutionAuthorization(for: testExecutionScope)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope) == false)
}

@Test func deleteAuthorizationIsSingleUse() async {
    let session = AuthorizationSession()
    await session.authorizeSingleUse(for: .deleteOrCredentialChange)
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange))
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

@Test func readAuthorizationCannotAuthorizeHigherRiskClass() async {
    let session = AuthorizationSession()
    await session.authorizeRead()
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
    #expect(await session.consumeAuthorization(for: .deleteOrCredentialChange) == false)
}

@Test func invalidateClearsAuthorizations() async {
    let session = AuthorizationSession()
    await session.authorizeRead()
    await session.authorizeSingleUse(for: .writeOrExternalSend)
    await session.authorizeExecution(for: testExecutionScope)
    await session.invalidate()
    #expect(await session.consumeAuthorization(for: .read) == false)
    #expect(await session.consumeAuthorization(for: .writeOrExternalSend) == false)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope) == false)
}

@Test func executionAuthorizationDoesNotCrossScopes() async {
    let session = AuthorizationSession()
    let otherScope = ExecutionAuthorizationScope(
        principal: "agent",
        secretReferenceIDs: ["secret://0123456789ABCDEFGHJKMNPQRT"],
        normalizedDestination: "other.local",
        port: 22,
        protocolType: "ssh",
        actionFamily: "sshCommand",
        generation: 7
    )
    await session.authorizeExecution(for: testExecutionScope)
    #expect(await session.hasActiveExecutionAuthorization(for: testExecutionScope))
    #expect(await session.hasActiveExecutionAuthorization(for: otherScope) == false)
}

private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date
    init(_ now: Date) { storedNow = now }
    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }
}
''', encoding="utf-8")

Path("Tests/VaultAuthorizationTests/ScopedMasterKeyCoordinatorTests.swift").write_text(r'''import CryptoKit
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
    let coordinator = ScopedMasterKeyCoordinator { scope in await invalidations.record(scope) }
    let state = AuthorizationState(active: true)
    let capturedKey = SymmetricKey(data: Data(repeating: 0x31, count: 32))
    let replacementKey = SymmetricKey(data: Data(repeating: 0x32, count: 32))

    await coordinator.storeAuthorizedKey(capturedKey, for: coordinatorTestScope)
    let reused = try await coordinator.resolveKey(
        for: coordinatorTestScope,
        isAuthorizationActive: { await state.isActive },
        load: { replacementKey }
    )
    #expect(keyData(reused) == keyData(capturedKey))
    #expect(await invalidations.count == 0)

    await state.setActive(false)
    let refreshed = try await coordinator.resolveKey(
        for: coordinatorTestScope,
        isAuthorizationActive: { await state.isActive },
        load: { replacementKey }
    )
    #expect(keyData(refreshed) == keyData(replacementKey))
    #expect(await invalidations.count == 1)
    #expect(await coordinator.hasAuthorization(for: coordinatorTestScope) == false)
}

@Test func scopedMasterKeyCoordinatorSharesOneInFlightInvalidationAndLoad() async throws {
    let invalidations = InvalidationRecorder()
    let coordinator = ScopedMasterKeyCoordinator { scope in await invalidations.record(scope) }
    let gate = KeyLoadGate()
    let key = SymmetricKey(data: Data(repeating: 0x33, count: 32))

    let first = Task {
        try await coordinator.resolveKey(
            for: coordinatorTestScope,
            isAuthorizationActive: { false },
            load: { try await gate.load(key) }
        )
    }
    await gate.waitForStart()
    let second = Task {
        try await coordinator.resolveKey(
            for: coordinatorTestScope,
            isAuthorizationActive: { false },
            load: { try await gate.load(key) }
        )
    }
    await gate.release()
    #expect(keyData(try await first.value) == keyData(key))
    #expect(keyData(try await second.value) == keyData(key))
    #expect(await gate.loadCount == 1)
    #expect(await invalidations.count == 1)
}

@Test func scopedMasterKeyCoordinatorHasNoTimeBasedExpiry() async throws {
    let invalidations = InvalidationRecorder()
    let coordinator = ScopedMasterKeyCoordinator { scope in await invalidations.record(scope) }
    let key = SymmetricKey(data: Data(repeating: 0x34, count: 32))
    await coordinator.storeAuthorizedKey(key, for: coordinatorTestScope)
    try await Task.sleep(for: .milliseconds(100))
    #expect(await coordinator.hasAuthorization(for: coordinatorTestScope))
    #expect(await invalidations.count == 0)
    await coordinator.abandon(scope: coordinatorTestScope)
    #expect(await coordinator.hasAuthorization(for: coordinatorTestScope) == false)
    #expect(await invalidations.count == 1)
}

private func keyData(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

private actor AuthorizationState {
    private(set) var isActive: Bool
    init(active: Bool) { isActive = active }
    func setActive(_ active: Bool) { isActive = active }
}

private actor InvalidationRecorder {
    private(set) var scopes: [ExecutionAuthorizationScope] = []
    var count: Int { scopes.count }
    func record(_ scope: ExecutionAuthorizationScope) { scopes.append(scope) }
}

private actor KeyLoadGate {
    private(set) var loadCount = 0
    private var released = false
    private var startContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?
    func load(_ key: SymmetricKey) async throws -> SymmetricKey {
        loadCount += 1
        startContinuation?.resume(); startContinuation = nil
        if !released {
            await withCheckedContinuation { releaseContinuation = $0 }
        }
        return key
    }
    func waitForStart() async {
        guard loadCount == 0 else { return }
        await withCheckedContinuation { startContinuation = $0 }
    }
    func release() {
        released = true
        releaseContinuation?.resume(); releaseContinuation = nil
    }
}
''', encoding="utf-8")

# Daemon config test must no longer expose execution TTL.
p = Path("Tests/VaultAuthorizationTests/VaultDaemonCoreTests.swift")
s = p.read_text(encoding="utf-8")
s = regex_once(
    s,
    r"@Test func daemonConfigurationKeepsExecutionAuthorizationTTLIndependent\(\) \{.*?\n\}\n\n",
    '''@Test func daemonConfigurationKeepsCredentialAndExternalSendTTLs() {
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: URL(filePath: "/tmp/svlt-config-vault"),
        auditRootURL: URL(filePath: "/tmp/svlt-config-audit"),
        ipcConfiguration: UnixSocketServerConfiguration(
            directoryURL: URL(filePath: "/tmp/svlt-config-ipc")
        ),
        credentialAuthorizationTTL: 600,
        externalSendAuthorizationTTL: 60
    )
    #expect(configuration.credentialAuthorizationTTL == 600)
    #expect(configuration.externalSendAuthorizationTTL == 60)
}

''',
    "daemon config test",
)
p.write_text(s, encoding="utf-8")

# Service tests: replace the timer-specific behavioral tests and remove obsolete
# initializer arguments everywhere else.
p = Path("Tests/VaultAuthorizationTests/SecretOperationServiceTests.swift")
s = p.read_text(encoding="utf-8")
s = regex_once(
    s,
    r"@Test func executionApprovalExplainsItsScopedReuseWindow\(\) async throws \{.*?\n\}\n\n",
    '''@Test func executionApprovalExplainsItsSessionScopedReuse() async throws {
    let fixture = try await OperationServiceFixture(approval: .allow)
    defer { fixture.remove() }
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    )
    let summary = await fixture.approver.summaries.first ?? ""
    #expect(summary.contains("当前 Agent 授权会话"))
    #expect(summary.contains("不设固定时间超时"))
    #expect(summary.contains("锁屏、睡眠"))
    #expect(summary.contains("不会授权其他凭据、目标或协议"))
    #expect(!summary.contains("300 秒"))
}

''',
    "approval summary test",
)
s = s.replace("@Test func failedScopedOperationKeepsOwnerAuthorizationUntilExpiry() async throws {", "@Test func failedScopedOperationKeepsOwnerAuthorizationUntilSessionInvalidation() async throws {")
s = s.replace("// §10/§11: the 300-second lease records that the owner authorized this\n    // scope. A remote execution failure is reported honestly but never\n    // revokes the owner's decision.", "// The session-scoped grant records that the owner authorized this scope.\n    // A remote execution failure is reported honestly but never revokes it.")
s = regex_once(
    s,
    r"@Test func eligibleSecretOperationsReuseExecutionAuthorizationUntilExpiry\(\) async throws \{.*?\n\}\n\n@Test func boundedFilesystemDeletionWithoutJudgeReviewRequiresFreshApproval",
    '''@Test func eligibleSecretOperationsReuseExecutionAuthorizationWithoutTimeExpiry() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 3_000)
    let clock = ServiceTestClock(start)
    let authorizationSession = AuthorizationSession(now: { clock.now })
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        now: { clock.now }
    )
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    )
    let scope = fixture.executionScope()
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))

    clock.now = start.addingTimeInterval(7 * 86_400)
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "touch /share/svlt-test", agentRisk: .approvalRequired)
    )
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
    let modes = await fixture.auditEntries().compactMap(\\.authorizationMode)
    #expect(modes.contains(.freshLocalApproval))
    #expect(modes.contains(.executionWindowReuse))

    await authorizationSession.invalidateExecutionAuthorization(for: scope)
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test-2", agentRisk: .approvalRequired)
    )
    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 3)
}

@Test func boundedFilesystemDeletionWithoutJudgeReviewRequiresFreshApproval''',
    "elapsed time reuse test",
)
s = regex_once(
    s,
    r"@Test func boundedFilesystemDeletionWithoutJudgeReviewRequiresFreshApproval\(\) async throws \{.*?\n\}\n\n@Test func forgedIndependentJudgeSourceCannotDowngradeGrayOperation",
    '''@Test func boundedFilesystemDeletionWithoutJudgeReviewRequiresFreshApproval() async throws {
    let authorizationSession = AuthorizationSession()
    let fixture = try await OperationServiceFixture(authorizationSession: authorizationSession)
    defer { fixture.remove() }
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    )
    let scope = fixture.executionScope()
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
    let output = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "rm -rf /share/svlt-test", agentRisk: .approvalRequired)
    )
    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
}

@Test func forgedIndependentJudgeSourceCannotDowngradeGrayOperation''',
    "gray fresh operation test",
)
s = regex_once(
    s,
    r"@Test func agentApprovalHintKeepsReusableOperationsInsideTheExecutionWindow\(\) async throws \{.*?\n\}\n\n@Test func agentApprovalHintOnHostnameBehavesAsAnOrdinaryWindowOperation",
    '''@Test func agentApprovalHintKeepsReusableOperationsInsideTheSessionAuthorization() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 6_000)
    let clock = ServiceTestClock(start)
    let authorizationSession = AuthorizationSession(now: { clock.now })
    let fixture = try await OperationServiceFixture(authorizationSession: authorizationSession, now: { clock.now })
    defer { fixture.remove() }
    let mkdir = fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(mkdir)
    let scope = fixture.executionScope(for: mkdir)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
    clock.now = start.addingTimeInterval(86_400)
    let touch = fixture.ssh(command: "touch /share/svlt-test", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(touch)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
}

@Test func agentApprovalHintOnHostnameBehavesAsAnOrdinarySessionOperation''',
    "agent reusable hint test",
)
s = regex_once(
    s,
    r"@Test func agentApprovalHintOnHostnameBehavesAsAnOrdinarySessionOperation\(\) async throws \{.*?\n\}\n\n@Test func containerLifecycleRemovalWithoutJudgeReviewRequiresFreshApproval",
    '''@Test func agentApprovalHintOnHostnameBehavesAsAnOrdinarySessionOperation() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 7_000)
    let clock = ServiceTestClock(start)
    let authorizationSession = AuthorizationSession(now: { clock.now })
    let fixture = try await OperationServiceFixture(authorizationSession: authorizationSession, now: { clock.now })
    defer { fixture.remove() }
    let mkdir = fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(mkdir)
    let scope = fixture.executionScope(for: mkdir)
    clock.now = start.addingTimeInterval(172_800)
    let hostname = fixture.ssh(command: "hostname", agentRisk: .denied)
    _ = try await fixture.service.performSecretOperation(hostname)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
}

@Test func containerLifecycleRemovalWithoutJudgeReviewRequiresFreshApproval''',
    "hostname session reuse test",
)
s = regex_once(
    s,
    r"@Test func containerLifecycleRemovalWithoutJudgeReviewRequiresFreshApproval\(\) async throws \{.*?\n\}\n\n@Test func concurrentEligibleOperationsShareOneApproval",
    '''@Test func containerLifecycleRemovalWithoutJudgeReviewRequiresFreshApproval() async throws {
    let authorizationSession = AuthorizationSession()
    let fixture = try await OperationServiceFixture(authorizationSession: authorizationSession)
    defer { fixture.remove() }
    let restart = fixture.ssh(command: "docker restart web", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(restart)
    let scope = fixture.executionScope(for: restart)
    let startContainer = fixture.ssh(command: "docker start web", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(startContainer)
    #expect(await fixture.approver.count == 1)
    let remove = fixture.ssh(command: "docker rm -f web", agentRisk: .approvalRequired)
    _ = try await fixture.service.performSecretOperation(remove)
    #expect(await fixture.approver.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: scope))
}

@Test func concurrentEligibleOperationsShareOneApproval''',
    "container fresh operation test",
)
s = regex_once(
    s,
    r"@Test func concurrentOperationsWithDisabledExecutionWindowDoNotShareApproval\(\) async throws \{.*?\n\}\n\n",
    "",
    "obsolete disabled-window test",
)
# Other fresh-only tests may construct a timed session only to assert no scope is
# created. Remove those obsolete initializer arguments while preserving clocks.
s = re.sub(r"\n\s*executionTTL: 300,", "", s)
s = re.sub(r"\n\s*monotonicNow: \{ clock\.monotonicNow \},", "", s)
if "executionAuthorizationExpiresAt" in s or "executionTTL:" in s:
    raise SystemExit("SecretOperationServiceTests still references removed execution TTL APIs")
p.write_text(s, encoding="utf-8")

# Security documentation: reusable approval remains, only the arbitrary timer
# disappears. Fresh/high-risk approval stays one-shot.
p = Path("docs/security/operation-authorization.md")
s = p.read_text(encoding="utf-8")
s = s.replace("technical failure or owner approval / scoped lease", "technical failure or owner approval / session-scoped grant")
s = s.replace("exact device-owner approval or scoped execution lease", "exact device-owner approval or session-scoped execution grant")
s = s.replace("首次认证打开当前 scope 的固定 300 秒窗口；目标/协议提示不额外升级", "首次认证建立当前 scope 的会话级授权；不设固定时间超时，目标/协议提示不额外升级")
s = s.replace("不自动拒绝，也不建立普通可复用 lease", "不自动拒绝，也不建立普通可复用会话授权")
s = s.replace("不建立可复用 lease", "不建立可复用会话授权")
s = s.replace("不建立执行 lease", "不建立执行会话授权")
s = regex_once(
    s,
    r"对可执行的 `approvalRequired` 操作，设备认证完成后最多建立一个固定 300 秒的.*?明文显示和复制仍保持 exact、\none-shot 认证。\n",
    '''对可执行的 `reusableApproval` 操作，设备所有者完成一次认证后，SVLT 建立一个仅存在于当前 Agent 安全会话中的 scope grant。它绑定调用主体、完整的 `secret://` 引用集合、规范化目标和端口、协议、执行动作类型以及 security generation；它不是全局授权，也没有固定 TTL。时间流逝本身不会使授权失效，因此不再存在“300 秒内自动放行、超时后重新审批”的行为。每个后续请求仍会先做 executor capability preflight，再重新读取 metadata 和执行策略；高风险或 `freshApprovalRequired` 操作仍然逐次认证。

会话级授权只会在安全边界变化时失效，包括锁屏、睡眠、用户会话切换/注销、显式锁定、Agent 进程重启、安全代际变化或该 scope 被明确撤销。远端执行失败、transport/session 失败以及普通请求之间的空闲时间都不会撤销已经建立的 owner grant。与 scope 对应的解密 capability 只保存在内存中，并与授权状态一起失效。

这里的 reusable grant 是明确的 scope grant，而不是“只批准屏幕上这一条命令”的 exact-operation grant。这样可以让 Agent 连续完成同一主机/同一凭据任务，而不会因为任意计时器再次打断用户；每个后续请求仍重新经过固定高危规则。数据库 scope 继续按窄操作族隔离；DELETE/UPDATE/MERGE、管理权限、动态执行以及未知 SQL 不会创建 reusable grant。

本地明文导出属于 non-downgradable `freshApprovalRequired` 操作，每次都需要设备所有者确认，不建立会话级 execution grant。明文显示和复制同样保持 exact、one-shot 认证。
''',
    "authorization documentation",
)
p.write_text(s, encoding="utf-8")

# Active implementation/docs must not retain the removed timed-approval API.
for needle in [
    "executionAuthorizationTTL",
    "executionTTL:",
    "executionAuthorizationExpiresAt",
    "executionAuthorizationWindowEnabled",
    "executionAuthorizationWindowDuration",
    "复用最多 300 秒",
    "固定 300 秒",
]:
    hits = []
    for root in [Path("Sources"), Path("Tests"), Path("docs/security")]:
        for file in root.rglob("*"):
            if file.is_file():
                try:
                    content = file.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    continue
                if needle in content:
                    hits.append(str(file))
    if hits:
        raise SystemExit(f"removed timed-approval token {needle!r} remains in {hits}")

print("session-scoped reusable approval refactor applied")
