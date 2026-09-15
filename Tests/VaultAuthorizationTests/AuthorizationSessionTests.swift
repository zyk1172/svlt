import Foundation
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
