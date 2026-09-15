import CryptoKit
import Foundation
import LocalAuthentication
import Testing
@testable import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func longRunningOperationDoesNotBlockLaterOperation() async throws {
    let service = SecretOperationService()
    let firstGate = ConcurrentOperationGate()
    let secondStarted = ConcurrentOperationGate()
    let descriptor = SecretOperationDescriptor(
        actionType: .localExecution,
        secretReferences: [],
        destination: "test",
        parameters: [:]
    )

    let first = await service.start(principal: "agent", descriptor: descriptor) { _ in
        await firstGate.markStartedAndWait()
        return SecretOperationOutput(status: "FIRST_DONE")
    }
    await firstGate.waitUntilStarted()

    let second = await service.start(principal: "agent", descriptor: descriptor) { _ in
        await secondStarted.markStarted()
        return SecretOperationOutput(status: "SECOND_DONE")
    }
    await secondStarted.waitUntilStarted()

    #expect(first.operationID != second.operationID)
    await firstGate.release()
}

@Test func firstOrdinaryOperationTakesOneApprovalAndOpensTheWindow() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    // §22: every secret-bearing execution — including hostname — takes
    // exactly one device-owner approval on first use.
    let output = try await fixture.service.performSecretOperation(fixture.ssh(command: "hostname"))

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 1)
}

@Test func destinationBindingTakesFreshApprovalAndNeverLaunchesAnExecutor() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let descriptor = fixture.bind(destination: "http://192.168.2.240:3000")
    let output = try await fixture.service.performSecretOperation(descriptor)
    let record = try await fixture.store.latest(id: fixture.reference.id)

    #expect(output.status == "BOUND")
    #expect(output.redacted)
    #expect(output.destination == "http://192.168.2.240:3000")
    #expect(output.protocolType == .http)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 0)
    #expect(record.allowedDestinations == ["qnap.local", "http://192.168.2.240:3000"])
    #expect(record.allowedProtocols == ["ssh", "http"])
    #expect(record.allowedBindings == [
        SecretDestinationBinding(protocolType: .ssh, destination: "qnap.local"),
        SecretDestinationBinding(protocolType: .http, destination: "http://192.168.2.240:3000")
    ])
    #expect(record.recordVersion == 2)
    #expect(try VaultCipher().decrypt(record, masterKey: fixture.key) == Data("ASV_CANARY_OPERATION_SECRET".utf8))
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope(for: descriptor)) == false)
}

@Test func malformedDestinationBindingIsRejectedBeforeOwnerApproval() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(
            fixture.bind(destination: "http://192.168.2.240:3000/api")
        )
        Issue.record("A destination path was accepted for a binding operation.")
    } catch let error as SecretOperationError {
        #expect(error == .invalidOperationParameters)
    }
    #expect(await fixture.approver.count == 0)
    #expect(await fixture.executor.count == 0)
}

@Test func destinationBindingReportsCommittedResultAfterSecurityInvalidation() async throws {
    let saveGate = BindingCommitGate()
    let fixture = try await OperationServiceFixture(bindingSaveGate: saveGate)
    defer { fixture.remove() }

    await saveGate.pauseNextSave()
    let operation = Task { () -> SecretOperationOutput? in
        try? await fixture.service.performSecretOperation(
            fixture.bind(destination: "http://192.168.2.240:3000")
        )
    }

    await saveGate.waitUntilSaveStarts()
    await fixture.service.invalidateSecurityState()
    await saveGate.releaseSave()

    let output = await operation.value
    #expect(output?.status == "BOUND")
    #expect(output?.destination == "http://192.168.2.240:3000")
    let record = try await fixture.store.latest(id: fixture.reference.id)
    #expect(record.recordVersion == 2)
    #expect(record.allowedBindings.contains(
        SecretDestinationBinding(
            protocolType: .http,
            destination: "http://192.168.2.240:3000"
        )
    ))
}

@Test func insecureHTTPProfileMismatchDoesNotSelfDenyBeforeOwnerApproval() async throws {
    let fixture = try await OperationServiceFixture(allowedProtocols: ["https"])
    defer { fixture.remove() }

    // The policy layer must show the plaintext-transport risk and let the
    // device owner decide. The concrete HTTP executor enforces the exact
    // saved origin profile after that approval; this service fixture uses a
    // recording executor and therefore only verifies the authorization path.
    let output = try await fixture.service.performSecretOperation(
        fixture.http(method: "GET", path: "/status")
    )
    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 1)
}

@Test func undeclaredLegacySecretReferenceIsRejectedBeforeOwnerApproval() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        parameters: [
            "passwordRef": fixture.reference.description,
            "username": "admin"
        ]
    )

    do {
        _ = try await fixture.service.performSecretOperation(descriptor)
        Issue.record("An undeclared executable secret reference was accepted.")
    } catch let error as SecretOperationError {
        #expect(error == .invalidOperationParameters)
    }
    #expect(await fixture.approver.count == 0)
    #expect(await fixture.executor.count == 0)
}

@Test func resolverRejectsAReferenceOutsideTheApprovedDescriptorSet() async throws {
    let undeclared = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    let fixture = try await OperationServiceFixture(executorResolveReference: undeclared)
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "hostname"))
        Issue.record("The executor resolved a reference outside the approved set.")
    } catch let error as SecretOperationError {
        #expect(error == .invalidOperationParameters)
    }
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 1)
}

@Test func firstOperationForwardsItsOwnerApprovalContextToTheMasterKeyLookup() async throws {
    let context = LocalAuthenticationContext(rawContext: LAContext())
    let contextualKeyProvider = ContextualKeyProvider(
        key: SymmetricKey(data: Data(repeating: 0x44, count: 32))
    )
    let fixture = try await OperationServiceFixture(
        contextApprover: ContextApprovalRecorder(context: context),
        contextualKeyProvider: contextualKeyProvider
    )
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "hostname")
    )

    #expect(output.status == "COMPLETED")
    #expect(await contextualKeyProvider.receivedContext === context)
}

@Test func dangerousSecretOperationWaitsForApprovalAndResumesSameRequest() async throws {
    let fixture = try await OperationServiceFixture(approval: .allow)
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(fixture.ssh(command: "reboot"))

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let statuses = await fixture.statusValues()
    #expect(statuses.map(\.approvalPending) == [true, false])
}

@Test func executionApprovalExplainsItsSessionScopedReuse() async throws {
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

@Test func plaintextExportRequiresFreshApprovalAndKeyForEachLeafFile() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 7_000)
    let clock = ServiceTestClock(start)
    let monotonicStart: UInt64 = 90_000_000_000
    clock.monotonicNow = monotonicStart
    let authorizationSession = AuthorizationSession(
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        usesMasterKeyProvider: true,
        now: { clock.now }
    )
    defer { fixture.remove() }

    let context = RevealContext(
        reason: "Export resolved local file",
        template: "Token: {{0}}",
        ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
    )
    let firstDestination = fixture.exportDirectory.appendingPathComponent("first.md")
    let secondDestination = fixture.exportDirectory.appendingPathComponent("second.md")

    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-exporter")
    ) {
        try await fixture.service.exportResolvedText(
            references: [fixture.reference.description],
            context: context,
            destinationPath: firstDestination.path
        )
    }
    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-exporter")
    ) {
        try await fixture.service.exportResolvedText(
            references: [fixture.reference.description],
            context: context,
            destinationPath: secondDestination.path
        )
    }

    // Plaintext export is a non-downgradable sensitive-control operation. It
    // must not establish or reuse an execution lease, even when two files
    // share the same owner-only export root.
    #expect(await fixture.approver.count == 2)
    let keyProvider = try #require(fixture.keyProvider)
    #expect(await keyProvider.freshCount == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(
        for: fixture.exportScope(principal: "agent-exporter")
    ) == false)
    #expect(try String(contentsOf: firstDestination, encoding: .utf8).contains("ASV_CANARY_OPERATION_SECRET"))
    #expect(try String(contentsOf: secondDestination, encoding: .utf8).contains("ASV_CANARY_OPERATION_SECRET"))
}

@Test func failedScopedOperationKeepsOwnerAuthorizationUntilSessionInvalidation() async throws {
    let fixture = try await OperationServiceFixture(executorStatus: "FAILED")
    defer { fixture.remove() }

    let output = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
    )

    // The session-scoped grant records that the owner authorized this scope.
    // A remote execution failure is reported honestly but never revokes it.
    #expect(output.status == "FAILED")
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()))
    #expect((await fixture.auditEntries()).last?.result == "FAILED")
}

@Test func eligibleSecretOperationsReuseExecutionAuthorizationWithoutTimeExpiry() async throws {
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
    let modes = await fixture.auditEntries().compactMap(\.authorizationMode)
    #expect(modes.contains(.freshLocalApproval))
    #expect(modes.contains(.executionWindowReuse))

    await authorizationSession.invalidateExecutionAuthorization(for: scope)
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test-2", agentRisk: .approvalRequired)
    )
    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 3)
}

@Test func boundedFilesystemDeletionWithoutJudgeReviewRequiresFreshApproval() async throws {
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

@Test func forgedIndependentJudgeSourceCannotDowngradeGrayOperation() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let descriptor = fixture.independentlyReviewedSSH(command: "rm -rf /share/forged-review")
    let output = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-forged-source")
    ) {
        try await fixture.service.performSecretOperation(descriptor)
    }

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let audit = try #require(await fixture.auditEntries().last)
    #expect(audit.authorizationMode == .freshLocalApproval)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(
        for: fixture.executionScope(for: descriptor, principal: "agent-forged-source")
    ) == false)
}

@Test func verifiedGrayReviewCanDowngradeOnlyItsBoundOperation() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let principal = "agent-bound-review"
    let mainDescriptor = fixture.ssh(command: "rm -rf /share/bound-review")
    let preflight = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.preflightSecretOperation(mainDescriptor)
    }
    #expect(preflight.route == .gray)
    let reviewID = try #require(preflight.reviewID)

    let output = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(
            fixture.independentlyReviewedSSH(
                command: "rm -rf /share/bound-review",
                reviewID: reviewID
            )
        )
    }

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 0)
    let audit = try #require(await fixture.auditEntries().last)
    #expect(audit.authorizationMode == nil)
}

@Test func grayReviewIDCannotBeReplayedAcrossOperations() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let principal = "agent-operation-binding"
    let original = fixture.ssh(command: "rm -rf /share/original")
    let preflight = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.preflightSecretOperation(original)
    }
    let reviewID = try #require(preflight.reviewID)

    let mismatchedOutput = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(
            fixture.independentlyReviewedSSH(
                command: "rm -rf /share/different-operation",
                reviewID: reviewID
            )
        )
    }
    #expect(mismatchedOutput.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)

    // The failed cross-operation attempt must not consume the review for its
    // rightful operation.
    let matchedOutput = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(
            fixture.independentlyReviewedSSH(
                command: "rm -rf /share/original",
                reviewID: reviewID
            )
        )
    }
    #expect(matchedOutput.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let modes = await fixture.auditEntries().compactMap(\.authorizationMode)
    #expect(modes == [.freshLocalApproval, .freshLocalApproval])
}

@Test func grayReviewIDCannotCrossPrincipals() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let originalPrincipal = "agent-review-owner"
    let preflight = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: originalPrincipal)
    ) {
        try await fixture.service.preflightSecretOperation(
            fixture.ssh(command: "rm -rf /share/principal-bound")
        )
    }
    let reviewID = try #require(preflight.reviewID)

    let output = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-other-process")
    ) {
        try await fixture.service.performSecretOperation(
            fixture.independentlyReviewedSSH(
                command: "rm -rf /share/principal-bound",
                reviewID: reviewID
            )
        )
    }

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let audit = try #require(await fixture.auditEntries().last)
    #expect(audit.authorizationMode == .freshLocalApproval)
}

@Test func expiredGrayReviewIDFailsClosedToFreshApproval() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 9_000)
    let clock = ServiceTestClock(start)
    let fixture = try await OperationServiceFixture(
        semanticReviewTTL: 10,
        now: { clock.now }
    )
    defer { fixture.remove() }

    let principal = "agent-expired-review"
    let preflight = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.preflightSecretOperation(
            fixture.ssh(command: "rm -rf /share/expired-review")
        )
    }
    let reviewID = try #require(preflight.reviewID)
    clock.now = start.addingTimeInterval(11)

    let output = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(
            fixture.independentlyReviewedSSH(
                command: "rm -rf /share/expired-review",
                reviewID: reviewID
            )
        )
    }

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let audit = try #require(await fixture.auditEntries().last)
    #expect(audit.authorizationMode == .freshLocalApproval)
}

@Test func grayReviewIDIsConsumedAfterOneSuccessfulUse() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let principal = "agent-one-shot-review"
    let command = "rm -rf /share/one-shot-review"
    let preflight = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.preflightSecretOperation(fixture.ssh(command: command))
    }
    let reviewID = try #require(preflight.reviewID)
    let reviewed = fixture.independentlyReviewedSSH(command: command, reviewID: reviewID)

    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(reviewed)
    }
    let replay = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: principal)
    ) {
        try await fixture.service.performSecretOperation(reviewed)
    }

    #expect(replay.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let modes = await fixture.auditEntries().compactMap(\.authorizationMode)
    #expect(modes == [.freshLocalApproval, .freshLocalApproval])
}

@Test func insecureHTTPRequiresAFreshApprovalForEachOperationWithoutALease() async throws {
    let start = Date(timeIntervalSinceReferenceDate: 5_000)
    let clock = ServiceTestClock(start)
    let monotonicStart: UInt64 = 50_000_000_000
    clock.monotonicNow = monotonicStart
    let authorizationSession = AuthorizationSession(
        now: { clock.now }
    )
    let fixture = try await OperationServiceFixture(
        authorizationSession: authorizationSession,
        allowedDestinations: ["qnap.local:8080"],
        allowedProtocols: ["http"],
        now: { clock.now }
    )
    defer { fixture.remove() }

    // Insecure HTTP is never refused, but it is never silently reusable
    // either: every secret-bearing request over http:// takes a fresh
    // approval with the plaintext-transport warning, and no lease is
    // established for it.
    let read = fixture.http(method: "GET", path: "/api/status")
    let readOutput = try await fixture.service.performSecretOperation(read)
    #expect(readOutput.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    let readScope = fixture.executionScope(for: read)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: readScope) == false)
    let readSummary = await fixture.approver.summaries.first ?? ""
    #expect(readSummary.contains("未加密 HTTP"))
    #expect(!readSummary.contains("复用最多"))

    clock.now = start.addingTimeInterval(100)
    clock.monotonicNow = monotonicStart + 100_000_000_000
    let delete = fixture.http(method: "DELETE", path: "/api/items/123")
    let output = try await fixture.service.performSecretOperation(delete)

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(
        for: fixture.executionScope(for: delete)
    ) == false)
    #expect(await authorizationSession.hasActiveExecutionAuthorization(for: readScope) == false)

    let deleteSummary = await fixture.approver.summaries.last ?? ""
    #expect(deleteSummary.contains("未加密 HTTP"))
    #expect(!deleteSummary.contains("复用最多"))
}

@Test func publicHTTPSSecretSendUsesFreshOwnerApprovalInsteadOfPolicyDenial() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    let descriptor = SecretOperationDescriptor(
        actionType: .apiRequest,
        secretReferences: [fixture.reference],
        destination: "api.example.com",
        port: 443,
        protocolType: .https,
        httpMethod: "GET",
        url: "https://api.example.com/v1/status",
        requestedEffects: ["read-only"],
        parameters: ["tokenRef": fixture.reference.description]
    )

    let output = try await fixture.service.performSecretOperation(descriptor)

    #expect(output.status == "COMPLETED")
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 1)
    let summary = await fixture.approver.summaries.first ?? ""
    #expect(summary.contains("Secret 将离开本机发送到 HTTP(S) 目标"))
}

@Test func agentApprovalHintKeepsReusableOperationsInsideTheSessionAuthorization() async throws {
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

@Test func agentApprovalHintOnHostnameBehavesAsAnOrdinarySessionOperation() async throws {
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

@Test func containerLifecycleRemovalWithoutJudgeReviewRequiresFreshApproval() async throws {
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

@Test func concurrentEligibleOperationsShareOneApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let outputs = try await withThrowingTaskGroup(of: SecretOperationOutput.self) { group in
        // Only commands classified as reusableApproval should share the
        // scoped single-flight approval. Broad copy/move/permission commands
        // intentionally take the fresh-approval path.
        for command in ["mkdir /share/svlt-a", "touch /share/svlt-b", "mkdir /share/svlt-c"] {
            group.addTask {
                try await fixture.service.performSecretOperation(
                    fixture.ssh(command: command, agentRisk: .approvalRequired)
                )
            }
        }

        var outputs: [SecretOperationOutput] = []
        for try await output in group {
            outputs.append(output)
        }
        return outputs
    }

    #expect(outputs.count == 3)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 3)
}

@Test func executionAuthorizationIsBoundToTheCallingAgentPrincipal() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-peer-one")
    ) {
        try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    }
    _ = try await AuditContext.$current.withValue(
        AuditContext(source: .agent, principal: "agent-peer-two")
    ) {
        try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
    }

    #expect(await fixture.approver.count == 2)
    #expect(await fixture.executor.count == 2)
}

@Test func unavailableExecutorIsRejectedBeforeApprovalAndCannotPrimeLease() async throws {
    let fixture = try await OperationServiceFixture(
        executorCapability: .unavailable
    )
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected unavailable executor, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .actionExecutorUnavailable)
    }

    #expect(await fixture.approver.count == 0)
    #expect(await fixture.executor.count == 0)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
}

@Test func legacyUnavailableExecutorStatusIsNotAuditedAsCompleted() async throws {
    let fixture = try await OperationServiceFixture(
        executorStatus: "ACTION_EXECUTOR_UNAVAILABLE"
    )
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected unavailable executor, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .actionExecutorUnavailable)
    }

    let entries = await fixture.auditEntries()
    #expect(entries.last?.result == "不可用")
    #expect(entries.last?.authorizationMode == .freshLocalApproval)
}

@Test func securityInvalidationCancelsPendingExecutionApproval() async throws {
    let fixture = try await OperationServiceFixture(approval: .delayed)
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(
                fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
            )
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.approver.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }

    #expect(await fixture.approver.count == 1)
    await fixture.service.invalidateSecurityState()

    #expect(await operation.value == .authorizationCancelled)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
    #expect(await fixture.executor.count == 0)
}

@Test func unboundPublicDestinationTakesFreshApprovalInsteadOfDenial() async throws {
    let fixture = try await OperationServiceFixture()
    defer { fixture.remove() }

    _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))

    // A destination outside the credential's saved binding is no longer
    // refused by policy: the owner sees the mismatch and decides. The
    // approval is per execution and never mutates the saved binding.
    _ = try await fixture.service.performSecretOperation(
        fixture.ssh(command: "mkdir /share/svlt-test").replacingDestination("8.8.8.8")
    )

    _ = try await fixture.service.performSecretOperation(
        SecretOperationDescriptor(
            actionType: .revealPlaintext,
            secretReferences: [fixture.reference]
        )
    )

    #expect(await fixture.approver.count == 3)
    #expect(await fixture.executor.count == 3)
}

@Test func policyMismatchAfterApprovalStillExecutesUnderTheOriginalApproval() async throws {
    let gate = ApprovalGate()
    let fixture = try await OperationServiceFixture(
        approval: .gated,
        approvalGate: gate
    )
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(
                fixture.ssh(command: "mkdir /share/svlt-test", agentRisk: .approvalRequired)
            )
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.approver.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await fixture.approver.count == 1)

    // §32/§45: a saved credential-policy mismatch is display-only metadata.
    // The re-evaluation after approval does not manufacture a second prompt:
    // the owner's single decision stands and the ordinary lease opens.
    try await fixture.replaceWithReadOnlyRecord()
    await gate.release()

    #expect(await operation.value == nil)
    #expect(await fixture.approver.count == 1)
    #expect(await fixture.executor.count == 1)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()))
}
@Test func securityInvalidationCancelsAnInFlightSecretExecutor() async throws {
    let fixture = try await OperationServiceFixture(blockExecution: true)
    defer { fixture.remove() }

    let operation = Task { () -> SecretOperationError? in
        do {
            _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
            return nil
        } catch let error as SecretOperationError {
            return error
        } catch {
            return .actionExecutionFailed
        }
    }

    for _ in 0..<100 {
        if await fixture.executor.count == 1 {
            break
        }
        try await Task.sleep(for: .milliseconds(1))
    }
    #expect(await fixture.executor.count == 1)

    await fixture.service.invalidateSecurityState()

    #expect(await operation.value == .authorizationCancelled)
    #expect(await fixture.authorizationSession.hasActiveExecutionAuthorization(for: fixture.executionScope()) == false)
}

@Test func cancelledApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.cancelled, expected: .authorizationCancelled)
}

@Test func deniedApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.denied, expected: .authorizationDenied)
}

@Test func unavailableApprovalIsReturnedAsStableStatus() async throws {
    try await expectApprovalFailure(.unavailable, expected: .authorizationUnavailable)
}

private func expectApprovalFailure(
    _ mode: ApprovalMode,
    expected: SecretOperationError
) async throws {
    let fixture = try await OperationServiceFixture(approval: mode)
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected \(expected), but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == expected)
    }
    #expect(await fixture.executor.count == 0)
}

@Test func approvalTimeoutDoesNotLaunchExecutor() async throws {
    let fixture = try await OperationServiceFixture(approval: .never, timeout: .milliseconds(20))
    defer { fixture.remove() }

    do {
        _ = try await fixture.service.performSecretOperation(fixture.ssh(command: "mkdir /share/svlt-test"))
        Issue.record("Expected authorization timeout, but operation succeeded.")
    } catch let error as SecretOperationError {
        #expect(error == .authorizationTimeout)
    }
    #expect(await fixture.executor.count == 0)
}

private actor ConcurrentOperationGate {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func markStarted() {
        started = true
        let waiters = startWaiters
        startWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }

    func markStartedAndWait() async {
        markStarted()
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

private enum ApprovalMode: Sendable {
    case allow
    case delayed
    case gated
    case cancelled
    case denied
    case unavailable
    case never
}

private actor ApprovalRecorder: OperationApproving {
    let mode: ApprovalMode
    let gate: ApprovalGate?
    private(set) var count = 0
    private(set) var summaries: [String] = []

    init(mode: ApprovalMode, gate: ApprovalGate? = nil) {
        self.mode = mode
        self.gate = gate
    }

    func approve(summary: String) async throws {
        count += 1
        summaries.append(summary)
        switch mode {
        case .allow:
            return
        case .delayed:
            try await Task.sleep(for: .milliseconds(100))
        case .gated:
            await gate?.waitForRelease()
        case .cancelled:
            throw OperationAuthorizationError.cancelled
        case .denied:
            throw OperationAuthorizationError.denied
        case .unavailable:
            throw OperationAuthorizationError.unavailable
        case .never:
            try await Task.sleep(for: .seconds(10))
        }
    }
}

private struct ContextApprovalRecorder: OperationApprovalContextProviding {
    let context: LocalAuthenticationContext

    func approve(summary _: String) async throws {}

    func approveWithAuthenticationContext(
        summary _: String
    ) async throws -> LocalAuthenticationContext? {
        context
    }
}

private actor ApprovalGate {
    private var released = false
    private var continuation: CheckedContinuation<Void, Never>?

    func waitForRelease() async {
        guard !released else { return }
        await withCheckedContinuation { continuation in
            self.continuation = continuation
        }
    }

    func release() {
        released = true
        continuation?.resume()
        continuation = nil
    }
}

private actor ExecutorRecorder: SecretOperationExecuting {
    let capability: SecretOperationExecutionCapability
    let outputStatus: String
    let blockExecution: Bool
    let resolveReference: SecretReference?
    private(set) var count = 0

    init(
        capability: SecretOperationExecutionCapability = .supported,
        outputStatus: String = "COMPLETED",
        blockExecution: Bool = false,
        resolveReference: SecretReference? = nil
    ) {
        self.capability = capability
        self.outputStatus = outputStatus
        self.blockExecution = blockExecution
        self.resolveReference = resolveReference
    }

    nonisolated func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        capability
    }

    func execute(
        _: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        count += 1
        if let resolveReference {
            _ = try await resolve(resolveReference)
        }
        if blockExecution {
            try await Task.sleep(for: .seconds(10))
        }
        return SecretOperationOutput(status: outputStatus, exitCode: 0, stdout: "hostname", stderr: "")
    }
}

private actor ScopedKeyProviderRecorder {
    private let key: SymmetricKey
    private(set) var masterCount = 0
    private(set) var freshCount = 0

    init(key: SymmetricKey) {
        self.key = key
    }

    func masterKey() -> SymmetricKey {
        masterCount += 1
        return key
    }

    func freshMasterKey() -> SymmetricKey {
        freshCount += 1
        return key
    }
}

private actor ContextualKeyProvider {
    private let key: SymmetricKey
    private(set) var receivedContext: LocalAuthenticationContext?

    init(key: SymmetricKey) {
        self.key = key
    }

    func masterKey(authenticationContext: LocalAuthenticationContext?) -> SymmetricKey {
        receivedContext = authenticationContext
        return key
    }
}

private actor StatusRecorder {
    private(set) var values: [WorkbenchStatus] = []

    func append(_ value: WorkbenchStatus) {
        values.append(value)
    }
}

private actor AuditRecorder {
    private(set) var entries: [AgentAutomationAuditEntry] = []

    func append(_ entry: AgentAutomationAuditEntry) {
        entries.append(entry)
    }
}

private struct DummyTextEncryptor: TextEncrypting {
    func encryptText(_: String, label _: String?, policy _: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    }
}

private final class OperationServiceFixture: @unchecked Sendable {
    let root: URL
    let key: SymmetricKey
    let reference: SecretReference
    let service: VaultAppServices
    let approver: ApprovalRecorder
    let executor: ExecutorRecorder
    let statusRecorder: StatusRecorder
    let authorizationSession: AuthorizationSession
    let store: FileRecordStore
    let auditRecorder: AuditRecorder
    let exportDirectory: URL
    let keyProvider: ScopedKeyProviderRecorder?

    init(
        approval: ApprovalMode = .allow,
        timeout: Duration = .seconds(1),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        approvalGate: ApprovalGate? = nil,
        auditRecorder: AuditRecorder? = nil,
        executorCapability: SecretOperationExecutionCapability = .supported,
        executorStatus: String = "COMPLETED",
        blockExecution: Bool = false,
        executorResolveReference: SecretReference? = nil,
        usesMasterKeyProvider: Bool = false,
        contextApprover: (any OperationApproving)? = nil,
        contextualKeyProvider: ContextualKeyProvider? = nil,
        bindingSaveGate: BindingCommitGate? = nil,
        allowedDestinations: [String] = ["qnap.local"],
        allowedProtocols: [String] = ["ssh"],
        semanticReviewTTL: TimeInterval = 120,
        now: @escaping @Sendable () -> Date = Date.init
    ) async throws {
        root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("svlt-operation-service-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        exportDirectory = root.appendingPathComponent("Exports", isDirectory: true)
        try FileManager.default.createDirectory(
            at: exportDirectory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let store = FileRecordStore(baseDirectory: root)
        self.store = store
        key = SymmetricKey(data: Data(repeating: 0x44, count: 32))
        reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
        let record = try VaultCipher().encrypt(
            Data("ASV_CANARY_OPERATION_SECRET".utf8),
            id: reference.id,
            version: 1,
            label: "QNAP credential",
            policy: .credential,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            masterKey: key
        )
        try await store.save(record)

        let keyProvider = usesMasterKeyProvider ? ScopedKeyProviderRecorder(key: key) : nil
        self.keyProvider = keyProvider
        let masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
        let freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
        if let keyProvider {
            masterKeyProvider = { _, _ in await keyProvider.masterKey() }
            freshMasterKeyProvider = { _, _ in await keyProvider.freshMasterKey() }
        } else {
            masterKeyProvider = nil
            freshMasterKeyProvider = nil
        }
        let masterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)?
        let freshMasterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)?
        if let contextualKeyProvider {
            masterKeyProviderWithAuthenticationContext = { _, _, authenticationContext in
                await contextualKeyProvider.masterKey(authenticationContext: authenticationContext)
            }
            freshMasterKeyProviderWithAuthenticationContext = { _, _, authenticationContext in
                await contextualKeyProvider.masterKey(authenticationContext: authenticationContext)
            }
        } else {
            masterKeyProviderWithAuthenticationContext = nil
            freshMasterKeyProviderWithAuthenticationContext = nil
        }

        let resolverStore: any RecordStore = bindingSaveGate.map {
            SaveGatedRecordStore(base: store, gate: $0)
        } ?? store

        let statuses = StatusRecorder()
        statusRecorder = statuses
        approver = ApprovalRecorder(mode: approval, gate: approvalGate)
        executor = ExecutorRecorder(
            capability: executorCapability,
            outputStatus: executorStatus,
            blockExecution: blockExecution,
            resolveReference: executorResolveReference
        )
        self.authorizationSession = authorizationSession
        let auditRecorder = auditRecorder ?? AuditRecorder()
        self.auditRecorder = auditRecorder
        service = VaultAppServices(
            textEncryptor: DummyTextEncryptor(),
            activeRoot: nil,
            recordResolver: VaultRecordResolver(recordStore: resolverStore),
            masterKey: keyProvider == nil && contextualKeyProvider == nil ? key : nil,
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
            masterKeyProviderWithAuthenticationContext: masterKeyProviderWithAuthenticationContext,
            freshMasterKeyProviderWithAuthenticationContext: freshMasterKeyProviderWithAuthenticationContext,
            authorizationSession: authorizationSession,
            operationApprover: contextApprover ?? approver,
            operationExecutor: executor,
            operationApprovalTimeout: timeout,
            semanticReviewTTL: semanticReviewTTL,
            now: now,
            statusObserver: { status in
                await statuses.append(status)
            },
            auditObserver: { entry in
                await auditRecorder.append(entry)
            },
            exportDirectory: exportDirectory
        )
    }

    func ssh(
        command: String,
        agentRisk: OperationRisk? = nil,
        reviewID: UUID? = nil,
        agentAssessment: AgentRiskAssessment? = nil
    ) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "qnap.local",
            port: 22,
            protocolType: .ssh,
            command: command,
            requestedEffects: [command == "hostname" ? "read-only" : "remote-write"],
            parameters: ["passwordRef": reference.description, "username": "admin"],
            reviewID: reviewID,
            agentAssessment: agentAssessment ?? agentRisk.map { risk in
                let isReadOnly = command == "hostname"
                let executionRecommendation: AgentRiskAssessment.ExecutionRecommendation
                switch risk {
                case .silent:
                    executionRecommendation = .automatic
                case .approvalRequired, .denied:
                    // The legacy denied hint is intentionally only a visible
                    // Agent warning; the daemon still evaluates the concrete
                    // operation and the structured assessment independently.
                    executionRecommendation = .reusableApproval
                }
                return AgentRiskAssessment(
                    declaredRisk: risk,
                    reason: "agent-reported risk",
                    userGoal: "Complete the requested SSH operation",
                    taskContext: "A bounded task-scoped SSH operation with one declared credential",
                    intendedEffect: isReadOnly ? "inspect host name" : "remote write",
                    expectedEffect: isReadOnly ? "Read the host name" : "Change only the requested remote target",
                    expectedResult: "The requested SSH operation completes",
                    intentAlignment: .direct,
                    effectSeverity: isReadOnly ? .none : .bounded,
                    reversibility: isReadOnly ? .readOnly : .recoverable,
                    secretHandling: .credentialUse,
                    executionRecommendation: executionRecommendation,
                    confidence: 0.95
                )
            } ?? .conservativeDefault
        )
    }

    func independentlyReviewedSSH(
        command: String,
        recommendation: AgentRiskAssessment.ExecutionRecommendation = .automatic,
        reviewID: UUID? = nil
    ) -> SecretOperationDescriptor {
        let readOnly = command == "hostname"
        return ssh(
            command: command,
            reviewID: reviewID,
            agentAssessment: AgentRiskAssessment(
                source: .independentJudge,
                declaredRisk: recommendation == .automatic ? .silent : .approvalRequired,
                reason: "Independent review of the concrete task",
                userGoal: "Complete the user-requested operation",
                taskContext: "The daemon-issued gray review covers one bounded task",
                intendedEffect: readOnly ? "Inspect the host name" : "Apply the requested remote change",
                expectedEffect: readOnly ? "No persistent change" : "Change only the requested target",
                expectedResult: "The requested operation completes",
                intentAlignment: .direct,
                effectSeverity: readOnly ? .none : .bounded,
                reversibility: readOnly ? .readOnly : .recoverable,
                secretHandling: .credentialUse,
                executionRecommendation: recommendation,
                confidence: 0.95
            )
        )
    }

    func http(method: String, path: String) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .apiRequest,
            secretReferences: [reference],
            destination: "qnap.local:8080",
            port: 8080,
            protocolType: .http,
            httpMethod: method,
            url: "http://qnap.local:8080\(path)",
            requestedEffects: [method == "GET" ? "read-only" : "remote-write"],
            parameters: ["tokenRef": reference.description]
        )
    }

    func bind(
        destination: String,
        protocolType: SecretOperationProtocol = .http
    ) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .changeDestinationBinding,
            secretReferences: [reference],
            destination: destination,
            protocolType: protocolType,
            requestedEffects: ["bind-secret-destination"]
        )
    }

    func statusValues() async -> [WorkbenchStatus] {
        await statusRecorder.values
    }

    func auditEntries() async -> [AgentAutomationAuditEntry] {
        await auditRecorder.entries
    }

    func executionScope(
        principal: String = AuditSource.agent.rawValue,
        generation: UInt64 = 0
    ) -> ExecutionAuthorizationScope {
        return ExecutionAuthorizationScope(
            principal: principal,
            secretReferenceIDs: [reference.description],
            normalizedDestination: "qnap.local",
            port: 22,
            username: "admin",
            protocolType: SecretOperationProtocol.ssh.rawValue,
            actionFamily: SecretOperationAction.sshCommand.rawValue,
            generation: generation
        )
    }

    /// Mirrors `VaultAppServices.scopedAuthorizationScope` so tests can assert
    /// exact lease state for any descriptor, including HTTP operations whose
    /// scope carries the operation fingerprint.
    func executionScope(
        for descriptor: SecretOperationDescriptor,
        principal: String = AuditSource.agent.rawValue,
        generation: UInt64 = 0
    ) -> ExecutionAuthorizationScope {
        let actionFamily = descriptor.actionType == .databaseQuery
            ? SecretOperationPolicyEngine().databaseAuthorizationScopeFamily(for: descriptor.effectiveDatabaseStatement)
            : descriptor.actionType.rawValue
        return ExecutionAuthorizationScope(
            principal: principal,
            secretReferenceIDs: descriptor.secretReferences.map(\.description),
            normalizedDestination: descriptor.normalizedDestination,
            port: descriptor.port,
            username: descriptor.actionType == .sshCommand ? descriptor.parameters["username"] : nil,
            protocolType: descriptor.protocolType?.rawValue,
            actionFamily: actionFamily,
            operationFingerprint: nil,
            generation: generation
        )
    }

    func exportScope(
        principal: String = AuditSource.agent.rawValue,
        generation: UInt64 = 0
    ) -> ExecutionAuthorizationScope {
        ExecutionAuthorizationScope(
            principal: principal,
            secretReferenceIDs: [reference.description],
            normalizedDestination: exportDirectory.standardizedFileURL.path,
            port: nil,
            protocolType: SecretOperationProtocol.file.rawValue,
            actionFamily: SecretOperationAction.exportPlaintext.rawValue,
            generation: generation
        )
    }

    func replaceWithReadOnlyRecord() async throws {
        let record = try VaultCipher().encrypt(
            Data("ASV_CANARY_OPERATION_SECRET_V2".utf8),
            id: reference.id,
            version: 2,
            label: "QNAP credential",
            policy: .read,
            allowedDestinations: ["qnap.local"],
            allowedProtocols: ["ssh"],
            masterKey: key
        )
        try await store.save(record)
    }

    func remove() {
        try? FileManager.default.removeItem(at: root)
    }
}

private actor BindingCommitGate {
    private var shouldPauseNextSave = false
    private var saveStarted = false
    private var saveStartWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func pauseNextSave() {
        shouldPauseNextSave = true
    }

    func waitUntilSaveStarts() async {
        if saveStarted { return }
        await withCheckedContinuation { continuation in
            saveStartWaiters.append(continuation)
        }
    }

    func beforeSave() async {
        guard shouldPauseNextSave else { return }
        shouldPauseNextSave = false
        saveStarted = true
        let waiters = saveStartWaiters
        saveStartWaiters.removeAll()
        await withCheckedContinuation { continuation in
            releaseContinuation = continuation
            waiters.forEach { $0.resume() }
        }
    }

    func releaseSave() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private struct SaveGatedRecordStore: RecordStore, Sendable {
    let base: FileRecordStore
    let gate: BindingCommitGate

    func save(_ record: EncryptedRecord) async throws {
        await gate.beforeSave()
        try await base.save(record)
    }

    func latest(id: String) async throws -> EncryptedRecord {
        try await base.latest(id: id)
    }

    func versions(id: String) async throws -> [Int] {
        try await base.versions(id: id)
    }
}

private final class ServiceTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedNow: Date
    private var storedMonotonicNow: UInt64 = 0

    init(_ now: Date) {
        storedNow = now
    }

    var now: Date {
        get { lock.withLock { storedNow } }
        set { lock.withLock { storedNow = newValue } }
    }

    var monotonicNow: UInt64 {
        get { lock.withLock { storedMonotonicNow } }
        set { lock.withLock { storedMonotonicNow = newValue } }
    }
}
@Test func operationIDLifecycleReportsApprovalThenSuccess() async throws {
    let gate = ApprovalGate()
    let fixture = try await OperationServiceFixture(approval: .gated, approvalGate: gate)
    defer { fixture.remove() }

    let handle = try await fixture.service.startSecretOperation(fixture.ssh(command: "hostname"))
    #expect(handle.state == .queued)
    _ = try await waitForOperationState(fixture.service, operationID: handle.operationID, state: .awaitingApproval)

    await gate.release()
    let final = try await waitForOperationState(fixture.service, operationID: handle.operationID, state: .succeeded)
    #expect(final.output?.status == "COMPLETED")
    #expect(final.errorCode == nil)
}

@Test func operationIDCancellationBeforeApprovalIsDefinitive() async throws {
    let gate = ApprovalGate()
    let fixture = try await OperationServiceFixture(approval: .gated, approvalGate: gate)
    defer { fixture.remove() }

    let handle = try await fixture.service.startSecretOperation(fixture.ssh(command: "hostname"))
    _ = try await waitForOperationState(fixture.service, operationID: handle.operationID, state: .awaitingApproval)
    let cancelled = try await fixture.service.cancelSecretOperation(operationID: handle.operationID)
    #expect(cancelled.state == .cancelled)

    await gate.release()
    try await Task.sleep(for: .milliseconds(20))
    #expect(try await fixture.service.secretOperationStatus(operationID: handle.operationID).state == .cancelled)
    #expect(await fixture.executor.count == 0)
}

@Test func operationIDCancellationDuringExecutorIsOutcomeUnknown() async throws {
    let fixture = try await OperationServiceFixture(blockExecution: true)
    defer { fixture.remove() }

    let handle = try await fixture.service.startSecretOperation(fixture.ssh(command: "hostname"))
    _ = try await waitForOperationState(fixture.service, operationID: handle.operationID, state: .running)
    let cancelled = try await fixture.service.cancelSecretOperation(operationID: handle.operationID)
    #expect(cancelled.state == .outcomeUnknown)

    try await Task.sleep(for: .milliseconds(20))
    #expect(try await fixture.service.secretOperationStatus(operationID: handle.operationID).state == .outcomeUnknown)
}

private func waitForOperationState(
    _ service: VaultAppServices,
    operationID: UUID,
    state: SecretOperationState
) async throws -> SecretOperationStatus {
    for _ in 0..<200 {
        let status = try await service.secretOperationStatus(operationID: operationID)
        if status.state == state { return status }
        if status.state.isTerminal {
            Issue.record("Operation reached unexpected terminal state: \(status.state)")
            return status
        }
        try await Task.sleep(for: .milliseconds(5))
    }
    let status = try await service.secretOperationStatus(operationID: operationID)
    Issue.record("Timed out waiting for operation state \(state); current state is \(status.state)")
    return status
}
