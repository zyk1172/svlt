import Foundation
import Testing
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func daemonConfigurationKeepsCredentialAndExternalSendTTLs() {
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

@Test func daemonConfigurationCarriesOnlyAppOwnedHTTPProjectionProfiles() {
    let profile = HTTPResponseProjectionProfile(
        id: "status-profile",
        origin: "https://qnap.local",
        allowedMethods: [.get],
        path: "/status",
        allowedJSONPointers: ["/status"]
    )
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: URL(filePath: "/tmp/svlt-config-vault"),
        auditRootURL: URL(filePath: "/tmp/svlt-config-audit"),
        ipcConfiguration: UnixSocketServerConfiguration(
            directoryURL: URL(filePath: "/tmp/svlt-config-ipc")
        ),
        httpResponseProjectionProfiles: [profile]
    )

    #expect(configuration.httpResponseProjectionProfiles == [profile])
}

@Test func daemonStartsWithIPCAvailableButVaultLockedWithoutEagerAuthentication() async throws {
    let root = URL(filePath: "/tmp/svlt-vault-\(UUID().uuidString)")
    let audit = URL(filePath: "/tmp/svlt-audit-\(UUID().uuidString)")
    let ipc = URL(filePath: "/tmp/svlt-ipc-\(UUID().uuidString)")
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: root.appending(path: "vault"),
        auditRootURL: audit,
        ipcConfiguration: UnixSocketServerConfiguration(directoryURL: ipc)
    )
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: audit)
        try? FileManager.default.removeItem(at: ipc)
    }

    let daemon = try VaultDaemonCore(configuration: configuration)
    try await daemon.start()

    let status = await daemon.status()
    #expect(status.ipcAvailable)
    #expect(status.locked)
    #expect(FileManager.default.fileExists(atPath: configuration.ipcConfiguration.socketURL.path))
    #expect(FileManager.default.fileExists(atPath: configuration.ipcConfiguration.tokenURL.path))

    await daemon.stop()
    #expect(!FileManager.default.fileExists(atPath: configuration.ipcConfiguration.socketURL.path))
}

@Test func semanticReviewFallbackAllowsOnlyBoundedKnownGrayEffects() {
    let assessment = boundedAutomaticAssessment()
    let preflight = SecretOperationPreflight(
        route: .gray,
        policyRuleID: "ssh.fresh.filesystem-delete",
        authorizationRequirement: .freshApprovalRequired,
        blastRadius: .unknown,
        reasons: ["本地分类器检测到需要独立语义复核的操作族"],
        reviewID: UUID()
    )

    #expect(SemanticReviewFallbackPolicy.isEligible(
        assessment: assessment,
        preflight: preflight
    ))
}

@Test func semanticReviewFallbackRejectsBindingConflictOpaqueAndUnknownSemantics() {
    let assessment = boundedAutomaticAssessment()
    let bindingConflict = SecretOperationPreflight(
        route: .gray,
        policyRuleID: "ssh.fresh.filesystem-delete",
        authorizationRequirement: .freshApprovalRequired,
        blastRadius: .unknown,
        reasons: ["凭据执行目标或协议超出既有绑定范围"],
        reviewID: UUID()
    )
    let opaqueExecution = SecretOperationPreflight(
        route: .gray,
        policyRuleID: "ssh.fresh.filesystem-delete",
        authorizationRequirement: .freshApprovalRequired,
        blastRadius: .unknown,
        reasons: ["操作包含动态或不透明执行"],
        reviewID: UUID()
    )
    let unknownAssessment = AgentRiskAssessment(
        declaredRisk: .approvalRequired,
        reason: "The real effect is unknown",
        userGoal: "Complete the requested task",
        taskContext: "No reliable effect evidence",
        intendedEffect: "Unknown",
        expectedEffect: "Unknown",
        expectedResult: "Unknown",
        intentAlignment: .unclear,
        effectSeverity: .unknown,
        reversibility: .unknown,
        secretHandling: .unknown,
        executionRecommendation: .uncertain,
        confidence: 0.2
    )

    #expect(!SemanticReviewFallbackPolicy.isEligible(
        assessment: assessment,
        preflight: bindingConflict
    ))
    #expect(!SemanticReviewFallbackPolicy.isEligible(
        assessment: assessment,
        preflight: opaqueExecution
    ))
    #expect(!SemanticReviewFallbackPolicy.isEligible(
        assessment: unknownAssessment,
        preflight: SecretOperationPreflight(
            route: .gray,
            policyRuleID: "ssh.fresh.filesystem-delete",
            authorizationRequirement: .freshApprovalRequired,
            blastRadius: .unknown,
            reasons: ["语义字段仍有未决项"],
            reviewID: UUID()
        )
    ))
}

@Test func semanticReviewStoreBindsFallbackToOriginalAssessmentHash() {
    var store = SemanticReviewStore(ttl: 120)
    let now = Date(timeIntervalSinceReferenceDate: 9_000)
    let originalHash = SemanticReviewFallbackPolicy.assessmentHash(boundedAutomaticAssessment())
    let changedHash = SemanticReviewFallbackPolicy.assessmentHash(
        boundedAutomaticAssessment(reason: "Changed after preflight")
    )
    let reviewID = store.issue(
        principal: "agent-peer-one",
        operationHash: "operation-hash",
        policyRuleID: "ssh.fresh.filesystem-delete",
        mainAssessmentHash: originalHash,
        issuedAt: now
    )

    #expect(store.consumeIfValid(
        reviewID: reviewID,
        principal: "agent-peer-one",
        operationHash: "operation-hash",
        currentPolicyRuleID: "ssh.fresh.filesystem-delete",
        currentMainAssessmentHash: changedHash,
        now: now.addingTimeInterval(1)
    ) == nil)

    #expect(store.consumeIfValid(
        reviewID: reviewID,
        principal: "agent-peer-one",
        operationHash: "operation-hash",
        currentPolicyRuleID: "ssh.fresh.filesystem-delete",
        currentMainAssessmentHash: originalHash,
        now: now.addingTimeInterval(2)
    ) == "ssh.fresh.filesystem-delete")
}

@Test func verifiedBoundedMainAgentGrayFallbackReachesAutomaticPolicyPath() throws {
    let reference = try SecretReference("secret://01ARZ3NDEKTSV4RRFFQ69G5FAV")
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "nas.local",
        port: 22,
        protocolType: .ssh,
        command: "rm -rf /share/task-owned-temp",
        agentAssessment: boundedAutomaticAssessment()
    )
    let metadata = [SecretPolicyMetadata(
        reference: reference,
        policy: .credential,
        label: "NAS credential",
        allowedDestinations: ["nas.local"],
        allowedProtocols: ["ssh"]
    )]
    let engine = SecretOperationPolicyEngine()

    #expect(engine.semanticPreflight(descriptor, metadata: metadata).route == .gray)
    #expect(engine.evaluate(descriptor, metadata: metadata).authorizationRequirement == .freshApprovalRequired)

    let verified = engine.evaluateWithVerifiedBoundedMainAgentFallback(
        descriptor,
        metadata: metadata
    )
    #expect(verified.authorizationRequirement == .none)
    #expect(verified.risk == .silent)
    #expect(verified.reasons.contains { $0.contains("mainAgent") })
}

@Test func agentExecutableSourceDoesNotImportGUIFrameworksOrUseUnlockAtStartup() throws {
    let sourceURL = URL(filePath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appending(path: "Sources/SVLTAgent/SVLTAgent.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(!source.contains("SwiftUI"))
    #expect(!source.contains("AppKit"))
    #expect(!source.contains("unlockLowProtection"))
    #expect(source.contains("withCheckedContinuation"))
}

private func boundedAutomaticAssessment(
    reason: String = "Delete one generated cache file and recreate it if needed"
) -> AgentRiskAssessment {
    AgentRiskAssessment(
        declaredRisk: .silent,
        reason: reason,
        userGoal: "Repair the requested service",
        taskContext: "The target is one generated task artifact",
        intendedEffect: "Remove one bounded generated artifact",
        expectedEffect: "One recoverable local change",
        expectedResult: "The requested repair can continue",
        intentAlignment: .direct,
        effectSeverity: .bounded,
        reversibility: .recoverable,
        secretHandling: .credentialUse,
        executionRecommendation: .automatic,
        confidence: 0.95
    )
}
