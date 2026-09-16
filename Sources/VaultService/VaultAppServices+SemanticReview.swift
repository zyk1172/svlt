import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore

enum SemanticReviewFallbackPolicy {
    private static let fallbackRuleIDs: Set<String> = [
        "ssh.fresh.filesystem-delete",
        "ssh.gray.container-lifecycle-removal",
        "http.fresh.delete",
        "database.fresh.destructive-write",
        "database.fresh.dynamic-execution",
        "database.fresh.unknown",
        "sftp.fresh.delete"
    ]

    private static let blockedReasonFragments = [
        "凭据执行目标或协议超出既有绑定范围",
        "操作包含动态或不透明执行"
    ]

    static func isEligible(
        assessment: AgentRiskAssessment,
        preflight: SecretOperationPreflight
    ) -> Bool {
        guard preflight.route == .gray,
              !preflight.technicalFailure,
              fallbackRuleIDs.contains(preflight.policyRuleID),
              assessment.source == .mainAgent,
              assessment.confidence >= 0.65,
              assessment.intentAlignment == .direct || assessment.intentAlignment == .supporting,
              [.none, .minor, .bounded].contains(assessment.effectSeverity),
              [.readOnly, .easy, .recoverable].contains(assessment.reversibility),
              assessment.secretHandling == .none || assessment.secretHandling == .credentialUse,
              assessment.executionRecommendation != .uncertain
        else {
            return false
        }

        return !preflight.reasons.contains { reason in
            blockedReasonFragments.contains { reason.contains($0) }
        }
    }

    static func assessmentHash(_ assessment: AgentRiskAssessment) -> String {
        let fields = [
            assessment.source.rawValue,
            assessment.declaredRisk.rawValue,
            assessment.reason,
            assessment.userGoal,
            assessment.taskContext,
            assessment.intendedEffect,
            assessment.expectedEffect,
            assessment.expectedResult,
            assessment.intentAlignment.rawValue,
            assessment.effectSeverity.rawValue,
            assessment.reversibility.rawValue,
            assessment.secretHandling.rawValue,
            assessment.executionRecommendation.rawValue,
            String(assessment.confidence.bitPattern)
        ]
        let canonical = fields.map { "\($0.utf8.count):\($0)" }.joined()
        return SHA256.hash(data: Data(canonical.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

extension VaultAppServices {
    public func approvalMode() async -> VaultApprovalMode {
        VaultApprovalModeState.shared.mode
    }

    @discardableResult
    public func setApprovalMode(_ mode: VaultApprovalMode) async throws -> VaultApprovalMode {
        let persisted = try VaultApprovalModeState.shared.setMode(mode)
        // A mode change is a security-boundary transition. Cancel operations
        // that began under the previous posture so execution always observes
        // the current daemon-authoritative mode from start to finish.
        await invalidateSecurityState()
        return persisted
    }

    public func preflightSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationPreflight {
        let metadata = try await policyMetadata(for: descriptor.secretReferences)
        let preflight = operationPolicyEngine.semanticPreflight(descriptor, metadata: metadata)

        if VaultApprovalModeState.shared.mode == .noApproval {
            // In full-access mode the MCP layer must not invoke the semantic
            // judge or manufacture a fresh owner approval. Structural and
            // executor validation still run when the daemon executes the
            // descriptor, so malformed/unsupported operations still fail for
            // technical reasons rather than as an authorization decision.
            return SecretOperationPreflight(
                route: .fast,
                policyRuleID: preflight.policyRuleID,
                authorizationRequirement: .none,
                blastRadius: preflight.blastRadius,
                reasons: preflight.reasons + [
                    "SVLT 无审批模式：是否执行由主 Agent、用户意图和宿主审批/安全策略决定"
                ],
                technicalFailure: false,
                reviewID: nil
            )
        }

        guard preflight.route == .gray else {
            return preflight
        }

        let issuedAt = now()
        let reviewID = semanticReviewStore.issue(
            principal: AuditContext.current?.principal ?? AuditSource.agent.rawValue,
            operationHash: descriptor.operationHash,
            policyRuleID: preflight.policyRuleID,
            mainAssessmentHash: SemanticReviewFallbackPolicy.assessmentHash(descriptor.agentAssessment),
            issuedAt: issuedAt
        )
        return SecretOperationPreflight(
            route: preflight.route,
            policyRuleID: preflight.policyRuleID,
            authorizationRequirement: preflight.authorizationRequirement,
            blastRadius: preflight.blastRadius,
            reasons: preflight.reasons,
            technicalFailure: preflight.technicalFailure,
            reviewID: reviewID
        )
    }

    func evaluateSecretOperation(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        verifiedSemanticReviewRuleID: String?
    ) -> PolicyDecision {
        let decision: PolicyDecision
        if let verifiedSemanticReviewRuleID,
           operationPolicyEngine.semanticPreflight(descriptor, metadata: metadata).policyRuleID
               == verifiedSemanticReviewRuleID {
            switch descriptor.agentAssessment.source {
            case .independentJudge:
                decision = operationPolicyEngine.evaluateWithVerifiedIndependentJudge(
                    descriptor,
                    metadata: metadata
                )
            case .mainAgent:
                decision = operationPolicyEngine.evaluateWithVerifiedBoundedMainAgentFallback(
                    descriptor,
                    metadata: metadata
                )
            }
        } else {
            decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        }

        guard VaultApprovalModeState.shared.mode == .noApproval,
              !decision.technicalFailure else {
            return decision
        }

        // Preserve a fresh internal requirement for paths that use it as a
        // structural marker (for example destination-binding mutations), but
        // remove DENIED as an SVLT authorization outcome. LocalOperationApprover
        // is the final prompt boundary and is a no-op in this mode.
        let requirement: AuthorizationRequirement = decision.authorizationRequirement == .none
            ? .none
            : .freshApprovalRequired
        return PolicyDecision(
            risk: requirement == .none ? .silent : .approvalRequired,
            reasons: decision.reasons + [
                "SVLT 无审批模式：本机风险分级仅作为审计信息，不阻断该操作"
            ],
            normalizedDestination: decision.normalizedDestination,
            requiredApproval: false,
            policyRuleID: "\(decision.policyRuleID)+no-approval",
            authorizationRequirement: requirement,
            requiresFreshApprovalOnFirstUse: false,
            technicalFailure: false
        )
    }

    /// Consumes a daemon-issued gray review only after every binding has been
    /// checked. A mismatched review remains available to its rightful caller;
    /// a valid review is removed before any approval or execution await so it
    /// cannot be replayed after a later failure.
    func consumeSemanticReviewIfValid(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        principal: String
    ) -> String? {
        guard VaultApprovalModeState.shared.mode == .approvalRequired,
              descriptor.reviewID != nil else {
            return nil
        }

        let currentPreflight = operationPolicyEngine.semanticPreflight(
            descriptor,
            metadata: metadata
        )
        guard !currentPreflight.technicalFailure else {
            return nil
        }

        let isIndependentJudge = descriptor.agentAssessment.source == .independentJudge
        let isBoundMainFallback = SemanticReviewFallbackPolicy.isEligible(
            assessment: descriptor.agentAssessment,
            preflight: currentPreflight
        )
        guard isIndependentJudge || isBoundMainFallback else {
            return nil
        }

        return semanticReviewStore.consumeIfValid(
            reviewID: descriptor.reviewID,
            principal: principal,
            operationHash: descriptor.operationHash,
            currentPolicyRuleID: currentPreflight.policyRuleID,
            currentMainAssessmentHash: isBoundMainFallback
                ? SemanticReviewFallbackPolicy.assessmentHash(descriptor.agentAssessment)
                : nil,
            now: now()
        )
    }
}
