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
    public func preflightSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationPreflight {
        let metadata = try await policyMetadata(for: descriptor.secretReferences)
        let preflight = operationPolicyEngine.semanticPreflight(descriptor, metadata: metadata)
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
        if let verifiedSemanticReviewRuleID,
           operationPolicyEngine.semanticPreflight(descriptor, metadata: metadata).policyRuleID
               == verifiedSemanticReviewRuleID {
            // The verified review can be either a real independent-judge
            // result or the exact main-Agent assessment that the daemon bound
            // during preflight and later accepted under the narrow bounded
            // fallback policy. The policy engine already treats main-Agent
            // fresh/deny hints as evidence rather than final decisions.
            return operationPolicyEngine.evaluateWithVerifiedIndependentJudge(
                descriptor,
                metadata: metadata
            )
        }
        return operationPolicyEngine.evaluate(descriptor, metadata: metadata)
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
        guard descriptor.reviewID != nil else {
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
