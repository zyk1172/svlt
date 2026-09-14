import Foundation
import VaultAuthorization
import VaultCore

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
        guard descriptor.reviewID != nil,
              descriptor.agentAssessment.source == .independentJudge else {
            return nil
        }

        let currentPreflight = operationPolicyEngine.semanticPreflight(
            descriptor,
            metadata: metadata
        )
        guard !currentPreflight.technicalFailure else {
            return nil
        }

        return semanticReviewStore.consumeIfValid(
            reviewID: descriptor.reviewID,
            principal: principal,
            operationHash: descriptor.operationHash,
            currentPolicyRuleID: currentPreflight.policyRuleID,
            now: now()
        )
    }
}
