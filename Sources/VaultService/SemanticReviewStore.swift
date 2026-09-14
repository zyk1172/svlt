import Foundation

/// Actor-owned state for the short-lived evidence that binds an independent
/// semantic review to one daemon preflight. The review ID is only a lookup
/// handle; all authorization-relevant fields are checked against the caller's
/// current request before a record is consumed.
struct SemanticReviewStore: Sendable {
    private struct PendingReview: Sendable {
        let principal: String
        let operationHash: String
        let policyRuleID: String
        let expiresAt: Date
    }

    private let ttl: TimeInterval
    private var pending: [UUID: PendingReview] = [:]

    init(ttl: TimeInterval) {
        self.ttl = max(1, ttl)
    }

    mutating func issue(
        principal: String,
        operationHash: String,
        policyRuleID: String,
        issuedAt: Date
    ) -> UUID {
        prune(at: issuedAt)
        let reviewID = UUID()
        pending[reviewID] = PendingReview(
            principal: principal,
            operationHash: operationHash,
            policyRuleID: policyRuleID,
            expiresAt: issuedAt.addingTimeInterval(ttl)
        )
        return reviewID
    }

    mutating func consumeIfValid(
        reviewID: UUID?,
        principal: String,
        operationHash: String,
        currentPolicyRuleID: String,
        now: Date
    ) -> String? {
        guard let reviewID else { return nil }
        prune(at: now)
        guard let review = pending[reviewID],
              review.expiresAt > now,
              review.principal == principal,
              review.operationHash == operationHash,
              review.policyRuleID == currentPolicyRuleID
        else {
            return nil
        }
        pending.removeValue(forKey: reviewID)
        return review.policyRuleID
    }

    private mutating func prune(at date: Date) {
        pending = pending.filter { _, review in
            review.expiresAt > date
        }
    }
}
