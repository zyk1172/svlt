import Foundation

/// Compatibility state for older purpose-bound Agent authorization records.
/// Current effect-based policy does not create this scope for ordinary AUTO
/// operations: Secret use, first use, operation IDs, transport sessions, and
/// elapsed time are not authorization grants. Existing scope state remains
/// principal/Secret/destination/generation bound so old state can be invalidated
/// safely, and it must never contain resolved Secret material.
public struct ExecutionAuthorizationScope: Hashable, Sendable {
    public let principal: String
    public let secretReferenceIDs: [String]
    public let normalizedDestination: String?
    public let port: Int?
    public let username: String?
    public let protocolType: String?
    public let actionFamily: String
    /// Canonical operation identity for legacy compatibility records where
    /// reusing an approval across paths, methods, headers, or bodies would be
    /// unsafe. Current ordinary SSH policy does not use a scope grant.
    public let operationFingerprint: String?
    public let generation: UInt64

    public init(
        principal: String,
        secretReferenceIDs: [String],
        normalizedDestination: String?,
        port: Int?,
        username: String? = nil,
        protocolType: String?,
        actionFamily: String,
        operationFingerprint: String? = nil,
        generation: UInt64
    ) {
        self.principal = principal
        // Duplicate references are rejected by the policy boundary. Preserve
        // the input here instead of silently deduplicating an invalid scope.
        self.secretReferenceIDs = secretReferenceIDs.sorted()
        self.normalizedDestination = normalizedDestination
        self.port = port
        self.username = username
        self.protocolType = protocolType
        self.actionFamily = actionFamily
        self.operationFingerprint = operationFingerprint
        self.generation = generation
    }
}
