import Foundation

/// Compatibility state owned by one running Agent. The current effect-based
/// Secret operation policy does not authorize or create execution scopes for
/// ordinary `AUTO` work. Legacy and strict flows may still use these entries,
/// which remain bound to the exact principal, Secret, destination and security
/// generation; the daemon clears them on sleep, screen lock, user/session
/// changes, explicit lock, security-state invalidation and process restart.
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
