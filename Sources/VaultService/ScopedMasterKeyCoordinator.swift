import CryptoKit
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
