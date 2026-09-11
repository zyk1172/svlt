import CryptoKit
import Foundation
import VaultAuthorization

/// Coordinates the in-memory master-key capability that backs one scoped
/// execution authorization lease.
///
/// The coordinator deliberately owns only transient key material and the
/// tasks associated with it. It has no IPC surface and never persists or
/// returns plaintext. The caller remains responsible for policy evaluation
/// and for establishing the matching `AuthorizationSession` lease.
public actor ScopedMasterKeyCoordinator {
    private struct Authorization: Sendable {
        let key: SymmetricKey
    }

    private struct Flight: Sendable {
        let task: Task<SymmetricKey, Error>
    }

    private struct Expiry: Sendable {
        let id: UUID
        let task: Task<Void, Never>
    }

    private let invalidateExecutionAuthorization:
        @Sendable (ExecutionAuthorizationScope) async -> Void
    private var authorizations: [ExecutionAuthorizationScope: Authorization] = [:]
    private var flights: [ExecutionAuthorizationScope: Flight] = [:]
    private var expiryTasks: [ExecutionAuthorizationScope: Expiry] = [:]

    public init(
        invalidateExecutionAuthorization: @escaping @Sendable (ExecutionAuthorizationScope) async -> Void
    ) {
        self.invalidateExecutionAuthorization = invalidateExecutionAuthorization
    }

    /// Whether this coordinator still has the key captured for a scope.
    /// This is intentionally separate from `AuthorizationSession`: both the
    /// lease and the matching key must be present before a scoped operation
    /// can reuse authorization.
    public func hasAuthorization(for scope: ExecutionAuthorizationScope) -> Bool {
        authorizations[scope] != nil
    }

    /// Resolve a key for an already-scoped operation.
    ///
    /// A missing or expired lease invalidates any stale key before loading a
    /// new one. Invalidation and provider loading are one per-scope flight so
    /// concurrent callers cannot race multiple stale-lease invalidations
    /// against a newly committed authorization or duplicate provider work.
    public func resolveKey(
        for scope: ExecutionAuthorizationScope,
        isLeaseActive: @escaping @Sendable () async -> Bool,
        load: @escaping @Sendable () async throws -> SymmetricKey
    ) async throws -> SymmetricKey {
        if await isLeaseActive(), let authorization = authorizations[scope] {
            return authorization.key
        }

        // `isLeaseActive()` crosses an actor boundary. Another caller may have
        // established a refresh flight while this actor was re-entrant, so
        // always join that flight before invalidating the same scope again.
        if let flight = flights[scope] {
            return try await flight.task.value
        }

        clearAuthorization(for: scope)
        let invalidateExecutionAuthorization = self.invalidateExecutionAuthorization
        let task = Task<SymmetricKey, Error> {
            // The stale-lease invalidation belongs to the same single-flight as
            // the provider read. This prevents a second concurrent caller from
            // issuing a late invalidation after the first caller has committed
            // a new lease for the same scope.
            await invalidateExecutionAuthorization(scope)
            try Task.checkCancellation()
            return try await load()
        }
        flights[scope] = Flight(task: task)
        do {
            let key = try await task.value
            // Keep the completed flight until the caller commits the matching
            // authorization. A second request can resume after key loading
            // but before that commit; retaining the flight preserves the
            // original single-flight handoff and prevents it from starting a
            // second provider read or invalidating the first lease.
            return key
        } catch {
            flights.removeValue(forKey: scope)
            throw error
        }
    }

    /// Capture the key obtained immediately after owner approval. The expiry
    /// duration is descriptive and mirrors the `AuthorizationSession` window;
    /// the session remains the authorization source of truth.
    public func storeAuthorizedKey(
        _ key: SymmetricKey,
        for scope: ExecutionAuthorizationScope,
        duration: TimeInterval?
    ) {
        if let duration {
            authorizations[scope] = Authorization(key: key)
            scheduleExpiry(for: scope, after: duration)
        } else {
            clearAuthorization(for: scope)
        }
        flights.removeValue(forKey: scope)
    }

    /// Drop all transient capability material during lock, sleep, shutdown,
    /// or another security-state invalidation. The caller invalidates the
    /// broader authorization session in the same transition.
    public func invalidateAll() {
        for flight in flights.values {
            flight.task.cancel()
        }
        flights.removeAll()
        for expiry in expiryTasks.values {
            expiry.task.cancel()
        }
        expiryTasks.removeAll()
        for authorization in authorizations.values {
            wipe(authorization.key)
        }
        authorizations.removeAll()
    }

    /// Drop one scope and its associated in-flight/expiry tasks.
    public func abandon(scope: ExecutionAuthorizationScope) async {
        flights.removeValue(forKey: scope)?.task.cancel()
        clearAuthorization(for: scope)
        await invalidateExecutionAuthorization(scope)
    }

    private func scheduleExpiry(
        for scope: ExecutionAuthorizationScope,
        after duration: TimeInterval
    ) {
        expiryTasks.removeValue(forKey: scope)?.task.cancel()
        let id = UUID()
        let task = Task { [weak self] in
            try? await Task.sleep(for: .seconds(duration))
            guard !Task.isCancelled else { return }
            await self?.expire(scope: scope, expiryID: id)
        }
        expiryTasks[scope] = Expiry(id: id, task: task)
    }

    private func expire(
        scope: ExecutionAuthorizationScope,
        expiryID: UUID
    ) async {
        guard expiryTasks[scope]?.id == expiryID else {
            return
        }
        expiryTasks.removeValue(forKey: scope)
        clearAuthorization(for: scope)
        await invalidateExecutionAuthorization(scope)
    }

    private func clearAuthorization(for scope: ExecutionAuthorizationScope) {
        expiryTasks.removeValue(forKey: scope)?.task.cancel()
        if let authorization = authorizations.removeValue(forKey: scope) {
            wipe(authorization.key)
        }
    }

    private func wipe(_ key: SymmetricKey) {
        var keyData = key.withUnsafeBytes { Data($0) }
        keyData.resetBytes(in: 0..<keyData.count)
    }
}
