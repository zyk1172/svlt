import Foundation
import VaultCore

enum CatalogWriteAccessState: Sendable {
    case pending
    case authenticating
    case approved
    case consumed
    case denied
    case expired
    case cancelled

    var isPendingForPresentation: Bool {
        self == .pending || self == .authenticating
    }

    var isTerminal: Bool {
        switch self {
        case .approved, .consumed, .denied, .expired, .cancelled:
            return true
        case .pending, .authenticating:
            return false
        }
    }
}

final class CatalogWriteAccessContinuationBox: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?

    func store(_ continuation: CheckedContinuation<Void, Error>) {
        lock.lock()
        defer { lock.unlock() }
        self.continuation = continuation
    }

    func resume(throwing error: Error? = nil) {
        lock.lock()
        defer { lock.unlock() }
        guard let continuation else { return }
        self.continuation = nil
        if let error {
            continuation.resume(throwing: error)
        } else {
            continuation.resume()
        }
    }
}

struct CatalogWriteAccessResponseSnapshot: Sendable {
    let request: CatalogAgentWriteAccessRequest
    let continuation: CatalogWriteAccessContinuationBox
    let auditContext: AuditContext?
}

/// Actor-confined owner for the four pieces of state that must advance with one
/// Catalog write-access request. Device-owner authentication, authorization
/// grants, notifications, timeout scheduling, and audit emission remain in
/// `VaultAppServices`; this value only keeps request lifecycle bookkeeping
/// coherent across those operations.
struct CatalogWriteAccessLifecycle: Sendable {
    private var requests: [UUID: CatalogAgentWriteAccessRequest] = [:]
    private var continuations: [UUID: CatalogWriteAccessContinuationBox] = [:]
    private var states: [UUID: CatalogWriteAccessState] = [:]
    private var auditContexts: [UUID: AuditContext] = [:]

    @discardableResult
    mutating func insert(
        _ request: CatalogAgentWriteAccessRequest,
        auditContext: AuditContext
    ) -> CatalogWriteAccessContinuationBox {
        let continuation = CatalogWriteAccessContinuationBox()
        requests[request.id] = request
        continuations[request.id] = continuation
        states[request.id] = .pending
        auditContexts[request.id] = auditContext
        return continuation
    }

    func pendingRequest(id: UUID) -> CatalogAgentWriteAccessRequest? {
        guard let request = requests[id],
              states[id]?.isPendingForPresentation == true
        else {
            return nil
        }
        return request
    }

    var pendingRequestIDs: [UUID] {
        requests.keys
            .filter { states[$0]?.isPendingForPresentation == true }
            .sorted { lhs, rhs in
                (requests[lhs]?.createdAt ?? "") < (requests[rhs]?.createdAt ?? "")
            }
    }

    func responseSnapshot(id: UUID) -> CatalogWriteAccessResponseSnapshot? {
        guard states[id] == .pending,
              let request = requests[id],
              let continuation = continuations[id]
        else {
            return nil
        }
        return CatalogWriteAccessResponseSnapshot(
            request: request,
            continuation: continuation,
            auditContext: auditContexts[id]
        )
    }

    func state(for id: UUID) -> CatalogWriteAccessState? {
        states[id]
    }

    func intent(for id: UUID) -> CatalogAgentWriteIntent? {
        requests[id]?.intent
    }

    mutating func markAuthenticating(id: UUID) -> Bool {
        guard states[id] == .pending else { return false }
        states[id] = .authenticating
        return true
    }

    mutating func markApproved(id: UUID) {
        guard states[id] != nil else { return }
        states[id] = .approved
    }

    mutating func markConsumed(id: UUID) {
        guard states[id] != nil else { return }
        states[id] = .consumed
    }

    mutating func markDenied(id: UUID) {
        guard states[id] != nil else { return }
        states[id] = .denied
    }

    @discardableResult
    mutating func markExpiredIfActive(id: UUID) -> CatalogWriteAccessContinuationBox? {
        guard states[id]?.isPendingForPresentation == true else { return nil }
        states[id] = .expired
        return continuations[id]
    }

    @discardableResult
    mutating func markCancelledIfActive(id: UUID) -> CatalogWriteAccessContinuationBox? {
        guard states[id]?.isPendingForPresentation == true else { return nil }
        states[id] = .cancelled
        return continuations[id]
    }

    mutating func cleanup(id: UUID) {
        requests.removeValue(forKey: id)
        continuations.removeValue(forKey: id)
        auditContexts.removeValue(forKey: id)
        pruneTerminalStates()
    }

    var retainedStateCount: Int {
        states.count
    }

    private mutating func pruneTerminalStates() {
        guard states.count > 128 else { return }
        let terminal = states.filter { $0.value.isTerminal }
        for id in terminal.keys.prefix(states.count - 128) {
            states.removeValue(forKey: id)
        }
    }
}
