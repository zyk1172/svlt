import Foundation
import VaultCore

enum CatalogSecureInputState: Equatable, Sendable {
    case awaitingInput
    case submitting
    /// The request has crossed the cancellation linearization point. No
    /// cancellation/expiry request can turn this committed write into a
    /// terminal cancellation after the store call begins.
    case committing
    case completed
    case failed
    case expired
    case cancelled

    var statusValue: CatalogSecureInputStatusValue {
        switch self {
        case .awaitingInput, .submitting, .committing: return .pending
        case .completed: return .completed
        case .failed: return .failed
        case .expired: return .expired
        case .cancelled: return .cancelled
        }
    }
}

enum CatalogSecureInputAbortReason: Equatable, Sendable {
    case cancelled
    case expired
}

enum CatalogSecureInputAbortError: Error, Equatable, Sendable {
    case cancelled
    case expired
}

/// A bounded, non-sensitive terminal receipt. It contains only the opaque
/// request ID, outcome metadata, and timestamp; Catalog contents and
/// plaintext never enter this sidecar.
struct CatalogSecureInputReceiptRecord: Codable, Sendable {
    static let currentSchemaVersion = 1

    let schemaVersion: Int
    let requestID: UUID
    let status: CatalogSecureInputStatusValue
    let revision: UInt64?
    let errorCode: String?
    let terminalAt: Date
}

/// Owns the synchronous state transitions for one-shot Catalog Secure Input
/// requests. The surrounding service owns authentication, encryption, I/O,
/// notifications, and audit contexts; this value owns only request state and
/// non-sensitive terminal receipts.
struct CatalogSecureInputTransaction: Sendable {
    private var requests: [UUID: CatalogAgentSecureInputRequest] = [:]
    private var states: [UUID: CatalogSecureInputState] = [:]
    private var statuses: [UUID: CatalogSecureInputStatus] = [:]
    private var terminalAt: [UUID: Date] = [:]
    private var abortReasons: [UUID: CatalogSecureInputAbortReason] = [:]

    init(receipts: [CatalogSecureInputReceiptRecord] = []) {
        // The sidecar is non-authoritative. The loader orders records
        // oldest-to-newest so the newest valid record wins deterministically.
        for record in receipts {
            statuses[record.requestID] = CatalogSecureInputStatus(
                requestID: record.requestID,
                status: record.status,
                revision: record.revision,
                errorCode: record.errorCode
            )
            terminalAt[record.requestID] = record.terminalAt
        }
    }

    var pendingRequestIDs: [UUID] {
        requests
            .filter { states[$0.key] == .awaitingInput || states[$0.key] == .submitting }
            .sorted { $0.value.createdAt < $1.value.createdAt }
            .map(\.key)
    }

    var requestIDs: [UUID] {
        Array(requests.keys)
    }

    func request(id: UUID) -> CatalogAgentSecureInputRequest? {
        requests[id]
    }

    func pendingRequest(id: UUID) -> CatalogAgentSecureInputRequest? {
        guard let request = requests[id],
              states[id] == .awaitingInput || states[id] == .submitting
        else {
            return nil
        }
        return request
    }

    func state(for id: UUID) -> CatalogSecureInputState? {
        states[id]
    }

    func status(for requestID: UUID) -> CatalogSecureInputStatus {
        if let status = statuses[requestID] {
            return status
        }
        if let state = states[requestID] {
            return CatalogSecureInputStatus(
                requestID: requestID,
                status: state.statusValue
            )
        }
        return CatalogSecureInputStatus(
            requestID: requestID,
            status: .unknown,
            errorCode: "SECURE_INPUT_REQUEST_UNKNOWN"
        )
    }

    func hasRequest(forEntryID entryID: String) -> Bool {
        requests.values.contains { $0.entryID == entryID }
    }

    mutating func insert(_ request: CatalogAgentSecureInputRequest) {
        requests[request.id] = request
        states[request.id] = .awaitingInput
        statuses[request.id] = CatalogSecureInputStatus(
            requestID: request.id,
            status: .pending
        )
    }

    mutating func beginSubmission(
        id: UUID,
        now: Date
    ) throws -> CatalogAgentSecureInputRequest {
        guard let request = requests[id],
              states[id] == .awaitingInput,
              request.expiresAt > now
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        states[id] = .submitting
        return request
    }

    mutating func latchAbort(
        _ reason: CatalogSecureInputAbortReason,
        for id: UUID
    ) {
        abortReasons[id] = reason
    }

    func ensureSubmissionIsStillActive(
        id: UUID,
        request: CatalogAgentSecureInputRequest,
        now: Date
    ) throws {
        guard requests[id] != nil,
              states[id] == .submitting
        else {
            throw CatalogSecureInputAbortError.cancelled
        }
        if abortReasons[id] == .expired || request.expiresAt <= now {
            throw CatalogSecureInputAbortError.expired
        }
        if abortReasons[id] == .cancelled {
            throw CatalogSecureInputAbortError.cancelled
        }
    }

    mutating func markCommitting(
        id: UUID,
        request: CatalogAgentSecureInputRequest,
        now: Date
    ) throws {
        try ensureSubmissionIsStillActive(id: id, request: request, now: now)
        states[id] = .committing
    }

    func dueRequestIDs(now: Date) -> [UUID] {
        requests.values
            .filter { $0.expiresAt <= now }
            .map(\.id)
    }

    /// Finishes a request and returns its immutable request metadata for the
    /// caller's audit/notification work. The status itself contains no
    /// Catalog content or plaintext.
    mutating func finish(
        id: UUID,
        status: CatalogSecureInputStatus,
        terminalDate: Date
    ) -> CatalogAgentSecureInputRequest? {
        guard let request = requests.removeValue(forKey: id) else { return nil }
        states[id] = state(for: status.status)
        statuses[id] = status
        terminalAt[id] = terminalDate
        abortReasons.removeValue(forKey: id)
        return request
    }

    mutating func prune(now: Date) -> Bool {
        let cutoff = now.addingTimeInterval(-15 * 60)
        var didChange = false
        for id in Array(terminalAt.keys) where terminalAt[id, default: .distantFuture] < cutoff {
            terminalAt.removeValue(forKey: id)
            statuses.removeValue(forKey: id)
            states.removeValue(forKey: id)
            didChange = true
        }
        if terminalAt.count > 128 {
            let oldest = terminalAt
                .sorted { $0.value < $1.value }
                .prefix(terminalAt.count - 128)
            for (id, _) in oldest {
                terminalAt.removeValue(forKey: id)
                statuses.removeValue(forKey: id)
                states.removeValue(forKey: id)
                didChange = true
            }
        }
        return didChange
    }

    func receiptRecords(now: Date) -> [CatalogSecureInputReceiptRecord] {
        let cutoff = now.addingTimeInterval(-15 * 60)
        let records: [CatalogSecureInputReceiptRecord] = terminalAt.compactMap { id, terminalDate in
            guard terminalDate >= cutoff,
                  let status = statuses[id],
                  status.status != .pending
            else {
                return nil
            }
            return CatalogSecureInputReceiptRecord(
                schemaVersion: CatalogSecureInputReceiptRecord.currentSchemaVersion,
                requestID: id,
                status: status.status,
                revision: status.revision,
                errorCode: status.errorCode,
                terminalAt: terminalDate
            )
        }
        .sorted { $0.terminalAt < $1.terminalAt }
        return Array(records.suffix(128))
    }

    private func state(for status: CatalogSecureInputStatusValue) -> CatalogSecureInputState {
        switch status {
        case .completed: return .completed
        case .failed: return .failed
        case .expired: return .expired
        case .cancelled: return .cancelled
        case .pending: return .submitting
        case .unknown: return .failed
        }
    }
}
