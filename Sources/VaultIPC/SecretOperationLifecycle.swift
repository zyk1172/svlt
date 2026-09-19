import Foundation
import VaultCore
import VaultExecution

public enum SecretOperationState: String, Codable, Equatable, Sendable {
    case queued
    case awaitingApproval
    case running
    case succeeded
    case failed
    case cancelled
    case outcomeUnknown

    public var isTerminal: Bool {
        switch self {
        case .succeeded, .failed, .cancelled, .outcomeUnknown:
            return true
        case .queued, .awaitingApproval, .running:
            return false
        }
    }
}

/// Stable lifecycle-level error codes shared by every IPC consumer. These are
/// deliberately separate from executor failures: cancellation before the
/// execution linearization point is definitive, while cancellation after that
/// point cannot prove whether an external side effect completed.
public enum SecretOperationLifecycleErrorCode {
    public static let operationNotFound = "OPERATION_NOT_FOUND"
    public static let cancelled = "OPERATION_CANCELLED"
    public static let outcomeUnknown = "OPERATION_OUTCOME_UNKNOWN"
    public static let idempotencyKeyConflict = "IDEMPOTENCY_KEY_CONFLICT"
}

public enum SecretOperationOutputStream: String, Codable, Equatable, Sendable {
    case stdout
    case stderr
}

public struct SecretOperationOutputChunk: Codable, Equatable, Sendable {
    public let cursor: UInt64
    public let stream: SecretOperationOutputStream
    public let text: String
    public let commandIndex: Int?

    public init(
        cursor: UInt64,
        stream: SecretOperationOutputStream,
        text: String,
        commandIndex: Int? = nil
    ) {
        self.cursor = cursor
        self.stream = stream
        self.text = text
        self.commandIndex = commandIndex
    }
}

public struct SecretOperationOutputPage: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let state: SecretOperationState
    public let cursor: UInt64
    public let nextCursor: UInt64
    public let chunks: [SecretOperationOutputChunk]
    public let hasMore: Bool

    public init(
        operationID: UUID,
        state: SecretOperationState,
        cursor: UInt64,
        nextCursor: UInt64,
        chunks: [SecretOperationOutputChunk],
        hasMore: Bool
    ) {
        self.operationID = operationID
        self.state = state
        self.cursor = cursor
        self.nextCursor = nextCursor
        self.chunks = chunks
        self.hasMore = hasMore
    }
}

public struct SecretOperationHandle: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let state: SecretOperationState
    public let reused: Bool?

    public init(
        operationID: UUID,
        state: SecretOperationState,
        reused: Bool? = nil
    ) {
        self.operationID = operationID
        self.state = state
        self.reused = reused
    }
}

public struct SecretOperationStatus: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let state: SecretOperationState
    public let output: SecretOperationOutput?
    public let errorCode: String?
    public let nextOutputCursor: UInt64?

    public init(
        operationID: UUID,
        state: SecretOperationState,
        output: SecretOperationOutput? = nil,
        errorCode: String? = nil,
        nextOutputCursor: UInt64? = nil
    ) {
        self.operationID = operationID
        self.state = state
        self.output = output
        self.errorCode = errorCode
        self.nextOutputCursor = nextOutputCursor
    }
}
