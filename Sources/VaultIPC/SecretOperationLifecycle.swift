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

public struct SecretOperationHandle: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let state: SecretOperationState

    public init(operationID: UUID, state: SecretOperationState) {
        self.operationID = operationID
        self.state = state
    }
}

public struct SecretOperationStatus: Codable, Equatable, Sendable {
    public let operationID: UUID
    public let state: SecretOperationState
    public let output: SecretOperationOutput?
    public let errorCode: String?

    public init(
        operationID: UUID,
        state: SecretOperationState,
        output: SecretOperationOutput? = nil,
        errorCode: String? = nil
    ) {
        self.operationID = operationID
        self.state = state
        self.output = output
        self.errorCode = errorCode
    }
}
