import Foundation
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

/// Thin compatibility adapter between the App service surface and the
/// dedicated SecretOperationService coordination owner.
public extension VaultAppServices {
    func startSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationHandle {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        return await secretOperationService.start(
            principal: principal,
            descriptor: descriptor,
            execute: { [weak self] descriptor in
                guard let self else {
                    throw VaultCore.SecretOperationError.actionExecutionFailed
                }
                return try await self.performSecretOperation(descriptor)
            }
        )
    }

    func secretOperationStatus(operationID: UUID) async throws -> SecretOperationStatus {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        return await secretOperationService.statusForBoundary(
            operationID: operationID,
            principal: principal
        )
    }

    func cancelSecretOperation(operationID: UUID) async throws -> SecretOperationStatus {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        return await secretOperationService.cancelForBoundary(
            operationID: operationID,
            principal: principal
        ).status
    }
}

extension VaultAppServices {
    static func approveWithTimeout(
        approver: any OperationApproving,
        timeout: Duration,
        summary: String
    ) async throws -> LocalAuthenticationContext? {
        try await withThrowingTaskGroup(of: LocalAuthenticationContext?.self) { group in
            group.addTask {
                if let contextApprover = approver as? any OperationApprovalContextProviding {
                    return try await contextApprover.approveWithAuthenticationContext(summary: summary)
                }
                try await approver.approve(summary: summary)
                return nil
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                throw OperationAuthorizationError.timeout
            }
            defer { group.cancelAll() }
            guard let result = try await group.next() else {
                throw OperationAuthorizationError.cancelled
            }
            return result
        }
    }

    func noteTrackedSecretOperationState(_ state: SecretOperationState) async {
        await secretOperationService.transitionCurrent(to: state)
    }

    func ensureTrackedSecretOperationIsActive() throws {
        try SecretOperationService.ensureCurrentOperationIsActive()
    }

    func trackedSecretOperationID() -> UUID? {
        SecretOperationService.currentOperationID
    }
}
