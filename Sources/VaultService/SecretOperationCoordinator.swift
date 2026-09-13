import Foundation
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
