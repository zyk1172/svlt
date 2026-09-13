import Foundation
import VaultCore
import VaultExecution
import VaultIPC

/// Thin compatibility adapter between the App service surface and the
/// dedicated SecretOperationService lifecycle owner.
public extension VaultAppServices {
    func startSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationHandle {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        return await secretOperationCoordinator.start(
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
        return await secretOperationCoordinator.statusForBoundary(
            operationID: operationID,
            principal: principal
        )
    }

    func cancelSecretOperation(operationID: UUID) async throws -> SecretOperationStatus {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        let cancellation = await secretOperationCoordinator.cancelForBoundary(
            operationID: operationID,
            principal: principal
        )
        // Only an operation proven to belong to this principal may reach the
        // lower executor task map. Missing and foreign IDs remain externally
        // indistinguishable without creating a cancellation side channel.
        if cancellation.ownedByPrincipal {
            inFlightSecretOperations[operationID]?.cancel()
        }
        return cancellation.status
    }
}

extension VaultAppServices {
    func noteTrackedSecretOperationState(_ state: SecretOperationState) async {
        await secretOperationCoordinator.transitionCurrent(to: state)
    }

    func ensureTrackedSecretOperationIsActive() throws {
        try SecretOperationService.ensureCurrentOperationIsActive()
    }

    func invalidateTrackedSecretOperations() async {
        await secretOperationCoordinator.cancelAll()
    }

    func trackedSecretOperationID() -> UUID? {
        SecretOperationService.currentOperationID
    }
}
