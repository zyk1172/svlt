import Foundation
import Testing
import VaultCore
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func operationLifecycleIsPrincipalScoped() async {
    let coordinator = SecretOperationCoordinator()
    let handle = await coordinator.register(principal: "pid:100")

    #expect(await coordinator.status(operationID: handle.operationID, principal: "pid:100")?.state == .queued)
    #expect(await coordinator.status(operationID: handle.operationID, principal: "pid:200") == nil)
    #expect(await coordinator.cancel(operationID: handle.operationID, principal: "pid:200") == nil)
}

@Test func cancellingRunningOperationProducesOutcomeUnknown() async {
    let coordinator = SecretOperationCoordinator()
    let handle = await coordinator.register(principal: "pid:100")
    await coordinator.transition(operationID: handle.operationID, to: .running)

    let cancelled = await coordinator.cancel(operationID: handle.operationID, principal: "pid:100")
    #expect(cancelled?.state == .outcomeUnknown)

    await coordinator.succeed(
        operationID: handle.operationID,
        output: SecretOperationOutput(status: "COMPLETED")
    )
    #expect(await coordinator.status(operationID: handle.operationID, principal: "pid:100")?.state == .outcomeUnknown)
}

@Test func cancellingQueuedOrApprovalOperationIsDefinitive() async {
    let coordinator = SecretOperationCoordinator()
    let queued = await coordinator.register(principal: "pid:100")
    #expect(await coordinator.cancel(operationID: queued.operationID, principal: "pid:100")?.state == .cancelled)

    let approval = await coordinator.register(principal: "pid:100")
    await coordinator.transition(operationID: approval.operationID, to: .awaitingApproval)
    #expect(await coordinator.cancel(operationID: approval.operationID, principal: "pid:100")?.state == .cancelled)
}
