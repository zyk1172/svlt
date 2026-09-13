import Foundation
import Testing
import VaultCore
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func operationLifecycleIsPrincipalScopedAtServiceBoundary() async {
    let service = SecretOperationService()
    let handle = await service.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            try await Task.sleep(for: .seconds(60))
            return SecretOperationOutput(status: "COMPLETED")
        }
    )

    let ownerStatus = await service.statusForBoundary(
        operationID: handle.operationID,
        principal: "pid:100"
    )
    #expect(ownerStatus.state == .queued)

    let foreignStatus = await service.statusForBoundary(
        operationID: handle.operationID,
        principal: "pid:200"
    )
    #expect(foreignStatus.state == .failed)
    #expect(foreignStatus.errorCode == SecretOperationLifecycleErrorCode.operationNotFound)

    let foreignCancellation = await service.cancelForBoundary(
        operationID: handle.operationID,
        principal: "pid:200"
    )
    #expect(foreignCancellation.ownedByPrincipal == false)
    #expect(foreignCancellation.status.errorCode == SecretOperationLifecycleErrorCode.operationNotFound)

    _ = await service.cancelForBoundary(operationID: handle.operationID, principal: "pid:100")
}

@Test func cancellingRunningOperationProducesOutcomeUnknown() async {
    let service = SecretOperationService()
    let handle = await service.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            await service.transitionCurrent(to: .running)
            try await Task.sleep(for: .seconds(60))
            return SecretOperationOutput(status: "COMPLETED")
        }
    )

    let running = await waitForState(
        .running,
        operationID: handle.operationID,
        principal: "pid:100",
        service: service
    )
    #expect(running.state == .running)

    let cancellation = await service.cancelForBoundary(
        operationID: handle.operationID,
        principal: "pid:100"
    )
    #expect(cancellation.ownedByPrincipal)
    #expect(cancellation.status.state == .outcomeUnknown)
    #expect(cancellation.status.errorCode == SecretOperationLifecycleErrorCode.outcomeUnknown)

    await Task.yield()
    let retained = await service.statusForBoundary(
        operationID: handle.operationID,
        principal: "pid:100"
    )
    #expect(retained.state == .outcomeUnknown)
    #expect(retained.errorCode == SecretOperationLifecycleErrorCode.outcomeUnknown)
}

@Test func cancellingQueuedOrApprovalOperationIsDefinitive() async {
    let queuedService = SecretOperationService()
    let queued = await queuedService.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            try await Task.sleep(for: .seconds(60))
            return SecretOperationOutput(status: "COMPLETED")
        }
    )
    let cancelledQueued = await queuedService.cancelForBoundary(
        operationID: queued.operationID,
        principal: "pid:100"
    )
    #expect(cancelledQueued.status.state == .cancelled)
    #expect(cancelledQueued.status.errorCode == SecretOperationLifecycleErrorCode.cancelled)

    let approvalService = SecretOperationService()
    let approval = await approvalService.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            await approvalService.transitionCurrent(to: .awaitingApproval)
            try await Task.sleep(for: .seconds(60))
            return SecretOperationOutput(status: "COMPLETED")
        }
    )
    let awaitingApproval = await waitForState(
        .awaitingApproval,
        operationID: approval.operationID,
        principal: "pid:100",
        service: approvalService
    )
    #expect(awaitingApproval.state == .awaitingApproval)

    let cancelledApproval = await approvalService.cancelForBoundary(
        operationID: approval.operationID,
        principal: "pid:100"
    )
    #expect(cancelledApproval.status.state == .cancelled)
    #expect(cancelledApproval.status.errorCode == SecretOperationLifecycleErrorCode.cancelled)
}

@Test func approvalPendingRemainsTrueUntilEveryOverlappingApprovalFinishes() async {
    let service = SecretOperationService()
    let first = await service.beginApproval()
    let second = await service.beginApproval()

    let initiallyPending = await service.approvalPending
    #expect(initiallyPending)

    let removedFirst = await service.finishApproval(id: first)
    let stillPending = await service.approvalPending
    #expect(removedFirst)
    #expect(stillPending)

    let removedSecond = await service.finishApproval(id: second)
    let finallyPending = await service.approvalPending
    #expect(removedSecond)
    #expect(!finallyPending)
}

@Test func lifecycleCancellationReachesRegisteredExecutorTask() async {
    let service = SecretOperationService()
    let probe = CancellationProbe()
    let handle = await service.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            await service.transitionCurrent(to: .running)
            let executorTask = Task<SecretOperationOutput, Error> {
                do {
                    try await Task.sleep(for: .seconds(60))
                    return SecretOperationOutput(status: "COMPLETED")
                } catch is CancellationError {
                    await probe.markCancelled()
                    throw CancellationError()
                }
            }
            return try await service.awaitExecutionTask(
                executorTask,
                operationID: SecretOperationService.currentOperationID
            )
        }
    )

    let running = await waitForState(
        .running,
        operationID: handle.operationID,
        principal: "pid:100",
        service: service
    )
    #expect(running.state == .running)

    let cancellation = await service.cancelForBoundary(
        operationID: handle.operationID,
        principal: "pid:100"
    )
    #expect(cancellation.status.state == .outcomeUnknown)

    let executorObservedCancellation = await waitForCancellation(probe)
    #expect(executorObservedCancellation)

    let retained = await service.statusForBoundary(
        operationID: handle.operationID,
        principal: "pid:100"
    )
    #expect(retained.state == .outcomeUnknown)
}

@Test func releasedExecutionOwnerCannotLeaveOperationQueuedForever() async {
    let service = SecretOperationService()
    let handle = await service.start(
        principal: "pid:100",
        descriptor: testDescriptor(),
        execute: { _ in
            throw SecretOperationError.actionExecutionFailed
        }
    )

    let terminal = await waitForState(
        .failed,
        operationID: handle.operationID,
        principal: "pid:100",
        service: service
    )
    #expect(terminal.state == .failed)
    #expect(terminal.errorCode == SecretOperationError.actionExecutionFailed.responseCode)
}

private actor CancellationProbe {
    private var cancelled = false

    func markCancelled() {
        cancelled = true
    }

    func wasCancelled() -> Bool {
        cancelled
    }
}

private func testDescriptor() -> SecretOperationDescriptor {
    SecretOperationDescriptor(actionType: .vaultStatus, secretReferences: [])
}

private func waitForState(
    _ expected: SecretOperationState,
    operationID: UUID,
    principal: String,
    service: SecretOperationService
) async -> SecretOperationStatus {
    var last = await service.statusForBoundary(operationID: operationID, principal: principal)
    for _ in 0..<200 where last.state != expected {
        await Task.yield()
        last = await service.statusForBoundary(operationID: operationID, principal: principal)
    }
    return last
}

private func waitForCancellation(_ probe: CancellationProbe) async -> Bool {
    for _ in 0..<200 {
        if await probe.wasCancelled() {
            return true
        }
        await Task.yield()
    }
    return await probe.wasCancelled()
}
