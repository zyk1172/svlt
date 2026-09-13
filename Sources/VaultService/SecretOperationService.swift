import Foundation
import VaultCore
import VaultExecution
import VaultIPC

private enum SecretOperationLifecycleContext {
    @TaskLocal static var operationID: UUID?
}

/// Owns the durable-in-process lifecycle of Agent secret operations.
///
/// This actor deliberately sits between IPC-facing adapters and the much larger
/// `VaultAppServices` actor. It owns operation identity, principal isolation,
/// lifecycle state, cancellation semantics, terminal retention, and the task
/// that drives one operation to completion. Business execution/authorization
/// is injected as an async closure so that those responsibilities can migrate
/// behind this boundary without changing the IPC contract again.
actor SecretOperationService {
    struct CancellationResult: Sendable {
        let status: SecretOperationStatus
        let ownedByPrincipal: Bool
    }

    private struct Record {
        let principal: String
        let sequence: UInt64
        var state: SecretOperationState
        var output: SecretOperationOutput?
        var errorCode: String?
        var task: Task<Void, Never>?
    }

    private let terminalRetentionLimit: Int
    private var nextSequence: UInt64 = 0
    private var records: [UUID: Record] = [:]

    init(terminalRetentionLimit: Int = 128) {
        self.terminalRetentionLimit = max(1, terminalRetentionLimit)
    }

    func start(
        principal: String,
        descriptor: SecretOperationDescriptor,
        execute: @escaping @Sendable (SecretOperationDescriptor) async throws -> SecretOperationOutput
    ) -> SecretOperationHandle {
        let handle = register(principal: principal)
        let operationID = handle.operationID
        let task = Task { [weak self] in
            guard let self else { return }
            await SecretOperationLifecycleContext.$operationID.withValue(operationID) {
                do {
                    try Task.checkCancellation()
                    let output = try await execute(descriptor)
                    await self.succeed(operationID: operationID, output: output)
                } catch let error as VaultCore.SecretOperationError {
                    await self.fail(operationID: operationID, errorCode: error.responseCode)
                } catch is CancellationError {
                    await self.fail(
                        operationID: operationID,
                        errorCode: VaultCore.SecretOperationError.authorizationCancelled.responseCode
                    )
                } catch {
                    await self.fail(
                        operationID: operationID,
                        errorCode: VaultCore.SecretOperationError.actionExecutionFailed.responseCode
                    )
                }
            }
        }
        attachTask(operationID: operationID, principal: principal, task: task)
        return handle
    }

    func statusForBoundary(operationID: UUID, principal: String) -> SecretOperationStatus {
        guard let status = status(operationID: operationID, principal: principal) else {
            return notFoundStatus(operationID: operationID)
        }
        return status
    }

    func cancelForBoundary(operationID: UUID, principal: String) -> CancellationResult {
        guard let status = cancel(operationID: operationID, principal: principal) else {
            return CancellationResult(
                status: notFoundStatus(operationID: operationID),
                ownedByPrincipal: false
            )
        }
        return CancellationResult(status: status, ownedByPrincipal: true)
    }

    func transitionCurrent(to state: SecretOperationState) {
        guard let operationID = SecretOperationLifecycleContext.operationID else { return }
        transition(operationID: operationID, to: state)
    }

    func cancelAll() {
        for operationID in records.keys {
            guard var record = records[operationID], !record.state.isTerminal else { continue }
            applyCancellation(to: &record)
            let task = record.task
            record.task = nil
            records[operationID] = record
            task?.cancel()
        }
        trimTerminalRecords()
    }

    nonisolated static var currentOperationID: UUID? {
        SecretOperationLifecycleContext.operationID
    }

    nonisolated static func ensureCurrentOperationIsActive() throws {
        guard SecretOperationLifecycleContext.operationID != nil, Task.isCancelled else { return }
        throw VaultCore.SecretOperationError.authorizationCancelled
    }

    private func register(principal: String) -> SecretOperationHandle {
        let operationID = UUID()
        nextSequence &+= 1
        records[operationID] = Record(
            principal: principal,
            sequence: nextSequence,
            state: .queued,
            output: nil,
            errorCode: nil,
            task: nil
        )
        return SecretOperationHandle(operationID: operationID, state: .queued)
    }

    private func attachTask(
        operationID: UUID,
        principal: String,
        task: Task<Void, Never>
    ) {
        guard var record = records[operationID],
              record.principal == principal,
              !record.state.isTerminal
        else {
            task.cancel()
            return
        }
        record.task = task
        records[operationID] = record
    }

    private func transition(operationID: UUID, to state: SecretOperationState) {
        guard !state.isTerminal,
              var record = records[operationID],
              !record.state.isTerminal
        else { return }
        record.state = state
        records[operationID] = record
    }

    private func succeed(operationID: UUID, output: SecretOperationOutput) {
        finish(operationID: operationID, state: .succeeded, output: output, errorCode: nil)
    }

    private func fail(operationID: UUID, errorCode: String) {
        finish(operationID: operationID, state: .failed, output: nil, errorCode: errorCode)
    }

    private func status(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard let record = records[operationID], record.principal == principal else {
            return nil
        }
        return status(operationID: operationID, record: record)
    }

    private func cancel(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard var record = records[operationID], record.principal == principal else {
            return nil
        }
        guard !record.state.isTerminal else {
            return status(operationID: operationID, record: record)
        }

        applyCancellation(to: &record)
        let task = record.task
        record.task = nil
        records[operationID] = record
        task?.cancel()
        trimTerminalRecords()
        return status(operationID: operationID, record: record)
    }

    private func applyCancellation(to record: inout Record) {
        switch record.state {
        case .queued, .awaitingApproval:
            record.state = .cancelled
            record.errorCode = SecretOperationLifecycleErrorCode.cancelled
        case .running:
            record.state = .outcomeUnknown
            record.errorCode = SecretOperationLifecycleErrorCode.outcomeUnknown
        case .succeeded, .failed, .cancelled, .outcomeUnknown:
            break
        }
    }

    private func finish(
        operationID: UUID,
        state: SecretOperationState,
        output: SecretOperationOutput?,
        errorCode: String?
    ) {
        guard state.isTerminal,
              var record = records[operationID],
              !record.state.isTerminal
        else { return }
        record.state = state
        record.output = output
        record.errorCode = errorCode
        record.task = nil
        records[operationID] = record
        trimTerminalRecords()
    }

    private func trimTerminalRecords() {
        let terminal = records
            .filter { $0.value.state.isTerminal }
            .sorted { $0.value.sequence < $1.value.sequence }
        guard terminal.count > terminalRetentionLimit else { return }
        for (operationID, _) in terminal.prefix(terminal.count - terminalRetentionLimit) {
            records.removeValue(forKey: operationID)
        }
    }

    private func status(operationID: UUID, record: Record) -> SecretOperationStatus {
        SecretOperationStatus(
            operationID: operationID,
            state: record.state,
            output: record.output,
            errorCode: record.errorCode
        )
    }

    private func notFoundStatus(operationID: UUID) -> SecretOperationStatus {
        SecretOperationStatus(
            operationID: operationID,
            state: .failed,
            errorCode: SecretOperationLifecycleErrorCode.operationNotFound
        )
    }
}

// Keep the stored-property spelling in VaultAppServices source-compatible while
// the architectural boundary migrates. New code should use SecretOperationService.
typealias SecretOperationCoordinator = SecretOperationService
