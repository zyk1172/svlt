import Foundation
import VaultCore
import VaultIPC

private enum SecretOperationLifecycleContext {
    @TaskLocal static var operationID: UUID?
}

actor SecretOperationCoordinator {
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

    func register(principal: String) -> SecretOperationHandle {
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

    func attachTask(
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

    func transition(operationID: UUID, to state: SecretOperationState) {
        guard !state.isTerminal,
              var record = records[operationID],
              !record.state.isTerminal
        else { return }
        record.state = state
        records[operationID] = record
    }

    func succeed(operationID: UUID, output: SecretOperationOutput) {
        finish(operationID: operationID, state: .succeeded, output: output, errorCode: nil)
    }

    func fail(operationID: UUID, errorCode: String) {
        finish(operationID: operationID, state: .failed, output: nil, errorCode: errorCode)
    }

    func status(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard let record = records[operationID], record.principal == principal else {
            return nil
        }
        return status(operationID: operationID, record: record)
    }

    func cancel(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard var record = records[operationID], record.principal == principal else {
            return nil
        }
        guard !record.state.isTerminal else {
            return status(operationID: operationID, record: record)
        }

        switch record.state {
        case .queued, .awaitingApproval:
            record.state = .cancelled
        case .running:
            // Once execution has started, cancellation cannot prove that the
            // remote/local side effect did not already cross its commit point.
            record.state = .outcomeUnknown
        case .succeeded, .failed, .cancelled, .outcomeUnknown:
            break
        }
        let task = record.task
        record.task = nil
        records[operationID] = record
        task?.cancel()
        trimTerminalRecords()
        return status(operationID: operationID, record: record)
    }

    func cancelAll() {
        for operationID in records.keys {
            guard var record = records[operationID], !record.state.isTerminal else { continue }
            switch record.state {
            case .queued, .awaitingApproval:
                record.state = .cancelled
            case .running:
                record.state = .outcomeUnknown
            case .succeeded, .failed, .cancelled, .outcomeUnknown:
                break
            }
            let task = record.task
            record.task = nil
            records[operationID] = record
            task?.cancel()
        }
        trimTerminalRecords()
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
}

public extension VaultAppServices {
    func startSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationHandle {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        let coordinator = secretOperationCoordinator
        let handle = await coordinator.register(principal: principal)
        let operationID = handle.operationID
        let task = Task { [weak self] in
            guard let self else { return }
            await SecretOperationLifecycleContext.$operationID.withValue(operationID) {
                await coordinator.transition(operationID: operationID, to: .running)
                do {
                    try Task.checkCancellation()
                    let output = try await self.performSecretOperation(descriptor)
                    await coordinator.succeed(operationID: operationID, output: output)
                } catch let error as SecretOperationError {
                    await coordinator.fail(operationID: operationID, errorCode: error.responseCode)
                } catch is CancellationError {
                    await coordinator.fail(operationID: operationID, errorCode: SecretOperationError.authorizationCancelled.responseCode)
                } catch {
                    await coordinator.fail(operationID: operationID, errorCode: SecretOperationError.actionExecutionFailed.responseCode)
                }
            }
        }
        await coordinator.attachTask(operationID: operationID, principal: principal, task: task)
        return handle
    }

    func secretOperationStatus(operationID: UUID) async throws -> SecretOperationStatus {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        guard let status = await secretOperationCoordinator.status(
            operationID: operationID,
            principal: principal
        ) else {
            throw SecretOperationError.invalidOperationParameters
        }
        return status
    }

    func cancelSecretOperation(operationID: UUID) async throws -> SecretOperationStatus {
        let principal = AuditContext.current?.principal ?? AuditSource.agent.rawValue
        guard let status = await secretOperationCoordinator.cancel(
            operationID: operationID,
            principal: principal
        ) else {
            throw SecretOperationError.invalidOperationParameters
        }
        inFlightSecretOperations[operationID]?.cancel()
        return status
    }

    func noteTrackedSecretOperationState(_ state: SecretOperationState) async {
        guard let operationID = SecretOperationLifecycleContext.operationID else { return }
        await secretOperationCoordinator.transition(operationID: operationID, to: state)
    }

    func ensureTrackedSecretOperationIsActive() throws {
        guard SecretOperationLifecycleContext.operationID != nil, Task.isCancelled else { return }
        throw SecretOperationError.authorizationCancelled
    }

    func invalidateTrackedSecretOperations() async {
        await secretOperationCoordinator.cancelAll()
    }

    func trackedSecretOperationID() -> UUID? {
        SecretOperationLifecycleContext.operationID
    }
}
