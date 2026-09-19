import Foundation
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

private enum SecretOperationLifecycleContext {
    @TaskLocal static var operationID: UUID?
}

/// Owns the mutable coordination state for Agent secret operations.
///
/// IPC lifecycle records, executor tasks, cancellation, approval-pending
/// accounting and execution-approval flight deduplication live here instead
/// of in the much larger `VaultAppServices` actor. Policy evaluation,
/// owner-prompt construction and key resolution remain injected business
/// responsibilities.
actor SecretOperationService {
    struct CancellationResult: Sendable {
        let status: SecretOperationStatus
        let ownedByPrincipal: Bool
    }

    struct ExecutionApprovalFlight: Sendable {
        let id: UUID
        let generation: UInt64
        let task: Task<LocalAuthenticationContext?, Error>
    }

    struct ExecutionApprovalFlightAcquisition: Sendable {
        let flight: ExecutionApprovalFlight
        let created: Bool
    }

    private struct Record {
        let principal: String
        let sequence: UInt64
        let operationHash: String
        let idempotencyKey: String?
        var state: SecretOperationState
        var output: SecretOperationOutput?
        var errorCode: String?
        var progressChunks: [SecretOperationOutputChunk]
        var task: Task<Void, Never>?
    }

    private struct ExecutionTaskRecord {
        let registrationID: UUID
        let task: Task<SecretOperationOutput, Error>
    }

    private let terminalRetentionLimit: Int
    private var nextSequence: UInt64 = 0
    private var records: [UUID: Record] = [:]
    private var executionTasks: [UUID: ExecutionTaskRecord] = [:]
    private var pendingApprovalIDs: Set<UUID> = []
    private var executionApprovalFlights: [ExecutionAuthorizationScope: ExecutionApprovalFlight] = [:]

    init(terminalRetentionLimit: Int = 128) {
        self.terminalRetentionLimit = max(1, terminalRetentionLimit)
    }

    var approvalPending: Bool {
        !pendingApprovalIDs.isEmpty
    }

    func start(
        principal: String,
        descriptor: SecretOperationDescriptor,
        idempotencyKey: String? = nil,
        execute: @escaping @Sendable (SecretOperationDescriptor) async throws -> SecretOperationOutput
    ) throws -> SecretOperationHandle {
        let normalizedKey = try normalizeIdempotencyKey(idempotencyKey)
        if let normalizedKey,
           let existing = records.first(where: {
               $0.value.principal == principal && $0.value.idempotencyKey == normalizedKey
           }) {
            guard existing.value.operationHash == descriptor.operationHash else {
                throw VaultCore.SecretOperationError.idempotencyKeyConflict
            }
            return SecretOperationHandle(
                operationID: existing.key,
                state: existing.value.state,
                reused: true
            )
        }

        let handle = register(
            principal: principal,
            operationHash: descriptor.operationHash,
            idempotencyKey: normalizedKey
        )
        let operationID = handle.operationID
        let task = Task { [weak self] in
            guard let self else { return }
            await SecretOperationLifecycleContext.$operationID.withValue(operationID) {
                do {
                    try Task.checkCancellation()
                    let output = try await SecretOperationProgressContext.$reporter.withValue(
                        { progress in
                            await self.appendProgress(operationID: operationID, progress: progress)
                        }
                    ) {
                        try await execute(descriptor)
                    }
                    await self.succeed(operationID: operationID, output: output)
                } catch let error as VaultCore.SecretOperationError {
                    await self.fail(operationID: operationID, errorCode: error.responseCode)
                } catch is CancellationError {
                    await self.fail(operationID: operationID, errorCode: VaultCore.SecretOperationError.authorizationCancelled.responseCode)
                } catch {
                    await self.fail(operationID: operationID, errorCode: VaultCore.SecretOperationError.actionExecutionFailed.responseCode)
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
            return CancellationResult(status: notFoundStatus(operationID: operationID), ownedByPrincipal: false)
        }
        return CancellationResult(status: status, ownedByPrincipal: true)
    }

    func outputForBoundary(
        operationID: UUID,
        principal: String,
        cursor: UInt64,
        maxChunks: Int
    ) throws -> SecretOperationOutputPage {
        guard (1...64).contains(maxChunks) else {
            throw VaultCore.SecretOperationError.invalidOperationParameters
        }
        guard let record = records[operationID], record.principal == principal else {
            throw VaultCore.SecretOperationError.operationNotFound
        }
        let chunks = availableChunks(for: record)
        let boundedCursor = min(cursor, UInt64(chunks.count))
        let start = Int(boundedCursor)
        let end = min(chunks.count, start + maxChunks)
        let pageChunks = Array(chunks[start..<end])
        return SecretOperationOutputPage(
            operationID: operationID,
            state: record.state,
            cursor: boundedCursor,
            nextCursor: UInt64(end),
            chunks: pageChunks,
            hasMore: end < chunks.count
        )
    }

    func transitionCurrent(to state: SecretOperationState) {
        guard let operationID = SecretOperationLifecycleContext.operationID else { return }
        transition(operationID: operationID, to: state)
    }

    func awaitExecutionTask(
        _ task: Task<SecretOperationOutput, Error>,
        operationID: UUID?
    ) async throws -> SecretOperationOutput {
        if let operationID {
            guard let record = records[operationID], !record.state.isTerminal else {
                task.cancel()
                throw CancellationError()
            }
        }
        let executionID = operationID ?? UUID()
        let registrationID = UUID()
        if let existing = executionTasks[executionID] { existing.task.cancel() }
        executionTasks[executionID] = ExecutionTaskRecord(registrationID: registrationID, task: task)
        defer {
            if executionTasks[executionID]?.registrationID == registrationID {
                executionTasks.removeValue(forKey: executionID)
            }
        }
        return try await task.value
    }

    func joinOrCreateExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        generation: UInt64,
        create: @escaping @Sendable () async throws -> LocalAuthenticationContext?
    ) -> ExecutionApprovalFlightAcquisition {
        if let existing = executionApprovalFlights[scope] {
            return ExecutionApprovalFlightAcquisition(flight: existing, created: false)
        }
        let approvalID = UUID()
        let task = Task { try await create() }
        let flight = ExecutionApprovalFlight(id: approvalID, generation: generation, task: task)
        executionApprovalFlights[scope] = flight
        pendingApprovalIDs.insert(approvalID)
        return ExecutionApprovalFlightAcquisition(flight: flight, created: true)
    }

    func executionApprovalFlight(for scope: ExecutionAuthorizationScope) -> ExecutionApprovalFlight? {
        executionApprovalFlights[scope]
    }

    @discardableResult
    func removeExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        matching approvalID: UUID? = nil,
        cancelTask: Bool = false
    ) -> Bool {
        guard let flight = executionApprovalFlights[scope],
              approvalID == nil || flight.id == approvalID else {
            if let approvalID { return pendingApprovalIDs.remove(approvalID) != nil }
            return false
        }
        executionApprovalFlights.removeValue(forKey: scope)
        if cancelTask { flight.task.cancel() }
        return pendingApprovalIDs.remove(flight.id) != nil
    }

    @discardableResult
    func finishExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        approvalID: UUID,
        generation: UInt64
    ) -> Bool {
        guard let flight = executionApprovalFlights[scope],
              flight.id == approvalID,
              flight.generation == generation else {
            return pendingApprovalIDs.remove(approvalID) != nil
        }
        executionApprovalFlights.removeValue(forKey: scope)
        flight.task.cancel()
        return pendingApprovalIDs.remove(approvalID) != nil
    }

    @discardableResult
    func beginApproval(id: UUID = UUID()) -> UUID {
        pendingApprovalIDs.insert(id)
        return id
    }

    @discardableResult
    func finishApproval(id: UUID) -> Bool {
        pendingApprovalIDs.remove(id) != nil
    }

    func invalidateAllCoordination() {
        cancelAllLifecycleOperations()
        for execution in executionTasks.values { execution.task.cancel() }
        executionTasks.removeAll()
        for flight in executionApprovalFlights.values { flight.task.cancel() }
        executionApprovalFlights.removeAll()
        pendingApprovalIDs.removeAll()
    }

    nonisolated static var currentOperationID: UUID? { SecretOperationLifecycleContext.operationID }

    nonisolated static func ensureCurrentOperationIsActive() throws {
        guard SecretOperationLifecycleContext.operationID != nil, Task.isCancelled else { return }
        throw VaultCore.SecretOperationError.authorizationCancelled
    }

    private func register(
        principal: String,
        operationHash: String,
        idempotencyKey: String?
    ) -> SecretOperationHandle {
        let operationID = UUID()
        nextSequence &+= 1
        records[operationID] = Record(
            principal: principal,
            sequence: nextSequence,
            operationHash: operationHash,
            idempotencyKey: idempotencyKey,
            state: .queued,
            output: nil,
            errorCode: nil,
            progressChunks: [],
            task: nil
        )
        return SecretOperationHandle(
            operationID: operationID,
            state: .queued,
            reused: idempotencyKey == nil ? nil : false
        )
    }

    private func attachTask(operationID: UUID, principal: String, task: Task<Void, Never>) {
        guard var record = records[operationID], record.principal == principal, !record.state.isTerminal else {
            task.cancel()
            return
        }
        record.task = task
        records[operationID] = record
    }

    private func transition(operationID: UUID, to state: SecretOperationState) {
        guard !state.isTerminal, var record = records[operationID], !record.state.isTerminal else { return }
        record.state = state
        records[operationID] = record
    }

    private func succeed(operationID: UUID, output: SecretOperationOutput) {
        finish(operationID: operationID, state: .succeeded, output: output, errorCode: nil)
    }

    private func appendProgress(operationID: UUID, progress: SecretOperationProgress) {
        guard var record = records[operationID], !record.state.isTerminal else { return }
        if let stdout = progress.stdout {
            append(
                text: stdout,
                stream: .stdout,
                commandIndex: progress.commandIndex,
                to: &record.progressChunks
            )
        }
        if let stderr = progress.stderr {
            append(
                text: stderr,
                stream: .stderr,
                commandIndex: progress.commandIndex,
                to: &record.progressChunks
            )
        }
        records[operationID] = record
    }

    private func fail(operationID: UUID, errorCode: String) {
        finish(operationID: operationID, state: .failed, output: nil, errorCode: errorCode)
    }

    private func status(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard let record = records[operationID], record.principal == principal else { return nil }
        return status(operationID: operationID, record: record)
    }

    private func cancel(operationID: UUID, principal: String) -> SecretOperationStatus? {
        guard var record = records[operationID], record.principal == principal else { return nil }
        guard !record.state.isTerminal else { return status(operationID: operationID, record: record) }
        applyCancellation(to: &record)
        let driverTask = record.task
        record.task = nil
        records[operationID] = record
        let executionTask = executionTasks.removeValue(forKey: operationID)?.task
        driverTask?.cancel()
        executionTask?.cancel()
        trimTerminalRecords()
        return status(operationID: operationID, record: record)
    }

    private func cancelAllLifecycleOperations() {
        for operationID in records.keys {
            guard var record = records[operationID], !record.state.isTerminal else { continue }
            applyCancellation(to: &record)
            let driverTask = record.task
            record.task = nil
            records[operationID] = record
            let executionTask = executionTasks.removeValue(forKey: operationID)?.task
            driverTask?.cancel()
            executionTask?.cancel()
        }
        trimTerminalRecords()
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

    private func finish(operationID: UUID, state: SecretOperationState, output: SecretOperationOutput?, errorCode: String?) {
        guard state.isTerminal, var record = records[operationID], !record.state.isTerminal else { return }
        record.state = state
        record.output = output
        record.errorCode = errorCode
        if output != nil {
            record.progressChunks.removeAll(keepingCapacity: false)
        }
        record.task = nil
        records[operationID] = record
        trimTerminalRecords()
    }

    private func trimTerminalRecords() {
        let terminal = records.filter { $0.value.state.isTerminal }.sorted { $0.value.sequence < $1.value.sequence }
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
            errorCode: record.errorCode,
            nextOutputCursor: UInt64(availableChunks(for: record).count)
        )
    }

    private func normalizeIdempotencyKey(_ value: String?) throws -> String? {
        guard let value else { return nil }
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty,
              normalized.utf8.count <= 128,
              normalized.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F })
        else {
            throw VaultCore.SecretOperationError.invalidOperationParameters
        }
        return normalized
    }

    private func availableChunks(for record: Record) -> [SecretOperationOutputChunk] {
        if let output = record.output {
            var chunks: [SecretOperationOutputChunk] = []
            if let stdout = output.stdout {
                append(text: stdout, stream: .stdout, commandIndex: nil, to: &chunks)
            }
            if let stderr = output.stderr {
                append(text: stderr, stream: .stderr, commandIndex: nil, to: &chunks)
            }
            if let results = output.results {
                for result in results {
                    if let stdout = result.stdout {
                        append(text: stdout, stream: .stdout, commandIndex: result.index, to: &chunks)
                    }
                    if let stderr = result.stderr {
                        append(text: stderr, stream: .stderr, commandIndex: result.index, to: &chunks)
                    }
                }
            }
            return chunks
        }
        return record.progressChunks
    }

    private func append(
        text: String,
        stream: SecretOperationOutputStream,
        commandIndex: Int?,
        to chunks: inout [SecretOperationOutputChunk]
    ) {
        guard !text.isEmpty else { return }
        var start = text.startIndex
        while start < text.endIndex {
            let end = text.index(start, offsetBy: 4_096, limitedBy: text.endIndex) ?? text.endIndex
            chunks.append(
                SecretOperationOutputChunk(
                    cursor: UInt64(chunks.count),
                    stream: stream,
                    text: String(text[start..<end]),
                    commandIndex: commandIndex
                )
            )
            start = end
        }
    }

    private func notFoundStatus(operationID: UUID) -> SecretOperationStatus {
        SecretOperationStatus(operationID: operationID, state: .failed, errorCode: SecretOperationLifecycleErrorCode.operationNotFound)
    }
}
