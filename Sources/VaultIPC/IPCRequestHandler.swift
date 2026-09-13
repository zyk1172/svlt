import Foundation
import VaultCore
import VaultExecution

public protocol WorkbenchServicing: Sendable {
    func recordPluginActivity() async
    func status() async -> WorkbenchStatus
    func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata
    func savedSecretReferences() async throws -> [SecretReferenceMetadata]
    func searchSecrets(
        query: String,
        field: SecretCatalogField?,
        limit: Int
    ) async throws -> SecretCatalogSearchResult
    func getCatalogEntry(entryID: String) async throws -> SecretCatalogSearchResult
    func listCatalogIndexes() async throws -> SecretCatalogIndexListResult
    func listCatalogEntries(indexID: String) async throws -> SecretCatalogEntryListResult
    func createCatalogIndex(
        title: String,
        aliases: [String],
        tags: [String]
    ) async throws -> CatalogWriteResult
    func createCatalogEntry(_ request: CatalogDraftRequest) async throws -> CatalogWriteResult
    func createCatalogStructure(_ request: CatalogCreateStructureRequest) async throws -> CatalogStructureWriteResult
    func createCatalogDraft(_ request: CatalogDraftRequest) async throws -> CatalogDraft
    func patchCatalogMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func bindCatalogExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func applyCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult
    func requestCatalogSecureInputs(
        entryID: String,
        targets: [CatalogSecureInputTargetRequest],
        expectedRevision: UInt64
    ) async throws -> CatalogSecureInputStatus
    func catalogSecureInputStatus(requestID: UUID) async -> CatalogSecureInputStatus
    func validateCatalog() async throws -> CatalogValidationResult
    func catalogFilePreflight() async throws -> CatalogFilePreflight
    func pendingCatalogWriteAccessRequestIDs() async throws -> [UUID]
    func pendingCatalogSecureInputRequestIDs() async -> [UUID]
    func requestCatalogWriteAccess(
        source: CatalogAgentWriteRequestSource,
        reasonCategory: CatalogAgentWriteReasonCategory,
        duration: CatalogAgentWriteAccessDuration
    ) async throws
    func pendingRevealSessionIDs() async throws -> [String]
    func performSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationOutput
    func startSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationHandle
    func secretOperationStatus(operationID: UUID) async throws -> SecretOperationStatus
    func cancelSecretOperation(operationID: UUID) async throws -> SecretOperationStatus
    func secretOperationCapabilities() async -> [SecretOperationCapability]
    func reviewSSHHostKey(host: String, port: Int) async throws -> SSHHostKeyReview
    func sshSessionStatuses(sessionID: String?) async throws -> [SSHSessionStatus]
    func closeSSHSession(sessionID: String) async throws
    func deleteRecord(_ reference: String) async throws
    func authorizeHighRisk(reason: String) async throws
    func openRevealSession(references: [String], context: RevealContext) async throws -> String
    func exportResolvedText(references: [String], context: RevealContext, destinationPath: String) async throws -> String
    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult
    func clearRevealSessions() async
    func invalidateSecurityState() async
}

public extension WorkbenchServicing {
    func recordPluginActivity() async {}

    func savedSecretReferences() async throws -> [SecretReferenceMetadata] {
        []
    }

    func searchSecrets(
        query _: String,
        field _: SecretCatalogField?,
        limit _: Int
    ) async throws -> SecretCatalogSearchResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func pendingRevealSessionIDs() async throws -> [String] {
        []
    }

    func sshSessionStatuses(sessionID _: String?) async throws -> [SSHSessionStatus] {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func closeSSHSession(sessionID _: String) async throws {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func getCatalogEntry(entryID _: String) async throws -> SecretCatalogSearchResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func listCatalogIndexes() async throws -> SecretCatalogIndexListResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func listCatalogEntries(indexID _: String) async throws -> SecretCatalogEntryListResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func createCatalogIndex(
        title _: String,
        aliases _: [String],
        tags _: [String]
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func createCatalogEntry(_: CatalogDraftRequest) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func createCatalogStructure(_: CatalogCreateStructureRequest) async throws -> CatalogStructureWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func createCatalogDraft(_: CatalogDraftRequest) async throws -> CatalogDraft {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func patchCatalogMetadata(
        entryID _: String,
        patch _: CatalogMetadataPatch,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func commitCatalogDraft(
        _: CatalogDraft,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func addCatalogSecretPlaceholder(
        entryID _: String,
        key _: String,
        label _: String,
        agentVisible _: Bool,
        searchable _: Bool,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func bindCatalogExistingSecret(
        entryID _: String,
        key _: String,
        secretRef _: String,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func applyCatalogBatch(
        _: CatalogBatchMutation,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func requestCatalogSecureInputs(
        entryID _: String,
        targets _: [CatalogSecureInputTargetRequest],
        expectedRevision _: UInt64
    ) async throws -> CatalogSecureInputStatus {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func catalogSecureInputStatus(requestID: UUID) async -> CatalogSecureInputStatus {
        CatalogSecureInputStatus(requestID: requestID, status: .failed, errorCode: "SECURE_INPUT_UNSUPPORTED")
    }

    func validateCatalog() async throws -> CatalogValidationResult {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func catalogFilePreflight() async throws -> CatalogFilePreflight {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func pendingCatalogWriteAccessRequestIDs() async throws -> [UUID] {
        []
    }

    func pendingCatalogSecureInputRequestIDs() async -> [UUID] {
        []
    }

    func requestCatalogWriteAccess(
        source _: CatalogAgentWriteRequestSource,
        reasonCategory _: CatalogAgentWriteReasonCategory,
        duration _: CatalogAgentWriteAccessDuration
    ) async throws {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func performSecretOperation(_: SecretOperationDescriptor) async throws -> SecretOperationOutput {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func startSecretOperation(_: SecretOperationDescriptor) async throws -> SecretOperationHandle {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func secretOperationStatus(operationID _: UUID) async throws -> SecretOperationStatus {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func cancelSecretOperation(operationID _: UUID) async throws -> SecretOperationStatus {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func secretOperationCapabilities() async -> [SecretOperationCapability] { [] }

    func reviewSSHHostKey(host _: String, port _: Int) async throws -> SSHHostKeyReview {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func deleteRecord(_ reference: String) async throws {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func authorizeHighRisk(reason: String) async throws {
        throw IPCRequestHandlerError.unsupportedRequest
    }

    func clearRevealSessions() async {}
    func invalidateSecurityState() async {}
}

public enum IPCRequestHandlerError: Error, Equatable, Sendable {
    case unsupportedRequest
}

public struct IPCRequestHandler: Sendable {
    private let service: any WorkbenchServicing

    public init(service: any WorkbenchServicing) {
        self.service = service
    }

    public func handle(
        _ request: IPCRequest,
        principal: String = AuditSource.agent.rawValue,
        caller: AgentCallerIdentity? = nil
    ) async throws -> IPCResponse {
        let context = AuditContext(
            source: .agent,
            principal: principal,
            caller: caller.map { AuditCaller(name: $0.name, version: $0.version) }
                ?? AuditCaller.unknownMCPClient
        )
        return try await AuditContext.$current.withValue(context) {
            await service.recordPluginActivity()
            return try await handleInContext(request)
        }
    }

    private func handleInContext(_ request: IPCRequest) async throws -> IPCResponse {
        switch request {
        case .status:
            return .status(locked: await service.status().locked)
        case .workbenchStatus:
            return .workbenchStatus(await service.status())
        case .savedReferences:
            return .savedReferences(try await service.savedSecretReferences())
        case let .searchCatalog(query, field, limit):
            return try await handleCatalogSearch(query: query, field: field, limit: limit)
        case let .catalogSearch(query, field, limit):
            return try await handleCatalogSearch(query: query, field: field, limit: limit)
        case let .catalogGet(entryID):
            return .catalogSearchResult(try await service.getCatalogEntry(entryID: entryID))
        case .catalogListIndexes:
            return .catalogIndexListResult(try await service.listCatalogIndexes())
        case let .catalogListEntries(indexID):
            return .catalogEntryListResult(try await service.listCatalogEntries(indexID: indexID))
        case let .catalogCreateIndex(title, aliases, tags):
            return .catalogWriteResult(try await service.createCatalogIndex(
                title: title,
                aliases: aliases,
                tags: tags
            ))
        case let .catalogCreateEntry(request):
            return .catalogWriteResult(try await service.createCatalogEntry(request))
        case let .catalogCreateStructure(request):
            return .catalogStructureWriteResult(try await service.createCatalogStructure(request))
        case let .catalogCreateDraft(request):
            return .catalogDraft(try await service.createCatalogDraft(request))
        case let .catalogPatchMetadata(entryID, patch, expectedRevision):
            return .catalogWriteResult(try await service.patchCatalogMetadata(
                entryID: entryID,
                patch: patch,
                expectedRevision: expectedRevision
            ))
        case let .catalogCommit(draft, expectedRevision):
            return .catalogWriteResult(try await service.commitCatalogDraft(
                draft,
                expectedRevision: expectedRevision
            ))
        case let .catalogAddSecretPlaceholder(entryID, key, label, agentVisible, searchable, expectedRevision):
            return .catalogWriteResult(try await service.addCatalogSecretPlaceholder(
                entryID: entryID,
                key: key,
                label: label,
                agentVisible: agentVisible,
                searchable: searchable,
                expectedRevision: expectedRevision
            ))
        case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
            return .catalogWriteResult(try await service.bindCatalogExistingSecret(
                entryID: entryID,
                key: key,
                secretRef: secretRef,
                expectedRevision: expectedRevision
            ))
        case let .catalogApplyBatch(mutation, expectedRevision):
            return .catalogWriteResult(try await service.applyCatalogBatch(
                mutation,
                expectedRevision: expectedRevision
            ))
        case let .catalogRequestSecureInputs(entryID, targets, expectedRevision):
            return .catalogSecureInputStatus(try await service.requestCatalogSecureInputs(
                entryID: entryID,
                targets: targets,
                expectedRevision: expectedRevision
            ))
        case .catalogValidate:
            let result = try await service.validateCatalog()
            return .catalogValidation(
                status: result.status,
                revision: result.revision,
                rawSHA256: result.rawSHA256,
                diagnostics: result.diagnostics,
                filePreflight: result.filePreflight
            )
        case .catalogFilePreflight:
            return .catalogFilePreflight(try await service.catalogFilePreflight())
        case .catalogPendingWriteAccessRequestIDs:
            return .catalogPendingWriteAccessRequestIDs(
                try await service.pendingCatalogWriteAccessRequestIDs()
            )
        case .catalogPendingSecureInputRequestIDs:
            return .catalogPendingSecureInputRequestIDs(
                await service.pendingCatalogSecureInputRequestIDs()
            )
        case let .catalogSecureInputStatus(requestID):
            return .catalogSecureInputStatus(await service.catalogSecureInputStatus(requestID: requestID))
        case let .catalogRequestWriteAccess(request):
            try await service.requestCatalogWriteAccess(
                source: request.source,
                reasonCategory: request.reasonCategory,
                duration: request.duration
            )
            return .operationCompleted
        case .pendingRevealSessions:
            return .revealSessionIDs(try await service.pendingRevealSessionIDs())
        case let .inspectReference(reference):
            return .referenceMetadata(try await service.inspectReference(reference))
        case let .deleteRecord(reference):
            try await service.deleteRecord(reference)
            return .operationCompleted
        case let .authorizeHighRisk(reason):
            try await service.authorizeHighRisk(reason: reason)
            return .authorizationApproved
        case .lock:
            await service.invalidateSecurityState()
            return .operationCompleted
        case .clearRevealSessions:
            await service.clearRevealSessions()
            return .operationCompleted
        case let .reveal(reference, reason):
            _ = try await service.openRevealSession(
                references: [reference],
                context: RevealContext(
                    reason: reason,
                    template: "{{0}}",
                    ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
                )
            )
            return .displayedToUser
        case .encrypt:
            return .failure(code: "SELECTION_ENCRYPT_UNAVAILABLE")
        case .encryptBound:
            return .failure(code: "SELECTION_ENCRYPT_UNAVAILABLE")
        case let .revealReferences(references, context):
            let sessionID = try await service.openRevealSession(references: references, context: context)
            return .revealSessionOpened(sessionID: sessionID)
        case let .exportResolvedText(references, context, destinationPath):
            let path = try await service.exportResolvedText(
                references: references,
                context: context,
                destinationPath: destinationPath
            )
            return .exported(path: path)
        case let .scanOrphans(markdownReferences):
            return .orphanScan(try await service.scanOrphans(markdownReferences: markdownReferences))
        case .execute:
            return .failure(code: "EXECUTE_UNAVAILABLE")
        case let .executeSecretOperation(descriptor):
            do {
                return .secretOperation(try await service.performSecretOperation(descriptor))
            } catch let error as SecretOperationError {
                return .failure(code: error.responseCode)
            } catch {
                return .failure(code: "ACTION_EXECUTION_FAILED")
            }
        case let .startSecretOperation(descriptor):
            return try await lifecycleResponse { try await service.startSecretOperation(descriptor) }
        case let .secretOperationStatus(operationID):
            return try await lifecycleStatusResponse { try await service.secretOperationStatus(operationID: operationID) }
        case let .cancelSecretOperation(operationID):
            return try await lifecycleStatusResponse { try await service.cancelSecretOperation(operationID: operationID) }
        case let .reviewSSHHostKey(host, port):
            return .sshHostKeyReview(try await service.reviewSSHHostKey(host: host, port: port))
        case .secretOperationCapabilities:
            return .secretOperationCapabilities(await service.secretOperationCapabilities())
        case let .sshSessionStatus(sessionID):
            return .sshSessionStatus(try await service.sshSessionStatuses(sessionID: sessionID))
        case let .sshSessionClose(sessionID):
            try await service.closeSSHSession(sessionID: sessionID)
            return .operationCompleted
        }
    }

    private func lifecycleResponse(
        _ operation: () async throws -> SecretOperationHandle
    ) async throws -> IPCResponse {
        do {
            return .secretOperationHandle(try await operation())
        } catch let error as SecretOperationError {
            return .failure(code: error.responseCode)
        } catch {
            return .failure(code: "ACTION_EXECUTION_FAILED")
        }
    }

    private func lifecycleStatusResponse(
        _ operation: () async throws -> SecretOperationStatus
    ) async throws -> IPCResponse {
        do {
            return .secretOperationStatus(try await operation())
        } catch let error as SecretOperationError {
            return .failure(code: error.responseCode)
        } catch {
            return .failure(code: "ACTION_EXECUTION_FAILED")
        }
    }

    private func handleCatalogSearch(
        query: String,
        field: SecretCatalogField?,
        limit: Int
    ) async throws -> IPCResponse {
        .catalogSearchResult(try await service.searchSecrets(query: query, field: field, limit: limit))
    }
}
