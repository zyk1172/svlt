import Foundation
import VaultCore
import VaultExecution

public enum AppControlRequestHandlerError: Error, Equatable, Sendable {
    case unsupportedRequest
}

public struct AppControlRequestHandler: Sendable {
    private let service: any AppControlServicing

    public init(service: any AppControlServicing) {
        self.service = service
    }

    public func handle(_ request: AppControlRequest) async -> AppControlResponse {
        let context = AuditContext(source: .app)
        return await AuditContext.$current.withValue(context) {
            await handleInContext(request)
        }
    }

    private func handleInContext(_ request: AppControlRequest) async -> AppControlResponse {
        do {
            switch request {
            case .catalogStatus:
                return .catalogStatus(try await service.catalogStatus())
            case .catalogPresentationState:
                return .catalogPresentationState(await service.catalogPresentationState())
            case let .catalogSelectDocument(path):
                return .catalogPresentationState(try await service.selectCatalogDocument(path: path))
            case .catalogFormatRepairPlan:
                return .catalogFormatRepairPlan(try await service.catalogFormatRepairPlan())
            case let .catalogRepairFormat(expectedRawSHA256):
                return .catalogStatus(try await service.repairCatalogFormat(expectedRawSHA256: expectedRawSHA256))
            case let .catalogRecentAuditEntries(limit):
                return .catalogRecentAuditEntries(try await service.catalogRecentAuditEntries(limit: limit))
            case .catalogAuditHealth:
                return .catalogAuditHealth(await service.catalogAuditHealth())
            case let .catalogSecureInputRequest(id):
                return .catalogSecureInputRequest(try await service.catalogSecureInputRequest(id: id))
            case let .catalogSubmitSecureInput(id, submission):
                return .catalogSecureInputStatus(try await service.submitCatalogSecureInput(
                    id: id,
                    submission: submission
                ))
            case let .catalogBeginSecureInputCommit(id):
                _ = id
                return .failure(code: "SECURE_INPUT_LEGACY_BEGIN_UNSUPPORTED")
            case let .catalogCompleteSecureInput(id, completion):
                _ = id
                _ = completion
                return .failure(code: "SECURE_INPUT_LEGACY_COMPLETE_UNSUPPORTED")
            case let .catalogCancelSecureInput(id):
                await service.cancelCatalogSecureInput(id: id)
                return .operationCompleted
            case .catalogAdoptExternalV2:
                return .catalogStatus(try await service.adoptCatalogExternalV2())
            case .catalogAdoptExternalV3:
                return .catalogStatus(try await service.adoptCatalogExternalV3())
            case let .catalogApproveExternalChange(expectedRevision, expectedRawSHA256, expectedSemanticSHA256):
                return .catalogStatus(try await service.approveCatalogExternalChange(
                    expectedRevision: expectedRevision,
                    expectedRawSHA256: expectedRawSHA256,
                    expectedSemanticSHA256: expectedSemanticSHA256
                ))
            case let .setCatalogAgentWriteMode(mode, duration):
                return .catalogAgentWriteStatus(try await service.setCatalogAgentWriteMode(mode: mode, duration: duration))
            case .revokeCatalogAgentWrite:
                await service.revokeCatalogAgentWrite()
                return .operationCompleted
            case .catalogAgentWriteStatus:
                return .catalogAgentWriteStatus(await service.catalogAgentWriteStatus())
            case let .catalogWriteAccessRequest(id):
                return .catalogWriteAccessRequest(try await service.pendingCatalogWriteAccessRequest(id: id))
            case let .respondToCatalogWriteAccessRequest(id, approved):
                try await service.respondToCatalogWriteAccessRequest(id: id, approved: approved)
                return .operationCompleted
            case let .catalogCreateIndex(title, aliases, tags, expectedRevision):
                return .catalogWriteResult(try await service.catalogCreateIndex(
                    title: title,
                    aliases: aliases,
                    tags: tags,
                    expectedRevision: expectedRevision
                ))
            case let .catalogCreateEntry(request, expectedRevision):
                return .catalogWriteResult(try await service.catalogCreateEntry(request, expectedRevision: expectedRevision))
            case let .catalogUpdateEntry(entry, expectedRevision):
                return .catalogWriteResult(try await service.catalogUpdateEntry(entry, expectedRevision: expectedRevision))
            case let .catalogCommitEntryEdit(entry, secretInputs, expectedRevision):
                return .catalogWriteResult(try await service.catalogCommitEntryEdit(
                    entry,
                    secretInputs: secretInputs,
                    expectedRevision: expectedRevision
                ))
            case let .catalogApplyBatch(mutation, expectedRevision):
                return .catalogWriteResult(try await service.catalogApplyBatch(mutation, expectedRevision: expectedRevision))
            case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
                return .catalogWriteResult(try await service.catalogBindExistingSecret(
                    entryID: entryID,
                    key: key,
                    secretRef: secretRef,
                    expectedRevision: expectedRevision
                ))
            case let .catalogSecureInput(entryID, key, label, plaintext, policy):
                let result = try await service.catalogSecureInput(
                    entryID: entryID,
                    key: key,
                    label: label,
                    plaintext: plaintext,
                    policy: policy
                )
                return .secretBound(reference: result.reference, revision: result.revision)
            case let .catalogRevealField(entryID, key):
                return .catalogFieldPlaintext(try await service.catalogRevealField(entryID: entryID, key: key))
            case let .revealSessionData(sessionID):
                return .revealSessionData(try await service.revealSessionData(sessionID: sessionID))
            case let .restoreReferences(references, context):
                return .restoredText(try await service.restoreReferences(
                    references: references,
                    context: context
                ))
            }
        } catch let error as SecretCatalogAgentError {
            return .failure(code: Self.catalogCode(error))
        } catch let error as SecretOperationError {
            return .failure(code: Self.operationCode(error))
        } catch {
            return .failure(code: "APP_CONTROL_REQUEST_FAILED")
        }
    }

    private static func catalogCode(_ error: SecretCatalogAgentError) -> String {
        switch error {
        case .unavailable: return "CATALOG_UNAVAILABLE"
        case .legacyCatalogUnsupported: return "LEGACY_CATALOG_UNSUPPORTED"
        case .integrityMissing: return "INTEGRITY_MISSING"
        case .externalModification: return "EXTERNAL_CATALOG_MODIFICATION"
        case .pendingExternalChange: return "PENDING_EXTERNAL_CHANGE"
        case .invalidCatalog: return "CATALOG_INVALID"
        case .agentWriteNotAllowed: return "CATALOG_AGENT_WRITE_NOT_ALLOWED"
        case .revisionConflict: return "CATALOG_REVISION_CONFLICT"
        case .formatRepairConflict: return "FORMAT_REPAIR_CONFLICT"
        case .invalidOperation: return "CATALOG_INVALID_OPERATION"
        case .approvalRequired: return "CATALOG_APPROVAL_REQUIRED"
        case .writeFailed: return "CATALOG_WRITE_FAILED"
        case .cleanupRequired: return "CATALOG_CLEANUP_REQUIRED"
        case .agentWriteApprovalUnavailable: return "CATALOG_AGENT_WRITE_APPROVAL_UNAVAILABLE"
        }
    }

    private static func operationCode(_ error: SecretOperationError) -> String {
        switch error {
        case .operationDenied: return "CATALOG_OPERATION_DENIED"
        case .authorizationCancelled: return "CATALOG_AUTHORIZATION_CANCELLED"
        case .authorizationDenied: return "CATALOG_AUTHORIZATION_DENIED"
        case .authorizationTimeout: return "CATALOG_AUTHORIZATION_TIMEOUT"
        case .authorizationUnavailable: return "CATALOG_AUTHORIZATION_UNAVAILABLE"
        case .actionExecutorUnavailable: return "ACTION_EXECUTOR_UNAVAILABLE"
        case .actionExecutionFailed: return "ACTION_EXECUTION_FAILED"
        case .invalidOperationParameters: return "ARGUMENT_VALIDATION"
        case .sessionNotFound: return "SESSION_NOT_FOUND"
        case .sessionExpired: return "SESSION_EXPIRED"
        case .sessionScopeMismatch: return "SESSION_SCOPE_MISMATCH"
        case .sessionControlUnavailable: return "SESSION_CONTROL_UNAVAILABLE"
        case .sessionLimitReached: return "SESSION_LIMIT_REACHED"
        case .batchValidationFailed: return "BATCH_VALIDATION_FAILED"
        case .redirectRequiresReview: return "REDIRECT_REQUIRES_REVIEW"
        case .outputQuarantined: return "ACTION_OUTPUT_QUARANTINED"
        case .insecureTransportDenied: return "INSECURE_TRANSPORT_DENIED"
        case .operationNotFound: return "OPERATION_NOT_FOUND"
        case .idempotencyKeyConflict: return "IDEMPOTENCY_KEY_CONFLICT"
        }
    }
}
