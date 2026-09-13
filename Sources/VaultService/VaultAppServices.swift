import CryptoKit
import Foundation
import os
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

public protocol TextEncrypting: Sendable {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference
}

public enum VaultAppServicesOrphanScanError: Error, Equatable, Sendable {
    case scanUnavailable
}

public enum VaultAppServicesSavedReferencesError: Error, Equatable, Sendable {
    case listUnavailable
}

public struct AgentAutomationAuditEntry: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let occurredAt: Date
    public let action: String
    public let target: String
    public let referenceCount: Int
    public let result: String
    public let authorizationMode: AuditAuthorizationMode?
    public let caller: AuditCaller?

    public init(
        id: UUID = UUID(),
        occurredAt: Date = Date(),
        action: String,
        target: String,
        referenceCount: Int,
        result: String,
        authorizationMode: AuditAuthorizationMode? = nil,
        caller: AuditCaller? = nil
    ) {
        self.id = id
        self.occurredAt = occurredAt
        self.action = action
        self.target = target
        self.referenceCount = referenceCount
        self.result = result
        self.authorizationMode = authorizationMode
        self.caller = caller
    }
}

private struct AgentDecryptAuthorization: Sendable {
    let key: SymmetricKey
    let policy: SecretPolicy
    let destination: String?
    let expiresAt: Date
}

private struct DestinationBindingRequest: Sendable {
    let destination: String
    let protocolType: SecretOperationProtocol
    let port: Int?
    let hostKeyPin: SSHHostKeyPin?

    var isHostKeyPinning: Bool {
        hostKeyPin != nil
    }
}

private enum CatalogMutationPhase: String {
    case inputValidation = "input-validation"
    case policy = "policy"
    case agentAuthorization = "agent-authorization"
    case snapshot = "snapshot"
    case model = "model"
    case identifierGeneration = "identifier-generation"
    case store = "store"
}

private enum SecretOperationAuthorizationPath: Sendable {
    case notRequired
    case freshLocalApproval(LocalAuthenticationContext?)
    case executionWindowReuse

    /// This context is short-lived request state, never an IPC value or a
    /// reusable authorization capability. It is passed only to the immediate
    /// Keychain-backed master-key lookup that follows the same owner approval.
    var authenticationContext: LocalAuthenticationContext? {
        guard case let .freshLocalApproval(context) = self else {
            return nil
        }
        return context
    }

    var auditMode: AuditAuthorizationMode? {
        switch self {
        case .notRequired:
            return nil
        case .freshLocalApproval:
            return .freshLocalApproval
        case .executionWindowReuse:
            return .executionWindowReuse
        }
    }

    var auditOutcome: AuditAuthorizationOutcome {
        switch self {
        case .notRequired:
            return .notRequired
        case .freshLocalApproval, .executionWindowReuse:
            return .approved
        }
    }

    var operationAuditAction: String {
        switch self {
        case .executionWindowReuse:
            return "智能体专用操作（执行授权复用）"
        case .notRequired, .freshLocalApproval:
            return "智能体专用操作"
        }
    }

    func operationAuditAction(for action: SecretOperationAction) -> String {
        guard action == .localExecution else {
            return operationAuditAction
        }
        return "userApprovedSecretRelease"
    }
}

private enum ExecutionAuthorizationCommit: Equatable, Sendable {
    case leaseEstablished
    case leaseReused
    case approvedWithoutLease
    case needsFreshApproval
}

public actor VaultAppServices: WorkbenchServicing, AppControlServicing {
    private static let catalogMutationLogger = Logger(subsystem: "AgentSecretVault", category: "CatalogMutation")
    let textEncryptor: any TextEncrypting
    private let activeRoot: URL?
    private let recordLister: (any RecordListing)?
    let recordDeleter: (any RecordDeleting)?
    let recordResolver: VaultRecordResolver?
    let catalogDocumentOwner: CatalogDocumentOwner?
    let catalogSearchService: SecretCatalogEntrySearchService
    private let catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization
    let catalogMutationPolicyEngine: CatalogMutationPolicyEngine
    private let masterKey: SymmetricKey?
    private let masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
    private let freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)?
    private let masterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)?
    private let freshMasterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)?
    private let clearProtectedKeyState: (@Sendable () async -> Void)?
    private let isUnlockedProvider: (@Sendable () async -> Bool)
    private let revealSessionCoordinator: RevealSessionCoordinator
    private let authorizationSession: AuthorizationSession
    private let scopedMasterKeyCoordinator: ScopedMasterKeyCoordinator
    let secretOperationService = SecretOperationService()
    let operationPolicyEngine: SecretOperationPolicyEngine
    private let approvalTicketStore: ApprovalTicketStore
    private let operationApprover: any OperationApproving
    private let operationExecutor: any SecretOperationExecuting
    private let operationApprovalTimeout: Duration
    private let agentDecryptAuthorizationTTL: TimeInterval?
    private let credentialAuthorizationTTL: TimeInterval
    private let externalSendAuthorizationTTL: TimeInterval
    let now: @Sendable () -> Date
    private let orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)?
    private let statusObserver: (@Sendable (WorkbenchStatus) async -> Void)?
    private let auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)?
    private let savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)?
    let auditPersistenceCoordinator: CatalogAuditPersistenceCoordinator
    private let secureInputReceiptStore: CatalogSecureInputReceiptStore
    private let exportCoordinator: CatalogExportCoordinator
    private let writeAccessNotifier: CatalogAgentWriteAccessNotifier
    let secureInputNotifier: CatalogAgentSecureInputNotifier
    lazy var catalogWriteAccessCoordinator: CatalogWriteAccessCoordinator = {
        CatalogWriteAccessCoordinator(
            authorization: catalogAgentWriteAuthorization,
            approver: { [weak self] summary in
                guard let self else {
                    throw SecretCatalogAgentError.unavailable
                }
                _ = try await self.approveWithTimeout(summary: summary)
            },
            notifier: writeAccessNotifier,
            now: now,
            emitAudit: { [weak self] event in
                await self?.emitCatalogWriteAccessAudit(event)
            }
        )
    }()
    private var pluginConnectedAt: Date?
    private var agentDecryptAuthorizations: [String: AgentDecryptAuthorization] = [:]
    var pendingCatalogDrafts: [String: SecretCatalogEntry] = [:]
    var pendingCatalogDraftDocumentPaths: [String: String] = [:]
    var catalogFormatRepairDocumentPaths: [String: String] = [:]
    var secureInputCatalogOperations: [UUID: CatalogDocumentOperation] = [:]
    private var securityGeneration: UInt64 = 0
    var secureInputLifecycle = CatalogSecureInputLifecycle()
    /// Keep cancellation/expiry latched during suspended submission so a late
    /// SecureField callback cannot commit after App cancellation.

    public init(
        textEncryptor: any TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        masterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)? = nil,
        clearProtectedKeyState: (@Sendable () async -> Void)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = NoopRevealSessionPresenter(),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        operationPolicyEngine: SecretOperationPolicyEngine = SecretOperationPolicyEngine(),
        approvalTicketStore: ApprovalTicketStore = ApprovalTicketStore(),
        operationApprover: any OperationApproving = LocalOperationApprover(),
        operationExecutor: any SecretOperationExecuting = LocalSecretOperationExecutor(),
        operationApprovalTimeout: Duration = .seconds(30),
        agentDecryptAuthorizationTTL: TimeInterval? = nil,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init,
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        auditHealthURL: URL? = nil,
        secureInputReceiptURL: URL? = nil,
        exportDirectory: URL? = nil,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier = CatalogAgentWriteAccessNotifier(),
        secureInputNotifier: CatalogAgentSecureInputNotifier = CatalogAgentSecureInputNotifier()
    ) {
        self.textEncryptor = textEncryptor
        self.activeRoot = activeRoot
        self.recordLister = recordLister
        self.recordDeleter = recordDeleter
        self.recordResolver = recordResolver
        let catalogSelectionStore = catalogSelectionManifestURL.map(SecretCatalogSelectionStore.init(manifestURL:))
        self.catalogDocumentOwner = catalogDocumentStore.map {
            CatalogDocumentOwner(store: $0, selectionStore: catalogSelectionStore)
        }
        self.catalogSearchService = SecretCatalogEntrySearchService()
        self.catalogAgentWriteAuthorization = catalogAgentWriteAuthorization ?? CatalogAgentWriteAuthorization(now: now)
        self.catalogMutationPolicyEngine = CatalogMutationPolicyEngine()
        self.masterKey = masterKey
        self.masterKeyProvider = masterKeyProvider
        self.freshMasterKeyProvider = freshMasterKeyProvider
        self.masterKeyProviderWithAuthenticationContext = masterKeyProviderWithAuthenticationContext
        self.freshMasterKeyProviderWithAuthenticationContext = freshMasterKeyProviderWithAuthenticationContext
        self.clearProtectedKeyState = clearProtectedKeyState
        self.isUnlockedProvider = isUnlockedProvider
        self.revealSessionCoordinator = RevealSessionCoordinator(
            store: revealSessionStore,
            presenter: revealSessionPresenter
        )
        self.authorizationSession = authorizationSession
        self.scopedMasterKeyCoordinator = ScopedMasterKeyCoordinator(
            invalidateExecutionAuthorization: { scope in
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
            }
        )
        self.operationPolicyEngine = operationPolicyEngine
        self.approvalTicketStore = approvalTicketStore
        self.operationApprover = operationApprover
        self.operationExecutor = operationExecutor
        self.operationApprovalTimeout = operationApprovalTimeout
        self.agentDecryptAuthorizationTTL = agentDecryptAuthorizationTTL
        self.credentialAuthorizationTTL = agentDecryptAuthorizationTTL ?? credentialAuthorizationTTL
        self.externalSendAuthorizationTTL = externalSendAuthorizationTTL
        self.now = now
        self.orphanScanObserver = orphanScanObserver
        self.statusObserver = statusObserver
        self.auditObserver = auditObserver
        self.savedReferencesObserver = savedReferencesObserver
        self.auditPersistenceCoordinator = CatalogAuditPersistenceCoordinator(
            auditLog: auditLog,
            auditHealthURL: auditHealthURL,
            fallbackMasterKey: masterKey,
            now: now
        )
        let resolvedSecureInputReceiptURL = (secureInputReceiptURL
            ?? auditHealthURL?.deletingLastPathComponent().appendingPathComponent("secure-input-receipts.json"))?
            .standardizedFileURL
        let secureInputReceiptStore = CatalogSecureInputReceiptStore(url: resolvedSecureInputReceiptURL)
        self.secureInputReceiptStore = secureInputReceiptStore
        let persistedSecureInputReceipts = secureInputReceiptStore.load(now: now())
        self.secureInputLifecycle = CatalogSecureInputLifecycle(receipts: persistedSecureInputReceipts)
        self.exportCoordinator = CatalogExportCoordinator(root: exportDirectory ?? CatalogExportCoordinator.defaultRoot())
        self.writeAccessNotifier = writeAccessNotifier
        self.secureInputNotifier = secureInputNotifier
    }

    public init(
        encryptSelection: any EncryptSelectionCoordinating & TextEncrypting,
        activeRoot: URL?,
        recordLister: (any RecordListing)? = nil,
        recordDeleter: (any RecordDeleting)? = nil,
        recordResolver: VaultRecordResolver? = nil,
        catalogDocumentStore: SensitiveCatalogDocumentStore? = nil,
        catalogSelectionManifestURL: URL? = nil,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization? = nil,
        masterKey: SymmetricKey? = nil,
        masterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProvider: (@Sendable (SecretPolicy, String) async throws -> SymmetricKey)? = nil,
        masterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)? = nil,
        freshMasterKeyProviderWithAuthenticationContext: (@Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey)? = nil,
        clearProtectedKeyState: (@Sendable () async -> Void)? = nil,
        isUnlockedProvider: @escaping @Sendable () async -> Bool = { true },
        revealSessionStore: RevealSessionStore = RevealSessionStore(),
        revealSessionPresenter: any RevealSessionPresenting = NoopRevealSessionPresenter(),
        authorizationSession: AuthorizationSession = AuthorizationSession(),
        operationPolicyEngine: SecretOperationPolicyEngine = SecretOperationPolicyEngine(),
        approvalTicketStore: ApprovalTicketStore = ApprovalTicketStore(),
        operationApprover: any OperationApproving = LocalOperationApprover(),
        operationExecutor: any SecretOperationExecuting = LocalSecretOperationExecutor(),
        operationApprovalTimeout: Duration = .seconds(30),
        agentDecryptAuthorizationTTL: TimeInterval? = nil,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init,
        orphanScanObserver: (@Sendable (OrphanScanResult) async -> Void)? = nil,
        statusObserver: (@Sendable (WorkbenchStatus) async -> Void)? = nil,
        auditObserver: (@Sendable (AgentAutomationAuditEntry) async -> Void)? = nil,
        savedReferencesObserver: (@Sendable ([SecretReferenceMetadata]) async -> Void)? = nil,
        auditLog: EncryptedAuditLog? = nil,
        auditHealthURL: URL? = nil,
        secureInputReceiptURL: URL? = nil,
        exportDirectory: URL? = nil,
        writeAccessNotifier: CatalogAgentWriteAccessNotifier = CatalogAgentWriteAccessNotifier()
    ) {
        self.init(
            textEncryptor: encryptSelection,
            activeRoot: activeRoot,
            recordLister: recordLister,
            recordDeleter: recordDeleter,
            recordResolver: recordResolver,
            catalogDocumentStore: catalogDocumentStore,
            catalogSelectionManifestURL: catalogSelectionManifestURL,
            catalogAgentWriteAuthorization: catalogAgentWriteAuthorization,
            masterKey: masterKey,
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
            masterKeyProviderWithAuthenticationContext: masterKeyProviderWithAuthenticationContext,
            freshMasterKeyProviderWithAuthenticationContext: freshMasterKeyProviderWithAuthenticationContext,
            clearProtectedKeyState: clearProtectedKeyState,
            isUnlockedProvider: isUnlockedProvider,
            revealSessionStore: revealSessionStore,
            revealSessionPresenter: revealSessionPresenter,
            authorizationSession: authorizationSession,
            operationPolicyEngine: operationPolicyEngine,
            approvalTicketStore: approvalTicketStore,
            operationApprover: operationApprover,
            operationExecutor: operationExecutor,
            operationApprovalTimeout: operationApprovalTimeout,
            agentDecryptAuthorizationTTL: agentDecryptAuthorizationTTL,
            credentialAuthorizationTTL: credentialAuthorizationTTL,
            externalSendAuthorizationTTL: externalSendAuthorizationTTL,
            now: now,
            orphanScanObserver: orphanScanObserver,
            statusObserver: statusObserver,
            auditObserver: auditObserver,
            savedReferencesObserver: savedReferencesObserver,
            auditLog: auditLog,
            auditHealthURL: auditHealthURL,
            secureInputReceiptURL: secureInputReceiptURL,
            exportDirectory: exportDirectory,
            writeAccessNotifier: writeAccessNotifier
        )
    }

    public func recordPluginActivity() async {
        let wasConnected = isPluginConnected()
        pluginConnectedAt = now()
        if !wasConnected {
            // Connection/status bookkeeping is intentionally not an encrypted
            // Vault audit write. This keeps health checks disk/keychain-free.
            await statusObserver?(status())
        }
    }

    public func status() async -> WorkbenchStatus {
        WorkbenchStatus(
            locked: !(await isUnlockedProvider()),
            ipcAvailable: true,
            available: true,
            ready: true,
            approvalPending: await secretOperationService.approvalPending,
            activeKnowledgeBaseRoot: activeRoot?.path,
            pluginConnected: isPluginConnected()
        )
    }

    public func clearRevealSessions() async {
        await revealSessionCoordinator.clearAll()
    }

    public func invalidateSecurityState() async {
        // Lock/sleep/daemon shutdown must latch cancellation before protected
        // keys are cleared.  A submit suspended in authentication or Catalog
        // I/O then observes the abort reason on its next actor resumption;
        // requests that have not crossed the commit linearization point cannot
        // outlive the security-state invalidation.
        securityGeneration &+= 1
        await secretOperationService.invalidateAllCoordination()
        await scopedMasterKeyCoordinator.invalidateAll()
        await cancelAllSecureInputRequests()
        await authorizationSession.invalidate()
        await operationExecutor.invalidateSecurityState()
        for authorization in agentDecryptAuthorizations.values {
            var keyData = authorization.key.withUnsafeBytes { Data($0) }
            keyData.resetBytes(in: 0..<keyData.count)
        }
        agentDecryptAuthorizations.removeAll()
        await clearProtectedKeyState?()
        await statusObserver?(status())
    }

    private func cancelAllSecureInputRequests() async {
        let requestIDs = secureInputLifecycle.requestIDs
        for id in requestIDs {
            guard let request = secureInputLifecycle.request(id: id),
                  let state = secureInputLifecycle.state(for: id)
            else { continue }
            switch state {
            case .awaitingInput:
                await finishSecureInputRequest(
                    id: id,
                    status: CatalogSecureInputStatus(
                        requestID: request.id,
                        status: .cancelled,
                        errorCode: "SECURE_INPUT_CANCELLED"
                    ),
                    action: "智能体安全输入取消",
                    result: "已取消",
                    authorizationOutcome: .cancelled,
                    auditStatus: .cancelled
                )
            case .submitting:
                secureInputLifecycle.latchAbort(.cancelled, for: id)
                secureInputNotifier.notifyQueueChanged(requestID: id)
            case .committing, .completed, .failed, .expired, .cancelled:
                // `.committing` is the linearization point: it is already
                // authorized to finish, so shutdown must not rewrite a real
                // commit as a cancellation.
                continue
            }
        }
    }

    public func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        let reference = try await textEncryptor.encryptText(
            plaintext,
            label: label,
            policy: policy
        )
        await notifySavedReferencesChanged()
        return reference.description
    }

    public func encryptText(
        _ plaintext: String,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    ) async throws -> String {
        let reference: SecretReference
        if let bindingEncryptor = textEncryptor as? any DestinationBindingTextEncrypting {
            reference = try await bindingEncryptor.encryptText(
                plaintext,
                label: label,
                policy: policy,
                allowedDestinations: allowedDestinations,
                allowedProtocols: allowedProtocols
            )
        } else {
            reference = try await textEncryptor.encryptText(
                plaintext,
                label: label,
                policy: policy
            )
        }
        await notifySavedReferencesChanged()
        return reference.description
    }

    public func performSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationOutput {
        if descriptor.actionType == .vaultStatus {
            let currentStatus = await status()
            return SecretOperationOutput(
                status: currentStatus.ready ? "READY" : "UNAVAILABLE"
            )
        }

        let operationGeneration = securityGeneration
        let metadata = try await policyMetadata(for: descriptor.secretReferences)
        if descriptor.actionType == .changeDestinationBinding {
            let normalizedDescriptor = try normalizedDestinationBindingDescriptor(descriptor)
            return try await performDestinationBindingChange(
                normalizedDescriptor,
                metadata: metadata,
                generation: operationGeneration
            )
        }
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        guard decision.risk != .denied else {
            await emitAudit(
                action: "智能体操作请求无效",
                target: decision.policyRuleID,
                referenceCount: descriptor.secretReferences.count,
                result: "失败"
            )
            throw policyDecisionError(for: decision)
        }

        let executorAction = isExecutionLeaseEligible(descriptor.actionType)
        let executorCapability = isExecutorBackedAction(descriptor.actionType)
            ? operationExecutor.preflight(descriptor)
            : .supported
        if executorCapability == .unavailable {
            await emitAudit(
                action: "智能体操作执行器不可用",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "不可用",
                operation: .secureExecute,
                status: .failure
            )
            throw SecretOperationError.actionExecutorUnavailable
        }
        if executorCapability == .invalidParameters {
            await emitAudit(
                action: "智能体操作参数无效",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "参数无效",
                operation: .secureExecute,
                status: .failure
            )
            throw descriptor.sshCommandBatch == nil
                ? SecretOperationError.invalidOperationParameters
                : SecretOperationError.batchValidationFailed
        }

        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        let executionWindowEnabled: Bool
        if executorAction {
            executionWindowEnabled = await authorizationSession.executionAuthorizationWindowEnabled()
        } else {
            executionWindowEnabled = false
        }
        var executionScope: ExecutionAuthorizationScope? = decision.authorizationRequirement == .reusableApproval && executionWindowEnabled
            ? scopedAuthorizationScope(for: descriptor, generation: operationGeneration)
            : nil
        var authorizationPath = try await authorizeIfNeeded(
            descriptor,
            metadata: metadata,
            decision: decision,
            expectedGeneration: operationGeneration,
            executionScope: executionScope
        )

        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        // Re-read policy after approval because actor reentrancy may change bindings.
        var currentMetadata: [SecretPolicyMetadata]
        do {
            currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
        var currentDecision = operationPolicyEngine.evaluate(
            descriptor,
            metadata: currentMetadata
        )
        guard currentDecision.risk != .denied else {
            await emitAudit(
                action: "智能体操作请求在执行前无效",
                target: currentDecision.policyRuleID,
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw policyDecisionError(for: currentDecision)
        }
        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        // A stricter re-evaluation discards reusable scope before fresh approval.
        if executionScope != nil,
           currentDecision.authorizationRequirement != .reusableApproval {
            // A re-evaluated fresh requirement takes the one-shot path, but
            // the owner's already-granted ordinary lease stays untouched
            // (§55): fresh never deletes, refreshes, or extends it.
            executionScope = nil
            authorizationPath = try await authorizeIfNeeded(
                descriptor,
                metadata: currentMetadata,
                decision: currentDecision,
                expectedGeneration: operationGeneration,
                executionScope: nil
            )
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            do {
                currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
            } catch {
                throw SecretOperationError.actionExecutionFailed
            }
            currentDecision = operationPolicyEngine.evaluate(
                descriptor,
                metadata: currentMetadata
            )
            guard currentDecision.risk != .denied else {
                throw policyDecisionError(for: currentDecision)
            }
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
        }

        guard let recordResolver else {
            throw SecretOperationError.actionExecutionFailed
        }

        var key: SymmetricKey
        do {
            key = try await masterKeyForScopedAuthorization(
                scope: executionScope,
                for: authorizationPolicy(for: currentMetadata.map(\.policy)),
                reason: operationReason(for: descriptor),
                destination: currentDecision.normalizedDestination,
                authenticationContext: authorizationPath.authenticationContext,
                forceFreshWhenUnscoped: false
            )
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }

        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        var shouldEmitExecutionWindowReuseAudit = false
        if let executionScope {
            var commit = try await commitExecutionAuthorization(
                scope: executionScope,
                generation: operationGeneration,
                masterKey: key
            )

            if commit == .needsFreshApproval {
                await noteTrackedSecretOperationState(.awaitingApproval)
                authorizationPath = try await authorizeAgentExecution(
                    descriptor,
                    metadata: currentMetadata,
                    decision: currentDecision,
                    generation: operationGeneration,
                    scope: executionScope
                )
                try ensureTrackedSecretOperationIsActive()
                await noteTrackedSecretOperationState(.running)
                guard operationGeneration == securityGeneration else {
                    throw SecretOperationError.authorizationCancelled
                }

                let refreshedMetadata: [SecretPolicyMetadata]
                do {
                    refreshedMetadata = try await policyMetadata(for: descriptor.secretReferences)
                } catch {
                    throw SecretOperationError.actionExecutionFailed
                }
                let refreshedDecision = operationPolicyEngine.evaluate(
                    descriptor,
                    metadata: refreshedMetadata
                )
                guard refreshedDecision.risk != .denied else {
                    throw policyDecisionError(for: refreshedDecision)
                }
                guard operationGeneration == securityGeneration else {
                    throw SecretOperationError.authorizationCancelled
                }

                currentMetadata = refreshedMetadata
                currentDecision = refreshedDecision

                do {
                    key = try await masterKeyForScopedAuthorization(
                        scope: executionScope,
                        for: authorizationPolicy(for: refreshedMetadata.map(\.policy)),
                        reason: operationReason(for: descriptor),
                        destination: refreshedDecision.normalizedDestination,
                        authenticationContext: authorizationPath.authenticationContext,
                        forceFreshWhenUnscoped: false
                    )
                } catch {
                    throw SecretOperationError.actionExecutionFailed
                }
                guard operationGeneration == securityGeneration else {
                    throw SecretOperationError.authorizationCancelled
                }

                commit = try await commitExecutionAuthorization(
                    scope: executionScope,
                    generation: operationGeneration,
                    masterKey: key
                )
                guard commit != .needsFreshApproval else {
                    throw SecretOperationError.authorizationCancelled
                }
            }

            switch commit {
            case .leaseEstablished, .approvedWithoutLease:
                authorizationPath = .freshLocalApproval(authorizationPath.authenticationContext)
            case .leaseReused:
                authorizationPath = .executionWindowReuse
                shouldEmitExecutionWindowReuseAudit = true
            case .needsFreshApproval:
                throw SecretOperationError.authorizationCancelled
            }
        }

        // Final generation/cancellation gate before executor registration.
        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }
        try ensureTrackedSecretOperationIsActive()
        await noteTrackedSecretOperationState(.running)
        if shouldEmitExecutionWindowReuseAudit {
            await emitExecutionWindowReuseAudit(
                descriptor: descriptor,
                decision: currentDecision
            )
        }

        // Audit append can suspend; re-check before creating the executor.
        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }
        try ensureTrackedSecretOperationIsActive()

        let executionContext = SecretOperationExecutionContext(
            principal: AuditContext.current?.principal ?? AuditSource.agent.rawValue,
            securityGeneration: operationGeneration
        )
        let authorizedReferences = Set(descriptor.secretReferences)
        let executionTask = Task { [operationExecutor, descriptor, currentMetadata, recordResolver, key, executionContext, authorizedReferences] in
            try await operationExecutor.execute(
                descriptor,
                metadata: currentMetadata,
                context: executionContext,
                resolve: { reference in
                    // The executor may resolve only references approved for this operation.
                    guard authorizedReferences.contains(reference) else {
                        throw SecretOperationExecutionError.invalidParameter
                    }
                    return try await recordResolver.resolve(
                        reference: reference.description,
                        masterKey: key
                    )
                }
            )
        }
        do {
            let output = try await secretOperationService.awaitExecutionTask(
                executionTask,
                operationID: trackedSecretOperationID()
            )
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            guard output.status != "ACTION_EXECUTOR_UNAVAILABLE" else {
                throw SecretOperationError.actionExecutorUnavailable
            }
            guard output.status == "COMPLETED" else {
                await emitAudit(
                    action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                    target: currentDecision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: output.status,
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .failure
                )
                return output
            }
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: output.status,
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .completed
            )
            return output
        } catch SecretOperationExecutionError.unavailable {
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "不可用",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.actionExecutorUnavailable
        } catch SecretOperationError.actionExecutorUnavailable {
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "不可用",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.actionExecutorUnavailable
        } catch SecretOperationExecutionError.redirectRequiresReview {
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "需要复核",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.redirectRequiresReview
        } catch SecretOperationExecutionError.outputQuarantined {
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "已隔离",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .quarantined
            )
            throw SecretOperationError.outputQuarantined
        } catch let error as SecretOperationExecutionError {
            let mappedError = mapExecutionError(error)
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: mappedError.responseCode,
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw mappedError
        } catch {
            if operationGeneration != securityGeneration {
                await emitAudit(
                    action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                    target: currentDecision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "已取消",
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .cancelled
                )
                throw SecretOperationError.authorizationCancelled
            }
            await emitAudit(
                action: authorizationPath.operationAuditAction(for: descriptor.actionType),
                target: currentDecision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.actionExecutionFailed
        }
    }

    private func performDestinationBindingChange(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        generation: UInt64
    ) async throws -> SecretOperationOutput {
        let binding = try destinationBinding(from: descriptor)
        let bindingAction = binding.isHostKeyPinning ? "固定 SSH 主机指纹" : "绑定凭据地址"
        let bindingTarget = auditTarget(for: binding)
        guard descriptor.secretReferences.count == 1,
              metadata.count == 1,
              metadata[0].reference == descriptor.secretReferences[0]
        else {
            throw SecretOperationError.invalidOperationParameters
        }

        let hostKeyReview: SSHHostKeyReview?
        if binding.isHostKeyPinning {
            guard let port = binding.port,
                  let reviewer = operationExecutor as? any SSHHostKeyReviewing else {
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "执行器不可用",
                    operation: .secureExecute,
                    status: .failure
                )
                throw SecretOperationError.actionExecutorUnavailable
            }
            do {
                let review = try await reviewer.reviewSSHHostKey(
                    host: binding.destination,
                    port: port
                )
                guard let pin = binding.hostKeyPin,
                      review.pins.contains(pin) else {
                    throw SSHHostKeyReviewError.pinNotPresented
                }
                hostKeyReview = review
            } catch SSHHostKeyReviewError.pinNotPresented {
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "主机指纹未出现",
                    operation: .secureExecute,
                    status: .failure
                )
                throw SecretOperationError.invalidOperationParameters
            } catch {
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "主机身份不可用",
                    operation: .secureExecute,
                    status: .failure
                )
                throw SecretOperationError.actionExecutionFailed
            }
        } else {
            hostKeyReview = nil
        }

        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        guard decision.risk != .denied,
              decision.authorizationRequirement == .freshApprovalRequired
        else {
            throw policyDecisionError(for: decision)
        }

        let authorizationPath = try await authorizeIfNeeded(
            descriptor,
            metadata: metadata,
            decision: decision,
            expectedGeneration: generation,
            hostKeyReview: hostKeyReview
        )
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        let currentMetadata: [SecretPolicyMetadata]
        do {
            currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
        let currentDecision = operationPolicyEngine.evaluate(
            descriptor,
            metadata: currentMetadata
        )
        guard currentDecision.risk != .denied,
              currentDecision.authorizationRequirement == .freshApprovalRequired else {
            throw policyDecisionError(for: currentDecision)
        }
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        guard let recordResolver else {
            throw SecretOperationError.actionExecutionFailed
        }

        // The approved key is used only inside the re-sealing call; it never
        // enters a descriptor, IPC response, or audit record.
        let key: SymmetricKey
        do {
            key = try await masterKeyForScopedAuthorization(
                scope: nil,
                for: authorizationPolicy(for: currentMetadata.map(\.policy)),
                reason: operationReason(for: descriptor),
                destination: currentDecision.normalizedDestination,
                authenticationContext: authorizationPath.authenticationContext,
                forceFreshWhenUnscoped: true
            )
        } catch {
            await emitAudit(
                action: bindingAction,
                target: bindingTarget,
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.actionExecutionFailed
        }

        // Final pre-commit security check. Once the persistence call starts,
        // it is the binding commit linearization point: a later security
        // invalidation may clear future authorization state, but it must not
        // rewrite a successfully persisted binding as CANCELLED.
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if let pin = binding.hostKeyPin {
            guard let port = binding.port,
                  let pinner = operationExecutor as? any SSHHostKeyPinning else {
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "执行器不可用",
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .failure
                )
                throw SecretOperationError.actionExecutorUnavailable
            }
            do {
                // Re-discovery after approval closes the TOCTOU gap between
                // the identity shown to the owner and the identity persisted
                // in the strict trust profile.
                try await pinner.installSSHHostKey(
                    host: binding.destination,
                    port: port,
                    pin: pin
                )
            } catch {
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "主机指纹复核失败",
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .failure
                )
                throw SecretOperationError.actionExecutionFailed
            }
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
        }

        let boundMetadata: SecretReferenceMetadata
        do {
            boundMetadata = try await recordResolver.bindDestination(
                reference: descriptor.secretReferences[0].description,
                destination: binding.destination,
                protocolType: binding.protocolType,
                masterKey: key,
                port: binding.port,
                hostKeyPin: binding.hostKeyPin,
                now: now(),
                preCommitCheck: { [self] in
                    guard await securityGenerationIsCurrent(generation) else {
                        throw VaultRecordBindingError.authorizationCancelled
                    }
                }
            )
        } catch let error as VaultRecordBindingError {
            switch error {
            case .authorizationCancelled:
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "已取消",
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .cancelled
                )
                throw SecretOperationError.authorizationCancelled
            case .invalidReference, .invalidDestination, .tooManyDestinations, .tooManyProtocols, .tooManyBindings:
                await emitAudit(
                    action: bindingAction,
                    target: bindingTarget,
                    referenceCount: descriptor.secretReferences.count,
                    result: "参数无效",
                    operation: .secureExecute,
                    authorizationOutcome: authorizationPath.auditOutcome,
                    authorizationMode: authorizationPath.auditMode,
                    status: .failure
                )
                throw SecretOperationError.invalidOperationParameters
            }
        } catch {
            await emitAudit(
                action: bindingAction,
                target: bindingTarget,
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .secureExecute,
                authorizationOutcome: authorizationPath.auditOutcome,
                authorizationMode: authorizationPath.auditMode,
                status: .failure
            )
            throw SecretOperationError.actionExecutionFailed
        }

        await notifySavedReferencesChanged()
        await emitAudit(
            action: bindingAction,
            target: bindingTarget,
            referenceCount: descriptor.secretReferences.count,
            result: "成功",
            operation: .secureExecute,
            authorizationOutcome: authorizationPath.auditOutcome,
            authorizationMode: authorizationPath.auditMode,
            status: .completed
        )
        return SecretOperationOutput(
            status: "BOUND",
            destination: boundMetadata.allowedBindings.first(where: {
                $0.protocolType == binding.protocolType
                    && $0.destination == binding.destination
                    && $0.port == binding.port
                    && $0.hostKeyPin == binding.hostKeyPin
            })?.destination ?? binding.destination,
            protocolType: binding.protocolType,
            port: binding.port,
            hostKeyPin: binding.hostKeyPin,
            redacted: true
        )
    }

    private func securityGenerationIsCurrent(_ expected: UInt64) -> Bool {
        expected == securityGeneration
    }

    private func normalizedDestinationBindingDescriptor(
        _ descriptor: SecretOperationDescriptor
    ) throws -> SecretOperationDescriptor {
        let binding = try destinationBinding(from: descriptor)
        return descriptor.replacingDestination(binding.destination)
    }

    private func destinationBinding(
        from descriptor: SecretOperationDescriptor
    ) throws -> DestinationBindingRequest {
        let isDestinationBind = descriptor.requestedEffects == ["bind-secret-destination"]
        let isHostKeyPin = descriptor.requestedEffects == ["pin-ssh-host-key"]
        guard descriptor.secretReferences.count == 1,
              isDestinationBind || isHostKeyPin,
              descriptor.destination != nil,
              descriptor.protocolType != nil,
              descriptor.command == nil,
              descriptor.httpMethod == nil,
              descriptor.url == nil,
              descriptor.databaseStatement == nil,
              descriptor.fileOperation == nil,
              descriptor.fileTarget == nil,
              descriptor.localAppBundleID == nil,
              descriptor.sessionID == nil,
              descriptor.sshCommandBatch == nil,
              descriptor.payload == nil
        else {
            throw SecretOperationError.invalidOperationParameters
        }

        guard let rawDestination = descriptor.destination,
              let protocolType = descriptor.protocolType else {
            throw SecretOperationError.invalidOperationParameters
        }
        let trimmed = rawDestination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.utf8.count <= 512,
              !trimmed.contains("secret://"),
              trimmed.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F })
        else {
            throw SecretOperationError.invalidOperationParameters
        }

        let hostKeyPin: SSHHostKeyPin?
        if isHostKeyPin {
            guard protocolType.supportsSSHHostKeyPin,
                  let port = descriptor.port,
                  (1...65_535).contains(port),
                  descriptor.parameters.count == 2,
                  Set(descriptor.parameters.keys) == Set(["hostKeyAlgorithm", "hostKeySHA256"]),
                  let algorithm = descriptor.parameters["hostKeyAlgorithm"],
                  let sha256 = descriptor.parameters["hostKeySHA256"],
                  !trimmed.contains("://"),
                  isHostWithoutEmbeddedPort(trimmed),
                  let parsedPin = try? SSHHostKeyPin(algorithm: algorithm, sha256: sha256) else {
                throw SecretOperationError.invalidOperationParameters
            }
            hostKeyPin = parsedPin
        } else {
            guard descriptor.parameters.isEmpty, descriptor.port == nil else {
                throw SecretOperationError.invalidOperationParameters
            }
            hostKeyPin = nil
        }

        if protocolType == .http || protocolType == .https {
            guard let normalized = SecretOperationDescriptor.normalizeHTTPOrigin(
                trimmed,
                expectedScheme: protocolType.rawValue,
                allowURLPath: false
            ) else {
                throw SecretOperationError.invalidOperationParameters
            }
            return DestinationBindingRequest(
                destination: normalized,
                protocolType: protocolType,
                port: nil,
                hostKeyPin: nil
            )
        }

        if trimmed.contains("://") {
            guard let url = URL(string: trimmed),
                  url.scheme?.lowercased() == protocolType.rawValue,
                  url.user == nil,
                  url.password == nil,
                  url.fragment == nil,
                  url.query == nil,
                  url.path.isEmpty || url.path == "/",
                  let host = url.host,
                  !host.isEmpty else {
                throw SecretOperationError.invalidOperationParameters
            }
        } else {
            guard !trimmed.contains("/"),
                  !trimmed.contains("?"),
                  !trimmed.contains("#"),
                  !trimmed.contains("@") else {
                throw SecretOperationError.invalidOperationParameters
            }
        }

        guard let normalized = SecretOperationDescriptor.normalizeDestination(trimmed),
              !normalized.isEmpty else {
            throw SecretOperationError.invalidOperationParameters
        }
        return DestinationBindingRequest(
            destination: normalized,
            protocolType: protocolType,
            port: descriptor.port,
            hostKeyPin: hostKeyPin
        )
    }

    private func isHostWithoutEmbeddedPort(_ value: String) -> Bool {
        if value.hasPrefix("[") {
            return value.hasSuffix("]")
                && !value.dropFirst().dropLast().contains("]")
        }
        return value.filter { $0 == ":" }.count != 1
    }

    private func auditTarget(for binding: DestinationBindingRequest) -> String {
        let destination = safeDisplayLabel(binding.destination)
        guard let port = binding.port else { return destination }
        let hostPort = binding.destination.contains(":")
            ? "[\(destination)]:\(port)"
            : "\(destination):\(port)"
        guard let pin = binding.hostKeyPin else { return hostPort }
        return "\(hostPort) \(safeDisplayLabel(pin.algorithm)) \(safeDisplayLabel(pin.sha256))"
    }

    private func sshHostKeyReviewAuditTarget(host: String, port: Int) -> String {
        let destination = safeDisplayLabel(host)
        return destination.contains(":")
            ? "[\(destination)]:\(port)"
            : "\(destination):\(port)"
    }

    /// Discovers non-secret SSH host-key metadata before any Secret is
    /// resolved. The caller can use the returned fingerprint in a subsequent
    /// owner-approved `pin-ssh-host-key` binding operation.
    public func reviewSSHHostKey(host: String, port: Int) async throws -> SSHHostKeyReview {
        let target = sshHostKeyReviewAuditTarget(host: host, port: port)
        guard let reviewer = operationExecutor as? any SSHHostKeyReviewing else {
            await emitAudit(
                action: "查看 SSH 主机指纹",
                target: target,
                referenceCount: 0,
                result: "执行器不可用",
                operation: .secureExecute,
                status: .failure
            )
            throw SecretOperationError.actionExecutorUnavailable
        }

        do {
            let review = try await reviewer.reviewSSHHostKey(host: host, port: port)
            await emitAudit(
                action: "查看 SSH 主机指纹",
                target: target,
                referenceCount: 0,
                result: "成功",
                operation: .secureExecute,
                status: .completed
            )
            return review
        } catch let error as SSHHostKeyReviewError {
            let mappedError: SecretOperationError
            let auditResult: String
            switch error {
            case .invalidHost, .invalidPort:
                mappedError = .invalidOperationParameters
                auditResult = "参数无效"
            case .unavailable, .noHostKey, .malformedHostKey, .pinNotPresented, .trustStoreUnavailable:
                mappedError = .actionExecutionFailed
                auditResult = "主机身份不可用"
            }
            await emitAudit(
                action: "查看 SSH 主机指纹",
                target: target,
                referenceCount: 0,
                result: auditResult,
                operation: .secureExecute,
                status: .failure
            )
            throw mappedError
        } catch {
            await emitAudit(
                action: "查看 SSH 主机指纹",
                target: target,
                referenceCount: 0,
                result: "失败",
                operation: .secureExecute,
                status: .failure
            )
            throw SecretOperationError.actionExecutionFailed
        }
    }

    /// Agent-facing transport management is intentionally narrower than the
    /// execution API. The caller can inspect only its own opaque session
    /// projections, and closing a session never exposes its ControlPath or
    /// secret reference.
    public func sshSessionStatuses(sessionID: String?) async throws -> [SSHSessionStatus] {
        do {
            return try await operationExecutor.sshSessionStatuses(
                sessionID: sessionID,
                context: currentExecutionContext()
            )
        } catch SecretOperationExecutionError.unavailable {
            throw SecretOperationError.actionExecutorUnavailable
        } catch let error as SecretOperationExecutionError {
            throw mapExecutionError(error)
        } catch let error as SecretOperationError {
            throw error
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
    }

    public func closeSSHSession(sessionID: String) async throws {
        do {
            try await operationExecutor.closeSSHSession(
                sessionID: sessionID,
                context: currentExecutionContext()
            )
        } catch SecretOperationExecutionError.unavailable {
            throw SecretOperationError.actionExecutorUnavailable
        } catch let error as SecretOperationExecutionError {
            throw mapExecutionError(error)
        } catch let error as SecretOperationError {
            throw error
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
        await emitAudit(
            action: "关闭 SSH transport session",
            target: "SSH session",
            referenceCount: 0,
            result: "已关闭",
            operation: .secureExecute,
            status: .completed
        )
    }

    public func secretOperationCapabilities() async -> [SecretOperationCapability] {
        operationExecutor.capabilities() + [exportCoordinator.capability()]
    }

    public func deleteRecord(_ reference: String) async throws {
        let parsed = try SecretReference(reference)
        guard let recordResolver else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }
        guard let recordDeleter else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }

        let metadata = try await recordResolver.metadata(reference: reference)
        let descriptor = SecretOperationDescriptor(
            actionType: .deleteSecret,
            secretReferences: [parsed],
            requestedEffects: ["delete-record"]
        )
        let decision = operationPolicyEngine.evaluate(
            descriptor,
            metadata: [SecretPolicyMetadata(
                reference: parsed,
                policy: metadata.policy,
                label: metadata.label,
                allowedDestinations: metadata.allowedDestinations,
                allowedProtocols: metadata.allowedProtocols,
                allowedBindings: metadata.allowedBindings
            )]
        )
        guard decision.risk != .denied else {
            throw SecretOperationError.invalidOperationParameters
        }
        try await authorizeIfNeeded(
            descriptor,
            metadata: [SecretPolicyMetadata(
                reference: parsed,
                policy: metadata.policy,
                label: metadata.label,
                allowedDestinations: metadata.allowedDestinations,
                allowedProtocols: metadata.allowedProtocols,
                allowedBindings: metadata.allowedBindings
            )],
            decision: decision
        )
        try await recordDeleter.delete(id: parsed.id)
        await notifySavedReferencesChanged()
        await emitAudit(
            action: "删除本机加密记录",
            target: reference,
            referenceCount: 0,
            result: "已删除"
        )
    }

    public func authorizeHighRisk(reason: String) async throws {
        let descriptor = SecretOperationDescriptor(
            actionType: .changeAuthorizationRules,
            requestedEffects: ["explicit-local-authorization"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: [])
        try await authorizeIfNeeded(descriptor, metadata: [], decision: decision)
    }

    public func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata {
        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }
        let metadata = try await recordResolver.metadata(reference: reference)
        await emitAudit(
            action: "查看引用元数据",
            target: sanitizedReason(reference),
            referenceCount: 1,
            result: "成功"
        )
        return metadata
    }

    public func savedSecretReferences() async throws -> [SecretReferenceMetadata] {
        guard let recordLister, let recordResolver else {
            throw VaultAppServicesSavedReferencesError.listUnavailable
        }

        let references = try await recordLister.recordIDs()
            .map { "secret://\($0)" }
            .asyncMap { try await recordResolver.metadata(reference: $0) }

        return references.sorted { lhs, rhs in
            if lhs.updatedAt == rhs.updatedAt {
                return lhs.reference < rhs.reference
            }
            return lhs.updatedAt > rhs.updatedAt
        }
    }

    public func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .revealPlaintext,
            references: references,
            context: context,
            effects: ["display-to-local-user"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let resolvedParagraph = try await resolveReferencesWithValues(references: references, context: context)
        let sessionID = await revealSessionCoordinator.createAndPresent(resolvedParagraph)
        await emitAudit(
            action: "本机显示明文",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "已显示"
        )
        return sessionID
    }

    public func pendingRevealSessionIDs() async throws -> [String] {
        await revealSessionCoordinator.sessionIDs()
    }

    public func revealSessionData(sessionID: String) async throws -> RestoredParagraph {
        try await revealSessionCoordinator.data(sessionID: sessionID)
    }

    public func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .copyPlaintext,
            references: references,
            context: context,
            effects: ["local-write-back"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let restored = try await resolveReferencesWithValues(references: references, context: context)
        await emitAudit(
            action: "本机脱密使用",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "成功",
            operation: .credentialUse
        )
        return restored.text
    }

    public func restoreReferencesWithValues(
        references: [String],
        context: RevealContext
    ) async throws -> RestoredParagraph {
        let (descriptor, metadata) = try await plaintextOperation(
            action: .copyPlaintext,
            references: references,
            context: context,
            effects: ["local-write-back"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        let restored = try await resolveReferencesWithValues(references: references, context: context)
        await emitAudit(
            action: "本机脱密使用",
            target: sanitizedReason(context.reason),
            referenceCount: references.count,
            result: "成功",
            operation: .credentialUse
        )
        return restored
    }

    public func exportResolvedText(
        references: [String],
        context: RevealContext,
        destinationPath: String
    ) async throws -> String {
        let destination = try exportCoordinator.validatedDestination(destinationPath)
        // Export is not an executor adapter, so perform its capability check
        // explicitly before issuing any device-owner approval. A missing,
        // shared, or symlinked root must never consume an approval ticket or
        // establish a reusable export lease for an operation that cannot be
        // committed safely.
        try exportCoordinator.requireReadyForApproval()
        let operationGeneration = securityGeneration
        let operationContext = RevealContext(
            reason: context.reason,
            template: context.template,
            ranges: context.ranges,
            destination: destination.path,
            agentAssessment: context.agentAssessment
        )
        let (descriptor, metadata) = try await plaintextOperation(
            action: .exportPlaintext,
            references: references,
            context: operationContext,
            effects: ["write-local-file"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        let executionWindowEnabled = await authorizationSession.executionAuthorizationWindowEnabled()
        var scope: ExecutionAuthorizationScope? = decision.authorizationRequirement == .reusableApproval && executionWindowEnabled
            ? scopedAuthorizationScope(for: descriptor, generation: operationGeneration)
            : nil
        var authorizationPath = try await authorizeIfNeeded(
            descriptor,
            metadata: metadata,
            decision: decision,
            expectedGeneration: operationGeneration,
            executionScope: scope
        )

        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        var currentMetadata: [SecretPolicyMetadata]
        do {
            currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
        var currentDecision = operationPolicyEngine.evaluate(descriptor, metadata: currentMetadata)
        guard currentDecision.risk != .denied else {
            throw SecretOperationError.invalidOperationParameters
        }
        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        // Export has its own reusable scope, but it must obey the same
        // post-approval promotion rule as execution. If fresh approval is
        // now required, discard the export lease candidate and perform an
        // exact one-shot approval without creating/extending a reusable lease.
        if scope != nil,
           currentDecision.authorizationRequirement != .reusableApproval {
            // The owner's already-granted export lease stays untouched when a
            // re-evaluation promotes this request to a fresh one-shot (§55).
            scope = nil
            authorizationPath = try await authorizeIfNeeded(
                descriptor,
                metadata: currentMetadata,
                decision: currentDecision,
                expectedGeneration: operationGeneration,
                executionScope: nil
            )
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            do {
                currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
            } catch {
                throw SecretOperationError.actionExecutionFailed
            }
            currentDecision = operationPolicyEngine.evaluate(
                descriptor,
                metadata: currentMetadata
            )
            guard currentDecision.risk != .denied else {
                throw SecretOperationError.invalidOperationParameters
            }
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
        }

        var key: SymmetricKey
        do {
            key = try await masterKeyForScopedAuthorization(
                scope: scope,
                for: authorizationPolicy(for: currentMetadata.map(\.policy)),
                reason: operationContext.reason,
                destination: exportCoordinator.authorizationDestination,
                authenticationContext: authorizationPath.authenticationContext,
                forceFreshWhenUnscoped: true
            )
        } catch {
            throw SecretOperationError.actionExecutionFailed
        }
        guard operationGeneration == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        var reusedScopedAuthorization = false
        if let scope {
            var commit = try await commitExecutionAuthorization(
                scope: scope,
                generation: operationGeneration,
                masterKey: key
            )
            if commit == .needsFreshApproval {
                await noteTrackedSecretOperationState(.awaitingApproval)
                authorizationPath = try await authorizeAgentExecution(
                    descriptor,
                    metadata: currentMetadata,
                    decision: currentDecision,
                    generation: operationGeneration,
                    scope: scope
                )
                guard operationGeneration == securityGeneration else {
                    throw SecretOperationError.authorizationCancelled
                }
                do {
                    currentMetadata = try await policyMetadata(for: descriptor.secretReferences)
                } catch {
                    throw SecretOperationError.actionExecutionFailed
                }
                currentDecision = operationPolicyEngine.evaluate(descriptor, metadata: currentMetadata)
                guard currentDecision.risk != .denied else {
                    throw SecretOperationError.invalidOperationParameters
                }
                guard operationGeneration == securityGeneration else {
                    throw SecretOperationError.authorizationCancelled
                }
                do {
                    key = try await masterKeyForScopedAuthorization(
                        scope: scope,
                        for: authorizationPolicy(for: currentMetadata.map(\.policy)),
                        reason: operationContext.reason,
                        destination: exportCoordinator.authorizationDestination,
                        authenticationContext: authorizationPath.authenticationContext,
                        forceFreshWhenUnscoped: true
                    )
                } catch {
                    throw SecretOperationError.actionExecutionFailed
                }
                commit = try await commitExecutionAuthorization(
                    scope: scope,
                    generation: operationGeneration,
                    masterKey: key
                )
                guard commit != .needsFreshApproval else {
                    throw SecretOperationError.authorizationCancelled
                }
            }

            switch commit {
            case .leaseEstablished, .approvedWithoutLease:
                authorizationPath = .freshLocalApproval(authorizationPath.authenticationContext)
            case .leaseReused:
                authorizationPath = .executionWindowReuse
                reusedScopedAuthorization = true
            case .needsFreshApproval:
                throw SecretOperationError.authorizationCancelled
            }
        }

        do {
            let resolvedText = try await resolveReferencesWithValues(
                references: references,
                context: operationContext,
                masterKeyOverride: key
            ).text
            guard operationGeneration == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            try exportCoordinator.write(
                Data(resolvedText.utf8),
                to: destination
            )
        } catch {
            throw error
        }

        if reusedScopedAuthorization {
            await emitExecutionWindowReuseAudit(descriptor: descriptor, decision: currentDecision)
        }
        await emitAudit(
            action: "写入本地文件",
            target: "local-export",
            referenceCount: references.count,
            result: "成功",
            operation: .credentialUse,
            authorizationOutcome: authorizationPath.auditOutcome,
            authorizationMode: authorizationPath.auditMode
        )
        return destination.path
    }

    func policyMetadata(
        for references: [SecretReference]
    ) async throws -> [SecretPolicyMetadata] {
        guard Set(references).count == references.count else {
            throw VaultAppServicesRevealError.invalidReference
        }
        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        var metadata: [SecretPolicyMetadata] = []
        metadata.reserveCapacity(references.count)
        for reference in references {
            let recordMetadata = try await recordResolver.metadata(reference: reference.description)
            metadata.append(
                SecretPolicyMetadata(
                    reference: reference,
                    policy: recordMetadata.policy,
                    label: recordMetadata.label,
                    allowedDestinations: recordMetadata.allowedDestinations,
                    allowedProtocols: recordMetadata.allowedProtocols,
                    allowedBindings: recordMetadata.allowedBindings
                )
            )
        }
        return metadata
    }

    func plaintextOperation(
        action: SecretOperationAction,
        references: [String],
        context: RevealContext,
        effects: [String]
    ) async throws -> (SecretOperationDescriptor, [SecretPolicyMetadata]) {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let parsedReferences: [SecretReference]
        do {
            parsedReferences = try references.map(SecretReference.init)
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }
        guard Set(parsedReferences).count == parsedReferences.count else {
            throw VaultAppServicesRevealError.invalidReference
        }
        try validateRevealContext(context, referenceCount: parsedReferences.count)
        let metadata = try await policyMetadata(for: parsedReferences)
        let descriptor = SecretOperationDescriptor(
            actionType: action,
            secretReferences: parsedReferences,
            destination: context.destination,
            requestedEffects: effects,
            agentAssessment: context.agentAssessment
        )
        return (descriptor, metadata)
    }

    @discardableResult
    func authorizeIfNeeded(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision,
        expectedGeneration: UInt64? = nil,
        executionScope: ExecutionAuthorizationScope? = nil,
        hostKeyReview: SSHHostKeyReview? = nil
    ) async throws -> SecretOperationAuthorizationPath {
        let generation = expectedGeneration ?? securityGeneration
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        switch decision.authorizationRequirement {
        case .none:
            return .notRequired
        case .denied:
            throw SecretOperationError.invalidOperationParameters
        case .reusableApproval, .freshApprovalRequired:
            break
        }

        await noteTrackedSecretOperationState(.awaitingApproval)
        if decision.authorizationRequirement == .reusableApproval,
           let executionScope {
            let authorization = try await authorizeAgentExecution(
                descriptor,
                metadata: metadata,
                decision: decision,
                generation: generation,
                scope: executionScope,
                hostKeyReview: hostKeyReview
            )
            try ensureTrackedSecretOperationIsActive()
            await noteTrackedSecretOperationState(.running)
            return authorization
        }

        await emitAudit(
            action: "本机授权请求",
            target: decision.normalizedDestination ?? "local",
            referenceCount: descriptor.secretReferences.count,
            result: "请求中",
            operation: .authorization,
            authorizationOutcome: .requested,
            status: .requested
        )
        let ticket = await approvalTicketStore.issue(for: descriptor, now: now())
        let summary = approvalSummary(
            descriptor: descriptor,
            metadata: metadata,
            decision: decision,
            hostKeyReview: hostKeyReview
        )
        let approvalID = await secretOperationService.beginApproval()
        await statusObserver?(status())

        var authenticationContext: LocalAuthenticationContext?
        do {
            authenticationContext = try await Self.approveWithTimeout(
                approver: operationApprover,
                timeout: operationApprovalTimeout,
                summary: summary
            )
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }
            guard await approvalTicketStore.consume(ticket, for: descriptor, now: now()) else {
                throw SecretOperationError.invalidOperationParameters
            }
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }
            await emitAudit(
                action: "本机授权完成",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "成功",
                operation: .authorization,
                authorizationOutcome: .approved,
                authorizationMode: .freshLocalApproval
            )
        } catch let error as SecretOperationError {
            if await secretOperationService.finishApproval(id: approvalID) {
                await statusObserver?(status())
            }
            await emitAudit(
                action: "本机授权失败",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .authorization,
                authorizationOutcome: .denied,
                status: .failure
            )
            throw error
        } catch let error as OperationAuthorizationError {
            if await secretOperationService.finishApproval(id: approvalID) {
                await statusObserver?(status())
            }
            switch error {
            case .cancelled:
                await emitAudit(action: "本机授权取消", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已取消", operation: .authorization, authorizationOutcome: .cancelled, status: .cancelled)
                throw SecretOperationError.authorizationCancelled
            case .denied:
                await emitAudit(action: "本机授权拒绝", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已拒绝", operation: .authorization, authorizationOutcome: .denied, status: .failure)
                throw SecretOperationError.authorizationDenied
            case .timeout:
                await emitAudit(action: "本机授权超时", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "已超时", operation: .authorization, authorizationOutcome: .expired, status: .expired)
                throw SecretOperationError.authorizationTimeout
            case .unavailable:
                await emitAudit(action: "本机授权不可用", target: decision.normalizedDestination ?? "local", referenceCount: descriptor.secretReferences.count, result: "失败", operation: .authorization, authorizationOutcome: .denied, status: .failure)
                throw SecretOperationError.authorizationUnavailable
            }
        } catch {
            if await secretOperationService.finishApproval(id: approvalID) {
                await statusObserver?(status())
            }
            await emitAudit(
                action: "本机授权失败",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "失败",
                operation: .authorization,
                authorizationOutcome: .denied,
                status: .failure
            )
            throw SecretOperationError.authorizationDenied
        }

        if await secretOperationService.finishApproval(id: approvalID) {
            await statusObserver?(status())
        }
        try ensureTrackedSecretOperationIsActive()
        await noteTrackedSecretOperationState(.running)
        return .freshLocalApproval(authenticationContext)
    }

    private func isExecutionLeaseEligible(_ action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand,
             .httpRequest,
             .apiRequest,
             .databaseQuery,
             .sftpTransfer,
             .ftpTransfer,
             .browserLogin,
             .localAppFill,
             .trustedProcess:
            return true
        default:
            return false
        }
    }

    private func isExecutorBackedAction(_ action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand, .httpRequest, .apiRequest, .databaseQuery, .sftpTransfer, .ftpTransfer,
             .browserLogin, .localAppFill, .localExecution, .trustedProcess:
            return true
        default:
            return false
        }
    }

    private func authorizeAgentExecution(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision,
        generation: UInt64,
        scope: ExecutionAuthorizationScope,
        hostKeyReview: SSHHostKeyReview? = nil
    ) async throws -> SecretOperationAuthorizationPath {
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            return .executionWindowReuse
        }

        if let flight = await secretOperationService.executionApprovalFlight(for: scope) {
            return try await waitForExecutionApprovalFlight(
                flight,
                scope: scope,
                generation: generation
            )
        }

        // AuthorizationSession is a separate actor. Recheck before asking the
        // SecretOperationService to atomically join-or-create the shared
        // approval flight. The second check plus atomic insert prevents
        // duplicate owner prompts under actor reentrancy.
        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            return .executionWindowReuse
        }

        let acquisition = await secretOperationService.joinOrCreateExecutionApprovalFlight(
            scope: scope,
            generation: generation,
            create: { [weak self] in
                guard let self else {
                    throw OperationAuthorizationError.cancelled
                }
                return try await self.performFreshExecutionApproval(
                    descriptor: descriptor,
                    metadata: metadata,
                    decision: decision,
                    generation: generation,
                    hostKeyReview: hostKeyReview
                )
            }
        )
        let flight = acquisition.flight
        if !acquisition.created {
            return try await waitForExecutionApprovalFlight(
                flight,
                scope: scope,
                generation: generation
            )
        }
        await statusObserver?(status())

        do {
            let authenticationContext = try await flight.task.value
            await markExecutionApprovalCompleted(flight.id)
            return .freshLocalApproval(authenticationContext)
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }
    }

    private func waitForExecutionApprovalFlight(
        _ flight: SecretOperationService.ExecutionApprovalFlight,
        scope: ExecutionAuthorizationScope,
        generation: UInt64
    ) async throws -> SecretOperationAuthorizationPath {
        do {
            let authenticationContext = try await flight.task.value
            guard generation == securityGeneration else {
                throw SecretOperationError.authorizationCancelled
            }
            await markExecutionApprovalCompleted(flight.id)
            // The approval is kept as a completed flight until one request
            // reaches the final execution commit. This closes the gap where
            // the first request is still rechecking policy while a later
            // request would otherwise start a second Touch ID prompt.
            return .freshLocalApproval(authenticationContext)
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }
    }

    private func performFreshExecutionApproval(
        descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision,
        generation: UInt64,
        hostKeyReview: SSHHostKeyReview? = nil
    ) async throws -> LocalAuthenticationContext? {
        do {
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }
            let ticket = await approvalTicketStore.issue(for: descriptor, now: now())
            let executionWindowDuration = await authorizationSession.executionAuthorizationWindowDuration()
            let summary = approvalSummary(
                descriptor: descriptor,
                metadata: metadata,
                decision: decision,
                executionWindowDuration: executionWindowDuration,
                hostKeyReview: hostKeyReview
            )
            await emitAudit(
                action: "本机授权请求",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "请求中",
                operation: .authorization,
                authorizationOutcome: .requested,
                status: .requested
            )
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }
            let authenticationContext = try await Self.approveWithTimeout(
                approver: operationApprover,
                timeout: operationApprovalTimeout,
                summary: summary
            )
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }
            guard await approvalTicketStore.consume(ticket, for: descriptor, now: now()) else {
                throw SecretOperationError.invalidOperationParameters
            }
            guard generation == securityGeneration else {
                throw OperationAuthorizationError.cancelled
            }

            await emitAudit(
                action: "本机授权完成",
                target: decision.normalizedDestination ?? "local",
                referenceCount: descriptor.secretReferences.count,
                result: "成功",
                operation: .authorization,
                authorizationOutcome: .approved,
                authorizationMode: .freshLocalApproval
            )
            return authenticationContext
        } catch {
            let mappedError = mappedSecretOperationError(error)
            switch mappedError {
            case .authorizationCancelled:
                await emitAudit(
                    action: "本机授权取消",
                    target: decision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "已取消",
                    operation: .authorization,
                    authorizationOutcome: .cancelled,
                    status: .cancelled
                )
            case .authorizationTimeout:
                await emitAudit(
                    action: "本机授权超时",
                    target: decision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "已超时",
                    operation: .authorization,
                    authorizationOutcome: .expired,
                    status: .expired
                )
            case .authorizationDenied:
                await emitAudit(
                    action: "本机授权拒绝",
                    target: decision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "已拒绝",
                    operation: .authorization,
                    authorizationOutcome: .denied,
                    status: .failure
                )
            case .authorizationUnavailable:
                await emitAudit(
                    action: "本机授权不可用",
                    target: decision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "失败",
                    operation: .authorization,
                    authorizationOutcome: .denied,
                    status: .failure
                )
            case .operationDenied, .actionExecutorUnavailable, .actionExecutionFailed,
                 .invalidOperationParameters, .sessionNotFound, .sessionExpired,
                 .sessionScopeMismatch, .sessionControlUnavailable, .sessionLimitReached,
                 .batchValidationFailed, .redirectRequiresReview, .outputQuarantined,
                 .insecureTransportDenied:
                await emitAudit(
                    action: "本机授权失败",
                    target: decision.normalizedDestination ?? "local",
                    referenceCount: descriptor.secretReferences.count,
                    result: "失败",
                    operation: .authorization,
                    authorizationOutcome: .denied,
                    status: .failure
                )
            }
            throw mappedError
        }
    }

    private func scopedAuthorizationScope(
        for descriptor: SecretOperationDescriptor,
        generation: UInt64
    ) -> ExecutionAuthorizationScope {
        let destination: String?
        let port: Int?
        let username: String?
        let protocolType: String?
        if descriptor.actionType == .exportPlaintext {
            // The export root is the validated security boundary. The leaf
            // file name intentionally stays out of the scope so distinct new
            // files within the same root can reuse the same authorization.
            destination = exportCoordinator.authorizationDestination
            port = nil
            username = nil
            protocolType = SecretOperationProtocol.file.rawValue
        } else {
            destination = descriptor.normalizedDestination
            port = descriptor.port
            username = descriptor.actionType == .sshCommand ? descriptor.parameters["username"] : nil
            protocolType = descriptor.protocolType?.rawValue
        }
        // §80: the ordinary lease is a scope grant, not an exact-operation
        // grant. Database statements use the policy engine's narrower
        // operation family: read-only statements can share a read workflow,
        // while ordinary writes and maintenance operations cannot borrow the
        // generic database scope. Fresh/unknown SQL never reaches this path;
        // fixed dangerous rules are re-checked by policy on every request.
        let actionFamily = descriptor.actionType == .databaseQuery
            ? operationPolicyEngine.databaseAuthorizationScopeFamily(for: descriptor.effectiveDatabaseStatement)
            : descriptor.actionType.rawValue
        return ExecutionAuthorizationScope(
            principal: AuditContext.current?.principal ?? AuditSource.agent.rawValue,
            secretReferenceIDs: descriptor.secretReferences.map(\.description),
            normalizedDestination: destination,
            port: port,
            username: username,
            protocolType: protocolType,
            actionFamily: actionFamily,
            operationFingerprint: nil,
            generation: generation
        )
    }

    private func finishExecutionApprovalFlight(
        scope: ExecutionAuthorizationScope,
        approvalID: UUID,
        generation: UInt64
    ) async {
        if await secretOperationService.finishExecutionApprovalFlight(
            scope: scope,
            approvalID: approvalID,
            generation: generation
        ) {
            await statusObserver?(status())
        }
    }

    private func markExecutionApprovalCompleted(_ approvalID: UUID) async {
        guard await secretOperationService.finishApproval(id: approvalID) else {
            return
        }
        await statusObserver?(status())
    }

    private func commitExecutionAuthorization(
        scope: ExecutionAuthorizationScope,
        generation: UInt64,
        masterKey: SymmetricKey
    ) async throws -> ExecutionAuthorizationCommit {
        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(scope: scope) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard let flight = await secretOperationService.executionApprovalFlight(for: scope),
              flight.generation == generation
        else {
            return .needsFreshApproval
        }

        do {
            _ = try await flight.task.value
        } catch {
            await finishExecutionApprovalFlight(
                scope: scope,
                approvalID: flight.id,
                generation: flight.generation
            )
            throw mappedSecretOperationError(error)
        }

        guard generation == securityGeneration else {
            throw SecretOperationError.authorizationCancelled
        }

        if await authorizationSession.hasActiveExecutionAuthorization(for: scope) {
            guard await scopedMasterKeyCoordinator.hasAuthorization(for: scope) else {
                await authorizationSession.invalidateExecutionAuthorization(for: scope)
                return .needsFreshApproval
            }
            if await secretOperationService.removeExecutionApprovalFlight(
                scope: scope,
                matching: flight.id
            ) {
                await statusObserver?(status())
            }
            return .leaseReused
        }

        guard await secretOperationService.executionApprovalFlight(for: scope)?.id == flight.id else {
            return .needsFreshApproval
        }

        let expiresAt = await authorizationSession.authorizeExecution(for: scope)
        guard generation == securityGeneration else {
            await authorizationSession.invalidateExecutionAuthorization(for: scope)
            throw SecretOperationError.authorizationCancelled
        }

        let executionWindowDuration: TimeInterval?
        if expiresAt == nil {
            executionWindowDuration = nil
        } else {
            executionWindowDuration = await authorizationSession.executionAuthorizationWindowDuration()
        }
        await scopedMasterKeyCoordinator.storeAuthorizedKey(
            masterKey,
            for: scope,
            duration: executionWindowDuration
        )

        if await secretOperationService.removeExecutionApprovalFlight(
            scope: scope,
            matching: flight.id
        ) {
            await statusObserver?(status())
        }
        return expiresAt == nil ? .approvedWithoutLease : .leaseEstablished
    }

    private func abandonExecutionAuthorization(
        scope: ExecutionAuthorizationScope?
    ) async {
        guard let scope else {
            return
        }
        if await secretOperationService.removeExecutionApprovalFlight(
            scope: scope,
            cancelTask: true
        ) {
            await statusObserver?(status())
        }
        await scopedMasterKeyCoordinator.abandon(scope: scope)
    }

    private func emitExecutionWindowReuseAudit(
        descriptor: SecretOperationDescriptor,
        decision: PolicyDecision
    ) async {
        await emitAudit(
            action: "执行授权窗口复用",
            target: decision.normalizedDestination ?? "local",
            referenceCount: descriptor.secretReferences.count,
            result: "继续",
            operation: .authorization,
            authorizationOutcome: .approved,
            authorizationMode: .executionWindowReuse,
            status: .completed
        )
    }

    private func mappedSecretOperationError(_ error: Error) -> SecretOperationError {
        if let error = error as? SecretOperationError {
            return error
        }
        if let error = error as? OperationAuthorizationError {
            switch error {
            case .cancelled:
                return .authorizationCancelled
            case .denied:
                return .authorizationDenied
            case .timeout:
                return .authorizationTimeout
            case .unavailable:
                return .authorizationUnavailable
            }
        }
        if error is CancellationError {
            return .authorizationCancelled
        }
        return .authorizationDenied
    }

    private func policyDecisionError(for decision: PolicyDecision) -> SecretOperationError {
        switch decision.policyRuleID {
        case "http.insecure-profile.denied":
            return .insecureTransportDenied
        default:
            return .invalidOperationParameters
        }
    }

    private func mapExecutionError(_ error: SecretOperationExecutionError) -> SecretOperationError {
        switch error {
        case .invalidParameter:
            return .invalidOperationParameters
        case .batchValidationFailed:
            return .batchValidationFailed
        case .sessionNotFound:
            return .sessionNotFound
        case .sessionExpired:
            return .sessionExpired
        case .sessionScopeMismatch:
            return .sessionScopeMismatch
        case .sessionControlUnavailable:
            return .sessionControlUnavailable
        case .sessionLimitReached:
            return .sessionLimitReached
        case .outputQuarantined, .outputLimitExceeded:
            return .outputQuarantined
        case .redirectRequiresReview:
            return .redirectRequiresReview
        case .insecureTransportDenied:
            return .insecureTransportDenied
        case .unavailable, .unsupportedAction, .missingSecretReference,
             .invalidSecretUTF8, .timedOut, .processFailed:
            return .actionExecutionFailed
        }
    }

    private func currentExecutionContext() -> SecretOperationExecutionContext {
        SecretOperationExecutionContext(
            principal: AuditContext.current?.principal ?? AuditSource.agent.rawValue,
            securityGeneration: securityGeneration
        )
    }

    func approveWithTimeout(summary: String) async throws -> LocalAuthenticationContext? {
        try await Self.approveWithTimeout(
            approver: operationApprover,
            timeout: operationApprovalTimeout,
            summary: summary
        )
    }

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

    func authorizeCatalogDiff(
        _ diff: CatalogSemanticDiff,
        transport: CatalogMutationKind,
        requireAgentSafeWrite: Bool = true,
        requestedEffect: String = "catalog-semantic-approval"
    ) async throws {
        let catalogDecision = catalogMutationPolicyEngine.evaluate(diff, transport: transport)
        switch catalogDecision {
        case .denied:
            throw SecretOperationError.invalidOperationParameters
        case .silent:
            if requireAgentSafeWrite {
                // A caller that still asks for the removed global gate is a
                // legacy path. It must not silently inherit an approved
                // ticket; every Agent mutation is authorized above with an
                // exact intent.
                throw SecretCatalogAgentError.agentWriteNotAllowed
            }
        case .approvalRequired:
            let references: [SecretReference]
            do {
                references = try diff.referencedSecretRefs.map(SecretReference.init)
            } catch {
                throw SecretCatalogAgentError.invalidOperation
            }

            let descriptor: SecretOperationDescriptor
            let metadata: [SecretPolicyMetadata]
            if references.isEmpty {
                descriptor = SecretOperationDescriptor(
                    actionType: .changeAuthorizationRules,
                    requestedEffects: [requestedEffect]
                )
                metadata = []
            } else {
                do {
                    metadata = try await policyMetadata(for: references)
                } catch {
                    throw SecretCatalogAgentError.invalidOperation
                }
                descriptor = SecretOperationDescriptor(
                    actionType: diff.changesSecretTarget ? .changeDestinationBinding : .changeSecretPolicy,
                    secretReferences: references,
                    requestedEffects: [requestedEffect]
                )
            }
            let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
            try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)
        }
    }

    func approvalSummary(
        descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        decision: PolicyDecision,
        executionWindowDuration: TimeInterval? = nil,
        hostKeyReview: SSHHostKeyReview? = nil
    ) -> String {
        let labels = metadata.compactMap(\.label)
            .map(safeDisplayLabel)
            .filter { !$0.isEmpty }
        let labelText = labels.isEmpty ? "未命名凭据" : labels.prefix(3).joined(separator: "、")
        let target = safeDisplayLabel(decision.normalizedDestination ?? "本机")
        // The device owner must see the actual command: raw single-line and
        // multi-line commands are shown in full with newlines preserved, and
        // the policy's risk reasons (including the agent's own warning) are
        // part of the prompt. The final decision belongs to the owner.
        let rawDetail = operationDetail(for: descriptor)
        let detail: String
        switch descriptor.actionType {
        case .sshCommand:
            detail = displayCommandText(rawDetail, maxBytes: 65_536)
        default:
            detail = safeDisplayLabel(rawDetail)
        }
        let riskText = decision.reasons
            .map { safeDisplayLabel($0) }
            .filter { !$0.isEmpty }
            .prefix(3)
            .joined(separator: "；")
        let riskSection = riskText.isEmpty ? "" : "；风险：\(riskText)"
        let batchRequirement = descriptor.sshCommandBatch != nil
            ? "；批处理最高授权级别：\(authorizationRequirementDisplay(decision.authorizationRequirement))"
            : ""
        let hostKeySection: String
        if let hostKeyReview {
            let requestedPin: SSHHostKeyPin? = {
                guard let algorithm = descriptor.parameters["hostKeyAlgorithm"],
                      let sha256 = descriptor.parameters["hostKeySHA256"] else {
                    return nil
                }
                return try? SSHHostKeyPin(algorithm: algorithm, sha256: sha256)
            }()
            let fingerprints = hostKeyReview.pins.map {
                let selection = requestedPin == $0 ? "（待固定）" : ""
                return "\(safeDisplayLabel($0.algorithm)) \(safeDisplayLabel($0.sha256))\(selection)"
            }.joined(separator: "、")
            hostKeySection = "；待审核 SSH 主机身份：\(safeDisplayLabel(hostKeyReview.host)):\(hostKeyReview.port)；算法/指纹：\(fingerprints)"
        } else {
            hostKeySection = ""
        }
        let base = "SVLT 请求本机审批：\(displayName(for: descriptor))；操作：\(detail)；目标：\(target)；凭据：\(labelText)\(riskSection)\(batchRequirement)\(hostKeySection)"
        guard let executionWindowDuration else {
            return base
        }
        let seconds = executionWindowDuration.formatted(.number.precision(.fractionLength(0...3)))
        return "\(base)；本次审批可在同一调用主体、同一凭据、同一目标、同一端口、同一协议及执行类型下复用最多 \(seconds) 秒；不会授权其他凭据、目标或协议"
    }

    private func displayName(for descriptor: SecretOperationDescriptor) -> String {
        if descriptor.requestedEffects.contains("catalog-replace-secret") {
            return "替换目录密码"
        }
        if descriptor.requestedEffects.contains("pin-ssh-host-key") {
            return "固定 SSH 主机指纹"
        }
        return displayName(for: descriptor.actionType)
    }

    func operationDetail(for descriptor: SecretOperationDescriptor) -> String {
        switch descriptor.actionType {
        case .sshCommand:
            if let batch = descriptor.sshCommandBatch {
                return sshBatchOperationDetail(batch)
            }
            return descriptor.command ?? "未提供命令"
        case .httpRequest, .apiRequest, .browserLogin:
            let method = (descriptor.effectiveHTTPMethod ?? "GET").uppercased()
            return "\(method) \(descriptor.normalizedPath ?? "/")"
        case .changeDestinationBinding:
            let protocolName = descriptor.protocolType?.rawValue.uppercased() ?? "未知协议"
            let pinDetail = descriptor.requestedEffects.contains("pin-ssh-host-key")
                ? "（请求固定主机指纹）"
                : ""
            return "\(protocolName) \(descriptor.destination ?? "未指定目标")\(pinDetail)"
        case .databaseQuery:
            guard let statement = descriptor.effectiveDatabaseStatement else {
                return "数据库查询"
            }
            return displayCommandText(statement.trimmingCharacters(in: .whitespacesAndNewlines), maxBytes: 65_536)
        case .sftpTransfer:
            return "\(descriptor.effectiveFileOperation?.rawValue ?? "transfer") \(descriptor.fileTarget ?? "远程目标")"
        case .ftpTransfer:
            return "\(descriptor.effectiveFileOperation?.rawValue ?? "transfer") \(descriptor.fileTarget ?? "远程目标")"
        case .localAppFill:
            return descriptor.localAppBundleID ?? "本地 App 表单"
        default:
            return "受保护操作"
        }
    }

    private func sshBatchOperationDetail(_ batch: SSHCommandBatch) -> String {
        // Every batch command is shown: the owner approves the exact batch,
        // so nothing is summarized away.
        let commandDetails = batch.commands.enumerated().map { offset, command in
            let executable = displayCommandText(command.executable, maxBytes: 4_096)
            let arguments = command.arguments.map {
                "「\(displayCommandText($0, maxBytes: 4_096))」"
            }.joined(separator: " ")
            return "\(offset + 1). \(executable)\(arguments.isEmpty ? "" : " \(arguments)")"
        }
        return displayCommandText(
            "SSH 批处理（\(batch.commands.count) 条）：\(commandDetails.joined(separator: "；"))",
            maxBytes: 65_536
        )
    }

    private func displayName(for action: SecretOperationAction) -> String {
        switch action {
        case .revealPlaintext:
            return "显示明文"
        case .copyPlaintext:
            return "本机写回明文"
        case .exportPlaintext:
            return "导出明文"
        case .deleteSecret:
            return "删除加密记录"
        case .changeDestinationBinding:
            return "绑定凭据地址"
        case .changeSecretPolicy, .changeAllowlist,
             .changeAuthorizationRules, .changeKeychain:
            return "修改安全设置"
        case .sshCommand:
            return "执行 SSH 操作"
        case .httpRequest, .apiRequest:
            return "发送 HTTP/API 请求"
        case .databaseQuery:
            return "执行数据库操作"
        case .sftpTransfer:
            return "执行 SFTP 操作"
        case .ftpTransfer:
            return "执行 FTP 操作"
        default:
            return "执行受保护操作"
        }
    }

    private func sanitizedDisplayText(_ value: String) -> String {
        value.unicodeScalars.map { scalar -> String in
            if scalar.value < 0x20 || scalar.value == 0x7F {
                return " "
            }
            return String(scalar)
        }.joined()
    }

    func safeDisplayLabel(_ value: String) -> String {
        String(sanitizedDisplayText(value).prefix(80))
    }

    private func isInsecureSecretHTTPTarget(_ descriptor: SecretOperationDescriptor) -> Bool {
        guard !descriptor.secretReferences.isEmpty,
              let rawURL = descriptor.url,
              let url = URL(string: rawURL) else {
            return false
        }
        return url.scheme?.lowercased() == "http"
    }

    /// Display text for commands: preserves newlines and tabs so multi-line
    /// commands stay readable in the approval prompt, strips other control
    /// characters, and bounds the total by UTF-8 bytes.
    private func displayCommandText(_ value: String, maxBytes: Int) -> String {
        let sanitized = String(String.UnicodeScalarView(value.unicodeScalars.compactMap { scalar -> UnicodeScalar? in
            if scalar == "\n" || scalar == "\t" {
                return scalar
            }
            if scalar.value < 0x20 || scalar.value == 0x7F {
                return nil
            }
            return scalar
        }))
        let data = Data(sanitized.utf8)
        guard data.count > maxBytes else { return sanitized }
        guard maxBytes > 3 else {
            return String(decoding: data.prefix(maxBytes), as: UTF8.self)
        }
        return String(decoding: data.prefix(maxBytes - 3), as: UTF8.self) + "…"
    }

    private func authorizationRequirementDisplay(_ requirement: AuthorizationRequirement) -> String {
        switch requirement {
        case .none:
            return "无需额外认证"
        case .reusableApproval:
            return "可复用审批"
        case .freshApprovalRequired:
            return "必须重新本机认证"
        case .denied:
            return "拒绝"
        }
    }

    private func operationReason(for descriptor: SecretOperationDescriptor) -> String {
        switch descriptor.actionType {
        case .sshCommand:
            return "智能体 SSH 操作"
        case .httpRequest, .apiRequest:
            return "智能体 HTTP/API 操作"
        case .databaseQuery:
            return "智能体数据库操作"
        case .sftpTransfer:
            return "智能体 SFTP 操作"
        case .ftpTransfer:
            return "智能体 FTP 操作"
        case .changeDestinationBinding:
            return descriptor.requestedEffects.contains("pin-ssh-host-key")
                ? "智能体固定 SSH 主机指纹"
                : "智能体绑定凭据地址"
        default:
            return "智能体受保护操作"
        }
    }

    func resolveReferences(
        references: [String],
        context: RevealContext,
        forceFreshAuthorization: Bool = false,
        authenticationContext: LocalAuthenticationContext? = nil
    ) async throws -> String {
        try await resolveReferencesWithValues(
            references: references,
            context: context,
            forceFreshAuthorization: forceFreshAuthorization,
            authenticationContext: authenticationContext
        ).text
    }

    private func resolveReferencesWithValues(
        references: [String],
        context: RevealContext,
        forceFreshAuthorization: Bool = false,
        authenticationContext: LocalAuthenticationContext? = nil,
        masterKeyOverride: SymmetricKey? = nil
    ) async throws -> RestoredParagraph {
        guard !references.isEmpty else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        let validatedReferences: [String]
        do {
            validatedReferences = try references.map { try SecretReference($0).description }
        } catch {
            throw VaultAppServicesRevealError.invalidReference
        }
        guard Set(validatedReferences).count == validatedReferences.count else {
            throw VaultAppServicesRevealError.invalidReference
        }

        try validateRevealContext(context, referenceCount: validatedReferences.count)

        guard let recordResolver else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        var metadata: [SecretReferenceMetadata] = []
        metadata.reserveCapacity(validatedReferences.count)
        for reference in validatedReferences {
            metadata.append(try await recordResolver.metadata(reference: reference))
        }
        let operationMasterKey: SymmetricKey
        if let masterKeyOverride {
            operationMasterKey = masterKeyOverride
        } else {
            let operationPolicy = authorizationPolicy(for: metadata.map(\.policy))
            operationMasterKey = try await resolvedMasterKey(
                for: operationPolicy,
                reason: context.reason,
                allowsAgentDecryptReuse: !forceFreshAuthorization,
                destination: context.destination,
                authenticationContext: authenticationContext,
                forceFresh: forceFreshAuthorization
            )
        }

        var plaintexts: [String] = []
        plaintexts.reserveCapacity(validatedReferences.count)
        for reference in validatedReferences {
            let data = try await recordResolver.resolve(reference: reference, masterKey: operationMasterKey)
            guard let plaintext = String(data: data, encoding: .utf8) else {
                throw VaultAppServicesRevealError.invalidResolvedPlaintext
            }
            plaintexts.append(plaintext)
        }

        return RestoredParagraph(
            text: try resolveTemplate(context.template, ranges: context.ranges, plaintexts: plaintexts),
            values: plaintexts
        )
    }

    private func authorizationPolicy(for policies: [SecretPolicy]) -> SecretPolicy {
        if policies.contains(.credential) {
            return .credential
        }
        if policies.contains(.externalSend) {
            return .externalSend
        }
        return .read
    }

    private func resolvedMasterKey(
        for policy: SecretPolicy,
        reason: String,
        allowsAgentDecryptReuse: Bool = false,
        destination: String? = nil,
        authenticationContext: LocalAuthenticationContext? = nil,
        forceFresh: Bool = false
    ) async throws -> SymmetricKey {
        if let masterKey {
            return masterKey
        }

        if allowsAgentDecryptReuse,
           !forceFresh,
           let cacheKey = authorizationCacheKey(policy: policy, destination: destination),
           let cached = cachedAgentDecryptAuthorization(cacheKey: cacheKey),
           await consumeCachedAuthorization(policy: policy, destination: destination) {
            return cached.key
        }

        let key: SymmetricKey
        if forceFresh {
            if let freshMasterKeyProviderWithAuthenticationContext {
                key = try await freshMasterKeyProviderWithAuthenticationContext(
                    policy,
                    reason,
                    authenticationContext
                )
            } else if let freshMasterKeyProvider {
                key = try await freshMasterKeyProvider(policy, reason)
            } else if let masterKeyProviderWithAuthenticationContext {
                key = try await masterKeyProviderWithAuthenticationContext(
                    policy,
                    reason,
                    authenticationContext
                )
            } else if let masterKeyProvider {
                key = try await masterKeyProvider(policy, reason)
            } else {
                throw VaultAppServicesRevealError.revealUnavailable
            }
        } else if let masterKeyProviderWithAuthenticationContext {
            key = try await masterKeyProviderWithAuthenticationContext(
                policy,
                reason,
                authenticationContext
            )
        } else if let masterKeyProvider {
            key = try await masterKeyProvider(policy, reason)
        } else {
            throw VaultAppServicesRevealError.revealUnavailable
        }

        if allowsAgentDecryptReuse,
           !forceFresh,
           let cacheKey = authorizationCacheKey(policy: policy, destination: destination) {
            await authorizeCachedOperation(policy: policy, destination: destination)
            cacheAgentDecryptAuthorization(
                key: key,
                policy: policy,
                destination: destination,
                cacheKey: cacheKey
            )
        }
        return key
    }

    /// Scoped Agent operations may reuse only the key material captured when
    /// that exact scope acquired device-owner authorization. Falling back to
    /// the broader credential cache here would let its independent TTL extend
    /// an Agent authorization lease.
    private func masterKeyForScopedAuthorization(
        scope: ExecutionAuthorizationScope?,
        for policy: SecretPolicy,
        reason: String,
        destination: String?,
        authenticationContext: LocalAuthenticationContext?,
        forceFreshWhenUnscoped: Bool
    ) async throws -> SymmetricKey {
        guard let scope else {
            return try await resolvedMasterKey(
                for: policy,
                reason: reason,
                allowsAgentDecryptReuse: false,
                destination: destination,
                authenticationContext: authenticationContext,
                forceFresh: forceFreshWhenUnscoped
            )
        }

        let authorizationSession = self.authorizationSession
        let masterKey = self.masterKey
        let masterKeyProvider = self.masterKeyProvider
        let freshMasterKeyProvider = self.freshMasterKeyProvider
        let masterKeyProviderWithAuthenticationContext = self.masterKeyProviderWithAuthenticationContext
        let freshMasterKeyProviderWithAuthenticationContext = self.freshMasterKeyProviderWithAuthenticationContext
        return try await scopedMasterKeyCoordinator.resolveKey(
            for: scope,
            isLeaseActive: {
                await authorizationSession.hasActiveExecutionAuthorization(for: scope)
            },
            load: {
                if let masterKey {
                    return masterKey
                }
                if let freshMasterKeyProviderWithAuthenticationContext {
                    return try await freshMasterKeyProviderWithAuthenticationContext(
                        policy,
                        reason,
                        authenticationContext
                    )
                }
                if let freshMasterKeyProvider {
                    return try await freshMasterKeyProvider(policy, reason)
                }
                if let masterKeyProviderWithAuthenticationContext {
                    return try await masterKeyProviderWithAuthenticationContext(
                        policy,
                        reason,
                        authenticationContext
                    )
                }
                guard let masterKeyProvider else {
                    throw VaultAppServicesRevealError.revealUnavailable
                }
                return try await masterKeyProvider(policy, reason)
            }
        )
    }

    private func freshMasterKey(
        for policy: SecretPolicy,
        reason: String
    ) async throws -> SymmetricKey {
        if let masterKey {
            return masterKey
        }
        if let freshMasterKeyProvider {
            return try await freshMasterKeyProvider(policy, reason)
        }
        guard let masterKeyProvider else {
            throw VaultAppServicesRevealError.revealUnavailable
        }
        return try await masterKeyProvider(policy, reason)
    }

    private func authorizationCacheKey(
        policy: SecretPolicy,
        destination: String?
    ) -> String? {
        switch policy {
        case .read:
            return "read"
        case .credential:
            return "credential"
        case .externalSend:
            guard let destination, !destination.isEmpty else {
                return nil
            }
            return "externalSend:\(destination)"
        }
    }

    private func consumeCachedAuthorization(
        policy: SecretPolicy,
        destination: String?
    ) async -> Bool {
        switch policy {
        case .read:
            return await authorizationSession.consumeAuthorization(for: .read)
        case .credential:
            return await authorizationSession.consumeCredential()
        case .externalSend:
            guard let destination else {
                return false
            }
            return await authorizationSession.consumeExternalSend(destination: destination)
        }
    }

    private func authorizeCachedOperation(
        policy: SecretPolicy,
        destination: String?
    ) async {
        switch policy {
        case .read:
            await authorizationSession.authorizeRead()
        case .credential:
            await authorizationSession.authorizeCredential()
        case .externalSend:
            if let destination {
                await authorizationSession.authorizeExternalSend(destination: destination)
            }
        }
    }

    private func cachedAgentDecryptAuthorization(cacheKey: String) -> AgentDecryptAuthorization? {
        guard let authorization = agentDecryptAuthorizations[cacheKey] else {
            return nil
        }
        guard now() < authorization.expiresAt else {
            agentDecryptAuthorizations[cacheKey] = nil
            return nil
        }
        return authorization
    }

    private func cacheAgentDecryptAuthorization(
        key: SymmetricKey,
        policy: SecretPolicy,
        destination: String?,
        cacheKey: String
    ) {
        let expiresAt: Date
        switch policy {
        case .read:
            expiresAt = agentDecryptAuthorizationTTL.map {
                now().addingTimeInterval($0)
            } ?? .distantFuture
        case .credential:
            guard credentialAuthorizationTTL > 0 else {
                agentDecryptAuthorizations[cacheKey] = nil
                return
            }
            expiresAt = now().addingTimeInterval(credentialAuthorizationTTL)
        case .externalSend:
            guard externalSendAuthorizationTTL > 0 else {
                agentDecryptAuthorizations[cacheKey] = nil
                return
            }
            expiresAt = now().addingTimeInterval(externalSendAuthorizationTTL)
        }
        agentDecryptAuthorizations[cacheKey] = AgentDecryptAuthorization(
            key: key,
            policy: policy,
            destination: destination,
            expiresAt: expiresAt
        )
    }

    private func isPluginConnected() -> Bool {
        guard let pluginConnectedAt else {
            return false
        }
        return now().timeIntervalSince(pluginConnectedAt) < 15
    }

    func notifySavedReferencesChanged() async {
        guard let savedReferencesObserver,
              let references = try? await savedSecretReferences()
        else {
            return
        }
        await savedReferencesObserver(references)
    }

    public func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        guard let recordLister else {
            throw VaultAppServicesOrphanScanError.scanUnavailable
        }

        let markdownReferenceSet = Set(markdownReferences.compactMap(Self.canonicalReference))
        let storedReferenceSet = Set(try await recordLister.recordIDs().map { "secret://\($0)" })

        let result = OrphanScanResult(
            missingRecords: Array(markdownReferenceSet.subtracting(storedReferenceSet)).sorted(),
            unreferencedRecords: Array(storedReferenceSet.subtracting(markdownReferenceSet)).sorted()
        )
        await orphanScanObserver?(result)
        await emitAudit(
            action: "扫描知识库引用",
            target: "当前知识库",
            referenceCount: markdownReferenceSet.count,
            result: "成功"
        )
        return result
    }

    /// Retries durable compensation entries. The returned IDs are still
    /// unresolved and remain persisted for a later run; no secret value is
    /// loaded or included in the result.
    public func reconcilePendingCatalogSecretCleanup() async throws -> [String] {
        try await withCatalogOperation { operation in
        let pending = try await operation.pendingSecretCleanupReferenceIDs()
        guard !pending.isEmpty else { return [] }

        // Cleanup metadata is authenticated, but it is still only a recovery
        // hint. Re-read the current accepted Catalog before every deletion
        // pass and refuse to delete a record that has since become referenced.
        // A pending external change makes the accepted state unavailable, so
        // snapshot() fails closed and no deletion is attempted.
        let current = try await operation.snapshot()
        let referencedIDs = Set(current.document.entries.flatMap { entry in
            entry.fields.compactMap { field in
                field.secretRef.flatMap { try? SecretReference($0).id }
            }
        })
        let referencedPending = pending.filter { referencedIDs.contains($0) }
        var orphanPending = pending.filter { !referencedIDs.contains($0) }
        var resolved = referencedPending

        guard let recordDeleter else {
            if !resolved.isEmpty {
                try await operation.clearPendingSecretCleanup(referenceIDs: resolved)
            }
            return orphanPending
        }

        var remaining: [String] = []
        for id in orphanPending {
            do {
                try await recordDeleter.delete(id: id)
                resolved.append(id)
            } catch {
                remaining.append(id)
            }
        }
        if !resolved.isEmpty {
            try await operation.clearPendingSecretCleanup(referenceIDs: resolved)
        }
        await notifySavedReferencesChanged()
        orphanPending = remaining
        return orphanPending
        }
    }

    private static func canonicalReference(_ reference: String) -> String? {
        try? SecretReference(reference).description
    }

    func emitAudit(
        action: String,
        target: String,
        referenceCount: Int,
        result: String,
        context: AuditContext? = nil,
        operation: AuditOperation? = nil,
        authorizationOutcome: AuditAuthorizationOutcome = .notRequired,
        authorizationMode: AuditAuthorizationMode? = nil,
        status: AuditStatus? = nil
    ) async {
        let auditContext = context ?? AuditContext.current
        let entry = AgentAutomationAuditEntry(
            action: action,
            target: target,
            referenceCount: referenceCount,
            result: result,
            authorizationMode: authorizationMode,
            caller: auditContext?.caller
        )
        await auditObserver?(entry)
        // A production request always arrives through one of the two IPC
        // handlers, which installs AuditContext.current. Do not infer `.agent`
        // here: an unscoped event cannot be safely attributed to a caller.
        guard let auditContext else { return }
        await auditPersistenceCoordinator.append(
            entry: entry,
            context: auditContext,
            operation: operation,
            authorizationOutcome: authorizationOutcome,
            authorizationMode: authorizationMode,
            status: status
        )
    }

    private func emitCatalogWriteAccessAudit(_ event: CatalogWriteAccessAuditEvent) async {
        await emitAudit(
            action: event.action,
            target: "catalog-write",
            referenceCount: 0,
            result: event.result,
            context: event.context,
            operation: .authorization,
            authorizationOutcome: event.authorizationOutcome,
            status: event.status
        )
    }

    func persistSecureInputReceipts() {
        do {
            try secureInputReceiptStore.persist(
                secureInputLifecycle.receiptRecords(now: now())
            )
        } catch {
            Logger(subsystem: "com.agent-secret-vault.SVLT", category: "secure-input")
                .error("SECURE_INPUT_RECEIPT_PERSIST_FAILED")
        }
    }

    func agentAuditContext() -> AuditContext {
        AuditContext.current ?? AuditContext(source: .agent)
    }

    private func appAuditContext() -> AuditContext {
        AuditContext.current ?? AuditContext(source: .app)
    }

    func emitCatalogMutationStarted(
        action: String,
        referenceCount: Int,
        context: AuditContext
    ) async {
        await emitAudit(
            action: action,
            target: "catalog",
            referenceCount: referenceCount,
            result: "开始",
            context: context,
            operation: .catalogMutation,
            authorizationOutcome: context.requestID == nil ? .notRequired : .approved,
            status: .requested
        )
    }

    func emitCatalogMutationFailed(
        action: String,
        referenceCount: Int,
        context: AuditContext
    ) async {
        await emitAudit(
            action: action,
            target: "catalog",
            referenceCount: referenceCount,
            result: "失败",
            context: context,
            operation: .catalogMutation,
            authorizationOutcome: context.requestID == nil ? .notRequired : .approved,
            status: .failure
        )
    }

    func withCatalogOperation<T>(
        _ body: (CatalogDocumentOperation) async throws -> T
    ) async throws -> T {
        let operation = try await beginCatalogOperation()
        do {
            let result = try await body(operation)
            await endCatalogOperation(operation)
            return result
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    func beginCatalogOperation() async throws -> CatalogDocumentOperation {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        return try await catalogDocumentOwner.beginOperation()
    }

    func beginCatalogOperation(documentPath: String) async throws -> CatalogDocumentOperation {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        return try await catalogDocumentOwner.beginOperation(documentPath: documentPath)
    }

    func endCatalogOperation(_ operation: CatalogDocumentOperation) async {
        await operation.end()
    }

    /// Keep App-control errors stable so the UI can distinguish a stale
    /// revision from an invalid document and retry only the safe case.
    func catalogAgentError(
        for error: SensitiveCatalogDocumentStoreError
    ) -> SecretCatalogAgentError {
        switch error {
        case .noSelectedDocument:
            return .unavailable
        case .legacyCatalogUnsupported:
            return .legacyCatalogUnsupported
        case .integrityMissing:
            return .integrityMissing
        case .externalModification:
            return .externalModification
        case .pendingExternalChange:
            return .pendingExternalChange
        case .revisionConflict:
            return .revisionConflict
        case .formatRepairConflict:
            return .formatRepairConflict
        case .invalidOperation:
            return .invalidOperation
        case .writeFailed, .recoveryRollbackBackupInvalid:
            return .writeFailed
        case .malformedDocument, .symlinkRejected, .invalidIntegrity,
             .referenceSetChanged:
            return .invalidCatalog
        }
    }

    /// Compensate records created before a Catalog commit. Deletion is
    /// attempted for every ID so a multi-secret transaction does not abandon
    /// the remaining records after the first failure. Any failure is made
    /// explicit to the caller and persisted as opaque cleanup metadata.
    func compensateCreatedReferences(
        _ references: [SecretReference],
        operation: CatalogDocumentOperation? = nil
    ) async -> SecretCatalogAgentError? {
        guard !references.isEmpty else { return nil }
        guard let recordDeleter else {
            guard let operation else { return .cleanupRequired }
            do {
                try await operation.recordPendingSecretCleanup(
                    referenceIDs: references.map(\.id)
                )
            } catch {
                return .cleanupRequired
            }
            return .cleanupRequired
        }

        var failedIDs: [String] = []
        for reference in references {
            do {
                try await recordDeleter.delete(id: reference.id)
            } catch {
                failedIDs.append(reference.id)
            }
        }
        guard !failedIDs.isEmpty else {
            await notifySavedReferencesChanged()
            return nil
        }

        // The cleanup record contains only opaque IDs. If its write itself
        // fails, the operation still reports cleanupRequired; the caller must
        // not mistake a best-effort compensation failure for a clean rollback.
        guard let operation else { return .cleanupRequired }
        do {
            try await operation.recordPendingSecretCleanup(referenceIDs: failedIDs)
        } catch {
            return .cleanupRequired
        }
        await notifySavedReferencesChanged()
        return .cleanupRequired
    }

    func catalogSnapshotForAgent() async throws -> SensitiveCatalogSnapshot {
        try await withCatalogOperation { operation in
            try await catalogSnapshotForAgent(using: operation)
        }
    }

    func catalogSnapshotForAgent(
        using operation: CatalogDocumentOperation
    ) async throws -> SensitiveCatalogSnapshot {
        do {
            let snapshot = try await operation.snapshot()
            guard snapshot.integrity == .verified else {
                throw SecretCatalogAgentError.unavailable
            }
            return snapshot
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .legacyCatalogUnsupported:
                throw SecretCatalogAgentError.legacyCatalogUnsupported
            case .integrityMissing:
                throw SecretCatalogAgentError.integrityMissing
            case .externalModification:
                throw SecretCatalogAgentError.externalModification
            case .pendingExternalChange:
                throw SecretCatalogAgentError.pendingExternalChange
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .formatRepairConflict:
                throw SecretCatalogAgentError.formatRepairConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .noSelectedDocument, .malformedDocument,
                 .invalidIntegrity, .symlinkRejected, .referenceSetChanged:
                throw SecretCatalogAgentError.invalidCatalog
            case .writeFailed, .recoveryRollbackBackupInvalid:
                throw SecretCatalogAgentError.writeFailed
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    /// Resolves the selected document through the same manifest and Store
    /// instance used by MCP mutations, then runs only the non-destructive file
    /// access probe. This deliberately does not use the App process or a test
    /// temporary directory as a permission substitute.
    func catalogFilePreflightForAgent() async throws -> CatalogFilePreflight {
        try await withCatalogOperation { operation in
            try await operation.preflightFileAccess()
        }
    }

    private func validateSafeCatalogMutation(_ kind: CatalogMutationKind) async throws {
        do {
            try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: kind))
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-mutation", phase: .policy, error: error)
            throw error
        }
        // The old global safe-write gate was intentionally removed. Callers
        // must use requestAgentCatalogAuthorization with a candidate digest.
    }

    static func logCatalogMutationFailure(
        operation: String,
        phase: CatalogMutationPhase,
        error: Error
    ) {
        // Only a fixed operation/phase and the error type are logged. Never
        // interpolate request values, paths, Markdown, secret references, or
        // plaintext into the local diagnostic stream.
        let errorType = String(reflecting: type(of: error))
        let errorCode = safeCatalogMutationErrorCode(error)
        catalogMutationLogger.error(
            "SVLT Catalog mutation failure: operation=\(operation, privacy: .public) phase=\(phase.rawValue, privacy: .public) error=\(errorType, privacy: .public) code=\(errorCode, privacy: .public)"
        )
    }

    private static func safeCatalogMutationErrorCode(_ error: Error) -> String {
        // These enums have no associated values. Their case names are fixed
        // diagnostic vocabulary and cannot contain request data, paths,
        // Markdown, secret references, or plaintext. Unknown errors remain
        // deliberately opaque.
        if let error = error as? SecretCatalogValidationError {
            return String(describing: error)
        }
        if let error = error as? SensitiveCatalogDocumentStoreError {
            return String(describing: error)
        }
        if let error = error as? SecretCatalogAgentError {
            return String(describing: error)
        }
        return "unknown"
    }

    private func validateCatalogPatchMutation(
        from oldEntry: SecretCatalogEntry,
        to newEntry: SecretCatalogEntry
    ) async throws {
        let hasSecretReference = oldEntry.fields.contains { $0.secretRef != nil }
        let changesTarget = oldEntry.endpoints != newEntry.endpoints && hasSecretReference
        let changesSecretSemantics = CatalogMutationCandidateBuilder.sensitiveChangeNeedsApproval(
            from: oldEntry,
            to: newEntry
        )
        let descriptor = CatalogMutationDescriptor(
            kind: changesSecretSemantics ? .changeSecretType : .patchMetadata,
            touchesExistingSecret: changesSecretSemantics,
            changesSecretTarget: changesTarget
        )
        try catalogMutationPolicyEngine.requireSilent(descriptor)
    }

    private func sanitizedReason(_ reason: String) -> String {
        // Reasons arrive from local MCP clients and are not trusted log data.
        // Keep only a stable category; never persist the caller's free-form
        // text, which could contain a secret despite redaction heuristics.
        let normalized = reason.lowercased()
        if normalized.contains("ssh") {
            return "local-ssh"
        }
        if normalized.contains("http") || normalized.contains("api") {
            return "local-api"
        }
        if normalized.contains("export") || normalized.contains("file") {
            return "local-file"
        }
        if normalized.contains("delete") || normalized.contains("删除") {
            return "record-delete"
        }
        return "local-operation"
    }

    private func resolveTemplate(_ template: String, ranges: [ReferenceRange], plaintexts: [String]) throws -> String {
        var replacements: [String: String] = [:]

        for range in ranges {
            guard plaintexts.indices.contains(range.index), !range.placeholder.isEmpty else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            guard replacements[range.placeholder] == nil else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
            replacements[range.placeholder] = plaintexts[range.index]
        }

        return replacePlaceholders(in: template, replacements: replacements)
    }

    private func validateRevealContext(_ context: RevealContext, referenceCount: Int) throws {
        guard context.ranges.count == referenceCount else {
            throw VaultAppServicesRevealError.invalidRevealContext
        }

        var seenIndices: Set<Int> = []
        var seenPlaceholders: Set<String> = []

        for range in context.ranges {
            guard 0..<referenceCount ~= range.index,
                  !range.placeholder.isEmpty,
                  seenIndices.insert(range.index).inserted,
                  seenPlaceholders.insert(range.placeholder).inserted
            else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }

            guard countOccurrences(of: range.placeholder, in: context.template) == 1 else {
                throw VaultAppServicesRevealError.invalidRevealContext
            }
        }

        let placeholders = Array(seenPlaceholders)
        for lhsIndex in placeholders.indices {
            for rhsIndex in placeholders.indices where lhsIndex != rhsIndex {
                guard !placeholders[lhsIndex].contains(placeholders[rhsIndex]) else {
                    throw VaultAppServicesRevealError.invalidRevealContext
                }
            }
        }
    }

    private func countOccurrences(of needle: String, in haystack: String) -> Int {
        var count = 0
        var searchRange = haystack.startIndex..<haystack.endIndex

        while let range = haystack.range(of: needle, range: searchRange) {
            count += 1
            searchRange = range.upperBound..<haystack.endIndex
        }

        return count
    }

    private func replacePlaceholders(in template: String, replacements: [String: String]) -> String {
        var result = ""
        var remaining = template[...]
        let placeholders = replacements.keys.sorted { lhs, rhs in
            if lhs.count == rhs.count {
                return lhs < rhs
            }
            return lhs.count > rhs.count
        }

        while !remaining.isEmpty {
            let nextMatch = placeholders.compactMap { placeholder -> (String, Range<String.Index>)? in
                guard let range = remaining.range(of: placeholder) else {
                    return nil
                }
                return (placeholder, range)
            }
            .min { lhs, rhs in
                if lhs.1.lowerBound == rhs.1.lowerBound {
                    return lhs.0.count > rhs.0.count
                }
                return lhs.1.lowerBound < rhs.1.lowerBound
            }

            guard let nextMatch else {
                result.append(contentsOf: remaining)
                break
            }

            result.append(contentsOf: remaining[..<nextMatch.1.lowerBound])
            result.append(replacements[nextMatch.0] ?? "")
            remaining = remaining[nextMatch.1.upperBound...]
        }

        return result
    }
}

public enum VaultAppServicesRevealError: Error, Equatable, Sendable {
    case invalidReference
    case sessionNotFound
    case invalidRevealContext
    case invalidResolvedPlaintext
    case revealUnavailable
}

private extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async throws -> [T] {
        var values: [T] = []
        values.reserveCapacity(underestimatedCount)
        for element in self {
            try await values.append(transform(element))
        }
        return values
    }
}

private extension SecretPolicy {
    var decryptAuthorizationRank: Int {
        switch self {
        case .read:
            return 0
        case .externalSend:
            return 1
        case .credential:
            return 2
        }
    }

    func canAuthorizeDecrypt(for requestedPolicy: SecretPolicy) -> Bool {
        decryptAuthorizationRank >= requestedPolicy.decryptAuthorizationRank
    }
}
