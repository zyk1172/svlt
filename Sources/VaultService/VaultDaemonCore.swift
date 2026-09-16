import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

public enum VaultDaemonCoreError: Error, Equatable, Sendable {
    case alreadyStarted
    case notStarted
}

public struct VaultDaemonConfiguration: Sendable, Equatable {
    public let vaultRootURL: URL
    public let auditRootURL: URL
    public let ipcConfiguration: UnixSocketServerConfiguration
    public let catalogSelectionURL: URL
    public let credentialAuthorizationTTL: TimeInterval
    public let externalSendAuthorizationTTL: TimeInterval
    public let readAuthorizationTTL: TimeInterval?
    /// App-owned, non-secret response projection profiles. An empty list is
    /// deliberately metadata-only; the daemon never invents an allowlist.
    public let httpResponseProjectionProfiles: [HTTPResponseProjectionProfile]

    public init(
        vaultRootURL: URL,
        auditRootURL: URL,
        ipcConfiguration: UnixSocketServerConfiguration,
        catalogSelectionURL: URL? = nil,
        credentialAuthorizationTTL: TimeInterval = 600,
        externalSendAuthorizationTTL: TimeInterval = 60,
        readAuthorizationTTL: TimeInterval? = nil,
        httpResponseProjectionProfiles: [HTTPResponseProjectionProfile] = []
    ) {
        let normalizedVaultRootURL = vaultRootURL.standardizedFileURL
        self.vaultRootURL = normalizedVaultRootURL
        self.auditRootURL = auditRootURL.standardizedFileURL
        self.ipcConfiguration = ipcConfiguration
        self.catalogSelectionURL = (catalogSelectionURL ?? normalizedVaultRootURL
            .deletingLastPathComponent()
            .appendingPathComponent("sensitive-index-selection.json"))
            .standardizedFileURL
        self.credentialAuthorizationTTL = credentialAuthorizationTTL
        self.externalSendAuthorizationTTL = externalSendAuthorizationTTL
        self.readAuthorizationTTL = readAuthorizationTTL
        self.httpResponseProjectionProfiles = httpResponseProjectionProfiles
    }

    public static func `default`() throws -> VaultDaemonConfiguration {
        let appSupport = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let applicationRoot = appSupport.appendingPathComponent(
            "AgentSecretVault",
            isDirectory: true
        )
        return VaultDaemonConfiguration(
            vaultRootURL: applicationRoot.appendingPathComponent("Vault", isDirectory: true),
            auditRootURL: applicationRoot.appendingPathComponent("Audit", isDirectory: true),
            ipcConfiguration: try .defaultConfiguration()
        )
    }
}

/// The only owner of VaultAppServices and the Unix socket in production. The
/// GUI application is a client and never constructs this core.
public actor VaultDaemonCore {
    public let configuration: VaultDaemonConfiguration

    private let controller: AppIPCController
    private let appControlController: AppControlIPCController
    private let services: VaultAppServices
    private let protectionKeyStore: AppProtectionKeyStore
    private let lifecycleMonitor: VaultDaemonLifecycleMonitor
    private var started = false

    public init(configuration: VaultDaemonConfiguration? = nil) throws {
        let configuration = try configuration ?? VaultDaemonConfiguration.default()
        self.configuration = configuration

        let fileManager = FileManager.default
        try fileManager.createDirectory(
            at: configuration.vaultRootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.createDirectory(
            at: configuration.auditRootURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        try fileManager.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: configuration.vaultRootURL.path
        )
        try fileManager.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: configuration.auditRootURL.path
        )

        // Production resolves to ~/Library/Application Support/AgentSecretVault/
        // approval-mode.json. Tests using a temporary vault root get an isolated
        // mode file automatically and cannot inherit a developer's GUI setting.
        VaultApprovalModeState.shared.configure(
            storageURL: configuration.vaultRootURL
                .deletingLastPathComponent()
                .appendingPathComponent("approval-mode.json", isDirectory: false)
        )

        let recordStore = FileRecordStore(baseDirectory: configuration.vaultRootURL)
        let deviceKeyStore = DeviceKeyStore()
        let protectionKeyStore = AppProtectionKeyStore(
            deviceKeyStore: deviceKeyStore,
            credentialTTL: configuration.credentialAuthorizationTTL,
            externalSendTTL: configuration.externalSendAuthorizationTTL
        )
        let wrappedMasterKeyStore = FileWrappedMasterKeyStore(
            fileURL: configuration.vaultRootURL
                .appendingPathComponent(".agent-secret-vault", isDirectory: true)
                .appendingPathComponent("master-key.json")
        )
        let masterKeyCoordinator = MasterKeyCoordinator(
            deviceKeyStore: deviceKeyStore,
            wrappedStore: wrappedMasterKeyStore
        )
        let legacyMigrationVerifier = LegacyVaultMigrationVerifier()

        let unlockUsingWrappingKey: @Sendable (Data, String) async throws -> Data = {
            localWrappingKey,
            reason in
            let wrappedMasterKeySet = try await wrappedMasterKeyStore.loadWrappedMasterKeySet()
            let hasLegacyRecords = !(try await recordStore.recordIDs()).isEmpty
            if wrappedMasterKeySet == nil, hasLegacyRecords {
                return try await masterKeyCoordinator.adoptExistingVault(
                    reason: reason,
                    localWrappingKey: localWrappingKey,
                    verifyExistingMasterKey: {
                        try await legacyMigrationVerifier.verifyAtLeastOneExistingRecord(
                            masterKey: localWrappingKey,
                            in: recordStore
                        )
                    }
                )
            }
            let masterKey = try await masterKeyCoordinator.unlock(
                reason: reason,
                localWrappingKey: localWrappingKey
            )
            // Never treat a successfully opened wrapper as proof that the
            // records are still usable. Validate the current record set before
            // allowing plaintext operations, without returning plaintext.
            do {
                try await legacyMigrationVerifier.verifyAtLeastOneExistingRecord(
                    masterKey: masterKey,
                    in: recordStore,
                    requireAtLeastOne: false
                )
            } catch {
                throw MasterKeyCoordinatorError.integrityFailed
            }
            return masterKey
        }

        let masterKeyProviderWithAuthenticationContext: @Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey = {
            policy,
            reason,
            authenticationContext in
            let candidates = try await protectionKeyStore.deviceKeyCandidates(
                for: policy,
                reason: reason,
                authenticationContext: authenticationContext
            )
            var remainingCandidates = candidates
            while !remainingCandidates.isEmpty {
                var localWrappingKey = remainingCandidates.removeFirst()
                do {
                    let masterKey = try await unlockUsingWrappingKey(localWrappingKey, reason)
                    // Promotion is deliberately after both wrapper opening and
                    // record verification. Merely reading an authenticated
                    // legacy Keychain item is not enough evidence to make it
                    // the canonical silent wrapping key.
                    try await deviceKeyStore.promoteVerifiedDeviceKey(localWrappingKey)
                    await protectionKeyStore.rememberDeviceKey(localWrappingKey, for: policy)
                    localWrappingKey.resetBytes(in: 0..<localWrappingKey.count)
                    return SymmetricKey(data: masterKey)
                } catch let error as MasterKeyCoordinatorError {
                    localWrappingKey.resetBytes(in: 0..<localWrappingKey.count)
                    guard error == .integrityFailed else {
                        throw error
                    }
                }
            }
            throw MasterKeyCoordinatorError.integrityFailed
        }
        let freshMasterKeyProviderWithAuthenticationContext: @Sendable (SecretPolicy, String, LocalAuthenticationContext?) async throws -> SymmetricKey = {
            policy,
            reason,
            authenticationContext in
            let candidates = try await protectionKeyStore.freshDeviceKeyCandidates(
                for: policy,
                reason: reason,
                authenticationContext: authenticationContext
            )
            var remainingCandidates = candidates
            while !remainingCandidates.isEmpty {
                var localWrappingKey = remainingCandidates.removeFirst()
                do {
                    let masterKey = try await unlockUsingWrappingKey(localWrappingKey, reason)
                    try await deviceKeyStore.promoteVerifiedDeviceKey(localWrappingKey)
                    localWrappingKey.resetBytes(in: 0..<localWrappingKey.count)
                    return SymmetricKey(data: masterKey)
                } catch let error as MasterKeyCoordinatorError {
                    localWrappingKey.resetBytes(in: 0..<localWrappingKey.count)
                    guard error == .integrityFailed else {
                        throw error
                    }
                }
            }
            throw MasterKeyCoordinatorError.integrityFailed
        }
        let masterKeyProvider: @Sendable (SecretPolicy, String) async throws -> SymmetricKey = {
            policy,
            reason in
            try await masterKeyProviderWithAuthenticationContext(policy, reason, nil)
        }
        let freshMasterKeyProvider: @Sendable (SecretPolicy, String) async throws -> SymmetricKey = {
            policy,
            reason in
            try await freshMasterKeyProviderWithAuthenticationContext(policy, reason, nil)
        }

        let encryptor = EncryptSelectionCoordinator(
            recordStore: recordStore,
            selectionReplacer: NoopSelectionReplacer(),
            masterKeyProvider: { policy, reason in
                let key = try await masterKeyProvider(policy, reason)
                return key.withUnsafeBytes { Data($0) }
            }
        )
        let auditKeyStore = KeychainAuditKeyStore()
        let auditLog = EncryptedAuditLog(
            directoryURL: configuration.auditRootURL,
            auditKeyProvider: {
                SymmetricKey(data: try await auditKeyStore.loadOrCreateAuditKeyData())
            }
        )
        let approvalPresentationNotifier = AgentApprovalPresentationNotifier()
        let services = VaultAppServices(
            textEncryptor: encryptor,
            activeRoot: configuration.vaultRootURL,
            recordLister: recordStore,
            recordDeleter: recordStore,
            recordResolver: VaultRecordResolver(recordStore: recordStore),
            catalogDocumentStore: SensitiveCatalogDocumentStore(
                secretReferenceExists: { reference in
                    guard let id = try? SecretReference(reference).id else { return false }
                    return (try? await recordStore.latest(id: id)) != nil
                }
            ),
            catalogSelectionManifestURL: configuration.catalogSelectionURL,
            masterKeyProvider: masterKeyProvider,
            freshMasterKeyProvider: freshMasterKeyProvider,
            masterKeyProviderWithAuthenticationContext: masterKeyProviderWithAuthenticationContext,
            freshMasterKeyProviderWithAuthenticationContext: freshMasterKeyProviderWithAuthenticationContext,
            clearProtectedKeyState: {
                await protectionKeyStore.clearAll()
            },
            isUnlockedProvider: {
                await protectionKeyStore.isUnlocked
            },
            revealSessionStore: RevealSessionStore(defaultTTLSeconds: 60),
            revealSessionPresenter: AgentUIRequestNotifier(),
            authorizationSession: AuthorizationSession(
                readTTL: configuration.readAuthorizationTTL,
                credentialTTL: configuration.credentialAuthorizationTTL,
                externalSendTTL: configuration.externalSendAuthorizationTTL
            ),
            operationApprover: LocalOperationApprover(
                authenticator: LocalAuthenticator(
                    presentationObserver: { approvalID in
                        approvalPresentationNotifier.notify(approvalID: approvalID)
                    }
                )
            ),
            operationExecutor: LocalSecretOperationExecutor(
                adapterRegistry: SecretOperationAdapterRegistry(
                    responseProjectionProfiles: configuration.httpResponseProjectionProfiles
                )
            ),
            credentialAuthorizationTTL: configuration.credentialAuthorizationTTL,
            externalSendAuthorizationTTL: configuration.externalSendAuthorizationTTL,
            auditLog: auditLog,
            auditHealthURL: configuration.auditRootURL
                .appendingPathComponent("audit-health.json", isDirectory: false)
        )
        let server = UnixSocketServer(configuration: configuration.ipcConfiguration)
        let controller = AppIPCController(
            server: server,
            handler: IPCRequestHandler(service: services)
        )
        let appControlServer = UnixSocketServer(
            configuration: try .appControlConfiguration(
                directoryURL: configuration.ipcConfiguration.directoryURL
            )
        )
        let appControlController = AppControlIPCController(
            server: appControlServer,
            handler: AppControlRequestHandler(service: services)
        )
        let lifecycleMonitor = VaultDaemonLifecycleMonitor {
            await services.invalidateSecurityState()
            await protectionKeyStore.clearAll()
            await services.clearRevealSessions()
        }

        self.controller = controller
        self.appControlController = appControlController
        self.services = services
        self.protectionKeyStore = protectionKeyStore
        self.lifecycleMonitor = lifecycleMonitor
    }

    public func start() throws {
        guard !started else {
            throw VaultDaemonCoreError.alreadyStarted
        }
        // Deliberately no unlock call here. The first protected request enters
        // the lazy master-key provider. Current wrapping keys are silent while
        // a legacy userPresence item may require one migration authentication.
        try controller.start()
        try appControlController.start()
        lifecycleMonitor.start()
        started = true
    }

    public func stop() async {
        guard started else {
            return
        }
        lifecycleMonitor.stop()
        // Invalidate the service security state before tearing down the IPC
        // controllers.  This latches cancellation for Secure Input requests
        // that are still awaiting authentication or Catalog I/O, while the
        // service remains available to finish their terminal receipts.  A
        // request already in `.committing` is intentionally allowed to finish
        // because that state is the transaction's linearization point.
        await services.invalidateSecurityState()
        controller.stop()
        appControlController.stop()
        await protectionKeyStore.clearAll()
        await services.clearRevealSessions()
        started = false
    }

    public func status() async -> WorkbenchStatus {
        await services.status()
    }
}

private struct NoopSelectionReplacer: SelectionReplacing {
    func replaceSelection(with text: String) async throws {
        throw NoopSelectionReplacerError.unavailable
    }
}

private enum NoopSelectionReplacerError: Error {
    case unavailable
}
