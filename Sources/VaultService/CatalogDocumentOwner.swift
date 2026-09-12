import Foundation
import VaultCore
import VaultIPC

/// A capability for one Catalog operation. It identifies an operation owned
/// by `CatalogDocumentOwner`; it never exposes the mutable Store itself.
struct CatalogDocumentOperation: Sendable {
    private let owner: CatalogDocumentOwner
    private let id: UUID

    fileprivate init(owner: CatalogDocumentOwner, id: UUID) {
        self.owner = owner
        self.id = id
    }

    func end() async {
        await owner.endOperation(id: id)
    }

    func snapshot() async throws -> SensitiveCatalogSnapshot {
        try await owner.snapshot(for: id)
    }

    func validationReport() async throws -> CatalogValidationReport {
        try await owner.validationReport(for: id)
    }

    func preflightFileAccess() async throws -> CatalogFilePreflight {
        try await owner.preflightFileAccess(for: id)
    }

    func formatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        try await owner.formatRepairPlan(for: id)
    }

    func repairFormat(expectedRawSHA256: String) async throws -> SensitiveCatalogSnapshot {
        try await owner.repairFormat(for: id, expectedRawSHA256: expectedRawSHA256)
    }

    func adoptExternalV2() async throws -> SensitiveCatalogSnapshot {
        try await owner.adoptExternalV2(for: id)
    }

    func externalV3AdoptionCandidate() async throws -> CatalogExternalChange {
        try await owner.externalV3AdoptionCandidate(for: id)
    }

    func adoptExternalV3(
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.adoptExternalV3(
            for: id,
            expectedRawSHA256: expectedRawSHA256,
            expectedSemanticSHA256: expectedSemanticSHA256
        )
    }

    func pendingExternalChange() async throws -> CatalogExternalChange {
        try await owner.pendingExternalChange(for: id)
    }

    func acceptPendingExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.acceptPendingExternalChange(
            for: id,
            expectedRevision: expectedRevision,
            expectedRawSHA256: expectedRawSHA256,
            expectedSemanticSHA256: expectedSemanticSHA256
        )
    }

    func applyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.applyBatch(for: id, mutation: mutation, expectedRevision: expectedRevision)
    }

    func createIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.createIndex(
            for: id,
            title: title,
            aliases: aliases,
            tags: tags,
            expectedRevision: expectedRevision
        )
    }

    func createIndex(
        _ index: SecretCatalogIndex,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.createIndex(for: id, index: index, expectedRevision: expectedRevision)
    }

    func createEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.createEntry(for: id, entry: entry, expectedRevision: expectedRevision)
    }

    func updateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.updateEntry(for: id, entry: entry, expectedRevision: expectedRevision)
    }

    func addField(
        _ field: SecretCatalogFieldValue,
        toEntryID entryID: String,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.addField(
            for: id,
            field: field,
            entryID: entryID,
            expectedRevision: expectedRevision
        )
    }

    func bindSecret(
        _ secretRef: String,
        toFieldKey key: String,
        entryID: String,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await owner.bindSecret(
            for: id,
            secretRef: secretRef,
            key: key,
            entryID: entryID,
            expectedRevision: expectedRevision
        )
    }

    func pendingSecretCleanupReferenceIDs() async throws -> [String] {
        try await owner.pendingSecretCleanupReferenceIDs(for: id)
    }

    func recordPendingSecretCleanup(referenceIDs: [String]) async throws {
        try await owner.recordPendingSecretCleanup(for: id, referenceIDs: referenceIDs)
    }

    func clearPendingSecretCleanup(referenceIDs: [String]) async throws {
        try await owner.clearPendingSecretCleanup(for: id, referenceIDs: referenceIDs)
    }

    func presentationState() async -> CatalogPresentationState {
        await owner.presentationState(for: id)
    }
}

/// Owns the selected managed Catalog document inside the daemon process.
///
/// The GUI may choose a path and consume a projection over App-control IPC,
/// but it never constructs a `SensitiveCatalogDocumentStore`, reads accepted
/// state, reconciles external changes, or mutates the selection manifest.
/// Every operation receives only an opaque capability. The owner keeps the
/// operation's fixed-document Store in its own state, so actor reentrancy at
/// an `await` cannot move an in-flight read or write to another Catalog.
actor CatalogDocumentOwner {
    private struct ActiveOperation {
        let selectedDocumentURL: URL
        let store: SensitiveCatalogDocumentStore
    }

    private let store: SensitiveCatalogDocumentStore
    private let selectionStore: SecretCatalogSelectionStore?
    private var operations: [UUID: ActiveOperation] = [:]
    private var fallbackSelectionLoaded = false
    private var fallbackSelectedDocumentURL: URL?

    init(
        store: SensitiveCatalogDocumentStore,
        selectionStore: SecretCatalogSelectionStore?
    ) {
        self.store = store
        self.selectionStore = selectionStore
    }

    /// Captures the authoritative selection and creates a Store whose target
    /// can no longer be changed by selection IPC. The Store remains in this
    /// actor; callers receive only the operation capability.
    func beginOperation() async throws -> CatalogDocumentOperation {
        guard let selectedURL = try await authoritativeSelectedDocumentURL() else {
            throw SecretCatalogAgentError.unavailable
        }
        let id = UUID()
        let operationStore = await store.makeOperationStore(documentURL: selectedURL)
        operations[id] = ActiveOperation(
            selectedDocumentURL: selectedURL,
            store: operationStore
        )
        return CatalogDocumentOperation(owner: self, id: id)
    }

    func endOperation(id: UUID) {
        operations.removeValue(forKey: id)
    }

    func selectDocument(path: String) async throws {
        guard path.hasPrefix("/"), !path.contains("\0") else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let candidate = URL(fileURLWithPath: path).standardizedFileURL
        let candidateStore = await operationStore(for: candidate)

        do {
            guard await candidateStore.selectedDocumentExists() else {
                throw SecretCatalogAgentError.invalidOperation
            }
            try selectionStore?.save(documentURL: candidate)
            if selectionStore == nil {
                fallbackSelectedDocumentURL = candidate
                fallbackSelectionLoaded = true
            }
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch let error as SecretCatalogSelectionStoreError {
            switch error {
            case .writeFailed:
                throw SecretCatalogAgentError.writeFailed
            case .invalidManifest, .symlinkRejected, .malformedDocumentPath:
                throw SecretCatalogAgentError.invalidOperation
            }
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .writeFailed, .recoveryRollbackBackupInvalid:
                throw SecretCatalogAgentError.writeFailed
            case .noSelectedDocument, .malformedDocument, .symlinkRejected, .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    func catalogPresentationState() async -> CatalogPresentationState {
        guard let operation = try? await beginOperation() else {
            return CatalogPresentationState(validation: CatalogValidationResult(status: .unavailable))
        }
        let result = await operation.presentationState()
        await operation.end()
        return result
    }

    private func authoritativeSelectedDocumentURL() async throws -> URL? {
        if let selectionStore {
            return try selectionStore.selectedDocumentURL()
        }
        if !fallbackSelectionLoaded {
            fallbackSelectedDocumentURL = await store.selectedDocumentURL()
            fallbackSelectionLoaded = true
        }
        return fallbackSelectedDocumentURL
    }

    private func operationStore(for documentURL: URL) async -> SensitiveCatalogDocumentStore {
        await store.makeOperationStore(documentURL: documentURL)
    }

    private func activeOperation(for id: UUID) throws -> ActiveOperation {
        guard let operation = operations[id] else {
            throw SecretCatalogAgentError.unavailable
        }
        return operation
    }

    private func operationStore(for id: UUID) throws -> SensitiveCatalogDocumentStore {
        try activeOperation(for: id).store
    }

    func snapshot(for id: UUID) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).snapshot()
    }

    func validationReport(for id: UUID) async throws -> CatalogValidationReport {
        try await operationStore(for: id).validationReport()
    }

    func preflightFileAccess(for id: UUID) async throws -> CatalogFilePreflight {
        try await operationStore(for: id).preflightFileAccess()
    }

    func formatRepairPlan(for id: UUID) async throws -> CatalogFormatRepairPlan? {
        try await operationStore(for: id).formatRepairPlan()
    }

    func repairFormat(
        for id: UUID,
        expectedRawSHA256: String
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).repairFormat(expectedRawSHA256: expectedRawSHA256)
    }

    func adoptExternalV2(for id: UUID) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).adoptExternalV2()
    }

    func externalV3AdoptionCandidate(for id: UUID) async throws -> CatalogExternalChange {
        try await operationStore(for: id).externalV3AdoptionCandidate()
    }

    func adoptExternalV3(
        for id: UUID,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).adoptExternalV3(
            expectedRawSHA256: expectedRawSHA256,
            expectedSemanticSHA256: expectedSemanticSHA256
        )
    }

    func pendingExternalChange(for id: UUID) async throws -> CatalogExternalChange {
        try await operationStore(for: id).pendingExternalChange()
    }

    func acceptPendingExternalChange(
        for id: UUID,
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).acceptPendingExternalChange(
            expectedRevision: expectedRevision,
            expectedRawSHA256: expectedRawSHA256,
            expectedSemanticSHA256: expectedSemanticSHA256
        )
    }

    func applyBatch(
        for id: UUID,
        mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).applyBatch(mutation, expectedRevision: expectedRevision)
    }

    func createIndex(
        for id: UUID,
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).createIndex(
            title: title,
            aliases: aliases,
            tags: tags,
            expectedRevision: expectedRevision
        )
    }

    func createIndex(
        for id: UUID,
        index: SecretCatalogIndex,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).createIndex(index, expectedRevision: expectedRevision)
    }

    func createEntry(
        for id: UUID,
        entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).createEntry(entry, expectedRevision: expectedRevision)
    }

    func updateEntry(
        for id: UUID,
        entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).updateEntry(entry, expectedRevision: expectedRevision)
    }

    func addField(
        for id: UUID,
        field: SecretCatalogFieldValue,
        entryID: String,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).addField(
            field,
            toEntryID: entryID,
            expectedRevision: expectedRevision
        )
    }

    func bindSecret(
        for id: UUID,
        secretRef: String,
        key: String,
        entryID: String,
        expectedRevision: UInt64
    ) async throws -> SensitiveCatalogSnapshot {
        try await operationStore(for: id).bindSecret(
            secretRef,
            toFieldKey: key,
            entryID: entryID,
            expectedRevision: expectedRevision
        )
    }

    func pendingSecretCleanupReferenceIDs(for id: UUID) async throws -> [String] {
        try await operationStore(for: id).pendingSecretCleanupReferenceIDs()
    }

    func recordPendingSecretCleanup(for id: UUID, referenceIDs: [String]) async throws {
        try await operationStore(for: id).recordPendingSecretCleanup(referenceIDs: referenceIDs)
    }

    func clearPendingSecretCleanup(for id: UUID, referenceIDs: [String]) async throws {
        try await operationStore(for: id).clearPendingSecretCleanup(referenceIDs: referenceIDs)
    }

    fileprivate func presentationState(for id: UUID) async -> CatalogPresentationState {
        guard let operation = try? activeOperation(for: id) else {
            return CatalogPresentationState(validation: CatalogValidationResult(status: .unavailable))
        }

        let validation: CatalogValidationResult
        do {
            let report = try await operation.store.validationReport()
            validation = CatalogValidationResult(
                status: report.status,
                revision: report.revision,
                rawSHA256: report.rawSHA256,
                pendingExternalChange: report.pendingExternalChange,
                diagnostics: report.diagnostics
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            validation = validationResult(for: error)
        } catch {
            validation = CatalogValidationResult(status: .unavailable)
        }

        var snapshot: CatalogPresentationSnapshot?
        var canAdoptV2 = false
        var canAdoptV3 = false
        do {
            let value = try await operation.store.snapshot()
            if value.integrity == .verified {
                snapshot = CatalogPresentationSnapshot(
                    document: value.document,
                    revision: value.revision
                )
            }
        } catch SensitiveCatalogDocumentStoreError.integrityMissing {
            let availability = try? await operation.store.adoptionAvailability()
            canAdoptV2 = availability?.canAdoptV2 ?? false
            canAdoptV3 = availability?.canAdoptV3 ?? false
        } catch {
            // The validation result already carries the source-safe status and
            // diagnostics. A failed accepted-state read contributes no
            // document projection.
        }

        return CatalogPresentationState(
            selectedDocumentPath: operation.selectedDocumentURL.path,
            validation: validation,
            snapshot: snapshot,
            canAdoptV2: canAdoptV2,
            canAdoptV3: canAdoptV3
        )
    }

    private func validationResult(for error: SensitiveCatalogDocumentStoreError) -> CatalogValidationResult {
        switch error {
        case .noSelectedDocument:
            return CatalogValidationResult(status: .unavailable)
        case .writeFailed:
            return CatalogValidationResult(status: .unavailable, diagnostics: [CatalogValidationDiagnostic(
                code: "CATALOG_READ_UNAVAILABLE",
                line: 1,
                column: 1,
                scope: .document,
                message: "无法读取敏感信息目录。",
                hint: "请检查 App 选择的目录文件。"
            )])
        default:
            return CatalogValidationResult(status: .invalidCatalog, diagnostics: [CatalogValidationDiagnostic(
                code: "CATALOG_VALIDATION_FAILED",
                line: 1,
                column: 1,
                scope: .document,
                message: "敏感信息目录验证失败。",
                hint: "请在 SVLT App 中检查目录状态。"
            )])
        }
    }
}

public extension VaultAppServices {
    func catalogPresentationState() async -> CatalogPresentationState {
        guard let catalogDocumentOwner else {
            return CatalogPresentationState(
                validation: CatalogValidationResult(status: .unavailable)
            )
        }
        return await catalogDocumentOwner.catalogPresentationState()
    }

    func selectCatalogDocument(path: String) async throws -> CatalogPresentationState {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        try await catalogDocumentOwner.selectDocument(path: path)
        return await catalogDocumentOwner.catalogPresentationState()
    }
}
