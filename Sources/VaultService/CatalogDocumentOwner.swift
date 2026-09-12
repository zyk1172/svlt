import Foundation
import VaultCore
import VaultIPC

struct CatalogDocumentProjection: Sendable {
    let selectedDocumentPath: String?
    let snapshot: CatalogPresentationSnapshot?
    let canAdoptV2: Bool
    let canAdoptV3: Bool

    static let unavailable = CatalogDocumentProjection(
        selectedDocumentPath: nil,
        snapshot: nil,
        canAdoptV2: false,
        canAdoptV3: false
    )
}

/// Owns the selected managed Catalog document inside the daemon process.
///
/// The GUI may choose a path and consume a projection over App-control IPC,
/// but it never constructs a `SensitiveCatalogDocumentStore`, reads accepted
/// state, reconciles external changes, or mutates the selection manifest.
actor CatalogDocumentOwner {
    private let store: SensitiveCatalogDocumentStore
    private let selectionStore: SecretCatalogSelectionStore?

    init(
        store: SensitiveCatalogDocumentStore,
        selectionStore: SecretCatalogSelectionStore?
    ) {
        self.store = store
        self.selectionStore = selectionStore
    }

    func selectedStore() async throws -> SensitiveCatalogDocumentStore {
        guard let selectedURL = try await authoritativeSelectedDocumentURL() else {
            throw SecretCatalogAgentError.unavailable
        }
        try await store.selectDocument(at: selectedURL)
        return store
    }

    func presentationProjection() async -> CatalogDocumentProjection {
        let selectedURL: URL
        do {
            guard let value = try await authoritativeSelectedDocumentURL() else {
                return .unavailable
            }
            selectedURL = value
            try await store.selectDocument(at: selectedURL)
        } catch {
            return .unavailable
        }

        guard await store.selectedDocumentExists() else {
            return CatalogDocumentProjection(
                selectedDocumentPath: selectedURL.path,
                snapshot: nil,
                canAdoptV2: false,
                canAdoptV3: false
            )
        }

        do {
            let snapshot = try await store.snapshot()
            return CatalogDocumentProjection(
                selectedDocumentPath: selectedURL.path,
                snapshot: CatalogPresentationSnapshot(
                    document: snapshot.document,
                    revision: snapshot.revision
                ),
                canAdoptV2: false,
                canAdoptV3: false
            )
        } catch SensitiveCatalogDocumentStoreError.integrityMissing {
            let availability = try? await store.adoptionAvailability()
            return CatalogDocumentProjection(
                selectedDocumentPath: selectedURL.path,
                snapshot: nil,
                canAdoptV2: availability?.canAdoptV2 ?? false,
                canAdoptV3: availability?.canAdoptV3 ?? false
            )
        } catch {
            return CatalogDocumentProjection(
                selectedDocumentPath: selectedURL.path,
                snapshot: nil,
                canAdoptV2: false,
                canAdoptV3: false
            )
        }
    }

    /// Changes the authoritative selection only after the daemon can open the
    /// candidate. A failed selection restores the in-memory store and leaves
    /// the durable manifest untouched.
    func selectDocument(path: String) async throws {
        guard path.hasPrefix("/"), !path.contains("\0") else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let candidate = URL(fileURLWithPath: path).standardizedFileURL
        let previous = try await authoritativeSelectedDocumentURL()

        do {
            try await store.selectDocument(at: candidate)
            guard await store.selectedDocumentExists() else {
                throw SecretCatalogAgentError.invalidOperation
            }
            try selectionStore?.save(documentURL: candidate)
        } catch let error as SecretCatalogAgentError {
            try? await store.selectDocument(at: previous)
            throw error
        } catch let error as SecretCatalogSelectionStoreError {
            try? await store.selectDocument(at: previous)
            switch error {
            case .writeFailed:
                throw SecretCatalogAgentError.writeFailed
            case .invalidManifest, .symlinkRejected, .malformedDocumentPath:
                throw SecretCatalogAgentError.invalidOperation
            }
        } catch let error as SensitiveCatalogDocumentStoreError {
            try? await store.selectDocument(at: previous)
            switch error {
            case .writeFailed, .recoveryRollbackBackupInvalid:
                throw SecretCatalogAgentError.writeFailed
            case .noSelectedDocument, .malformedDocument, .symlinkRejected, .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            try? await store.selectDocument(at: previous)
            throw SecretCatalogAgentError.unavailable
        }
    }

    private func authoritativeSelectedDocumentURL() async throws -> URL? {
        if let selectionStore {
            return try selectionStore.selectedDocumentURL()
        }
        return await store.selectedDocumentURL()
    }
}

public extension VaultAppServices {
    func catalogPresentationState() async -> CatalogPresentationState {
        guard let catalogDocumentOwner else {
            return CatalogPresentationState(
                validation: CatalogValidationResult(status: .unavailable)
            )
        }
        let projection = await catalogDocumentOwner.presentationProjection()
        let validation = (try? await validateCatalog())
            ?? CatalogValidationResult(status: .unavailable)
        return CatalogPresentationState(
            selectedDocumentPath: projection.selectedDocumentPath,
            validation: validation,
            snapshot: projection.snapshot,
            canAdoptV2: projection.canAdoptV2,
            canAdoptV3: projection.canAdoptV3
        )
    }

    func selectCatalogDocument(path: String) async throws -> CatalogPresentationState {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        try await catalogDocumentOwner.selectDocument(path: path)
        return await catalogPresentationState()
    }
}
