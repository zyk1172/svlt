import Foundation
import VaultAuthorization

/// FileManager is documented as thread-safe, but the SDK does not currently
/// model that fact in its Sendable annotations. Operation creation passes
/// this immutable box instead of sending the Foundation object directly.
final class CatalogFileManagerBox: @unchecked Sendable {
    let value: FileManager

    init(_ value: FileManager) {
        self.value = value
    }
}

extension SensitiveCatalogDocumentStore {
    private static func makeOperationStore(
        documentURL: URL,
        integrityURL: URL?,
        keyStore: any CatalogIntegrityKeyStoring,
        fileManagerBox: CatalogFileManagerBox,
        atomicWriteFaultInjector: (any CatalogAtomicWriteFaultInjecting)?,
        integrityDirectoryURL: URL?,
        secretReferenceExists: (@Sendable (String) async -> Bool)?
    ) -> SensitiveCatalogDocumentStore {
        SensitiveCatalogDocumentStore(
            documentURL: documentURL,
            integrityURL: integrityURL,
            keyStore: keyStore,
            fileManager: fileManagerBox.value,
            atomicWriteFaultInjector: atomicWriteFaultInjector,
            integrityDirectoryURL: integrityDirectoryURL,
            secretReferenceExists: secretReferenceExists
        )
    }

    /// Creates a Store with an immutable document choice. The owner keeps the
    /// returned Store private to its operation state.
    internal func makeOperationStore(documentURL: URL) -> SensitiveCatalogDocumentStore {
        Self.makeOperationStore(
            documentURL: documentURL,
            integrityURL: suppliedIntegrityURL,
            keyStore: keyStore,
            fileManagerBox: fileManagerBox,
            atomicWriteFaultInjector: atomicWriteFaultInjector,
            integrityDirectoryURL: suppliedIntegrityDirectoryURL,
            secretReferenceExists: secretReferenceExists
        )
    }
}
