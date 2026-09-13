import Foundation
import Testing
@testable import VaultAuthorization
@testable import VaultCore
@testable import VaultService

private let ownerFirstIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let ownerSecondIndexID = "0123456789ABCDEFGHJKMNPQRX"
private let ownerOperationIndexID = "0123456789ABCDEFGHJKMNPQRY"

private struct CatalogOwnerOperationResult: Sendable {
    let initial: SensitiveCatalogSnapshot
    let updated: SensitiveCatalogSnapshot
}

/// A deterministic suspend point for the exact window under review. The
/// operation task announces that it has started and waits until the test has
/// changed the GUI selection before it resumes.
private actor CatalogOperationGate {
    private var reached = false
    private var released = false
    private var reachedWaiter: CheckedContinuation<Void, Never>?
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func pauseUntilReleased() async {
        reached = true
        reachedWaiter?.resume()
        reachedWaiter = nil
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseWaiters.append(continuation)
        }
    }

    func waitUntilReached() async {
        guard !reached else { return }
        await withCheckedContinuation { continuation in
            reachedWaiter = continuation
        }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }
}

private struct CatalogOwnerFixture {
    let root: URL
    let firstDocumentURL: URL
    let secondDocumentURL: URL
    let selectionURL: URL
    let integrityDirectoryURL: URL
    let keyStore: FixedCatalogIntegrityKeyStore
    let firstDocument: SecretCatalogDocument
    let secondDocument: SecretCatalogDocument

    init() async throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("svlt-catalog-owner-concurrency-\(UUID().uuidString)", isDirectory: true)
        firstDocumentURL = root.appendingPathComponent("first.md")
        secondDocumentURL = root.appendingPathComponent("second.md")
        selectionURL = root.appendingPathComponent("selection.json")
        integrityDirectoryURL = root.appendingPathComponent("CatalogIntegrity", isDirectory: true)
        keyStore = try FixedCatalogIntegrityKeyStore(key: Data(repeating: 13, count: 32))
        try FileManager.default.createDirectory(at: integrityDirectoryURL, withIntermediateDirectories: true)

        firstDocument = SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: ownerFirstIndexID, title: "目录 A")]
        )
        secondDocument = SecretCatalogDocument(
            indexes: [SecretCatalogIndex(id: ownerSecondIndexID, title: "目录 B")]
        )

        let firstStore = SensitiveCatalogDocumentStore(
            documentURL: firstDocumentURL,
            keyStore: keyStore,
            atomicWriteFaultInjector: nil,
            integrityDirectoryURL: integrityDirectoryURL
        )
        _ = try await firstStore.canonicalWrite(firstDocument)

        let secondStore = SensitiveCatalogDocumentStore(
            documentURL: secondDocumentURL,
            keyStore: keyStore,
            atomicWriteFaultInjector: nil,
            integrityDirectoryURL: integrityDirectoryURL
        )
        _ = try await secondStore.canonicalWrite(secondDocument)
        try SecretCatalogSelectionStore(manifestURL: selectionURL).save(documentURL: firstDocumentURL)
    }

    func makeOwner() -> CatalogDocumentOwner {
        let templateStore = SensitiveCatalogDocumentStore(
            documentURL: firstDocumentURL,
            keyStore: keyStore,
            atomicWriteFaultInjector: nil,
            integrityDirectoryURL: integrityDirectoryURL
        )
        return CatalogDocumentOwner(
            store: templateStore,
            selectionStore: SecretCatalogSelectionStore(manifestURL: selectionURL)
        )
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: root)
    }
}

@Test func catalogOperationRemainsBoundAcrossSelectionDuringReadAndWrite() async throws {
    let fixture = try await CatalogOwnerFixture()
    defer { fixture.cleanup() }
    let owner = fixture.makeOwner()
    let operation = try await owner.beginOperation()
    let gate = CatalogOperationGate()
    let operationTask = Task { () throws -> CatalogOwnerOperationResult in
        await gate.pauseUntilReleased()
        let initial = try await operation.snapshot()
        let mutation = CatalogBatchMutation(operations: [
            .createIndex(SecretCatalogIndex(id: ownerOperationIndexID, title: "只写入目录 A"))
        ])
        let updated = try await operation.applyBatch(
            mutation,
            expectedRevision: initial.revision
        )
        return CatalogOwnerOperationResult(initial: initial, updated: updated)
    }

    await gate.waitUntilReached()
    try await owner.selectDocument(path: fixture.secondDocumentURL.path)
    await gate.release()

    let result: CatalogOwnerOperationResult
    do {
        result = try await operationTask.value
    } catch {
        await operation.end()
        throw error
    }
    await operation.end()

    #expect(result.initial.document == fixture.firstDocument)
    #expect(result.updated.document.indexes.contains(where: {
        $0.id == ownerOperationIndexID && $0.title == "只写入目录 A"
    }))

    let firstVerifier = SensitiveCatalogDocumentStore(
        documentURL: fixture.firstDocumentURL,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: fixture.integrityDirectoryURL
    )
    let secondVerifier = SensitiveCatalogDocumentStore(
        documentURL: fixture.secondDocumentURL,
        keyStore: fixture.keyStore,
        atomicWriteFaultInjector: nil,
        integrityDirectoryURL: fixture.integrityDirectoryURL
    )
    let persistedFirst = try await firstVerifier.snapshot()
    let persistedSecond = try await secondVerifier.snapshot()
    #expect(persistedFirst.document == result.updated.document)
    #expect(persistedSecond.document == fixture.secondDocument)

    // Presentation is also one owner operation: the path, validation and
    // projection must all describe the selected B document.
    let presentation = await owner.catalogPresentationState()
    #expect(presentation.selectedDocumentPath == fixture.secondDocumentURL.path)
    #expect(presentation.snapshot?.document == fixture.secondDocument)
    #expect(presentation.validation.revision == persistedSecond.revision)
}

@Test func catalogOperationIdentityCanBeRehydratedWithoutRetainingLiveStore() async throws {
    let fixture = try await CatalogOwnerFixture()
    defer { fixture.cleanup() }
    let owner = fixture.makeOwner()

    let original = try await owner.beginOperation()
    let originalPath = original.selectedDocumentPath
    await original.end()

    try await owner.selectDocument(path: fixture.secondDocumentURL.path)
    let resumed = try await owner.beginOperation(documentPath: originalPath)
    let snapshot = try await resumed.snapshot()
    await resumed.end()

    #expect(originalPath == fixture.firstDocumentURL.path)
    #expect(snapshot.document == fixture.firstDocument)

    let current = await owner.catalogPresentationState()
    #expect(current.selectedDocumentPath == fixture.secondDocumentURL.path)
    #expect(current.snapshot?.document == fixture.secondDocument)
    #expect(current.validation.revision == current.snapshot?.revision)
}
