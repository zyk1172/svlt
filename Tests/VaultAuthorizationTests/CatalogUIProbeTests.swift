import Foundation
import Testing
import VaultCore
@testable import VaultService

private func catalogUIProbeFixtureURL() throws -> (root: URL, document: URL) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-catalog-ui-probe-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return (root, root.appendingPathComponent("敏感信息.md"))
}

@Test func catalogUIProbeReportsMissingSelectionAsUnavailable() async throws {
    let fixture = try catalogUIProbeFixtureURL()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let store = SensitiveCatalogDocumentStore(documentURL: fixture.document)

    #expect(await store.selectedDocumentExists() == false)
    let availability = try await store.adoptionAvailability()
    #expect(availability == SensitiveCatalogAdoptionAvailability())
}

@Test func catalogUIProbeRecognizesManagedV3WithoutMainActorFileRead() async throws {
    let fixture = try catalogUIProbeFixtureURL()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let raw = try SensitiveCatalogDocumentCodec.canonicalData(SecretCatalogDocument())
    try raw.write(to: fixture.document, options: [.atomic])
    let store = SensitiveCatalogDocumentStore(documentURL: fixture.document)

    #expect(await store.selectedDocumentExists())
    let availability = try await store.adoptionAvailability()
    #expect(availability.canAdoptV3)
    #expect(!availability.canAdoptV2)
}

@Test func catalogUIProbeRecognizesManagedV2WithoutMainActorFileRead() async throws {
    let fixture = try catalogUIProbeFixtureURL()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let document = SecretCatalogDocument(
        indexes: [
            SecretCatalogIndex(id: "0123456789ABCDEFGHJKMNPQRS", title: "旧版目录")
        ]
    )
    let raw = Data(try SensitiveCatalogDocumentCodec.encodeV2(document).utf8)
    try raw.write(to: fixture.document, options: [.atomic])
    let store = SensitiveCatalogDocumentStore(documentURL: fixture.document)

    let availability = try await store.adoptionAvailability()
    #expect(availability.canAdoptV2)
    #expect(!availability.canAdoptV3)
}
