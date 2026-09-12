import Foundation
import Testing
import VaultIPC
@testable import VaultService

private func exportCoordinatorFixture() throws -> (root: URL, coordinator: CatalogExportCoordinator) {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-export-coordinator-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
    return (root, CatalogExportCoordinator(root: root))
}

@Test func exportCoordinatorBindsAuthorizationToConfiguredRoot() throws {
    let fixture = try exportCoordinatorFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    #expect(fixture.coordinator.authorizationDestination == fixture.root.standardizedFileURL.path)
    #expect(fixture.coordinator.capability().status == .supported)
    try fixture.coordinator.requireReadyForApproval()
}

@Test func exportCoordinatorValidatesOnlyNewMarkdownOrTextLeavesInsideRoot() throws {
    let fixture = try exportCoordinatorFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let markdown = fixture.root.appendingPathComponent("notes.md")
    #expect(try fixture.coordinator.validatedDestination(markdown.path) == markdown.standardizedFileURL)

    let text = fixture.root.appendingPathComponent("notes.txt")
    #expect(try fixture.coordinator.validatedDestination(text.path) == text.standardizedFileURL)

    do {
        _ = try fixture.coordinator.validatedDestination("relative.md")
        Issue.record("A relative export path was accepted.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .invalidDestination)
    }

    do {
        _ = try fixture.coordinator.validatedDestination(fixture.root.appendingPathComponent("notes.json").path)
        Issue.record("A disallowed export extension was accepted.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .invalidDestination)
    }

    let nested = fixture.root.appendingPathComponent("nested", isDirectory: true)
        .appendingPathComponent("notes.md")
    do {
        _ = try fixture.coordinator.validatedDestination(nested.path)
        Issue.record("A nested export destination escaped the direct-leaf policy.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .destinationNotAllowed)
    }
}

@Test func exportCoordinatorRejectsExistingLeafBeforeApproval() throws {
    let fixture = try exportCoordinatorFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let destination = fixture.root.appendingPathComponent("existing.md")
    try Data("existing".utf8).write(to: destination)

    do {
        _ = try fixture.coordinator.validatedDestination(destination.path)
        Issue.record("An existing export destination was accepted.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .fileAlreadyExists)
    }
}

@Test func exportCoordinatorMapsWriterCommitAndNoOverwriteSemantics() throws {
    let fixture = try exportCoordinatorFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let destination = try fixture.coordinator.validatedDestination(
        fixture.root.appendingPathComponent("export.md").path
    )

    try fixture.coordinator.write(Data("secret material".utf8), to: destination)
    #expect(try String(contentsOf: destination, encoding: .utf8) == "secret material")

    do {
        try fixture.coordinator.write(Data("replacement".utf8), to: destination)
        Issue.record("The export coordinator overwrote an existing plaintext file.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .fileAlreadyExists)
    }
    #expect(try String(contentsOf: destination, encoding: .utf8) == "secret material")
}

@Test func exportCoordinatorFailsClosedForSharedRoot() throws {
    let fixture = try exportCoordinatorFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.root.path)

    #expect(fixture.coordinator.capability().status == .unavailable)
    do {
        try fixture.coordinator.requireReadyForApproval()
        Issue.record("A shared export root was accepted before approval.")
    } catch let error as VaultAppServicesExportError {
        #expect(error == .directorySecurityInvalid)
    }
}
