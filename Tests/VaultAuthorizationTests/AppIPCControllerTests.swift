import Foundation
import Security
import Testing
import VaultAuthorization
import VaultCore
import VaultIPC
import VaultService
@testable import AgentSecretVaultApp

@Test func pendingCatalogWriteQueueConsumesOnlyTheCurrentRequestInFIFOOrder() {
    let requestA = UUID()
    let requestB = UUID()
    let requestC = UUID()
    var queue = PendingCatalogWriteAccessQueue()
    queue.replace(with: [requestA, requestB, requestC])
    #expect(queue.currentID == requestA)
    #expect(queue.count == 3)

    queue.finish(requestA)
    #expect(queue.currentID == requestB)
    #expect(queue.ids == [requestB, requestC])
    queue.finish(requestB)
    #expect(queue.currentID == requestC)
    #expect(queue.count == 1)
    queue.finish(requestC)
    #expect(queue.currentID == nil)
    #expect(queue.ids.isEmpty)
}

@Test func appIPCControllerPublishesEndpointMetadataWithoutSecrets() throws {
    let metadata = AppIPCController.EndpointMetadata(socketPath: "/tmp/asv.sock")
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.withoutEscapingSlashes]
    let encoded = try encoder.encode(metadata)
    let json = String(decoding: encoded, as: UTF8.self)
    #expect(json.contains("/tmp/asv.sock"))
    #expect(!json.contains("capability"))
    #expect(!json.contains("token"))
}

@Test func appControlPeerAuthenticatorPinsTheExpectedBundleAndTeam() throws {
    #expect(AppControlPeerAuthenticator.svltBundleIdentifier == "com.agent-secret-vault.SVLT")
    #expect(AppControlPeerAuthenticator.svltTeamIdentifier == "JUQXD87P93")
    #expect(AppControlPeerAuthenticator.svltDesignatedRequirement.contains(AppControlPeerAuthenticator.svltBundleIdentifier))
    #expect(AppControlPeerAuthenticator.svltDesignatedRequirement.contains(AppControlPeerAuthenticator.svltTeamIdentifier))

    var requirement: SecRequirement?
    #expect(
        SecRequirementCreateWithString(
            AppControlPeerAuthenticator.svltDesignatedRequirement as CFString,
            SecCSFlags(),
            &requirement
        ) == errSecSuccess
    )
}

@Test func appIPCControllerHandlesAuthenticatedFrames() async throws {
    let service = ControllerSpyWorkbenchService()
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-\(UUID().uuidString.prefix(8))")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(
        directoryURL: directoryURL
    ))
    let controller = AppIPCController(server: server, handler: IPCRequestHandler(service: service))
    try controller.start()
    defer {
        controller.stop()
        try? FileManager.default.removeItem(at: directoryURL)
    }

    let token = try CapabilityToken(base64Encoded: String(
        contentsOf: server.configuration.tokenURL,
        encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines))
    let request = AuthenticatedIPCRequest(capabilityToken: token, request: .workbenchStatus)
    let responseFrame = try await controller.handleAuthenticatedFrame(try IPCFrameCodec.encode(request))
    let response = try IPCFrameCodec.decode(IPCResponse.self, from: responseFrame)

    #expect(response == .workbenchStatus(WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: false
    )))
}

@Test func controllerRotatesCapabilityTokenAcrossRestart() async throws {
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-rotate-\(UUID().uuidString)")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(directoryURL: directoryURL))
    let controller = AppIPCController(
        server: server,
        handler: IPCRequestHandler(service: ControllerSpyWorkbenchService())
    )
    defer {
        controller.stop()
        try? FileManager.default.removeItem(at: directoryURL)
    }

    try controller.start()
    let oldToken = try CapabilityToken(base64Encoded: String(contentsOf: server.configuration.tokenURL).trimmingCharacters(in: .whitespacesAndNewlines))
    let oldFrame = try IPCFrameCodec.encode(AuthenticatedIPCRequest(capabilityToken: oldToken, request: .status))

    controller.stop()
    try controller.start()
    let newToken = try CapabilityToken(base64Encoded: String(contentsOf: server.configuration.tokenURL).trimmingCharacters(in: .whitespacesAndNewlines))
    #expect(oldToken != newToken)

    let rejectedFrame = try await controller.handleAuthenticatedFrame(oldFrame)
    #expect(try IPCFrameCodec.decode(IPCResponse.self, from: rejectedFrame) == .failure(code: "INVALID_CAPABILITY_TOKEN"))
}

@Test func controllerRejectsAnUnboundedClientConfiguration() throws {
    let directoryURL = URL(fileURLWithPath: "/tmp/asv-limit-\(UUID().uuidString)")
    let server = UnixSocketServer(configuration: UnixSocketServerConfiguration(directoryURL: directoryURL))
    let controller = AppIPCController(
        server: server,
        handler: IPCRequestHandler(service: ControllerSpyWorkbenchService()),
        maxActiveClients: 0
    )

    #expect(throws: AppIPCControllerError.invalidMaxActiveClients) {
        try controller.start()
    }
    try? FileManager.default.removeItem(at: directoryURL)
}

@Test func appControlIPCUsesRealCatalogStoreAndHMACPathForEntryCreation() async throws {
    // Use the runner-provided per-user temporary volume rather than the
    // shared /tmp mount; hosted macOS runners can service the latter through
    // a provider overlay and trip the Catalog bounded-read timeout.
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-app-control-\(UUID().uuidString.prefix(8))", isDirectory: true)
    let ipcRoot = root.appendingPathComponent("ipc", isDirectory: true)
    let documentURL = root.appendingPathComponent("敏感信息.md")
    let selectionURL = root.appendingPathComponent("selection.json")
    let integrityURL = root.appendingPathComponent("catalog-integrity.json")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let store = SensitiveCatalogDocumentStore(
        documentURL: documentURL,
        integrityURL: integrityURL,
        keyStore: try FixedCatalogIntegrityKeyStore(key: Data(repeating: 11, count: 32))
    )
    try await store.selectDocument(at: documentURL)
    _ = try await store.canonicalWrite(SecretCatalogDocument(
        indexes: [SecretCatalogIndex(id: "0123456789ABCDEFGHJKMNPQRS", title: "QNAP")],
        entries: [SecretCatalogEntry(
            id: "0123456789ABCDEFGHJKMNPQRT",
            indexId: "0123456789ABCDEFGHJKMNPQRS",
            title: "NAS 管理员登录",
            fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("admin")),
                SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
            ]
        )]
    ))
    try SecretCatalogSelectionStore(manifestURL: selectionURL).save(documentURL: documentURL)

    let service = VaultAppServices(
        textEncryptor: IntegrationTextEncryptor(),
        activeRoot: nil,
        catalogDocumentStore: store,
        catalogSelectionManifestURL: selectionURL,
        catalogAgentWriteAuthorization: CatalogAgentWriteAuthorization()
    )
    let configuration = try UnixSocketServerConfiguration.appControlConfiguration(directoryURL: ipcRoot)
    let controller = AppControlIPCController(
        server: UnixSocketServer(configuration: configuration),
        handler: AppControlRequestHandler(service: service),
        peerAuthenticator: AppControlPeerAuthenticator(validator: { _ in true })
    )
    try controller.start()
    defer { controller.stop() }

    let client = AppControlIPCClient(configuration: configuration)
    let result = try await client.catalogCreateEntry(
        CatalogDraftRequest(
            indexID: "0123456789ABCDEFGHJKMNPQRS",
            title: "API Token Entry",
            fields: SensitiveCatalogEntryPreset.all.first(where: { $0.id == "api-token" })?.makeFields() ?? []
        ),
        // Deliberately stale UI revision. App-control must re-read the
        // authoritative store revision and retry this safe creation once.
        expectedRevision: 0
    )

    #expect(result.revision == 2)
    #expect(result.entry?.title == "API Token Entry")
    let verified = try await store.snapshot()
    #expect(verified.revision == 2)
    #expect(verified.integrity == .verified)
    let created = try #require(verified.document.entries.first(where: { $0.title == "API Token Entry" }))
    #expect(created.fields.first(where: { $0.key == "token" })?.secretRef == nil)

    let metadataUpdated = SecretCatalogEntry(
        id: created.id,
        indexId: created.indexId,
        title: created.title,
        type: created.type,
        aliases: created.aliases,
        endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 4533)],
        fields: created.fields.map { field in
            switch field.key {
            case "service":
                return SecretCatalogFieldValue(
                    key: field.key,
                    label: field.label,
                    type: field.type,
                    agentVisible: field.agentVisible,
                    searchable: field.searchable,
                    value: .string("QNAP 音乐服务器")
                )
            case "baseURL":
                return SecretCatalogFieldValue(
                    key: field.key,
                    label: field.label,
                    type: field.type,
                    agentVisible: field.agentVisible,
                    searchable: field.searchable,
                    value: .string("https://192.168.2.240:4533")
                )
            default:
                return field
            }
        },
        notes: "fixture metadata",
        tags: ["QNAP"],
        schema: created.schema
    )
    let updated = try await client.catalogUpdateEntry(metadataUpdated, expectedRevision: result.revision)
    #expect(updated.revision == 3)

    let bound = try await client.catalogSecureInput(
        entryID: created.id,
        key: "token",
        label: "API Key / Token",
        plaintext: "fixture-secret-canary",
        policy: .credential
    )
    #expect(bound.revision == 4)
    #expect(bound.reference.hasPrefix("secret://"))

    let final = try await store.snapshot()
    let finalEntry = try #require(final.document.entries.first(where: { $0.id == created.id }))
    #expect(finalEntry.fields.first(where: { $0.key == "service" })?.value == .string("QNAP 音乐服务器"))
    #expect(finalEntry.fields.first(where: { $0.key == "token" })?.secretRef == bound.reference)

    let presentation = try await client.catalogPresentationState()
    #expect(presentation.selectedDocumentPath == documentURL.standardizedFileURL.path)
    #expect(presentation.snapshot?.revision == final.revision)
    #expect(presentation.snapshot?.document == final.document)

    let selected = try await client.selectCatalogDocument(path: documentURL.path)
    #expect(selected.selectedDocumentPath == documentURL.standardizedFileURL.path)
    #expect(selected.snapshot?.revision == final.revision)

    let missingURL = root.appendingPathComponent("missing.md")
    var missingSelectionRejected = false
    do {
        _ = try await client.selectCatalogDocument(path: missingURL.path)
    } catch {
        missingSelectionRejected = true
    }
    #expect(missingSelectionRejected)
    #expect(try SecretCatalogSelectionStore(manifestURL: selectionURL).selectedDocumentURL() == documentURL.standardizedFileURL)
}

private actor ControllerSpyWorkbenchService: WorkbenchServicing {
    func status() async -> WorkbenchStatus {
        WorkbenchStatus(locked: false, ipcAvailable: true, activeKnowledgeBaseRoot: nil, pluginConnected: false)
    }

    func inspectReference(_ reference: String) async throws -> SecretReferenceMetadata {
        SecretReferenceMetadata(
            reference: reference,
            policy: .read,
            label: nil,
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )
    }

    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> String {
        "secret://0123456789ABCDEFGHJKMNPQRS"
    }

    func openRevealSession(references: [String], context: RevealContext) async throws -> String {
        "session-1"
    }

    func exportResolvedText(
        references: [String],
        context: RevealContext,
        destinationPath: String
    ) async throws -> String {
        destinationPath
    }

    func scanOrphans(markdownReferences: [String]) async throws -> OrphanScanResult {
        OrphanScanResult(missingRecords: [], unreferencedRecords: [])
    }
}

private struct IntegrationTextEncryptor: TextEncrypting {
    func encryptText(_ plaintext: String, label: String?, policy: SecretPolicy) async throws -> SecretReference {
        try SecretReference("secret://0123456789ABCDEFGHJKMNPQRT")
    }
}
