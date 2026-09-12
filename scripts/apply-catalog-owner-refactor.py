from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one exact match, found {count}: {old[:100]!r}")
    write(path, text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    text = read(path)
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise RuntimeError(f"{path}: expected one regex match, found {count}: {pattern}")
    write(path, updated)


# ---------------------------------------------------------------------------
# VaultIPC: a non-secret presentation projection + daemon-owned selection API.
# ---------------------------------------------------------------------------
message_path = "Sources/VaultIPC/AppControlMessage.swift"
replace_once(
    message_path,
    "import Foundation\nimport VaultCore\n\npublic enum AppControlRequest",
    '''import Foundation
import VaultCore

public struct CatalogPresentationSnapshot: Codable, Equatable, Sendable {
    public let document: SecretCatalogDocument
    public let revision: UInt64

    public init(document: SecretCatalogDocument, revision: UInt64) {
        self.document = document
        self.revision = revision
    }
}

public struct CatalogPresentationState: Codable, Equatable, Sendable {
    public let selectedDocumentPath: String?
    public let validation: CatalogValidationResult
    public let snapshot: CatalogPresentationSnapshot?
    public let canAdoptV2: Bool
    public let canAdoptV3: Bool

    public init(
        selectedDocumentPath: String? = nil,
        validation: CatalogValidationResult,
        snapshot: CatalogPresentationSnapshot? = nil,
        canAdoptV2: Bool = false,
        canAdoptV3: Bool = false
    ) {
        self.selectedDocumentPath = selectedDocumentPath
        self.validation = validation
        self.snapshot = snapshot
        self.canAdoptV2 = canAdoptV2
        self.canAdoptV3 = canAdoptV3
    }
}

public enum AppControlRequest''',
)
replace_once(
    message_path,
    "public enum AppControlRequest: Codable, Equatable, Sendable {\n    case catalogStatus\n",
    "public enum AppControlRequest: Codable, Equatable, Sendable {\n    case catalogStatus\n    case catalogPresentationState\n    case catalogSelectDocument(path: String)\n",
)
replace_once(message_path, "        case type\n        case duration\n", "        case type\n        case path\n        case duration\n")
replace_once(
    message_path,
    "    private enum RequestType: String, Codable {\n        case catalogStatus\n",
    "    private enum RequestType: String, Codable {\n        case catalogStatus\n        case catalogPresentationState\n        case catalogSelectDocument\n",
)
replace_once(
    message_path,
    "        case .catalogStatus:\n            self = .catalogStatus\n        case .catalogFormatRepairPlan:\n",
    "        case .catalogStatus:\n            self = .catalogStatus\n        case .catalogPresentationState:\n            self = .catalogPresentationState\n        case .catalogSelectDocument:\n            self = .catalogSelectDocument(path: try container.decode(String.self, forKey: .path))\n        case .catalogFormatRepairPlan:\n",
)
replace_once(
    message_path,
    "        case .catalogStatus:\n            try container.encode(RequestType.catalogStatus, forKey: .type)\n        case .catalogFormatRepairPlan:\n",
    "        case .catalogStatus:\n            try container.encode(RequestType.catalogStatus, forKey: .type)\n        case .catalogPresentationState:\n            try container.encode(RequestType.catalogPresentationState, forKey: .type)\n        case let .catalogSelectDocument(path):\n            try container.encode(RequestType.catalogSelectDocument, forKey: .type)\n            try container.encode(path, forKey: .path)\n        case .catalogFormatRepairPlan:\n",
)
replace_once(
    message_path,
    "public enum AppControlResponse: Codable, Equatable, Sendable {\n    case catalogStatus(CatalogValidationResult)\n",
    "public enum AppControlResponse: Codable, Equatable, Sendable {\n    case catalogStatus(CatalogValidationResult)\n    case catalogPresentationState(CatalogPresentationState)\n",
)
replace_once(
    message_path,
    "    private enum ResponseType: String, Codable {\n        case catalogStatus\n",
    "    private enum ResponseType: String, Codable {\n        case catalogStatus\n        case catalogPresentationState\n",
)
replace_once(
    message_path,
    "        case .catalogStatus:\n            self = .catalogStatus(try container.decode(CatalogValidationResult.self, forKey: .status))\n        case .catalogFormatRepairPlan:\n",
    "        case .catalogStatus:\n            self = .catalogStatus(try container.decode(CatalogValidationResult.self, forKey: .status))\n        case .catalogPresentationState:\n            self = .catalogPresentationState(try container.decode(CatalogPresentationState.self, forKey: .result))\n        case .catalogFormatRepairPlan:\n",
)
replace_once(
    message_path,
    "        case let .catalogStatus(status):\n            try container.encode(ResponseType.catalogStatus, forKey: .type)\n            try container.encode(status, forKey: .status)\n        case let .catalogFormatRepairPlan(plan):\n",
    "        case let .catalogStatus(status):\n            try container.encode(ResponseType.catalogStatus, forKey: .type)\n            try container.encode(status, forKey: .status)\n        case let .catalogPresentationState(state):\n            try container.encode(ResponseType.catalogPresentationState, forKey: .type)\n            try container.encode(state, forKey: .result)\n        case let .catalogFormatRepairPlan(plan):\n",
)
replace_once(
    message_path,
    "public protocol AppControlServicing: Sendable {\n    func catalogStatus() async throws -> CatalogValidationResult\n",
    "public protocol AppControlServicing: Sendable {\n    func catalogStatus() async throws -> CatalogValidationResult\n    func catalogPresentationState() async -> CatalogPresentationState\n    func selectCatalogDocument(path: String) async throws -> CatalogPresentationState\n",
)

handler_path = "Sources/VaultIPC/AppControlRequestHandler.swift"
replace_once(
    handler_path,
    "            case .catalogStatus:\n                return .catalogStatus(try await service.catalogStatus())\n            case .catalogFormatRepairPlan:\n",
    "            case .catalogStatus:\n                return .catalogStatus(try await service.catalogStatus())\n            case .catalogPresentationState:\n                return .catalogPresentationState(await service.catalogPresentationState())\n            case let .catalogSelectDocument(path):\n                return .catalogPresentationState(try await service.selectCatalogDocument(path: path))\n            case .catalogFormatRepairPlan:\n",
)

client_path = "Sources/VaultIPC/AppControlIPCClient.swift"
replace_once(
    client_path,
    '''    public func catalogStatus() async throws -> CatalogValidationResult {
        let response = try await send(.catalogStatus)
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

''',
    '''    public func catalogStatus() async throws -> CatalogValidationResult {
        let response = try await send(.catalogStatus)
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func catalogPresentationState() async throws -> CatalogPresentationState {
        let response = try await send(.catalogPresentationState)
        guard case let .catalogPresentationState(state) = response else { throw unexpected(response) }
        return state
    }

    public func selectCatalogDocument(path: String) async throws -> CatalogPresentationState {
        let response = try await send(.catalogSelectDocument(path: path))
        guard case let .catalogPresentationState(state) = response else { throw unexpected(response) }
        return state
    }

''',
)

# ---------------------------------------------------------------------------
# VaultService: one daemon-side owner for selection + mutating snapshot reads.
# ---------------------------------------------------------------------------
owner_path = "Sources/VaultService/CatalogDocumentOwner.swift"
write(
    owner_path,
    '''import Foundation
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
        guard path.hasPrefix("/"), !path.contains("\\0") else {
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
''',
)

services_path = "Sources/VaultService/VaultAppServices.swift"
replace_once(
    services_path,
    "    private let catalogDocumentStore: SensitiveCatalogDocumentStore?\n    private let catalogSelectionStore: SecretCatalogSelectionStore?\n",
    "    private let catalogDocumentStore: SensitiveCatalogDocumentStore?\n    private let catalogSelectionStore: SecretCatalogSelectionStore?\n    let catalogDocumentOwner: CatalogDocumentOwner?\n",
)
replace_once(
    services_path,
    "        self.catalogDocumentStore = catalogDocumentStore\n        self.catalogSelectionStore = catalogSelectionManifestURL.map(SecretCatalogSelectionStore.init(manifestURL:))\n        self.catalogSearchService = SecretCatalogEntrySearchService()\n",
    '''        self.catalogDocumentStore = catalogDocumentStore
        let catalogSelectionStore = catalogSelectionManifestURL.map(SecretCatalogSelectionStore.init(manifestURL:))
        self.catalogSelectionStore = catalogSelectionStore
        self.catalogDocumentOwner = catalogDocumentStore.map {
            CatalogDocumentOwner(store: $0, selectionStore: catalogSelectionStore)
        }
        self.catalogSearchService = SecretCatalogEntrySearchService()
''',
)
regex_once(
    services_path,
    r"    private func selectedCatalogStoreForApp\(\) async throws -> SensitiveCatalogDocumentStore \{.*?\n    \}\n\n    /// Keep App-control errors stable",
    '''    private func selectedCatalogStoreForApp() async throws -> SensitiveCatalogDocumentStore {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        do {
            return try await catalogDocumentOwner.selectedStore()
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch let error as SensitiveCatalogDocumentStoreError {
            Self.logCatalogMutationFailure(operation: "catalog-snapshot", phase: .snapshot, error: error)
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
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        } catch {
            throw SecretCatalogAgentError.unavailable
        }
    }

    /// Keep App-control errors stable''',
)
regex_once(
    services_path,
    r"    private func catalogSnapshotForAgent\(\) async throws -> SensitiveCatalogSnapshot \{.*?\n    \}\n\n    /// Resolves the selected document",
    '''    private func catalogSnapshotForAgent() async throws -> SensitiveCatalogSnapshot {
        let catalogDocumentStore = try await selectedCatalogStoreForApp()
        do {
            let snapshot = try await catalogDocumentStore.snapshot()
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

    /// Resolves the selected document''',
)
regex_once(
    services_path,
    r"    private func catalogFilePreflightForAgent\(\) async throws -> CatalogFilePreflight \{.*?\n    \}\n",
    '''    private func catalogFilePreflightForAgent() async throws -> CatalogFilePreflight {
        let catalogDocumentStore = try await selectedCatalogStoreForApp()
        return try await catalogDocumentStore.preflightFileAccess()
    }
''',
)

# ---------------------------------------------------------------------------
# GUI: no managed Catalog store or selection manifest ownership.
# ---------------------------------------------------------------------------
app_path = "Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift"
replace_once(
    app_path,
    "    private var sensitiveIndexStore: SensitiveInformationDocumentStore?\n    private var sensitiveCatalogStore: SensitiveCatalogDocumentStore?\n",
    "",
)
replace_once(
    app_path,
    '''            try? catalogTemplateStore.ensureInstalled()
            sensitiveIndexStore = try makeSensitiveIndexStore()
            sensitiveCatalogStore = try makeSensitiveCatalogStore()
            guard let sensitiveIndexStore else {
                throw AgentSecretVaultRuntimeError.notStarted
            }
            let existingDocumentURL = await sensitiveIndexStore.selectedExistingDocumentURL()
            sensitiveIndexURL = existingDocumentURL
            if let documentURL = existingDocumentURL {
                // A missing previously selected file is not recreated on
                // startup. The user must explicitly choose an existing file.
                SensitiveIndexSelectionStore.save(documentURL)
                persistCatalogSelection(at: documentURL)
                sensitiveIndexURL = documentURL
            }

            await refreshSensitiveCatalog()
''',
    '''            try? catalogTemplateStore.ensureInstalled()
            await refreshSensitiveCatalog()
''',
)
regex_once(
    app_path,
    r"    func refreshSensitiveCatalog\(\) async \{.*?\n    func adoptExternalV2Catalog\(\) async \{",
    '''    func refreshSensitiveCatalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法读取敏感信息目录"
            return
        }
        do {
            applyCatalogPresentationState(try await appControlClient.catalogPresentationState())
        } catch {
            // Keep the last successful projection on transient IPC failure.
            sensitiveIndexError = "无法读取敏感信息目录"
        }
    }

    private func applyCatalogPresentationState(_ state: CatalogPresentationState) {
        sensitiveIndexURL = state.selectedDocumentPath.map {
            URL(fileURLWithPath: $0).standardizedFileURL
        }
        sensitiveCatalogCanAdoptV2 = state.canAdoptV2
        sensitiveCatalogCanAdoptV3 = state.canAdoptV3
        sensitiveCatalogSnapshot = state.snapshot.map {
            SensitiveCatalogSnapshot(
                document: $0.document,
                revision: $0.revision,
                integrity: .verified
            )
        }

        switch state.validation.status {
        case .found:
            sensitiveIndexError = nil
        case .legacyCatalogUnsupported:
            sensitiveIndexError = "当前敏感信息.md 是旧版格式。SVLT 不提供自动升级，请先备份并手动转换为 Catalog v3。"
        case .integrityMissing:
            sensitiveIndexError = state.canAdoptV3
                ? "检测到合法但尚未建立本机 accepted state 的 v3 文件，请验证并接纳。"
                : "检测到合法但尚未被 SVLT 接管的 v2 文件，请验证并升级为 v3。"
        case .externalModification:
            sensitiveIndexError = "检测到目录被外部修改，已暂停使用"
        case .pendingExternalChange:
            sensitiveIndexError = "目录存在待审批的高风险外部变更，已暂停使用"
        case .invalidCatalog:
            sensitiveIndexError = "敏感信息目录校验失败，未继续使用"
        case .notFound:
            sensitiveIndexError = "已选择的敏感信息目录文件不存在"
        case .unavailable:
            sensitiveIndexError = state.selectedDocumentPath == nil
                ? nil
                : "敏感信息目录当前不可用"
        case .invalidQuery:
            sensitiveIndexError = "敏感信息目录当前不可用"
        }
    }

    func validateSensitiveCatalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法验证敏感信息目录"
            return
        }
        do {
            _ = try await appControlClient.catalogStatus()
            applyCatalogPresentationState(try await appControlClient.catalogPresentationState())
        } catch {
            sensitiveIndexError = "无法验证敏感信息目录"
        }
    }

    func adoptExternalV2Catalog() async {''',
)
regex_once(
    app_path,
    r"    private func activateSensitiveIndex\(at url: URL\) async \{.*?\n    private func makeSensitiveIndexStore\(\) throws -> SensitiveInformationDocumentStore \{.*?\n    \}\n\n    private func makeSensitiveCatalogStore\(\) throws -> SensitiveCatalogDocumentStore \{.*?\n    \}\n\n    private func persistCatalogSelection\(at url: URL\) \{.*?\n    \}\n",
    '''    private func activateSensitiveIndex(at url: URL) async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法切换敏感信息目录"
            return
        }
        do {
            let state = try await appControlClient.selectCatalogDocument(path: url.path)
            applyCatalogPresentationState(state)
            await refreshSavedReferences()
        } catch {
            sensitiveIndexError = "所选文件不是有效的敏感信息.md"
        }
    }
''',
)
replace_once(
    app_path,
    '''
private enum AgentSecretVaultRuntimeError: Error {
    case notStarted
}

''',
    "\n",
)

# ---------------------------------------------------------------------------
# Regression tests for the protocol and real App-control daemon boundary.
# ---------------------------------------------------------------------------
ipc_tests = "Tests/VaultIPCTests/AppControlMessageTests.swift"
replace_once(
    ipc_tests,
    '''private struct ControlService: AppControlServicing {
    func catalogStatus() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 3)
    }

''',
    '''private struct ControlService: AppControlServicing {
    func catalogStatus() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 3)
    }

    func catalogPresentationState() async -> CatalogPresentationState {
        CatalogPresentationState(
            selectedDocumentPath: "/tmp/sensitive.md",
            validation: CatalogValidationResult(status: .found, revision: 3),
            snapshot: CatalogPresentationSnapshot(
                document: SecretCatalogDocument(indexes: [], entries: []),
                revision: 3
            )
        )
    }

    func selectCatalogDocument(path: String) async throws -> CatalogPresentationState {
        CatalogPresentationState(
            selectedDocumentPath: path,
            validation: CatalogValidationResult(status: .found, revision: 3),
            snapshot: CatalogPresentationSnapshot(
                document: SecretCatalogDocument(indexes: [], entries: []),
                revision: 3
            )
        )
    }

''',
)
insert_anchor = "@Test func plaintextRevealOperationsRoundTripOnlyOnAppControlChannel() async throws {"
replace_once(
    ipc_tests,
    insert_anchor,
    '''@Test func catalogPresentationMessagesRoundTripAndRouteSelection() async throws {
    let path = "/tmp/managed-sensitive.md"
    let request = AppControlRequest.catalogSelectDocument(path: path)
    let decodedRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(request)
    )
    #expect(decodedRequest == request)

    let handler = AppControlRequestHandler(service: ControlService())
    let response = await handler.handle(request)
    guard case let .catalogPresentationState(state) = response else {
        Issue.record("Expected Catalog presentation state")
        return
    }
    #expect(state.selectedDocumentPath == path)
    #expect(state.snapshot?.revision == 3)

    let decodedResponse = try JSONDecoder().decode(
        AppControlResponse.self,
        from: JSONEncoder().encode(response)
    )
    #expect(decodedResponse == response)
}

@Test func plaintextRevealOperationsRoundTripOnlyOnAppControlChannel() async throws {''',
)

auth_tests = "Tests/VaultAuthorizationTests/AppIPCControllerTests.swift"
replace_once(
    auth_tests,
    '''    let final = try await store.snapshot()
    let finalEntry = try #require(final.document.entries.first(where: { $0.id == created.id }))
    #expect(finalEntry.fields.first(where: { $0.key == "service" })?.value == .string("QNAP 音乐服务器"))
    #expect(finalEntry.fields.first(where: { $0.key == "token" })?.secretRef == bound.reference)
}
''',
    '''    let final = try await store.snapshot()
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
''',
)

# ---------------------------------------------------------------------------
# Architecture guard: the GUI entry point must not regain managed Store state.
# ---------------------------------------------------------------------------
guard_path = "scripts/check-catalog-owner-boundary.sh"
write(
    guard_path,
    '''#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="$ROOT_DIR/Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift"

for forbidden in \
  'SensitiveCatalogDocumentStore' \
  'SensitiveInformationDocumentStore' \
  'SensitiveIndexSelectionStore' \
  'SecretCatalogSelectionStore'; do
  if grep -nF "$forbidden" "$RUNTIME"; then
    echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden owner symbol: $forbidden" >&2
    exit 1
  fi
done

echo "Catalog ownership boundary verified: GUI runtime has no managed Catalog store or selection owner."
''',
)

ci_path = ".github/workflows/ci.yml"
replace_once(
    ci_path,
    '''      - name: Enforce large-file architecture budgets
        run: bash scripts/check-architecture-budgets.sh
      - name: Check whitespace
''',
    '''      - name: Enforce large-file architecture budgets
        run: bash scripts/check-architecture-budgets.sh
      - name: Enforce daemon-owned Catalog state
        run: bash scripts/check-catalog-owner-boundary.sh
      - name: Check whitespace
''',
)

# Freeze the now-lower VaultAppServices ceiling rather than allowing this
# architecture refactor to create fresh room for the monolith to grow back.
budget_path = "scripts/check-architecture-budgets.sh"
services_size = (ROOT / services_path).stat().st_size
if services_size > 255_049:
    raise RuntimeError(
        f"VaultAppServices grew from the audited 255049-byte ceiling to {services_size}; extract more instead"
    )
replace_once(
    budget_path,
    '  "Sources/VaultService/VaultAppServices.swift:255049"\n',
    f'  "Sources/VaultService/VaultAppServices.swift:{services_size}"\n',
)

print(f"Catalog owner refactor staged; VaultAppServices ceiling -> {services_size} bytes")
