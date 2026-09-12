from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one anchor, found {count}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


def regex_once(path: str, pattern: str, replacement: str) -> None:
    p = Path(path)
    text = p.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: regex anchor count={count}: {pattern[:100]!r}")
    p.write_text(updated)


store = "Sources/VaultService/SensitiveCatalogDocumentStore.swift"
replace_once(store, "    private func validationReportUnlocked() throws -> CatalogValidationReport {", "    func validationReportUnlocked() throws -> CatalogValidationReport {")
replace_once(store, "    private func snapshotUnlocked() throws -> SensitiveCatalogSnapshot {", "    func snapshotUnlocked() throws -> SensitiveCatalogSnapshot {")
replace_once(store, "    private func withCatalogLock<T>(exclusive: Bool, _ operation: () throws -> T) throws -> T {", "    func withCatalogLock<T>(exclusive: Bool, _ operation: () throws -> T) throws -> T {")

operation_file = "Sources/VaultService/SensitiveCatalogDocumentStore+Operation.swift"
p = Path(operation_file)
text = p.read_text()
if "struct SensitiveCatalogPresentationProjection" in text:
    raise SystemExit("presentation projection already installed")
text = text.replace(
    "import VaultAuthorization\n\n",
    "import VaultAuthorization\n\nstruct SensitiveCatalogPresentationProjection: Sendable {\n    let validation: CatalogValidationReport\n    let snapshot: SensitiveCatalogSnapshot?\n}\n\n",
    1,
)
anchor = """    internal func makeOperationStore(documentURL: URL) -> SensitiveCatalogDocumentStore {
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
}"""
replacement = """    internal func makeOperationStore(documentURL: URL) -> SensitiveCatalogDocumentStore {
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

    /// Produces validation and the accepted document projection while holding
    /// one Catalog lock, so revisions from different on-disk states cannot be
    /// combined into one UI response.
    internal func presentationProjection() throws -> SensitiveCatalogPresentationProjection {
        try withCatalogLock(exclusive: true) {
            let snapshot: SensitiveCatalogSnapshot?
            do {
                let value = try snapshotUnlocked()
                snapshot = value.integrity == .verified ? value : nil
            } catch let error as SensitiveCatalogDocumentStoreError {
                switch error {
                case .legacyCatalogUnsupported,
                     .integrityMissing,
                     .externalModification,
                     .pendingExternalChange,
                     .malformedDocument,
                     .invalidIntegrity:
                    snapshot = nil
                default:
                    throw error
                }
            }

            let validation = try validationReportUnlocked()
            if let snapshot {
                guard validation.status == .found,
                      validation.revision == snapshot.revision
                else {
                    throw SensitiveCatalogDocumentStoreError.invalidIntegrity
                }
            }
            return SensitiveCatalogPresentationProjection(validation: validation, snapshot: snapshot)
        }
    }
}"""
if text.count(anchor) != 1:
    raise SystemExit("operation extension anchor mismatch")
p.write_text(text.replace(anchor, replacement, 1))

owner = "Sources/VaultService/CatalogDocumentOwner.swift"
replace_once(
    owner,
    """struct CatalogDocumentOperation: Sendable {
    private let owner: CatalogDocumentOwner
    private let id: UUID

    fileprivate init(owner: CatalogDocumentOwner, id: UUID) {
        self.owner = owner
        self.id = id
    }""",
    """struct CatalogDocumentOperation: Sendable {
    private let owner: CatalogDocumentOwner
    private let id: UUID
    let selectedDocumentPath: String

    fileprivate init(owner: CatalogDocumentOwner, id: UUID, selectedDocumentURL: URL) {
        self.owner = owner
        self.id = id
        self.selectedDocumentPath = selectedDocumentURL.standardizedFileURL.path
    }""",
)
regex_once(
    owner,
    r"    /// Captures the authoritative selection and creates a Store whose target\n    /// can no longer be changed by selection IPC\. The Store remains in this\n    /// actor; callers receive only the operation capability\.\n    func beginOperation\(\) async throws -> CatalogDocumentOperation \{.*?\n    \}\n\n    func endOperation\(id: UUID\) \{",
    """    /// Captures the authoritative selection and creates a Store whose target
    /// can no longer be changed by selection IPC. The Store remains in this
    /// actor; callers receive only the operation capability.
    func beginOperation() async throws -> CatalogDocumentOperation {
        guard let selectedURL = try await authoritativeSelectedDocumentURL() else {
            throw SecretCatalogAgentError.unavailable
        }
        return await beginOperation(documentURL: selectedURL)
    }

    /// Rehydrates a captured document identity without retaining a live Store
    /// while a user-facing draft or repair plan is idle.
    func beginOperation(documentPath: String) async throws -> CatalogDocumentOperation {
        guard documentPath.hasPrefix("/"), !documentPath.contains("\\0") else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return await beginOperation(documentURL: URL(fileURLWithPath: documentPath).standardizedFileURL)
    }

    private func beginOperation(documentURL: URL) async -> CatalogDocumentOperation {
        let id = UUID()
        let operationStore = await store.makeOperationStore(documentURL: documentURL)
        operations[id] = ActiveOperation(selectedDocumentURL: documentURL, store: operationStore)
        return CatalogDocumentOperation(owner: self, id: id, selectedDocumentURL: documentURL)
    }

    func endOperation(id: UUID) {""",
)
regex_once(
    owner,
    r"    fileprivate func presentationState\(for id: UUID\) async -> CatalogPresentationState \{.*?\n    \}\n\n    private func validationResult",
    """    fileprivate func presentationState(for id: UUID) async -> CatalogPresentationState {
        guard let operation = try? activeOperation(for: id) else {
            return CatalogPresentationState(validation: CatalogValidationResult(status: .unavailable))
        }

        do {
            let projection = try await operation.store.presentationProjection()
            let report = projection.validation
            let validation = CatalogValidationResult(
                status: report.status,
                revision: report.revision,
                rawSHA256: report.rawSHA256,
                pendingExternalChange: report.pendingExternalChange,
                diagnostics: report.diagnostics
            )
            var canAdoptV2 = false
            var canAdoptV3 = false
            if report.status == .integrityMissing,
               let availability = try? await operation.store.adoptionAvailability() {
                canAdoptV2 = availability.canAdoptV2
                canAdoptV3 = availability.canAdoptV3
            }
            let snapshot = projection.snapshot.map {
                CatalogPresentationSnapshot(document: $0.document, revision: $0.revision)
            }
            return CatalogPresentationState(
                selectedDocumentPath: operation.selectedDocumentURL.path,
                validation: validation,
                snapshot: snapshot,
                canAdoptV2: canAdoptV2,
                canAdoptV3: canAdoptV3
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            return CatalogPresentationState(
                selectedDocumentPath: operation.selectedDocumentURL.path,
                validation: validationResult(for: error)
            )
        } catch {
            return CatalogPresentationState(
                selectedDocumentPath: operation.selectedDocumentURL.path,
                validation: CatalogValidationResult(status: .unavailable)
            )
        }
    }

    private func validationResult""",
)

services = "Sources/VaultService/VaultAppServices.swift"
replace_once(
    services,
    """    private var pendingCatalogDrafts: [String: SecretCatalogEntry] = [:]
    private var pendingCatalogDraftOperations: [String: CatalogDocumentOperation] = [:]
    private var catalogFormatRepairOperations: [String: CatalogDocumentOperation] = [:]""",
    """    private var pendingCatalogDrafts: [String: SecretCatalogEntry] = [:]
    private var pendingCatalogDraftDocumentPaths: [String: String] = [:]
    private var catalogFormatRepairDocumentPaths: [String: String] = [:]""",
)
replace_once(
    services,
    """            pendingCatalogDraftOperations[draftID] = operation
            return CatalogDraft(draftID: draftID, baseRevision: snapshot.revision, entry: match.entry)""",
    """            pendingCatalogDraftDocumentPaths[draftID] = operation.selectedDocumentPath
            await endCatalogOperation(operation)
            return CatalogDraft(draftID: draftID, baseRevision: snapshot.revision, entry: match.entry)""",
)
replace_once(
    services,
    """        let operation: CatalogDocumentOperation
        let operationWasRetained: Bool
        if let retained = pendingCatalogDraftOperations[draft.draftID] {
            operation = retained
            operationWasRetained = true
        } else {
            operation = try await beginCatalogOperation()
            operationWasRetained = false
        }""",
    """        let operation: CatalogDocumentOperation
        if let documentPath = pendingCatalogDraftDocumentPaths[draft.draftID] {
            operation = try await beginCatalogOperation(documentPath: documentPath)
        } else {
            operation = try await beginCatalogOperation()
        }""",
)
replace_once(services, "pendingCatalogDraftOperations.removeValue(forKey: draft.draftID)", "pendingCatalogDraftDocumentPaths.removeValue(forKey: draft.draftID)")
replace_once(
    services,
    """        } catch let error as SensitiveCatalogDocumentStoreError {
            if !operationWasRetained {
                await endCatalogOperation(operation)
            }
            throw catalogAgentError(for: error)
        } catch {
            if !operationWasRetained {
                await endCatalogOperation(operation)
            }
            throw error
        }
    }

    public func addCatalogSecretPlaceholder(""",
    """        } catch let error as SensitiveCatalogDocumentStoreError {
            await endCatalogOperation(operation)
            throw catalogAgentError(for: error)
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    public func addCatalogSecretPlaceholder(""",
)
replace_once(
    services,
    """            let plan = try await operation.formatRepairPlan()
            if let plan, plan.canRepair {
                catalogFormatRepairOperations[plan.currentRawSHA256] = operation
            } else {
                await endCatalogOperation(operation)
            }""",
    """            let plan = try await operation.formatRepairPlan()
            catalogFormatRepairDocumentPaths.removeAll(keepingCapacity: true)
            if let plan, plan.canRepair {
                catalogFormatRepairDocumentPaths[plan.currentRawSHA256] = operation.selectedDocumentPath
            }
            await endCatalogOperation(operation)""",
)
replace_once(
    services,
    """        let operation: CatalogDocumentOperation
        if let retained = catalogFormatRepairOperations.removeValue(forKey: expectedRawSHA256) {
            operation = retained
        } else {
            operation = try await beginCatalogOperation()
        }""",
    """        let operation: CatalogDocumentOperation
        if let documentPath = catalogFormatRepairDocumentPaths.removeValue(forKey: expectedRawSHA256) {
            operation = try await beginCatalogOperation(documentPath: documentPath)
        } else {
            operation = try await beginCatalogOperation()
        }""",
)
replace_once(
    services,
    """    private func beginCatalogOperation() async throws -> CatalogDocumentOperation {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        return try await catalogDocumentOwner.beginOperation()
    }

    private func endCatalogOperation""",
    """    private func beginCatalogOperation() async throws -> CatalogDocumentOperation {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        return try await catalogDocumentOwner.beginOperation()
    }

    private func beginCatalogOperation(documentPath: String) async throws -> CatalogDocumentOperation {
        guard let catalogDocumentOwner else {
            throw SecretCatalogAgentError.unavailable
        }
        return try await catalogDocumentOwner.beginOperation(documentPath: documentPath)
    }

    private func endCatalogOperation""",
)

Path("scripts/check-catalog-owner-boundary.sh").write_text("""#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/Sources/AgentSecretVaultApp"

mapfile -d '' swift_files < <(find "$RUNTIME_DIR" -type f -name '*.swift' -print0)
if [ "${#swift_files[@]}" -eq 0 ]; then
  echo "No GUI Swift sources found under $RUNTIME_DIR" >&2
  exit 1
fi

for forbidden in \
  'SensitiveCatalogDocumentStore' \
  'SensitiveInformationDocumentStore' \
  'SensitiveIndexSelectionStore' \
  'SecretCatalogSelectionStore'; do
  if grep -nFH "$forbidden" "${swift_files[@]}"; then
    echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden owner symbol: $forbidden" >&2
    exit 1
  fi
done

echo "Catalog ownership boundary verified across the complete GUI target."
""")

tests = Path("Tests/VaultAuthorizationTests/CatalogDocumentOwnerConcurrencyTests.swift")
test_text = tests.read_text()
if "catalogOperationIdentityCanBeRehydratedWithoutRetainingLiveStore" in test_text:
    raise SystemExit("rehydration test already installed")
test_text += """

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
"""
tests.write_text(test_text)
