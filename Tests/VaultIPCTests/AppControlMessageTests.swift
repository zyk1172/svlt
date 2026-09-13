import Foundation
import Testing
import VaultCore
import VaultIPC

private struct ControlService: AppControlServicing {
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

    func repairCatalogFormat(expectedRawSHA256: String) async throws -> CatalogValidationResult {
        _ = expectedRawSHA256
        return CatalogValidationResult(status: .found, revision: 4)
    }

    func catalogFormatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        nil
    }

    func catalogRecentAuditEntries(limit: Int) async throws -> CatalogRecentAuditResult {
        _ = limit
        return CatalogRecentAuditResult(entries: [])
    }

    func catalogAuditHealth() async -> String? { nil }

    func catalogSecureInputRequest(id _: UUID) async throws -> CatalogAgentSecureInputRequest {
        throw AppControlRequestHandlerError.unsupportedRequest
    }

    func submitCatalogSecureInput(
        id: UUID,
        submission: CatalogSecureInputSubmission
    ) async throws -> CatalogSecureInputStatus {
        _ = submission
        return CatalogSecureInputStatus(requestID: id, status: .completed, revision: 4)
    }

    func beginCatalogSecureInputCommit(id _: UUID) async throws -> CatalogAgentSecureInputRequest {
        throw AppControlRequestHandlerError.unsupportedRequest
    }

    func completeCatalogSecureInput(id _: UUID, completion _: CatalogSecureInputCompletion) async {}

    func cancelCatalogSecureInput(id _: UUID) async {}

    func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 1)
    }

    func adoptCatalogExternalV3() async throws -> CatalogValidationResult {
        CatalogValidationResult(status: .found, revision: 1)
    }

    func approveCatalogExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> CatalogValidationResult {
        _ = (expectedRevision, expectedRawSHA256, expectedSemanticSHA256)
        return CatalogValidationResult(status: .found, revision: 2)
    }

    func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        CatalogAgentWriteAuthorizationStatus(mode: mode, expiresAt: Date().addingTimeInterval(duration ?? 600))
    }

    func revokeCatalogAgentWrite() async {}

    func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus {
        CatalogAgentWriteAuthorizationStatus(mode: .disabled, expiresAt: nil)
    }

    func pendingCatalogWriteAccessRequest(id _: UUID) async throws -> CatalogAgentWriteAccessRequest {
        CatalogAgentWriteAccessRequest(
            source: .codex,
            reasonCategory: .knowledgeMaintenance,
            duration: .singleUse
        )
    }

    func respondToCatalogWriteAccessRequest(id _: UUID, approved _: Bool) async throws {}

    func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogCommitEntryEdit(
        _ entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        _ = (entry, secretInputs)
        return CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        CatalogWriteResult(revision: expectedRevision + 1)
    }

    func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64) {
        ("secret://0123456789ABCDEFGHJKMNPQRS", 4)
    }

    func catalogRevealField(entryID: String, key: String) async throws -> String {
        _ = (entryID, key)
        return "ASV_REVEAL_TEST_VALUE"
    }

    func revealSessionData(sessionID: String) async throws -> RestoredParagraph {
        _ = sessionID
        return RestoredParagraph(text: "ASV_SIGNED_APP_REVEAL", values: ["ASV_FIELD_VALUE"])
    }

    func restoreReferences(references: [String], context: RevealContext) async throws -> String {
        _ = (references, context)
        return "ASV_SIGNED_APP_RESTORE"
    }

    func catalogApplyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        _ = mutation
        return CatalogWriteResult(revision: expectedRevision + 1)
    }
}

@Test func appControlMessagesRoundTripWithoutPuttingPlaintextInResponse() async throws {
    let request = AppControlRequest.catalogSecureInput(
        entryID: "0123456789ABCDEFGHJKMNPQRS",
        key: "password",
        label: "QNAP password",
        plaintext: "ASV_APP_CONTROL_CANARY",
        policy: .credential
    )
    let decodedRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(request)
    )
    #expect(decodedRequest == request)

    let bindRequest = AppControlRequest.catalogBindExistingSecret(
        entryID: "0123456789ABCDEFGHJKMNPQRS",
        key: "password",
        secretRef: "secret://0123456789ABCDEFGHJKMNPQRT",
        expectedRevision: 3
    )
    let decodedBindRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(bindRequest)
    )
    #expect(decodedBindRequest == bindRequest)

    let secureInputRequestID = UUID()
    let secureInputRequest = AppControlRequest.catalogSubmitSecureInput(
        id: secureInputRequestID,
        submission: CatalogSecureInputSubmission(
            selectedTargetIDs: ["0123456789ABCDEFGHJKMNPQRT:password"],
            plaintextByFieldKey: ["password": "ASV_SECURE_INPUT_CANARY"]
        )
    )
    let decodedSecureInputRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(secureInputRequest)
    )
    #expect(decodedSecureInputRequest == secureInputRequest)

    let secureInputResponse = await AppControlRequestHandler(service: ControlService()).handle(secureInputRequest)
    #expect(secureInputResponse == .catalogSecureInputStatus(
        CatalogSecureInputStatus(requestID: secureInputRequestID, status: .completed, revision: 4)
    ))
    let encodedSecureInputResponse = String(decoding: try JSONEncoder().encode(secureInputResponse), as: UTF8.self)
    #expect(!encodedSecureInputResponse.contains("ASV_SECURE_INPUT_CANARY"))

    let commitRequest = AppControlRequest.catalogCommitEntryEdit(
        entry: SecretCatalogEntry(
            id: "0123456789ABCDEFGHJKMNPQRT",
            indexId: "0123456789ABCDEFGHJKMNPQRS",
            title: "QNAP",
            fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
        ),
        secretInputs: [CatalogSecretInput(key: "password", label: "密码", plaintext: "ASV_ENTRY_EDIT_CANARY")],
        expectedRevision: 3
    )
    let decodedCommitRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(commitRequest)
    )
    #expect(decodedCommitRequest == commitRequest)

    let approvalRequest = AppControlRequest.catalogApproveExternalChange(
        expectedRevision: 7,
        expectedRawSHA256: String(repeating: "a", count: 64),
        expectedSemanticSHA256: String(repeating: "b", count: 64)
    )
    let decodedApprovalRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(approvalRequest)
    )
    #expect(decodedApprovalRequest == approvalRequest)

    let response = await AppControlRequestHandler(service: ControlService()).handle(request)
    let encoded = String(decoding: try JSONEncoder().encode(response), as: UTF8.self)
    #expect(!encoded.contains("ASV_APP_CONTROL_CANARY"))
    #expect(response == .secretBound(reference: "secret://0123456789ABCDEFGHJKMNPQRS", revision: 4))
}

@Test func catalogPresentationMessagesRoundTripAndRouteSelection() async throws {
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

@Test func plaintextRevealOperationsRoundTripOnlyOnAppControlChannel() async throws {
    let revealRequest = AppControlRequest.revealSessionData(sessionID: "session-1")
    let decodedRevealRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(revealRequest)
    )
    #expect(decodedRevealRequest == revealRequest)

    let restoreRequest = AppControlRequest.restoreReferences(
        references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
        context: RevealContext(
            reason: "restore",
            template: "Token: {{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
        )
    )
    let decodedRestoreRequest = try JSONDecoder().decode(
        AppControlRequest.self,
        from: JSONEncoder().encode(restoreRequest)
    )
    #expect(decodedRestoreRequest == restoreRequest)

    let handler = AppControlRequestHandler(service: ControlService())
    let revealResponse = await handler.handle(revealRequest)
    #expect(revealResponse == .revealSessionData(RestoredParagraph(
        text: "ASV_SIGNED_APP_REVEAL",
        values: ["ASV_FIELD_VALUE"]
    )))

    let restoreResponse = await handler.handle(restoreRequest)
    #expect(restoreResponse == .restoredText("ASV_SIGNED_APP_RESTORE"))

    for response in [revealResponse, restoreResponse] {
        let decodedResponse = try JSONDecoder().decode(
            AppControlResponse.self,
            from: JSONEncoder().encode(response)
        )
        #expect(decodedResponse == response)
    }
}

@Test func appControlPeerIdentityIsInjectedForTests() {
    let authenticator = AppControlPeerAuthenticator(validator: { $0 == 123 })
    #expect(authenticator.isAuthorized(fileDescriptor: 123))
    #expect(!authenticator.isAuthorized(fileDescriptor: 124))
}

@Test func recentAuditResponseRoundTripsSafeReadDiagnostics() throws {
    let result = CatalogRecentAuditResult(
        entries: [CatalogSecurityAuditEntry(
            id: UUID(),
            timestamp: Date(timeIntervalSince1970: 1_900_000_600),
            source: .agent,
            operation: .catalogMutation,
            authorizationOutcome: .notRequired,
            result: .completed,
            target: "catalog",
            referenceCount: 0
        )],
        diagnostics: AuditReadDiagnostics(
            recordDecodeFailureCount: 1,
            authenticationFailureCount: 2,
            eventDecodeFailureCount: 3,
            unsupportedMetadataVersionCount: 4,
            legacyCompatibilityFailureCount: 5
        )
    )
    let response = AppControlResponse.catalogRecentAuditEntries(result)
    let decoded = try JSONDecoder().decode(
        AppControlResponse.self,
        from: JSONEncoder().encode(response)
    )

    #expect(decoded == response)
}

@Test func legacyRecentAuditResponseDefaultsMissingDiagnosticsToNone() throws {
    let legacyResponse = Data(#"{"type":"catalogRecentAuditEntries","entries":[]}"#.utf8)
    let decoded = try JSONDecoder().decode(AppControlResponse.self, from: legacyResponse)

    #expect(decoded == .catalogRecentAuditEntries(CatalogRecentAuditResult(entries: [])))
}
