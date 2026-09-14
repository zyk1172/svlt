import Foundation
import Darwin
import Testing
import VaultAuthorization
import VaultCore
import VaultExecution
@testable import VaultIPC

private let testIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let testEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let testSecretReference = "secret://0123456789ABCDEFGHJKMNPQRS"
private let testSemanticReviewID = UUID(uuidString: "00000000-0000-4000-8000-000000000086")!

private func ipcTestSSHHostKeyPin(byte: UInt8 = 0x41) throws -> SSHHostKeyPin {
    try SSHHostKeyPin(
        algorithm: "ssh-ed25519",
        sha256: "SHA256:" + Data(repeating: byte, count: 32).base64EncodedString().replacingOccurrences(of: "=", with: "")
    )
}

private func sampleCatalogMatch() -> SecretCatalogMatch {
    SecretCatalogMatch(
        index: SecretCatalogIndexMatch(
            id: testIndexID,
            title: "QNAP",
            aliases: ["NAS"],
            tags: ["设备"]
        ),
        entry: SecretCatalogEntryMatch(
            id: testEntryID,
            indexId: testIndexID,
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: ["QNAP 登录"],
            endpoints: [CatalogEndpoint(type: "https", host: "192.168.2.240", port: 443)],
            fields: [
                SecretCatalogFieldMatch(
                    key: "username",
                    label: "用户名",
                    type: .text,
                    value: .string("admin")
                ),
                SecretCatalogFieldMatch(
                    key: "password",
                    label: "密码",
                    type: .secret,
                    secretRef: testSecretReference
                )
            ],
            notes: "管理后台",
            tags: ["QNAP"]
        )
    )
}

@Test func requestJSONRoundTripsEveryCase() throws {
    let pin = try ipcTestSSHHostKeyPin()
    let operationDescriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
        destination: "qnap.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        requestedEffects: ["read-only"],
        parameters: ["passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS"],
        reviewID: testSemanticReviewID,
        agentAssessment: AgentRiskAssessment(
            declaredRisk: .silent,
            reason: "read-only diagnostic",
            intendedEffect: "read status"
        )
    )
    let requests: [IPCRequest] = [
        .status,
        .workbenchStatus,
        .sshSessionStatus(sessionID: nil),
        .sshSessionStatus(sessionID: "ssh_session_test"),
        .sshSessionClose(sessionID: "ssh_session_test"),
        .savedReferences,
        .searchCatalog(query: "QNAP", field: .password, limit: 10),
        .catalogSearch(query: "Komga", field: nil, limit: 20),
        .catalogGet(entryID: testEntryID),
        .catalogListIndexes,
        .catalogListEntries(indexID: testIndexID),
        .catalogCreateIndex(title: "数据库", aliases: [], tags: []),
        .catalogCreateStructure(request: CatalogCreateStructureRequest(
            index: CatalogStructureIndexRequest(title: "数据库"),
            entries: [CatalogStructureEntryRequest(
                clientKey: "postgres",
                title: "PostgreSQL",
                endpoints: [CatalogEndpoint(type: "postgresql", host: "db.home", port: 5432)],
                fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
            )]
        )),
        .catalogCreateDraft(
            request: CatalogDraftRequest(indexID: testIndexID, title: "SSH", fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("zyk"))
            ])
        ),
        .catalogPatchMetadata(
            entryID: testEntryID,
            patch: CatalogMetadataPatch(title: "新标题"),
            expectedRevision: 1
        ),
        .catalogCommit(
            draft: CatalogDraft(draftID: testEntryID, baseRevision: 1, entry: sampleCatalogMatch().entry),
            expectedRevision: 1
        ),
        .catalogAddSecretPlaceholder(
            entryID: testEntryID,
            key: "token",
            label: "Token",
            agentVisible: true,
            searchable: false,
            expectedRevision: 1
        ),
        .catalogBindExistingSecret(
            entryID: testEntryID,
            key: "password",
            secretRef: testSecretReference,
            expectedRevision: 1
        ),
        .catalogRequestSecureInputs(
            entryID: testEntryID,
            targets: [CatalogSecureInputTargetRequest(
                entryID: testEntryID,
                fieldKey: "password",
                mode: .replaceSecret,
                required: true
            )],
            expectedRevision: 1
        ),
        .catalogValidate,
        .catalogPendingWriteAccessRequestIDs,
        .catalogSecureInputStatus(requestID: UUID()),
        .pendingRevealSessions,
        .inspectReference(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .deleteRecord(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .authorizeHighRisk(reason: "delete record"),
        .lock,
        .clearRevealSessions,
        .reveal(reference: "secret://0123456789ABCDEFGHJKMNPQRS", reason: "show to user"),
        .encrypt(label: "api token", policy: .externalSend),
        .encryptBound(
            label: "QNAP credential",
            policy: .credential,
            allowedDestinations: ["qnap.local", "192.168.2.240"],
            allowedProtocols: ["ssh", "https"]
        ),
        .exportResolvedText(
            references: ["secret://0123456789ABCDEFGHJKMNPQRS"],
            context: RevealContext(
                reason: "export",
                template: "Token: {{0}}",
                ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")]
            ),
            destinationPath: "/Users/example/Desktop/token.md"
        ),
        .execute(ExecutionRequest(
            templateID: "send-message",
            executable: "/usr/bin/printf",
            values: ["message": "hello"],
            secrets: ["apiToken": try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")],
            destinationHost: "api.example.com",
            destinationPath: "/v1/send",
            requestedRisk: .writeOrExternalSend
        )),
        .preflightSecretOperation(operationDescriptor),
        .executeSecretOperation(operationDescriptor),
        .reviewSSHHostKey(host: "qnap.local", port: 2222)
    ]

    for request in requests {
        let encoded = try JSONEncoder().encode(request)
        let decoded = try JSONDecoder().decode(IPCRequest.self, from: encoded)

        #expect(decoded == request)
    }
}

@Test func secureInputStatusRequestDecodesMCPRequestIDWireFixture() throws {
    let requestID = try #require(UUID(uuidString: "00000000-0000-4000-8000-000000000024"))
    let data = Data(#"{"type":"catalogSecureInputStatus","requestID":"00000000-0000-4000-8000-000000000024"}"#.utf8)

    let decoded = try JSONDecoder().decode(IPCRequest.self, from: data)

    #expect(decoded == .catalogSecureInputStatus(requestID: requestID))
    let encoded = try JSONSerialization.jsonObject(
        with: JSONEncoder().encode(decoded)
    ) as? [String: Any]
    #expect(encoded?["requestID"] as? String == requestID.uuidString.lowercased())
    #expect(encoded?["id"] == nil)
}

@Test func normalIPCRejectsLegacyPlaintextWireCases() throws {
    let legacyRequests = [
        Data(#"{"type":"revealSessionData","sessionID":"session-1"}"#.utf8),
        Data(#"{"type":"restoreReferences","references":["secret://0123456789ABCDEFGHJKMNPQRS"],"context":{"reason":"restore","template":"{{0}}","ranges":[]}}"#.utf8)
    ]
    for payload in legacyRequests {
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(IPCRequest.self, from: payload)
        }
    }

    let legacyResponses = [
        Data(#"{"type":"revealSessionData","paragraph":{"text":"legacy","values":["legacy"]}}"#.utf8),
        Data(#"{"type":"restoredText","text":"legacy"}"#.utf8)
    ]
    for payload in legacyResponses {
        #expect(throws: DecodingError.self) {
            _ = try JSONDecoder().decode(IPCResponse.self, from: payload)
        }
    }
}

@Test func responseJSONRoundTripsEveryCase() throws {
    let pin = try ipcTestSSHHostKeyPin()
    let responses: [IPCResponse] = [
        .status(locked: false),
        .workbenchStatus(WorkbenchStatus(locked: true, ipcAvailable: true, activeKnowledgeBaseRoot: nil, pluginConnected: false)),
        .savedReferences([]),
        .catalogSearchResult(SecretCatalogSearchResult(
            status: .found,
            matches: [sampleCatalogMatch()]
        )),
        .catalogIndexListResult(SecretCatalogIndexListResult(
            revision: 2,
            indices: [SecretCatalogIndexSummary(id: testIndexID, title: "QNAP", entryCount: 1)]
        )),
        .catalogEntryListResult(SecretCatalogEntryListResult(
            status: .found,
            revision: 2,
            indexID: testIndexID,
            entries: [sampleCatalogMatch().entry]
        )),
        .catalogDraft(CatalogDraft(draftID: testEntryID, baseRevision: 1, entry: sampleCatalogMatch().entry)),
        .catalogWriteResult(CatalogWriteResult(revision: 2, entry: sampleCatalogMatch().entry)),
        .catalogStructureWriteResult(CatalogStructureWriteResult(
            indexID: testIndexID,
            entries: [CatalogStructureEntryResult(clientKey: "postgres", entryID: testEntryID)],
            revision: 3,
            validation: CatalogValidationResult(status: .found, revision: 3)
        )),
        .catalogValidation(
            status: .found,
            revision: 2,
            rawSHA256: nil,
            diagnostics: [],
            filePreflight: nil
        ),
        .catalogPendingWriteAccessRequestIDs([UUID()]),
        .catalogSecureInputStatus(CatalogSecureInputStatus(
            requestID: UUID(),
            status: .pending
        )),
        .referenceMetadata(SecretReferenceMetadata(
            reference: "secret://0123456789ABCDEFGHJKMNPQRS",
            policy: .read,
            label: "NAS password",
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )),
        .displayedToUser,
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .exported(path: "/Users/example/Desktop/token.md"),
        .execution(.completed(exitCode: 0, stdout: "ok [REDACTED_SECRET]", stderr: "")),
        .execution(.quarantined(reason: .binaryOutput)),
        .secretOperationPreflight(SecretOperationPreflight(
            route: .fast,
            policyRuleID: "test.fast",
            authorizationRequirement: .none,
            blastRadius: .tiny,
            reasons: ["routine bounded operation"],
            reviewID: testSemanticReviewID
        )),
        .secretOperation(SecretOperationOutput(status: "COMPLETED", httpStatus: 200, contentType: "application/json", bodyPreview: "{\"ok\":true}")),
        .secretOperation(SecretOperationOutput(
            status: "BOUND",
            destination: "qnap.local",
            protocolType: .ssh,
            port: 2222,
            hostKeyPin: pin
        )),
        .sshHostKeyReview(SSHHostKeyReview(host: "qnap.local", port: 2222, pins: [pin])),
        .sshSessionStatus([SSHSessionStatus(
            sessionID: "ssh_session_test",
            host: "qnap.local",
            port: 22,
            status: .active,
            idleExpiresIn: 299
        )]),
        .failure(code: "APP_UNAVAILABLE")
    ]

    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: encoded)

        #expect(decoded == response)
    }
}

@Test func secureInputStatusUsesUppercaseWireValue() throws {
    let response = IPCResponse.catalogSecureInputStatus(
        CatalogSecureInputStatus(requestID: UUID(), status: .pending)
    )
    let object = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(response)) as? [String: Any]
    )
    let status = try #require(object["status"] as? [String: Any])
    #expect(status["status"] as? String == "PENDING")
}

@Test func encodedResponsesNeverContainPlaintextShapedKeys() throws {
    let responses: [IPCResponse] = [
        .status(locked: true),
        .referenceMetadata(SecretReferenceMetadata(
            reference: "secret://0123456789ABCDEFGHJKMNPQRS",
            policy: .read,
            label: "NAS password",
            createdAt: Date(timeIntervalSinceReferenceDate: 1),
            updatedAt: Date(timeIntervalSinceReferenceDate: 2)
        )),
        .displayedToUser,
        .created(reference: "secret://0123456789ABCDEFGHJKMNPQRS"),
        .exported(path: "/Users/example/Desktop/token.md"),
        .execution(.completed(exitCode: 0, stdout: "sanitized", stderr: "")),
        .execution(.quarantined(reason: .encodedSecretVariantDetected)),
        .failure(code: "DENIED")
    ]

    for response in responses {
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(response))
        let forbiddenKeys = collectForbiddenKeys(in: object)

        #expect(forbiddenKeys.isEmpty)
    }
}

@Test func frameCodecUsesBigEndianLengthPrefixAndRoundTripsJSON() throws {
    let frame = try IPCFrameCodec.encode(IPCResponse.status(locked: false))

    #expect(frame.count > 4)
    #expect(frame.prefix(4).elementsEqual([0, 0, 0, UInt8(frame.count - 4)]))

    let decoded = try IPCFrameCodec.decode(IPCResponse.self, from: frame)
    #expect(decoded == .status(locked: false))
}

@Test func frameCodecRejectsFramesOverOneMiB() throws {
    let oversizedPayload = Data(repeating: 0x41, count: 1_048_577)
    var frame = Data([0, 16, 0, 1])
    frame.append(oversizedPayload)

    #expect(throws: IPCFrameError.frameTooLarge) {
        _ = try IPCFrameCodec.decode(IPCResponse.self, from: frame)
    }
}

@Test func capabilityTokenRequiresExactlyThirtyTwoDecodedBytes() throws {
    let valid = try CapabilityToken(base64Encoded: Data(repeating: 0xA5, count: 32).base64EncodedString())

    #expect(valid.rawValue == Data(repeating: 0xA5, count: 32).base64EncodedString())
    #expect(throws: CapabilityTokenError.invalidEncoding) {
        _ = try CapabilityToken(base64Encoded: "not base64")
    }
    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 31)) {
        _ = try CapabilityToken(base64Encoded: Data(repeating: 0x00, count: 31).base64EncodedString())
    }
    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 33)) {
        _ = try CapabilityToken(base64Encoded: Data(repeating: 0x00, count: 33).base64EncodedString())
    }
}

@Test func authenticatedRequestRejectsNon256BitTokenDuringDecoding() throws {
    let json = """
    {
      "capabilityToken": "\(Data(repeating: 0x00, count: 16).base64EncodedString())",
      "request": { "type": "status" }
    }
    """.data(using: .utf8)!

    #expect(throws: CapabilityTokenError.invalidLength(actualBytes: 16)) {
        _ = try JSONDecoder().decode(AuthenticatedIPCRequest.self, from: json)
    }
}

@Test func authenticatedRequestRoundTripsWithValidatedCapabilityToken() throws {
    let token = try CapabilityToken(base64Encoded: Data(repeating: 0x7F, count: 32).base64EncodedString())
    let request = AuthenticatedIPCRequest(capabilityToken: token, request: .status)

    let encoded = try JSONEncoder().encode(request)
    let decoded = try JSONDecoder().decode(AuthenticatedIPCRequest.self, from: encoded)

    #expect(decoded == request)
}

@Test func authenticatedRequestCarriesOptionalSelfDeclaredCallerWithoutChangingAuthentication() throws {
    let token = try CapabilityToken(base64Encoded: Data(repeating: 0x6A, count: 32).base64EncodedString())
    let caller = AgentCallerIdentity(name: "Pi", version: "1.2.3", transport: "mcp")
    let request = AuthenticatedIPCRequest(
        capabilityToken: token,
        request: .status,
        caller: caller
    )

    let decoded = try JSONDecoder().decode(
        AuthenticatedIPCRequest.self,
        from: JSONEncoder().encode(request)
    )
    #expect(decoded.caller == caller)
    #expect(try IPCAuthenticator(expectedToken: token).authenticate(decoded) == .status)
}

@Test func authenticatorReturnsRequestOnlyForMatchingCapabilityToken() throws {
    let expected = try CapabilityToken(base64Encoded: Data(repeating: 0x11, count: 32).base64EncodedString())
    let different = try CapabilityToken(base64Encoded: Data(repeating: 0x22, count: 32).base64EncodedString())
    let authenticator = IPCAuthenticator(expectedToken: expected)

    let authenticated = AuthenticatedIPCRequest(capabilityToken: expected, request: .status)
    #expect(try authenticator.authenticate(authenticated) == .status)

    let rejected = AuthenticatedIPCRequest(capabilityToken: different, request: .status)
    #expect(throws: IPCAuthenticationError.invalidCapabilityToken) {
        _ = try authenticator.authenticate(rejected)
    }
}

@Test func serverWritesCapabilityTokenFileWithOwnerOnlyPermissions() throws {
    let temporaryDirectory = FileManager.default.temporaryDirectory
        .appending(path: "vault-ipc-\(UUID().uuidString)")
    let configuration = UnixSocketServerConfiguration(directoryURL: temporaryDirectory)
    let server = UnixSocketServer(configuration: configuration)
    let token = try CapabilityToken(base64Encoded: Data(repeating: 0x4D, count: 32).base64EncodedString())

    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    try server.writeCapabilityToken(token)

    let tokenData = try Data(contentsOf: configuration.tokenURL)
    #expect(tokenData == Data(token.rawValue.utf8))

    var fileStat = stat()
    #expect(stat(configuration.tokenURL.path, &fileStat) == 0)
    #expect((fileStat.st_mode & 0o777) == 0o600)
}

@Test func serverBindsSocketUnderConfiguredDirectoryWithOwnerOnlyPermissions() throws {
    let temporaryDirectory = URL(filePath: "/tmp")
        .appending(path: "vipc-\(UUID().uuidString)")
    let configuration = UnixSocketServerConfiguration(directoryURL: temporaryDirectory)
    let server = UnixSocketServer(configuration: configuration)

    defer {
        try? FileManager.default.removeItem(at: temporaryDirectory)
    }

    let boundSocket = try server.bindListeningSocket()
    defer {
        boundSocket.close()
    }

    #expect(boundSocket.fileDescriptor >= 0)

    var socketStat = stat()
    #expect(stat(configuration.socketURL.path, &socketStat) == 0)
    #expect((socketStat.st_mode & 0o777) == 0o600)
}

@Test func controlPlaneResponsesRoundTripWithoutPlaintext() throws {
    let responses: [IPCResponse] = [
        .operationCompleted,
        .authorizationApproved,
        .savedReferences([]),
        .revealSessionIDs(["session-1"])
    ]
    for response in responses {
        let encoded = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(IPCResponse.self, from: encoded)
        #expect(decoded == response)
    }
}

private func collectForbiddenKeys(in value: Any) -> [String] {
    let forbidden = /plaintext|secretValue|resolvedArguments|masterKey/.ignoresCase()

    if let dictionary = value as? [String: Any] {
        return dictionary.flatMap { key, nestedValue in
            var matches: [String] = []
            if key.contains(forbidden) {
                matches.append(key)
            }
            matches.append(contentsOf: collectForbiddenKeys(in: nestedValue))
            return matches
        }
    }

    if let array = value as? [Any] {
        return array.flatMap(collectForbiddenKeys)
    }

    return []
}
