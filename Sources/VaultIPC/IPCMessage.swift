import Foundation
import VaultCore
import VaultExecution

public enum CapabilityTokenError: Error, Equatable, Sendable {
    case invalidEncoding
    case invalidLength(actualBytes: Int)
}

public struct CapabilityToken: Codable, Equatable, Sendable {
    public static let byteCount = 32

    public let rawValue: String

    private init(uncheckedRawValue: String) {
        self.rawValue = uncheckedRawValue
    }

    public init(base64Encoded rawValue: String) throws {
        guard let decoded = Data(base64Encoded: rawValue) else {
            throw CapabilityTokenError.invalidEncoding
        }
        guard decoded.count == Self.byteCount else {
            throw CapabilityTokenError.invalidLength(actualBytes: decoded.count)
        }

        self.rawValue = rawValue
    }

    public static func random() -> CapabilityToken {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<byteCount).map { _ in
            UInt8.random(in: UInt8.min ... UInt8.max, using: &generator)
        }
        return CapabilityToken(uncheckedRawValue: Data(bytes).base64EncodedString())
    }

    public func constantTimeEquals(_ other: CapabilityToken) -> Bool {
        guard let lhs = Data(base64Encoded: rawValue),
              let rhs = Data(base64Encoded: other.rawValue),
              lhs.count == rhs.count
        else {
            return false
        }

        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(base64Encoded: container.decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public enum IPCRequest: Codable, Equatable, Sendable {
    case status
    case workbenchStatus
    case secretOperationCapabilities
    case savedReferences
    /// Compatibility spelling for older in-process callers.  It still emits
    /// the v2 Entry-centric payload and never returns the old flat shape.
    case searchCatalog(query: String, field: SecretCatalogField?, limit: Int)
    case catalogSearch(query: String, field: SecretCatalogField?, limit: Int)
    case catalogGet(entryID: String)
    case catalogListIndexes
    case catalogListEntries(indexID: String)
    case catalogCreateIndex(title: String, aliases: [String], tags: [String])
    case catalogCreateEntry(request: CatalogDraftRequest)
    case catalogCreateStructure(request: CatalogCreateStructureRequest)
    case catalogCreateDraft(request: CatalogDraftRequest)
    case catalogPatchMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    )
    case catalogCommit(
        draft: CatalogDraft,
        expectedRevision: UInt64
    )
    case catalogAddSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64
    )
    case catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    )
    case catalogApplyBatch(mutation: CatalogBatchMutation, expectedRevision: UInt64)
    case catalogRequestSecureInputs(
        entryID: String,
        targets: [CatalogSecureInputTargetRequest],
        expectedRevision: UInt64
    )
    case catalogValidate
    case catalogFilePreflight
    case catalogPendingWriteAccessRequestIDs
    case catalogPendingSecureInputRequestIDs
    case catalogSecureInputStatus(requestID: UUID)
    case catalogRequestWriteAccess(CatalogAgentWriteAccessRequest)
    case pendingRevealSessions
    case inspectReference(reference: String)
    case deleteRecord(reference: String)
    case authorizeHighRisk(reason: String)
    case lock
    case clearRevealSessions
    case reveal(reference: String, reason: String)
    case encrypt(label: String?, policy: SecretPolicy)
    case encryptBound(
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    )
    case revealReferences(references: [String], context: RevealContext)
    case exportResolvedText(references: [String], context: RevealContext, destinationPath: String)
    case scanOrphans(markdownReferences: [String])
    case execute(ExecutionRequest)
    case preflightSecretOperation(SecretOperationDescriptor)
    case executeSecretOperation(SecretOperationDescriptor)
    case startSecretOperation(SecretOperationDescriptor)
    case startSecretOperationIdempotent(descriptor: SecretOperationDescriptor, idempotencyKey: String)
    case secretOperationStatus(operationID: UUID)
    case secretOperationOutput(operationID: UUID, cursor: UInt64, maxChunks: Int)
    case cancelSecretOperation(operationID: UUID)
    case reviewSSHHostKey(host: String, port: Int)
    case sshSessionStatus(sessionID: String?)
    case sshSessionClose(sessionID: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case reference
        case references
        case reason
        case query
        case field
        case limit
        case indexID
        case entryID
        case request
        case title
        case aliases
        case tags
        case patch
        case draft
        case expectedRevision
        case key
        case secretRef
        case agentVisible
        case searchable
        case label
        case policy
        case allowedDestinations
        case allowedProtocols
        case context
        case destinationPath
        case markdownReferences
        case descriptor
        case operationID
        case idempotencyKey
        case cursor
        case maxChunks
        case host
        case port
        case mutation
        case targets
        case requestID
        case sessionID
    }

    private enum RequestType: String, Codable {
        case status
        case workbenchStatus
        case secretOperationCapabilities
        case savedReferences
        case searchCatalog
        case catalogSearch
        case catalogGet
        case catalogListIndexes
        case catalogListEntries
        case catalogCreateIndex
        case catalogCreateEntry
        case catalogCreateStructure
        case catalogCreateDraft
        case catalogPatchMetadata
        case catalogCommit
        case catalogAddSecretPlaceholder
        case catalogBindExistingSecret
        case catalogApplyBatch
        case catalogRequestSecureInputs
        case catalogValidate
        case catalogFilePreflight
        case catalogPendingWriteAccessRequestIDs
        case catalogPendingSecureInputRequestIDs
        case catalogSecureInputStatus
        case catalogRequestWriteAccess
        case pendingRevealSessions
        case inspectReference
        case deleteRecord
        case authorizeHighRisk
        case lock
        case clearRevealSessions
        case reveal
        case encrypt
        case encryptBound
        case revealReferences
        case exportResolvedText
        case scanOrphans
        case execute
        case preflightSecretOperation
        case executeSecretOperation
        case startSecretOperation
        case startSecretOperationIdempotent
        case secretOperationStatus
        case secretOperationOutput
        case cancelSecretOperation
        case reviewSSHHostKey
        case sshSessionStatus
        case sshSessionClose
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(RequestType.self, forKey: .type) {
        case .status:
            self = .status
        case .workbenchStatus:
            self = .workbenchStatus
        case .secretOperationCapabilities:
            self = .secretOperationCapabilities
        case .savedReferences:
            self = .savedReferences
        case .searchCatalog:
            self = .searchCatalog(
                query: try container.decode(String.self, forKey: .query),
                field: try container.decodeIfPresent(SecretCatalogField.self, forKey: .field),
                limit: try container.decode(Int.self, forKey: .limit)
            )
        case .catalogSearch:
            self = .catalogSearch(
                query: try container.decode(String.self, forKey: .query),
                field: try container.decodeIfPresent(SecretCatalogField.self, forKey: .field),
                limit: try container.decode(Int.self, forKey: .limit)
            )
        case .catalogGet:
            self = .catalogGet(entryID: try container.decode(String.self, forKey: .entryID))
        case .catalogListIndexes:
            self = .catalogListIndexes
        case .catalogListEntries:
            self = .catalogListEntries(indexID: try container.decode(String.self, forKey: .indexID))
        case .catalogCreateIndex:
            self = .catalogCreateIndex(
                title: try container.decode(String.self, forKey: .title),
                aliases: try container.decode([String].self, forKey: .aliases),
                tags: try container.decode([String].self, forKey: .tags)
            )
        case .catalogCreateEntry:
            self = .catalogCreateEntry(
                request: try container.decode(CatalogDraftRequest.self, forKey: .request)
            )
        case .catalogCreateStructure:
            self = .catalogCreateStructure(
                request: try container.decode(CatalogCreateStructureRequest.self, forKey: .request)
            )
        case .catalogCreateDraft:
            self = .catalogCreateDraft(
                request: try container.decode(CatalogDraftRequest.self, forKey: .request)
            )
        case .catalogPatchMetadata:
            self = .catalogPatchMetadata(
                entryID: try container.decode(String.self, forKey: .entryID),
                patch: try container.decode(CatalogMetadataPatch.self, forKey: .patch),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogCommit:
            self = .catalogCommit(
                draft: try container.decode(CatalogDraft.self, forKey: .draft),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogAddSecretPlaceholder:
            self = .catalogAddSecretPlaceholder(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                label: try container.decode(String.self, forKey: .label),
                agentVisible: try container.decode(Bool.self, forKey: .agentVisible),
                searchable: try container.decode(Bool.self, forKey: .searchable),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogBindExistingSecret:
            self = .catalogBindExistingSecret(
                entryID: try container.decode(String.self, forKey: .entryID),
                key: try container.decode(String.self, forKey: .key),
                secretRef: try container.decode(String.self, forKey: .secretRef),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogApplyBatch:
            self = .catalogApplyBatch(
                mutation: try container.decode(CatalogBatchMutation.self, forKey: .mutation),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogRequestSecureInputs:
            self = .catalogRequestSecureInputs(
                entryID: try container.decode(String.self, forKey: .entryID),
                targets: try container.decode([CatalogSecureInputTargetRequest].self, forKey: .targets),
                expectedRevision: try container.decode(UInt64.self, forKey: .expectedRevision)
            )
        case .catalogValidate:
            self = .catalogValidate
        case .catalogFilePreflight:
            self = .catalogFilePreflight
        case .catalogPendingWriteAccessRequestIDs:
            self = .catalogPendingWriteAccessRequestIDs
        case .catalogPendingSecureInputRequestIDs:
            self = .catalogPendingSecureInputRequestIDs
        case .catalogSecureInputStatus:
            self = .catalogSecureInputStatus(requestID: try container.decode(UUID.self, forKey: .requestID))
        case .catalogRequestWriteAccess:
            self = .catalogRequestWriteAccess(
                try container.decode(CatalogAgentWriteAccessRequest.self, forKey: .request)
            )
        case .pendingRevealSessions:
            self = .pendingRevealSessions
        case .inspectReference:
            self = .inspectReference(
                reference: try container.decode(String.self, forKey: .reference)
            )
        case .deleteRecord:
            self = .deleteRecord(
                reference: try container.decode(String.self, forKey: .reference)
            )
        case .authorizeHighRisk:
            self = .authorizeHighRisk(
                reason: try container.decode(String.self, forKey: .reason)
            )
        case .lock:
            self = .lock
        case .clearRevealSessions:
            self = .clearRevealSessions
        case .reveal:
            self = .reveal(
                reference: try container.decode(String.self, forKey: .reference),
                reason: try container.decode(String.self, forKey: .reason)
            )
        case .encrypt:
            self = .encrypt(
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy)
            )
        case .encryptBound:
            self = .encryptBound(
                label: try container.decodeIfPresent(String.self, forKey: .label),
                policy: try container.decode(SecretPolicy.self, forKey: .policy),
                allowedDestinations: try container.decode([String].self, forKey: .allowedDestinations),
                allowedProtocols: try container.decode([String].self, forKey: .allowedProtocols)
            )
        case .revealReferences:
            self = .revealReferences(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context)
            )
        case .exportResolvedText:
            self = .exportResolvedText(
                references: try container.decode([String].self, forKey: .references),
                context: try container.decode(RevealContext.self, forKey: .context),
                destinationPath: try container.decode(String.self, forKey: .destinationPath)
            )
        case .scanOrphans:
            self = .scanOrphans(
                markdownReferences: try container.decode([String].self, forKey: .markdownReferences)
            )
        case .execute:
            self = .execute(try container.decode(ExecutionRequest.self, forKey: .request))
        case .preflightSecretOperation:
            self = .preflightSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))
        case .executeSecretOperation:
            self = .executeSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))
        case .startSecretOperation:
            self = .startSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))
        case .startSecretOperationIdempotent:
            self = .startSecretOperationIdempotent(
                descriptor: try container.decode(SecretOperationDescriptor.self, forKey: .descriptor),
                idempotencyKey: try container.decode(String.self, forKey: .idempotencyKey)
            )
        case .secretOperationStatus:
            self = .secretOperationStatus(operationID: try container.decode(UUID.self, forKey: .operationID))
        case .secretOperationOutput:
            self = .secretOperationOutput(
                operationID: try container.decode(UUID.self, forKey: .operationID),
                cursor: try container.decode(UInt64.self, forKey: .cursor),
                maxChunks: try container.decode(Int.self, forKey: .maxChunks)
            )
        case .cancelSecretOperation:
            self = .cancelSecretOperation(operationID: try container.decode(UUID.self, forKey: .operationID))
        case .reviewSSHHostKey:
            self = .reviewSSHHostKey(
                host: try container.decode(String.self, forKey: .host),
                port: try container.decode(Int.self, forKey: .port)
            )
        case .sshSessionStatus:
            self = .sshSessionStatus(
                sessionID: try container.decodeIfPresent(String.self, forKey: .sessionID)
            )
        case .sshSessionClose:
            self = .sshSessionClose(
                sessionID: try container.decode(String.self, forKey: .sessionID)
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .status:
            try container.encode(RequestType.status, forKey: .type)
        case .workbenchStatus:
            try container.encode(RequestType.workbenchStatus, forKey: .type)
        case .secretOperationCapabilities:
            try container.encode(RequestType.secretOperationCapabilities, forKey: .type)
        case .savedReferences:
            try container.encode(RequestType.savedReferences, forKey: .type)
        case let .searchCatalog(query, field, limit):
            try container.encode(RequestType.searchCatalog, forKey: .type)
            try container.encode(query, forKey: .query)
            try container.encodeIfPresent(field, forKey: .field)
            try container.encode(limit, forKey: .limit)
        case let .catalogSearch(query, field, limit):
            try container.encode(RequestType.catalogSearch, forKey: .type)
            try container.encode(query, forKey: .query)
            try container.encodeIfPresent(field, forKey: .field)
            try container.encode(limit, forKey: .limit)
        case let .catalogGet(entryID):
            try container.encode(RequestType.catalogGet, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
        case .catalogListIndexes:
            try container.encode(RequestType.catalogListIndexes, forKey: .type)
        case let .catalogListEntries(indexID):
            try container.encode(RequestType.catalogListEntries, forKey: .type)
            try container.encode(indexID, forKey: .indexID)
        case let .catalogCreateIndex(title, aliases, tags):
            try container.encode(RequestType.catalogCreateIndex, forKey: .type)
            try container.encode(title, forKey: .title)
            try container.encode(aliases, forKey: .aliases)
            try container.encode(tags, forKey: .tags)
        case let .catalogCreateEntry(request):
            try container.encode(RequestType.catalogCreateEntry, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .catalogCreateStructure(request):
            try container.encode(RequestType.catalogCreateStructure, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .catalogCreateDraft(request):
            try container.encode(RequestType.catalogCreateDraft, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .catalogPatchMetadata(entryID, patch, expectedRevision):
            try container.encode(RequestType.catalogPatchMetadata, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(patch, forKey: .patch)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogCommit(draft, expectedRevision):
            try container.encode(RequestType.catalogCommit, forKey: .type)
            try container.encode(draft, forKey: .draft)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogAddSecretPlaceholder(entryID, key, label, agentVisible, searchable, expectedRevision):
            try container.encode(RequestType.catalogAddSecretPlaceholder, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encode(label, forKey: .label)
            try container.encode(agentVisible, forKey: .agentVisible)
            try container.encode(searchable, forKey: .searchable)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogBindExistingSecret(entryID, key, secretRef, expectedRevision):
            try container.encode(RequestType.catalogBindExistingSecret, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(key, forKey: .key)
            try container.encode(secretRef, forKey: .secretRef)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogApplyBatch(mutation, expectedRevision):
            try container.encode(RequestType.catalogApplyBatch, forKey: .type)
            try container.encode(mutation, forKey: .mutation)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case let .catalogRequestSecureInputs(entryID, targets, expectedRevision):
            try container.encode(RequestType.catalogRequestSecureInputs, forKey: .type)
            try container.encode(entryID, forKey: .entryID)
            try container.encode(targets, forKey: .targets)
            try container.encode(expectedRevision, forKey: .expectedRevision)
        case .catalogValidate:
            try container.encode(RequestType.catalogValidate, forKey: .type)
        case .catalogFilePreflight:
            try container.encode(RequestType.catalogFilePreflight, forKey: .type)
        case .catalogPendingWriteAccessRequestIDs:
            try container.encode(RequestType.catalogPendingWriteAccessRequestIDs, forKey: .type)
        case .catalogPendingSecureInputRequestIDs:
            try container.encode(RequestType.catalogPendingSecureInputRequestIDs, forKey: .type)
        case let .catalogSecureInputStatus(requestID):
            try container.encode(RequestType.catalogSecureInputStatus, forKey: .type)
            try container.encode(requestID, forKey: .requestID)
        case let .catalogRequestWriteAccess(request):
            try container.encode(RequestType.catalogRequestWriteAccess, forKey: .type)
            try container.encode(request, forKey: .request)
        case .pendingRevealSessions:
            try container.encode(RequestType.pendingRevealSessions, forKey: .type)
        case let .inspectReference(reference):
            try container.encode(RequestType.inspectReference, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .deleteRecord(reference):
            try container.encode(RequestType.deleteRecord, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .authorizeHighRisk(reason):
            try container.encode(RequestType.authorizeHighRisk, forKey: .type)
            try container.encode(reason, forKey: .reason)
        case .lock:
            try container.encode(RequestType.lock, forKey: .type)
        case .clearRevealSessions:
            try container.encode(RequestType.clearRevealSessions, forKey: .type)
        case let .reveal(reference, reason):
            try container.encode(RequestType.reveal, forKey: .type)
            try container.encode(reference, forKey: .reference)
            try container.encode(reason, forKey: .reason)
        case let .encrypt(label, policy):
            try container.encode(RequestType.encrypt, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
        case let .encryptBound(label, policy, allowedDestinations, allowedProtocols):
            try container.encode(RequestType.encryptBound, forKey: .type)
            try container.encodeIfPresent(label, forKey: .label)
            try container.encode(policy, forKey: .policy)
            try container.encode(allowedDestinations, forKey: .allowedDestinations)
            try container.encode(allowedProtocols, forKey: .allowedProtocols)
        case let .revealReferences(references, context):
            try container.encode(RequestType.revealReferences, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
        case let .exportResolvedText(references, context, destinationPath):
            try container.encode(RequestType.exportResolvedText, forKey: .type)
            try container.encode(references, forKey: .references)
            try container.encode(context, forKey: .context)
            try container.encode(destinationPath, forKey: .destinationPath)
        case let .scanOrphans(markdownReferences):
            try container.encode(RequestType.scanOrphans, forKey: .type)
            try container.encode(markdownReferences, forKey: .markdownReferences)
        case let .execute(request):
            try container.encode(RequestType.execute, forKey: .type)
            try container.encode(request, forKey: .request)
        case let .preflightSecretOperation(descriptor):
            try container.encode(RequestType.preflightSecretOperation, forKey: .type)
            try container.encode(descriptor, forKey: .descriptor)
        case let .executeSecretOperation(descriptor):
            try container.encode(RequestType.executeSecretOperation, forKey: .type)
            try container.encode(descriptor, forKey: .descriptor)
        case let .startSecretOperation(descriptor):
            try container.encode(RequestType.startSecretOperation, forKey: .type)
            try container.encode(descriptor, forKey: .descriptor)
        case let .startSecretOperationIdempotent(descriptor, idempotencyKey):
            try container.encode(RequestType.startSecretOperationIdempotent, forKey: .type)
            try container.encode(descriptor, forKey: .descriptor)
            try container.encode(idempotencyKey, forKey: .idempotencyKey)
        case let .secretOperationStatus(operationID):
            try container.encode(RequestType.secretOperationStatus, forKey: .type)
            try container.encode(operationID, forKey: .operationID)
        case let .secretOperationOutput(operationID, cursor, maxChunks):
            try container.encode(RequestType.secretOperationOutput, forKey: .type)
            try container.encode(operationID, forKey: .operationID)
            try container.encode(cursor, forKey: .cursor)
            try container.encode(maxChunks, forKey: .maxChunks)
        case let .cancelSecretOperation(operationID):
            try container.encode(RequestType.cancelSecretOperation, forKey: .type)
            try container.encode(operationID, forKey: .operationID)
        case let .reviewSSHHostKey(host, port):
            try container.encode(RequestType.reviewSSHHostKey, forKey: .type)
            try container.encode(host, forKey: .host)
            try container.encode(port, forKey: .port)
        case let .sshSessionStatus(sessionID):
            try container.encode(RequestType.sshSessionStatus, forKey: .type)
            try container.encodeIfPresent(sessionID, forKey: .sessionID)
        case let .sshSessionClose(sessionID):
            try container.encode(RequestType.sshSessionClose, forKey: .type)
            try container.encode(sessionID, forKey: .sessionID)
        }
    }
}

public struct WorkbenchStatus: Codable, Equatable, Sendable {
    /// Kept for wire compatibility only. Agent workflows must use ready and
    /// approvalPending instead of treating this field as a global gate.
    public let locked: Bool
    public let ipcAvailable: Bool
    public let available: Bool
    public let ready: Bool
    public let approvalPending: Bool
    public let activeKnowledgeBaseRoot: String?
    public let pluginConnected: Bool

    private enum CodingKeys: String, CodingKey {
        case locked
        case ipcAvailable
        case available
        case ready
        case approvalPending
        case activeKnowledgeBaseRoot
        case pluginConnected
    }

    public init(
        locked: Bool,
        ipcAvailable: Bool,
        available: Bool = true,
        ready: Bool = true,
        approvalPending: Bool = false,
        activeKnowledgeBaseRoot: String?,
        pluginConnected: Bool
    ) {
        self.locked = locked
        self.ipcAvailable = ipcAvailable
        self.available = available
        self.ready = ready
        self.approvalPending = approvalPending
        self.activeKnowledgeBaseRoot = activeKnowledgeBaseRoot
        self.pluginConnected = pluginConnected
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            locked: try container.decode(Bool.self, forKey: .locked),
            ipcAvailable: try container.decode(Bool.self, forKey: .ipcAvailable),
            available: try container.decodeIfPresent(Bool.self, forKey: .available) ?? true,
            ready: try container.decodeIfPresent(Bool.self, forKey: .ready) ?? true,
            approvalPending: try container.decodeIfPresent(Bool.self, forKey: .approvalPending) ?? false,
            activeKnowledgeBaseRoot: try container.decodeIfPresent(String.self, forKey: .activeKnowledgeBaseRoot),
            pluginConnected: try container.decode(Bool.self, forKey: .pluginConnected)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(locked, forKey: .locked)
        try container.encode(ipcAvailable, forKey: .ipcAvailable)
        try container.encode(available, forKey: .available)
        try container.encode(ready, forKey: .ready)
        try container.encode(approvalPending, forKey: .approvalPending)
        if let activeKnowledgeBaseRoot {
            try container.encode(activeKnowledgeBaseRoot, forKey: .activeKnowledgeBaseRoot)
        } else {
            try container.encodeNil(forKey: .activeKnowledgeBaseRoot)
        }
        try container.encode(pluginConnected, forKey: .pluginConnected)
    }
}

public struct ReferenceRange: Codable, Equatable, Sendable {
    public let index: Int
    public let placeholder: String

    public init(index: Int, placeholder: String) {
        self.index = index
        self.placeholder = placeholder
    }
}

public struct OrphanScanResult: Codable, Equatable, Sendable {
    public let missingRecords: [String]
    public let unreferencedRecords: [String]

    public init(missingRecords: [String], unreferencedRecords: [String]) {
        self.missingRecords = missingRecords
        self.unreferencedRecords = unreferencedRecords
    }
}

public struct SecretReferenceMetadata: Codable, Equatable, Sendable {
    public let reference: String
    public let policy: SecretPolicy
    public let label: String?
    public let allowedDestinations: [String]
    public let allowedProtocols: [String]
    public let allowedBindings: [SecretDestinationBinding]
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        reference: String,
        policy: SecretPolicy,
        label: String?,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = [],
        allowedBindings: [SecretDestinationBinding] = [],
        createdAt: Date,
        updatedAt: Date
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.allowedDestinations = allowedDestinations
        self.allowedProtocols = allowedProtocols
        self.allowedBindings = allowedBindings
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    private enum CodingKeys: String, CodingKey {
        case reference
        case policy
        case label
        case allowedDestinations
        case allowedProtocols
        case allowedBindings
        case createdAt
        case updatedAt
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            reference: try container.decode(String.self, forKey: .reference),
            policy: try container.decode(SecretPolicy.self, forKey: .policy),
            label: try container.decodeIfPresent(String.self, forKey: .label),
            allowedDestinations: try container.decodeIfPresent([String].self, forKey: .allowedDestinations) ?? [],
            allowedProtocols: try container.decodeIfPresent([String].self, forKey: .allowedProtocols) ?? [],
            allowedBindings: try container.decodeIfPresent([SecretDestinationBinding].self, forKey: .allowedBindings) ?? [],
            createdAt: try container.decode(Date.self, forKey: .createdAt),
            updatedAt: try container.decode(Date.self, forKey: .updatedAt)
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(reference, forKey: .reference)
        try container.encode(policy, forKey: .policy)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encode(allowedDestinations, forKey: .allowedDestinations)
        try container.encode(allowedProtocols, forKey: .allowedProtocols)
        try container.encode(allowedBindings, forKey: .allowedBindings)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(updatedAt, forKey: .updatedAt)
    }
}

public enum IPCResponse: Codable, Equatable, Sendable {
    case status(locked: Bool)
    case workbenchStatus(WorkbenchStatus)
    case secretOperationCapabilities([SecretOperationCapability])
    case savedReferences([SecretReferenceMetadata])
    case catalogSearchResult(SecretCatalogSearchResult)
    case catalogIndexListResult(SecretCatalogIndexListResult)
    case catalogEntryListResult(SecretCatalogEntryListResult)
    case catalogDraft(CatalogDraft)
    case catalogWriteResult(CatalogWriteResult)
    case catalogStructureWriteResult(CatalogStructureWriteResult)
    case catalogValidation(
        status: SecretCatalogSearchStatus,
        revision: UInt64?,
        rawSHA256: String?,
        diagnostics: [CatalogValidationDiagnostic],
        filePreflight: CatalogFilePreflight?
    )
    case catalogFilePreflight(CatalogFilePreflight)
    case catalogPendingWriteAccessRequestIDs([UUID])
    case catalogPendingSecureInputRequestIDs([UUID])
    case catalogSecureInputStatus(CatalogSecureInputStatus)
    case revealSessionIDs([String])
    case referenceMetadata(SecretReferenceMetadata)
    case displayedToUser
    case operationCompleted
    case authorizationApproved
    case created(reference: String)
    case revealSessionOpened(sessionID: String)
    case exported(path: String)
    case orphanScan(OrphanScanResult)
    case execution(SanitizedExecutionResult)
    case secretOperation(SecretOperationOutput)
    case secretOperationPreflight(SecretOperationPreflight)
    case secretOperationHandle(SecretOperationHandle)
    case secretOperationStatus(SecretOperationStatus)
    case secretOperationOutput(SecretOperationOutputPage)
    case sshHostKeyReview(SSHHostKeyReview)
    case sshSessionStatus([SSHSessionStatus])
    case failure(code: String)

    private enum CodingKeys: String, CodingKey {
        case type
        case capabilities
        case locked
        case status
        case references
        case result
        case draft
        case revision
        case catalogStatus
        case rawSHA256
        case diagnostics
        case filePreflight
        case requestIDs
        case sessionIDs
        case metadata
        case reference
        case sessionID
        case path
        case output
        case code
        case sessions
        case review
    }

    private enum ResponseType: String, Codable {
        case status
        case workbenchStatus
        case secretOperationCapabilities
        case savedReferences
        case catalogSearchResult
        case catalogIndexListResult
        case catalogEntryListResult
        case catalogDraft
        case catalogWriteResult
        case catalogStructureWriteResult
        case catalogValidation
        case catalogFilePreflight
        case catalogPendingWriteAccessRequestIDs
        case catalogPendingSecureInputRequestIDs
        case catalogSecureInputStatus
        case revealSessionIDs
        case referenceMetadata
        case displayedToUser
        case operationCompleted
        case authorizationApproved
        case created
        case revealSessionOpened
        case exported
        case orphanScan
        case execution
        case secretOperation
        case secretOperationPreflight
        case secretOperationHandle
        case secretOperationStatus
        case secretOperationOutput
        case sshHostKeyReview
        case sshSessionStatus
        case failure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResponseType.self, forKey: .type) {
        case .status:
            self = .status(locked: try container.decode(Bool.self, forKey: .locked))
        case .workbenchStatus:
            self = .workbenchStatus(try container.decode(WorkbenchStatus.self, forKey: .status))
        case .secretOperationCapabilities:
            self = .secretOperationCapabilities(
                try container.decode([SecretOperationCapability].self, forKey: .capabilities)
            )
        case .savedReferences:
            self = .savedReferences(try container.decode([SecretReferenceMetadata].self, forKey: .references))
        case .catalogSearchResult:
            self = .catalogSearchResult(try container.decode(SecretCatalogSearchResult.self, forKey: .result))
        case .catalogIndexListResult:
            self = .catalogIndexListResult(try container.decode(SecretCatalogIndexListResult.self, forKey: .result))
        case .catalogEntryListResult:
            self = .catalogEntryListResult(try container.decode(SecretCatalogEntryListResult.self, forKey: .result))
        case .catalogDraft:
            self = .catalogDraft(try container.decode(CatalogDraft.self, forKey: .draft))
        case .catalogWriteResult:
            self = .catalogWriteResult(try container.decode(CatalogWriteResult.self, forKey: .result))
        case .catalogStructureWriteResult:
            self = .catalogStructureWriteResult(try container.decode(CatalogStructureWriteResult.self, forKey: .result))
        case .catalogValidation:
            self = .catalogValidation(
                status: try container.decode(SecretCatalogSearchStatus.self, forKey: .catalogStatus),
                revision: try container.decodeIfPresent(UInt64.self, forKey: .revision),
                rawSHA256: try container.decodeIfPresent(String.self, forKey: .rawSHA256),
                diagnostics: try container.decodeIfPresent([CatalogValidationDiagnostic].self, forKey: .diagnostics) ?? [],
                filePreflight: try container.decodeIfPresent(CatalogFilePreflight.self, forKey: .filePreflight)
            )
        case .catalogFilePreflight:
            self = .catalogFilePreflight(try container.decode(CatalogFilePreflight.self, forKey: .filePreflight))
        case .catalogPendingWriteAccessRequestIDs:
            self = .catalogPendingWriteAccessRequestIDs(
                try container.decode([UUID].self, forKey: .requestIDs)
            )
        case .catalogPendingSecureInputRequestIDs:
            self = .catalogPendingSecureInputRequestIDs(
                try container.decode([UUID].self, forKey: .requestIDs)
            )
        case .catalogSecureInputStatus:
            self = .catalogSecureInputStatus(try container.decode(CatalogSecureInputStatus.self, forKey: .status))
        case .revealSessionIDs:
            self = .revealSessionIDs(try container.decode([String].self, forKey: .sessionIDs))
        case .referenceMetadata:
            self = .referenceMetadata(try container.decode(SecretReferenceMetadata.self, forKey: .metadata))
        case .displayedToUser:
            self = .displayedToUser
        case .operationCompleted:
            self = .operationCompleted
        case .authorizationApproved:
            self = .authorizationApproved
        case .created:
            self = .created(reference: try container.decode(String.self, forKey: .reference))
        case .revealSessionOpened:
            self = .revealSessionOpened(sessionID: try container.decode(String.self, forKey: .sessionID))
        case .exported:
            self = .exported(path: try container.decode(String.self, forKey: .path))
        case .orphanScan:
            self = .orphanScan(try container.decode(OrphanScanResult.self, forKey: .result))
        case .execution:
            self = .execution(try container.decode(SanitizedExecutionResult.self, forKey: .result))
        case .secretOperation:
            self = .secretOperation(try container.decode(SecretOperationOutput.self, forKey: .output))
        case .secretOperationPreflight:
            self = .secretOperationPreflight(try container.decode(SecretOperationPreflight.self, forKey: .result))
        case .secretOperationHandle:
            self = .secretOperationHandle(try container.decode(SecretOperationHandle.self, forKey: .result))
        case .secretOperationStatus:
            self = .secretOperationStatus(try container.decode(SecretOperationStatus.self, forKey: .result))
        case .secretOperationOutput:
            self = .secretOperationOutput(try container.decode(SecretOperationOutputPage.self, forKey: .result))
        case .sshHostKeyReview:
            self = .sshHostKeyReview(try container.decode(SSHHostKeyReview.self, forKey: .review))
        case .sshSessionStatus:
            self = .sshSessionStatus(try container.decode([SSHSessionStatus].self, forKey: .sessions))
        case .failure:
            self = .failure(code: try container.decode(String.self, forKey: .code))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .status(locked):
            try container.encode(ResponseType.status, forKey: .type)
            try container.encode(locked, forKey: .locked)
        case let .workbenchStatus(status):
            try container.encode(ResponseType.workbenchStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .secretOperationCapabilities(capabilities):
            try container.encode(ResponseType.secretOperationCapabilities, forKey: .type)
            try container.encode(capabilities, forKey: .capabilities)
        case let .savedReferences(references):
            try container.encode(ResponseType.savedReferences, forKey: .type)
            try container.encode(references, forKey: .references)
        case let .catalogSearchResult(result):
            try container.encode(ResponseType.catalogSearchResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogIndexListResult(result):
            try container.encode(ResponseType.catalogIndexListResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogEntryListResult(result):
            try container.encode(ResponseType.catalogEntryListResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogDraft(draft):
            try container.encode(ResponseType.catalogDraft, forKey: .type)
            try container.encode(draft, forKey: .draft)
        case let .catalogWriteResult(result):
            try container.encode(ResponseType.catalogWriteResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogStructureWriteResult(result):
            try container.encode(ResponseType.catalogStructureWriteResult, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .catalogValidation(status, revision, rawSHA256, diagnostics, filePreflight):
            try container.encode(ResponseType.catalogValidation, forKey: .type)
            try container.encode(status, forKey: .catalogStatus)
            try container.encodeIfPresent(revision, forKey: .revision)
            try container.encodeIfPresent(rawSHA256, forKey: .rawSHA256)
            try container.encode(diagnostics, forKey: .diagnostics)
            try container.encodeIfPresent(filePreflight, forKey: .filePreflight)
        case let .catalogFilePreflight(preflight):
            try container.encode(ResponseType.catalogFilePreflight, forKey: .type)
            try container.encode(preflight, forKey: .filePreflight)
        case let .catalogPendingWriteAccessRequestIDs(requestIDs):
            try container.encode(ResponseType.catalogPendingWriteAccessRequestIDs, forKey: .type)
            try container.encode(requestIDs, forKey: .requestIDs)
        case let .catalogPendingSecureInputRequestIDs(requestIDs):
            try container.encode(ResponseType.catalogPendingSecureInputRequestIDs, forKey: .type)
            try container.encode(requestIDs, forKey: .requestIDs)
        case let .catalogSecureInputStatus(status):
            try container.encode(ResponseType.catalogSecureInputStatus, forKey: .type)
            try container.encode(status, forKey: .status)
        case let .revealSessionIDs(sessionIDs):
            try container.encode(ResponseType.revealSessionIDs, forKey: .type)
            try container.encode(sessionIDs, forKey: .sessionIDs)
        case let .referenceMetadata(metadata):
            try container.encode(ResponseType.referenceMetadata, forKey: .type)
            try container.encode(metadata, forKey: .metadata)
        case .displayedToUser:
            try container.encode(ResponseType.displayedToUser, forKey: .type)
        case .operationCompleted:
            try container.encode(ResponseType.operationCompleted, forKey: .type)
        case .authorizationApproved:
            try container.encode(ResponseType.authorizationApproved, forKey: .type)
        case let .created(reference):
            try container.encode(ResponseType.created, forKey: .type)
            try container.encode(reference, forKey: .reference)
        case let .revealSessionOpened(sessionID):
            try container.encode(ResponseType.revealSessionOpened, forKey: .type)
            try container.encode(sessionID, forKey: .sessionID)
        case let .exported(path):
            try container.encode(ResponseType.exported, forKey: .type)
            try container.encode(path, forKey: .path)
        case let .orphanScan(result):
            try container.encode(ResponseType.orphanScan, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .execution(result):
            try container.encode(ResponseType.execution, forKey: .type)
            try container.encode(result, forKey: .result)
        case let .secretOperation(output):
            try container.encode(ResponseType.secretOperation, forKey: .type)
            try container.encode(output, forKey: .output)
        case let .secretOperationPreflight(preflight):
            try container.encode(ResponseType.secretOperationPreflight, forKey: .type)
            try container.encode(preflight, forKey: .result)
        case let .secretOperationHandle(handle):
            try container.encode(ResponseType.secretOperationHandle, forKey: .type)
            try container.encode(handle, forKey: .result)
        case let .secretOperationStatus(status):
            try container.encode(ResponseType.secretOperationStatus, forKey: .type)
            try container.encode(status, forKey: .result)
        case let .secretOperationOutput(output):
            try container.encode(ResponseType.secretOperationOutput, forKey: .type)
            try container.encode(output, forKey: .result)
        case let .sshHostKeyReview(review):
            try container.encode(ResponseType.sshHostKeyReview, forKey: .type)
            try container.encode(review, forKey: .review)
        case let .sshSessionStatus(sessions):
            try container.encode(ResponseType.sshSessionStatus, forKey: .type)
            try container.encode(sessions, forKey: .sessions)
        case let .failure(code):
            try container.encode(ResponseType.failure, forKey: .type)
            try container.encode(code, forKey: .code)
        }
    }
}

/// Self-declared display metadata from an MCP connection. It is never used as
/// the security principal; AppIPCController still derives that from the peer.
public struct AgentCallerIdentity: Codable, Equatable, Sendable {
    public let name: String
    public let version: String?
    public let transport: String

    public init(name: String, version: String? = nil, transport: String = "mcp") {
        self.name = name
        self.version = version
        self.transport = transport
    }
}

public struct AuthenticatedIPCRequest: Codable, Equatable, Sendable {
    public let capabilityToken: CapabilityToken
    public let request: IPCRequest
    public let caller: AgentCallerIdentity?

    public init(
        capabilityToken: CapabilityToken,
        request: IPCRequest,
        caller: AgentCallerIdentity? = nil
    ) {
        self.capabilityToken = capabilityToken
        self.request = request
        self.caller = caller
    }
}

public enum IPCAuthenticationError: Error, Equatable, Sendable {
    case invalidCapabilityToken
}

public struct IPCAuthenticator: Sendable {
    public let expectedToken: CapabilityToken

    public init(expectedToken: CapabilityToken) {
        self.expectedToken = expectedToken
    }

    public func authenticate(_ request: AuthenticatedIPCRequest) throws -> IPCRequest {
        guard request.capabilityToken.constantTimeEquals(expectedToken) else {
            throw IPCAuthenticationError.invalidCapabilityToken
        }
        return request.request
    }
}
