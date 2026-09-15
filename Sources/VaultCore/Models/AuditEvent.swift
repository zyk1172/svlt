import Foundation

public enum AuditCallerTrust: String, Codable, Equatable, Sendable {
    case selfDeclared = "self-declared"
}

/// Display-only MCP caller metadata. It is deliberately separate from the
/// kernel-derived `AuditContext.principal`, which remains the only identity
/// used for authorization and compatibility-scope isolation.
public struct AuditCaller: Codable, Equatable, Sendable {
    public let displayName: String
    public let version: String?
    public let trust: AuditCallerTrust

    public init(name: String?, version: String? = nil) {
        let sanitizedName = Self.sanitize(name, fallback: "Unknown MCP Client", maxBytes: 64)
        self.displayName = sanitizedName ?? "Unknown MCP Client"
        self.version = Self.sanitize(version, fallback: nil, maxBytes: 32)
        self.trust = .selfDeclared
    }

    public init(displayName: String, version: String? = nil, trust: AuditCallerTrust = .selfDeclared) {
        self.displayName = Self.sanitize(displayName, fallback: "Unknown MCP Client", maxBytes: 64)
            ?? "Unknown MCP Client"
        self.version = Self.sanitize(version, fallback: nil, maxBytes: 32)
        self.trust = trust
    }

    public static let unknownMCPClient = Self(name: nil)

    public var displayLabel: String {
        if let version, !version.isEmpty {
            return "\(displayName)（自报 \(version)）"
        }
        return "\(displayName)（自报）"
    }

    private enum CodingKeys: String, CodingKey {
        case displayName
        case version
        case trust
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            displayName: try container.decode(String.self, forKey: .displayName),
            version: try container.decodeIfPresent(String.self, forKey: .version),
            trust: try container.decodeIfPresent(AuditCallerTrust.self, forKey: .trust) ?? .selfDeclared
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(displayName, forKey: .displayName)
        try container.encodeIfPresent(version, forKey: .version)
        try container.encode(trust, forKey: .trust)
    }

    private static func sanitize(_ value: String?, fallback: String?, maxBytes: Int) -> String? {
        guard let value else { return fallback }
        let stripped = value.unicodeScalars
            .filter {
                $0.value >= 0x20
                    && $0.value != 0x7F
                    && $0.value != 0x2028
                    && $0.value != 0x2029
            }
            .map(String.init)
            .joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !stripped.isEmpty,
              !stripped.localizedCaseInsensitiveContains("secret://"),
              !stripped.contains("/"),
              !stripped.contains("\\"),
              !stripped.contains("://")
        else {
            return fallback
        }
        var bounded = ""
        for scalar in stripped.unicodeScalars {
            let scalarText = String(scalar)
            guard bounded.utf8.count + scalarText.utf8.count <= maxBytes else { break }
            bounded.append(contentsOf: scalarText)
        }
        return bounded.isEmpty ? fallback : bounded
    }
}

public struct AuditEvent: Codable, Equatable, Sendable {
    public static let allowedEncodedKeys: Set<String> = [
        "eventID",
        "timestamp",
        "source",
        "integration",
        "correlationID",
        "requestID",
        "referenceID",
        "referenceCount",
        "operation",
        "risk",
        "authorizationOutcome",
        "authorizationMode",
        "caller",
        "declaredTarget",
        "status",
        "exitCode"
    ]

    public let id: UUID
    public let timestamp: Date
    public let source: AuditSource
    public let integration: String
    /// Correlates the complete operation across the Agent and App control
    /// planes. It is an opaque UUID, never a request payload or secret ID.
    public let correlationID: UUID
    /// Identifies one operation-bound authorization request when applicable.
    public let requestID: UUID?
    public let referenceID: String?
    public let referenceCount: Int
    public let operation: AuditOperation
    public let risk: Int
    public let authorizationOutcome: AuditAuthorizationOutcome
    /// Optional detail for an approved operation. Keeping this separate from
    /// `authorizationOutcome` preserves wire compatibility with older App and
    /// Agent builds that only understand approved/not-required.
    public let authorizationMode: AuditAuthorizationMode?
    public let caller: AuditCaller?
    public let declaredTarget: String?
    public let status: AuditStatus
    public let exitCode: Int32?

    public init(
        id: UUID = UUID(),
        timestamp: Date,
        source: AuditSource = .agent,
        integration: String,
        correlationID: UUID = UUID(),
        requestID: UUID? = nil,
        referenceID: String?,
        referenceCount: Int = 0,
        operation: AuditOperation,
        risk: Int,
        authorizationOutcome: AuditAuthorizationOutcome,
        declaredTarget: String?,
        status: AuditStatus,
        exitCode: Int32?,
        authorizationMode: AuditAuthorizationMode? = nil,
        caller: AuditCaller? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.source = source
        self.integration = integration
        self.correlationID = correlationID
        self.requestID = requestID
        self.referenceID = referenceID
        self.referenceCount = max(0, referenceCount)
        self.operation = operation
        self.risk = risk
        self.authorizationOutcome = authorizationOutcome
        self.authorizationMode = authorizationMode
        self.caller = caller
        self.declaredTarget = declaredTarget
        self.status = status
        self.exitCode = exitCode
    }

    private enum CodingKeys: String, CodingKey {
        case id = "eventID"
        case timestamp
        case source
        case integration
        case correlationID
        case requestID
        case referenceID
        case referenceCount
        case operation
        case risk
        case authorizationOutcome
        case authorizationMode
        case caller
        case declaredTarget
        case status
        case exitCode
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let integration = try container.decode(String.self, forKey: .integration)
        self.id = try container.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        self.timestamp = try container.decode(Date.self, forKey: .timestamp)
        self.source = try container.decodeIfPresent(AuditSource.self, forKey: .source)
            ?? AuditSource(integration: integration)
        self.integration = integration
        // Historical audit records predate explicit operation correlation.
        // Reusing their event ID keeps those records self-contained without
        // inferring a caller source from a new operation.
        self.correlationID = try container.decodeIfPresent(UUID.self, forKey: .correlationID) ?? self.id
        self.requestID = try container.decodeIfPresent(UUID.self, forKey: .requestID)
        self.referenceID = try container.decodeIfPresent(String.self, forKey: .referenceID)
        self.referenceCount = max(
            0,
            try container.decodeIfPresent(Int.self, forKey: .referenceCount)
                ?? (self.referenceID == nil ? 0 : 1)
        )
        self.operation = try container.decode(AuditOperation.self, forKey: .operation)
        self.risk = try container.decode(Int.self, forKey: .risk)
        self.authorizationOutcome = try container.decode(AuditAuthorizationOutcome.self, forKey: .authorizationOutcome)
        self.authorizationMode = try container.decodeIfPresent(AuditAuthorizationMode.self, forKey: .authorizationMode)
        self.caller = try container.decodeIfPresent(AuditCaller.self, forKey: .caller)
        self.declaredTarget = try container.decodeIfPresent(String.self, forKey: .declaredTarget)
        self.status = try container.decode(AuditStatus.self, forKey: .status)
        self.exitCode = try container.decodeIfPresent(Int32.self, forKey: .exitCode)
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(timestamp, forKey: .timestamp)
        try container.encode(source, forKey: .source)
        try container.encode(integration, forKey: .integration)
        try container.encode(correlationID, forKey: .correlationID)
        try container.encodeIfPresent(requestID, forKey: .requestID)
        try container.encodeIfPresent(referenceID, forKey: .referenceID)
        try container.encode(referenceCount, forKey: .referenceCount)
        try container.encode(operation, forKey: .operation)
        try container.encode(risk, forKey: .risk)
        try container.encode(authorizationOutcome, forKey: .authorizationOutcome)
        try container.encodeIfPresent(authorizationMode, forKey: .authorizationMode)
        try container.encodeIfPresent(caller, forKey: .caller)
        try container.encodeIfPresent(declaredTarget, forKey: .declaredTarget)
        try container.encode(status, forKey: .status)
        try container.encodeIfPresent(exitCode, forKey: .exitCode)
    }
}

/// Non-sensitive diagnostics produced while reading encrypted audit records.
/// Counts identify how many records were omitted without exposing paths,
/// ciphertext, payloads, or key material. The two legacy aliases are kept in
/// the public shape and on the wire for older App/Agent builds.
public struct AuditReadDiagnostics: Codable, Equatable, Sendable {
    public let recordDecodeFailureCount: Int
    public let authenticationFailureCount: Int
    public let eventDecodeFailureCount: Int
    public let unsupportedMetadataVersionCount: Int
    public let legacyCompatibilityFailureCount: Int

    public init(
        recordDecodeFailureCount: Int = 0,
        authenticationFailureCount: Int = 0,
        eventDecodeFailureCount: Int = 0,
        unsupportedMetadataVersionCount: Int = 0,
        legacyCompatibilityFailureCount: Int = 0
    ) {
        self.recordDecodeFailureCount = max(0, recordDecodeFailureCount)
        self.authenticationFailureCount = max(0, authenticationFailureCount)
        self.eventDecodeFailureCount = max(0, eventDecodeFailureCount)
        self.unsupportedMetadataVersionCount = max(0, unsupportedMetadataVersionCount)
        self.legacyCompatibilityFailureCount = max(0, legacyCompatibilityFailureCount)
    }

    /// Source-compatible initializer for the aggregate diagnostics used by
    /// older App/Agent callers.
    public init(unreadableRecordCount: Int, integrityFailureCount: Int = 0) {
        self.init(
            recordDecodeFailureCount: unreadableRecordCount,
            authenticationFailureCount: integrityFailureCount
        )
    }

    /// Source-compatible initializer for callers that only supplied the old
    /// integrity aggregate.
    public init(integrityFailureCount: Int) {
        self.init(authenticationFailureCount: integrityFailureCount)
    }

    public static let none = Self()

    /// Source-compatible aggregate for callers written before diagnostics
    /// were split into concrete failure classes. Keep all non-authentication
    /// omissions visible to an older App that only understands this field.
    public var unreadableRecordCount: Int {
        recordDecodeFailureCount
            + eventDecodeFailureCount
            + unsupportedMetadataVersionCount
            + legacyCompatibilityFailureCount
    }

    /// Source-compatible alias for AES-GCM authentication failures.
    public var integrityFailureCount: Int { authenticationFailureCount }

    public var skippedRecordCount: Int {
        recordDecodeFailureCount
            + authenticationFailureCount
            + eventDecodeFailureCount
            + unsupportedMetadataVersionCount
            + legacyCompatibilityFailureCount
    }

    public var hasIssues: Bool {
        skippedRecordCount > 0
    }

    private enum CodingKeys: String, CodingKey {
        case unreadableRecordCount
        case integrityFailureCount
        case recordDecodeFailureCount
        case authenticationFailureCount
        case eventDecodeFailureCount
        case unsupportedMetadataVersionCount
        case legacyCompatibilityFailureCount
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let recordDecodeFailureCount = try container.decodeIfPresent(Int.self, forKey: .recordDecodeFailureCount)
        let legacyRecordDecodeFailureCount = try container.decodeIfPresent(Int.self, forKey: .unreadableRecordCount)
        let authenticationFailureCount = try container.decodeIfPresent(Int.self, forKey: .authenticationFailureCount)
        let legacyAuthenticationFailureCount = try container.decodeIfPresent(Int.self, forKey: .integrityFailureCount)
        self.init(
            recordDecodeFailureCount: recordDecodeFailureCount ?? legacyRecordDecodeFailureCount ?? 0,
            authenticationFailureCount: authenticationFailureCount ?? legacyAuthenticationFailureCount ?? 0,
            eventDecodeFailureCount: try container.decodeIfPresent(Int.self, forKey: .eventDecodeFailureCount) ?? 0,
            unsupportedMetadataVersionCount: try container.decodeIfPresent(Int.self, forKey: .unsupportedMetadataVersionCount) ?? 0,
            legacyCompatibilityFailureCount: try container.decodeIfPresent(Int.self, forKey: .legacyCompatibilityFailureCount) ?? 0
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        // Write both names so an older App can still render an aggregate
        // warning while a newer App receives the detailed classification.
        try container.encode(unreadableRecordCount, forKey: .unreadableRecordCount)
        try container.encode(authenticationFailureCount, forKey: .integrityFailureCount)
        try container.encode(recordDecodeFailureCount, forKey: .recordDecodeFailureCount)
        try container.encode(authenticationFailureCount, forKey: .authenticationFailureCount)
        try container.encode(eventDecodeFailureCount, forKey: .eventDecodeFailureCount)
        try container.encode(unsupportedMetadataVersionCount, forKey: .unsupportedMetadataVersionCount)
        try container.encode(legacyCompatibilityFailureCount, forKey: .legacyCompatibilityFailureCount)
    }
}

/// A bounded audit read returns every record that could be authenticated and
/// decoded, together with safe diagnostics for records that were skipped.
public struct AuditReadResult: Equatable, Sendable {
    public let events: [AuditEvent]
    public let diagnostics: AuditReadDiagnostics

    public init(events: [AuditEvent], diagnostics: AuditReadDiagnostics = .none) {
        self.events = events
        self.diagnostics = diagnostics
    }
}

/// Trusted caller metadata installed at the IPC handler boundary. Production
/// AppControl requests use `.app`; Agent/MCP requests use `.agent` plus a
/// kernel-derived principal for the calling process. The principal is kept in
/// memory for authorization scoping and is not persisted in audit events. The
/// task local survives actor hops without mutable shared state, so concurrent
/// requests cannot overwrite one another's audit source or correlation.
public struct AuditContext: Equatable, Sendable {
    public let source: AuditSource
    public let principal: String
    public let correlationID: UUID
    public let requestID: UUID?
    public let caller: AuditCaller?

    public init(
        source: AuditSource,
        correlationID: UUID = UUID(),
        requestID: UUID? = nil,
        principal: String? = nil,
        caller: AuditCaller? = nil
    ) {
        self.source = source
        self.principal = principal ?? source.rawValue
        self.correlationID = correlationID
        self.requestID = requestID
        self.caller = caller
    }

    public func withRequestID(_ requestID: UUID?) -> Self {
        Self(
            source: source,
            correlationID: correlationID,
            requestID: requestID,
            principal: principal,
            caller: caller
        )
    }

    @TaskLocal public static var current: AuditContext?
}

public enum AuditSource: String, Codable, Equatable, Sendable {
    case app
    case agent

    public var displayName: String {
        switch self {
        case .app: return "App"
        case .agent: return "Agent"
        }
    }

    fileprivate init(integration: String) {
        self = integration.localizedCaseInsensitiveContains("app-control") ? .app : .agent
    }
}

public enum AuditOperation: String, Codable, Equatable, Sendable {
    case status
    case reveal
    case create
    case secureExecute
    case catalogMutation
    case authorization
    case credentialUse
    case formatCheck
    case formatRepair

    public var displayName: String {
        switch self {
        case .status: return "状态检查"
        case .reveal: return "本机显示"
        case .create: return "创建密文"
        case .secureExecute: return "智能体安全执行"
        case .catalogMutation: return "目录修改"
        case .authorization: return "本机授权"
        case .credentialUse: return "凭据使用"
        case .formatCheck: return "检查格式"
        case .formatRepair: return "修复格式"
        }
    }
}

public enum AuditAuthorizationOutcome: String, Codable, Equatable, Sendable {
    case approved
    case denied
    case notRequired
    case requested
    case cancelled
    case expired

    public var displayName: String {
        switch self {
        case .approved: return "已授权"
        case .denied: return "已拒绝"
        case .notRequired: return "无需授权"
        case .requested: return "待授权"
        case .cancelled: return "已取消"
        case .expired: return "已过期"
        }
    }
}

/// Non-sensitive detail describing how an approved operation was authorized.
/// This is optional so older audit records and older App/Agent peers remain
/// readable. It deliberately does not contain operation descriptors or secret
/// material.
public enum AuditAuthorizationMode: String, Codable, Equatable, Sendable {
    case freshLocalApproval = "fresh-local-approval"
    case executionWindowReuse = "execution-window-reuse"

    public var displayName: String {
        switch self {
        case .freshLocalApproval: return "本机新认证"
        case .executionWindowReuse: return "会话授权复用"
        }
    }
}

public enum AuditStatus: String, Codable, Equatable, Sendable {
    case displayedToUser
    case created
    case completed
    case quarantined
    case failure
    case requested
    case cancelled
    case expired

    public var displayName: String {
        switch self {
        case .displayedToUser: return "已显示"
        case .created: return "已创建"
        case .completed: return "已完成"
        case .quarantined: return "已隔离"
        case .failure: return "失败"
        case .requested: return "已请求"
        case .cancelled: return "已取消"
        case .expired: return "已过期"
        }
    }
}

/// The only audit shape exposed to the App UI. It intentionally omits
/// reference IDs and all decrypted values.
public struct CatalogSecurityAuditEntry: Codable, Equatable, Identifiable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let source: AuditSource
    public let operation: AuditOperation
    public let authorizationOutcome: AuditAuthorizationOutcome
    public let authorizationMode: AuditAuthorizationMode?
    public let caller: AuditCaller?
    public let result: AuditStatus
    public let target: String
    public let referenceCount: Int

    public init(
        id: UUID,
        timestamp: Date,
        source: AuditSource,
        operation: AuditOperation,
        authorizationOutcome: AuditAuthorizationOutcome,
        result: AuditStatus,
        target: String,
        referenceCount: Int,
        authorizationMode: AuditAuthorizationMode? = nil,
        caller: AuditCaller? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.source = source
        self.operation = operation
        self.authorizationOutcome = authorizationOutcome
        self.authorizationMode = authorizationMode
        self.caller = caller
        self.result = result
        self.target = target
        self.referenceCount = max(0, referenceCount)
    }
}

/// The bounded, non-sensitive AppControl projection of a recent audit read.
public struct CatalogRecentAuditResult: Codable, Equatable, Sendable {
    public let entries: [CatalogSecurityAuditEntry]
    public let diagnostics: AuditReadDiagnostics

    public init(
        entries: [CatalogSecurityAuditEntry],
        diagnostics: AuditReadDiagnostics = .none
    ) {
        self.entries = entries
        self.diagnostics = diagnostics
    }
}
