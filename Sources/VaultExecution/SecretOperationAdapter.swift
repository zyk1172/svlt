import Foundation
import VaultCore

/// The capability inventory is derived from the daemon's actual adapters. It
/// is intentionally a projection: it contains no executable path, session
/// secret, or other internal implementation detail.
public enum SecretAdapterKind: String, Codable, CaseIterable, Sendable {
    case ssh
    case http
    case database
    case sftp
    case ftp
    case browser
    case localApp
    case export
    case localExecution
    case trustedProcess
}

/// Non-sensitive feature detail advertised by the concrete adapter registry.
/// This is descriptive capability data, never an authorization grant.
public struct SecretOperationCapabilityFeatures: Codable, Equatable, Sendable {
    public let auth: [String]
    public let body: [String]
    public let response: [String]
    public let transportSessionReuse: Bool
    public let derivedCredentialCapture: Bool
    public let publicNetworkEgress: Bool
    public let insecurePrivateNetworkHTTPProfileOptIn: Bool

    public init(
        auth: [String] = [],
        body: [String] = [],
        response: [String] = [],
        transportSessionReuse: Bool = false,
        derivedCredentialCapture: Bool = false,
        publicNetworkEgress: Bool = false,
        insecurePrivateNetworkHTTPProfileOptIn: Bool = false
    ) {
        self.auth = Self.sanitize(auth)
        self.body = Self.sanitize(body)
        self.response = Self.sanitize(response)
        self.transportSessionReuse = transportSessionReuse
        self.derivedCredentialCapture = derivedCredentialCapture
        self.publicNetworkEgress = publicNetworkEgress
        self.insecurePrivateNetworkHTTPProfileOptIn = insecurePrivateNetworkHTTPProfileOptIn
    }

    public static let empty = SecretOperationCapabilityFeatures()

    private static func sanitize(_ values: [String]) -> [String] {
        var result: [String] = []
        var seen = Set<String>()
        for value in values {
            let sanitized = String(value
                .filter { $0 != "\n" && $0 != "\r" && $0 != "\t" }
                .prefix(64))
            guard !sanitized.isEmpty, seen.insert(sanitized).inserted else { continue }
            result.append(sanitized)
            if result.count == 32 { break }
        }
        return result
    }
}

public struct SecretOperationCapability: Codable, Equatable, Sendable {
    public let version: Int
    public let kind: SecretAdapterKind
    public let status: SecretOperationExecutionCapability
    public let operations: [SecretOperationAction]
    public let reason: String?
    public let features: SecretOperationCapabilityFeatures

    public init(
        kind: SecretAdapterKind,
        status: SecretOperationExecutionCapability,
        operations: [SecretOperationAction],
        reason: String? = nil,
        version: Int = 1,
        features: SecretOperationCapabilityFeatures = .empty
    ) {
        self.version = max(1, version)
        self.kind = kind
        self.status = status
        self.operations = operations
        self.reason = reason.map(Self.sanitizeReason)
        self.features = features
    }

    private enum CodingKeys: String, CodingKey {
        case version, kind, status, operations, reason, features
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            kind: try container.decode(SecretAdapterKind.self, forKey: .kind),
            status: try container.decode(SecretOperationExecutionCapability.self, forKey: .status),
            operations: try container.decode([SecretOperationAction].self, forKey: .operations),
            reason: try container.decodeIfPresent(String.self, forKey: .reason),
            version: try container.decodeIfPresent(Int.self, forKey: .version) ?? 1,
            features: try container.decodeIfPresent(SecretOperationCapabilityFeatures.self, forKey: .features) ?? .empty
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(kind, forKey: .kind)
        try container.encode(status, forKey: .status)
        try container.encode(operations, forKey: .operations)
        try container.encodeIfPresent(reason, forKey: .reason)
        try container.encode(features, forKey: .features)
    }

    private static func sanitizeReason(_ value: String) -> String {
        String(value
            .split(whereSeparator: { $0 == "\n" || $0 == "\r" || $0 == "\t" })
            .joined(separator: " ")
            .prefix(240))
    }
}

/// Every non-SSH operation is dispatched through a purpose-built adapter.
/// The adapter receives the already-authorized resolver, but it remains
/// responsible for keeping resolved bytes inside its own execution boundary.
public protocol SecretOperationAdapter: Sendable {
    var kind: SecretAdapterKind { get }
    var capability: SecretOperationCapability { get }

    func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput

    func invalidateSecurityState() async
}

/// A disabled adapter is explicit. It is never allowed to perform a no-op
/// "success" because that would prime an authorization lease for an action the
/// daemon cannot actually execute.
public struct UnavailableSecretOperationAdapter: SecretOperationAdapter {
    public let kind: SecretAdapterKind
    public let capability: SecretOperationCapability

    public init(
        kind: SecretAdapterKind,
        operations: [SecretOperationAction],
        reason: String
    ) {
        self.kind = kind
        self.capability = SecretOperationCapability(
            kind: kind,
            status: .unavailable,
            operations: operations,
            reason: reason
        )
    }

    public func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        .unavailable
    }

    public func execute(
        _: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        context _: SecretOperationExecutionContext,
        resolve _: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        throw SecretOperationExecutionError.unavailable
    }

    public func invalidateSecurityState() async {}
}

/// Central registry for purpose-built adapters. SSH remains owned by
/// LocalSecretOperationExecutor because it also owns the existing SSH session
/// manager; all other secret-bearing operations use this registry.
public struct SecretOperationAdapterRegistry: @unchecked Sendable {
    private let adapters: [any SecretOperationAdapter]

    public init(
        processRunner: any ProcessRunning = FoundationProcessRunner(),
        httpSessionManager: HTTPSessionManager = HTTPSessionManager(),
        responseProjectionProfiles: [HTTPResponseProjectionProfile] = [],
        sshKnownHostsDirectory: URL? = nil
    ) {
        adapters = [
            HTTPSecretOperationAdapter(
                sessionManager: httpSessionManager,
                responseProjectionProfiles: responseProjectionProfiles
            ),
            UnavailableSecretOperationAdapter(
                kind: .database,
                operations: [.databaseQuery],
                reason: "没有安装并启用受 SVLT 约束的 PostgreSQL/MySQL 只读 driver"
            ),
            SFTPSecretOperationAdapter(
                processRunner: processRunner,
                sshKnownHostsDirectory: sshKnownHostsDirectory
            ),
            FTPSecretOperationAdapter(),
            UnavailableSecretOperationAdapter(
                kind: .browser,
                operations: [.browserLogin],
                reason: "没有签名的 Browser Native Messaging executor"
            ),
            UnavailableSecretOperationAdapter(
                kind: .localApp,
                operations: [.localAppFill],
                reason: "没有完成目标 App 签名校验的 Accessibility executor"
            ),
            UnavailableSecretOperationAdapter(
                kind: .localExecution,
                operations: [.localExecution],
                reason: "没有安装经过 SVLT 授权边界校验的 localExecution adapter"
            ),
            UnavailableSecretOperationAdapter(
                kind: .trustedProcess,
                operations: [.trustedProcess],
                reason: "没有配置 allowlisted signed trusted-process profile"
            )
        ]
    }

    public func capabilityManifest() -> [SecretOperationCapability] {
        adapters.map(\.capability)
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        guard let adapter = adapter(for: descriptor.actionType) else {
            return .unavailable
        }
        return adapter.preflight(descriptor)
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard let adapter = adapter(for: descriptor.actionType) else {
            throw SecretOperationExecutionError.unsupportedAction
        }
        return try await adapter.execute(
            descriptor,
            metadata: metadata,
            context: context,
            resolve: resolve
        )
    }

    public func invalidateSecurityState() async {
        for adapter in adapters {
            await adapter.invalidateSecurityState()
        }
    }

    private func adapter(for action: SecretOperationAction) -> (any SecretOperationAdapter)? {
        adapters.first { $0.capability.operations.contains(action) }
    }
}
