import CryptoKit
import Foundation

/// The risk state used by the local policy engine.  This is deliberately not
/// a numeric risk class: a denied operation is not a more convenient form of
/// approval, and the state machine must keep that distinction explicit.
public enum OperationRisk: String, Codable, CaseIterable, Sendable {
    case silent
    case approvalRequired
    case denied

    public var severity: Int {
        switch self {
        case .silent:
            return 0
        case .approvalRequired:
            return 1
        case .denied:
            return 2
        }
    }

    public static func max(_ lhs: Self, _ rhs: Self) -> Self {
        lhs.severity >= rhs.severity ? lhs : rhs
    }

    public var authorizationRequirement: AuthorizationRequirement {
        switch self {
        case .silent:
            return .none
        case .approvalRequired:
            return .reusableApproval
        case .denied:
            return .denied
        }
    }
}

/// Risk and authorization reuse are separate policy dimensions. A destructive
/// operation can therefore require a new device-owner decision even when a
/// reusable approval lease for ordinary writes is still active.
public enum AuthorizationRequirement: String, Codable, CaseIterable, Sendable {
    case none
    case reusableApproval
    case freshApprovalRequired
    case denied

    public var severity: Int {
        switch self {
        case .none: return 0
        case .reusableApproval: return 1
        case .freshApprovalRequired: return 2
        case .denied: return 3
        }
    }

    public static func max(_ lhs: Self, _ rhs: Self) -> Self {
        lhs.severity >= rhs.severity ? lhs : rhs
    }

    public var requiresApproval: Bool {
        self == .reusableApproval || self == .freshApprovalRequired
    }
}

public struct AgentRiskAssessment: Codable, Equatable, Sendable {
    public enum Source: String, Codable, CaseIterable, Sendable {
        case mainAgent
        case independentJudge
    }

    public enum IntentAlignment: String, Codable, CaseIterable, Sendable {
        case direct, supporting, unclear, unrelated
    }

    public enum EffectSeverity: String, Codable, CaseIterable, Sendable {
        case none, minor, bounded, broad, systemic, unknown
    }

    public enum Reversibility: String, Codable, CaseIterable, Sendable {
        case readOnly, easy, recoverable, difficult, irreversible, unknown
    }

    public enum SecretHandling: String, Codable, CaseIterable, Sendable {
        case none, credentialUse, userVisibleSensitiveData, thirdPartyExposure, plaintextSecretExposure, unknown
    }

    public enum ExecutionRecommendation: String, Codable, CaseIterable, Sendable {
        case automatic
        case reusableApproval
        case freshApproval
        case uncertain

        public var authorizationRequirement: AuthorizationRequirement {
            switch self {
            case .automatic: return .none
            case .reusableApproval: return .reusableApproval
            case .freshApproval, .uncertain: return .freshApprovalRequired
            }
        }
    }

    public let source: Source
    public let declaredRisk: OperationRisk
    public let reason: String
    public let userGoal: String
    public let taskContext: String
    public let intendedEffect: String
    public let expectedEffect: String
    public let expectedResult: String
    public let intentAlignment: IntentAlignment
    public let effectSeverity: EffectSeverity
    public let reversibility: Reversibility
    public let secretHandling: SecretHandling
    public let executionRecommendation: ExecutionRecommendation
    public let confidence: Double

    public init(
        source: Source = .mainAgent,
        declaredRisk: OperationRisk = .approvalRequired,
        reason: String,
        userGoal: String = "Complete the requested operation",
        taskContext: String = "No additional task context supplied",
        intendedEffect: String,
        expectedEffect: String = "Perform the intended operation",
        expectedResult: String = "Complete the requested task",
        intentAlignment: IntentAlignment = .unclear,
        effectSeverity: EffectSeverity = .unknown,
        reversibility: Reversibility = .unknown,
        secretHandling: SecretHandling = .unknown,
        executionRecommendation: ExecutionRecommendation = .uncertain,
        confidence: Double = 0
    ) {
        self.source = source
        self.declaredRisk = declaredRisk
        self.reason = reason
        self.userGoal = userGoal
        self.taskContext = taskContext
        self.intendedEffect = intendedEffect
        self.expectedEffect = expectedEffect
        self.expectedResult = expectedResult
        self.intentAlignment = intentAlignment
        self.effectSeverity = effectSeverity
        self.reversibility = reversibility
        self.secretHandling = secretHandling
        self.executionRecommendation = executionRecommendation
        self.confidence = confidence
    }

    public static let conservativeDefault = AgentRiskAssessment(
        declaredRisk: .approvalRequired,
        reason: "No semantic Agent assessment was supplied",
        userGoal: "Complete the requested operation",
        taskContext: "No additional task context supplied",
        intendedEffect: "unspecified",
        expectedEffect: "Unknown until reviewed",
        expectedResult: "Complete the requested task",
        intentAlignment: .unclear,
        effectSeverity: .unknown,
        reversibility: .unknown,
        secretHandling: .unknown,
        executionRecommendation: .uncertain,
        confidence: 0
    )
}

public struct SecretOperationPreflight: Codable, Equatable, Sendable {
    public enum Route: String, Codable, CaseIterable, Sendable {
        case fast
        case hard
        case gray
        case denied
    }

    public enum BlastRadius: String, Codable, CaseIterable, Sendable {
        case none
        case tiny
        case bounded
        case broad
        case systemic
        case unknown
    }

    public let route: Route
    public let policyRuleID: String
    public let authorizationRequirement: AuthorizationRequirement
    public let blastRadius: BlastRadius
    public let reasons: [String]
    public let technicalFailure: Bool
    /// A daemon-issued, short-lived binding for a GRAY preflight. This is
    /// evidence that the daemon is willing to accept one independent review;
    /// it is not trusted merely because it is present on a later descriptor.
    public let reviewID: UUID?

    public init(
        route: Route,
        policyRuleID: String,
        authorizationRequirement: AuthorizationRequirement,
        blastRadius: BlastRadius,
        reasons: [String],
        technicalFailure: Bool = false,
        reviewID: UUID? = nil
    ) {
        self.route = route
        self.policyRuleID = policyRuleID
        self.authorizationRequirement = authorizationRequirement
        self.blastRadius = blastRadius
        self.reasons = reasons
        self.technicalFailure = technicalFailure
        self.reviewID = reviewID
    }
}

public enum SecretOperationAction: String, Codable, CaseIterable, Sendable {
    case vaultStatus
    case usagePolicy
    case inspectReference
    case checkReferenceExists
    case sshCommand
    case httpRequest
    case apiRequest
    case databaseQuery
    case sftpTransfer
    case ftpTransfer
    case browserLogin
    case localAppFill
    case revealPlaintext
    case copyPlaintext
    case exportPlaintext
    case deleteSecret
    case changeSecretPolicy
    case changeDestinationBinding
    case changeAllowlist
    case changeAuthorizationRules
    case changeKeychain
    case migrateMasterKey
    case importRecoveryKey
    case exportRecoveryKey
    case restoreVault
    case clearVault
    case batchDelete
    case resetVault
    case localExecution
    /// An allowlisted signed process is a distinct future adapter boundary.
    /// `localExecution` is the explicit fresh-approval boundary for handing a
    /// Secret to an arbitrary local process; it is not an implicit shell
    /// fallback.
    case trustedProcess
}

/// Stable, sanitized failure states exposed on the local IPC boundary.  The
/// enum deliberately contains no free-form error text so a rejected request
/// cannot turn an exception message into a secret/log exfiltration channel.
public enum SecretOperationError: Error, Equatable, Sendable {
    case operationDenied
    case authorizationCancelled
    case authorizationDenied
    case authorizationTimeout
    case authorizationUnavailable
    case actionExecutorUnavailable
    case actionExecutionFailed
    case invalidOperationParameters
    case sessionNotFound
    case sessionExpired
    case sessionScopeMismatch
    case sessionControlUnavailable
    case sessionLimitReached
    case batchValidationFailed
    case redirectRequiresReview
    case outputQuarantined
    case insecureTransportDenied

    public var responseCode: String {
        switch self {
        case .operationDenied:
            return "OPERATION_DENIED"
        case .authorizationCancelled:
            return "AUTHORIZATION_CANCELLED"
        case .authorizationDenied:
            return "AUTHORIZATION_DENIED"
        case .authorizationTimeout:
            return "AUTHORIZATION_TIMEOUT"
        case .authorizationUnavailable:
            return "AUTHORIZATION_UNAVAILABLE"
        case .actionExecutorUnavailable:
            return "ACTION_EXECUTOR_UNAVAILABLE"
        case .actionExecutionFailed:
            return "ACTION_EXECUTION_FAILED"
        case .invalidOperationParameters:
            return "ARGUMENT_VALIDATION"
        case .sessionNotFound:
            return "SESSION_NOT_FOUND"
        case .sessionExpired:
            return "SESSION_EXPIRED"
        case .sessionScopeMismatch:
            return "SESSION_SCOPE_MISMATCH"
        case .sessionControlUnavailable:
            return "SESSION_CONTROL_UNAVAILABLE"
        case .sessionLimitReached:
            return "SESSION_LIMIT_REACHED"
        case .batchValidationFailed:
            return "BATCH_VALIDATION_FAILED"
        case .redirectRequiresReview:
            return "REDIRECT_REQUIRES_REVIEW"
        case .outputQuarantined:
            return "ACTION_OUTPUT_QUARANTINED"
        case .insecureTransportDenied:
            return "INSECURE_TRANSPORT_DENIED"
        }
    }
}

public enum SecretOperationProtocol: String, Codable, CaseIterable, Sendable {
    case ssh
    case http
    case https
    case sftp
    case scp
    case ftp
    case postgres
    case mysql
    case browser
    case localApp
    case file

    public var supportsSSHHostKeyPin: Bool {
        switch self {
        case .ssh, .sftp, .scp:
            return true
        default:
            return false
        }
    }
}

public enum SSHHostKeyPinValidationError: Error, Equatable, Sendable {
    case invalidAlgorithm
    case invalidSHA256Fingerprint
}

/// An owner-reviewed SSH host-key identity. The public key itself stays in an
/// App-owned OpenSSH trust file; only this non-secret fingerprint is persisted
/// with the encrypted destination binding and exposed through metadata.
public struct SSHHostKeyPin: Codable, Equatable, Hashable, Sendable {
    public let algorithm: String
    public let sha256: String

    public init(
        algorithm: String,
        sha256: String
    ) throws {
        let normalizedAlgorithm = algorithm.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...128).contains(normalizedAlgorithm.utf8.count),
              normalizedAlgorithm.unicodeScalars.allSatisfy(Self.isSafeAlgorithmScalar)
        else {
            throw SSHHostKeyPinValidationError.invalidAlgorithm
        }

        let normalizedFingerprint = sha256.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isValidSHA256Fingerprint(normalizedFingerprint) else {
            throw SSHHostKeyPinValidationError.invalidSHA256Fingerprint
        }

        self.algorithm = normalizedAlgorithm
        self.sha256 = normalizedFingerprint
    }

    private enum CodingKeys: String, CodingKey {
        case algorithm
        case sha256
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        do {
            try self.init(
                algorithm: container.decode(String.self, forKey: .algorithm),
                sha256: container.decode(String.self, forKey: .sha256)
            )
        } catch let error as SSHHostKeyPinValidationError {
            throw DecodingError.dataCorruptedError(
                forKey: .sha256,
                in: container,
                debugDescription: "Invalid SSH host-key pin: \(error)"
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(sha256, forKey: .sha256)
    }

    private static func isSafeAlgorithmScalar(_ scalar: UnicodeScalar) -> Bool {
        (scalar.value >= 0x41 && scalar.value <= 0x5A)
            || (scalar.value >= 0x61 && scalar.value <= 0x7A)
            || (scalar.value >= 0x30 && scalar.value <= 0x39)
            || scalar == "-"
            || scalar == "."
            || scalar == "_"
    }

    private static func isValidSHA256Fingerprint(_ value: String) -> Bool {
        guard value.hasPrefix("SHA256:") else { return false }
        let payload = value.dropFirst("SHA256:".count)
        guard payload.count == 43,
              payload.unicodeScalars.allSatisfy({ scalar in
                  (scalar.value >= 0x41 && scalar.value <= 0x5A)
                      || (scalar.value >= 0x61 && scalar.value <= 0x7A)
                      || (scalar.value >= 0x30 && scalar.value <= 0x39)
                      || scalar == "+"
                      || scalar == "/"
              })
        else {
            return false
        }
        return Data(base64Encoded: String(payload) + "=")?.count == 32
    }
}

/// An owner-approved service binding. The protocol and destination are one
/// authenticated unit; keeping them together prevents independently stored
/// arrays from being interpreted as an implicit Cartesian product.
public struct SecretDestinationBinding: Codable, Equatable, Sendable {
    public let protocolType: SecretOperationProtocol
    public let destination: String
    /// Optional exact service port. A nil port preserves legacy bindings that
    /// were intentionally scoped only to the normalized destination.
    public let port: Int?
    /// Present only for an owner-reviewed SSH host-key pin. Other protocols
    /// must treat this field as invalid rather than silently ignoring it.
    public let hostKeyPin: SSHHostKeyPin?

    public init(
        protocolType: SecretOperationProtocol,
        destination: String,
        port: Int? = nil,
        hostKeyPin: SSHHostKeyPin? = nil
    ) {
        self.protocolType = protocolType
        self.destination = destination
        self.port = port
        self.hostKeyPin = hostKeyPin
    }

    private enum CodingKeys: String, CodingKey {
        case protocolType
        case destination
        case port
        case hostKeyPin
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let protocolType = try container.decode(SecretOperationProtocol.self, forKey: .protocolType)
        let destination = try container.decode(String.self, forKey: .destination)
        let port = try container.decodeIfPresent(Int.self, forKey: .port)
        let hostKeyPin = try container.decodeIfPresent(SSHHostKeyPin.self, forKey: .hostKeyPin)
        guard port.map({ (1...65_535).contains($0) }) ?? true,
              hostKeyPin == nil || protocolType.supportsSSHHostKeyPin else {
            throw DecodingError.dataCorruptedError(
                forKey: .hostKeyPin,
                in: container,
                debugDescription: "Invalid destination binding profile"
            )
        }
        self.init(
            protocolType: protocolType,
            destination: destination,
            port: port,
            hostKeyPin: hostKeyPin
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(protocolType, forKey: .protocolType)
        try container.encode(destination, forKey: .destination)
        try container.encodeIfPresent(port, forKey: .port)
        try container.encodeIfPresent(hostKeyPin, forKey: .hostKeyPin)
    }

    public func matches(
        requestedProtocol: SecretOperationProtocol,
        destination: String?,
        url: String?,
        port requestedPort: Int? = nil
    ) -> Bool {
        guard protocolType == requestedProtocol else { return false }
        if let bindingPort = port {
            let effectiveRequestedPort = requestedPort ?? Self.defaultPort(for: requestedProtocol)
            guard effectiveRequestedPort == bindingPort else { return false }
        }
        if requestedProtocol == .http || requestedProtocol == .https {
            let requestedOrigin = SecretOperationDescriptor.normalizeHTTPOrigin(
                url ?? destination,
                expectedScheme: requestedProtocol.rawValue,
                defaultPort: requestedProtocol == .https ? 443 : 80,
                allowURLPath: true
            )
            let savedOrigin = SecretOperationDescriptor.normalizeHTTPOrigin(
                self.destination,
                expectedScheme: requestedProtocol.rawValue,
                requireExplicitPort: true,
                allowURLPath: false
            )
            return requestedOrigin != nil && requestedOrigin == savedOrigin
        }
        return SecretOperationDescriptor.normalizeDestination(destination ?? url)
            == SecretOperationDescriptor.normalizeDestination(self.destination)
    }

    private static func defaultPort(for protocolType: SecretOperationProtocol) -> Int? {
        switch protocolType {
        case .ssh, .sftp, .scp:
            return 22
        case .ftp:
            return 21
        default:
            return nil
        }
    }
}

/// Descriptive transport markers retained in Secret metadata. An explicit
/// `http` entry is an owner-saved opt-in for insecure HTTP; the exact origin
/// check is performed by the HTTP executor. Host-class helpers below are not
/// proof of DNS resolution or actual network egress and must not be used as a
/// substitute for that exact profile check.
public enum HTTPTransportSecurityPolicy: String, Codable, CaseIterable, Sendable {
    case httpsRequired
    case allowInsecureLoopback
    case allowInsecurePrivateNetwork

    public static func fromAllowedProtocols(_ allowedProtocols: [String]) -> Self {
        let normalized = Set(allowedProtocols.map { $0.lowercased() })
        if normalized.contains("http-loopback") {
            return .allowInsecureLoopback
        }
        if normalized.contains("http") {
            return .allowInsecurePrivateNetwork
        }
        return .httpsRequired
    }

    public func permitsInsecureHTTP(toHost host: String) -> Bool {
        let normalizedHost = Self.normalizedHost(host)
        switch self {
        case .httpsRequired:
            return false
        case .allowInsecureLoopback:
            return Self.isLoopbackHost(normalizedHost)
        case .allowInsecurePrivateNetwork:
            return Self.isLoopbackHost(normalizedHost) || Self.isPrivateHost(normalizedHost)
        }
    }

    /// Returns whether a host is explicitly local/private according to the
    /// same classification used by the HTTP transport policy. Public
    /// adapters use this as a fail-closed egress guard before resolving a
    /// Secret.
    public static func isPrivateOrLoopbackHost(_ host: String) -> Bool {
        let normalizedHost = Self.normalizedHost(host)
        return Self.isLoopbackHost(normalizedHost) || Self.isPrivateHost(normalizedHost)
    }

    private static func normalizedHost(_ host: String) -> String {
        host
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            .trimmingCharacters(in: CharacterSet(charactersIn: "."))
            .lowercased()
    }

    private static func isLoopbackHost(_ host: String) -> Bool {
        host == "localhost"
            || host.hasSuffix(".localhost")
            || host == "::1"
            || host.split(separator: ".").count == 4
                && ipv4Parts(host).first == 127
    }

    private static func isPrivateHost(_ host: String) -> Bool {
        if host.hasSuffix(".local") || host.hasSuffix(".lan")
            || host.hasSuffix(".internal") || host.hasSuffix(".home.arpa") {
            return true
        }
        if host.contains(":") {
            return host == "::"
                || host.hasPrefix("fc")
                || host.hasPrefix("fd")
                || host.hasPrefix("fe8")
                || host.hasPrefix("fe9")
                || host.hasPrefix("fea")
                || host.hasPrefix("feb")
        }
        let parts = ipv4Parts(host)
        guard parts.count == 4 else { return false }
        let first = parts[0]
        let second = parts[1]
        return first == 0
            || first == 10
            || first == 127
            || (first == 100 && (64...127).contains(second))
            || (first == 169 && second == 254)
            || (first == 172 && (16...31).contains(second))
            || (first == 192 && second == 168)
    }

    private static func ipv4Parts(_ host: String) -> [Int] {
        let components = host.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4,
              components.allSatisfy({ component in
                  !component.isEmpty
                      && (component.count == 1 || component.first != "0")
                      && component.allSatisfy(\.isNumber)
              }) else {
            return []
        }
        let parts = components.compactMap { Int($0) }
        guard parts.count == 4, parts.allSatisfy({ (0...255).contains($0) }) else {
            return []
        }
        return parts
    }
}

public enum SSHCommandBatchValidationError: Error, Equatable, Sendable {
    case empty
    case tooManyCommands
    case executableMissing
    case executableTooLong
    case executableContainsControlCharacter
    case tooManyArguments
    case argumentTooLong
    case argumentContainsControlCharacter
    case encodedBatchTooLarge
}

/// Structured SSH input. The command is still encoded as one safely quoted
/// remote-shell string at the final OpenSSH boundary; callers never provide a
/// raw shell fragment.
public struct SSHCommandSpec: Codable, Equatable, Hashable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String] = []) {
        self.executable = executable
        self.arguments = arguments
    }

    public func validate(
        maxExecutableLength: Int = 128,
        maxArgumentCount: Int = 32,
        maxArgumentLength: Int = 4_096
    ) throws {
        guard !executable.isEmpty else { throw SSHCommandBatchValidationError.executableMissing }
        guard executable.utf8.count <= maxExecutableLength else {
            throw SSHCommandBatchValidationError.executableTooLong
        }
        guard !executable.unicodeScalars.contains(where: Self.isUnsafeExecutableScalar) else {
            throw SSHCommandBatchValidationError.executableContainsControlCharacter
        }
        guard arguments.count <= maxArgumentCount else {
            throw SSHCommandBatchValidationError.tooManyArguments
        }
        for argument in arguments {
            guard argument.utf8.count <= maxArgumentLength else {
                throw SSHCommandBatchValidationError.argumentTooLong
            }
            guard !argument.unicodeScalars.contains(where: Self.isUnsafeArgumentScalar) else {
                throw SSHCommandBatchValidationError.argumentContainsControlCharacter
            }
        }
    }

    private static func isUnsafeExecutableScalar(_ scalar: UnicodeScalar) -> Bool {
        scalar.value < 0x20 || scalar.value == 0x7F
    }

    /// Tabs, newlines, and carriage returns are valid literal argument bytes
    /// when the remote encoder places the complete argument inside POSIX
    /// single quotes. NUL and other controls are rejected because they cannot
    /// be represented safely in an argv value or may act as terminal/control
    /// injection data on the remote side.
    private static func isUnsafeArgumentScalar(_ scalar: UnicodeScalar) -> Bool {
        scalar.value == 0
            || ((scalar.value < 0x20 || scalar.value == 0x7F)
                && scalar.value != 0x09
                && scalar.value != 0x0A
                && scalar.value != 0x0D)
    }
}

public struct SSHCommandBatch: Codable, Equatable, Sendable {
    public static let maxCommands = 32
    public static let maxEncodedBytes = 256 * 1024

    public let commands: [SSHCommandSpec]
    public let stopOnFailure: Bool

    public init(commands: [SSHCommandSpec], stopOnFailure: Bool = true) {
        self.commands = commands
        self.stopOnFailure = stopOnFailure
    }

    public func validate() throws {
        guard !commands.isEmpty else { throw SSHCommandBatchValidationError.empty }
        guard commands.count <= Self.maxCommands else {
            throw SSHCommandBatchValidationError.tooManyCommands
        }
        for command in commands {
            try command.validate()
        }
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(self), data.count <= Self.maxEncodedBytes else {
            throw SSHCommandBatchValidationError.encodedBatchTooLarge
        }
    }
}

public enum SecretFileOperation: String, Codable, CaseIterable, Sendable {
    case list
    case read
    case download
    case upload
    case write
    case overwrite
    case move
    case delete
}

/// Metadata needed by the policy engine.  It is safe to pass across IPC:
/// there is no encrypted record or plaintext value here.
public struct SecretPolicyMetadata: Codable, Equatable, Sendable {
    public let reference: SecretReference
    public let policy: SecretPolicy
    public let label: String?
    public let allowedDestinations: [String]
    public let allowedProtocols: [String]
    public let allowedBindings: [SecretDestinationBinding]

    /// Legacy records only have separate arrays. Preserve their historical
    /// behavior when it is unambiguous (one protocol marker), but once an
    /// explicit binding exists it is the sole source for pair-sensitive
    /// checks. Never synthesize a cross-product for mixed legacy protocols.
    public var destinationBindings: [SecretDestinationBinding] {
        guard allowedBindings.isEmpty else { return allowedBindings }
        guard allowedProtocols.count == 1 else { return [] }
        let marker = allowedProtocols[0].lowercased()
        let protocolType = marker == "http-loopback"
            ? SecretOperationProtocol.http
            : SecretOperationProtocol(rawValue: marker)
        guard let protocolType else { return [] }
        return allowedDestinations.map {
            SecretDestinationBinding(protocolType: protocolType, destination: $0)
        }
    }

    public var httpTransportSecurityPolicy: HTTPTransportSecurityPolicy {
        HTTPTransportSecurityPolicy.fromAllowedProtocols(allowedProtocols)
    }

    public init(
        reference: SecretReference,
        policy: SecretPolicy,
        label: String?,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = [],
        allowedBindings: [SecretDestinationBinding] = []
    ) {
        self.reference = reference
        self.policy = policy
        self.label = label
        self.allowedDestinations = allowedDestinations
        self.allowedProtocols = allowedProtocols
        self.allowedBindings = allowedBindings
    }
}

/// A complete, plaintext-free description of one operation.  `parameters`
/// contains only action parameters and opaque references; the local policy
/// engine treats it as untrusted input and never treats an agent assessment as
/// authorization.
public struct SecretOperationDescriptor: Codable, Equatable, Sendable {
    public let actionType: SecretOperationAction
    public let secretReferences: [SecretReference]
    public let destination: String?
    public let port: Int?
    public let protocolType: SecretOperationProtocol?
    public let command: String?
    public let httpMethod: String?
    public let url: String?
    public let databaseStatement: String?
    public let fileOperation: SecretFileOperation?
    public let fileTarget: String?
    public let localAppBundleID: String?
    /// Opaque transport handle. It is never used as an authorization grant;
    /// the service still validates the kernel-derived principal and policy for
    /// every command.
    public let sessionID: String?
    public let sshCommandBatch: SSHCommandBatch?
    public let payload: SecretOperationPayload?
    public let requestedEffects: [String]
    public let parameters: [String: String]
    /// A daemon-issued semantic-review binding. It is not an authorization
    /// grant by itself and is excluded from `operationHash`.
    public let reviewID: UUID?
    public let agentAssessment: AgentRiskAssessment

    public init(
        actionType: SecretOperationAction,
        secretReferences: [SecretReference] = [],
        destination: String? = nil,
        port: Int? = nil,
        protocolType: SecretOperationProtocol? = nil,
        command: String? = nil,
        httpMethod: String? = nil,
        url: String? = nil,
        databaseStatement: String? = nil,
        fileOperation: SecretFileOperation? = nil,
        fileTarget: String? = nil,
        localAppBundleID: String? = nil,
        sessionID: String? = nil,
        sshCommandBatch: SSHCommandBatch? = nil,
        payload: SecretOperationPayload? = nil,
        requestedEffects: [String] = [],
        parameters: [String: String] = [:],
        reviewID: UUID? = nil,
        agentAssessment: AgentRiskAssessment = .conservativeDefault
    ) {
        self.actionType = actionType
        self.secretReferences = secretReferences
        self.destination = destination
        self.port = port
        self.protocolType = protocolType
        self.command = command
        self.httpMethod = httpMethod
        self.url = url
        self.databaseStatement = databaseStatement
        self.fileOperation = fileOperation
        self.fileTarget = fileTarget
        self.localAppBundleID = localAppBundleID
        self.sessionID = sessionID
        self.sshCommandBatch = sshCommandBatch
        self.payload = payload
        self.requestedEffects = requestedEffects
        self.parameters = parameters
        self.reviewID = reviewID
        self.agentAssessment = agentAssessment
    }

    public var normalizedDestination: String? {
        Self.normalizeDestination(destination ?? url)
    }

    public var normalizedPath: String? {
        if let url, let parsedURL = URL(string: url) {
            return parsedURL.path.isEmpty ? "/" : parsedURL.path
        }
        return fileTarget
    }

    /// Typed payloads are canonical for new callers while legacy fields remain
    /// readable for compatibility with older MCP clients.
    public var effectiveHTTPMethod: String? {
        if case let .http(operation)? = payload { return operation.method.rawValue }
        return httpMethod
    }

    public var effectiveDatabaseStatement: String? {
        if case let .database(operation)? = payload { return operation.statement }
        return databaseStatement
    }

    public var effectiveFileOperation: SecretFileOperation? {
        if case let .fileTransfer(operation)? = payload { return operation.operation }
        return fileOperation
    }

    public var commandHash: String? {
        if let sshCommandBatch,
           let data = try? JSONEncoder().encode(sshCommandBatch) {
            return Self.sha256Hex(data)
        }
        guard let command else {
            return nil
        }
        return Self.sha256Hex(Data(command.utf8))
    }

    /// Stable enough for a short-lived local ticket because sorted JSON makes
    /// dictionary ordering deterministic. Transport handles are intentionally
    /// excluded: a sessionID identifies a reusable connection, not the
    /// operation's authorization subject, so replacing an expired transport
    /// must not change the exact operation ticket. The agent's free-text risk
    /// metadata is excluded for the same reason: it is untrusted explanatory
    /// input that the policy engine re-evaluates on every request, and two
    /// byte-identical operations must share one lease regardless of how the
    /// Agent words its assessment. The daemon-issued reviewID is excluded as
    /// well: it binds evidence to this operation, but is not the operation
    /// being authorized.
    public var operationHash: String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let data = (try? encoder.encode(AuthorizationHashPayload(descriptor: self))) ?? Data()
        return Self.sha256Hex(data)
    }

    private struct AuthorizationHashPayload: Codable {
        let actionType: SecretOperationAction
        let secretReferences: [SecretReference]
        let destination: String?
        let port: Int?
        let protocolType: SecretOperationProtocol?
        let command: String?
        let httpMethod: String?
        let url: String?
        let databaseStatement: String?
        let fileOperation: SecretFileOperation?
        let fileTarget: String?
        let localAppBundleID: String?
        let sshCommandBatch: SSHCommandBatch?
        let payload: SecretOperationPayload?
        let requestedEffects: [String]
        let parameters: [String: String]

        init(descriptor: SecretOperationDescriptor) {
            actionType = descriptor.actionType
            secretReferences = descriptor.secretReferences
            destination = descriptor.destination
            port = descriptor.port
            protocolType = descriptor.protocolType
            command = descriptor.command
            httpMethod = descriptor.httpMethod
            url = descriptor.url
            databaseStatement = descriptor.databaseStatement
            fileOperation = descriptor.fileOperation
            fileTarget = descriptor.fileTarget
            localAppBundleID = descriptor.localAppBundleID
            sshCommandBatch = descriptor.sshCommandBatch
            payload = descriptor.payload
            requestedEffects = descriptor.requestedEffects
            parameters = descriptor.parameters
        }
    }

    public func replacingDestination(_ destination: String, url: String? = nil) -> Self {
        Self(
            actionType: actionType,
            secretReferences: secretReferences,
            destination: destination,
            port: port,
            protocolType: protocolType,
            command: command,
            httpMethod: httpMethod,
            url: url ?? self.url,
            databaseStatement: databaseStatement,
            fileOperation: fileOperation,
            fileTarget: fileTarget,
            localAppBundleID: localAppBundleID,
            sessionID: sessionID,
            sshCommandBatch: sshCommandBatch,
            payload: payload,
            requestedEffects: requestedEffects,
            parameters: parameters,
            reviewID: reviewID,
            agentAssessment: agentAssessment
        )
    }

    public static func normalizeDestination(_ value: String?) -> String? {
        guard var value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            return nil
        }

        if let url = URL(string: value), let host = url.host {
            let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
            guard !normalizedHost.isEmpty else {
                return nil
            }
            if let port = url.port {
                return "\(normalizedHost):\(port)"
            }
            return normalizedHost
        }

        if value.hasPrefix("[") && value.hasSuffix("]") {
            value.removeFirst()
            value.removeLast()
        }
        return value.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
    }

    /// Canonicalizes an HTTP origin for profile-bound transport checks. A
    /// bare profile destination is accepted only when it includes an
    /// explicit port; a bare host must never widen an insecure HTTP profile to
    /// every port on that host. The scheme is supplied for legacy host[:port]
    /// bindings because protocol allowlists store it separately.
    public static func normalizeHTTPOrigin(
        _ value: String?,
        expectedScheme: String? = nil,
        defaultPort: Int? = nil,
        requireExplicitPort: Bool = false,
        allowURLPath: Bool = false
    ) -> String? {
        guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty,
              raw.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F }) else {
            return nil
        }

        let normalizedExpectedScheme = expectedScheme?.lowercased()
        guard normalizedExpectedScheme == nil
                || normalizedExpectedScheme == "http"
                || normalizedExpectedScheme == "https" else {
            return nil
        }

        var scheme: String
        var host: String
        var explicitPort: Int?
        var hadAbsoluteScheme = false

        if let url = URL(string: raw),
           let parsedScheme = url.scheme?.lowercased(),
           parsedScheme == "http" || parsedScheme == "https" {
            guard url.user == nil,
                  url.password == nil,
                  (allowURLPath || url.query == nil),
                  url.fragment == nil,
                  (allowURLPath || url.path.isEmpty || url.path == "/"),
                  let parsedHost = url.host,
                  !parsedHost.isEmpty else {
                return nil
            }
            scheme = parsedScheme
            host = parsedHost
            explicitPort = url.port
            hadAbsoluteScheme = true
        } else {
            guard let normalizedExpectedScheme else { return nil }
            guard !raw.contains("/") && !raw.contains("?") && !raw.contains("#") && !raw.contains("@") else {
                return nil
            }
            scheme = normalizedExpectedScheme

            if raw.hasPrefix("[") {
                guard let closingBracket = raw.firstIndex(of: "]") else { return nil }
                host = String(raw[raw.index(after: raw.startIndex)..<closingBracket])
                let suffix = raw[raw.index(after: closingBracket)...]
                if suffix.isEmpty {
                    explicitPort = nil
                } else {
                    guard suffix.first == ":",
                          let parsedPort = Int(suffix.dropFirst()) else {
                        return nil
                    }
                    explicitPort = parsedPort
                }
            } else {
                let parts = raw.split(separator: ":", omittingEmptySubsequences: false)
                if parts.count == 2, let parsedPort = Int(parts[1]) {
                    host = String(parts[0])
                    explicitPort = parsedPort
                } else if parts.count == 1 {
                    host = raw
                    explicitPort = nil
                } else {
                    // Unbracketed IPv6 is ambiguous when a port may follow.
                    return nil
                }
            }
        }

        guard normalizedExpectedScheme == nil || scheme == normalizedExpectedScheme,
              !host.isEmpty,
              !host.contains("/") else {
            return nil
        }
        let normalizedHost = host
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]."))
            .lowercased()
        guard !normalizedHost.isEmpty,
              normalizedHost.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F }) else {
            return nil
        }

        // A full `http://host`/`https://host` profile is already an exact
        // origin because the scheme determines its default port. Only the
        // legacy bare `host` form must provide an explicit port before it can
        // opt into an insecure HTTP origin.
        guard !requireExplicitPort || explicitPort != nil || hadAbsoluteScheme else { return nil }
        let port = explicitPort
            ?? (hadAbsoluteScheme ? (scheme == "https" ? 443 : 80) : (defaultPort ?? (scheme == "https" ? 443 : 80)))
        guard (1...65_535).contains(port) else { return nil }
        let formattedHost = normalizedHost.contains(":") ? "[\(normalizedHost)]" : normalizedHost
        return "\(scheme)://\(formattedHost):\(port)"
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

public struct PolicyDecision: Codable, Equatable, Sendable {
    public let risk: OperationRisk
    public let reasons: [String]
    public let normalizedDestination: String?
    public let requiredApproval: Bool
    public let authorizationRequirement: AuthorizationRequirement
    public let policyRuleID: String
    /// Kept for wire compatibility. The current authorization model never
    /// sets this flag: Agent risk is display/audit metadata only, fixed local
    /// rules choose the authorization requirement, and only technical
    /// failures fail hard.
    public let requiresFreshApprovalOnFirstUse: Bool
    /// True when the request could not be processed for technical reasons
    /// (malformed shape, contradictory fields, unverifiable identity) and the
    /// failure is an input error rather than an authorization decision. The
    /// service layer surfaces these as invalid-parameter errors, never as
    /// security denials.
    public let technicalFailure: Bool

    public init(
        risk: OperationRisk,
        reasons: [String],
        normalizedDestination: String?,
        requiredApproval: Bool,
        policyRuleID: String,
        authorizationRequirement: AuthorizationRequirement? = nil,
        requiresFreshApprovalOnFirstUse: Bool = false,
        technicalFailure: Bool = false
    ) {
        self.risk = risk
        self.reasons = reasons
        self.normalizedDestination = normalizedDestination
        self.requiredApproval = requiredApproval
        self.authorizationRequirement = authorizationRequirement ?? risk.authorizationRequirement
        self.policyRuleID = policyRuleID
        self.requiresFreshApprovalOnFirstUse = requiresFreshApprovalOnFirstUse
        self.technicalFailure = technicalFailure
    }

    private enum CodingKeys: String, CodingKey {
        case risk, reasons, normalizedDestination, requiredApproval, authorizationRequirement, policyRuleID,
             requiresFreshApprovalOnFirstUse, technicalFailure
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let risk = try container.decode(OperationRisk.self, forKey: .risk)
        self.init(
            risk: risk,
            reasons: try container.decode([String].self, forKey: .reasons),
            normalizedDestination: try container.decodeIfPresent(String.self, forKey: .normalizedDestination),
            requiredApproval: try container.decodeIfPresent(Bool.self, forKey: .requiredApproval) ?? (risk != .silent),
            policyRuleID: try container.decode(String.self, forKey: .policyRuleID),
            authorizationRequirement: try container.decodeIfPresent(AuthorizationRequirement.self, forKey: .authorizationRequirement),
            requiresFreshApprovalOnFirstUse: try container.decodeIfPresent(Bool.self, forKey: .requiresFreshApprovalOnFirstUse) ?? false,
            technicalFailure: try container.decodeIfPresent(Bool.self, forKey: .technicalFailure) ?? false
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(risk, forKey: .risk)
        try container.encode(reasons, forKey: .reasons)
        try container.encodeIfPresent(normalizedDestination, forKey: .normalizedDestination)
        try container.encode(requiredApproval, forKey: .requiredApproval)
        try container.encode(authorizationRequirement, forKey: .authorizationRequirement)
        try container.encode(policyRuleID, forKey: .policyRuleID)
        try container.encode(requiresFreshApprovalOnFirstUse, forKey: .requiresFreshApprovalOnFirstUse)
        try container.encode(technicalFailure, forKey: .technicalFailure)
    }
}
