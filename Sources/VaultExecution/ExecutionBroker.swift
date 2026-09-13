import CryptoKit
import Foundation
import VaultAuthorization
import VaultCore

public protocol ExecutionAuthorizing: Sendable {
    func consumeAuthorization(for risk: RiskClass) async -> Bool
    func consumeExternalSend(destination: String) async -> Bool
}

public extension ExecutionAuthorizing {
    func consumeExternalSend(destination: String) async -> Bool {
        await consumeAuthorization(for: .writeOrExternalSend)
    }
}

extension AuthorizationSession: ExecutionAuthorizing {}

public protocol SecretResolving: Sendable {
    func resolve(_ reference: SecretReference, named name: String) async throws -> Data
}

public enum ExecutionBrokerError: Error, Equatable, Sendable {
    case authorizationRequired
    case secretInjectionNotAllowed
    case invalidSecretUTF8(String)
    case sanitizedOutputInvalidUTF8
}

public enum SanitizedExecutionResult: Codable, Equatable, Sendable {
    case completed(exitCode: Int32, stdout: String, stderr: String)
    case quarantined(reason: OutputQuarantineReason)

    private enum CodingKeys: String, CodingKey {
        case type
        case exitCode
        case stdout
        case stderr
        case reason
    }

    private enum ResultType: String, Codable {
        case completed
        case quarantined
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(ResultType.self, forKey: .type) {
        case .completed:
            self = .completed(
                exitCode: try container.decode(Int32.self, forKey: .exitCode),
                stdout: try container.decode(String.self, forKey: .stdout),
                stderr: try container.decode(String.self, forKey: .stderr)
            )
        case .quarantined:
            self = .quarantined(
                reason: try container.decode(OutputQuarantineReason.self, forKey: .reason)
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .completed(exitCode, stdout, stderr):
            try container.encode(ResultType.completed, forKey: .type)
            try container.encode(exitCode, forKey: .exitCode)
            try container.encode(stdout, forKey: .stdout)
            try container.encode(stderr, forKey: .stderr)
        case let .quarantined(reason):
            try container.encode(ResultType.quarantined, forKey: .type)
            try container.encode(reason, forKey: .reason)
        }
    }
}

public struct VaultSecretResolver: SecretResolving {
    private let recordStore: any RecordStore
    private let deviceKeyStore: any DeviceKeyStoring
    private let cipher: VaultCipher
    private let authenticationReason: String

    public init(
        recordStore: any RecordStore,
        deviceKeyStore: any DeviceKeyStoring,
        cipher: VaultCipher = VaultCipher(),
        authenticationReason: String = "Resolve a secret for approved local execution"
    ) {
        self.recordStore = recordStore
        self.deviceKeyStore = deviceKeyStore
        self.cipher = cipher
        self.authenticationReason = authenticationReason
    }

    public func resolve(_ reference: SecretReference, named name: String) async throws -> Data {
        let record = try await recordStore.latest(id: reference.id)
        let deviceKey = try await deviceKeyStore.deviceKey(reason: authenticationReason)

        return try cipher.decrypt(record, masterKey: SymmetricKey(data: deviceKey))
    }
}

public struct ExecutionBroker: Sendable {
    private let authorizer: any ExecutionAuthorizing
    private let secretResolver: any SecretResolving
    private let processRunner: any ProcessRunning
    private let sanitizer: OutputSanitizer
    private let validator: TemplateValidator
    private let timeout: Duration?
    private let outputLimitBytes: Int

    public init(
        authorizer: any ExecutionAuthorizing,
        secretResolver: any SecretResolving,
        processRunner: any ProcessRunning,
        sanitizer: OutputSanitizer = OutputSanitizer(),
        validator: TemplateValidator = TemplateValidator(),
        timeout: Duration? = nil,
        outputLimitBytes: Int = 1_048_576
    ) {
        self.authorizer = authorizer
        self.secretResolver = secretResolver
        self.processRunner = processRunner
        self.sanitizer = sanitizer
        self.validator = validator
        self.timeout = timeout
        self.outputLimitBytes = outputLimitBytes
    }

    public func validateAndExecute(
        _ request: ExecutionRequest,
        against template: ExecutionTemplate
    ) async throws -> SanitizedExecutionResult {
        let validated = try validator.validate(request, against: template)
        return try await execute(validated)
    }

    public func execute(_ execution: ValidatedExecution) async throws -> SanitizedExecutionResult {
        try Task.checkCancellation()

        // Generic shell execution is deliberately no longer a secret
        // transport. Purpose-built SecretOperationExecutor actions keep
        // resolved bytes inside the Agent and pass only non-secret arguments
        // to a narrowly defined runner.
        if execution.arguments.contains(where: { argument in
            if case .secret = argument {
                return true
            }
            return false
        }) {
            throw ExecutionBrokerError.secretInjectionNotAllowed
        }

        let isAuthorized: Bool
        if execution.risk == .writeOrExternalSend,
           let destination = execution.destinationHost,
           !destination.isEmpty {
            isAuthorized = await authorizer.consumeExternalSend(destination: destination)
        } else {
            isAuthorized = await authorizer.consumeAuthorization(for: execution.risk)
        }

        guard isAuthorized else {
            throw ExecutionBrokerError.authorizationRequired
        }

        try Task.checkCancellation()

        var invocationArguments: [String] = []
        for argument in execution.arguments {
            switch argument {
            case let .literal(value):
                invocationArguments.append(value)
            case let .value(_, value):
                invocationArguments.append(value)
            case .secret:
                throw ExecutionBrokerError.secretInjectionNotAllowed
            }

            try Task.checkCancellation()
        }

        let processResult = try await processRunner.run(
            ProcessInvocation(
                executable: execution.executable,
                arguments: invocationArguments
            ),
            stdin: Data(),
            timeout: timeout,
            outputLimitBytes: outputLimitBytes
        )

        switch sanitizer.sanitize(processResult, secrets: []) {
        case let .quarantined(reason):
            return .quarantined(reason: reason)
        case let .sanitized(result):
            guard let stdout = String(data: result.stdout, encoding: .utf8),
                  let stderr = String(data: result.stderr, encoding: .utf8) else {
                throw ExecutionBrokerError.sanitizedOutputInvalidUTF8
            }

            return .completed(
                exitCode: result.exitCode,
                stdout: stdout,
                stderr: stderr
            )
        }
    }
}
