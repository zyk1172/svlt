import Foundation
import VaultAuthorization
import VaultCore

public enum SecretOperationExecutionError: Error, Equatable, Sendable {
    case unavailable
    case unsupportedAction
    case missingSecretReference
    case invalidSecretUTF8
    case invalidParameter
    case batchValidationFailed
    case sessionNotFound
    case sessionExpired
    case sessionScopeMismatch
    case sessionControlUnavailable
    case sessionLimitReached
    case timedOut
    case outputLimitExceeded
    case processFailed
    case outputQuarantined
    case redirectRequiresReview
    case insecureTransportDenied
}

public enum SecretOperationExecutionCapability: String, Codable, Equatable, Sendable {
    case supported
    case unavailable
    case invalidParameters
}

public enum SecretOperationStage: String, Codable, Equatable, Sendable {
    case frameRead = "FRAME_READ"
    case frameDecode = "FRAME_DECODE"
    case argumentValidation = "ARGUMENT_VALIDATION"
    case authentication = "AUTHENTICATION"
    case timeout = "TIMEOUT"
    case connection = "CONNECTION"
    case hostKey = "HOST_KEY"
    case sshWrapper = "SSH_WRAPPER"
    case remoteCommand = "REMOTE_COMMAND"
}

public struct SecretOperationExecutionContext: Equatable, Sendable {
    public let principal: String
    public let securityGeneration: UInt64

    public init(principal: String, securityGeneration: UInt64) {
        self.principal = principal
        self.securityGeneration = securityGeneration
    }
}

public struct SSHCommandResult: Codable, Equatable, Sendable {
    public let index: Int
    public let status: String
    public let exitCode: Int32?
    public let stage: SecretOperationStage?
    public let stdout: String?
    public let stderr: String?

    public init(
        index: Int,
        status: String,
        exitCode: Int32? = nil,
        stage: SecretOperationStage? = nil,
        stdout: String? = nil,
        stderr: String? = nil
    ) {
        self.index = index
        self.status = status
        self.exitCode = exitCode
        self.stage = stage
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// The only result shape returned from an Agent secret action.  It contains
/// sanitized output and never contains a resolved secret value.
public struct SecretOperationOutput: Codable, Equatable, Sendable {
    public let status: String
    public let exitCode: Int32?
    public let stage: SecretOperationStage?
    public let stdout: String?
    public let stderr: String?
    public let httpStatus: Int?
    public let contentType: String?
    public let bodyPreview: String?
    public let rowCount: Int?
    public let rowsPreview: String?
    public let listingPreview: String?
    public let localPath: String?
    public let remotePath: String?
    public let sessionID: String?
    public let failedIndex: Int?
    public let results: [SSHCommandResult]?
    /// Populated only for a successful destination-binding operation. These
    /// are non-sensitive canonical metadata values, not resolved Secret data.
    public let destination: String?
    public let protocolType: SecretOperationProtocol?
    public let port: Int?
    public let hostKeyPin: SSHHostKeyPin?
    /// Set when an HTTP redirect stopped for an owner decision (§37). The
    /// agent re-submits a new exact request to this URL; that request is
    /// authorized through the ordinary flow.
    public let redirectLocation: String?
    public let redacted: Bool

    public init(
        status: String,
        exitCode: Int32? = nil,
        stage: SecretOperationStage? = nil,
        stdout: String? = nil,
        stderr: String? = nil,
        httpStatus: Int? = nil,
        contentType: String? = nil,
        bodyPreview: String? = nil,
        rowCount: Int? = nil,
        rowsPreview: String? = nil,
        listingPreview: String? = nil,
        localPath: String? = nil,
        remotePath: String? = nil,
        sessionID: String? = nil,
        failedIndex: Int? = nil,
        results: [SSHCommandResult]? = nil,
        destination: String? = nil,
        protocolType: SecretOperationProtocol? = nil,
        port: Int? = nil,
        hostKeyPin: SSHHostKeyPin? = nil,
        redirectLocation: String? = nil,
        redacted: Bool = true
    ) {
        self.status = status
        self.exitCode = exitCode
        self.stage = stage
        self.stdout = stdout
        self.stderr = stderr
        self.httpStatus = httpStatus
        self.contentType = contentType
        self.bodyPreview = bodyPreview
        self.rowCount = rowCount
        self.rowsPreview = rowsPreview
        self.listingPreview = listingPreview
        self.localPath = localPath
        self.remotePath = remotePath
        self.sessionID = sessionID
        self.failedIndex = failedIndex
        self.results = results
        self.destination = destination
        self.protocolType = protocolType
        self.port = port
        self.hostKeyPin = hostKeyPin
        self.redirectLocation = redirectLocation
        self.redacted = redacted
    }
}

private enum SSHWrapperExitCode {
    static let frameRead: Int32 = 121
    static let frameDecode: Int32 = 122
    static let argumentValidation: Int32 = 123
    static let timedOut: Int32 = 124
    static let wrapperFailed: Int32 = 125
    static let authenticationFailed: Int32 = 126
}

public protocol SecretOperationExecuting: Sendable {
    /// A side-effect-free capability check. It must not resolve a secret or
    /// perform any network/process operation. The service uses it before any
    /// approval or Secret resolution so an unavailable runner cannot consume a
    /// prompt or create compatibility authorization state.
    func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability

    /// The daemon-facing, non-sensitive capability manifest. A capability is
    /// never inferred from an MCP tool name; it comes from the concrete
    /// adapter registry used by this executor.
    func capabilities() -> [SecretOperationCapability]

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput

    func sshSessionStatuses(
        sessionID: String?,
        context: SecretOperationExecutionContext
    ) async throws -> [SSHSessionStatus]

    func closeSSHSession(
        sessionID: String,
        context: SecretOperationExecutionContext
    ) async throws

    func invalidateSecurityState() async
}

public extension SecretOperationExecuting {
    /// An executor must opt in to every supported action. Returning supported
    /// by default could make an unsupported action appear successful and let
    /// an older compatibility executor cross an authorization boundary.
    func preflight(_: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        .unavailable
    }

    func capabilities() -> [SecretOperationCapability] { [] }

    func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context _: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        try await execute(descriptor, metadata: metadata, resolve: resolve)
    }

    func sshSessionStatuses(
        sessionID _: String?,
        context _: SecretOperationExecutionContext
    ) async throws -> [SSHSessionStatus] {
        throw SecretOperationExecutionError.unavailable
    }

    func closeSSHSession(
        sessionID _: String,
        context _: SecretOperationExecutionContext
    ) async throws {
        throw SecretOperationExecutionError.unavailable
    }

    func invalidateSecurityState() async {}
}

/// Runs only purpose-built actions.  It intentionally has no generic command
/// path that accepts a secret as a CLI argument, environment variable, URL
/// query, or log field.
public struct LocalSecretOperationExecutor: SecretOperationExecuting {
    private static let expectExecutablePath = "/usr/bin/expect"
    /// Written only by the wrapper to its own stderr after a successful
    /// `wait`. Spawned SSH output is logged to the wrapper's stdout, so a
    /// remote command cannot manufacture this out-of-band completion proof.
    static let sshCompletionMarker = "__SVLT_SSH_REMOTE_COMMAND_COMPLETED_v1__"
    private let processRunner: any ProcessRunning
    private let outputSanitizer: OutputSanitizer
    private let sshSessionManager: SSHSessionManager
    private let outputLimitBytes: Int
    private let batchOutputLimitBytes: Int
    private let adapterRegistry: SecretOperationAdapterRegistry
    private let sshHostKeyDiscovery: SSHHostKeyDiscovery
    private let sshKnownHostsStore: SSHKnownHostsStore

    public init(
        processRunner: any ProcessRunning = FoundationProcessRunner(),
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        outputLimitBytes: Int = 1_048_576,
        batchOutputLimitBytes: Int = 4_194_304,
        sshSessionManager: SSHSessionManager? = nil,
        adapterRegistry: SecretOperationAdapterRegistry? = nil,
        sshKnownHostsDirectory: URL? = nil
    ) {
        self.processRunner = processRunner
        self.outputSanitizer = outputSanitizer
        self.outputLimitBytes = outputLimitBytes
        self.batchOutputLimitBytes = max(outputLimitBytes, batchOutputLimitBytes)
        self.sshSessionManager = sshSessionManager ?? SSHSessionManager(processRunner: processRunner)
        self.sshKnownHostsStore = SSHKnownHostsStore(directoryURL: sshKnownHostsDirectory)
        self.sshHostKeyDiscovery = SSHHostKeyDiscovery(processRunner: processRunner)
        self.adapterRegistry = adapterRegistry ?? SecretOperationAdapterRegistry(
            processRunner: processRunner,
            sshKnownHostsDirectory: sshKnownHostsDirectory
        )
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        try await execute(
            descriptor,
            metadata: metadata,
            context: SecretOperationExecutionContext(
                principal: "unscoped-agent",
                securityGeneration: 0
            ),
            resolve: resolve
        )
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        switch descriptor.actionType {
        case .sshCommand:
            return try await executeSSH(
                descriptor,
                metadata: metadata,
                context: context,
                resolve: resolve
            )
        case .httpRequest, .apiRequest, .sftpTransfer, .ftpTransfer, .databaseQuery, .browserLogin, .localAppFill,
             .localExecution, .trustedProcess:
            return try await adapterRegistry.execute(
                descriptor,
                metadata: metadata,
                context: context,
                resolve: resolve
            )
        default:
            throw SecretOperationExecutionError.unsupportedAction
        }
    }

    public func invalidateSecurityState() async {
        await sshSessionManager.invalidateAll()
        await adapterRegistry.invalidateSecurityState()
    }

    public func reviewSSHHostKey(host: String, port: Int) async throws -> SSHHostKeyReview {
        try await sshHostKeyDiscovery.review(host: host, port: port)
    }

    public func installSSHHostKey(host: String, port: Int, pin: SSHHostKeyPin) async throws {
        try await sshHostKeyDiscovery.install(
            host: host,
            port: port,
            pin: pin,
            into: sshKnownHostsStore
        )
    }

    public func capabilities() -> [SecretOperationCapability] {
        let expectAvailable = FileManager.default.isExecutableFile(atPath: Self.expectExecutablePath)
        return [
            SecretOperationCapability(
                kind: .ssh,
                status: expectAvailable ? .supported : .unavailable,
                operations: [.sshCommand],
                reason: expectAvailable
                    ? "raw single/multi-line commands and structured batches through an in-memory scoped ControlMaster with isolated SVLT host-key trust; the device owner decides execution"
                    : "macOS expect executable is unavailable",
                features: SecretOperationCapabilityFeatures(
                    auth: ["password"],
                    body: ["rawCommand", "multilineCommand", "structuredCommands"],
                    response: ["stdout", "stderr", "perCommandResults"],
                    transportSessionReuse: true
                )
            )
        ] + adapterRegistry.capabilityManifest()
    }

    public func sshSessionStatuses(
        sessionID: String?,
        context: SecretOperationExecutionContext
    ) async throws -> [SSHSessionStatus] {
        if let sessionID {
            return [try await sshSessionManager.status(
                sessionID: sessionID,
                principal: context.principal,
                securityGeneration: context.securityGeneration
            )]
        }
        return try await sshSessionManager.statuses(
            for: context.principal,
            securityGeneration: context.securityGeneration
        )
    }

    public func closeSSHSession(
        sessionID: String,
        context: SecretOperationExecutionContext
    ) async throws {
        do {
            try await sshSessionManager.close(
                sessionID: sessionID,
                principal: context.principal,
                securityGeneration: context.securityGeneration
            )
        } catch let error as SSHSessionManagerError {
            throw Self.mapSessionError(error)
        }
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        switch descriptor.actionType {
        case .sshCommand:
            if !FileManager.default.isExecutableFile(atPath: Self.expectExecutablePath) {
                return .unavailable
            }
            let port = descriptor.port ?? 22
            guard descriptor.destination?.isEmpty == false,
                  (1...65_535).contains(port),
                  reference(for: "passwordRef", in: descriptor) != nil,
                  reference(for: "usernameRef", in: descriptor) == nil,
                  let username = descriptor.parameters["username"],
                  Self.isSafeSSHUsername(username)
            else {
                return .invalidParameters
            }
            do {
                if let batch = descriptor.sshCommandBatch {
                    try batch.validate()
                } else if let command = descriptor.command {
                    // Technical validation only: non-empty, no NUL, size
                    // limit. Shell syntax is never inspected here.
                    _ = try SSHRemoteCommandEncoder.rawRemoteCommand(command)
                } else {
                    return .invalidParameters
                }
            } catch {
                return .invalidParameters
            }
            return .supported
        case .httpRequest, .apiRequest, .sftpTransfer, .ftpTransfer, .databaseQuery, .browserLogin, .localAppFill,
             .localExecution, .trustedProcess:
            return adapterRegistry.preflight(descriptor)
        default:
            return .unavailable
        }
    }

    private func executeSSH(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard let host = descriptor.destination,
              let passwordReference = reference(for: "passwordRef", in: descriptor)
        else {
            throw SecretOperationExecutionError.invalidParameter
        }

        guard Self.isSafeSSHHost(host),
              reference(for: "usernameRef", in: descriptor) == nil,
              let username = descriptor.parameters["username"],
              Self.isSafeSSHUsername(username)
        else {
            throw SecretOperationExecutionError.invalidParameter
        }

        let port = descriptor.port ?? 22
        guard (1...65_535).contains(port) else {
            throw SecretOperationExecutionError.invalidParameter
        }

        let hostKeyPin = try matchingHostKeyPin(
            host: host,
            port: port,
            protocolType: .ssh,
            metadata: metadata
        )

        let remoteCommands: [String]
        let stopOnFailure: Bool
        do {
            if let batch = descriptor.sshCommandBatch {
                try batch.validate()
                remoteCommands = try batch.commands.map { try SSHRemoteCommandEncoder.encode($0) }
                stopOnFailure = batch.stopOnFailure
            } else if let command = descriptor.command {
                // The raw command is executed byte-for-byte: it is passed as
                // a single ssh remote-command argv element, so the local
                // shell never interprets it and the remote login shell sees
                // exactly what the caller wrote — including newlines, quotes,
                // pipelines, redirects, and heredocs.
                remoteCommands = [try SSHRemoteCommandEncoder.rawRemoteCommand(command)]
                stopOnFailure = true
            } else {
                throw SSHCommandBatchValidationError.empty
            }
        } catch {
            throw SecretOperationExecutionError.batchValidationFailed
        }

        let scope = SSHSessionScope(
            principal: context.principal,
            host: host,
            port: port,
            username: username,
            passwordReferenceID: passwordReference.description,
            securityGeneration: context.securityGeneration,
            hostKeyPin: hostKeyPin
        )

        var commandResults: [SSHCommandResult] = []
        commandResults.reserveCapacity(remoteCommands.count)
        var sessionID = descriptor.sessionID
        var firstFailureIndex: Int?
        var totalOutputBytes = 0

        for (index, remoteCommand) in remoteCommands.enumerated() {
            let requestedSessionID = index == 0 ? descriptor.sessionID : sessionID
            let execution: SSHSessionCommandExecution
            do {
                execution = try await sshSessionManager.execute(
                    scope: scope,
                    requestedSessionID: requestedSessionID
                ) { [self] access in
                    try await executeSSHChannel(
                        access: access,
                        host: host,
                        port: port,
                        username: username,
                        passwordReference: passwordReference,
                        remoteCommand: remoteCommand,
                        hostKeyPin: hostKeyPin,
                        resolve: resolve
                    )
                }
            } catch let error as SSHSessionManagerError {
                throw Self.mapSessionError(error)
            } catch ProcessRunError.timedOut {
                throw SecretOperationExecutionError.timedOut
            } catch ProcessRunError.outputLimitExceeded {
                throw SecretOperationExecutionError.outputLimitExceeded
            }

            if execution.channelState == .remoteCommandCompleted,
               execution.masterReady {
                sessionID = execution.sessionID
            } else {
                // A failed wrapper/transport, or a command whose optional
                // ControlMaster was not verified, cannot keep an old session
                // handle alive. The caller must not mistake it for a
                // reusable transport after an unproven or non-persistent
                // channel.
                sessionID = nil
            }
            let processResult = Self.normalizedProcessResult(for: execution)
            totalOutputBytes += processResult.stdout.count + processResult.stderr.count
            guard totalOutputBytes <= batchOutputLimitBytes else {
                throw SecretOperationExecutionError.outputLimitExceeded
            }

            let sanitized: ProcessResult
            switch outputSanitizer.sanitize(
                processResult,
                fingerprints: execution.outputFingerprints
            ) {
            case .quarantined:
                throw SecretOperationExecutionError.outputQuarantined
            case let .sanitized(result):
                sanitized = result
            }
            guard let stdout = String(data: sanitized.stdout, encoding: .utf8),
                  let stderr = String(data: sanitized.stderr, encoding: .utf8)
            else {
                throw SecretOperationExecutionError.outputQuarantined
            }

            let outcome = Self.sshOutcome(
                for: execution.channelState,
                result: sanitized
            )
            let commandResult = SSHCommandResult(
                index: index,
                status: outcome.status,
                exitCode: sanitized.exitCode,
                stage: outcome.stage,
                stdout: stdout,
                stderr: stderr
            )
            commandResults.append(commandResult)
            if descriptor.sshCommandBatch != nil {
                await SecretOperationProgressContext.report(
                    SecretOperationProgress(
                        commandIndex: index,
                        stdout: stdout.isEmpty ? nil : stdout,
                        stderr: stderr.isEmpty ? nil : stderr
                    )
                )
            }
            if outcome.status != "COMPLETED" {
                firstFailureIndex = firstFailureIndex ?? index
                if stopOnFailure {
                    for notExecutedIndex in (index + 1)..<remoteCommands.count {
                        commandResults.append(
                            SSHCommandResult(index: notExecutedIndex, status: "NOT_EXECUTED")
                        )
                    }
                    break
                }
            }
        }

        if descriptor.sshCommandBatch != nil {
            return SecretOperationOutput(
                status: firstFailureIndex == nil ? "COMPLETED" : "PARTIAL_FAILED",
                sessionID: sessionID,
                failedIndex: firstFailureIndex,
                results: commandResults,
                redacted: true
            )
        }

        guard let result = commandResults.first else {
            throw SecretOperationExecutionError.processFailed
        }
        return SecretOperationOutput(
            status: result.status,
            exitCode: result.exitCode,
            stage: result.stage,
            stdout: result.stdout,
            stderr: result.stderr,
            sessionID: sessionID,
            redacted: true
        )
    }

    private func executeSSHChannel(
        access: SSHSessionAccess,
        host: String,
        port: Int,
        username: String,
        passwordReference: SecretReference,
        remoteCommand: String,
        hostKeyPin: SSHHostKeyPin?,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SSHSessionCommandExecution {
        let knownHostsPath: String
        do {
            if let hostKeyPin {
                knownHostsPath = try sshKnownHostsStore.validatedPinnedPath(
                    host: host,
                    port: port,
                    pin: hostKeyPin
                )
            } else {
                knownHostsPath = try sshKnownHostsStore.prepare()
            }
        } catch {
            throw SecretOperationExecutionError.unavailable
        }

        if access.requiresAuthentication {
            var passwordData = try await resolve(passwordReference)
            defer { passwordData.resetBytes(in: 0..<passwordData.count) }
            guard let password = String(data: passwordData, encoding: .utf8), !password.isEmpty else {
                throw SecretOperationExecutionError.invalidSecretUTF8
            }

            let rawResult: ProcessResult
            do {
                rawResult = try await processRunner.run(
                    ProcessInvocation(
                        executable: Self.expectExecutablePath,
                        arguments: ["-c", Self.expectSSHScript()]
                    ),
                    stdin: Self.expectSSHInput(
                        host: host,
                        port: port,
                        command: remoteCommand,
                        controlPath: access.controlPath,
                        knownHostsPath: knownHostsPath,
                        username: username,
                        password: password,
                        timeoutSeconds: 30, // legacy wrapper frame field; ignored
                        strictHostKeyChecking: hostKeyPin != nil
                    ),
                    timeout: nil,
                    outputLimitBytes: outputLimitBytes
                )
            } catch let error as ProcessRunError {
                switch error {
                case .timedOut:
                    return SSHSessionCommandExecution(
                        processResult: ProcessResult(
                            exitCode: SSHWrapperExitCode.timedOut,
                            stdout: Data(),
                            stderr: Data()
                        ),
                        channelState: .wrapperFailed,
                        outputFingerprints: OutputSanitizer.fingerprints(for: passwordData)
                    )
                case let .processLaunchFailed(message),
                     let .stdinWriteFailed(message),
                     let .launchFailed(message):
                    return SSHSessionCommandExecution(
                        processResult: ProcessResult(
                            exitCode: SSHWrapperExitCode.wrapperFailed,
                            stdout: Data(),
                            stderr: Data(message.utf8)
                        ),
                        channelState: .wrapperFailed,
                        outputFingerprints: OutputSanitizer.fingerprints(for: passwordData)
                    )
                case .outputLimitExceeded:
                    throw error
                }
            }

            let (unmarkedResult, remoteCommandCompleted) = Self.removeCompletionMarker(from: rawResult)
            let sanitized: ProcessResult
            switch outputSanitizer.sanitize(unmarkedResult, secrets: [passwordData]) {
            case .quarantined:
                throw SecretOperationExecutionError.outputQuarantined
            case let .sanitized(result):
                sanitized = result
            }
            return SSHSessionCommandExecution(
                processResult: sanitized,
                channelState: Self.initialChannelState(
                    for: sanitized,
                    remoteCommandCompleted: remoteCommandCompleted
                ),
                outputFingerprints: OutputSanitizer.fingerprints(for: passwordData)
            )
        }

        let result: ProcessResult
        do {
            result = try await processRunner.run(
                ProcessInvocation(
                    executable: "/usr/bin/ssh",
                    arguments: [
                    "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=\(hostKeyPin == nil ? "accept-new" : "yes")",
                        "-o", "UserKnownHostsFile=\(knownHostsPath)",
                        "-o", "GlobalKnownHostsFile=/dev/null",
                        "-o", "HashKnownHosts=\(hostKeyPin == nil ? "yes" : "no")",
                        "-o", "UpdateHostKeys=no",
                        "-o", "VerifyHostKeyDNS=yes",
                        "-o", "ControlMaster=auto",
                        "-o", "ControlPersist=300",
                        // `-S` passes the socket path through OpenSSH's
                        // dedicated socket-option boundary. Keep this in sync
                        // with the Expect-backed first channel.
                        "-S", access.controlPath,
                        "-p", String(port),
                        "--",
                        "\(username)@\(host)",
                        remoteCommand
                    ]
                ),
                stdin: Data(),
                timeout: nil,
                outputLimitBytes: outputLimitBytes
            )
        } catch let error as ProcessRunError {
            switch error {
            case .timedOut:
                return SSHSessionCommandExecution(
                    processResult: ProcessResult(exitCode: 124, stdout: Data(), stderr: Data()),
                    channelState: .wrapperFailed,
                    outputFingerprints: access.outputFingerprints
                )
            case let .processLaunchFailed(message),
                 let .stdinWriteFailed(message),
                 let .launchFailed(message):
                return SSHSessionCommandExecution(
                    processResult: ProcessResult(
                        exitCode: SSHWrapperExitCode.wrapperFailed,
                        stdout: Data(),
                        stderr: Data(message.utf8)
                    ),
                    channelState: .wrapperFailed,
                    outputFingerprints: access.outputFingerprints
                )
            case .outputLimitExceeded:
                throw error
            }
        }
        return SSHSessionCommandExecution(
            processResult: result,
            channelState: result.exitCode == 255 ? .transportFailed : .remoteCommandCompleted,
            outputFingerprints: access.outputFingerprints
        )
    }

    private static func mapSessionError(_ error: SSHSessionManagerError) -> SecretOperationExecutionError {
        switch error {
        case .sessionNotFound: return .sessionNotFound
        case .sessionExpired: return .sessionExpired
        case .scopeMismatch: return .sessionScopeMismatch
        case .controlUnavailable: return .sessionControlUnavailable
        case .controlDirectoryUnavailable: return .sessionControlUnavailable
        case .sessionLimitReached: return .sessionLimitReached
        }
    }

    private static func initialChannelState(
        for result: ProcessResult,
        remoteCommandCompleted: Bool
    ) -> SSHChannelState {
        guard remoteCommandCompleted else {
            // A non-marker result is never allowed to become a remote
            // command result merely because its process exit code is zero.
            // Preserve OpenSSH's conventional 255 connection failure when it
            // is available; all other unproven exits are wrapper failures.
            return result.exitCode == 255 ? .transportFailed : .wrapperFailed
        }
        // OpenSSH reserves 255 for its own transport errors. A remote command
        // that exits with any other status, including 125/126, is a completed
        // command and must not be confused with our wrapper status namespace.
        return result.exitCode == 255 ? .transportFailed : .remoteCommandCompleted
    }

    static func normalizedProcessResult(
        for execution: SSHSessionCommandExecution
    ) -> ProcessResult {
        guard execution.processResult.exitCode == 0 else {
            return execution.processResult
        }
        switch execution.channelState {
        case .wrapperFailed:
            return ProcessResult(
                exitCode: SSHWrapperExitCode.wrapperFailed,
                stdout: execution.processResult.stdout,
                stderr: execution.processResult.stderr
            )
        case .transportFailed:
            return ProcessResult(
                exitCode: 255,
                stdout: execution.processResult.stdout,
                stderr: execution.processResult.stderr
            )
        case .remoteCommandCompleted:
            return execution.processResult
        }
    }

    private static func containsHostKeyFailure(_ result: ProcessResult) -> Bool {
        let text = String(decoding: result.stderr + result.stdout, as: UTF8.self).lowercased()
        return text.contains("remote host identification has changed")
            || text.contains("host key verification failed")
    }

    private static func isSafeSSHHost(_ host: String) -> Bool {
        guard (1...255).contains(host.utf8.count),
              !host.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }),
              !host.contains(where: { $0.isWhitespace }),
              !host.contains("/"),
              !host.contains("@")
        else {
            return false
        }
        return true
    }

    private func reference(
        for parameter: String,
        in descriptor: SecretOperationDescriptor
    ) -> SecretReference? {
        guard let rawReference = descriptor.parameters[parameter] else {
            return nil
        }
        return descriptor.secretReferences.first { $0.description == rawReference }
    }

    private func matchingHostKeyPin(
        host: String,
        port: Int,
        protocolType: SecretOperationProtocol,
        metadata: [SecretPolicyMetadata]
    ) throws -> SSHHostKeyPin? {
        let pins = metadata
            .flatMap(\.destinationBindings)
            .filter {
                $0.matches(
                    requestedProtocol: protocolType,
                    destination: host,
                    url: nil,
                    port: port
                )
            }
            .compactMap(\.hostKeyPin)
        let uniquePins = Set(pins)
        guard uniquePins.count <= 1 else {
            // Multiple credentials cannot silently select different server
            // identities for one transport operation.
            throw SecretOperationExecutionError.invalidParameter
        }
        return uniquePins.first
    }

    static func expectSSHInput(
        host: String,
        port: Int,
        command: String,
        username: String,
        password: String,
        timeoutSeconds: Int
    ) -> Data {
        expectSSHInput(
            host: host,
            port: port,
            command: command,
            controlPath: "/svlt-test-control-path",
            knownHostsPath: "/private/tmp/svlt-test-known-hosts",
            username: username,
            password: password,
            timeoutSeconds: timeoutSeconds
        )
    }

    static func expectSSHInput(
        host: String,
        port: Int,
        command: String,
        controlPath: String,
        knownHostsPath: String = "/private/tmp/svlt-test-known-hosts",
        username: String,
        password: String,
        timeoutSeconds: Int,
        strictHostKeyChecking: Bool = false
    ) -> Data {
        let fields = [
            host,
            String(port),
            command,
            controlPath,
            knownHostsPath,
            username,
            password,
            String(timeoutSeconds),
            strictHostKeyChecking ? "1" : "0"
        ]
        return Data(fields.map {
            hexEncoded(Data($0.utf8))
        }.joined(separator: "\n").appending("\n").utf8)
    }

    /// Removes the wrapper-only completion line from stderr and reports
    /// whether the authenticated child reached the post-`wait` proof point.
    /// The marker is intentionally not accepted from stdout, where Expect
    /// logs all spawned SSH output.
    static func removeCompletionMarker(
        from result: ProcessResult
    ) -> (result: ProcessResult, completed: Bool) {
        let marker = Data("\(sshCompletionMarker)\n".utf8)
        guard let range = result.stderr.range(of: marker) else {
            return (result, false)
        }

        var stderr = result.stderr
        stderr.removeSubrange(range)
        guard stderr.range(of: marker) == nil else {
            // Multiple markers are not a valid wrapper transcript. Leave the
            // bytes untouched so the caller treats it as unproven.
            return (result, false)
        }
        return (
            ProcessResult(exitCode: result.exitCode, stdout: result.stdout, stderr: stderr),
            true
        )
    }

    static func expectTimeoutSeconds(for timeout: Duration) -> Int {
        max(1, Int(timeout.timeInterval.rounded(.up)))
    }

    private static func hexEncoded(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    static func sshOutcome(
        for channelState: SSHChannelState,
        result: ProcessResult
    ) -> (status: String, stage: SecretOperationStage?) {
        switch channelState {
        case .remoteCommandCompleted:
            return result.exitCode == 0
                ? ("COMPLETED", nil)
                : ("FAILED", .remoteCommand)
        case .transportFailed:
            return containsHostKeyFailure(result)
                ? ("HOST_KEY_FAILED", .hostKey)
                : ("FAILED", .connection)
        case .wrapperFailed:
            switch result.exitCode {
            case SSHWrapperExitCode.frameRead:
                return ("WRAPPER_FAILED", .frameRead)
            case SSHWrapperExitCode.frameDecode:
                return ("WRAPPER_FAILED", .frameDecode)
            case SSHWrapperExitCode.argumentValidation:
                return ("WRAPPER_FAILED", .argumentValidation)
            case SSHWrapperExitCode.timedOut:
                return ("TIMED_OUT", .timeout)
            case SSHWrapperExitCode.authenticationFailed:
                return ("AUTH_FAILED", .authentication)
            default:
                return ("WRAPPER_FAILED", .sshWrapper)
            }
        }
    }

    private static func isSafeSSHUsername(_ username: String) -> Bool {
        let bytes = username.utf8
        guard (1...256).contains(bytes.count),
              let first = bytes.first,
              (first >= 48 && first <= 57) || (first >= 65 && first <= 90) || (first >= 97 && first <= 122)
        else {
            return false
        }
        return bytes.allSatisfy { byte in
            (byte >= 48 && byte <= 57)
                || (byte >= 65 && byte <= 90)
                || (byte >= 97 && byte <= 122)
                || byte == 46 || byte == 95 || byte == 45
        }
    }

    static func expectSSHScript() -> String {
        return """
        proc readHexField {} {
            if {[gets stdin encoded] < 0 || $encoded eq ""} { exit \(SSHWrapperExitCode.frameRead) }
            if {[regexp {[^0-9A-Fa-f]} $encoded]} { exit \(SSHWrapperExitCode.frameDecode) }
            if {([string length $encoded] % 2) != 0} { exit \(SSHWrapperExitCode.frameDecode) }
            if {[catch {binary format H* $encoded} value]} { exit \(SSHWrapperExitCode.frameDecode) }
            return $value
        }
        set host [readHexField]
        set port [readHexField]
        set command [readHexField]
        set controlPath [readHexField]
        set knownHostsPath [readHexField]
        set username [readHexField]
        set password [readHexField]
        set timeoutSeconds [readHexField]
        set strictHostKeyChecking [readHexField]
        if {$host eq "" || $command eq "" || $controlPath eq "" || $knownHostsPath eq "" || $username eq "" || $password eq ""} { exit \(SSHWrapperExitCode.argumentValidation) }
        if {![string is integer -strict $port] || $port < 1 || $port > 65535} { exit \(SSHWrapperExitCode.argumentValidation) }
        if {![string is integer -strict $timeoutSeconds] || $timeoutSeconds < 1 || $timeoutSeconds > 30} { exit \(SSHWrapperExitCode.argumentValidation) }
        if {$strictHostKeyChecking ne "0" && $strictHostKeyChecking ne "1"} { exit \(SSHWrapperExitCode.argumentValidation) }
        # No execution deadline; cancellation is propagated by the owning Task.
        set timeout -1
        set passwordSent 0
        log_user 1
        set hostKeyCheckingMode accept-new
        set hashKnownHostsMode yes
        if {$strictHostKeyChecking eq "1"} {
            set hostKeyCheckingMode yes
            set hashKnownHostsMode no
        }
        # Build an actual Tcl list and expand it as argv. The final command,
        # trust-store path, and socket path each remain one ssh argv element,
        # including spaces and newlines; the local shell never interprets them.
        set sshArguments [list \
            /usr/bin/ssh \
            -o BatchMode=no \
            -o StrictHostKeyChecking=$hostKeyCheckingMode \
            -o "UserKnownHostsFile=$knownHostsPath" \
            -o GlobalKnownHostsFile=/dev/null \
            -o HashKnownHosts=$hashKnownHostsMode \
            -o UpdateHostKeys=no \
            -o VerifyHostKeyDNS=yes \
            -o ControlMaster=yes \
            -o ControlPersist=300 \
            -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 \
            -o PreferredAuthentications=password,keyboard-interactive \
            -S $controlPath \
            -p $port \
            -- \
            "$username@$host" \
            $command]
        if {[catch {spawn -noecho {*}$sshArguments}]} {
            exit \(SSHWrapperExitCode.wrapperFailed)
        }
        expect {
            -re "(?i)permission denied" { exit \(SSHWrapperExitCode.authenticationFailed) }
            -re "(?i)(password|passphrase).*:" {
                send -- "$password\\r"
                set passwordSent 1
            }
            eof {}
            timeout { exit \(SSHWrapperExitCode.timedOut) }
        }
        # EOF before a password prompt means SSH never established the
        # password-backed channel. Do not issue a second expect against the
        # closed spawn id; only wait once to collect the child's real status.
        if {$passwordSent} {
            # After the one authentication response, only wait for SSH to
            # finish. The spawn stream also contains remote stdout/stderr, so
            # post-auth text must never be interpreted as another protocol
            # prompt or authentication failure.
            expect {
                eof {}
                timeout { exit \(SSHWrapperExitCode.timedOut) }
            }
        }
        if {[catch {wait} waitResult]} { exit \(SSHWrapperExitCode.wrapperFailed) }
        if {[llength $waitResult] < 4} { exit \(SSHWrapperExitCode.wrapperFailed) }
        lassign $waitResult pid spawnId osError childStatus
        if {![string is integer -strict $osError] || $osError != 0} { exit \(SSHWrapperExitCode.wrapperFailed) }
        if {![string is integer -strict $childStatus] || $childStatus < 0 || $childStatus > 255} { exit \(SSHWrapperExitCode.wrapperFailed) }
        if {!$passwordSent || $childStatus == 255} {
            # Preserve OpenSSH's 255 connection failure for diagnostics. Any
            # other exit without a password prompt is an unproven wrapper
            # result and must not be allowed to look like remote success.
            if {$childStatus == 255} { exit 255 }
            exit \(SSHWrapperExitCode.wrapperFailed)
        }
        # This line is a wrapper-only protocol proof. Spawned SSH output is
        # logged to stdout; the completion marker is written to Expect's own
        # stderr only after wait and authentication have succeeded.
        puts stderr "\(sshCompletionMarker)"
        exit $childStatus
        """
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds) + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
