import Foundation
import VaultCore

/// Purpose-built SFTP/SCP execution. OpenSSH is used only as the protocol
/// implementation; the adapter never invokes a shell and never places a
/// resolved credential in argv or environment. The Expect wrapper receives
/// hex-framed fields and supplies the password only to the password prompt.
public struct SFTPSecretOperationAdapter: SecretOperationAdapter, SSHHostKeyPinning {
    public let kind: SecretAdapterKind = .sftp
    public let capability: SecretOperationCapability

    private static let expectExecutablePath = "/usr/bin/expect"
    private static let sftpExecutablePath = "/usr/bin/sftp"
    private static let outputLimitBytes = 1_048_576
    private static let wrapperFrameRead: Int32 = 121
    private static let wrapperFrameDecode: Int32 = 122
    private static let wrapperArgumentValidation: Int32 = 123
    private static let wrapperTimedOut: Int32 = 124
    private static let wrapperFailed: Int32 = 125
    private static let wrapperAuthenticationFailed: Int32 = 126
    static let completionMarker = "__SVLT_SFTP_TRANSFER_COMPLETED_v1__"

    private let processRunner: any ProcessRunning
    private let outputSanitizer: OutputSanitizer
    private let localRoot: URL
    private let sshHostKeyDiscovery: SSHHostKeyDiscovery
    private let sshKnownHostsStore: SSHKnownHostsStore

    public init(
        processRunner: any ProcessRunning = FoundationProcessRunner(),
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        localRoot: URL = FileTransferAdapterSupport.defaultTransferRoot,
        sshKnownHostsDirectory: URL? = nil
    ) {
        self.processRunner = processRunner
        self.outputSanitizer = outputSanitizer
        self.localRoot = localRoot.standardizedFileURL
        self.sshHostKeyDiscovery = SSHHostKeyDiscovery(processRunner: processRunner)
        self.sshKnownHostsStore = SSHKnownHostsStore(directoryURL: sshKnownHostsDirectory)
        let available = FileManager.default.isExecutableFile(atPath: Self.expectExecutablePath)
            && FileManager.default.isExecutableFile(atPath: Self.sftpExecutablePath)
        self.capability = SecretOperationCapability(
            kind: .sftp,
            status: available ? .supported : .unavailable,
            operations: [.sftpTransfer],
            reason: available
                ? "SFTP/SCP list/download/upload/delete；本地文件可使用任意绝对路径，远端路径不限定目录"
                : "macOS expect 或 sftp executable 不可用",
            features: SecretOperationCapabilityFeatures(
                auth: ["password"],
                body: ["list", "download", "upload", "overwrite", "delete"],
                response: ["listing", "localPath", "remotePath", "metadataOnly"],
                transportSessionReuse: false,
                derivedCredentialCapture: false,
                publicNetworkEgress: true
            )
        )
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        guard capability.status == .supported else { return .unavailable }
        do {
            _ = try FileTransferAdapterSupport.makePlan(
                for: descriptor,
                action: .sftpTransfer,
                protocols: [.sftp, .scp],
                defaultPort: 22,
                localRoot: localRoot
            )
            return .supported
        } catch {
            return .invalidParameters
        }
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        context _: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        guard capability.status == .supported else {
            throw SecretOperationExecutionError.unavailable
        }

        let plan: FileTransferPlan
        do {
            plan = try FileTransferAdapterSupport.makePlan(
                for: descriptor,
                action: .sftpTransfer,
                protocols: [.sftp, .scp],
                defaultPort: 22,
                localRoot: localRoot
            )
        } catch FileTransferAdapterError.unsupportedOperation {
            throw SecretOperationExecutionError.invalidParameter
        } catch {
            throw SecretOperationExecutionError.invalidParameter
        }

        do {
            try prepareLocalFile(for: plan)
        } catch {
            throw SecretOperationExecutionError.invalidParameter
        }

        let hostKeyPin = try matchingHostKeyPin(
            host: plan.host,
            port: plan.port,
            protocolType: plan.protocolType,
            metadata: metadata
        )
        let knownHostsPath: String
        do {
            if let hostKeyPin {
                knownHostsPath = try sshKnownHostsStore.validatedPinnedPath(
                    host: plan.host,
                    port: plan.port,
                    pin: hostKeyPin
                )
            } else {
                knownHostsPath = try sshKnownHostsStore.prepare()
            }
        } catch {
            throw SecretOperationExecutionError.unavailable
        }

        var secretBuffers: [Data] = []
        defer {
            for index in secretBuffers.indices {
                secretBuffers[index].resetBytes(in: 0..<secretBuffers[index].count)
            }
        }

        let passwordData = try await resolve(plan.passwordReference)
        secretBuffers.append(passwordData)
        let password = try Self.secretString(passwordData)
        let username: String
        if let usernameReference = plan.usernameReference {
            let usernameData = try await resolve(usernameReference)
            secretBuffers.append(usernameData)
            username = try Self.safeUsername(Self.secretString(usernameData))
        } else if let planUsername = plan.username {
            username = try Self.safeUsername(planUsername)
        } else {
            throw SecretOperationExecutionError.invalidParameter
        }

        let stagingURL = plan.operation == .download
            ? FileTransferAdapterSupport.makeStagingURL(for: plan.localURL!)
            : nil
        defer {
            if let stagingURL {
                try? FileManager.default.removeItem(at: stagingURL)
            }
        }

        let command = try Self.batchCommand(for: plan, stagingURL: stagingURL)
        let rawResult: ProcessResult
        do {
            rawResult = try await processRunner.run(
                ProcessInvocation(
                    executable: Self.expectExecutablePath,
                    arguments: ["-c", Self.expectScript()]
                ),
                stdin: Self.expectInput(
                    host: plan.host,
                    port: plan.port,
                    username: username,
                    password: password,
                    batch: command,
                    timeoutSeconds: Self.timeoutSeconds(plan.timeout),
                    knownHostsPath: knownHostsPath,
                    strictHostKeyChecking: hostKeyPin != nil
                ),
                timeout: nil,
                outputLimitBytes: Self.outputLimitBytes
            )
        } catch ProcessRunError.timedOut {
            throw SecretOperationExecutionError.timedOut
        } catch ProcessRunError.outputLimitExceeded {
            throw SecretOperationExecutionError.outputLimitExceeded
        } catch ProcessRunError.processLaunchFailed,
                ProcessRunError.stdinWriteFailed,
                ProcessRunError.launchFailed {
            throw SecretOperationExecutionError.processFailed
        }

        let (unmarkedResult, completed) = Self.removeCompletionMarker(from: rawResult)
        let sanitized: ProcessResult
        switch outputSanitizer.sanitize(unmarkedResult, secrets: secretBuffers) {
        case .quarantined:
            throw SecretOperationExecutionError.outputQuarantined
        case let .sanitized(result):
            sanitized = result
        }

        guard completed else {
            return Self.wrapperOutput(for: sanitized)
        }

        guard sanitized.exitCode == 0 else {
            return SecretOperationOutput(
                status: "FAILED",
                exitCode: sanitized.exitCode,
                stage: .remoteCommand,
                stderr: Self.boundedText(sanitized.stderr),
                remotePath: plan.remotePath,
                redacted: true
            )
        }

        if let stagingURL, let destinationURL = plan.localURL {
            do {
                try FileManager.default.moveItem(at: stagingURL, to: destinationURL)
            } catch {
                return SecretOperationOutput(
                    status: "FAILED",
                    stage: .remoteCommand,
                    stderr: "本地文件写入失败",
                    remotePath: plan.remotePath,
                    redacted: true
                )
            }
        }

        let listing = plan.operation == .list ? Self.boundedText(sanitized.stdout) : nil
        return SecretOperationOutput(
            status: "COMPLETED",
            stderr: Self.boundedText(sanitized.stderr),
            listingPreview: listing,
            localPath: plan.localURL?.path,
            remotePath: plan.remotePath,
            redacted: true
        )
    }

    public func invalidateSecurityState() async {}

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

    private func prepareLocalFile(for plan: FileTransferPlan) throws {
        guard plan.localURL != nil || plan.operation == .list || plan.operation == .delete else {
            throw FileTransferAdapterError.invalidLocalPath
        }
        guard plan.operation == .list || plan.operation == .delete || plan.localURL != nil else {
            throw FileTransferAdapterError.invalidLocalPath
        }
        try FileTransferAdapterSupport.prepareLocalRoot(localRoot)
        guard let localURL = plan.localURL else { return }
        switch plan.operation {
        case .download:
            try FileTransferAdapterSupport.validateDownloadDestination(localURL)
        case .upload, .overwrite, .write:
            try FileTransferAdapterSupport.validateUploadSource(localURL)
        default:
            break
        }
    }

    private static func batchCommand(
        for plan: FileTransferPlan,
        stagingURL: URL?
    ) throws -> String {
        switch plan.operation {
        case .list:
            return "ls -la \(try sftpQuote(plan.remotePath))\nexit\n"
        case .download:
            guard let stagingURL else { throw SecretOperationExecutionError.invalidParameter }
            return "get \(try sftpQuote(plan.remotePath)) \(try sftpQuote(stagingURL.path))\nexit\n"
        case .upload, .overwrite, .write:
            guard let localURL = plan.localURL else { throw SecretOperationExecutionError.invalidParameter }
            return "put \(try sftpQuote(localURL.path)) \(try sftpQuote(plan.remotePath))\nexit\n"
        case .delete:
            return "rm \(try sftpQuote(plan.remotePath))\nexit\n"
        case .read, .move:
            throw SecretOperationExecutionError.invalidParameter
        }
    }

    static func sftpQuote(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            throw SecretOperationExecutionError.invalidParameter
        }
        var quoted = "\""
        for scalar in value.unicodeScalars {
            if scalar == "\\" || scalar == "\"" {
                quoted.append("\\")
            }
            quoted.append(String(scalar))
        }
        quoted.append("\"")
        return quoted
    }

    static func expectInput(
        host: String,
        port: Int,
        username: String,
        password: String,
        batch: String,
        timeoutSeconds: Int,
        knownHostsPath: String = "/private/tmp/svlt-test-known-hosts",
        strictHostKeyChecking: Bool = false
    ) -> Data {
        let fields = [
            host,
            String(port),
            username,
            password,
            batch,
            String(timeoutSeconds),
            knownHostsPath,
            strictHostKeyChecking ? "1" : "0"
        ]
        return Data(fields.map { hexEncoded(Data($0.utf8)) }.joined(separator: "\n").appending("\n").utf8)
    }

    static func removeCompletionMarker(
        from result: ProcessResult
    ) -> (result: ProcessResult, completed: Bool) {
        let marker = Data("\(completionMarker)\n".utf8)
        guard let range = result.stderr.range(of: marker) else {
            return (result, false)
        }
        var stderr = result.stderr
        stderr.removeSubrange(range)
        guard stderr.range(of: marker) == nil else {
            return (result, false)
        }
        return (
            ProcessResult(exitCode: result.exitCode, stdout: result.stdout, stderr: stderr),
            true
        )
    }

    private static func wrapperOutput(for result: ProcessResult) -> SecretOperationOutput {
        switch result.exitCode {
        case wrapperAuthenticationFailed:
            return SecretOperationOutput(status: "AUTH_FAILED", exitCode: result.exitCode, stage: .authentication, stderr: boundedText(result.stderr), redacted: true)
        case wrapperTimedOut:
            return SecretOperationOutput(status: "TIMED_OUT", exitCode: result.exitCode, stage: .timeout, stderr: boundedText(result.stderr), redacted: true)
        case 255:
            return containsHostKeyFailure(result)
                ? SecretOperationOutput(status: "HOST_KEY_FAILED", exitCode: result.exitCode, stage: .hostKey, stderr: boundedText(result.stderr), redacted: true)
                : SecretOperationOutput(status: "FAILED", exitCode: result.exitCode, stage: .connection, stderr: boundedText(result.stderr), redacted: true)
        case wrapperFrameRead:
            return SecretOperationOutput(status: "WRAPPER_FAILED", exitCode: result.exitCode, stage: .frameRead, redacted: true)
        case wrapperFrameDecode:
            return SecretOperationOutput(status: "WRAPPER_FAILED", exitCode: result.exitCode, stage: .frameDecode, redacted: true)
        case wrapperArgumentValidation:
            return SecretOperationOutput(status: "WRAPPER_FAILED", exitCode: result.exitCode, stage: .argumentValidation, redacted: true)
        default:
            return SecretOperationOutput(status: "WRAPPER_FAILED", exitCode: result.exitCode, stage: .sshWrapper, stderr: boundedText(result.stderr), redacted: true)
        }
    }

    static func expectScript() -> String {
        """
        proc readHexField {} {
            if {[gets stdin encoded] < 0 || $encoded eq ""} { exit \(wrapperFrameRead) }
            if {[regexp {[^0-9A-Fa-f]} $encoded]} { exit \(wrapperFrameDecode) }
            if {([string length $encoded] % 2) != 0} { exit \(wrapperFrameDecode) }
            if {[catch {binary format H* $encoded} value]} { exit \(wrapperFrameDecode) }
            return $value
        }
        set host [readHexField]
        set port [readHexField]
        set username [readHexField]
        set password [readHexField]
        set batch [readHexField]
        set timeoutSeconds [readHexField]
        set knownHostsPath [readHexField]
        set strictHostKeyChecking [readHexField]
        if {$host eq "" || $username eq "" || $password eq "" || $batch eq "" || $knownHostsPath eq ""} { exit \(wrapperArgumentValidation) }
        if {![string is integer -strict $port] || $port < 1 || $port > 65535} { exit \(wrapperArgumentValidation) }
        if {![string is integer -strict $timeoutSeconds] || $timeoutSeconds < 1 || $timeoutSeconds > 60} { exit \(wrapperArgumentValidation) }
        if {$strictHostKeyChecking ne "0" && $strictHostKeyChecking ne "1"} { exit \(wrapperArgumentValidation) }
        # Execution lifetime is controlled only by completion or explicit cancellation.
        set timeout -1
        set passwordSent 0
        set sessionReady 0
        log_user 1
        set hostKeyCheckingMode accept-new
        set hashKnownHostsMode yes
        if {$strictHostKeyChecking eq "1"} {
            set hostKeyCheckingMode yes
            set hashKnownHostsMode no
        }
        set destinationHost $host
        if {[string first ":" $destinationHost] >= 0 && ![string match "[*]" $destinationHost]} {
            set destinationHost "\\[$destinationHost\\]"
        }
        set sftpArguments [list \
            /usr/bin/sftp \
            -q \
            -o BatchMode=no \
            -o StrictHostKeyChecking=$hostKeyCheckingMode \
            -o UserKnownHostsFile=$knownHostsPath \
            -o GlobalKnownHostsFile=/dev/null \
            -o HashKnownHosts=$hashKnownHostsMode \
            -o PubkeyAuthentication=no \
            -o PasswordAuthentication=yes \
            -o KbdInteractiveAuthentication=yes \
            -o NumberOfPasswordPrompts=1 \
            -o PreferredAuthentications=password,keyboard-interactive \
            -P $port \
            "$username@$destinationHost"]
        if {[catch {spawn -noecho {*}$sftpArguments}]} {
            exit \(wrapperFailed)
        }
        expect {
            -re "(?i)permission denied" { exit \(wrapperAuthenticationFailed) }
            -re "(?i)(password|passphrase).*:" {
                send -- "$password\\r"
                set passwordSent 1
                exp_continue
            }
            -re {sftp> ?$} { set sessionReady 1 }
            eof {}
            timeout { exit \(wrapperTimedOut) }
        }
        if {!$sessionReady} {
            if {[catch {wait} waitResult]} { exit \(wrapperFailed) }
            if {[llength $waitResult] < 4} { exit \(wrapperFailed) }
            lassign $waitResult pid spawnId osError childStatus
            if {$childStatus == 255} { exit 255 }
            exit \(wrapperFailed)
        }
        send -- $batch
        expect {
            eof {}
            timeout { exit \(wrapperTimedOut) }
        }
        if {[catch {wait} waitResult]} { exit \(wrapperFailed) }
        if {[llength $waitResult] < 4} { exit \(wrapperFailed) }
        lassign $waitResult pid spawnId osError childStatus
        if {![string is integer -strict $osError] || $osError != 0} { exit \(wrapperFailed) }
        if {![string is integer -strict $childStatus] || $childStatus < 0 || $childStatus > 255} { exit \(wrapperFailed) }
        puts stderr "\(completionMarker)"
        exit $childStatus
        """
    }

    private static func secretString(_ data: Data) throws -> String {
        guard !data.isEmpty,
              let value = String(data: data, encoding: .utf8),
              value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            throw SecretOperationExecutionError.invalidSecretUTF8
        }
        return value
    }

    private static func safeUsername(_ value: String) throws -> String {
        guard !value.isEmpty,
              value.utf8.count <= 256,
              !value.contains(":") && !value.contains("@") && !value.contains("/"),
              value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            throw SecretOperationExecutionError.invalidParameter
        }
        return value
    }

    private static func containsHostKeyFailure(_ result: ProcessResult) -> Bool {
        let text = String(decoding: result.stderr + result.stdout, as: UTF8.self).lowercased()
        return text.contains("remote host identification has changed")
            || text.contains("host key verification failed")
    }

    private func matchingHostKeyPin(
        host: String,
        port: Int,
        protocolType: SecretOperationProtocol,
        metadata: [SecretPolicyMetadata]
    ) throws -> SSHHostKeyPin? {
        let pins = metadata
            .flatMap { $0.destinationBindings }
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
            throw SecretOperationExecutionError.invalidParameter
        }
        return uniquePins.first
    }

    private static func timeoutSeconds(_ duration: Duration) -> Int {
        max(1, Int(duration.timeInterval.rounded(.up)))
    }

    private static func hexEncoded(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    private static func boundedText(_ data: Data, maxBytes: Int = 16_384) -> String? {
        guard !data.isEmpty else { return nil }
        let sanitized = String(decoding: data.prefix(maxBytes), as: UTF8.self)
        return sanitized.isEmpty ? nil : sanitized
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
