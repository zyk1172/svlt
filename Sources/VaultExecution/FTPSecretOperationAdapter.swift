import Foundation
import CoreFoundation
import Network
import VaultCore

/// Purpose-built plaintext FTP adapter. It has no process or shell fallback:
/// the control and passive data connections are owned by this Agent process.
/// Because FTP sends the credential without encryption, only loopback/private
/// destinations are accepted and local policy requests fresh owner approval.
public struct FTPSecretOperationAdapter: SecretOperationAdapter {
    public let kind: SecretAdapterKind = .ftp
    public let capability: SecretOperationCapability = SecretOperationCapability(
        kind: .ftp,
        status: .supported,
        operations: [.ftpTransfer],
        reason: "受控明文 FTP list/download/upload/delete；仅允许回环或私有地址，并要求本机重新认证",
        features: SecretOperationCapabilityFeatures(
            auth: ["password"],
            body: ["list", "download", "upload", "overwrite", "delete"],
            response: ["listing", "localPath", "remotePath", "metadataOnly"],
            transportSessionReuse: false,
            derivedCredentialCapture: false,
            publicNetworkEgress: false
        )
    )

    private let outputSanitizer: OutputSanitizer
    private let localRoot: URL

    public init(
        outputSanitizer: OutputSanitizer = OutputSanitizer(),
        localRoot: URL = FileTransferAdapterSupport.defaultTransferRoot
    ) {
        self.outputSanitizer = outputSanitizer
        self.localRoot = localRoot.standardizedFileURL
    }

    public func preflight(_ descriptor: SecretOperationDescriptor) -> SecretOperationExecutionCapability {
        do {
            let plan = try FileTransferAdapterSupport.makePlan(
                for: descriptor,
                action: .ftpTransfer,
                protocols: [.ftp],
                defaultPort: 21,
                localRoot: localRoot
            )
            guard HTTPTransportSecurityPolicy.isPrivateOrLoopbackHost(plan.host) else {
                return .invalidParameters
            }
            return .supported
        } catch {
            return .invalidParameters
        }
    }

    public func execute(
        _ descriptor: SecretOperationDescriptor,
        metadata _: [SecretPolicyMetadata],
        context _: SecretOperationExecutionContext,
        resolve: @escaping @Sendable (SecretReference) async throws -> Data
    ) async throws -> SecretOperationOutput {
        let plan: FileTransferPlan
        do {
            plan = try FileTransferAdapterSupport.makePlan(
                for: descriptor,
                action: .ftpTransfer,
                protocols: [.ftp],
                defaultPort: 21,
                localRoot: localRoot
            )
        } catch FileTransferAdapterError.unsupportedOperation {
            throw SecretOperationExecutionError.invalidParameter
        } catch {
            throw SecretOperationExecutionError.invalidParameter
        }

        guard HTTPTransportSecurityPolicy.isPrivateOrLoopbackHost(plan.host) else {
            throw SecretOperationExecutionError.insecureTransportDenied
        }

        do {
            try prepareLocalFile(for: plan)
        } catch {
            throw SecretOperationExecutionError.invalidParameter
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

        do {
            let result = try await FTPClient(
                host: plan.host,
                port: plan.port,
                timeout: plan.timeout
            ).execute(plan: plan, username: username, password: password)

            var listingPreview: String?
            if let listing = result.listing {
                let sanitized: ProcessResult
                switch outputSanitizer.sanitize(
                    ProcessResult(exitCode: 0, stdout: listing, stderr: Data()),
                    secrets: secretBuffers
                ) {
                case .quarantined:
                    throw SecretOperationExecutionError.outputQuarantined
                case let .sanitized(value):
                    sanitized = value
                }
                listingPreview = Self.boundedText(sanitized.stdout)
            }

            return SecretOperationOutput(
                status: "COMPLETED",
                listingPreview: listingPreview,
                localPath: result.localURL?.path,
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch let error as SecretOperationExecutionError {
            throw error
        } catch FTPClientError.timedOut {
            return SecretOperationOutput(status: "TIMED_OUT", stage: .timeout, redacted: true)
        } catch FTPClientError.authenticationFailed {
            return SecretOperationOutput(status: "AUTH_FAILED", stage: .authentication, redacted: true)
        } catch let FTPClientError.server(code) {
            let status = code == 530 || code == 532 || code == 534 ? "AUTH_FAILED" : "FAILED"
            let stage: SecretOperationStage = status == "AUTH_FAILED" ? .authentication : .remoteCommand
            return SecretOperationOutput(
                status: status,
                stage: stage,
                stderr: "FTP 服务器响应码 (code)",
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch FTPClientError.localIO {
            return SecretOperationOutput(
                status: "FAILED",
                stage: .remoteCommand,
                stderr: "本地文件写入失败",
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch FTPClientError.connection {
            return SecretOperationOutput(
                status: "FAILED",
                stage: .connection,
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            return SecretOperationOutput(
                status: "FAILED",
                stage: .connection,
                remotePath: plan.remotePath,
                redacted: true
            )
        }
    }

    public func invalidateSecurityState() async {}

    private func prepareLocalFile(for plan: FileTransferPlan) throws {
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

    private static func boundedText(_ data: Data, maxBytes: Int = 16_384) -> String? {
        guard !data.isEmpty else { return nil }
        let value = String(decoding: data.prefix(maxBytes), as: UTF8.self)
        return value.isEmpty ? nil : value
    }
}

private enum FTPClientError: Error {
    case timedOut
    case connection
    case authenticationFailed
    case server(Int)
    case localIO
}

private struct FTPTransferResult: Sendable {
    let listing: Data?
    let localURL: URL?
}

private struct FTPReply: Sendable {
    let code: Int
    let lines: [String]
}

private struct FTPReceiveResult: Sendable {
    let data: Data
    let isComplete: Bool
}

private final class FTPContinuationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var didComplete = false

    func claim() -> Bool {
        lock.withLock {
            guard !didComplete else { return false }
            didComplete = true
            return true
        }
    }
}

private final class FTPWire: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.agent-secret-vault.ftp-wire")

    init(host: String, port: Int) {
        connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: UInt16(port))!,
            using: .tcp
        )
    }

    func start() async throws {
        let gate = FTPContinuationGate()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    guard gate.claim() else { return }
                    continuation.resume()
                case .failed, .cancelled:
                    guard gate.claim() else { return }
                    continuation.resume(throwing: FTPClientError.connection)
                default:
                    break
                }
            }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func send(_ data: Data) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.send(content: data, completion: .contentProcessed { error in
                    if error == nil {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: FTPClientError.connection)
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func finishSending() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.send(
                    content: nil,
                    contentContext: .finalMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if error == nil {
                            continuation.resume()
                        } else {
                            continuation.resume(throwing: FTPClientError.connection)
                        }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func receive(maxLength: Int) async throws -> FTPReceiveResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                connection.receive(
                    minimumIncompleteLength: 1,
                    maximumLength: maxLength
                ) { content, _, isComplete, error in
                    if error != nil {
                        continuation.resume(throwing: FTPClientError.connection)
                    } else {
                        continuation.resume(returning: FTPReceiveResult(
                            data: content ?? Data(),
                            isComplete: isComplete
                        ))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func cancel() {
        connection.cancel()
    }
}

enum FTPPathEncoding: Sendable, Equatable {
    case utf8
    case gb18030

    var stringEncoding: String.Encoding {
        switch self {
        case .utf8:
            return .utf8
        case .gb18030:
            // CFString encoding 0x0632 is GB 18030-2000 on Apple platforms.
            return String.Encoding(
                rawValue: CFStringConvertEncodingToNSStringEncoding(
                    CFStringEncoding(0x0632)
                )
            )
        }
    }

    func data(for value: String) -> Data? {
        value.data(using: stringEncoding)
    }

    static func candidates(
        for remotePath: String,
        operation: SecretFileOperation
    ) -> [FTPPathEncoding] {
        guard remotePath.unicodeScalars.contains(where: { $0.value > 0x7F }) else {
            return [.utf8]
        }
        switch operation {
        case .list, .download:
            return [.utf8, .gb18030]
        default:
            // Do not silently repeat a remote write or delete with another encoding.
            return [.utf8]
        }
    }
}

private struct FTPClient: Sendable {
    let host: String
    let port: Int
    let timeout: Duration

    func execute(
        plan: FileTransferPlan,
        username: String,
        password: String
    ) async throws -> FTPTransferResult {
        let encodings = FTPPathEncoding.candidates(
            for: plan.remotePath,
            operation: plan.operation
        )
        var lastRetryableError: FTPClientError?
        for (index, encoding) in encodings.enumerated() {
            do {
                return try await executeOnce(
                    plan: plan,
                    username: username,
                    password: password,
                    pathEncoding: encoding
                )
            } catch let error as FTPClientError {
                if index + 1 < encodings.count,
                   Self.shouldRetry(error: error, plan: plan, encoding: encoding) {
                    lastRetryableError = error
                    continue
                }
                throw error
            }
        }
        throw lastRetryableError ?? FTPClientError.connection
    }

    private func executeOnce(
        plan: FileTransferPlan,
        username: String,
        password: String,
        pathEncoding: FTPPathEncoding
    ) async throws -> FTPTransferResult {
        let control = FTPWire(host: host, port: port)
        var reader = FTPReplyReader()
        defer { control.cancel() }

        do {
            try await runFTPStage { try await control.start() }
            let greeting = try await readReply(on: control, reader: &reader)
            guard (200...399).contains(greeting.code) else {
                throw FTPClientError.server(greeting.code)
            }

            let userReply = try await command("USER \(username)", on: control, reader: &reader)
            if userReply.code != 230 {
                guard userReply.code == 331 else {
                    throw userReply.code == 530
                        ? FTPClientError.authenticationFailed
                        : FTPClientError.server(userReply.code)
                }
                let passReply = try await command("PASS \(password)", on: control, reader: &reader)
                guard passReply.code == 230 else {
                    throw passReply.code == 530
                        ? FTPClientError.authenticationFailed
                        : FTPClientError.server(passReply.code)
                }
            }

            let typeReply = try await command("TYPE I", on: control, reader: &reader)
            guard (200...299).contains(typeReply.code) else {
                throw FTPClientError.server(typeReply.code)
            }

            switch plan.operation {
            case .list:
                let dataConnection = try await openPassiveConnection(
                    control: control,
                    reader: &reader
                )
                defer { dataConnection.cancel() }
                let preliminary = try await command(
                    "LIST \(plan.remotePath)",
                    encoding: pathEncoding,
                    on: control,
                    reader: &reader
                )
                guard (125...199).contains(preliminary.code) else {
                    throw FTPClientError.server(preliminary.code)
                }
                let listing = try await readData(
                    from: dataConnection,
                    maxBytes: 1_048_576
                )
                dataConnection.cancel()
                let finalReply = try await readReply(on: control, reader: &reader)
                guard (200...299).contains(finalReply.code) else {
                    throw FTPClientError.server(finalReply.code)
                }
                return FTPTransferResult(
                    listing: Self.normalizedListingData(listing, using: pathEncoding),
                    localURL: nil
                )
            case .download:
                guard let destination = plan.localURL else { throw FTPClientError.localIO }
                let staging = FileTransferAdapterSupport.makeStagingURL(for: destination)
                defer { try? FileManager.default.removeItem(at: staging) }
                guard FileManager.default.createFile(
                    atPath: staging.path,
                    contents: nil,
                    attributes: [.posixPermissions: 0o600]
                ) else {
                    throw FTPClientError.localIO
                }
                let handle: FileHandle
                do {
                    handle = try FileHandle(forWritingTo: staging)
                } catch {
                    throw FTPClientError.localIO
                }
                defer { try? handle.close() }
                let dataConnection = try await openPassiveConnection(control: control, reader: &reader)
                defer { dataConnection.cancel() }
                let preliminary = try await command(
                    "RETR \(plan.remotePath)",
                    encoding: pathEncoding,
                    on: control,
                    reader: &reader
                )
                guard (125...199).contains(preliminary.code) else {
                    throw FTPClientError.server(preliminary.code)
                }
                try await writeData(from: dataConnection, to: handle)
                dataConnection.cancel()
                let finalReply = try await readReply(on: control, reader: &reader)
                guard (200...299).contains(finalReply.code) else {
                    throw FTPClientError.server(finalReply.code)
                }
                do {
                    try handle.close()
                    try FileManager.default.moveItem(at: staging, to: destination)
                } catch {
                    throw FTPClientError.localIO
                }
                return FTPTransferResult(listing: nil, localURL: destination)
            case .upload, .overwrite, .write:
                guard let source = plan.localURL else { throw FTPClientError.localIO }
                let handle: FileHandle
                do {
                    handle = try FileHandle(forReadingFrom: source)
                } catch {
                    throw FTPClientError.localIO
                }
                defer { try? handle.close() }
                let dataConnection = try await openPassiveConnection(control: control, reader: &reader)
                defer { dataConnection.cancel() }
                let preliminary = try await command(
                    "STOR \(plan.remotePath)",
                    encoding: pathEncoding,
                    on: control,
                    reader: &reader
                )
                guard (125...199).contains(preliminary.code) else {
                    throw FTPClientError.server(preliminary.code)
                }
                try await sendData(from: handle, to: dataConnection)
                dataConnection.cancel()
                let finalReply = try await readReply(on: control, reader: &reader)
                guard (200...299).contains(finalReply.code) else {
                    throw FTPClientError.server(finalReply.code)
                }
                return FTPTransferResult(listing: nil, localURL: source)
            case .delete:
                let reply = try await command(
                    "DELE \(plan.remotePath)",
                    encoding: pathEncoding,
                    on: control,
                    reader: &reader
                )
                guard (200...299).contains(reply.code) else {
                    throw FTPClientError.server(reply.code)
                }
                return FTPTransferResult(listing: nil, localURL: nil)
            case .read, .move:
                throw FTPClientError.server(501)
            }
        } catch let error as FTPClientError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw FTPClientError.connection
        }
    }

    private static func shouldRetry(
        error: FTPClientError,
        plan: FileTransferPlan,
        encoding: FTPPathEncoding
    ) -> Bool {
        guard encoding == .utf8,
              plan.operation == .list || plan.operation == .download,
              plan.remotePath.unicodeScalars.contains(where: { $0.value > 0x7F }),
              case let .server(code) = error else {
            return false
        }
        return [450, 451, 500, 501, 550, 553].contains(code)
    }

    private static func normalizedListingData(
        _ data: Data,
        using encoding: FTPPathEncoding
    ) -> Data {
        if let listing = String(data: data, encoding: encoding.stringEncoding) {
            return Data(listing.utf8)
        }
        if encoding == .utf8,
           let listing = String(data: data, encoding: FTPPathEncoding.gb18030.stringEncoding) {
            return Data(listing.utf8)
        }
        return data
    }

    private func command(
        _ value: String,
        on wire: FTPWire,
        reader: inout FTPReplyReader
    ) async throws -> FTPReply {
        try await command(
            value,
            encoding: .utf8,
            on: wire,
            reader: &reader
        )
    }

    private func command(
        _ value: String,
        encoding: FTPPathEncoding,
        on wire: FTPWire,
        reader: inout FTPReplyReader
    ) async throws -> FTPReply {
        guard let commandData = encoding.data(for: value + "\r\n") else {
            throw FTPClientError.connection
        }
        try await runFTPStage {
            try await wire.send(commandData)
        }
        return try await readReply(on: wire, reader: &reader)
    }

    private func readReply(
        on wire: FTPWire,
        reader: inout FTPReplyReader
    ) async throws -> FTPReply {
        try await reader.readReply(from: wire, timeout: timeout)
    }

    private func openPassiveConnection(
        control: FTPWire,
        reader: inout FTPReplyReader
    ) async throws -> FTPWire {
        let extended = try await command("EPSV", on: control, reader: &reader)
        let dataPort: Int
        if extended.code == 229 {
            guard let parsed = Self.parseEPSVPort(extended) else {
                throw FTPClientError.connection
            }
            dataPort = parsed
        } else {
            let passive = try await command("PASV", on: control, reader: &reader)
            guard passive.code == 227,
                  let parsed = Self.parsePASVPort(passive) else {
                throw FTPClientError.server(passive.code)
            }
            dataPort = parsed
        }
        guard (1...65_535).contains(dataPort) else {
            throw FTPClientError.connection
        }
        let data = FTPWire(host: host, port: dataPort)
        do {
            try await runFTPStage { try await data.start() }
        } catch is CancellationError {
            data.cancel()
            throw CancellationError()
        } catch {
            data.cancel()
            throw FTPClientError.connection
        }
        return data
    }

    private func readData(from wire: FTPWire, maxBytes: Int) async throws -> Data {
        var data = Data()
        while true {
            let received: FTPReceiveResult
            do {
                received = try await runFTPStage {
                    try await wire.receive(maxLength: 64 * 1024)
                }
            } catch FTPClientError.connection {
                // Some NAS FTP daemons reset the passive data socket after the
                // final payload while still sending a successful control reply.
                // Let the 2xx completion reply below decide whether the transfer
                // really succeeded.
                return data
            }
            guard data.count + received.data.count <= maxBytes else {
                throw FTPClientError.localIO
            }
            data.append(received.data)
            if received.isComplete { return data }
        }
    }

    private func writeData(from wire: FTPWire, to handle: FileHandle) async throws {
        while true {
            let received: FTPReceiveResult
            do {
                received = try await runFTPStage {
                    try await wire.receive(maxLength: 64 * 1024)
                }
            } catch FTPClientError.connection {
                // See readData: validate the transfer using the final control
                // reply instead of treating a post-payload data reset as failure.
                return
            }
            do {
                try handle.write(contentsOf: received.data)
            } catch {
                throw FTPClientError.localIO
            }
            if received.isComplete { return }
        }
    }

    private func sendData(from handle: FileHandle, to wire: FTPWire) async throws {
        do {
            while let data = try handle.read(upToCount: 64 * 1024), !data.isEmpty {
                try await runFTPStage { try await wire.send(data) }
            }
            try await runFTPStage { try await wire.finishSending() }
        } catch let error as FTPClientError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw FTPClientError.localIO
        }
    }

    private static func parseEPSVPort(_ reply: FTPReply) -> Int? {
        guard let line = reply.lines.last,
              let open = line.firstIndex(of: "("),
              let close = line[open...].firstIndex(of: ")") else {
            return nil
        }
        let body = line[line.index(after: open)..<close]
        return body.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }.last
    }

    private static func parsePASVPort(_ reply: FTPReply) -> Int? {
        guard let line = reply.lines.last,
              let open = line.firstIndex(of: "("),
              let close = line[open...].firstIndex(of: ")") else {
            return nil
        }
        let body = line[line.index(after: open)..<close]
        let values = body.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
        guard values.count >= 6,
              values[4] <= 255,
              values[5] <= 255 else {
            return nil
        }
        return values[4] * 256 + values[5]
    }
}

private struct FTPReplyReader: Sendable {
    private var buffer = Data()

    mutating func readReply(from wire: FTPWire, timeout: Duration) async throws -> FTPReply {
        let firstLine = try await readLine(from: wire, timeout: timeout)
        guard firstLine.utf8.count >= 3,
              let code = Int(firstLine.prefix(3)) else {
            throw FTPClientError.connection
        }
        var lines = [firstLine]
        guard firstLine.count > 3, firstLine[firstLine.index(firstLine.startIndex, offsetBy: 3)] == "-" else {
            return FTPReply(code: code, lines: lines)
        }
        let terminator = "\(code) "
        while true {
            let line = try await readLine(from: wire, timeout: timeout)
            lines.append(line)
            if line.hasPrefix(terminator) { return FTPReply(code: code, lines: lines) }
        }
    }

    private mutating func readLine(from wire: FTPWire, timeout: Duration) async throws -> String {
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer[..<newline]
                buffer.removeSubrange(...newline)
                guard let line = String(data: lineData, encoding: .utf8)
                    ?? String(
                        data: lineData,
                        encoding: FTPPathEncoding.gb18030.stringEncoding
                    ) else {
                    throw FTPClientError.connection
                }
                return line.hasSuffix("\r") ? String(line.dropLast()) : line
            }
            guard buffer.count <= 64 * 1024 else {
                throw FTPClientError.connection
            }
            let received = try await runFTPStage {
                try await wire.receive(maxLength: 8 * 1024)
            }
            buffer.append(received.data)
            if received.isComplete && !buffer.contains(0x0A) {
                throw FTPClientError.connection
            }
        }
    }
}

func runFTPStage<T: Sendable>(
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try Task.checkCancellation()
    do {
        let result = try await operation()
        try Task.checkCancellation()
        return result
    } catch {
        try Task.checkCancellation()
        throw error
    }
}
