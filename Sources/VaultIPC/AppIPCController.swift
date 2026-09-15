import Darwin
import Dispatch
import CryptoKit
import Foundation
import os
import VaultCore

public enum AppIPCControllerError: Error, Equatable, Sendable {
    case notStarted
    case invalidMaxActiveClients
}

public final class AppIPCController: @unchecked Sendable {
    private static let logger = Logger(subsystem: "AgentSecretVault", category: "IPC")

    public struct EndpointMetadata: Codable, Equatable, Sendable {
        public let socketPath: String

        public init(socketPath: String) {
            self.socketPath = socketPath
        }
    }

    private let server: UnixSocketServer
    private let handler: IPCRequestHandler
    private let maxActiveClients: Int
    private let stateLock = NSLock()
    private let clientGroup = DispatchGroup()
    private var boundSocket: BoundUnixSocket?
    private var acceptTask: Task<Void, Never>?
    private var isStopping = false
    private var authenticator: IPCAuthenticator?
    private var activeClientFDs: Set<Int32> = []

    public init(
        server: UnixSocketServer,
        handler: IPCRequestHandler,
        maxActiveClients: Int = 32
    ) {
        self.server = server
        self.handler = handler
        self.maxActiveClients = maxActiveClients
    }

    deinit {
        stop()
    }

    public var endpointMetadata: EndpointMetadata {
        EndpointMetadata(socketPath: server.configuration.socketURL.path)
    }

    public func start() throws {
        guard maxActiveClients > 0 else {
            throw AppIPCControllerError.invalidMaxActiveClients
        }

        stateLock.lock()
        if boundSocket != nil || isStopping {
            stateLock.unlock()
            return
        }

        let token = CapabilityToken.random()
        do {
            try server.writeCapabilityToken(token)
            let socket = try server.bindListeningSocket()
            let authenticator = IPCAuthenticator(expectedToken: token)
            let task = Task.detached(priority: .userInitiated) { [weak self, socket, authenticator] in
                guard let self else {
                    return
                }
                await self.acceptLoop(socket: socket, authenticator: authenticator)
            }
            boundSocket = socket
            self.authenticator = authenticator
            acceptTask = task
            stateLock.unlock()
        } catch {
            stateLock.unlock()
            throw error
        }
    }

    public func stop() {
        stateLock.lock()
        guard !isStopping else {
            stateLock.unlock()
            return
        }
        guard boundSocket != nil || acceptTask != nil else {
            stateLock.unlock()
            return
        }
        let task = acceptTask
        let socket = boundSocket
        let activeClients = Array(activeClientFDs)
        isStopping = true
        acceptTask = nil
        boundSocket = nil
        authenticator = nil
        stateLock.unlock()

        task?.cancel()
        socket?.close()
        for fileDescriptor in activeClients {
            _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
        }
        // Detached handlers own their file descriptors. Do not permit a
        // restart to reuse descriptor numbers until every old handler has
        // closed its descriptor and left the group.
        clientGroup.wait()
        stateLock.lock()
        isStopping = false
        stateLock.unlock()
    }

    public func handleAuthenticatedFrame(_ frame: Data) async throws -> Data {
        guard let authenticator = currentAuthenticator() else {
            throw AppIPCControllerError.notStarted
        }
        return try await handleAuthenticatedFrame(frame, authenticator: authenticator)
    }

    private func currentAuthenticator() -> IPCAuthenticator? {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }
        return authenticator
    }

    private func acceptLoop(socket: BoundUnixSocket, authenticator: IPCAuthenticator) async {
        while !Task.isCancelled {
            let clientFD = Darwin.accept(socket.fileDescriptor, nil, nil)
            if clientFD < 0 {
                let errorNumber = errno
                if errorNumber == EINTR {
                    continue
                }
                if Task.isCancelled || socket.fileDescriptor < 0 {
                    return
                }
                if errorNumber == EAGAIN || errorNumber == EWOULDBLOCK || errorNumber == ECONNABORTED {
                    continue
                }
                Self.log(code: "IPC_ACCEPT_FAILED")
                return
            }

            guard Self.configureAcceptedSocket(clientFD), Self.isOwner(clientFD) else {
                _ = Darwin.shutdown(clientFD, SHUT_RDWR)
                Darwin.close(clientFD)
                continue
            }

            guard registerClientIfAvailable(fileDescriptor: clientFD) else {
                _ = Darwin.shutdown(clientFD, SHUT_RDWR)
                Darwin.close(clientFD)
                continue
            }

            Task.detached(priority: .userInitiated) { [weak self, authenticator] in
                await self?.handleClient(fileDescriptor: clientFD, authenticator: authenticator)
            }
        }
    }

    private func handleClient(fileDescriptor: Int32, authenticator: IPCAuthenticator) async {
        defer {
            unregisterClient(fileDescriptor: fileDescriptor)
            Darwin.close(fileDescriptor)
            clientGroup.leave()
        }

        do {
            try setIOTimeouts(on: fileDescriptor)
            let frame = try readFrame(from: fileDescriptor)
            let responseFrame = try await handleAuthenticatedFrame(
                frame,
                authenticator: authenticator,
                principal: Self.peerPrincipal(fileDescriptor)
            )
            try writeAll(responseFrame, to: fileDescriptor)
        } catch let error as IPCFrameError {
            Self.log(code: error.diagnosticCode)
            let failureFrame = try? IPCFrameCodec.encode(IPCResponse.failure(code: error.responseCode))
            if let failureFrame {
                try? writeAll(failureFrame, to: fileDescriptor)
            }
        } catch let error as IPCSocketError {
            Self.log(code: error.diagnosticCode)
        } catch {
            Self.log(code: "IPC_REQUEST_FAILED")
            let failureFrame = try? IPCFrameCodec.encode(IPCResponse.failure(code: "IPC_REQUEST_FAILED"))
            if let failureFrame {
                try? writeAll(failureFrame, to: fileDescriptor)
            }
        }
    }

    private func handleAuthenticatedFrame(
        _ frame: Data,
        authenticator: IPCAuthenticator,
        principal: String = AuditSource.agent.rawValue
    ) async throws -> Data {
        do {
            let authenticated = try IPCFrameCodec.decode(AuthenticatedIPCRequest.self, from: frame)
            let request = try authenticator.authenticate(authenticated)
            let response = try await handler.handle(
                request,
                principal: principal,
                caller: authenticated.caller
            )
            return try IPCFrameCodec.encode(response)
        } catch IPCAuthenticationError.invalidCapabilityToken {
            Self.log(code: "IPC_AUTH_FAILED")
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "INVALID_CAPABILITY_TOKEN"))
        } catch IPCRequestHandlerError.unsupportedRequest {
            Self.log(code: "IPC_UNSUPPORTED_REQUEST")
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "UNSUPPORTED_REQUEST"))
        } catch let error as SecretCatalogAgentError {
            let code: String
            switch error {
            case .unavailable:
                code = "CATALOG_UNAVAILABLE"
            case .legacyCatalogUnsupported:
                code = "LEGACY_CATALOG_UNSUPPORTED"
            case .integrityMissing:
                code = "INTEGRITY_MISSING"
            case .externalModification:
                code = "EXTERNAL_CATALOG_MODIFICATION"
            case .pendingExternalChange:
                code = "PENDING_EXTERNAL_CHANGE"
            case .invalidCatalog:
                code = "CATALOG_INVALID"
            case .agentWriteNotAllowed:
                code = "CATALOG_AGENT_WRITE_NOT_ALLOWED"
            case .revisionConflict:
                code = "CATALOG_REVISION_CONFLICT"
            case .formatRepairConflict:
                code = "FORMAT_REPAIR_CONFLICT"
            case .invalidOperation:
                code = "CATALOG_INVALID_OPERATION"
            case .approvalRequired:
                code = "CATALOG_APPROVAL_REQUIRED"
            case .writeFailed:
                code = "CATALOG_WRITE_FAILED"
            case .cleanupRequired:
                code = "CATALOG_CLEANUP_REQUIRED"
            case .agentWriteApprovalUnavailable:
                code = "CATALOG_AGENT_WRITE_APPROVAL_UNAVAILABLE"
            }
            Self.log(code: code)
            return try IPCFrameCodec.encode(IPCResponse.failure(code: code))
        } catch let error as SecretOperationError {
            Self.log(code: error.responseCode)
            return try IPCFrameCodec.encode(IPCResponse.failure(code: error.responseCode))
        } catch {
            Self.log(code: "IPC_REQUEST_FAILED")
            return try IPCFrameCodec.encode(IPCResponse.failure(code: "REQUEST_FAILED"))
        }
    }

    private func registerClientIfAvailable(fileDescriptor: Int32) -> Bool {
        stateLock.lock()
        defer {
            stateLock.unlock()
        }
        guard boundSocket != nil else {
            return false
        }
        guard activeClientFDs.count < maxActiveClients else {
            Self.log(code: "IPC_CLIENT_LIMIT_REACHED")
            return false
        }
        activeClientFDs.insert(fileDescriptor)
        clientGroup.enter()
        return true
    }

    private func unregisterClient(fileDescriptor: Int32) {
        stateLock.lock()
        activeClientFDs.remove(fileDescriptor)
        stateLock.unlock()
    }

    private func setIOTimeouts(on fileDescriptor: Int32) throws {
        var timeout = timeval(tv_sec: 30, tv_usec: 0)
        let receiveResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_RCVTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
        let sendResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_SNDTIMEO,
                pointer,
                socklen_t(MemoryLayout<timeval>.size)
            )
        }
        guard receiveResult == 0, sendResult == 0 else {
            throw IPCSocketError.operationFailed("setsockopt", errno: errno)
        }
    }

    private static func configureAcceptedSocket(_ fileDescriptor: Int32) -> Bool {
        var enabled: Int32 = 1
        return withUnsafePointer(to: &enabled) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                pointer,
                socklen_t(MemoryLayout<Int32>.size)
            ) == 0
        }
    }

    private static func isOwner(_ fileDescriptor: Int32) -> Bool {
        var uid = uid_t()
        var gid = gid_t()
        guard getpeereid(fileDescriptor, &uid, &gid) == 0 else {
            return false
        }
        return uid == geteuid()
    }

    /// Returns a process-bound, non-secret principal for execution identity.
    /// The kernel audit token prevents two processes that only happen to reuse
    /// a PID from inheriting one another's compatibility scope state.
    /// If the platform cannot provide the token, use a connection-unique
    /// principal instead of falling back to a global value or a reusable PID;
    /// that fails closed for scope reuse while the request remains
    /// owner-checked.
    private static func peerPrincipal(_ fileDescriptor: Int32) -> String {
        var pid = pid_t()
        var pidLength = socklen_t(MemoryLayout<pid_t>.size)
        guard getsockopt(
            fileDescriptor,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &pid,
            &pidLength
        ) == 0, pid > 0 else {
            return "agent-connection-\(UUID().uuidString)"
        }

        var auditToken = audit_token_t()
        var auditTokenLength = socklen_t(MemoryLayout<audit_token_t>.size)
        if getsockopt(
            fileDescriptor,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            &auditToken,
            &auditTokenLength
        ) == 0 {
            let tokenData = withUnsafeBytes(of: &auditToken) { Data($0) }
            let fingerprint = SHA256.hash(data: tokenData)
                .prefix(16)
                .map { String(format: "%02x", $0) }
                .joined()
            return "agent-peer-\(pid)-\(fingerprint)"
        }
        return "agent-connection-\(UUID().uuidString)"
    }

    private static func log(code: String) {
        logger.error("\(code, privacy: .public)")
        writeDiagnosticError(code: code)
    }

    private static func writeDiagnosticError(code: String) {
        do {
            let appSupport = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
            let directory = appSupport
                .appendingPathComponent("AgentSecretVault", isDirectory: true)
                .appendingPathComponent("IPC", isDirectory: true)
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            let fileURL = directory.appendingPathComponent("last-error.log")
            let line = "\(ISO8601DateFormatter().string(from: Date())) \(code)\n"
            try line.write(to: fileURL, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            // Diagnostics are best effort and intentionally contain no Error
            // description, request, argument, or secret value.
        }
    }

    private func readFrame(from fileDescriptor: Int32) throws -> Data {
        let header = try readExactly(byteCount: 4, from: fileDescriptor)
        let payloadLength = header.reduce(UInt32(0)) { partial, byte in
            (partial << 8) | UInt32(byte)
        }
        guard payloadLength <= IPCFrameCodec.maxFrameBytes else {
            throw IPCFrameError.frameTooLarge
        }
        let payload = try readExactly(byteCount: Int(payloadLength), from: fileDescriptor)
        return header + payload
    }

    private func readExactly(byteCount: Int, from fileDescriptor: Int32) throws -> Data {
        var data = Data(count: byteCount)
        var offset = 0

        while offset < byteCount {
            let readCount = data.withUnsafeMutableBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else {
                    return -1
                }
                return Darwin.read(
                    fileDescriptor,
                    baseAddress.advanced(by: offset),
                    byteCount - offset
                )
            }
            if readCount > 0 {
                offset += readCount
                continue
            }
            if readCount < 0, errno == EINTR {
                continue
            }
            if readCount < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                throw IPCFrameError.incompleteFrame
            }
            throw IPCFrameError.incompleteFrame
        }

        return data
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else {
                    return -1
                }
                return Darwin.write(
                    fileDescriptor,
                    baseAddress.advanced(by: offset),
                    data.count - offset
                )
            }
            if written > 0 {
                offset += written
                continue
            }
            if written < 0, errno == EINTR {
                continue
            }
            throw IPCSocketError.operationFailed("write", errno: errno)
        }
    }
}

private extension IPCFrameError {
    var diagnosticCode: String {
        switch self {
        case .incompleteFrame:
            return "IPC_INCOMPLETE_FRAME"
        case .frameTooLarge:
            return "IPC_FRAME_TOO_LARGE"
        case .lengthMismatch:
            return "IPC_FRAME_LENGTH_MISMATCH"
        }
    }

    var responseCode: String {
        switch self {
        case .frameTooLarge:
            return "FRAME_TOO_LARGE"
        case .incompleteFrame, .lengthMismatch:
            return "INVALID_FRAME"
        }
    }
}

private extension IPCSocketError {
    var diagnosticCode: String {
        switch self {
        case .socketPathTooLong:
            return "IPC_SOCKET_PATH_TOO_LONG"
        case .operationFailed(let operation, _):
            switch operation {
            case "write":
                return "IPC_WRITE_FAILED"
            case "setsockopt":
                return "IPC_SOCKET_OPTION_FAILED"
            default:
                return "IPC_SOCKET_OPERATION_FAILED"
            }
        }
    }
}
