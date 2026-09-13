import Darwin
import Foundation
import VaultCore

/// Client for the dedicated App-control channel.  It intentionally reads a
/// different token and has no API for MCP clients to call through.
public actor AppControlIPCClient {
    private static let connectTimeoutMilliseconds: Int32 = 2_000
    // App-control approvals wait for device-owner authentication. Keep this
    // above the Agent's 30-second authorization window; the ordinary MCP IPC
    // client intentionally keeps its shorter timeout.
    private static let ioTimeoutSeconds: Int32 = 40

    private let configuration: UnixSocketServerConfiguration

    public init(configuration: UnixSocketServerConfiguration) {
        self.configuration = configuration
    }

    public static func defaultClient() throws -> AppControlIPCClient {
        AppControlIPCClient(configuration: try .appControlConfiguration())
    }

    public func catalogStatus() async throws -> CatalogValidationResult {
        let response = try await send(.catalogStatus)
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func catalogPresentationState() async throws -> CatalogPresentationState {
        let response = try await send(.catalogPresentationState)
        guard case let .catalogPresentationState(state) = response else { throw unexpected(response) }
        return state
    }

    public func selectCatalogDocument(path: String) async throws -> CatalogPresentationState {
        let response = try await send(.catalogSelectDocument(path: path))
        guard case let .catalogPresentationState(state) = response else { throw unexpected(response) }
        return state
    }

    public func catalogFormatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        let response = try await send(.catalogFormatRepairPlan)
        guard case let .catalogFormatRepairPlan(plan) = response else { throw unexpected(response) }
        return plan
    }

    public func repairCatalogFormat(expectedRawSHA256: String) async throws -> CatalogValidationResult {
        let response = try await send(.catalogRepairFormat(expectedRawSHA256: expectedRawSHA256))
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func catalogRecentAuditEntries(limit: Int = 100) async throws -> CatalogRecentAuditResult {
        let response = try await send(.catalogRecentAuditEntries(limit: limit))
        guard case let .catalogRecentAuditEntries(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogAuditHealth() async throws -> String? {
        let response = try await send(.catalogAuditHealth)
        guard case let .catalogAuditHealth(health) = response else { throw unexpected(response) }
        return health
    }

    public func catalogSecureInputRequest(id: UUID) async throws -> CatalogAgentSecureInputRequest {
        let response = try await send(.catalogSecureInputRequest(id: id))
        guard case let .catalogSecureInputRequest(request) = response else { throw unexpected(response) }
        return request
    }

    public func submitCatalogSecureInput(
        id: UUID,
        submission: CatalogSecureInputSubmission
    ) async throws -> CatalogSecureInputStatus {
        let response = try await send(.catalogSubmitSecureInput(id: id, submission: submission))
        guard case let .catalogSecureInputStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func cancelCatalogSecureInput(id: UUID) async throws {
        let response = try await send(.catalogCancelSecureInput(id: id))
        guard case .operationCompleted = response else { throw unexpected(response) }
    }

    public func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        let response = try await send(.catalogAdoptExternalV2)
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func adoptCatalogExternalV3() async throws -> CatalogValidationResult {
        let response = try await send(.catalogAdoptExternalV3)
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func approveCatalogExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> CatalogValidationResult {
        let response = try await send(.catalogApproveExternalChange(
            expectedRevision: expectedRevision,
            expectedRawSHA256: expectedRawSHA256,
            expectedSemanticSHA256: expectedSemanticSHA256
        ))
        guard case let .catalogStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval? = 600
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        let response = try await send(.setCatalogAgentWriteMode(mode: mode, duration: duration))
        guard case let .catalogAgentWriteStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func revokeCatalogAgentWrite() async throws {
        let response = try await send(.revokeCatalogAgentWrite)
        guard case .operationCompleted = response else { throw unexpected(response) }
    }

    public func catalogAgentWriteStatus() async throws -> CatalogAgentWriteAuthorizationStatus {
        let response = try await send(.catalogAgentWriteStatus)
        guard case let .catalogAgentWriteStatus(status) = response else { throw unexpected(response) }
        return status
    }

    public func pendingCatalogWriteAccessRequest(id: UUID) async throws -> CatalogAgentWriteAccessRequest {
        let response = try await send(.catalogWriteAccessRequest(id: id))
        guard case let .catalogWriteAccessRequest(request) = response else { throw unexpected(response) }
        return request
    }

    public func respondToCatalogWriteAccessRequest(id: UUID, approved: Bool) async throws {
        let response = try await send(.respondToCatalogWriteAccessRequest(id: id, approved: approved))
        guard case .operationCompleted = response else { throw unexpected(response) }
    }

    public func catalogCreateIndex(
        title: String,
        aliases: [String] = [],
        tags: [String] = [],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCreateIndex(
            title: title,
            aliases: aliases,
            tags: tags,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCreateEntry(request: request, expectedRevision: expectedRevision))
        guard case let .catalogWriteResult(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogUpdateEntry(entry: entry, expectedRevision: expectedRevision))
        guard case let .catalogWriteResult(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogCommitEntryEdit(
        _ entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCommitEntryEdit(
            entry: entry,
            secretInputs: secretInputs,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogApplyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogApplyBatch(mutation: mutation, expectedRevision: expectedRevision))
        guard case let .catalogWriteResult(result) = response else { throw unexpected(response) }
        return result
    }

    public func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogBindExistingSecret(
            entryID: entryID,
            key: key,
            secretRef: secretRef,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64) {
        let response = try await send(.catalogSecureInput(
            entryID: entryID,
            key: key,
            label: label,
            plaintext: plaintext,
            policy: policy
        ))
        guard case let .secretBound(reference, revision) = response else {
            throw unexpected(response)
        }
        return (reference, revision)
    }

    public func catalogRevealField(entryID: String, key: String) async throws -> String {
        let response = try await send(.catalogRevealField(entryID: entryID, key: key))
        guard case let .catalogFieldPlaintext(plaintext) = response else {
            throw unexpected(response)
        }
        return plaintext
    }

    public func revealSessionData(sessionID: String) async throws -> RestoredParagraph {
        let response = try await send(.revealSessionData(sessionID: sessionID))
        guard case let .revealSessionData(paragraph) = response else {
            throw unexpected(response)
        }
        return paragraph
    }

    public func restoreReferences(
        references: [String],
        context: RevealContext
    ) async throws -> RestoredParagraph {
        let response = try await send(.restoreReferences(references: references, context: context))
        guard case let .restoredText(text) = response else {
            throw unexpected(response)
        }
        return RestoredParagraph(text: text, values: [])
    }

    public func send(_ request: AppControlRequest) async throws -> AppControlResponse {
        try validateEndpoint()
        let token = try readCapabilityToken()
        let fileDescriptor = try connect()
        defer {
            _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
            Darwin.close(fileDescriptor)
        }
        try setIOTimeouts(on: fileDescriptor)
        let frame = try IPCFrameCodec.encode(
            AuthenticatedAppControlRequest(capabilityToken: token, request: request)
        )
        try writeAll(frame, to: fileDescriptor)
        let responseFrame = try readFrame(from: fileDescriptor)
        let response = try IPCFrameCodec.decode(AppControlResponse.self, from: responseFrame)
        if case let .failure(code) = response {
            throw VaultIPCClientError.responseFailure(code)
        }
        return response
    }

    private func unexpected(_ response: AppControlResponse) -> VaultIPCClientError {
        .responseFailure("UNEXPECTED_APP_CONTROL_RESPONSE")
    }

    private func validateEndpoint() throws {
        var directoryStat = stat()
        guard lstat(configuration.directoryURL.path, &directoryStat) == 0,
              (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == geteuid(),
              (directoryStat.st_mode & 0o777) == 0o700
        else { throw VaultIPCClientError.endpointOwnershipInvalid }

        var socketStat = stat()
        guard lstat(configuration.socketURL.path, &socketStat) == 0,
              (socketStat.st_mode & S_IFMT) == S_IFSOCK,
              socketStat.st_uid == geteuid(),
              (socketStat.st_mode & 0o777) == 0o600
        else { throw VaultIPCClientError.endpointUnavailable }

        var tokenStat = stat()
        guard lstat(configuration.tokenURL.path, &tokenStat) == 0,
              (tokenStat.st_mode & S_IFMT) == S_IFREG,
              tokenStat.st_uid == geteuid(),
              (tokenStat.st_mode & 0o777) == 0o600
        else { throw VaultIPCClientError.endpointOwnershipInvalid }
    }

    private func readCapabilityToken() throws -> CapabilityToken {
        let raw = String(decoding: try Data(contentsOf: configuration.tokenURL), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return try CapabilityToken(base64Encoded: raw)
    }

    private func connect() throws -> Int32 {
        let descriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw VaultIPCClientError.operationFailed("socket", errno: errno)
        }
        do {
            try setNoSIGPIPE(on: descriptor)
            try setIOTimeouts(on: descriptor)
            let flags = Darwin.fcntl(descriptor, F_GETFL, 0)
            guard flags >= 0 else { throw VaultIPCClientError.operationFailed("fcntl-getfl", errno: errno) }
            guard Darwin.fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
                throw VaultIPCClientError.operationFailed("fcntl-setnonblock", errno: errno)
            }
            var address = try sockaddrUnix(for: configuration.socketURL.path)
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                    Darwin.connect(descriptor, rebound, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            if result != 0 {
                guard errno == EINPROGRESS else {
                    throw VaultIPCClientError.operationFailed("connect", errno: errno)
                }
                var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
                let pollResult = Darwin.poll(&pollDescriptor, 1, Self.connectTimeoutMilliseconds)
                guard pollResult > 0 else {
                    throw VaultIPCClientError.operationFailed("connect-timeout", errno: ETIMEDOUT)
                }
                var socketError: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0,
                      socketError == 0
                else { throw VaultIPCClientError.operationFailed("connect", errno: socketError) }
            }
            guard Darwin.fcntl(descriptor, F_SETFL, flags) >= 0 else {
                throw VaultIPCClientError.operationFailed("fcntl-restore", errno: errno)
            }
            return descriptor
        } catch {
            Darwin.close(descriptor)
            throw error
        }
    }

    private func sockaddrUnix(for path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        let bytes = Array(path.utf8)
        let maximum = MemoryLayout.size(ofValue: address.sun_path) - 1
        guard bytes.count <= maximum else {
            throw VaultIPCClientError.operationFailed("socket-path", errno: ENAMETOOLONG)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: bytes)
            buffer[bytes.count] = 0
        }
        return address
    }

    private func setNoSIGPIPE(on descriptor: Int32) throws {
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw VaultIPCClientError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func setIOTimeouts(on descriptor: Int32) throws {
        var timeout = timeval(tv_sec: Int(Self.ioTimeoutSeconds), tv_usec: 0)
        guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0,
              setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0
        else { throw VaultIPCClientError.operationFailed("setsockopt", errno: errno) }
    }

    private func writeAll(_ data: Data, to descriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.write(descriptor, baseAddress.advanced(by: offset), data.count - offset)
            }
            if written > 0 { offset += written; continue }
            if written < 0, errno == EINTR { continue }
            throw VaultIPCClientError.operationFailed("write", errno: errno)
        }
    }

    private func readFrame(from descriptor: Int32) throws -> Data {
        let header = try readExactly(4, from: descriptor)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= IPCFrameCodec.maxFrameBytes else { throw VaultIPCClientError.frameTooLarge }
        return header + (try readExactly(Int(length), from: descriptor))
    }

    private func readExactly(_ count: Int, from descriptor: Int32) throws -> Data {
        var data = Data(count: count)
        var offset = 0
        while offset < count {
            let read = data.withUnsafeMutableBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.read(descriptor, baseAddress.advanced(by: offset), count - offset)
            }
            if read > 0 { offset += read; continue }
            if read < 0, errno == EINTR { continue }
            throw VaultIPCClientError.incompleteFrame
        }
        return data
    }
}
