import Darwin
import Foundation
import VaultCore
import VaultExecution

public enum VaultIPCClientError: Error, Equatable, Sendable {
    case endpointUnavailable
    case endpointOwnershipInvalid
    case endpointPermissionsInvalid
    case responseFailure(String)
    case unexpectedResponse
    case operationFailed(String, errno: Int32)
    case frameTooLarge
    case incompleteFrame
}

/// Short-lived, one-request-per-connection client used by the GUI and other
/// trusted local integrations. It rereads the token for every connection so a
/// restarted Agent invalidates all previous capabilities.
public actor VaultIPCClient {
    private static let connectTimeoutMilliseconds: Int32 = 2_000
    private static let ioTimeoutSeconds: Int32 = 3

    private let configuration: UnixSocketServerConfiguration

    public init(configuration: UnixSocketServerConfiguration) {
        self.configuration = configuration
    }

    public static func defaultClient() throws -> VaultIPCClient {
        VaultIPCClient(configuration: try .defaultConfiguration())
    }

    public func status() async throws -> Bool {
        let response = try await send(.status)
        guard case let .status(locked) = response else {
            throw unexpected(response)
        }
        return locked
    }

    public func workbenchStatus() async throws -> WorkbenchStatus {
        let response = try await send(.workbenchStatus)
        guard case let .workbenchStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func secretOperationCapabilities() async throws -> [SecretOperationCapability] {
        let response = try await send(.secretOperationCapabilities)
        guard case let .secretOperationCapabilities(capabilities) = response else {
            throw unexpected(response)
        }
        return capabilities
    }

    public func savedSecretReferences() async throws -> [SecretReferenceMetadata] {
        let response = try await send(.savedReferences)
        guard case let .savedReferences(references) = response else {
            throw unexpected(response)
        }
        return references
    }

    public func searchSecrets(
        query: String,
        field: SecretCatalogField? = nil,
        limit: Int = 20
    ) async throws -> SecretCatalogSearchResult {
        let response = try await send(.catalogSearch(query: query, field: field, limit: limit))
        guard case let .catalogSearchResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func getCatalogEntry(entryID: String) async throws -> SecretCatalogSearchResult {
        let response = try await send(.catalogGet(entryID: entryID))
        guard case let .catalogSearchResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func listCatalogIndexes() async throws -> SecretCatalogIndexListResult {
        let response = try await send(.catalogListIndexes)
        guard case let .catalogIndexListResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func listCatalogEntries(indexID: String) async throws -> SecretCatalogEntryListResult {
        let response = try await send(.catalogListEntries(indexID: indexID))
        guard case let .catalogEntryListResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func createCatalogIndex(
        title: String,
        aliases: [String] = [],
        tags: [String] = []
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCreateIndex(title: title, aliases: aliases, tags: tags))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func createCatalogEntry(_ request: CatalogDraftRequest) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCreateEntry(request: request))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func createCatalogStructure(
        _ request: CatalogCreateStructureRequest
    ) async throws -> CatalogStructureWriteResult {
        let response = try await send(.catalogCreateStructure(request: request))
        guard case let .catalogStructureWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func createCatalogDraft(
        _ request: CatalogDraftRequest
    ) async throws -> CatalogDraft {
        let response = try await send(.catalogCreateDraft(request: request))
        guard case let .catalogDraft(draft) = response else {
            throw unexpected(response)
        }
        return draft
    }

    public func patchCatalogMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogPatchMetadata(
            entryID: entryID,
            patch: patch,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogCommit(
            draft: draft,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool = true,
        searchable: Bool = true,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogAddSecretPlaceholder(
            entryID: entryID,
            key: key,
            label: label,
            agentVisible: agentVisible,
            searchable: searchable,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func bindCatalogExistingSecret(
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

    public func applyCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        let response = try await send(.catalogApplyBatch(mutation: mutation, expectedRevision: expectedRevision))
        guard case let .catalogWriteResult(result) = response else {
            throw unexpected(response)
        }
        return result
    }

    public func requestCatalogSecureInputs(
        entryID: String,
        targets: [CatalogSecureInputTargetRequest],
        expectedRevision: UInt64
    ) async throws -> CatalogSecureInputStatus {
        let response = try await send(.catalogRequestSecureInputs(
            entryID: entryID,
            targets: targets,
            expectedRevision: expectedRevision
        ))
        guard case let .catalogSecureInputStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func catalogSecureInputStatus(requestID: UUID) async throws -> CatalogSecureInputStatus {
        let response = try await send(.catalogSecureInputStatus(requestID: requestID))
        guard case let .catalogSecureInputStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func validateCatalog() async throws -> CatalogValidationResult {
        let response = try await send(.catalogValidate)
        guard case let .catalogValidation(status, revision, rawSHA256, diagnostics, filePreflight) = response else {
            throw unexpected(response)
        }
        return CatalogValidationResult(
            status: status,
            revision: revision,
            rawSHA256: rawSHA256,
            filePreflight: filePreflight,
            diagnostics: diagnostics
        )
    }

    public func pendingCatalogWriteAccessRequestIDs() async throws -> [UUID] {
        let response = try await send(.catalogPendingWriteAccessRequestIDs)
        guard case let .catalogPendingWriteAccessRequestIDs(requestIDs) = response else {
            throw unexpected(response)
        }
        return requestIDs
    }

    public func pendingCatalogSecureInputRequestIDs() async throws -> [UUID] {
        let response = try await send(.catalogPendingSecureInputRequestIDs)
        guard case let .catalogPendingSecureInputRequestIDs(requestIDs) = response else {
            throw unexpected(response)
        }
        return requestIDs
    }

    public func requestCatalogWriteAccess(_ request: CatalogAgentWriteAccessRequest) async throws {
        let response = try await send(.catalogRequestWriteAccess(request))
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func pendingRevealSessionIDs() async throws -> [String] {
        let response = try await send(.pendingRevealSessions)
        guard case let .revealSessionIDs(sessionIDs) = response else {
            throw unexpected(response)
        }
        return sessionIDs
    }

    public func performSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationOutput {
        // The adapter owns the execution deadline and starts it after the
        // service has completed any device-owner approval. Do not apply the
        // short control-request timeout to this long-running response.
        let response = try await send(
            .executeSecretOperation(descriptor),
            ioTimeoutSeconds: nil
        )
        guard case let .secretOperation(output) = response else {
            throw unexpected(response)
        }
        return output
    }

    public func startSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationHandle {
        let response = try await send(.startSecretOperation(descriptor))
        guard case let .secretOperationHandle(handle) = response else {
            throw unexpected(response)
        }
        return handle
    }

    public func secretOperationStatus(operationID: UUID) async throws -> SecretOperationStatus {
        let response = try await send(.secretOperationStatus(operationID: operationID))
        guard case let .secretOperationStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func cancelSecretOperation(operationID: UUID) async throws -> SecretOperationStatus {
        let response = try await send(.cancelSecretOperation(operationID: operationID))
        guard case let .secretOperationStatus(status) = response else {
            throw unexpected(response)
        }
        return status
    }

    public func reviewSSHHostKey(host: String, port: Int) async throws -> SSHHostKeyReview {
        let response = try await send(.reviewSSHHostKey(host: host, port: port))
        guard case let .sshHostKeyReview(review) = response else {
            throw unexpected(response)
        }
        return review
    }

    public func sshSessionStatuses(sessionID: String? = nil) async throws -> [SSHSessionStatus] {
        let response = try await send(.sshSessionStatus(sessionID: sessionID))
        guard case let .sshSessionStatus(sessions) = response else {
            throw unexpected(response)
        }
        return sessions
    }

    public func closeSSHSession(sessionID: String) async throws {
        let response = try await send(.sshSessionClose(sessionID: sessionID))
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func encryptSelection(
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String]
    ) async throws -> String {
        let response = try await send(.encryptBound(
            label: label,
            policy: policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols
        ))
        guard case let .created(reference) = response else {
            throw unexpected(response)
        }
        return reference
    }

    public func deleteRecord(_ reference: String) async throws {
        let response = try await send(.deleteRecord(reference: reference))
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func authorizeHighRisk(reason: String) async throws {
        let response = try await send(.authorizeHighRisk(reason: reason))
        guard case .authorizationApproved = response else {
            throw unexpected(response)
        }
    }

    public func lock() async throws {
        let response = try await send(.lock)
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func clearRevealSessions() async throws {
        let response = try await send(.clearRevealSessions)
        guard case .operationCompleted = response else {
            throw unexpected(response)
        }
    }

    public func send(_ request: IPCRequest) async throws -> IPCResponse {
        try await send(request, ioTimeoutSeconds: Self.ioTimeoutSeconds)
    }

    private func send(
        _ request: IPCRequest,
        ioTimeoutSeconds: Int32?
    ) async throws -> IPCResponse {
        try validateEndpoint()
        let token = try readCapabilityToken()
        let fileDescriptor = try connect()
        defer {
            _ = Darwin.shutdown(fileDescriptor, SHUT_RDWR)
            Darwin.close(fileDescriptor)
        }

        try setIOTimeouts(on: fileDescriptor, seconds: ioTimeoutSeconds)
        let frame = try IPCFrameCodec.encode(
            AuthenticatedIPCRequest(capabilityToken: token, request: request)
        )
        try writeAll(frame, to: fileDescriptor)
        let responseFrame = try readFrame(from: fileDescriptor)
        let response = try IPCFrameCodec.decode(IPCResponse.self, from: responseFrame)
        if case let .failure(code) = response {
            throw VaultIPCClientError.responseFailure(code)
        }
        return response
    }

    private func validateEndpoint() throws {
        var directoryStat = stat()
        guard lstat(configuration.directoryURL.path, &directoryStat) == 0,
              (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == geteuid(),
              (directoryStat.st_mode & 0o777) == 0o700
        else {
            throw VaultIPCClientError.endpointOwnershipInvalid
        }

        var socketStat = stat()
        guard lstat(configuration.socketURL.path, &socketStat) == 0,
              (socketStat.st_mode & S_IFMT) == S_IFSOCK,
              socketStat.st_uid == geteuid()
        else {
            throw VaultIPCClientError.endpointUnavailable
        }
        guard (socketStat.st_mode & 0o777) == 0o600 else {
            throw VaultIPCClientError.endpointPermissionsInvalid
        }

        var tokenStat = stat()
        guard lstat(configuration.tokenURL.path, &tokenStat) == 0,
              (tokenStat.st_mode & S_IFMT) == S_IFREG,
              tokenStat.st_uid == geteuid()
        else {
            throw VaultIPCClientError.endpointOwnershipInvalid
        }
        guard (tokenStat.st_mode & 0o777) == 0o600 else {
            throw VaultIPCClientError.endpointPermissionsInvalid
        }
    }

    private func readCapabilityToken() throws -> CapabilityToken {
        let data = try Data(contentsOf: configuration.tokenURL)
        let rawValue = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return try CapabilityToken(base64Encoded: rawValue)
    }

    private func connect() throws -> Int32 {
        let fileDescriptor = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fileDescriptor >= 0 else {
            throw VaultIPCClientError.operationFailed("socket", errno: errno)
        }
        do {
            try setNoSIGPIPE(on: fileDescriptor)
            let originalFlags = Darwin.fcntl(fileDescriptor, F_GETFL, 0)
            guard originalFlags >= 0 else {
                throw VaultIPCClientError.operationFailed("fcntl-getfl", errno: errno)
            }
            guard Darwin.fcntl(fileDescriptor, F_SETFL, originalFlags | O_NONBLOCK) >= 0 else {
                throw VaultIPCClientError.operationFailed("fcntl-setnonblock", errno: errno)
            }

            var address = try sockaddrUnix(for: configuration.socketURL.path)
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { rebound in
                    Darwin.connect(
                        fileDescriptor,
                        rebound,
                        socklen_t(MemoryLayout<sockaddr_un>.size)
                    )
                }
            }

            if result != 0 {
                guard errno == EINPROGRESS else {
                    throw VaultIPCClientError.operationFailed("connect", errno: errno)
                }

                var descriptor = pollfd(
                    fd: fileDescriptor,
                    events: Int16(POLLOUT),
                    revents: 0
                )
                let pollResult = Darwin.poll(
                    &descriptor,
                    1,
                    Self.connectTimeoutMilliseconds
                )
                guard pollResult > 0 else {
                    if pollResult == 0 {
                        throw VaultIPCClientError.operationFailed("connect-timeout", errno: ETIMEDOUT)
                    }
                    throw VaultIPCClientError.operationFailed("poll", errno: errno)
                }

                var socketError: Int32 = 0
                var socketErrorLength = socklen_t(MemoryLayout<Int32>.size)
                let errorResult = withUnsafeMutablePointer(to: &socketError) { pointer in
                    getsockopt(
                        fileDescriptor,
                        SOL_SOCKET,
                        SO_ERROR,
                        pointer,
                        &socketErrorLength
                    )
                }
                guard errorResult == 0 else {
                    throw VaultIPCClientError.operationFailed("getsockopt", errno: errno)
                }
                guard socketError == 0 else {
                    throw VaultIPCClientError.operationFailed("connect", errno: socketError)
                }
            }

            guard Darwin.fcntl(fileDescriptor, F_SETFL, originalFlags) >= 0 else {
                throw VaultIPCClientError.operationFailed("fcntl-restore", errno: errno)
            }
            return fileDescriptor
        } catch {
            Darwin.close(fileDescriptor)
            throw error
        }
    }

    private func sockaddrUnix(for path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        let pathBytes = Array(path.utf8)
        let maximumPathBytes = MemoryLayout.size(ofValue: address.sun_path) - 1
        guard pathBytes.count <= maximumPathBytes else {
            throw VaultIPCClientError.operationFailed("socket-path", errno: ENAMETOOLONG)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { buffer in
            buffer.copyBytes(from: pathBytes)
            buffer[pathBytes.count] = 0
        }
        return address
    }

    private func setNoSIGPIPE(on fileDescriptor: Int32) throws {
        var enabled: Int32 = 1
        let result = withUnsafePointer(to: &enabled) { pointer in
            setsockopt(
                fileDescriptor,
                SOL_SOCKET,
                SO_NOSIGPIPE,
                pointer,
                socklen_t(MemoryLayout<Int32>.size)
            )
        }
        guard result == 0 else {
            throw VaultIPCClientError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func setIOTimeouts(on fileDescriptor: Int32, seconds: Int32?) throws {
        guard let seconds else { return }
        var timeout = timeval(tv_sec: Int(seconds), tv_usec: 0)
        let receiveResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_RCVTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        let sendResult = withUnsafePointer(to: &timeout) { pointer in
            setsockopt(fileDescriptor, SOL_SOCKET, SO_SNDTIMEO, pointer, socklen_t(MemoryLayout<timeval>.size))
        }
        guard receiveResult == 0, sendResult == 0 else {
            throw VaultIPCClientError.operationFailed("setsockopt", errno: errno)
        }
    }

    private func readFrame(from fileDescriptor: Int32) throws -> Data {
        let header = try readExactly(4, from: fileDescriptor)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length <= IPCFrameCodec.maxFrameBytes else {
            throw VaultIPCClientError.frameTooLarge
        }
        return header + (try readExactly(Int(length), from: fileDescriptor))
    }

    private func readExactly(_ byteCount: Int, from fileDescriptor: Int32) throws -> Data {
        var data = Data(count: byteCount)
        var offset = 0
        while offset < byteCount {
            let count = data.withUnsafeMutableBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.read(fileDescriptor, baseAddress.advanced(by: offset), byteCount - offset)
            }
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else if count < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                throw VaultIPCClientError.incompleteFrame
            } else {
                throw VaultIPCClientError.incompleteFrame
            }
        }
        return data
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return -1 }
                return Darwin.write(fileDescriptor, baseAddress.advanced(by: offset), data.count - offset)
            }
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                throw VaultIPCClientError.operationFailed("write", errno: errno)
            }
        }
    }

    private func unexpected(_ response: IPCResponse) -> VaultIPCClientError {
        if case let .failure(code) = response {
            return .responseFailure(code)
        }
        return .unexpectedResponse
    }
}
