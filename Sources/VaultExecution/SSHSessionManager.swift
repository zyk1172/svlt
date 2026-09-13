import Darwin
import Foundation
import VaultCore

public enum SSHSessionManagerError: Error, Equatable, Sendable {
    case sessionNotFound
    case sessionExpired
    case scopeMismatch
    case controlUnavailable
    case controlDirectoryUnavailable
    case sessionLimitReached
}

/// The result of one SSH channel is intentionally separate from the child
/// process exit status. An exit status of zero is only a remote-command
/// success when the wrapper has completed its own protocol and reported that
/// the SSH child was authenticated and waited to completion.
public enum SSHChannelState: String, Codable, Equatable, Sendable {
    /// The local wrapper or process boundary failed before it could prove an
    /// authenticated SSH channel and completed remote command.
    case wrapperFailed
    /// SSH ran, but the transport/authentication failed before a remote
    /// command completion was proven.
    case transportFailed
    /// The authenticated SSH child was waited successfully; its exit status
    /// is therefore the remote command's status, including non-zero values.
    case remoteCommandCompleted
}

/// The transport scope contains no plaintext. `principal` is supplied by the
/// trusted IPC boundary, never by an Agent descriptor.
public struct SSHSessionScope: Hashable, Sendable {
    public let principal: String
    public let host: String
    public let port: Int
    public let username: String
    public let passwordReferenceID: String
    public let hostKeyPin: SSHHostKeyPin?
    public let securityGeneration: UInt64

    public init(
        principal: String,
        host: String,
        port: Int,
        username: String,
        passwordReferenceID: String,
        securityGeneration: UInt64,
        hostKeyPin: SSHHostKeyPin? = nil
    ) {
        self.principal = principal
        self.host = host
        self.port = port
        self.username = username
        self.passwordReferenceID = passwordReferenceID
        self.hostKeyPin = hostKeyPin
        self.securityGeneration = securityGeneration
    }
}

public struct SSHSessionAccess: Sendable, Equatable {
    public let id: String
    public let requiresAuthentication: Bool

    // This value is deliberately internal to VaultExecution. It is not
    // Codable, not part of IPC, and is never returned in a tool response.
    let controlPath: String
    let outputFingerprints: [SecretOutputFingerprint]

    init(
        id: String,
        controlPath: String,
        requiresAuthentication: Bool,
        outputFingerprints: [SecretOutputFingerprint] = []
    ) {
        self.id = id
        self.controlPath = controlPath
        self.requiresAuthentication = requiresAuthentication
        self.outputFingerprints = outputFingerprints
    }
}

public struct SSHSessionCommandExecution: Sendable, Equatable {
    public let processResult: ProcessResult
    public let channelState: SSHChannelState
    /// Whether the manager verified a reusable ControlMaster for this result.
    /// This is independent from remote command completion: a command may run
    /// successfully even when the optional reuse socket could not persist.
    public let masterReady: Bool
    public let sessionID: String?
    let outputFingerprints: [SecretOutputFingerprint]

    /// Compatibility projection for callers compiled against the original
    /// boolean transport result. New code should use `channelState` so a
    /// wrapper failure cannot be confused with a completed remote command.
    @available(*, deprecated, message: "Use channelState")
    public var transportReady: Bool {
        channelState == .remoteCommandCompleted
    }

    /// Compatibility initializer for existing in-process clients. A false
    /// value is conservatively treated as a failed transport and never as a
    /// completed remote command.
    @available(*, deprecated, message: "Use the channelState initializer")
    public init(
        processResult: ProcessResult,
        transportReady: Bool,
        sessionID: String? = nil
    ) {
        self.init(
            processResult: processResult,
            channelState: transportReady ? .remoteCommandCompleted : .transportFailed,
            sessionID: sessionID,
            masterReady: transportReady,
            outputFingerprints: []
        )
    }

    public init(
        processResult: ProcessResult,
        channelState: SSHChannelState,
        sessionID: String? = nil
    ) {
        self.init(
            processResult: processResult,
            channelState: channelState,
            sessionID: sessionID,
            outputFingerprints: []
        )
    }

    init(
        processResult: ProcessResult,
        channelState: SSHChannelState,
        sessionID: String? = nil,
        masterReady: Bool = false,
        outputFingerprints: [SecretOutputFingerprint]
    ) {
        self.processResult = processResult
        self.channelState = channelState
        self.masterReady = masterReady
        self.sessionID = sessionID
        self.outputFingerprints = outputFingerprints
    }

    func assigningSessionID(_ id: String?, masterReady: Bool? = nil) -> Self {
        Self(
            processResult: processResult,
            channelState: channelState,
            sessionID: id,
            masterReady: masterReady ?? self.masterReady,
            outputFingerprints: outputFingerprints
        )
    }

    func assigningFingerprintsIfMissing(_ fingerprints: [SecretOutputFingerprint]) -> Self {
        guard outputFingerprints.isEmpty else { return self }
        return Self(
            processResult: processResult,
            channelState: channelState,
            sessionID: sessionID,
            masterReady: masterReady,
            outputFingerprints: fingerprints
        )
    }
}

public enum SSHSessionState: String, Codable, Equatable, Sendable {
    case active
}

/// The only public session projection contains an opaque ID and non-sensitive
/// status. ControlPath, password references, and authentication state never
/// cross this projection.
public struct SSHSessionStatus: Codable, Equatable, Sendable {
    public let sessionID: String
    public let host: String
    public let port: Int
    public let status: SSHSessionState
    public let idleExpiresIn: TimeInterval

    public init(
        sessionID: String,
        host: String,
        port: Int,
        status: SSHSessionState,
        idleExpiresIn: TimeInterval
    ) {
        self.sessionID = sessionID
        self.host = host
        self.port = port
        self.status = status
        self.idleExpiresIn = max(0, idleExpiresIn)
    }
}

/// Owns short-lived OpenSSH multiplexed transports. It never persists the
/// registry and it never accepts a caller-supplied ControlPath.
public actor SSHSessionManager {
    private enum RecordState: Equatable {
        case pending
        case active
        case draining
    }

    private struct Record {
        let id: String
        let scope: SSHSessionScope
        let controlPath: String
        let createdAt: Date
        let createdTick: UInt64
        var lastUsedAt: Date
        var lastUsedTick: UInt64
        var state: RecordState
        var outputFingerprints: [SecretOutputFingerprint]
        var inFlightCount: Int
    }

    /// A single-flight open is keyed by both scope and record ID. The ID
    /// prevents a cancelled or superseded open from removing a newer flight
    /// for the same scope after an actor re-entry.
    private struct OpeningTask {
        let recordID: String
        let task: Task<SSHSessionCommandExecution, Error>
    }

    private let processRunner: any ProcessRunning
    private let sessionDirectory: URL
    private let idleTTL: Duration
    private let absoluteTTL: Duration
    private let idleNanoseconds: UInt64
    private let absoluteNanoseconds: UInt64
    private let maxSessionsPerPrincipal: Int
    private let maxGlobalSessions: Int
    private let now: @Sendable () -> Date
    private let monotonicNow: @Sendable () -> UInt64
    // Darwin's sockaddr_un reserves 104 bytes for sun_path. Leave room for
    // its NUL terminator and fail before OpenSSH receives an unrepresentable
    // socket path.
    private static let maxControlPathBytes = 103
    private var records: [String: Record] = [:]
    private var openingTasks: [SSHSessionScope: OpeningTask] = [:]
    private var transientSessionCountsByPrincipal: [String: Int] = [:]
    private var transientSessionCount = 0
    private var didCleanStaleControlPaths = false

    public init(
        processRunner: any ProcessRunning = FoundationProcessRunner(),
        sessionDirectory: URL? = nil,
        idleTTL: Duration = .seconds(300),
        absoluteTTL: Duration = .seconds(1_800),
        maxSessionsPerPrincipal: Int = 8,
        maxGlobalSessions: Int = 32,
        now: @escaping @Sendable () -> Date = Date.init,
        monotonicNow: @escaping @Sendable () -> UInt64 = SSHSessionManager.defaultMonotonicNow
    ) {
        self.processRunner = processRunner
        self.sessionDirectory = (sessionDirectory
            ?? Self.defaultSessionDirectory(for: FileManager.default.homeDirectoryForCurrentUser))
            .standardizedFileURL
        self.idleTTL = idleTTL
        self.absoluteTTL = absoluteTTL
        self.idleNanoseconds = Self.nanoseconds(for: idleTTL)
        self.absoluteNanoseconds = Self.nanoseconds(for: absoluteTTL)
        self.maxSessionsPerPrincipal = max(1, maxSessionsPerPrincipal)
        self.maxGlobalSessions = max(1, maxGlobalSessions)
        self.now = now
        self.monotonicNow = monotonicNow
    }

    /// Executes one already-encoded remote command. The closure is the only
    /// place that knows how to feed the first password to Expect. For a reused
    /// transport the manager passes `requiresAuthentication == false`, so the
    /// closure must not resolve or send a password.
    public func execute(
        scope: SSHSessionScope,
        requestedSessionID: String? = nil,
        operation: @escaping @Sendable (SSHSessionAccess) async throws -> SSHSessionCommandExecution
    ) async throws -> SSHSessionCommandExecution {
        try ensureSessionDirectory()
        await reapExpired()

        if let requestedSessionID {
            guard let record = records[requestedSessionID] else {
                // A sessionID is only a transport-reuse hint. An expired or
                // otherwise stale handle must not turn a valid command into
                // a transport error; normal lookup/opening can reconnect.
                return try await execute(scope: scope, operation: operation)
            }
            guard record.scope == scope else {
                throw SSHSessionManagerError.scopeMismatch
            }
            guard !isExpired(record) else {
                await closeRecord(record)
                return try await execute(scope: scope, operation: operation)
            }
            guard record.state == .active else {
                return try await execute(scope: scope, operation: operation)
            }
            guard await checkControl(record) else {
                await closeRecord(record)
                return try await execute(scope: scope, operation: operation)
            }
            return try await executeOnActiveRecord(record, operation: operation)
        }

        if let existing = records.values.first(where: { $0.scope == scope && $0.state == .active }) {
            guard !isExpired(existing) else {
                await closeRecord(existing)
                return try await createAndExecute(scope: scope, operation: operation)
            }
            guard await checkControl(existing) else {
                await closeRecord(existing)
                return try await createAndExecute(scope: scope, operation: operation)
            }
            return try await executeOnActiveRecord(existing, operation: operation)
        }

        if openingTasks[scope] != nil {
            // The first command may legitimately run for hours. Never serialize a
            // later command behind that command just because its reusable master
            // has not been published yet. Use an isolated one-shot channel until
            // the shared transport becomes available.
            return try await executeWhileOpening(scope: scope, operation: operation)
        }

        return try await createAndExecute(scope: scope, operation: operation)
    }

    public func statuses(for principal: String) async -> [SSHSessionStatus] {
        await reapExpired()
        return sessionStatuses(
            records: records.values.filter { $0.scope.principal == principal && $0.state == .active }
        )
    }

    /// Returns only the sessions owned by the supplied kernel-derived
    /// principal and security generation. The optional ID is a selector, not
    /// a capability; the caller still cannot see another process's session.
    public func statuses(
        for principal: String,
        securityGeneration: UInt64,
        sessionID: String? = nil
    ) async throws -> [SSHSessionStatus] {
        await reapExpired()
        let matching = records.values.filter {
            $0.scope.principal == principal
                && $0.scope.securityGeneration == securityGeneration
                && $0.state == .active
                && (sessionID == nil || $0.id == sessionID)
        }
        if let sessionID, matching.isEmpty {
            guard records[sessionID] != nil else {
                throw SSHSessionManagerError.sessionNotFound
            }
            throw SSHSessionManagerError.scopeMismatch
        }
        return sessionStatuses(records: matching)
    }

    /// A targeted status lookup checks the ControlMaster before reporting it
    /// active. This makes a dead master fail closed and removes its registry
    /// record rather than returning a stale transport handle.
    public func status(
        sessionID: String,
        principal: String,
        securityGeneration: UInt64
    ) async throws -> SSHSessionStatus {
        guard let record = records[sessionID] else {
            throw SSHSessionManagerError.sessionNotFound
        }
        guard record.scope.principal == principal,
              record.scope.securityGeneration == securityGeneration else {
            throw SSHSessionManagerError.scopeMismatch
        }
        guard !isExpired(record) else {
            await closeRecord(record)
            throw SSHSessionManagerError.sessionExpired
        }
        guard record.state == .active else {
            if record.state != .draining {
                await closeRecord(record)
            }
            throw SSHSessionManagerError.controlUnavailable
        }
        guard await checkControl(record) else {
            await closeRecord(record)
            throw SSHSessionManagerError.controlUnavailable
        }
        return sessionStatuses(records: [record]).first!
    }

    public func close(sessionID: String, scope: SSHSessionScope) async throws {
        guard let record = records[sessionID] else {
            throw SSHSessionManagerError.sessionNotFound
        }
        guard record.scope == scope else {
            throw SSHSessionManagerError.scopeMismatch
        }
        await closeRecord(record)
    }

    /// Closes only a session owned by the kernel-derived principal in the
    /// current security generation. No secret reference or ControlPath is
    /// needed on this Agent-facing control operation.
    public func close(
        sessionID: String,
        principal: String,
        securityGeneration: UInt64
    ) async throws {
        guard let record = records[sessionID] else {
            throw SSHSessionManagerError.sessionNotFound
        }
        guard record.scope.principal == principal,
              record.scope.securityGeneration == securityGeneration else {
            throw SSHSessionManagerError.scopeMismatch
        }
        await closeRecord(record)
    }

    public func invalidateAll() async {
        for opening in openingTasks.values {
            opening.task.cancel()
        }
        openingTasks.removeAll()
        let recordsToClose = Array(records.values)
        records.removeAll()
        for record in recordsToClose {
            if record.state == .active || record.state == .draining {
                await closeControl(record)
            } else {
                removeControlPath(record.controlPath)
            }
        }
    }

    public func reapExpired() async {
        let expired = records.values.filter(isExpired)
        for record in expired {
            await closeRecord(record)
        }
    }

    private func createAndExecute(
        scope: SSHSessionScope,
        operation: @escaping @Sendable (SSHSessionAccess) async throws -> SSHSessionCommandExecution
    ) async throws -> SSHSessionCommandExecution {
        try enforceLimits(for: scope.principal)
        let id = Self.makeSessionID()
        let controlPath = try makeControlPath()
        let tick = monotonicNow()
        let date = now()
        let record = Record(
            id: id,
            scope: scope,
            controlPath: controlPath,
            createdAt: date,
            createdTick: tick,
            lastUsedAt: date,
            lastUsedTick: tick,
            state: .pending,
            outputFingerprints: [],
            inFlightCount: 1
        )
        records[id] = record
        let access = SSHSessionAccess(id: id, controlPath: controlPath, requiresAuthentication: true)
        let task = Task { [weak self] in
            do {
                let result = try await operation(access)
                guard let self else {
                    return result.assigningSessionID(nil, masterReady: false)
                }
                return await self.finishOpening(
                    scope: scope,
                    record: record,
                    result: result
                )
            } catch {
                await self?.finishFailedOpening(scope: scope, record: record)
                throw error
            }
        }
        openingTasks[scope] = OpeningTask(recordID: id, task: task)
        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }

    private func executeWhileOpening(
        scope: SSHSessionScope,
        operation: @escaping @Sendable (SSHSessionAccess) async throws -> SSHSessionCommandExecution
    ) async throws -> SSHSessionCommandExecution {
        try reserveTransientSlot(for: scope.principal)
        defer { releaseTransientSlot(for: scope.principal) }
        let id = Self.makeSessionID()
        let controlPath = try makeControlPath()
        let tick = monotonicNow()
        let date = now()
        let record = Record(
            id: id,
            scope: scope,
            controlPath: controlPath,
            createdAt: date,
            createdTick: tick,
            lastUsedAt: date,
            lastUsedTick: tick,
            state: .pending,
            outputFingerprints: [],
            inFlightCount: 1
        )
        let access = SSHSessionAccess(
            id: id,
            controlPath: controlPath,
            requiresAuthentication: true
        )
        do {
            let result = try await operation(access)
            await closeControl(record)
            return result.assigningSessionID(nil, masterReady: false)
        } catch {
            await closeControl(record)
            throw error
        }
    }

    /// Settles an initial transport before its task becomes observable to
    /// waiters. Keeping the flight registered through the ControlMaster
    /// health check prevents a waiter from racing a half-settled record; after
    /// a failed check, all waiters re-enter `execute` and reconnect normally.
    private func finishOpening(
        scope: SSHSessionScope,
        record: Record,
        result: SSHSessionCommandExecution
    ) async -> SSHSessionCommandExecution {
        guard openingTasks[scope]?.recordID == record.id else {
            return result.assigningSessionID(nil, masterReady: false)
        }

        guard result.channelState == .remoteCommandCompleted else {
            openingTasks.removeValue(forKey: scope)
            // A wrapper or transport failure is not an authenticated,
            // completed channel. Do not issue `ssh -O exit` on a path that
            // may never have been a live master.
            records.removeValue(forKey: record.id)
            removeControlPath(record.controlPath)
            return result.assigningSessionID(nil, masterReady: false)
        }

        // The first channel may complete successfully even when the
        // ControlMaster did not persist. The master is a reuse optimization,
        // never a precondition for execution: drop the unusable record and
        // preserve the real command result.
        guard await checkControl(record) else {
            guard openingTasks[scope]?.recordID == record.id else {
                return result.assigningSessionID(nil, masterReady: false)
            }
            openingTasks.removeValue(forKey: scope)
            records.removeValue(forKey: record.id)
            await closeControl(record)
            return result.assigningSessionID(nil, masterReady: false)
        }

        // `checkControl` above awaits. `invalidateAll()` may cancel this
        // flight and a later caller may already have started a replacement
        // flight for the same scope before we resume. Never remove that newer
        // flight while cleaning up this old one.
        guard openingTasks[scope]?.recordID == record.id,
              var current = records[record.id] else {
            return result.assigningSessionID(nil, masterReady: false)
        }
        current.state = .active
        current.lastUsedAt = now()
        current.lastUsedTick = monotonicNow()
        current.outputFingerprints = result.outputFingerprints
        current.inFlightCount = 0
        records[record.id] = current
        openingTasks.removeValue(forKey: scope)
        return result.assigningSessionID(record.id, masterReady: true)
    }

    private func finishFailedOpening(scope: SSHSessionScope, record: Record) {
        guard openingTasks[scope]?.recordID == record.id else {
            return
        }
        openingTasks.removeValue(forKey: scope)
        // The opening closure has not reported an authenticated transport.
        // Avoid invoking `ssh -O exit` on a path that may never have been a
        // live master.
        records.removeValue(forKey: record.id)
        removeControlPath(record.controlPath)
    }

    private func executeOnActiveRecord(
        _ record: Record,
        operation: @escaping @Sendable (SSHSessionAccess) async throws -> SSHSessionCommandExecution
    ) async throws -> SSHSessionCommandExecution {
        let access = SSHSessionAccess(
            id: record.id,
            controlPath: record.controlPath,
            requiresAuthentication: false,
            outputFingerprints: record.outputFingerprints
        )
        guard var active = records[record.id] else {
            return try await operation(access).assigningSessionID(nil, masterReady: false)
        }
        active.inFlightCount += 1
        records[record.id] = active
        do {
            let result = try await operation(access)
            guard var current = records[record.id] else {
                // Explicit invalidation may remove the cache record while the
                // command is finishing. Preserve the real command result.
                return result.assigningSessionID(nil, masterReady: false)
            }
            current.inFlightCount = max(0, current.inFlightCount - 1)
            current.lastUsedAt = now()
            current.lastUsedTick = monotonicNow()

            guard result.channelState == .remoteCommandCompleted else {
                if current.inFlightCount == 0 {
                    await closeRecord(current)
                } else {
                    current.state = .draining
                    records[record.id] = current
                }
                return result.assigningSessionID(nil, masterReady: false)
            }

            if current.state == .draining {
                if current.inFlightCount == 0 {
                    await closeRecord(current)
                } else {
                    records[record.id] = current
                }
                return result
                    .assigningFingerprintsIfMissing(record.outputFingerprints)
                    .assigningSessionID(nil, masterReady: false)
            }

            records[record.id] = current
            return result
                .assigningFingerprintsIfMissing(record.outputFingerprints)
                .assigningSessionID(record.id, masterReady: true)
        } catch {
            if var current = records[record.id] {
                current.inFlightCount = max(0, current.inFlightCount - 1)
                current.lastUsedAt = now()
                current.lastUsedTick = monotonicNow()
                if current.state == .draining, current.inFlightCount == 0 {
                    await closeRecord(current)
                } else {
                    records[record.id] = current
                }
            }
            throw error
        }
    }

    private func reserveTransientSlot(for principal: String) throws {
        try enforceLimits(for: principal)
        transientSessionCountsByPrincipal[principal, default: 0] += 1
        transientSessionCount += 1
    }

    private func releaseTransientSlot(for principal: String) {
        if let count = transientSessionCountsByPrincipal[principal] {
            if count <= 1 {
                transientSessionCountsByPrincipal.removeValue(forKey: principal)
            } else {
                transientSessionCountsByPrincipal[principal] = count - 1
            }
        }
        transientSessionCount = max(0, transientSessionCount - 1)
    }

    private func enforceLimits(for principal: String) throws {
        let principalRecords = records.values.filter { $0.scope.principal == principal }
        let principalTransientCount = transientSessionCountsByPrincipal[principal, default: 0]
        guard principalRecords.count + principalTransientCount < maxSessionsPerPrincipal,
              records.count + transientSessionCount < maxGlobalSessions
        else {
            throw SSHSessionManagerError.sessionLimitReached
        }
    }

    private func sessionStatuses(records: some Sequence<Record>) -> [SSHSessionStatus] {
        let currentTick = monotonicNow()
        let currentDate = now()
        return records
            .sorted { $0.createdAt < $1.createdAt }
            .map { record in
                let elapsed = currentTick >= record.lastUsedTick
                    ? TimeInterval(currentTick - record.lastUsedTick) / 1_000_000_000
                    : 0
                let wallElapsed = max(0, currentDate.timeIntervalSince(record.lastUsedAt))
                return SSHSessionStatus(
                    sessionID: record.id,
                    host: record.scope.host,
                    port: record.scope.port,
                    status: .active,
                    idleExpiresIn: max(0, idleTTL.timeInterval - max(elapsed, wallElapsed))
                )
            }
    }

    private func checkControl(_ record: Record) async -> Bool {
        do {
            let result = try await processRunner.run(
                ProcessInvocation(
                    executable: "/usr/bin/ssh",
                    arguments: [
                        "-S", record.controlPath,
                        "-O", "check",
                        "-p", String(record.scope.port),
                        "--",
                        "\(record.scope.username)@\(record.scope.host)"
                    ]
                ),
                stdin: Data(),
                timeout: .seconds(5),
                outputLimitBytes: 4_096
            )
            return result.exitCode == 0
        } catch {
            return false
        }
    }

    private func closeRecord(_ record: Record) async {
        records.removeValue(forKey: record.id)
        if record.state == .active || record.state == .draining {
            await closeControl(record)
        } else {
            removeControlPath(record.controlPath)
        }
    }

    private func closeControl(_ record: Record) async {
        _ = try? await processRunner.run(
            ProcessInvocation(
                executable: "/usr/bin/ssh",
                arguments: [
                    "-S", record.controlPath,
                    "-O", "exit",
                    "-p", String(record.scope.port),
                    "--",
                    "\(record.scope.username)@\(record.scope.host)"
                ]
            ),
            stdin: Data(),
            timeout: .seconds(5),
            outputLimitBytes: 4_096
        )
        removeControlPath(record.controlPath)
    }

    private func isExpired(_ record: Record) -> Bool {
        guard record.inFlightCount == 0 else { return false }
        let tick = monotonicNow()
        let idleExpired = tick >= record.lastUsedTick && tick - record.lastUsedTick >= idleNanoseconds
        let absoluteExpired = tick >= record.createdTick && tick - record.createdTick >= absoluteNanoseconds
        return idleExpired || absoluteExpired
    }

    /// Keep the default Unix-domain socket parent short enough for OpenSSH's
    /// temporary listener suffix on Darwin. This directory is private to the
    /// current user and is not a credential or configuration store.
    static func defaultSessionDirectory(for homeDirectory: URL) -> URL {
        homeDirectory.appendingPathComponent(".svlt/ssh", isDirectory: true)
    }

    private func makeControlPath() throws -> String {
        try ensureSessionDirectory()
        let path = sessionDirectory.appendingPathComponent(
            "s-\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased().prefix(24))",
            isDirectory: false
        ).path
        guard path.utf8.count < Self.maxControlPathBytes else {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }
        // A path collision is extraordinarily unlikely, but never reuse or
        // follow an existing path. The SSH process must create the socket.
        var info = stat()
        guard lstat(path, &info) != 0, errno == ENOENT else {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }
        return path
    }

    private func ensureSessionDirectory() throws {
        let fileManager = FileManager.default
        let pathComponents = sessionDirectory.pathComponents
        guard pathComponents.first == "/" else {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }

        // Create one component at a time. FileManager's recursive directory
        // creation can follow a symlink inserted into a missing tail between
        // the preflight and the final validation. A component-by-component
        // mkdir plus lstat keeps the private control-socket parent fail-closed
        // at every boundary.
        var current = URL(fileURLWithPath: "/", isDirectory: true)
        for component in pathComponents.dropFirst() {
            current.appendPathComponent(component, isDirectory: true)
            var info = stat()
            if lstat(current.path, &info) == 0 {
                guard (info.st_mode & S_IFMT) == S_IFDIR,
                      info.st_uid == geteuid() || info.st_uid == 0,
                      (info.st_mode & 0o022) == 0
                else {
                    throw SSHSessionManagerError.controlDirectoryUnavailable
                }
                continue
            }

            guard errno == ENOENT else {
                throw SSHSessionManagerError.controlDirectoryUnavailable
            }
            do {
                try fileManager.createDirectory(
                    at: current,
                    withIntermediateDirectories: false,
                    attributes: [.posixPermissions: 0o700]
                )
            } catch {
                // Another process may have created the component. Re-check
                // with lstat instead of accepting a raced symlink or file.
                var racedInfo = stat()
                guard lstat(current.path, &racedInfo) == 0 else {
                    throw SSHSessionManagerError.controlDirectoryUnavailable
                }
            }

            var createdInfo = stat()
            guard lstat(current.path, &createdInfo) == 0,
                  (createdInfo.st_mode & S_IFMT) == S_IFDIR,
                  createdInfo.st_uid == geteuid(),
                  (createdInfo.st_mode & 0o777) == 0o700
            else {
                throw SSHSessionManagerError.controlDirectoryUnavailable
            }
        }

        do {
            try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: sessionDirectory.path)
        } catch {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }
        try validateExistingParentChain()
        if !didCleanStaleControlPaths {
            didCleanStaleControlPaths = true
            cleanStaleControlPaths()
        }
    }

    /// Verify every existing path component without following symlinks. The
    /// final directory is owned by this user and is owner-only; ancestors may
    /// be root-owned system directories but must not be group/other writable.
    private func validateExistingParentChain() throws {
        let pathComponents = sessionDirectory.pathComponents
        guard pathComponents.first == "/" else {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }

        var current = URL(fileURLWithPath: "/", isDirectory: true)
        for component in pathComponents.dropFirst() {
            current.appendPathComponent(component, isDirectory: true)
            var info = stat()
            guard lstat(current.path, &info) == 0 else {
                throw SSHSessionManagerError.controlDirectoryUnavailable
            }
            guard (info.st_mode & S_IFMT) == S_IFDIR,
                  info.st_uid == geteuid() || info.st_uid == 0,
                  (info.st_mode & 0o022) == 0
            else {
                throw SSHSessionManagerError.controlDirectoryUnavailable
            }
        }

        var finalInfo = stat()
        guard lstat(sessionDirectory.path, &finalInfo) == 0,
              (finalInfo.st_mode & S_IFMT) == S_IFDIR,
              finalInfo.st_uid == geteuid(),
              (finalInfo.st_mode & 0o777) == 0o700
        else {
            throw SSHSessionManagerError.controlDirectoryUnavailable
        }
    }

    private func cleanStaleControlPaths() {
        guard let entries = try? FileManager.default.contentsOfDirectory(
            at: sessionDirectory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return
        }
        for entry in entries where entry.lastPathComponent.hasPrefix("s-") {
            removeControlPath(entry.path)
        }
    }

    private func removeControlPath(_ path: String) {
        var info = stat()
        guard lstat(path, &info) == 0,
              info.st_uid == geteuid(),
              ((info.st_mode & S_IFMT) == S_IFSOCK || (info.st_mode & S_IFMT) == S_IFREG)
        else {
            return
        }
        try? FileManager.default.removeItem(atPath: path)
    }

    private static func makeSessionID() -> String {
        "ssh_session_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased())"
    }

    private static func nanoseconds(for duration: Duration) -> UInt64 {
        let components = duration.components
        guard components.seconds >= 0 else { return 0 }
        let seconds = UInt64(components.seconds)
        let attoseconds = UInt64(max(0, components.attoseconds))
        return seconds &* 1_000_000_000 &+ attoseconds / 1_000_000_000
    }

    public static func defaultMonotonicNow() -> UInt64 {
        DispatchTime.now().uptimeNanoseconds
    }
}

private extension Duration {
    var timeInterval: TimeInterval {
        let components = components
        return TimeInterval(components.seconds)
            + TimeInterval(components.attoseconds) / 1_000_000_000_000_000_000
    }
}
