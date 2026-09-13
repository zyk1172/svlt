import Foundation
import Testing
import VaultCore
@testable import VaultExecution

@Test func SSHSessionManagerDefaultControlPathAllowsOpenSSHTemporarySuffix() {
    let sessionDirectory = SSHSessionManager.defaultSessionDirectory(
        for: URL(fileURLWithPath: "/Users/tester")
    )
    let controlPath = sessionDirectory.appendingPathComponent(
        "s-\(String(repeating: "a", count: 24)).\(String(repeating: "a", count: 16))"
    ).path

    #expect(sessionDirectory.path.hasSuffix("/.svlt/ssh"))
    #expect(controlPath.utf8.count < 103)
}

@Test func SSHSessionManagerReusesOnlyTheExactTransportScope() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let runner = SessionProcessRunner()
    let manager = SSHSessionManager(
        processRunner: runner,
        sessionDirectory: root.appendingPathComponent("sessions", isDirectory: true)
    )
    let scope = sessionScope()
    let firstFlags = CallFlags()
    let first = try await manager.execute(scope: scope) { access in
        await firstFlags.append(requiresAuthentication: access.requiresAuthentication, controlPath: access.controlPath)
        return SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data("first".utf8), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }

    let secondFlags = CallFlags()
    let second = try await manager.execute(scope: scope) { access in
        await secondFlags.append(requiresAuthentication: access.requiresAuthentication, controlPath: access.controlPath)
        return SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data("second".utf8), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }

    #expect(first.sessionID != nil)
    #expect(first.masterReady)
    #expect(second.sessionID == first.sessionID)
    #expect(second.masterReady)
    #expect(await firstFlags.requiresAuthentication == true)
    #expect(await secondFlags.requiresAuthentication == false)
    #expect(await firstFlags.controlPath?.contains("nas.local") == false)
    #expect(await firstFlags.controlPath?.contains("admin") == false)
    #expect(await firstFlags.controlPath?.contains(scope.passwordReferenceID) == false)
    #expect(first.sessionID?.hasPrefix("ssh_session_") == true)
    #expect(first.sessionID?.contains(scope.passwordReferenceID) == false)

    let invocations = await runner.invocations
    // The initial publish is gated by a health check, and the second command
    // performs its own health check before reusing the master.
    #expect(invocations.filter { $0.arguments.contains("check") }.count == 2)
    #expect(await manager.statuses(for: scope.principal).count == 1)
}

@Test func SSHSessionManagerDoesNotReuseAcrossHostUserSecretPrincipalOrGeneration() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let manager = SSHSessionManager(
        processRunner: SessionProcessRunner(),
        sessionDirectory: root
    )

    let original = sessionScope()
    let first = try await open(manager: manager, scope: original)
    let variations = [
        SSHSessionScope(principal: "other-process", host: original.host, port: original.port, username: original.username, passwordReferenceID: original.passwordReferenceID, securityGeneration: original.securityGeneration),
        SSHSessionScope(principal: original.principal, host: "other.local", port: original.port, username: original.username, passwordReferenceID: original.passwordReferenceID, securityGeneration: original.securityGeneration),
        SSHSessionScope(principal: original.principal, host: original.host, port: 2222, username: original.username, passwordReferenceID: original.passwordReferenceID, securityGeneration: original.securityGeneration),
        SSHSessionScope(principal: original.principal, host: original.host, port: original.port, username: "other-user", passwordReferenceID: original.passwordReferenceID, securityGeneration: original.securityGeneration),
        SSHSessionScope(principal: original.principal, host: original.host, port: original.port, username: original.username, passwordReferenceID: "secret://0123456789ABCDEFGHJKMNPQRT", securityGeneration: original.securityGeneration),
        SSHSessionScope(principal: original.principal, host: original.host, port: original.port, username: original.username, passwordReferenceID: original.passwordReferenceID, securityGeneration: original.securityGeneration + 1)
    ]

    for variation in variations {
        let result = try await open(manager: manager, scope: variation)
        #expect(result.sessionID != first.sessionID)
    }

    #expect(await manager.statuses(for: original.principal).count == 6)
    #expect(await manager.statuses(for: "other-process").count == 1)
}

@Test func SSHSessionManagerExpiresIdleAndAbsoluteSessionsUsingMonotonicTime() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let clock = SessionTestClock()
    let manager = SSHSessionManager(
        processRunner: SessionProcessRunner(),
        sessionDirectory: root,
        idleTTL: .seconds(5),
        absoluteTTL: .seconds(20),
        now: { clock.date },
        monotonicNow: { clock.tick }
    )
    let scope = sessionScope()
    let first = try await open(manager: manager, scope: scope)

    clock.tick += 4_999_000_000
    #expect(await manager.statuses(for: scope.principal).count == 1)
    clock.date = clock.date.addingTimeInterval(3_600)
    #expect(await manager.statuses(for: scope.principal).count == 1)

    clock.tick += 1_000_000
    #expect(await manager.statuses(for: scope.principal).isEmpty)

    let second = try await open(manager: manager, scope: scope)
    #expect(second.sessionID != first.sessionID)
    clock.tick += 20_000_000_000
    #expect(await manager.statuses(for: scope.principal).isEmpty)
}

@Test func SSHSessionManagerCleansStaleSocketsAndPendingOpenFailures() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let sessionDirectory = root.appendingPathComponent("sessions", isDirectory: true)
    try FileManager.default.createDirectory(at: sessionDirectory, withIntermediateDirectories: true)
    try Data("stale".utf8).write(to: sessionDirectory.appendingPathComponent("s-stale"))

    let runner = SessionProcessRunner()
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: sessionDirectory)
    let failed = try await manager.execute(scope: sessionScope()) { _ in
        SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 124, stdout: Data(), stderr: Data()),
            channelState: .transportFailed
        )
    }

    #expect(failed.sessionID == nil)
    #expect(!FileManager.default.fileExists(atPath: sessionDirectory.appendingPathComponent("s-stale").path))
    #expect(await manager.statuses(for: "agent-process").isEmpty)
    #expect(await runner.invocations.contains { $0.arguments.contains("exit") } == false)
}

@Test func SSHSessionManagerReturnsTheRealCommandResultWhenMasterHealthCheckFails() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let runner = SessionProcessRunner(checkExitCode: 1)
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: root)

    // §8: the ControlMaster is a reuse optimization, never a precondition.
    // The remote command already ran, so its real result is returned with
    // sessionID = nil; no error is raised and no session is published.
    let execution = try await manager.execute(scope: sessionScope()) { _ in
        SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data("command ran".utf8), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }

    #expect(execution.processResult.stdout == Data("command ran".utf8))
    #expect(execution.sessionID == nil)
    #expect(!execution.masterReady)
    #expect(await manager.statuses(for: "agent-process").isEmpty)
    let invocations = await runner.invocations
    #expect(invocations.contains { $0.arguments.contains("check") })
    #expect(invocations.contains { $0.arguments.contains("exit") })
}

@Test func SSHSessionManagerRejectsAnUnprovenZeroAndNeverPublishesItsSession() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let runner = SessionProcessRunner()
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: root)

    let execution = try await manager.execute(scope: sessionScope()) { _ in
        // A process exit of zero is not enough evidence for a remote command.
        // This models a wrapper that returned zero without reaching its
        // completion protocol marker.
        SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
            channelState: .wrapperFailed
        )
    }

    #expect(execution.processResult.exitCode == 0)
    #expect(execution.channelState == .wrapperFailed)
    #expect(!execution.masterReady)
    #expect(execution.sessionID == nil)
    let invocations = await runner.invocations
    #expect(invocations.contains { $0.arguments.contains("check") } == false)
    #expect(invocations.contains { $0.arguments.contains("exit") } == false)
    #expect(await manager.statuses(for: sessionScope().principal).isEmpty)
}

@Test func SSHSessionManagerRejectsAnUnprovenZeroOnAnExistingSession() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let runner = SessionProcessRunner()
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: root)
    let scope = sessionScope()
    let opened = try await open(manager: manager, scope: scope)
    let sessionID = try #require(opened.sessionID)

    let execution = try await manager.execute(scope: scope, requestedSessionID: sessionID) { _ in
        SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
            channelState: .transportFailed
        )
    }

    #expect(execution.processResult.exitCode == 0)
    #expect(execution.channelState == .transportFailed)
    #expect(!execution.masterReady)
    #expect(execution.sessionID == nil)
    #expect(await manager.statuses(for: scope.principal).isEmpty)
}

@Test func SSHSessionManagerRejectsAControlPathThatExceedsTheUnixSocketLimit() async throws {
    let root = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(String(repeating: "x", count: 80), isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let manager = SSHSessionManager(processRunner: SessionProcessRunner(), sessionDirectory: root)

    do {
        _ = try await manager.execute(scope: sessionScope()) { _ in
            return SSHSessionCommandExecution(
                processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
                channelState: .remoteCommandCompleted
            )
        }
        Issue.record("An overlong ControlPath was accepted.")
    } catch SSHSessionManagerError.controlDirectoryUnavailable {
        // Expected: the full path, not just the random filename, is bounded.
    }
}

@Test func SSHSessionManagerReconnectsAConcurrentWaiterWhenMasterHealthCheckFails() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let checkGate = SessionCheckGate()
    let runner = SessionProcessRunner(checkExitCode: 1, checkGate: checkGate)
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: root)
    let accesses = ConcurrentAccessFlags()
    let scope = sessionScope()

    let firstTask = Task {
        try await manager.execute(scope: scope) { access in
            await accesses.append("first", requiresAuthentication: access.requiresAuthentication)
            return SSHSessionCommandExecution(
                processResult: ProcessResult(exitCode: 0, stdout: Data("first command".utf8), stderr: Data()),
                channelState: .remoteCommandCompleted
            )
        }
    }

    // Hold the initial health check open so the second request joins the same
    // opening flight. The master then fails to persist, which used to make the
    // waiter throw SESSION_CONTROL_UNAVAILABLE.
    await checkGate.waitForFirstCheck()
    let secondTask = Task {
        try await manager.execute(scope: scope) { access in
            await accesses.append("second", requiresAuthentication: access.requiresAuthentication)
            return SSHSessionCommandExecution(
                processResult: ProcessResult(exitCode: 0, stdout: Data("second command".utf8), stderr: Data()),
                channelState: .remoteCommandCompleted
            )
        }
    }
    for _ in 0..<20 {
        await Task.yield()
    }
    await checkGate.releaseFirstCheck()

    let first = try await firstTask.value
    let second = try await secondTask.value

    #expect(first.processResult.stdout == Data("first command".utf8))
    #expect(second.processResult.stdout == Data("second command".utf8))
    #expect(first.sessionID == nil)
    #expect(second.sessionID == nil)
    #expect(!first.masterReady)
    #expect(!second.masterReady)
    #expect(await accesses.value(for: "first") == true)
    // The waiter reconnects as a normal first-channel operation instead of
    // assuming an unavailable ControlMaster was a failed command.
    #expect(await accesses.value(for: "second") == true)
}

@Test func SSHSessionManagerReconnectsWhenAnExplicitSessionHandleIsDead() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    // The first master is healthy, the explicit handle then fails its health
    // check, and the replacement master is healthy again.
    let runner = SessionProcessRunner(checkExitCodes: [0, 1, 0])
    let manager = SSHSessionManager(processRunner: runner, sessionDirectory: root)
    let scope = sessionScope()

    let firstAccess = CallFlags()
    let first = try await manager.execute(scope: scope) { access in
        await firstAccess.append(requiresAuthentication: access.requiresAuthentication, controlPath: access.controlPath)
        return SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data("first".utf8), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }
    let sessionID = try #require(first.sessionID)

    let secondAccess = CallFlags()
    let second = try await manager.execute(scope: scope, requestedSessionID: sessionID) { access in
        await secondAccess.append(requiresAuthentication: access.requiresAuthentication, controlPath: access.controlPath)
        return SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data("reconnected".utf8), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }

    #expect(first.processResult.stdout == Data("first".utf8))
    #expect(second.processResult.stdout == Data("reconnected".utf8))
    #expect(second.sessionID != sessionID)
    #expect(first.masterReady)
    #expect(second.masterReady)
    #expect(await firstAccess.requiresAuthentication == true)
    #expect(await secondAccess.requiresAuthentication == true)
    #expect(await runner.invocations.filter { $0.arguments.contains("check") }.count == 3)
}

@Test func SSHSessionManagerRejectsRequestedScopeMismatchAndEnforcesLimits() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let manager = SSHSessionManager(
        processRunner: SessionProcessRunner(),
        sessionDirectory: root,
        maxSessionsPerPrincipal: 1
    )
    let firstScope = sessionScope()
    let first = try await open(manager: manager, scope: firstScope)
    let otherScope = SSHSessionScope(
        principal: firstScope.principal,
        host: "other.local",
        port: firstScope.port,
        username: firstScope.username,
        passwordReferenceID: firstScope.passwordReferenceID,
        securityGeneration: firstScope.securityGeneration
    )

    do {
        _ = try await manager.execute(scope: otherScope) { _ in
            SSHSessionCommandExecution(
                processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
                channelState: .remoteCommandCompleted
            )
        }
        Issue.record("The per-principal session limit was not enforced.")
    } catch SSHSessionManagerError.sessionLimitReached {
        // Expected.
    } catch {
        Issue.record("Unexpected limit error: \(error)")
    }

    do {
        _ = try await manager.execute(scope: otherScope, requestedSessionID: first.sessionID) { _ in
            SSHSessionCommandExecution(
                processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
                channelState: .remoteCommandCompleted
            )
        }
        Issue.record("A session was reused across scopes.")
    } catch SSHSessionManagerError.scopeMismatch {
        // Expected.
    } catch {
        Issue.record("Unexpected scope error: \(error)")
    }
}

@Test func SSHSessionManagerProjectsStatusAndGuardsCloseByPrincipalAndGeneration() async throws {
    let root = try makeTemporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let manager = SSHSessionManager(
        processRunner: SessionProcessRunner(),
        sessionDirectory: root,
        idleTTL: .seconds(300)
    )
    let scope = sessionScope()
    let opened = try await open(manager: manager, scope: scope)
    let sessionID = try #require(opened.sessionID)

    let status = try await manager.status(
        sessionID: sessionID,
        principal: scope.principal,
        securityGeneration: scope.securityGeneration
    )
    #expect(status.sessionID == sessionID)
    #expect(status.host == scope.host)
    #expect(status.port == scope.port)
    #expect(status.status == .active)
    #expect(status.idleExpiresIn <= 300)

    do {
        _ = try await manager.status(
            sessionID: sessionID,
            principal: "other-process",
            securityGeneration: scope.securityGeneration
        )
        Issue.record("A different process was able to inspect the session.")
    } catch SSHSessionManagerError.scopeMismatch {
        // Expected.
    }

    do {
        try await manager.close(
            sessionID: sessionID,
            principal: "other-process",
            securityGeneration: scope.securityGeneration
        )
        Issue.record("A different process was able to close the session.")
    } catch SSHSessionManagerError.scopeMismatch {
        // Expected.
    }

    try await manager.close(
        sessionID: sessionID,
        principal: scope.principal,
        securityGeneration: scope.securityGeneration
    )
    #expect(await manager.statuses(for: scope.principal).isEmpty)
}

private func open(
    manager: SSHSessionManager,
    scope: SSHSessionScope
) async throws -> SSHSessionCommandExecution {
    try await manager.execute(scope: scope) { _ in
        SSHSessionCommandExecution(
            processResult: ProcessResult(exitCode: 0, stdout: Data(), stderr: Data()),
            channelState: .remoteCommandCompleted
        )
    }
}

private func sessionScope() -> SSHSessionScope {
    SSHSessionScope(
        principal: "agent-process",
        host: "nas.local",
        port: 22,
        username: "admin",
        passwordReferenceID: "secret://0123456789ABCDEFGHJKMNPQRS",
        securityGeneration: 7
    )
}

private func makeTemporaryDirectory() throws -> URL {
    // SSHSessionManager intentionally rejects symlinked parent components;
    // macOS's temporary directory is commonly reached through /var, which is
    // a symlink on this platform. Keep the test under the user's private home
    // hierarchy and keep the generated path short enough for sockaddr_un.
    let directory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".svlt-test-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
}

private actor SessionProcessRunner: ProcessRunning {
    private(set) var invocations: [ProcessInvocation] = []
    let checkExitCode: Int32
    private var checkExitCodes: [Int32]
    let checkGate: SessionCheckGate?

    init(
        checkExitCode: Int32 = 0,
        checkExitCodes: [Int32] = [],
        checkGate: SessionCheckGate? = nil
    ) {
        self.checkExitCode = checkExitCode
        self.checkExitCodes = checkExitCodes
        self.checkGate = checkGate
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin _: Data,
        timeout _: Duration?,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        invocations.append(invocation)
        if invocation.arguments.contains("check") {
            await checkGate?.waitAtFirstCheck()
            let exitCode = checkExitCodes.isEmpty ? checkExitCode : checkExitCodes.removeFirst()
            return ProcessResult(exitCode: exitCode, stdout: Data(), stderr: Data())
        }
        return ProcessResult(exitCode: 0, stdout: Data(), stderr: Data())
    }
}

private actor SessionCheckGate {
    private var firstCheckObserved = false
    private var released = false
    private var firstCheckContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func waitAtFirstCheck() async {
        guard !firstCheckObserved else { return }
        firstCheckObserved = true
        firstCheckContinuation?.resume()
        firstCheckContinuation = nil
        guard !released else { return }
        await withCheckedContinuation { continuation in
            releaseContinuation = continuation
        }
    }

    func waitForFirstCheck() async {
        guard !firstCheckObserved else { return }
        await withCheckedContinuation { continuation in
            firstCheckContinuation = continuation
        }
    }

    func releaseFirstCheck() {
        released = true
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

private actor ConcurrentAccessFlags {
    private var values: [String: Bool] = [:]

    func append(_ name: String, requiresAuthentication: Bool) {
        values[name] = requiresAuthentication
    }

    func value(for name: String) -> Bool? {
        values[name]
    }
}

private actor CallFlags {
    private(set) var requiresAuthentication: Bool?
    private(set) var controlPath: String?

    func append(requiresAuthentication: Bool, controlPath: String) {
        self.requiresAuthentication = requiresAuthentication
        self.controlPath = controlPath
    }
}

private final class SessionTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var storedDate = Date(timeIntervalSinceReferenceDate: 1_000)
    private var storedTick: UInt64 = 10_000_000_000

    var date: Date {
        get { lock.withLock { storedDate } }
        set { lock.withLock { storedDate = newValue } }
    }

    var tick: UInt64 {
        get { lock.withLock { storedTick } }
        set { lock.withLock { storedTick = newValue } }
    }
}
