import Darwin
import Foundation
import Testing
@testable import VaultExecution

@Test func directRunnerDoesNotInvokeShellForMetacharacters() async throws {
    let runner = FoundationProcessRunner()
    let result = try await runner.run(
        ProcessInvocation(
            executable: "/usr/bin/printf",
            arguments: ["%s", "hello; echo injected"]
        ),
        stdin: Data(),
        timeout: .seconds(2),
        outputLimitBytes: 1_024
    )

    #expect(result.exitCode == 0)
    #expect(String(decoding: result.stdout, as: UTF8.self) == "hello; echo injected")
    #expect(result.stderr.isEmpty)
}

@Test func directRunnerDoesNotExpandEnvironmentVariablesThroughShell() async throws {
    let runner = FoundationProcessRunner()
    let result = try await runner.run(
        ProcessInvocation(
            executable: "/usr/bin/env",
            arguments: ["/usr/bin/printf", "%s", "$HOME"]
        ),
        stdin: Data(),
        timeout: .seconds(2),
        outputLimitBytes: 1_024
    )

    #expect(result.exitCode == 0)
    #expect(String(decoding: result.stdout, as: UTF8.self) == "$HOME")
    #expect(result.stderr.isEmpty)
}

@Test func timeoutTerminatesLongRunningProcess() async throws {
    let runner = FoundationProcessRunner()

    await expectRunError(.timedOut) {
        _ = try await runner.run(
            ProcessInvocation(executable: "/bin/sleep", arguments: ["5"]),
            stdin: Data(),
            timeout: .milliseconds(100),
            outputLimitBytes: 1_024
        )
    }
}

@Test func cancellationForcesDownProcessThatIgnoresTerm() async throws {
    let runner = FoundationProcessRunner()
    let clock = ContinuousClock()
    let startedAt = clock.now

    let task = Task {
        try await runner.run(
            ProcessInvocation(
                executable: "/bin/sh",
                arguments: ["-c", "trap '' TERM; while :; do :; done"]
            ),
            stdin: Data(),
            timeout: .seconds(30),
            outputLimitBytes: 1_024
        )
    }

    try await Task.sleep(for: .milliseconds(100))
    task.cancel()

    do {
        _ = try await task.value
        Issue.record("Cancelled process unexpectedly completed successfully.")
    } catch is CancellationError {
        // Expected. The stubborn child should be force-killed after the grace
        // window so the runner can finish the cancelled task.
    } catch {
        Issue.record("Expected CancellationError, but caught \(error).")
    }

    #expect(startedAt.duration(to: clock.now) < .seconds(4))
}

@Test func outputLargerThanLimitIsRejected() async throws {
    let runner = FoundationProcessRunner()

    await expectRunError(.outputLimitExceeded) {
        _ = try await runner.run(
            ProcessInvocation(executable: "/usr/bin/yes", arguments: ["x"]),
            stdin: Data(),
            timeout: .seconds(2),
            outputLimitBytes: 1_024
        )
    }
}

@Test func stdinIsClosedAfterSuppliedBytes() async throws {
    let runner = FoundationProcessRunner()
    let result = try await runner.run(
        ProcessInvocation(
            executable: "/usr/bin/env",
            arguments: ["/bin/cat"]
        ),
        stdin: Data("sealed input".utf8),
        timeout: .seconds(2),
        outputLimitBytes: 1_024
    )

    #expect(result.exitCode == 0)
    #expect(String(decoding: result.stdout, as: UTF8.self) == "sealed input")
    #expect(result.stderr.isEmpty)
}

@Test func processLaunchFailureIsDistinctFromStdinFailure() async throws {
    do {
        _ = try await FoundationProcessRunner().run(
            ProcessInvocation(
                executable: "/private/tmp/svlt-executable-that-does-not-exist",
                arguments: []
            ),
            stdin: Data(),
            timeout: .seconds(2),
            outputLimitBytes: 1_024
        )
        Issue.record("A missing executable unexpectedly launched.")
    } catch ProcessRunError.processLaunchFailed(let message) {
        #expect(!message.isEmpty)
    } catch {
        Issue.record("Unexpected process error: \(error)")
    }
}

@Test func sshKnownHostsStoreCreatesOwnerOnlyTrustState() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let store = SSHKnownHostsStore(directoryURL: root)
    let firstPath = try store.prepare()
    let secondPath = try store.prepare()

    #expect(firstPath == secondPath)
    #expect(firstPath == root.appendingPathComponent("known_hosts").path)

    var directoryStat = stat()
    #expect(root.path.withCString { lstat($0, &directoryStat) } == 0)
    #expect((directoryStat.st_mode & mode_t(0o777)) == mode_t(0o700))

    var fileStat = stat()
    #expect(firstPath.withCString { lstat($0, &fileStat) } == 0)
    #expect((fileStat.st_mode & S_IFMT) == S_IFREG)
    #expect((fileStat.st_mode & mode_t(0o777)) == mode_t(0o600))
    #expect(fileStat.st_uid == geteuid())
}

@Test func sshKnownHostsStoreRejectsSymlinkedKnownHostsFile() throws {
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-\(UUID().uuidString)", isDirectory: true)
    let target = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-target-\(UUID().uuidString)")
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: target)
    }

    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    _ = FileManager.default.createFile(atPath: target.path, contents: Data())
    try FileManager.default.createSymbolicLink(
        at: root.appendingPathComponent("known_hosts"),
        withDestinationURL: target
    )

    #expect(throws: SSHKnownHostsStoreError.unavailable) {
        _ = try SSHKnownHostsStore(directoryURL: root).prepare()
    }
}

private func expectRunError(
    _ expected: ProcessRunError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but process execution succeeded.")
    } catch let error as ProcessRunError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}
