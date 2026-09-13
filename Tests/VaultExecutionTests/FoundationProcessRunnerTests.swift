import CryptoKit
import Darwin
import Foundation
import Testing
import VaultCore
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

@Test func sshHostKeyDiscoveryUsesKeyscanAndExposesOnlyFingerprintMetadata() async throws {
    let material = makeTestSSHHostKeyMaterial()
    let runner = HostKeyCapturingProcessRunner(
        result: ProcessResult(
            exitCode: 0,
            stdout: Data("nas.local ssh-ed25519 \(material.publicKeyBase64)\n".utf8),
            stderr: Data()
        )
    )
    let discovery = SSHHostKeyDiscovery(
        processRunner: runner,
        timeout: .seconds(5)
    )

    let review = try await discovery.review(host: "nas.local", port: 2222)

    #expect(review == SSHHostKeyReview(host: "nas.local", port: 2222, pins: [material.pin]))
    #expect(String(describing: review).contains(material.publicKeyBase64) == false)
    #expect(await runner.capturedInvocation() == ProcessInvocation(
        executable: "/usr/bin/ssh-keyscan",
        arguments: ["-T", "5", "-p", "2222", "--", "nas.local"]
    ))
    #expect(await runner.capturedStdin().isEmpty)
}

@Test func sshHostKeyDiscoveryInstallsAndValidatesAnOwnerSelectedProfile() async throws {
    let material = makeTestSSHHostKeyMaterial()
    let runner = HostKeyCapturingProcessRunner(
        result: ProcessResult(
            exitCode: 0,
            stdout: Data("nas.local ssh-ed25519 \(material.publicKeyBase64)\n".utf8),
            stderr: Data()
        )
    )
    let root = FileManager.default.temporaryDirectory
        .appendingPathComponent("svlt-known-hosts-pin-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: root) }

    let store = SSHKnownHostsStore(directoryURL: root)
    try await SSHHostKeyDiscovery(processRunner: runner).install(
        host: "nas.local",
        port: 2222,
        pin: material.pin,
        into: store
    )

    let path = try store.validatedPinnedPath(
        host: "nas.local",
        port: 2222,
        pin: material.pin
    )
    #expect(path.hasSuffix(".known_hosts"))
    #expect(String(data: try Data(contentsOf: URL(fileURLWithPath: path)), encoding: .utf8)
        == "[nas.local]:2222 ssh-ed25519 \(material.publicKeyBase64)\n")

    var pinsDirectoryStat = stat()
    let pinsDirectory = root.appendingPathComponent("pins", isDirectory: true)
    #expect(pinsDirectory.path.withCString { lstat($0, &pinsDirectoryStat) } == 0)
    #expect((pinsDirectoryStat.st_mode & S_IFMT) == S_IFDIR)
    #expect((pinsDirectoryStat.st_mode & mode_t(0o777)) == mode_t(0o700))

    var profileStat = stat()
    #expect(path.withCString { lstat($0, &profileStat) } == 0)
    #expect((profileStat.st_mode & S_IFMT) == S_IFREG)
    #expect((profileStat.st_mode & mode_t(0o777)) == mode_t(0o600))

    let wrongPin = try SSHHostKeyPin(
        algorithm: material.pin.algorithm,
        sha256: testSSHFingerprint(Data(repeating: 0xA5, count: 32))
    )
    #expect(throws: SSHKnownHostsStoreError.unavailable) {
        _ = try store.validatedPinnedPath(host: "nas.local", port: 2222, pin: wrongPin)
    }
}

private struct TestSSHHostKeyMaterial {
    let publicKeyBase64: String
    let pin: SSHHostKeyPin
}

private func makeTestSSHHostKeyMaterial() -> TestSSHHostKeyMaterial {
    var keyData = Data()
    keyData.append(contentsOf: [0, 0, 0, 11])
    keyData.append(contentsOf: Data("ssh-ed25519".utf8))
    keyData.append(contentsOf: [0, 0, 0, 32])
    keyData.append(contentsOf: (1...32).map { UInt8($0) })
    let publicKeyBase64 = keyData.base64EncodedString()
    let pin = try! SSHHostKeyPin(
        algorithm: "ssh-ed25519",
        sha256: testSSHFingerprint(keyData)
    )
    return TestSSHHostKeyMaterial(publicKeyBase64: publicKeyBase64, pin: pin)
}

private func testSSHFingerprint(_ keyData: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: keyData))
        .base64EncodedString()
        .replacingOccurrences(of: "=", with: "")
}

private actor HostKeyCapturingProcessRunner: ProcessRunning {
    private let result: ProcessResult
    private var invocation: ProcessInvocation?
    private var receivedStdin = Data()

    init(result: ProcessResult) {
        self.result = result
    }

    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout _: Duration?,
        outputLimitBytes _: Int
    ) async throws -> ProcessResult {
        self.invocation = invocation
        receivedStdin = stdin
        return result
    }

    func capturedInvocation() -> ProcessInvocation? {
        invocation
    }

    func capturedStdin() -> Data {
        receivedStdin
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

@Test func completedProcessCannotBeReclassifiedByLateTimeoutOrCancellation() {
    let state = FoundationProcessRunState()

    _ = state.markProcessExited()
    state.markTimedOutAndTerminate()
    state.markCancelledAndTerminate()

    #expect(state.finalizeProcessExit(outputLimitExceeded: false) == .completed)
}

@Test func outputLimitDiscoveredDuringFinalDrainOverridesProvisionalExit() {
    let state = FoundationProcessRunState()

    _ = state.markProcessExited()
    state.markOutputLimitExceededAndTerminate()

    #expect(state.finalizeProcessExit(outputLimitExceeded: true) == .outputLimitExceeded)
}

@Test func processRunnerReturnsWithoutWaitingForDescendantHoldingPipeOpen() async throws {
    let clock = ContinuousClock()
    let startedAt = clock.now

    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/bin/sh",
            arguments: ["-c", "/bin/sleep 2 & /usr/bin/printf done"]
        ),
        stdin: Data(),
        timeout: .seconds(5),
        outputLimitBytes: 1_024
    )

    #expect(result.exitCode == 0)
    #expect(String(decoding: result.stdout, as: UTF8.self) == "done")
    #expect(startedAt.duration(to: clock.now) < .seconds(1))
}

@Test func processRunnerAcceptsOutputExactlyAtLimit() async throws {
    let payload = String(repeating: "x", count: 1_024)

    let result = try await FoundationProcessRunner().run(
        ProcessInvocation(
            executable: "/usr/bin/printf",
            arguments: ["%s", payload]
        ),
        stdin: Data(),
        timeout: .seconds(2),
        outputLimitBytes: 1_024
    )

    #expect(result.exitCode == 0)
    #expect(result.stdout.count == 1_024)
}

@Test func processRunnerRejectsOutputThatCrossesLimitAtExit() async throws {
    let payload = String(repeating: "x", count: 1_025)

    do {
        _ = try await FoundationProcessRunner().run(
            ProcessInvocation(
                executable: "/usr/bin/printf",
                arguments: ["%s", payload]
            ),
            stdin: Data(),
            timeout: .seconds(2),
            outputLimitBytes: 1_024
        )
        Issue.record("Output above the configured limit unexpectedly succeeded.")
    } catch let error as ProcessRunError {
        #expect(error == .outputLimitExceeded)
    } catch {
        Issue.record("Expected outputLimitExceeded, but caught \(error).")
    }
}
