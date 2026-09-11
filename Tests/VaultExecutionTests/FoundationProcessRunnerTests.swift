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
