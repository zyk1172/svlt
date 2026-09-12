import Foundation
import Testing
@testable import VaultExecution

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
