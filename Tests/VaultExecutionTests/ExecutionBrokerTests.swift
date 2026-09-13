import Foundation
import Testing
import VaultAuthorization
import VaultCore
@testable import VaultExecution

@Test func validationPrecedesAuthorization() async throws {
    let trace = ExecutionTrace()
    let broker = ExecutionBroker(
        authorizer: RecordingAuthorizer(trace: trace, allowed: true),
        secretResolver: RecordingSecretResolver(trace: trace, secrets: [:]),
        processRunner: RecordingProcessRunner(trace: trace)
    )

    var request = validRequest()
    request.executable = "/usr/bin/env"

    await expectValidationError(.undeclaredExecutable) {
        _ = try await broker.validateAndExecute(request, against: validTemplate())
    }

    #expect(await trace.snapshot() == [])
}

@Test func genericExecutionRejectsSecretInjectionBeforeAuthorizationOrLaunch() async throws {
    let trace = ExecutionTrace()
    let broker = ExecutionBroker(
        authorizer: RecordingAuthorizer(trace: trace, allowed: true),
        secretResolver: RecordingSecretResolver(
            trace: trace,
            secrets: [try secretReference(): bytes("plain-token")]
        ),
        processRunner: RecordingProcessRunner(
            trace: trace,
            result: ProcessResult(
                exitCode: 0,
                stdout: bytes("ok plain-token"),
                stderr: Data()
            )
        )
    )

    await expectBrokerError(.secretInjectionNotAllowed) {
        _ = try await broker.execute(validatedExecution())
    }

    #expect(await trace.snapshot() == [])
}

@Test func cancellationPreventsProcessLaunch() async throws {
    let trace = ExecutionTrace()
    let runner = RecordingProcessRunner(trace: trace)
    let broker = ExecutionBroker(
        authorizer: DelayedAuthorizer(trace: trace),
        secretResolver: RecordingSecretResolver(
            trace: trace,
            secrets: [try secretReference(): bytes("plain-token")]
        ),
        processRunner: runner
    )

    let task = Task {
        try await broker.execute(validatedExecution())
    }
    task.cancel()

    do {
        _ = try await task.value
        Issue.record("Expected cancellation, but execution succeeded.")
    } catch is CancellationError {
        // Expected.
    } catch {
        Issue.record("Expected cancellation, but caught \(error).")
    }

    #expect(await runner.launchCount() == 0)
}

@Test func readAuthorizationCannotRunExternalSendTemplate() async throws {
    let session = AuthorizationSession()
    await session.authorizeRead()

    let trace = ExecutionTrace()
    let runner = RecordingProcessRunner(trace: trace)
    let broker = ExecutionBroker(
        authorizer: session,
        secretResolver: RecordingSecretResolver(
            trace: trace,
            secrets: [try secretReference(): bytes("plain-token")]
        ),
        processRunner: runner
    )

    await expectBrokerError(.secretInjectionNotAllowed) {
        _ = try await broker.execute(validatedExecution(risk: .writeOrExternalSend))
    }

    #expect(await runner.launchCount() == 0)
}

@Test func quarantinedOutputNeverBecomesCompletedResult() async throws {
    let trace = ExecutionTrace()
    let broker = ExecutionBroker(
        authorizer: RecordingAuthorizer(trace: trace, allowed: true),
        secretResolver: RecordingSecretResolver(
            trace: trace,
            secrets: [try secretReference(): bytes("plain-token")]
        ),
        processRunner: RecordingProcessRunner(
            trace: trace,
            result: ProcessResult(
                exitCode: 0,
                stdout: Data([0x41, 0x00, 0x42]),
                stderr: Data()
            )
        )
    )

    await expectBrokerError(.secretInjectionNotAllowed) {
        _ = try await broker.execute(validatedExecution())
    }
}

private actor ExecutionTrace {
    private var events: [String] = []

    func append(_ event: String) {
        events.append(event)
    }

    func snapshot() -> [String] {
        events
    }
}

private struct RecordingAuthorizer: ExecutionAuthorizing {
    let trace: ExecutionTrace
    let allowed: Bool

    func consumeAuthorization(for risk: RiskClass) async -> Bool {
        await trace.append("authorize:\(risk.eventName)")
        return allowed
    }
}

private struct DelayedAuthorizer: ExecutionAuthorizing {
    let trace: ExecutionTrace

    func consumeAuthorization(for risk: RiskClass) async -> Bool {
        await trace.append("authorize:\(risk.eventName)")
        try? await Task.sleep(for: .milliseconds(100))
        return true
    }
}

private struct RecordingSecretResolver: SecretResolving {
    let trace: ExecutionTrace
    let secrets: [SecretReference: Data]

    func resolve(_ reference: SecretReference, named name: String) async throws -> Data {
        await trace.append("resolve:\(name)")
        return secrets[reference] ?? Data()
    }
}

private actor ProcessLaunches {
    private var count = 0

    func increment() {
        count += 1
    }

    func snapshot() -> Int {
        count
    }
}

private struct RecordingProcessRunner: ProcessRunning {
    let trace: ExecutionTrace
    let launches = ProcessLaunches()
    var result = ProcessResult(exitCode: 0, stdout: bytes("ok"), stderr: Data())

    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration?,
        outputLimitBytes: Int
    ) async throws -> ProcessResult {
        await launches.increment()
        await trace.append("run:\(([invocation.executable] + invocation.arguments).joined(separator: "|"))")
        return result
    }

    func launchCount() async -> Int {
        await launches.snapshot()
    }
}

private func expectBrokerError(
    _ expected: ExecutionBrokerError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but execution succeeded.")
    } catch let error as ExecutionBrokerError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private func expectValidationError(
    _ expected: TemplateValidationError,
    performing operation: () async throws -> Void
) async {
    do {
        try await operation()
        Issue.record("Expected \(expected), but validation succeeded.")
    } catch let error as TemplateValidationError {
        #expect(error == expected)
    } catch {
        Issue.record("Expected \(expected), but caught \(error).")
    }
}

private func validTemplate() -> ExecutionTemplate {
    ExecutionTemplate(
        id: "send-message",
        executable: "/usr/bin/printf",
        arguments: [
            .literal("--token"),
            .secret(name: "apiToken"),
            .value(name: "message")
        ],
        risk: .writeOrExternalSend,
        allowedHosts: ["api.example.com"],
        allowedPaths: ["/v1/send"]
    )
}

private func validRequest() -> ExecutionRequest {
    ExecutionRequest(
        templateID: "send-message",
        executable: "/usr/bin/printf",
        values: ["message": "hello"],
        secrets: ["apiToken": try! secretReference()],
        destinationHost: "api.example.com",
        destinationPath: "/v1/send",
        requestedRisk: .writeOrExternalSend
    )
}

private func validatedExecution(
    risk: RiskClass = .writeOrExternalSend
) throws -> ValidatedExecution {
    ValidatedExecution(
        templateID: "send-message",
        executable: "/usr/bin/printf",
        arguments: [
            .literal("--token"),
            .secret(name: "apiToken", reference: try secretReference()),
            .value(name: "message", value: "hello")
        ],
        risk: risk,
        destinationHost: "api.example.com",
        destinationPath: "/v1/send"
    )
}

private func secretReference() throws -> SecretReference {
    try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
}

private func bytes(_ value: String) -> Data {
    Data(value.utf8)
}

private extension RiskClass {
    var eventName: String {
        switch self {
        case .read:
            return "read"
        case .writeOrExternalSend:
            return "writeOrExternalSend"
        case .deleteOrCredentialChange:
            return "deleteOrCredentialChange"
        }
    }
}
