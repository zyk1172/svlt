from pathlib import Path
import re


def contains(path, needle):
    return needle in Path(path).read_text()


def already_applied():
    return (
        contains(
            "Sources/VaultService/VaultAppServices.swift",
            "operationApprovalTimeout: Duration = .seconds(120),",
        )
        and contains(
            "Sources/VaultExecution/ProcessRunning.swift",
            "        timeout: Duration?,\n",
        )
        and contains(
            "Sources/VaultExecution/FoundationProcessRunner.swift",
            "let timeoutTask = timeout.map",
        )
        and contains(
            "Sources/VaultExecution/ExecutionBroker.swift",
            "        timeout: Duration? = nil,\n",
        )
        and not contains(
            "Sources/VaultExecution/SecretOperationExecutor.swift",
            "    private let timeout: Duration\n",
        )
        and contains(
            "Tests/VaultExecutionTests/SecretOperationExecutorTests.swift",
            "sshExecutorIgnoresLegacyDescriptorTimeoutAndUsesNoExecutionDeadline",
        )
        and contains(
            "Tests/VaultAuthorizationTests/SecretOperationServiceTests.swift",
            "longRunningOperationDoesNotBlockLaterOperation",
        )
        and not contains(
            "mcp-server/src/server.ts",
            "timeoutMs: z.number()",
        )
    )


if already_applied():
    print("unbounded execution refactor already applied")
    raise SystemExit(0)


def replace(path, old, new, count=1):
    p = Path(path)
    text = p.read_text()
    found = text.count(old)
    if found != count:
        raise SystemExit(f"{path}: expected {count} occurrences of {old!r}, found {found}")
    p.write_text(text.replace(old, new, count))


# Approval is an authorization window, not an execution deadline.
replace(
    "Sources/VaultService/VaultAppServices.swift",
    "operationApprovalTimeout: Duration = .seconds(30),",
    "operationApprovalTimeout: Duration = .seconds(120),",
    count=2,
)

# Process runners can explicitly opt out of a wall-clock deadline.
replace(
    "Sources/VaultExecution/ProcessRunning.swift",
    "        timeout: Duration,\n",
    "        timeout: Duration?,\n",
)
replace(
    "Sources/VaultExecution/FoundationProcessRunner.swift",
    "        timeout: Duration,\n",
    "        timeout: Duration?,\n",
)
replace(
    "Sources/VaultExecution/FoundationProcessRunner.swift",
    """                let timeoutTask = Task {
                    do {
                        try await Task.sleep(for: timeout)
                    } catch {
                        return
                    }

                    guard !Task.isCancelled else {
                        return
                    }
                    runState.markTimedOutAndTerminate()
                }
""",
    """                let timeoutTask = timeout.map { duration in
                    Task {
                        do {
                            try await Task.sleep(for: duration)
                        } catch {
                            return
                        }

                        guard !Task.isCancelled else {
                            return
                        }
                        runState.markTimedOutAndTerminate()
                    }
                }
""",
)
p = Path("Sources/VaultExecution/FoundationProcessRunner.swift")
text = p.read_text()
if text.count("timeoutTask.cancel()") != 3:
    raise SystemExit(f"FoundationProcessRunner timeout cancellation count changed: {text.count('timeoutTask.cancel()')}")
p.write_text(text.replace("timeoutTask.cancel()", "timeoutTask?.cancel()"))

# Generic broker defaults to unbounded execution while retaining opt-in timeout support.
replace("Sources/VaultExecution/ExecutionBroker.swift", "    private let timeout: Duration\n", "    private let timeout: Duration?\n")
replace("Sources/VaultExecution/ExecutionBroker.swift", "        timeout: Duration = .seconds(30),\n", "        timeout: Duration? = nil,\n")

# File transfer timeoutMs is legacy wire input only; it no longer limits execution.
replace(
    "Sources/VaultExecution/FileTransferAdapterSupport.swift",
    """    private static func timeout(from descriptor: SecretOperationDescriptor) throws -> Duration {
        guard let rawTimeout = descriptor.parameters["timeoutMs"] else {
            return .seconds(60)
        }
        guard let milliseconds = Int64(rawTimeout),
              (1_000...60_000).contains(milliseconds) else {
            throw FileTransferAdapterError.invalidParameter
        }
        return .milliseconds(milliseconds)
    }
""",
    """    private static func timeout(from _: SecretOperationDescriptor) throws -> Duration {
        // Legacy wire field retained for decoding compatibility only. File transfers
        // have no SVLT wall-clock execution deadline; cancellation remains explicit.
        .zero
    }
""",
)

# SFTP has no ProcessRunner deadline or OpenSSH connect deadline; Expect waits indefinitely.
replace(
    "Sources/VaultExecution/SFTPSecretOperationAdapter.swift",
    "                timeout: plan.timeout,\n",
    "                timeout: nil,\n",
)
replace(
    "Sources/VaultExecution/SFTPSecretOperationAdapter.swift",
    "        set timeout $timeoutSeconds\n",
    "        # Execution lifetime is controlled only by completion or explicit cancellation.\n        set timeout -1\n",
)
replace(
    "Sources/VaultExecution/SFTPSecretOperationAdapter.swift",
    "            -o ConnectTimeout=$timeoutSeconds \\\n",
    "",
)

# FTP stages no longer race against a timer. Cancellation is the lifecycle control.
p = Path("Sources/VaultExecution/FTPSecretOperationAdapter.swift")
text = p.read_text()
text = text.replace("withFTPTimeout(timeout)", "runFTPStage")
old_helper = """private func withFTPTimeout<T: Sendable>(
    _ duration: Duration,
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask(operation: operation)
        group.addTask {
            try await Task.sleep(for: duration)
            throw FTPClientError.timedOut
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw FTPClientError.timedOut
        }
        return result
    }
}
"""
new_helper = """private func runFTPStage<T: Sendable>(
    operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    try Task.checkCancellation()
    return try await operation()
}
"""
if old_helper not in text:
    raise SystemExit("FTP timeout helper shape changed")
text = text.replace(old_helper, new_helper, 1)
text = text.replace(
    "        } catch is CancellationError {\n            throw FTPClientError.timedOut\n",
    "        } catch is CancellationError {\n            throw CancellationError()\n",
    1,
)
marker = """        } catch FTPClientError.connection {
            return SecretOperationOutput(
                status: "FAILED",
                stage: .connection,
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch {
"""
replacement = """        } catch FTPClientError.connection {
            return SecretOperationOutput(
                status: "FAILED",
                stage: .connection,
                remotePath: plan.remotePath,
                redacted: true
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch {
"""
if marker not in text:
    raise SystemExit("FTP adapter catch shape changed")
text = text.replace(marker, replacement, 1)
p.write_text(text)

# Raw NWConnection waits must respond to explicit Task cancellation now that no timer rescues them.
p = Path("Sources/VaultExecution/FTPSecretOperationAdapter.swift")
text = p.read_text()
text = text.replace(
    """    func start() async throws {
        let gate = FTPContinuationGate()
        try await withCheckedThrowingContinuation { continuation in
""",
    """    func start() async throws {
        let gate = FTPContinuationGate()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
""",
    1,
)
text = text.replace(
    """            connection.start(queue: queue)
        }
    }

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { continuation in
""",
    """                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func send(_ data: Data) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
""",
    1,
)
text = text.replace(
    """            connection.send(content: data, completion: .contentProcessed { error in
                if error == nil {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: FTPClientError.connection)
                }
            })
        }
    }

    func finishSending() async throws {
        try await withCheckedThrowingContinuation { continuation in
""",
    """                connection.send(content: data, completion: .contentProcessed { error in
                    if error == nil {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: FTPClientError.connection)
                    }
                })
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func finishSending() async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
""",
    1,
)
text = text.replace(
    """            connection.send(
                content: nil,
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { error in
                    if error == nil {
                        continuation.resume()
                    } else {
                        continuation.resume(throwing: FTPClientError.connection)
                    }
                }
            )
        }
    }

    func receive(maxLength: Int) async throws -> FTPReceiveResult {
        try await withCheckedThrowingContinuation { continuation in
""",
    """                connection.send(
                    content: nil,
                    contentContext: .finalMessage,
                    isComplete: true,
                    completion: .contentProcessed { error in
                        if error == nil {
                            continuation.resume()
                        } else {
                            continuation.resume(throwing: FTPClientError.connection)
                        }
                    }
                )
            }
        } onCancel: {
            connection.cancel()
        }
    }

    func receive(maxLength: Int) async throws -> FTPReceiveResult {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
""",
    1,
)
text = text.replace(
    """            connection.receive(
                minimumIncompleteLength: 1,
                maximumLength: maxLength
            ) { content, _, isComplete, error in
                if error != nil {
                    continuation.resume(throwing: FTPClientError.connection)
                } else {
                    continuation.resume(returning: FTPReceiveResult(
                        data: content ?? Data(),
                        isComplete: isComplete
                    ))
                }
            }
        }
    }
""",
    """                connection.receive(
                    minimumIncompleteLength: 1,
                    maximumLength: maxLength
                ) { content, _, isComplete, error in
                    if error != nil {
                        continuation.resume(throwing: FTPClientError.connection)
                    } else {
                        continuation.resume(returning: FTPReceiveResult(
                            data: content ?? Data(),
                            isComplete: isComplete
                        ))
                    }
                }
            }
        } onCancel: {
            connection.cancel()
        }
    }
""",
    1,
)
p.write_text(text)

# HTTP descriptor timeoutMs remains decodable but is ignored by the executor.
p = Path("Sources/VaultExecution/HTTPSecretOperationAdapter.swift")
text = p.read_text()
text = text.replace("    private let defaultTimeout: Duration\n", "")
text = text.replace("        defaultTimeout: Duration = .seconds(30),\n", "")
text = text.replace("        self.defaultTimeout = defaultTimeout\n", "")
text = text.replace("        request.timeoutInterval = plan.timeout.timeInterval\n", "")
text = text.replace("        let timeout: Duration\n", "")
text = text.replace("        let timeoutMilliseconds: Int?\n", "")
text = text.replace("            timeoutMilliseconds = operation.timeoutMs\n", "")
text = text.replace("            timeoutMilliseconds = descriptor.parameters[\"timeoutMs\"].flatMap(Int.init)\n", "")
old_timeout_return = """        guard let timeoutMilliseconds else {
            return RequestPlan(
                url: url,
                method: method,
                auth: try validateAuth(auth, descriptor: descriptor),
                body: try validateBody(body),
                responsePolicy: try validateResponsePolicy(responsePolicy, for: url, method: method),
                timeout: defaultTimeout
            )
        }
        guard (100...30_000).contains(timeoutMilliseconds) else {
            throw HTTPAdapterError.invalidParameter
        }
        return RequestPlan(
            url: url,
            method: method,
            auth: try validateAuth(auth, descriptor: descriptor),
            body: try validateBody(body),
            responsePolicy: try validateResponsePolicy(responsePolicy, for: url, method: method),
            timeout: .milliseconds(timeoutMilliseconds)
        )
"""
new_timeout_return = """        return RequestPlan(
            url: url,
            method: method,
            auth: try validateAuth(auth, descriptor: descriptor),
            body: try validateBody(body),
            responsePolicy: try validateResponsePolicy(responsePolicy, for: url, method: method)
        )
"""
if old_timeout_return not in text:
    raise SystemExit("HTTP timeout return shape changed")
text = text.replace(old_timeout_return, new_timeout_return, 1)
p.write_text(text)

# HTTP reusable sessions protect in-flight requests from cache expiry.
p = Path("Sources/VaultExecution/HTTPSessionManager.swift")
text = p.read_text()
text = text.replace("        var lastUsedTick: UInt64\n", "        var lastUsedTick: UInt64\n        var inFlightCount: Int\n", 1)
text = text.replace(
    """        var current = record
        current.lastUsedTick = monotonicNow()
        records[current.id] = current

        do {
""",
    """        var current = record
        current.lastUsedTick = monotonicNow()
        current.inFlightCount += 1
        records[current.id] = current
        defer {
            if var finished = records[current.id] {
                finished.inFlightCount = max(0, finished.inFlightCount - 1)
                finished.lastUsedTick = monotonicNow()
                records[current.id] = finished
            }
        }

        do {
""",
    1,
)
text = text.replace(
    """        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(
""",
    """        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        // Approved operations have no SVLT wall-clock execution deadline.
        // Explicit cancellation and transport/system failures remain authoritative.
        configuration.timeoutIntervalForRequest = TimeInterval.greatestFiniteMagnitude
        configuration.timeoutIntervalForResource = TimeInterval.greatestFiniteMagnitude
        let session = URLSession(
""",
    1,
)
text = text.replace(
    """            createdTick: tick,
            lastUsedTick: tick
""",
    """            createdTick: tick,
            lastUsedTick: tick,
            inFlightCount: 0
""",
    1,
)
text = text.replace(
    """    private func isExpired(_ record: Record) -> Bool {
        let now = monotonicNow()
""",
    """    private func isExpired(_ record: Record) -> Bool {
        guard record.inFlightCount == 0 else { return false }
        let now = monotonicNow()
""",
    1,
)
p.write_text(text)

# SSH actual command execution has no per-command or batch deadline.
p = Path("Sources/VaultExecution/SecretOperationExecutor.swift")
text = p.read_text()
text = text.replace("    private let timeout: Duration\n", "")
text = text.replace("    private let batchTotalTimeout: Duration\n", "")
text = text.replace("        timeout: Duration = .seconds(30),\n", "")
text = text.replace("        batchTotalTimeout: Duration = .seconds(60),\n", "")
text = text.replace("        self.timeout = timeout\n", "")
text = text.replace("        self.batchTotalTimeout = batchTotalTimeout\n", "")
timeout_validation = """            if let rawTimeout = descriptor.parameters["timeoutMs"],
               let milliseconds = Int64(rawTimeout) {
                guard (100...30_000).contains(milliseconds) else { return .invalidParameters }
            } else if descriptor.parameters["timeoutMs"] != nil {
                return .invalidParameters
            }
"""
if text.count(timeout_validation) != 1:
    raise SystemExit("SSH preflight timeout block changed")
text = text.replace(timeout_validation, "", 1)
text = text.replace("        let operationTimeout = try timeout(for: descriptor)\n", "")
text = text.replace("        let batchDeadline = ContinuousClock.now.advanced(by: batchTotalTimeout)\n", "")
deadline_block = """            let commandStart = ContinuousClock.now
            guard commandStart < batchDeadline else {
                throw SecretOperationExecutionError.timedOut
            }
            let remainingBatchTime = commandStart.duration(to: batchDeadline)
            let commandTimeout = min(operationTimeout, remainingBatchTime)

"""
if text.count(deadline_block) != 1:
    raise SystemExit("SSH batch deadline block changed")
text = text.replace(deadline_block, "", 1)
text = text.replace("                        timeout: commandTimeout,\n", "", 1)
text = text.replace("        timeout operationTimeout: Duration,\n", "", 1)
text = text.replace("        let timeoutSeconds = Self.expectTimeoutSeconds(for: operationTimeout)\n", "", 1)
text = text.replace("                        timeoutSeconds: timeoutSeconds,\n", "                        timeoutSeconds: 30, // legacy wrapper frame field; ignored\n", 1)
if text.count("                timeout: operationTimeout,\n") != 2:
    raise SystemExit(f"expected two SSH execution timeout calls, found {text.count('                timeout: operationTimeout,')}")
text = text.replace("                timeout: operationTimeout,\n", "                timeout: nil,\n")
text = text.replace('                        "-o", "ConnectTimeout=\\(timeoutSeconds)",\n', "", 1)
timeout_func = """    private func timeout(for descriptor: SecretOperationDescriptor) throws -> Duration {
        guard let rawTimeout = descriptor.parameters["timeoutMs"] else {
            return timeout
        }
        guard let milliseconds = Int64(rawTimeout),
              (100...30_000).contains(milliseconds)
        else {
            throw SecretOperationExecutionError.invalidParameter
        }
        return .milliseconds(milliseconds)
    }

"""
if text.count(timeout_func) != 1:
    raise SystemExit("SSH timeout helper changed")
text = text.replace(timeout_func, "", 1)
text = text.replace("        set timeout $timeoutSeconds\n", "        # No execution deadline; cancellation is propagated by the owning Task.\n        set timeout -1\n", 1)
text = text.replace("            -o ConnectTimeout=$timeoutSeconds \\\n", "", 1)
p.write_text(text)

# SSH session manager: pending first command never blocks later work, and active work is not TTL-reaped.
p = Path("Sources/VaultExecution/SSHSessionManager.swift")
text = p.read_text()
text = text.replace("        var outputFingerprints: [SecretOutputFingerprint]\n", "        var outputFingerprints: [SecretOutputFingerprint]\n        var inFlightCount: Int\n", 1)
old_wait = """        if let opening = openingTasks[scope] {
            _ = try await opening.task.value
            // The opening command can succeed even though ControlMaster did
            // not persist. Once that flight has settled, re-enter the normal
            // lookup path: reuse a published master when present, otherwise
            // create a fresh authenticated connection. A missing optimization
            // must never turn a concurrent command into
            // SESSION_CONTROL_UNAVAILABLE.
            return try await execute(scope: scope, operation: operation)
        }
"""
new_wait = """        if openingTasks[scope] != nil {
            // The first command may legitimately run for hours. Never serialize a
            // later command behind that command just because its reusable master
            // has not been published yet. Use an isolated one-shot channel until
            // the shared transport becomes available.
            return try await executeWhileOpening(scope: scope, operation: operation)
        }
"""
if old_wait not in text:
    raise SystemExit("SSH opening wait block changed")
text = text.replace(old_wait, new_wait, 1)
text = text.replace(
    """            state: .pending,
            outputFingerprints: []
""",
    """            state: .pending,
            outputFingerprints: [],
            inFlightCount: 1
""",
    1,
)
needle = "        return try await task.value\n    }\n\n    /// Settles an initial transport"
replacement = """        return try await withTaskCancellationHandler {
            try await task.value
        } onCancel: {
            task.cancel()
        }
    }

    private func executeWhileOpening(
        scope: SSHSessionScope,
        operation: @escaping @Sendable (SSHSessionAccess) async throws -> SSHSessionCommandExecution
    ) async throws -> SSHSessionCommandExecution {
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

    /// Settles an initial transport"""
if needle not in text:
    raise SystemExit("SSH opening task return shape changed")
text = text.replace(needle, replacement, 1)
text = text.replace(
    """        current.outputFingerprints = result.outputFingerprints
        records[record.id] = current
""",
    """        current.outputFingerprints = result.outputFingerprints
        current.inFlightCount = 0
        records[record.id] = current
""",
    1,
)
old_active = """        let result = try await operation(access)
        guard result.channelState == .remoteCommandCompleted else {
            await closeRecord(record)
            return result.assigningSessionID(nil, masterReady: false)
        }
        guard var current = records[record.id] else {
            // The record vanished (reaped concurrently) but the command
            // already ran: return the real result instead of failing it.
            return result.assigningSessionID(nil, masterReady: false)
        }
        current.lastUsedAt = now()
        current.lastUsedTick = monotonicNow()
        records[record.id] = current
        return result
            .assigningFingerprintsIfMissing(record.outputFingerprints)
            .assigningSessionID(record.id, masterReady: true)
"""
new_active = """        guard var active = records[record.id] else {
            return try await operation(access).assigningSessionID(nil, masterReady: false)
        }
        active.inFlightCount += 1
        records[record.id] = active
        do {
            let result = try await operation(access)
            guard result.channelState == .remoteCommandCompleted else {
                await closeRecord(record)
                return result.assigningSessionID(nil, masterReady: false)
            }
            guard var current = records[record.id] else {
                // Explicit invalidation may remove the cache record while the
                // command is finishing. Preserve the real command result.
                return result.assigningSessionID(nil, masterReady: false)
            }
            current.inFlightCount = max(0, current.inFlightCount - 1)
            current.lastUsedAt = now()
            current.lastUsedTick = monotonicNow()
            records[record.id] = current
            return result
                .assigningFingerprintsIfMissing(record.outputFingerprints)
                .assigningSessionID(record.id, masterReady: true)
        } catch {
            if var current = records[record.id] {
                current.inFlightCount = max(0, current.inFlightCount - 1)
                current.lastUsedAt = now()
                current.lastUsedTick = monotonicNow()
                records[record.id] = current
            }
            throw error
        }
"""
if old_active not in text:
    raise SystemExit("SSH active execution block changed")
text = text.replace(old_active, new_active, 1)
text = text.replace(
    """    private func isExpired(_ record: Record) -> Bool {
        let tick = monotonicNow()
""",
    """    private func isExpired(_ record: Record) -> Bool {
        guard record.inFlightCount == 0 else { return false }
        let tick = monotonicNow()
""",
    1,
)
p.write_text(text)

# MCP tools no longer advertise or send operation execution deadlines.
p = Path("mcp-server/src/server.ts")
text = p.read_text()
timeout_schema_pattern = re.compile(r'^\s*timeoutMs: z\.number\(\)\.int\(\)\.min\([^\n]+\n', re.MULTILINE)
text, schema_count = timeout_schema_pattern.subn("", text)
if schema_count != 7:
    raise SystemExit(f"expected 7 operation timeout schema fields, found {schema_count}")
timeout_spread_pattern = re.compile(r'^\s*\.\.\.\(parsed\.timeoutMs === undefined \? \{\} : \{ timeoutMs: (?:String\(parsed\.timeoutMs\)|parsed\.timeoutMs) \}\),?\n', re.MULTILINE)
text, spread_count = timeout_spread_pattern.subn("", text)
if spread_count != 11:
    raise SystemExit(f"expected 11 operation timeout spreads, found {spread_count}")
p.write_text(text)

# ProcessRunning test doubles follow the optional timeout API.
for path in Path("Tests/VaultExecutionTests").glob("*.swift"):
    text = path.read_text()
    text = text.replace("timeout: Duration,", "timeout: Duration?,")
    text = text.replace("timeout _: Duration,", "timeout _: Duration?,")
    path.write_text(text)

# The redaction test also constructed the executor with the removed timeout.
replace(
    "Tests/VaultExecutionTests/SecretOperationExecutorTests.swift",
    """    let executor = LocalSecretOperationExecutor(
        processRunner: runner,
        timeout: .seconds(5)
    )
""",
    """    let executor = LocalSecretOperationExecutor(processRunner: runner)
""",
)

# SSH regression now verifies legacy timeoutMs does not create an execution deadline.
p = Path("Tests/VaultExecutionTests/SecretOperationExecutorTests.swift")
text = p.read_text()
old_test = """@Test func sshExecutorReportsProcessTimeoutAndHonorsDescriptorTimeout() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = TimeoutProcessRunner()
    let executor = LocalSecretOperationExecutor(processRunner: runner, timeout: .seconds(30))
    let descriptor = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "admin",
        "timeoutMs": "1200"
    ])

    let output = try await executor.execute(
        descriptor,
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_TIMEOUT_SECRET".utf8) }
    )

    #expect(output.status == "TIMED_OUT")
    #expect(output.stage == .timeout)
    #expect(await runner.timeout == .milliseconds(1200))
}
"""
new_test = """@Test func sshExecutorIgnoresLegacyDescriptorTimeoutAndUsesNoExecutionDeadline() async throws {
    let reference = try SecretReference("secret://0123456789ABCDEFGHJKMNPQRS")
    let runner = CapturingProcessRunner(
        result: ProcessResult(exitCode: 0, stdout: Data("ok".utf8), stderr: Data())
    )
    let executor = LocalSecretOperationExecutor(processRunner: runner)
    let descriptor = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "admin",
        "timeoutMs": "1"
    ])

    let output = try await executor.execute(
        descriptor,
        metadata: [],
        resolve: { _ in Data("ASV_CANARY_TIMEOUT_SECRET".utf8) }
    )

    #expect(output.status == "COMPLETED")
    #expect(await runner.timeout == nil)
}
"""
if old_test not in text:
    raise SystemExit("old SSH timeout test changed")
text = text.replace(old_test, new_test, 1)
old_invalid = """    let invalidTimeout = sshDescriptor(reference: reference, parameters: [
        "passwordRef": reference.description,
        "username": "admin",
        "timeoutMs": "30001"
    ])
    await #expect(throws: SecretOperationExecutionError.invalidParameter) {
        _ = try await executor.execute(invalidTimeout, metadata: [], resolve: { _ in Data("unused".utf8) })
    }
"""
if old_invalid not in text:
    raise SystemExit("old invalid timeout test changed")
text = text.replace(old_invalid, "", 1)
text = text.replace("@Test func sshExecutorRejectsSecretUsernameAndInvalidTimeout()", "@Test func sshExecutorRejectsSecretAndOptionLikeUsername()", 1)
p.write_text(text)

# A suspended lifecycle operation must not prevent a later operation from reaching execution.
p = Path("Tests/VaultAuthorizationTests/SecretOperationServiceTests.swift")
text = p.read_text()
anchor = "@Test func firstOrdinaryOperationTakesOneApprovalAndOpensTheWindow() async throws {"
concurrency_test = """@Test func longRunningOperationDoesNotBlockLaterOperation() async throws {
    let service = SecretOperationService()
    let firstGate = ConcurrentOperationGate()
    let secondStarted = ConcurrentOperationGate()
    let descriptor = SecretOperationDescriptor(
        actionType: .localExecution,
        secretReferences: [],
        destination: "test",
        parameters: [:]
    )

    let first = await service.start(principal: "agent", descriptor: descriptor) { _ in
        await firstGate.markStartedAndWait()
        return SecretOperationOutput(status: "FIRST_DONE")
    }
    await firstGate.waitUntilStarted()

    let second = await service.start(principal: "agent", descriptor: descriptor) { _ in
        await secondStarted.markStarted()
        return SecretOperationOutput(status: "SECOND_DONE")
    }
    await secondStarted.waitUntilStarted()

    #expect(first.operationID != second.operationID)
    await firstGate.release()
}

"""
if text.count(anchor) != 1:
    raise SystemExit("service test insertion anchor changed")
text = text.replace(anchor, concurrency_test + anchor, 1)
helper_anchor = "private enum ApprovalMode: Sendable {"
helper = """private actor ConcurrentOperationGate {
    private var started = false
    private var released = false
    private var startWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func markStarted() {
        started = true
        let waiters = startWaiters
        startWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }

    func markStartedAndWait() async {
        markStarted()
        guard !released else { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func waitUntilStarted() async {
        guard !started else { return }
        await withCheckedContinuation { startWaiters.append($0) }
    }

    func release() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters.removeAll()
        waiters.forEach { $0.resume() }
    }
}

"""
if text.count(helper_anchor) != 1:
    raise SystemExit("service helper insertion anchor changed")
text = text.replace(helper_anchor, helper + helper_anchor, 1)
p.write_text(text)
