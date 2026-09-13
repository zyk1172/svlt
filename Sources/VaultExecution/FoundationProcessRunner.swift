import Darwin
import Foundation

public struct FoundationProcessRunner: ProcessRunning {
    public init() {}

    public func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration?,
        outputLimitBytes: Int
    ) async throws -> ProcessResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: invocation.executable)
        process.arguments = invocation.arguments

        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        let output = BoundedProcessOutput(limit: outputLimitBytes)
        let runState = FoundationProcessRunState()
        runState.attach(process)

        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }

            if output.append(data, to: .stdout) {
                runState.markOutputLimitExceededAndTerminate()
            }
        }

        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }

            if output.append(data, to: .stderr) {
                runState.markOutputLimitExceededAndTerminate()
            }
        }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let completion = ProcessRunCompletion(continuation)
                let timeoutTask = timeout.map { duration in
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

                process.terminationHandler = { terminatedProcess in
                    // Claim process exit before cancelling the timeout task so
                    // a cancelled sleep cannot reclassify a completed child.
                    // Output validation may still turn this provisional exit
                    // into outputLimitExceeded while the final bytes drain.
                    _ = runState.markProcessExited()
                    timeoutTask?.cancel()
                    stdoutPipe.fileHandleForReading.readabilityHandler = nil
                    stderrPipe.fileHandleForReading.readabilityHandler = nil

                    if !output.hasExceededLimit {
                        let drainDeadline = DispatchTime.now().uptimeNanoseconds
                            &+ processOutputDrainGraceNanoseconds
                        drainAvailableOutput(
                            from: stdoutPipe.fileHandleForReading,
                            to: .stdout,
                            output: output,
                            runState: runState,
                            deadline: drainDeadline
                        )
                        drainAvailableOutput(
                            from: stderrPipe.fileHandleForReading,
                            to: .stderr,
                            output: output,
                            runState: runState,
                            deadline: drainDeadline
                        )
                    }

                    cleanup(stdoutPipe: stdoutPipe, stderrPipe: stderrPipe)

                    let finishReason = runState.finalizeProcessExit(
                        outputLimitExceeded: output.hasExceededLimit
                    )
                    switch finishReason {
                    case .completed:
                        completion.resume(
                            returning: ProcessResult(
                                exitCode: terminatedProcess.terminationStatus,
                                stdout: output.stdout,
                                stderr: output.stderr
                            )
                        )
                    case .cancelled:
                        completion.resume(throwing: CancellationError())
                    case .outputLimitExceeded:
                        completion.resume(throwing: ProcessRunError.outputLimitExceeded)
                    case .timedOut:
                        completion.resume(throwing: ProcessRunError.timedOut)
                    case let .stdinWriteFailed(message):
                        completion.resume(throwing: ProcessRunError.stdinWriteFailed(message))
                    }
                }

                do {
                    try process.run()
                    runState.markRunning()
                    try? stdinPipe.fileHandleForReading.close()
                    try? stdoutPipe.fileHandleForWriting.close()
                    try? stderrPipe.fileHandleForWriting.close()
                } catch {
                    timeoutTask?.cancel()
                    cleanup(stdoutPipe: stdoutPipe, stderrPipe: stderrPipe)
                    runState.terminate()
                    completion.resume(
                        throwing: ProcessRunError.processLaunchFailed(error.localizedDescription)
                    )
                    return
                }

                // Cancellation can race with process launch. Re-check after
                // Process.run() so a request cancelled just before launch
                // cannot leave a credential-bearing child running detached
                // from its caller.
                if Task.isCancelled {
                    runState.markCancelledAndTerminate()
                }

                do {
                    try stdinPipe.fileHandleForWriting.write(contentsOf: stdin)
                    try stdinPipe.fileHandleForWriting.close()
                } catch {
                    timeoutTask?.cancel()
                    let message = error.localizedDescription
                    guard runState.markStdinWriteFailedAndTerminate(message) else {
                        cleanup(stdoutPipe: stdoutPipe, stderrPipe: stderrPipe)
                        completion.resume(throwing: ProcessRunError.stdinWriteFailed(message))
                        return
                    }
                }
            }
        } onCancel: {
            // Cancellation is a security boundary for secret-bearing helper
            // processes. Give the child a short graceful shutdown window, then
            // force it down so cancellation cannot leave a stubborn process
            // running indefinitely with credentials in memory or stdin.
            runState.markCancelledAndTerminate()
        }
    }
}

private let processOutputDrainGraceNanoseconds: UInt64 = 100_000_000
private let processOutputDrainPollMicroseconds: UInt64 = 5_000
private let processOutputReadBufferSize = 16_384

private enum ProcessOutputStream {
    case stdout
    case stderr
}

private final class BoundedProcessOutput: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private var storedStdout = Data()
    private var storedStderr = Data()
    private var exceededLimit = false

    init(limit: Int) {
        self.limit = limit
    }

    var stdout: Data {
        lock.withLock { storedStdout }
    }

    var stderr: Data {
        lock.withLock { storedStderr }
    }

    var hasExceededLimit: Bool {
        lock.withLock { exceededLimit }
    }

    @discardableResult
    func append(_ data: Data, to stream: ProcessOutputStream) -> Bool {
        lock.withLock {
            guard !data.isEmpty else {
                return exceededLimit
            }

            guard !exceededLimit else {
                return true
            }

            let nextSize = storedStdout.count + storedStderr.count + data.count
            guard nextSize <= limit else {
                exceededLimit = true
                return true
            }

            switch stream {
            case .stdout:
                storedStdout.append(data)
            case .stderr:
                storedStderr.append(data)
            }

            return false
        }
    }
}

enum FoundationProcessFinishReason: Equatable {
    case completed
    case cancelled
    case timedOut
    case outputLimitExceeded
    case stdinWriteFailed(String)
}

final class FoundationProcessRunState: @unchecked Sendable {
    private enum Phase {
        case preparing
        case running
        case processExited
        case finished(FoundationProcessFinishReason)
    }

    private let lock = NSLock()
    private var process: Process?
    private var phase: Phase = .preparing

    var finishReason: FoundationProcessFinishReason? {
        lock.withLock {
            guard case let .finished(reason) = phase else {
                return nil
            }
            return reason
        }
    }

    func attach(_ process: Process) {
        lock.withLock {
            self.process = process
        }
    }

    func markRunning() {
        var processToTerminate: Process?
        lock.withLock {
            switch phase {
            case .preparing:
                phase = .running
            case .finished:
                if let process, process.isRunning {
                    processToTerminate = process
                }
            case .running, .processExited:
                break
            }
        }

        if let processToTerminate {
            requestTermination(processToTerminate, killFallback: true)
        }
    }

    @discardableResult
    func markProcessExited() -> FoundationProcessFinishReason? {
        lock.withLock {
            switch phase {
            case let .finished(reason):
                return reason
            case .processExited:
                return nil
            case .preparing, .running:
                phase = .processExited
                return nil
            }
        }
    }

    func finalizeProcessExit(outputLimitExceeded: Bool) -> FoundationProcessFinishReason {
        lock.withLock {
            switch phase {
            case let .finished(reason):
                return reason
            case .preparing, .running, .processExited:
                let reason: FoundationProcessFinishReason = outputLimitExceeded
                    ? .outputLimitExceeded
                    : .completed
                phase = .finished(reason)
                return reason
            }
        }
    }

    func markCancelledAndTerminate() {
        markAndTerminate(.cancelled, killFallback: true, allowAfterProcessExit: false)
    }

    func markTimedOutAndTerminate() {
        markAndTerminate(.timedOut, killFallback: true, allowAfterProcessExit: false)
    }

    func markOutputLimitExceededAndTerminate() {
        markAndTerminate(.outputLimitExceeded, killFallback: true, allowAfterProcessExit: true)
    }

    @discardableResult
    func markStdinWriteFailedAndTerminate(_ message: String) -> Bool {
        markAndTerminate(
            .stdinWriteFailed(message),
            killFallback: true,
            allowAfterProcessExit: true
        )
    }

    func terminate() {
        let processToTerminate = lock.withLock { () -> Process? in
            guard let process, process.isRunning else { return nil }
            return process
        }
        if let processToTerminate {
            processToTerminate.terminate()
        }
    }

    @discardableResult
    private func markAndTerminate(
        _ finishReason: FoundationProcessFinishReason,
        killFallback: Bool,
        allowAfterProcessExit: Bool
    ) -> Bool {
        var processToTerminate: Process?
        var wasRunning = false

        lock.withLock {
            switch phase {
            case .preparing, .running:
                phase = .finished(finishReason)
            case .processExited:
                guard allowAfterProcessExit else {
                    return
                }
                phase = .finished(finishReason)
            case .finished:
                break
            }

            guard let process, process.isRunning else {
                return
            }
            processToTerminate = process
            wasRunning = true
        }

        if let processToTerminate {
            requestTermination(processToTerminate, killFallback: killFallback)
        }
        return wasRunning
    }

    private func requestTermination(_ process: Process, killFallback: Bool) {
        if process.isRunning {
            process.terminate()
        }
        guard killFallback else {
            return
        }

        Task {
            try? await Task.sleep(for: .seconds(2))
            self.killIfNeeded(process)
        }
    }

    private func killIfNeeded(_ process: Process) {
        lock.withLock {
            guard process.isRunning else { return }
            Darwin.kill(process.processIdentifier, SIGKILL)
        }
    }
}

private final class ProcessRunCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ProcessResult, Error>?

    init(_ continuation: CheckedContinuation<ProcessResult, Error>) {
        self.continuation = continuation
    }

    func resume(returning result: ProcessResult) {
        lock.withLock {
            guard let continuation else { return }

            self.continuation = nil
            continuation.resume(returning: result)
        }
    }

    func resume(throwing error: Error) {
        lock.withLock {
            guard let continuation else { return }

            self.continuation = nil
            continuation.resume(throwing: error)
        }
    }
}

private func drainAvailableOutput(
    from handle: FileHandle,
    to stream: ProcessOutputStream,
    output: BoundedProcessOutput,
    runState: FoundationProcessRunState,
    deadline: UInt64
) {
    let fileDescriptor = handle.fileDescriptor
    guard fileDescriptor >= 0 else {
        return
    }

    let originalFlags = Darwin.fcntl(fileDescriptor, F_GETFL)
    guard originalFlags >= 0 else {
        return
    }
    guard Darwin.fcntl(fileDescriptor, F_SETFL, originalFlags | O_NONBLOCK) != -1 else {
        return
    }
    defer {
        _ = Darwin.fcntl(fileDescriptor, F_SETFL, originalFlags)
    }

    var buffer = [UInt8](repeating: 0, count: processOutputReadBufferSize)
    while true {
        let byteCount = buffer.withUnsafeMutableBytes { rawBuffer -> Int in
            guard let baseAddress = rawBuffer.baseAddress else {
                return 0
            }
            return Darwin.read(fileDescriptor, baseAddress, rawBuffer.count)
        }

        if byteCount > 0 {
            if output.append(Data(buffer.prefix(byteCount)), to: stream) {
                runState.markOutputLimitExceededAndTerminate()
                return
            }
            continue
        }

        if byteCount == 0 {
            return
        }

        if errno == EINTR {
            continue
        }

        guard errno == EAGAIN || errno == EWOULDBLOCK else {
            return
        }

        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else {
            return
        }
        let remainingMicroseconds = (deadline - now) / 1_000
        Darwin.usleep(useconds_t(min(remainingMicroseconds, processOutputDrainPollMicroseconds)))
    }
}

private func cleanup(stdoutPipe: Pipe, stderrPipe: Pipe) {
    stdoutPipe.fileHandleForReading.readabilityHandler = nil
    stderrPipe.fileHandleForReading.readabilityHandler = nil
    try? stdoutPipe.fileHandleForReading.close()
    try? stderrPipe.fileHandleForReading.close()
    try? stdoutPipe.fileHandleForWriting.close()
    try? stderrPipe.fileHandleForWriting.close()
}
