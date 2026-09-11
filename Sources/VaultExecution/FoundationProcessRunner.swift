import Darwin
import Foundation

public struct FoundationProcessRunner: ProcessRunning {
    public init() {}

    public func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration,
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
                let timeoutTask = Task {
                    try? await Task.sleep(for: timeout)
                    runState.markTimedOutAndTerminate()
                }

                process.terminationHandler = { terminatedProcess in
                    timeoutTask.cancel()
                    stdoutPipe.fileHandleForReading.readabilityHandler = nil
                    stderrPipe.fileHandleForReading.readabilityHandler = nil

                    if !output.hasExceededLimit {
                        output.append(stdoutPipe.fileHandleForReading.readDataToEndOfFile(), to: .stdout)
                        output.append(stderrPipe.fileHandleForReading.readDataToEndOfFile(), to: .stderr)
                    }

                    switch runState.finishReason {
                    case .cancelled:
                        completion.resume(throwing: CancellationError())
                    case .outputLimitExceeded:
                        completion.resume(throwing: ProcessRunError.outputLimitExceeded)
                    case .timedOut:
                        completion.resume(throwing: ProcessRunError.timedOut)
                    case let .stdinWriteFailed(message):
                        completion.resume(throwing: ProcessRunError.stdinWriteFailed(message))
                    case .none:
                        completion.resume(
                            returning: ProcessResult(
                                exitCode: terminatedProcess.terminationStatus,
                                stdout: output.stdout,
                                stderr: output.stderr
                            )
                        )
                    }
                }

                do {
                    try process.run()
                } catch {
                    timeoutTask.cancel()
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
                    timeoutTask.cancel()
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

private enum FoundationProcessFinishReason {
    case cancelled
    case timedOut
    case outputLimitExceeded
    case stdinWriteFailed(String)
}

private final class FoundationProcessRunState: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var reason: FoundationProcessFinishReason?

    var finishReason: FoundationProcessFinishReason? {
        lock.withLock { reason }
    }

    func attach(_ process: Process) {
        lock.withLock {
            self.process = process
        }
    }

    func markCancelledAndTerminate() {
        markAndTerminate(.cancelled, killFallback: true)
    }

    func markTimedOutAndTerminate() {
        markAndTerminate(.timedOut, killFallback: true)
    }

    func markOutputLimitExceededAndTerminate() {
        markAndTerminate(.outputLimitExceeded, killFallback: true)
    }

    @discardableResult
    func markStdinWriteFailedAndTerminate(_ message: String) -> Bool {
        var processToKill: Process?
        var wasRunning = false
        lock.withLock {
            if reason == nil {
                reason = .stdinWriteFailed(message)
            }
            guard let process, process.isRunning else { return }

            process.terminate()
            processToKill = process
            wasRunning = true
        }

        if let processToKill {
            Task {
                try? await Task.sleep(for: .seconds(2))
                self.killIfNeeded(processToKill)
            }
        }
        return wasRunning
    }

    func terminate() {
        lock.withLock {
            guard let process, process.isRunning else { return }

            process.terminate()
        }
    }

    private func markAndTerminate(
        _ finishReason: FoundationProcessFinishReason,
        killFallback: Bool
    ) {
        var processToKill: Process?
        lock.withLock {
            // Record the first terminal reason even if the child has not quite
            // started yet. The post-launch Task.isCancelled check closes that
            // race without allowing a later timeout to overwrite cancellation.
            if reason == nil {
                reason = finishReason
            }

            guard let process, process.isRunning else {
                return
            }

            process.terminate()
            if killFallback {
                processToKill = process
            }
        }

        guard let processToKill else {
            return
        }
        Task {
            try? await Task.sleep(for: .seconds(2))
            self.killIfNeeded(processToKill)
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

private func cleanup(stdoutPipe: Pipe, stderrPipe: Pipe) {
    stdoutPipe.fileHandleForReading.readabilityHandler = nil
    stderrPipe.fileHandleForReading.readabilityHandler = nil
    try? stdoutPipe.fileHandleForReading.close()
    try? stderrPipe.fileHandleForReading.close()
}
