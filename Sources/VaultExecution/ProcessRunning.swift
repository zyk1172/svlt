import Darwin
import Foundation

public struct ProcessInvocation: Equatable, Sendable {
    public let executable: String
    public let arguments: [String]

    public init(executable: String, arguments: [String]) {
        self.executable = executable
        self.arguments = arguments
    }
}

public struct ProcessResult: Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: Data
    public let stderr: Data

    public init(exitCode: Int32, stdout: Data, stderr: Data) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

public enum ProcessRunError: Error, Equatable, Sendable {
    case timedOut
    case outputLimitExceeded
    /// The executable could not be started. No child process was available
    /// to receive the supplied input.
    case processLaunchFailed(String)
    /// The child process was started, but writing or closing its stdin failed.
    /// This is deliberately distinct from a launch failure because the child
    /// may already have performed work before its input pipe disappeared.
    case stdinWriteFailed(String)
    /// Kept for source compatibility with older ProcessRunning clients. New
    /// runners must use one of the two explicit failure cases above.
    @available(*, deprecated, message: "Use processLaunchFailed or stdinWriteFailed")
    case launchFailed(String)
}

public protocol ProcessRunning: Sendable {
    func run(
        _ invocation: ProcessInvocation,
        stdin: Data,
        timeout: Duration?,
        outputLimitBytes: Int
    ) async throws -> ProcessResult
}

/// App-owned OpenSSH trust storage. Keeping SVLT host trust separate from the
/// user's global ~/.ssh/known_hosts prevents unrelated SSH clients from
/// silently widening (or clearing) the trust state used by secret-bearing
/// Agent execution.
struct SSHKnownHostsStore: Sendable {
    let directoryURL: URL

    init(directoryURL: URL? = nil) {
        self.directoryURL = (directoryURL
            ?? FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/AgentSecretVault/SSH", isDirectory: true))
            .standardizedFileURL
    }

    func prepare() throws -> String {
        let fileManager = FileManager.default
        do {
            try fileManager.createDirectory(
                at: directoryURL,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
            )
        } catch {
            throw SSHKnownHostsStoreError.unavailable
        }

        var directoryStat = stat()
        guard directoryURL.path.withCString({ lstat($0, &directoryStat) }) == 0,
              (directoryStat.st_mode & S_IFMT) == S_IFDIR,
              directoryStat.st_uid == geteuid() else {
            throw SSHKnownHostsStoreError.unavailable
        }
        guard directoryURL.path.withCString({ chmod($0, S_IRWXU) }) == 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }

        let knownHostsURL = directoryURL.appendingPathComponent("known_hosts", isDirectory: false)
        let mode = mode_t(S_IRUSR | S_IWUSR)
        let descriptor = knownHostsURL.path.withCString {
            Darwin.open($0, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode)
        }
        guard descriptor >= 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }
        defer { Darwin.close(descriptor) }

        var fileStat = stat()
        guard Darwin.fstat(descriptor, &fileStat) == 0,
              (fileStat.st_mode & S_IFMT) == S_IFREG,
              fileStat.st_uid == geteuid(),
              Darwin.fchmod(descriptor, mode) == 0 else {
            throw SSHKnownHostsStoreError.unavailable
        }

        return knownHostsURL.path
    }
}

enum SSHKnownHostsStoreError: Error, Equatable, Sendable {
    case unavailable
}
