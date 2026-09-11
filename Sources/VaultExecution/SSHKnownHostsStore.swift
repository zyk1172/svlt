import Darwin
import Foundation

/// App-owned OpenSSH trust storage. Keeping SVLT host trust separate from the
/// user's global ~/.ssh/known_hosts prevents unrelated SSH clients from
/// silently widening (or clearing) the trust state used by secret-bearing
/// Agent execution.
struct SSHKnownHostsStore: Sendable {
    private let directoryURL: URL

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
