import Darwin
import Foundation

/// Errors intentionally contain no path or errno text. Export failures cross
/// the Agent boundary and must remain a stable, non-sensitive status.
public enum SecureExportWriterError: Error, Equatable, Sendable {
    case invalidRoot
    case fileAlreadyExists
    case writeFailed
}

/// Creates a new owner-only export file below an already approved directory.
/// The root and target are opened through file descriptors so a symlink swap
/// between validation and write cannot redirect plaintext outside the export
/// root. Data is written to an owner-only temporary file and committed with
/// an exclusive atomic rename; existing files are never overwritten.
public struct SecureExportWriter: Sendable {
    public init() {}

    /// Performs the same no-side-effect directory check used by `write`.
    /// Capability manifests call this so they do not advertise export when
    /// the configured root is missing, traverses a symlink, or is shared.
    public func canWrite(to root: URL) -> Bool {
        guard let rootFD = openRoot(root) else { return false }
        defer { Darwin.close(rootFD) }
        return isOwnerOnlyDirectory(rootFD: rootFD)
    }

    public func write(_ data: Data, to destination: URL, under root: URL) throws {
        let standardizedRoot = root.standardizedFileURL
        let standardizedDestination = destination.standardizedFileURL
        guard standardizedDestination.deletingLastPathComponent().path == standardizedRoot.path,
              let fileName = standardizedDestination.path.split(separator: "/").last.map(String.init),
              !fileName.isEmpty,
              fileName != ".",
              fileName != "..",
              !fileName.contains("/"),
              !fileName.utf8.contains(0) else {
            throw SecureExportWriterError.invalidRoot
        }

        guard let rootFD = openRoot(standardizedRoot) else {
            throw SecureExportWriterError.invalidRoot
        }
        defer { Darwin.close(rootFD) }

        guard isOwnerOnlyDirectory(rootFD: rootFD) else {
            throw SecureExportWriterError.invalidRoot
        }

        // The temporary name is opaque and stays inside the already-open
        // export directory. It is never returned to the Agent or logged.
        let temporaryName = ".svlt-export-\(UUID().uuidString.lowercased()).tmp"
        let mode = mode_t(S_IRUSR | S_IWUSR)
        let temporaryFD: Int32 = temporaryName.withCString {
            Darwin.openat(
                rootFD,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode
            )
        }
        guard temporaryFD >= 0 else {
            throw SecureExportWriterError.writeFailed
        }

        var shouldUnlinkTemporary = true
        defer {
            Darwin.close(temporaryFD)
            if shouldUnlinkTemporary {
                _ = temporaryName.withCString { Darwin.unlinkat(rootFD, $0, 0) }
            }
        }

        do {
            try writeAll(data, to: temporaryFD)
            guard Darwin.fsync(temporaryFD) == 0 else {
                throw SecureExportWriterError.writeFailed
            }

            // RENAME_EXCL is required: plain renameat would atomically replace
            // a concurrently-created destination and violate the no-overwrite
            // export contract. If the filesystem cannot provide this primitive,
            // fail closed instead of falling back to a racy check-then-rename.
            let renameResult = temporaryName.withCString { source in
                fileName.withCString { target in
                    Darwin.renameatx_np(rootFD, source, rootFD, target, UInt32(RENAME_EXCL))
                }
            }
            guard renameResult == 0 else {
                if errno == EEXIST {
                    throw SecureExportWriterError.fileAlreadyExists
                }
                throw SecureExportWriterError.writeFailed
            }
            shouldUnlinkTemporary = false

            // The atomic rename above is the commit point exposed to callers.
            // The file itself was fsynced before commit, so reporting a failure
            // after the rename would create an ambiguous state where the Agent
            // retries an export that already exists. Directory fsync is kept as
            // a best-effort durability hint; failure affects crash durability,
            // not whether this invocation successfully committed the file.
            _ = Darwin.fsync(rootFD)
        } catch let error as SecureExportWriterError {
            throw error
        } catch {
            throw SecureExportWriterError.writeFailed
        }
    }

    private func openRoot(_ root: URL) -> Int32? {
        guard let path = canonicalPathWithoutUnexpectedSymlink(root.standardizedFileURL.path) else {
            return nil
        }

        // Capture the intended directory identity before opening it. The
        // descriptor is then acquired by walking from an already-open `/`
        // descriptor with O_NOFOLLOW_ANY for every component. If a pathname
        // component is replaced during that walk, the identity check below
        // fails closed; once returned, all writes use this descriptor rather
        // than resolving the root pathname again.
        var expectedStat = stat()
        guard path.withCString({ lstat($0, &expectedStat) }) == 0 else {
            return nil
        }

        guard let descriptor = openDirectoryByComponents(path) else {
            return nil
        }

        var actualStat = stat()
        guard Darwin.fstat(descriptor, &actualStat) == 0,
              actualStat.st_dev == expectedStat.st_dev,
              actualStat.st_ino == expectedStat.st_ino else {
            Darwin.close(descriptor)
            return nil
        }
        return descriptor
    }

    private func openDirectoryByComponents(_ path: String) -> Int32? {
        let rootDescriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC
        )
        guard rootDescriptor >= 0 else { return nil }

        var currentDescriptor = rootDescriptor
        for component in path.split(separator: "/") {
            let nextDescriptor = String(component).withCString {
                Darwin.openat(
                    currentDescriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW_ANY | O_CLOEXEC
                )
            }
            Darwin.close(currentDescriptor)
            guard nextDescriptor >= 0 else { return nil }
            currentDescriptor = nextDescriptor
        }
        return currentDescriptor
    }

    /// `O_NOFOLLOW_ANY` intentionally rejects every symlink in a pathname.
    /// macOS exposes `/var` as the stable system alias for `/private/var`, so
    /// normalize that one documented alias before opening the canonical path.
    /// Any other symlink in the caller-provided path remains a hard failure,
    /// including a symlinked export root or an attacker-controlled ancestor.
    private func canonicalPathWithoutUnexpectedSymlink(_ path: String) -> String? {
        guard path.hasPrefix("/") else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        guard path.withCString({ realpath($0, &buffer) }) != nil else {
            return nil
        }
        let resolved = String(
            decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
            as: UTF8.self
        )
        let normalizedInput: String
        if path == "/var" {
            normalizedInput = "/private/var"
        } else if path.hasPrefix("/var/") {
            normalizedInput = "/private" + path
        } else {
            normalizedInput = path
        }
        return normalizedInput == resolved ? resolved : nil
    }

    private func isOwnerOnlyDirectory(rootFD: Int32) -> Bool {
        var fileStat = stat()
        guard Darwin.fstat(rootFD, &fileStat) == 0,
              (fileStat.st_mode & S_IFMT) == S_IFDIR,
              fileStat.st_uid == geteuid(),
              (fileStat.st_mode & mode_t(S_IRWXG | S_IRWXO)) == 0 else {
            return false
        }
        return true
    }

    private func writeAll(_ data: Data, to fileDescriptor: Int32) throws {
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let baseAddress = buffer.baseAddress else { return 0 }
                return Darwin.write(
                    fileDescriptor,
                    baseAddress.advanced(by: offset),
                    buffer.count - offset
                )
            }
            guard written > 0 else {
                throw SecureExportWriterError.writeFailed
            }
            offset += written
        }
    }
}
