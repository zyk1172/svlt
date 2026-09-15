import Foundation
import VaultExecution
import VaultIPC

public enum VaultAppServicesExportError: Error, Equatable, Sendable {
    case invalidDestination
    case destinationNotAllowed
    case fileAlreadyExists
    case directorySecurityInvalid
    case writeFailed
}

/// Owns the non-secret export boundary: configured root, destination policy,
/// capability preflight, and the final owner-only atomic file commit.
/// Authorization and plaintext resolution stay with `VaultAppServices`.
struct CatalogExportCoordinator: Sendable {
    private static let allowedExtensions = Set(["md", "txt"])

    let root: URL
    private let writer: SecureExportWriter

    init(root: URL, writer: SecureExportWriter = SecureExportWriter()) {
        self.root = root.standardizedFileURL
        self.writer = writer
    }

    static func defaultRoot() -> URL {
        FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Desktop", isDirectory: true)
    }

    var authorizationDestination: String {
        root.path
    }

    func capability() -> SecretOperationCapability {
        let ready = writer.canWrite(to: root)
        return SecretOperationCapability(
            kind: .export,
            status: ready ? .supported : .unavailable,
            operations: [.exportPlaintext],
            reason: ready
                ? "App-owned export writer creates a new owner-only file below the configured export root"
                : "配置的导出根目录不存在、包含 symlink 或不是 owner-only 目录",
            features: SecretOperationCapabilityFeatures(
                response: ["exportStatus", "path"],
                transportSessionReuse: false
            )
        )
    }

    /// This check intentionally happens before device-owner approval. An
    /// export that cannot be committed safely must not consume an approval or
    /// create any legacy execution-scope state.
    func requireReadyForApproval() throws {
        guard writer.canWrite(to: root) else {
            throw VaultAppServicesExportError.directorySecurityInvalid
        }
    }

    func validatedDestination(_ destinationPath: String) throws -> URL {
        guard destinationPath.hasPrefix("/") else {
            throw VaultAppServicesExportError.invalidDestination
        }

        let destination = URL(fileURLWithPath: destinationPath).standardizedFileURL
        let fileExtension = destination.pathExtension.lowercased()
        let fileName = destination.lastPathComponent

        guard !fileName.isEmpty,
              fileName != ".",
              fileName != "..",
              Self.allowedExtensions.contains(fileExtension)
        else {
            throw VaultAppServicesExportError.invalidDestination
        }

        guard destination.deletingLastPathComponent().standardizedFileURL.path == root.path else {
            throw VaultAppServicesExportError.destinationNotAllowed
        }

        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: root.path, isDirectory: &isDirectory),
              isDirectory.boolValue
        else {
            throw VaultAppServicesExportError.invalidDestination
        }

        guard !FileManager.default.fileExists(atPath: destination.path) else {
            throw VaultAppServicesExportError.fileAlreadyExists
        }

        return destination
    }

    func write(_ data: Data, to destination: URL) throws {
        do {
            try writer.write(data, to: destination, under: root)
        } catch SecureExportWriterError.fileAlreadyExists {
            throw VaultAppServicesExportError.fileAlreadyExists
        } catch SecureExportWriterError.invalidRoot {
            throw VaultAppServicesExportError.directorySecurityInvalid
        } catch {
            throw VaultAppServicesExportError.writeFailed
        }
    }
}
