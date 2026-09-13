import Foundation
import VaultCore

enum FileTransferAdapterError: Error, Equatable {
    case unsupportedOperation
    case invalidParameter
    case invalidLocalPath
    case localFileUnavailable
    case localFileAlreadyExists
}

struct FileTransferPlan: Sendable {
    let action: SecretOperationAction
    let protocolType: SecretOperationProtocol
    let operation: SecretFileOperation
    let host: String
    let port: Int
    let remotePath: String
    let localURL: URL?
    let username: String?
    let usernameReference: SecretReference?
    let passwordReference: SecretReference
    let timeout: Duration
}

public enum FileTransferAdapterSupport {
    /// Used only as the convenience destination when a download does not
    /// provide an explicit local path. Explicit upload sources and download
    /// destinations are not confined to this directory.
    public static let defaultTransferRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/AgentSecretVault/Downloads", isDirectory: true)
        .standardizedFileURL

    static func makePlan(
        for descriptor: SecretOperationDescriptor,
        action: SecretOperationAction,
        protocols: Set<SecretOperationProtocol>,
        defaultPort: Int,
        localRoot: URL = defaultTransferRoot
    ) throws -> FileTransferPlan {
        guard descriptor.actionType == action,
              let protocolType = descriptor.protocolType,
              protocols.contains(protocolType),
              let destination = descriptor.destination,
              isSafeHost(destination) else {
            throw FileTransferAdapterError.invalidParameter
        }

        let operation = try operation(from: descriptor)
        guard operation.protocolType == protocolType,
              let passwordReference = operation.passwordReference,
              descriptor.secretReferences.contains(passwordReference),
              exactlyOne(operation.username, operation.usernameReference),
              operation.username.map(isSafeUsername) ?? true,
              operation.usernameReference.map(descriptor.secretReferences.contains) ?? true,
              operation.usernameReference != passwordReference,
              isValidRemotePath(operation.remotePath) else {
            throw FileTransferAdapterError.invalidParameter
        }

        let port = descriptor.port ?? defaultPort
        guard (1...65_535).contains(port) else {
            throw FileTransferAdapterError.invalidParameter
        }

        let timeout = try timeout(from: descriptor)
        let localURL = try localURL(
            for: operation,
            descriptor: descriptor,
            localRoot: localRoot
        )
        return FileTransferPlan(
            action: action,
            protocolType: protocolType,
            operation: operation.operation,
            host: normalizedHost(destination),
            port: port,
            remotePath: operation.remotePath,
            localURL: localURL,
            username: operation.username,
            usernameReference: operation.usernameReference,
            passwordReference: passwordReference,
            timeout: timeout
        )
    }

    static func prepareLocalRoot(_ root: URL) throws {
        let fileManager = FileManager.default
        try fileManager.createDirectory(at: root, withIntermediateDirectories: true)
        let resourceValues = try root.resourceValues(forKeys: [.isSymbolicLinkKey])
        guard resourceValues.isSymbolicLink != true,
              root.resolvingSymlinksInPath().standardizedFileURL.path == root.path else {
            throw FileTransferAdapterError.invalidLocalPath
        }
    }

    static func validateUploadSource(_ url: URL) throws {
        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: url.path) else {
            throw FileTransferAdapterError.localFileUnavailable
        }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw FileTransferAdapterError.localFileUnavailable
        }
        guard url.resolvingSymlinksInPath().standardizedFileURL.path == url.path else {
            throw FileTransferAdapterError.invalidLocalPath
        }
    }

    static func validateDownloadDestination(_ url: URL) throws {
        let fileManager = FileManager.default
        guard !fileManager.fileExists(atPath: url.path) else {
            throw FileTransferAdapterError.localFileAlreadyExists
        }
        let parent = url.deletingLastPathComponent()
        guard parent.resolvingSymlinksInPath().standardizedFileURL.path == parent.path else {
            throw FileTransferAdapterError.invalidLocalPath
        }
    }

    static func makeStagingURL(for destination: URL) -> URL {
        destination.deletingLastPathComponent()
            .appendingPathComponent(".svlt-transfer-\(UUID().uuidString)", isDirectory: false)
    }

    static func operation(from descriptor: SecretOperationDescriptor) throws -> FileTransferOperation {
        if case let .fileTransfer(operation)? = descriptor.payload {
            return operation
        }

        guard let protocolRaw = descriptor.protocolType?.rawValue,
              let protocolType = SecretOperationProtocol(rawValue: protocolRaw),
              let operation = descriptor.fileOperation,
              let remotePath = descriptor.parameters["remotePath"],
              let passwordRaw = descriptor.parameters["passwordRef"],
              let passwordReference = try? SecretReference(passwordRaw) else {
            throw FileTransferAdapterError.invalidParameter
        }
        let usernameReference: SecretReference?
        if let rawUsernameReference = descriptor.parameters["usernameRef"] {
            guard let parsedUsernameReference = try? SecretReference(rawUsernameReference) else {
                throw FileTransferAdapterError.invalidParameter
            }
            usernameReference = parsedUsernameReference
        } else {
            usernameReference = nil
        }
        return FileTransferOperation(
            protocolType: protocolType,
            operation: operation,
            remotePath: remotePath,
            localPath: descriptor.parameters["localPath"] ?? descriptor.fileTarget,
            localFileGrantID: descriptor.parameters["localFileGrantID"],
            username: descriptor.parameters["username"],
            usernameReference: usernameReference,
            passwordReference: passwordReference
        )
    }

    private static func localURL(
        for operation: FileTransferOperation,
        descriptor: SecretOperationDescriptor,
        localRoot: URL
    ) throws -> URL? {
        let needsLocalFile: Bool
        switch operation.operation {
        case .download:
            needsLocalFile = true
        case .upload, .overwrite, .write:
            needsLocalFile = true
        case .list, .delete:
            guard operation.localPath == nil,
                  descriptor.parameters["localPath"] == nil,
                  descriptor.fileTarget == nil else {
                throw FileTransferAdapterError.invalidParameter
            }
            return nil
        case .read, .move:
            throw FileTransferAdapterError.unsupportedOperation
        }

        guard needsLocalFile else { return nil }
        let rawPath: String
        if let localPath = operation.localPath {
            rawPath = localPath
        } else if operation.operation == .download,
                  let lastComponent = operation.remotePath.split(separator: "/").last,
                  isSafeLocalComponent(String(lastComponent)) {
            rawPath = localRoot.standardizedFileURL
                .appendingPathComponent(String(lastComponent))
                .path
        } else {
            throw FileTransferAdapterError.invalidLocalPath
        }

        guard rawPath.hasPrefix("/"),
              rawPath.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value != 0x7F }) else {
            throw FileTransferAdapterError.invalidLocalPath
        }

        let candidate = URL(fileURLWithPath: rawPath).standardizedFileURL
        guard candidate.path != "/",
              isSafeLocalComponent(candidate.lastPathComponent) else {
            throw FileTransferAdapterError.invalidLocalPath
        }
        return candidate
    }

    private static func timeout(from descriptor: SecretOperationDescriptor) throws -> Duration {
        guard let rawTimeout = descriptor.parameters["timeoutMs"] else {
            return .seconds(60)
        }
        guard let milliseconds = Int64(rawTimeout),
              (1_000...60_000).contains(milliseconds) else {
            throw FileTransferAdapterError.invalidParameter
        }
        return .milliseconds(milliseconds)
    }

    private static func exactlyOne(_ username: String?, _ reference: SecretReference?) -> Bool {
        (username != nil) != (reference != nil)
    }

    private static func isSafeHost(_ host: String) -> Bool {
        let normalized = normalizedHost(host)
        guard (1...253).contains(normalized.utf8.count),
              !normalized.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }),
              !normalized.contains(where: { $0.isWhitespace }),
              !normalized.contains("/"),
              !normalized.contains("@"),
              !normalized.hasPrefix("-") else {
            return false
        }
        return true
    }

    private static func normalizedHost(_ host: String) -> String {
        host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }

    private static func isSafeUsername(_ username: String) -> Bool {
        let bytes = username.utf8
        guard (1...256).contains(bytes.count),
              !username.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F }) else {
            return false
        }
        return !username.contains(":")
            && !username.contains("@")
            && !username.contains("/")
    }

    /// Remote file locations are intentionally not sandboxed to a particular
    /// directory. The protocol adapter quotes/encodes the path; this layer only
    /// rejects an empty/control-character path that cannot be represented safely.
    private static func isValidRemotePath(_ path: String) -> Bool {
        !path.isEmpty
            && path.utf8.count <= 4_096
            && path.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7F }
    }

    private static func isSafeLocalComponent(_ component: String) -> Bool {
        !component.isEmpty
            && component != "."
            && component != ".."
            && component.utf8.count <= 255
            && component.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7F }
    }
}
