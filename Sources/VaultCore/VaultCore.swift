import Foundation

public enum VaultFormat {
    public static let current = 2
    public static let legacyV1 = 1
}

/// Global authorization posture selected by the device owner in the SVLT App.
///
/// `approvalRequired` preserves SVLT's effect-based owner-approval policy.
/// `noApproval` removes SVLT's owner-approval/deny gate for otherwise valid,
/// supported Agent operations. Agent/host approval and safety policy remain
/// independent from this setting.
public enum VaultApprovalMode: String, Codable, CaseIterable, Sendable {
    case approvalRequired
    case noApproval
}

/// Cross-process approval-mode state backed by one owner-readable file. The App
/// writes the setting; the daemon re-reads it at every authorization boundary,
/// so a running Agent cannot keep using a stale in-memory mode after the user
/// changes the first-page control.
public final class VaultApprovalModeState: @unchecked Sendable {
    public static let shared = VaultApprovalModeState()

    public static var defaultStorageURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/AgentSecretVault", isDirectory: true)
            .appendingPathComponent("approval-mode.json", isDirectory: false)
            .standardizedFileURL
    }

    private let lock = NSLock()
    private var storedMode: VaultApprovalMode
    private var storageURL: URL?

    public init(storageURL: URL? = VaultApprovalModeState.defaultStorageURL) {
        let normalized = storageURL?.standardizedFileURL
        self.storageURL = normalized
        self.storedMode = Self.load(from: normalized) ?? .approvalRequired
    }

    public var mode: VaultApprovalMode {
        lock.lock()
        defer { lock.unlock() }
        // Missing/corrupt state always fails closed. Re-read on every access so
        // the independent App and daemon processes observe changes immediately.
        storedMode = Self.load(from: storageURL) ?? .approvalRequired
        return storedMode
    }

    /// Repoints the process-local reader to the daemon configuration's state
    /// file. Tests use temporary vault roots; production resolves to the same
    /// default location used by the GUI App.
    public func configure(storageURL: URL?) {
        lock.lock()
        defer { lock.unlock() }
        self.storageURL = storageURL?.standardizedFileURL
        storedMode = Self.load(from: self.storageURL) ?? .approvalRequired
    }

    @discardableResult
    public func setMode(_ mode: VaultApprovalMode) throws -> VaultApprovalMode {
        lock.lock()
        defer { lock.unlock() }

        if let storageURL {
            let directory = storageURL.deletingLastPathComponent()
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o700],
                ofItemAtPath: directory.path
            )
            let payload = try JSONEncoder().encode(PersistedState(version: 1, mode: mode))
            try payload.write(to: storageURL, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: storageURL.path
            )
        }
        storedMode = mode
        return mode
    }

    private struct PersistedState: Codable {
        let version: Int
        let mode: VaultApprovalMode
    }

    private static func load(from storageURL: URL?) -> VaultApprovalMode? {
        guard let storageURL,
              let data = try? Data(contentsOf: storageURL),
              let state = try? JSONDecoder().decode(PersistedState.self, from: data),
              state.version == 1 else {
            return nil
        }
        return state.mode
    }
}
