import Foundation
import VaultAuthorization
import VaultCore

/// Keeps only in-memory wrapping keys. These cache windows are key-availability
/// optimizations, not Agent operation authorization leases. Ordinary
/// effect-based `AUTO` operations may reuse a cached wrapping key, but every
/// operation still goes through principal, Secret binding, destination,
/// protocol, and effect policy evaluation. No key is written to disk or
/// UserDefaults.
public actor AppProtectionKeyStore {
    private struct CachedKey: Sendable {
        var data: Data
        let expiresAt: Date
    }

    private let deviceKeyStore: any DeviceKeyStoring
    private let credentialTTL: TimeInterval
    private let externalSendTTL: TimeInterval
    private let now: @Sendable () -> Date
    private var lowProtectionKey: Data?
    private var credentialKey: CachedKey?
    private var externalSendKey: CachedKey?

    public init(
        deviceKeyStore: any DeviceKeyStoring,
        credentialTTL: TimeInterval = 600,
        externalSendTTL: TimeInterval = 60,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.deviceKeyStore = deviceKeyStore
        self.credentialTTL = credentialTTL
        self.externalSendTTL = externalSendTTL
        self.now = now
    }

    public var isLowProtectionUnlocked: Bool {
        lowProtectionKey != nil
    }

    public var isUnlocked: Bool {
        let credentialActive = credentialKey.map { now() < $0.expiresAt } ?? false
        let externalActive = externalSendKey.map { now() < $0.expiresAt } ?? false
        return lowProtectionKey != nil || credentialActive || externalActive
    }

    /// Retained for explicit UI unlock actions. The daemon never calls this at
    /// startup; normal operation enters through `deviceKey(for:)` lazily.
    public func unlockLowProtection(reason: String = "打开知识库密文保险箱") async throws {
        _ = try await deviceKey(for: .read, reason: reason)
    }

    public func deviceKey(
        for policy: SecretPolicy,
        reason: String,
        destination: String? = nil,
        authenticationContext: LocalAuthenticationContext? = nil
    ) async throws -> Data {
        let candidates = try await deviceKeyCandidates(
            for: policy,
            reason: reason,
            destination: destination,
            authenticationContext: authenticationContext
        )
        guard let key = candidates.first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        rememberDeviceKey(key, for: policy, destination: destination)
        return key
    }

    /// Returns all compatible local Keychain candidates after one
    /// authentication. The daemon can prove which candidate opens the
    /// existing wrapper/records before caching it.
    public func deviceKeyCandidates(
        for policy: SecretPolicy,
        reason: String,
        destination _: String? = nil,
        authenticationContext: LocalAuthenticationContext? = nil
    ) async throws -> [Data] {
        switch policy {
        case .read:
            if let lowProtectionKey {
                return [lowProtectionKey]
            }
            return try await deviceKeyStore.deviceKeyCandidates(
                reason: "打开知识库密文保险箱",
                authenticationContext: authenticationContext
            )
        case .credential:
            if let credentialKey, now() < credentialKey.expiresAt {
                return [credentialKey.data]
            }
            self.credentialKey = nil
            return try await deviceKeyStore.deviceKeyCandidates(
                reason: reason,
                authenticationContext: authenticationContext
            )
        case .externalSend:
            // This cache contains only the vault wrapping key, not an
            // authorization grant. The wrapping key is vault-global, while
            // destination/Secret/protocol authorization is re-evaluated by
            // SecretOperationPolicyEngine for every operation. Keeping the key
            // cache destination-scoped made the production provider miss the
            // cache whenever the provider signature omitted destination, which
            // caused repeated Keychain/Touch ID work without adding a real
            // security boundary.
            if let externalSendKey, now() < externalSendKey.expiresAt {
                return [externalSendKey.data]
            }
            self.externalSendKey = nil
            return try await deviceKeyStore.deviceKeyCandidates(
                reason: reason,
                authenticationContext: authenticationContext
            )
        }
    }

    /// High-risk operations bypass every cached window and do not repopulate
    /// it. This is used for deletion, export, and security-setting changes.
    public func freshDeviceKey(
        for policy: SecretPolicy,
        reason: String,
        authenticationContext: LocalAuthenticationContext? = nil
    ) async throws -> Data {
        let candidates = try await freshDeviceKeyCandidates(
            for: policy,
            reason: reason,
            authenticationContext: authenticationContext
        )
        guard let key = candidates.first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        return key
    }

    public func freshDeviceKeyCandidates(
        for policy: SecretPolicy,
        reason: String,
        authenticationContext: LocalAuthenticationContext? = nil
    ) async throws -> [Data] {
        clearCachedKey(for: policy)
        return try await deviceKeyCandidates(
            for: policy,
            reason: reason,
            authenticationContext: authenticationContext
        )
    }

    /// Caches only the candidate that opened the vault. Failed migration
    /// candidates therefore never become the session key.
    public func rememberDeviceKey(
        _ key: Data,
        for policy: SecretPolicy,
        destination _: String? = nil
    ) {
        switch policy {
        case .read:
            lowProtectionKey = key
        case .credential:
            guard credentialTTL > 0 else {
                return
            }
            credentialKey = CachedKey(
                data: key,
                expiresAt: now().addingTimeInterval(credentialTTL)
            )
        case .externalSend:
            guard externalSendTTL > 0 else {
                return
            }
            externalSendKey = CachedKey(
                data: key,
                expiresAt: now().addingTimeInterval(externalSendTTL)
            )
        }
    }

    public func clearLowProtectionUnlock() {
        clear(&lowProtectionKey)
    }

    public func clearAll() {
        clear(&lowProtectionKey)
        clearCachedKey(for: .credential)
        clearCachedKey(for: .externalSend)
    }

    private func clearCachedKey(for policy: SecretPolicy) {
        switch policy {
        case .read:
            clear(&lowProtectionKey)
        case .credential:
            if var cached = credentialKey {
                cached.data.resetBytes(in: 0..<cached.data.count)
            }
            credentialKey = nil
        case .externalSend:
            if var cached = externalSendKey {
                cached.data.resetBytes(in: 0..<cached.data.count)
            }
            externalSendKey = nil
        }
    }

    private func clear(_ data: inout Data?) {
        guard data != nil else {
            return
        }
        let count = data?.count ?? 0
        data?.resetBytes(in: 0..<count)
        data = nil
    }
}
