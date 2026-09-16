import Foundation
import LocalAuthentication
import Security

public protocol DeviceKeyStoring: Sendable {
    func deviceKey(reason: String) async throws -> Data

    /// Returns compatible key material candidates after one authentication.
    /// The first candidate is canonical; additional candidates are only for
    /// migration from an older Keychain namespace.
    func deviceKeyCandidates(reason: String) async throws -> [Data]

    /// Uses an already evaluated owner-authentication context when the caller
    /// has one for this exact logical operation. Implementations that do not
    /// interact with Keychain may safely use the compatibility default.
    func deviceKeyCandidates(
        reason: String,
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data]

    /// Promotes key material only after the vault layer has proved that these
    /// exact bytes open the current master-key wrapper and records. Lightweight
    /// stores may keep the default no-op implementation.
    func promoteVerifiedDeviceKey(_ keyData: Data) async throws
}

public extension DeviceKeyStoring {
    func deviceKeyCandidates(reason: String) async throws -> [Data] {
        [try await deviceKey(reason: reason)]
    }

    func deviceKeyCandidates(
        reason: String,
        authenticationContext _: LocalAuthenticationContext?
    ) async throws -> [Data] {
        try await deviceKeyCandidates(reason: reason)
    }

    func promoteVerifiedDeviceKey(_: Data) async throws {}
}

public protocol DeviceKeyMaterialStoring: Sendable {
    func loadOrCreateDeviceKeyData() async throws -> Data

    /// The default keeps lightweight test stores source-compatible. The
    /// production Keychain store overrides it to use the already evaluated
    /// LAContext for every Security query in this operation.
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data

    func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data]

    /// Persists a candidate into the current non-interactive namespace only
    /// after the caller has cryptographically verified it against the vault.
    func promoteVerifiedDeviceKeyData(_ keyData: Data) async throws
}

public extension DeviceKeyMaterialStoring {
    func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data {
        try await loadOrCreateDeviceKeyData()
    }

    func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        [try await loadOrCreateDeviceKeyData(authenticationContext: authenticationContext)]
    }

    func promoteVerifiedDeviceKeyData(_: Data) async throws {}
}

protocol KeychainClient: Sendable {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?)
    func copyAttributes(_ query: [String: Any]) -> (status: OSStatus, attributes: [String: Any]?)
    func add(_ attributes: [String: Any]) -> OSStatus
}

public enum DeviceKeyStoreError: Error, Equatable, Sendable {
    case invalidKeySize(Int)
    case randomGenerationFailed(OSStatus)
    case accessControlCreationFailed
    case authenticationRequired
    case unsupportedRequiredKeychainControls
    case automaticKeyConflict
    case keychain(OSStatus)
}

public struct DeviceKeyStore: DeviceKeyStoring {
    private let authenticator: any BiometricAuthorizing
    private let materialStore: any DeviceKeyMaterialStoring

    public init(
        authenticator: any BiometricAuthorizing = LocalAuthenticator(),
        materialStore: any DeviceKeyMaterialStoring = KeychainDeviceKeyMaterialStore()
    ) {
        self.authenticator = authenticator
        self.materialStore = materialStore
    }

    public func deviceKey(reason: String) async throws -> Data {
        guard let key = try await deviceKeyCandidates(reason: reason).first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        return key
    }

    public func deviceKeyCandidates(reason: String) async throws -> [Data] {
        try await deviceKeyCandidates(reason: reason, authenticationContext: nil)
    }

    public func deviceKeyCandidates(
        reason: String,
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        let keys: [Data]
        do {
            keys = try await materialStore.loadDeviceKeyDataCandidates(
                authenticationContext: authenticationContext
            )
        } catch DeviceKeyStoreError.authenticationRequired {
            // An owner-authenticated context supplied by the operation
            // approver is the one and only system authentication for this
            // request. Do not silently create a second LAContext if a legacy
            // Keychain item rejects that context; surface the technical error
            // instead.
            if authenticationContext != nil {
                throw DeviceKeyStoreError.authenticationRequired
            }
            // Current wrapping keys live in an ordinary
            // WhenUnlockedThisDeviceOnly namespace and never need a biometric
            // prompt. A one-time prompt is retained only to read an older
            // userPresence item. The caller must still verify which candidate
            // actually opens the current vault before promoting it.
            if let contextAuthorizer = authenticator as? any KeychainContextAuthorizing {
                let context = try await contextAuthorizer.makeAuthenticationContext(reason: reason)
                keys = try await materialStore.loadDeviceKeyDataCandidates(
                    authenticationContext: context
                )
            } else {
                try await authenticator.evaluate(reason: reason)
                keys = try await materialStore.loadDeviceKeyDataCandidates(
                    authenticationContext: nil
                )
            }
        }

        guard !keys.isEmpty else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        for key in keys where key.count != 32 {
            throw DeviceKeyStoreError.invalidKeySize(key.count)
        }
        return keys
    }

    public func promoteVerifiedDeviceKey(_ keyData: Data) async throws {
        guard keyData.count == 32 else {
            throw DeviceKeyStoreError.invalidKeySize(keyData.count)
        }
        try await materialStore.promoteVerifiedDeviceKeyData(keyData)
    }
}

public struct KeychainDeviceKeyMaterialStore: DeviceKeyMaterialStoring {
    public let service: String
    public let account: String
    private let automaticService: String
    private let keychain: any KeychainClient
    private let randomKeyDataProvider: @Sendable () throws -> Data

    public init(
        service: String = "com.agent-secret-vault.device-key",
        account: String = "device-wrapping-key"
    ) {
        self.init(
            service: service,
            account: account,
            keychain: SystemKeychainClient(),
            randomKeyData: Self.randomKeyData
        )
    }

    init(
        service: String,
        account: String,
        keychain: any KeychainClient,
        randomKeyData: @escaping @Sendable () throws -> Data
    ) {
        self.service = service
        self.account = account
        self.automaticService = "\(service).automatic-v2"
        self.keychain = keychain
        self.randomKeyDataProvider = randomKeyData
    }

    public func loadOrCreateDeviceKeyData() async throws -> Data {
        try await loadOrCreateDeviceKeyData(authenticationContext: nil)
    }

    public func loadOrCreateDeviceKeyData(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> Data {
        guard let key = try await loadDeviceKeyDataCandidates(
            authenticationContext: authenticationContext
        ).first else {
            throw DeviceKeyStoreError.keychain(errSecItemNotFound)
        }
        return key
    }

    public func loadDeviceKeyDataCandidates(
        authenticationContext: LocalAuthenticationContext?
    ) async throws -> [Data] {
        // The v2 namespace is intentionally non-interactive. If it exists,
        // return it without probing any legacy userPresence item.
        if let automatic = try readKeyData(
            from: automaticBaseQuery,
            authenticationContext: authenticationContext,
            tolerateUnsupportedControls: false,
            interactionRequiresAuthentication: false
        ) {
            return [automatic]
        }

        var candidates: [Data] = []

        if let legacy = try readKeyData(
            from: legacyBaseQuery,
            authenticationContext: authenticationContext,
            tolerateUnsupportedControls: false,
            interactionRequiresAuthentication: true
        ) {
            candidates.append(legacy)
        }

        // A development build used the Data Protection Keychain without a
        // shared access group. Read it only as a migration candidate. Do not
        // persist either legacy candidate here: only the vault layer knows
        // which bytes actually open the current wrapper and records.
        if let dataProtection = try readKeyData(
            from: dataProtectionBaseQuery,
            authenticationContext: authenticationContext,
            tolerateUnsupportedControls: true,
            interactionRequiresAuthentication: false
        ), !candidates.contains(dataProtection) {
            candidates.append(dataProtection)
        }

        if !candidates.isEmpty {
            return candidates
        }

        let keyData = try randomKeyDataProvider()
        do {
            try saveAutomaticKeyData(keyData)
            return [keyData]
        } catch DeviceKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try readKeyData(
                from: automaticBaseQuery,
                authenticationContext: authenticationContext,
                tolerateUnsupportedControls: false,
                interactionRequiresAuthentication: false
            ) else {
                throw DeviceKeyStoreError.keychain(errSecItemNotFound)
            }
            return [existing]
        }
    }

    public func promoteVerifiedDeviceKeyData(_ keyData: Data) async throws {
        guard keyData.count == 32 else {
            throw DeviceKeyStoreError.invalidKeySize(keyData.count)
        }
        if let existing = try readKeyData(
            from: automaticBaseQuery,
            authenticationContext: nil,
            tolerateUnsupportedControls: false,
            interactionRequiresAuthentication: false
        ) {
            guard existing == keyData else {
                throw DeviceKeyStoreError.automaticKeyConflict
            }
            return
        }

        do {
            try saveAutomaticKeyData(keyData)
        } catch DeviceKeyStoreError.keychain(errSecDuplicateItem) {
            guard let existing = try readKeyData(
                from: automaticBaseQuery,
                authenticationContext: nil,
                tolerateUnsupportedControls: false,
                interactionRequiresAuthentication: false
            ), existing == keyData else {
                throw DeviceKeyStoreError.automaticKeyConflict
            }
        }
    }

    private func readKeyData(
        from baseQuery: [String: Any],
        authenticationContext: LocalAuthenticationContext?,
        tolerateUnsupportedControls: Bool,
        interactionRequiresAuthentication: Bool
    ) throws -> Data? {
        var query = baseQuery
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext.rawContext
        }

        let result = keychain.copyMatching(query)

        switch result.status {
        case errSecSuccess:
            guard let data = result.data else {
                throw DeviceKeyStoreError.keychain(result.status)
            }
            var attributesQuery = baseQuery
            attributesQuery[kSecReturnAttributes as String] = kCFBooleanTrue
            attributesQuery[kSecMatchLimit as String] = kSecMatchLimitOne
            if let authenticationContext {
                attributesQuery[kSecUseAuthenticationContext as String] = authenticationContext.rawContext
            }
            _ = keychain.copyAttributes(attributesQuery)
            return data
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed:
            if interactionRequiresAuthentication {
                throw DeviceKeyStoreError.authenticationRequired
            }
            if tolerateUnsupportedControls {
                return nil
            }
            // The current automatic namespace is deliberately non-interactive.
            // If macOS says it is unavailable (for example while the login
            // Keychain is locked), surface a technical failure rather than
            // manufacturing a biometric prompt.
            throw DeviceKeyStoreError.keychain(result.status)
        case errSecMissingEntitlement, errSecParam, errSecNotAvailable:
            if tolerateUnsupportedControls {
                return nil
            }
            throw DeviceKeyStoreError.unsupportedRequiredKeychainControls
        default:
            throw DeviceKeyStoreError.keychain(result.status)
        }
    }

    private func saveAutomaticKeyData(_ keyData: Data) throws {
        var attributes = automaticBaseQuery
        attributes[kSecValueData as String] = keyData
        // AUTO execution depends on the already-unlocked macOS login session,
        // not on per-operation userPresence. High-risk operations still obtain
        // an explicit LocalAuthentication decision through OperationApprover.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = keychain.add(attributes)
        guard status == errSecSuccess else {
            throw DeviceKeyStoreError.keychain(status)
        }
    }

    private var automaticBaseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: automaticService,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }

    private var legacyBaseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }

    private var dataProtectionBaseQuery: [String: Any] {
        var query = legacyBaseQuery
        query[kSecUseDataProtectionKeychain as String] = true
        return query
    }

    private func makeAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.userPresence],
            &error
        ) else {
            error?.release()
            throw DeviceKeyStoreError.accessControlCreationFailed
        }

        return accessControl
    }

    private static func randomKeyData() throws -> Data {
        var data = Data(count: 32)
        let status = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }

            return SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
        }

        guard status == errSecSuccess else {
            throw DeviceKeyStoreError.randomGenerationFailed(status)
        }

        return data
    }
}

struct SystemKeychainClient: KeychainClient {
    func copyMatching(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? Data)
    }

    func copyAttributes(_ query: [String: Any]) -> (status: OSStatus, attributes: [String: Any]?) {
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        return (status, item as? [String: Any])
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        SecItemAdd(attributes as CFDictionary, nil)
    }
}
