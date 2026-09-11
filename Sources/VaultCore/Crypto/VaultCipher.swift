import CryptoKit
import Foundation

public enum VaultCryptoError: Error, Equatable, Sendable {
    case integrityFailed
    case randomGenerationFailed
    case unsupportedFormatVersion(Int)
}

public struct VaultCipher: Sendable {
    public init() {}

    public func encrypt(
        _ plaintext: Data,
        id: String,
        version: Int,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String] = [],
        allowedProtocols: [String] = [],
        allowedBindings: [SecretDestinationBinding] = [],
        masterKey: SymmetricKey,
        formatVersion: Int = VaultFormat.current
    ) throws -> EncryptedRecord {
        let now = Date()
        return try encrypt(
            plaintext,
            id: id,
            version: version,
            label: label,
            policy: policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            allowedBindings: allowedBindings,
            masterKey: masterKey,
            formatVersion: formatVersion,
            createdAt: now,
            updatedAt: now
        )
    }

    /// Re-seals a record after an owner-approved destination/protocol binding
    /// change. Binding metadata is part of the AES-GCM authenticated data, so
    /// changing only the JSON fields would make the record undecryptable.
    /// The plaintext remains inside this process and is never returned to the
    /// caller or exposed through IPC.
    public func rebind(
        _ record: EncryptedRecord,
        allowedDestinations: [String],
        allowedProtocols: [String],
        allowedBindings: [SecretDestinationBinding],
        masterKey: SymmetricKey,
        updatedAt: Date = Date()
    ) throws -> EncryptedRecord {
        guard record.recordVersion < Int.max else {
            throw VaultCryptoError.integrityFailed
        }
        let plaintext = try decrypt(record, masterKey: masterKey)
        return try encrypt(
            plaintext,
            id: record.id,
            version: record.recordVersion + 1,
            label: record.label,
            policy: record.policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            allowedBindings: allowedBindings,
            masterKey: masterKey,
            formatVersion: VaultFormat.current,
            createdAt: record.createdAt,
            updatedAt: updatedAt
        )
    }

    private func encrypt(
        _ plaintext: Data,
        id: String,
        version: Int,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String],
        allowedBindings: [SecretDestinationBinding],
        masterKey: SymmetricKey,
        formatVersion: Int,
        createdAt: Date,
        updatedAt: Date
    ) throws -> EncryptedRecord {
        guard formatVersion == VaultFormat.legacyV1 || formatVersion == VaultFormat.current else {
            throw VaultCryptoError.unsupportedFormatVersion(formatVersion)
        }

        let dataKeyBytes = try RandomBytes.generate(count: 32)
        let dataKey = SymmetricKey(data: dataKeyBytes)
        let keyDerivationSalt = formatVersion >= 2 ? try RandomBytes.generate(count: 32) : nil
        let authenticatedData = Self.authenticatedData(
            formatVersion: formatVersion,
            id: id,
            recordVersion: version,
            label: label,
            policy: policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            allowedBindings: allowedBindings,
            policyBindingVersion: formatVersion >= 2 ? 1 : 0,
            createdAt: createdAt,
            updatedAt: updatedAt
        )

        let sealedPlaintext = try AES.GCM.seal(
            plaintext,
            using: dataKey,
            authenticating: authenticatedData
        )
        let wrappingKey = try Self.dataKeyWrappingKey(
            masterKey: masterKey,
            formatVersion: formatVersion,
            keyDerivationSalt: keyDerivationSalt,
            authenticatedData: authenticatedData
        )
        let wrappedDataKey = try AES.GCM.seal(
            dataKeyBytes,
            using: wrappingKey,
            authenticating: authenticatedData
        )

        return EncryptedRecord(
            formatVersion: formatVersion,
            id: id,
            recordVersion: version,
            ciphertext: sealedPlaintext.ciphertext,
            nonce: sealedPlaintext.nonce.data,
            tag: sealedPlaintext.tag,
            wrappedDataKey: wrappedDataKey.ciphertext,
            wrappedDataKeyNonce: wrappedDataKey.nonce.data,
            wrappedDataKeyTag: wrappedDataKey.tag,
            keyDerivationSalt: keyDerivationSalt,
            label: label,
            policy: policy,
            allowedDestinations: allowedDestinations,
            allowedProtocols: allowedProtocols,
            allowedBindings: allowedBindings,
            policyBindingVersion: formatVersion >= 2 ? 1 : 0,
            createdAt: createdAt,
            updatedAt: updatedAt
        )
    }

    public func decrypt(
        _ record: EncryptedRecord,
        masterKey: SymmetricKey
    ) throws -> Data {
        guard record.formatVersion == VaultFormat.legacyV1 || record.formatVersion == VaultFormat.current else {
            throw VaultCryptoError.unsupportedFormatVersion(record.formatVersion)
        }

        let authenticatedData = Self.authenticatedData(
            formatVersion: record.formatVersion,
            id: record.id,
            recordVersion: record.recordVersion,
            label: record.label,
            policy: record.policy,
            allowedDestinations: record.allowedDestinations,
            allowedProtocols: record.allowedProtocols,
            allowedBindings: record.allowedBindings,
            policyBindingVersion: record.policyBindingVersion,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )

        do {
            let wrappedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.wrappedDataKeyNonce),
                ciphertext: record.wrappedDataKey,
                tag: record.wrappedDataKeyTag
            )
            let wrappingKey = try Self.dataKeyWrappingKey(
                masterKey: masterKey,
                formatVersion: record.formatVersion,
                keyDerivationSalt: record.keyDerivationSalt,
                authenticatedData: authenticatedData
            )
            let dataKeyBytes = try AES.GCM.open(
                wrappedBox,
                using: wrappingKey,
                authenticating: authenticatedData
            )
            let dataKey = SymmetricKey(data: dataKeyBytes)
            let ciphertextBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.nonce),
                ciphertext: record.ciphertext,
                tag: record.tag
            )

            return try AES.GCM.open(
                ciphertextBox,
                using: dataKey,
                authenticating: authenticatedData
            )
        } catch {
            throw VaultCryptoError.integrityFailed
        }
    }

    private static func authenticatedData(
        formatVersion: Int,
        id: String,
        recordVersion: Int,
        label: String?,
        policy: SecretPolicy,
        allowedDestinations: [String],
        allowedProtocols: [String],
        allowedBindings: [SecretDestinationBinding],
        policyBindingVersion: Int,
        createdAt: Date,
        updatedAt: Date
    ) -> Data {
        var data = Data((formatVersion == VaultFormat.legacyV1
            ? "VaultCipher.EncryptedRecord.AAD.v1"
            : "VaultCipher.EncryptedRecord.AAD.v2").utf8)
        data.appendLengthPrefixed(Data(String(formatVersion).utf8))
        data.appendLengthPrefixed(Data(id.utf8))
        data.appendLengthPrefixed(Data(String(recordVersion).utf8))
        data.appendLengthPrefixed(label.map { Data($0.utf8) })
        data.appendLengthPrefixed(Data(policy.rawValue.utf8))
        data.appendLengthPrefixed(Data(String(createdAt.timeIntervalSinceReferenceDate.bitPattern).utf8))
        data.appendLengthPrefixed(Data(String(updatedAt.timeIntervalSinceReferenceDate.bitPattern).utf8))
        if policyBindingVersion > 0 {
            data.appendLengthPrefixed(Data(allowedDestinations.sorted().joined(separator: "\u{1F}" ).utf8))
            data.appendLengthPrefixed(Data(allowedProtocols.sorted().joined(separator: "\u{1F}" ).utf8))
        }
        // Keep the legacy AAD byte-for-byte stable when bindings contain no
        // profile metadata, but authenticate ports and SSH pins whenever they
        // are present. Otherwise an out-of-band edit could change the exact
        // host identity without invalidating the ciphertext.
        if !allowedBindings.isEmpty {
            let sortedBindings = allowedBindings.sorted {
                if $0.protocolType.rawValue == $1.protocolType.rawValue {
                    if $0.destination == $1.destination {
                        return ($0.port ?? 0) < ($1.port ?? 0)
                    }
                    return $0.destination < $1.destination
                }
                return $0.protocolType.rawValue < $1.protocolType.rawValue
            }
            data.appendLengthPrefixed(Data(String(sortedBindings.count).utf8))
            let hasProfileMetadata = sortedBindings.contains { $0.port != nil || $0.hostKeyPin != nil }
            if hasProfileMetadata {
                data.appendLengthPrefixed(Data("VaultCipher.Binding.v2".utf8))
            }
            for binding in sortedBindings {
                data.appendLengthPrefixed(Data(binding.protocolType.rawValue.utf8))
                data.appendLengthPrefixed(Data(binding.destination.utf8))
                if hasProfileMetadata {
                    data.appendLengthPrefixed(binding.port.map { Data(String($0).utf8) })
                    data.appendLengthPrefixed(binding.hostKeyPin.map {
                        Data("\($0.algorithm)\u{1F}\($0.sha256)".utf8)
                    })
                }
            }
        }
        return data
    }

    private static func dataKeyWrappingKey(
        masterKey: SymmetricKey,
        formatVersion: Int,
        keyDerivationSalt: Data?,
        authenticatedData: Data
    ) throws -> SymmetricKey {
        if formatVersion == VaultFormat.legacyV1 {
            return masterKey
        }
        guard formatVersion == VaultFormat.current,
              let keyDerivationSalt,
              keyDerivationSalt.count >= 16
        else {
            throw VaultCryptoError.integrityFailed
        }

        var info = Data("AgentSecretVault.RecordWrappingKey.v2".utf8)
        info.append(authenticatedData)

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            salt: keyDerivationSalt,
            info: info,
            outputByteCount: 32
        )
    }
}

private extension AES.GCM.Nonce {
    var data: Data {
        withUnsafeBytes { Data($0) }
    }
}

private extension Data {
    mutating func appendLengthPrefixed(_ component: Data?) {
        if let component {
            appendUInt64(UInt64(component.count))
            append(component)
        } else {
            appendUInt64(UInt64.max)
        }
    }

    mutating func appendUInt64(_ value: UInt64) {
        var bigEndian = value.bigEndian
        Swift.withUnsafeBytes(of: &bigEndian) { append(contentsOf: $0) }
    }
}
