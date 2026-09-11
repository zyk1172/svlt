import CryptoKit
import Foundation
import VaultCore
import VaultIPC

public enum VaultRecordBindingError: Error, Equatable, Sendable {
    case authorizationCancelled
    case invalidReference
    case invalidDestination
    case tooManyDestinations
    case tooManyProtocols
    case tooManyBindings
}

public struct VaultRecordResolver: Sendable {
    private let recordStore: any RecordStore
    private let cipher: VaultCipher

    public init(recordStore: any RecordStore, cipher: VaultCipher = VaultCipher()) {
        self.recordStore = recordStore
        self.cipher = cipher
    }

    public func resolve(reference: String, masterKey: SymmetricKey) async throws -> Data {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        return try cipher.decrypt(record, masterKey: masterKey)
    }

    public func metadata(reference: String) async throws -> SecretReferenceMetadata {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        return metadata(for: parsed, record: record)
    }

    /// Adds one exact destination/protocol binding and re-seals the record so
    /// the binding stays covered by the record's authenticated data. The
    /// method never returns or logs the resolved plaintext.
    public func bindDestination(
        reference: String,
        destination: String,
        protocolType: SecretOperationProtocol,
        masterKey: SymmetricKey,
        port: Int? = nil,
        hostKeyPin: SSHHostKeyPin? = nil,
        now: Date = Date(),
        preCommitCheck: (@Sendable () async throws -> Void)? = nil
    ) async throws -> SecretReferenceMetadata {
        let parsed: SecretReference
        do {
            parsed = try SecretReference(reference)
        } catch {
            throw VaultRecordBindingError.invalidReference
        }

        guard let normalizedDestination = canonicalDestination(
            destination,
            protocolType: protocolType
        ) else {
            throw VaultRecordBindingError.invalidDestination
        }
        guard port.map({ (1...65_535).contains($0) }) ?? true,
              hostKeyPin == nil || protocolType.supportsSSHHostKeyPin else {
            throw VaultRecordBindingError.invalidDestination
        }

        let current = try await recordStore.latest(id: parsed.id)
        var destinations = current.allowedDestinations
        if !destinations.contains(where: {
            canonicalDestination($0, protocolType: protocolType) == normalizedDestination
        }) {
            destinations.append(normalizedDestination)
        }
        guard destinations.count <= 32 else {
            throw VaultRecordBindingError.tooManyDestinations
        }

        var protocols = current.allowedProtocols
        if !protocols.contains(where: { $0.caseInsensitiveCompare(protocolType.rawValue) == .orderedSame }) {
            protocols.append(protocolType.rawValue)
        }
        guard protocols.count <= 16 else {
            throw VaultRecordBindingError.tooManyProtocols
        }

        var bindings = current.allowedBindings
        if bindings.isEmpty {
            bindings = legacyBindings(
                destinations: current.allowedDestinations,
                protocols: current.allowedProtocols
            )
        }
        let binding = SecretDestinationBinding(
            protocolType: protocolType,
            destination: normalizedDestination,
            port: port,
            hostKeyPin: hostKeyPin
        )
        if let index = bindings.firstIndex(where: { sameProfile($0, binding) }) {
            // A normal destination bind must not accidentally remove an
            // existing owner-reviewed SSH pin. Supplying a pin is the
            // explicit replace operation.
            if hostKeyPin != nil || bindings[index].hostKeyPin == nil {
                bindings[index] = binding
            }
        } else {
            bindings.append(binding)
        }
        guard bindings.count <= 32 else {
            throw VaultRecordBindingError.tooManyBindings
        }

        guard destinations != current.allowedDestinations
                || protocols != current.allowedProtocols
                || bindings != current.allowedBindings else {
            return metadata(for: parsed, record: current)
        }

        let updated = try cipher.rebind(
            current,
            allowedDestinations: destinations,
            allowedProtocols: protocols,
            allowedBindings: bindings,
            masterKey: masterKey,
            updatedAt: now
        )
        // The caller owns the authorization generation. Check it after all
        // reads/crypto work and immediately before the persistence call so a
        // security invalidation cannot leave a durable binding reported as
        // CANCELLED. Once save starts, its result is authoritative.
        try await preCommitCheck?()
        try await recordStore.save(updated)
        return metadata(for: parsed, record: updated)
    }

    public func resolve(
        reference: String,
        masterKeyProvider: @Sendable (SecretPolicy) async throws -> SymmetricKey
    ) async throws -> Data {
        let parsed = try SecretReference(reference)
        let record = try await recordStore.latest(id: parsed.id)
        let masterKey = try await masterKeyProvider(record.policy)
        return try cipher.decrypt(record, masterKey: masterKey)
    }

    private func metadata(
        for reference: SecretReference,
        record: EncryptedRecord
    ) -> SecretReferenceMetadata {
        SecretReferenceMetadata(
            reference: reference.description,
            policy: record.policy,
            label: record.label,
            allowedDestinations: record.allowedDestinations,
            allowedProtocols: record.allowedProtocols,
            allowedBindings: record.allowedBindings,
            createdAt: record.createdAt,
            updatedAt: record.updatedAt
        )
    }

    private func canonicalDestination(
        _ destination: String,
        protocolType: SecretOperationProtocol
    ) -> String? {
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              trimmed.utf8.count <= 512,
              trimmed.unicodeScalars.allSatisfy({ $0.value >= 0x21 && $0.value != 0x7F })
        else {
            return nil
        }
        if protocolType == .http || protocolType == .https {
            return SecretOperationDescriptor.normalizeHTTPOrigin(
                trimmed,
                expectedScheme: protocolType.rawValue,
                requireExplicitPort: true
            )
        }
        guard !trimmed.contains("secret://") else { return nil }
        return SecretOperationDescriptor.normalizeDestination(trimmed)
    }

    private func legacyBindings(
        destinations: [String],
        protocols: [String]
    ) -> [SecretDestinationBinding] {
        guard protocols.count == 1 else { return [] }
        let marker = protocols[0].lowercased()
        let protocolType = marker == "http-loopback"
            ? SecretOperationProtocol.http
            : SecretOperationProtocol(rawValue: marker)
        guard let protocolType else { return [] }
        return destinations.compactMap { destination in
            guard let canonical = canonicalDestination(destination, protocolType: protocolType) else {
                return nil
            }
            return SecretDestinationBinding(
                protocolType: protocolType,
                destination: canonical
            )
        }
    }

    private func containsBinding(
        _ binding: SecretDestinationBinding,
        in existing: [SecretDestinationBinding]
    ) -> Bool {
        existing.contains { sameProfile($0, binding) }
    }

    private func sameProfile(
        _ lhs: SecretDestinationBinding,
        _ rhs: SecretDestinationBinding
    ) -> Bool {
        lhs.protocolType == rhs.protocolType
            && lhs.port == rhs.port
            && canonicalDestination(lhs.destination, protocolType: lhs.protocolType)
                == canonicalDestination(rhs.destination, protocolType: rhs.protocolType)
    }
}
