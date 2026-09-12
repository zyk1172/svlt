import Foundation
import VaultCore

/// One generated Entry and the caller-owned correlation key used by an
/// atomic structure request. The key is never persisted in the Catalog.
struct CatalogStructureEntryCandidate: Equatable, Sendable {
    let clientKey: String
    let entry: SecretCatalogEntry
}

/// The in-memory result of validating and constructing a safe Catalog
/// structure mutation. It contains no authorization state, file I/O, or
/// plaintext secret input.
struct CatalogStructureCandidate: Equatable, Sendable {
    let index: SecretCatalogIndex
    let entries: [CatalogStructureEntryCandidate]
    let mutation: CatalogBatchMutation
}

struct CatalogSecretPlaceholderCandidate: Equatable, Sendable {
    let field: SecretCatalogFieldValue
    let entry: SecretCatalogEntry
}

/// Builds Catalog candidates before the service performs policy evaluation,
/// owner approval, and the authoritative store commit.
///
/// Keeping these rules in a stateless boundary makes the security-sensitive
/// distinction between metadata/placeholder construction and secret binding
/// independently testable. No function in this type encrypts, decrypts, or
/// performs I/O; callers remain responsible for validating any sensitive
/// fields before asking this type to construct a model.
enum CatalogMutationCandidateBuilder {
    static func makeEntry(from request: CatalogDraftRequest) throws -> SecretCatalogEntry {
        try SecretCatalogEntry.generated(
            indexId: request.indexID,
            title: request.title,
            type: request.type,
            aliases: request.aliases,
            endpoints: request.endpoints,
            fields: request.fields,
            notes: request.notes,
            tags: request.tags
        )
    }

    static func makeStructure(
        from request: CatalogCreateStructureRequest
    ) throws -> CatalogStructureCandidate {
        var clientKeys = Set<String>()
        for entry in request.entries {
            guard !entry.clientKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  clientKeys.insert(entry.clientKey).inserted,
                  entry.fields.allSatisfy({ field in
                      field.secretRef == nil && !(field.type.isSecret && field.value != nil)
                  })
            else {
                throw SecretCatalogAgentError.invalidOperation
            }
        }

        do {
            let index = try SecretCatalogIndex.generated(
                title: request.index.title,
                aliases: request.index.aliases,
                tags: request.index.tags
            )
            var entries: [CatalogStructureEntryCandidate] = []
            entries.reserveCapacity(request.entries.count)
            for item in request.entries {
                let entry = try SecretCatalogEntry.generated(
                    indexId: index.id,
                    title: item.title,
                    type: item.type,
                    aliases: item.aliases,
                    endpoints: item.endpoints,
                    fields: item.fields,
                    notes: item.notes,
                    tags: item.tags
                )
                entries.append(CatalogStructureEntryCandidate(clientKey: item.clientKey, entry: entry))
            }
            let mutation = CatalogBatchMutation(
                operations: [.createIndex(index)] + entries.map { .createEntry($0.entry) }
            )
            return CatalogStructureCandidate(index: index, entries: entries, mutation: mutation)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
    }

    static func patchMetadata(
        _ entry: SecretCatalogEntry,
        with patch: CatalogMetadataPatch
    ) throws -> SecretCatalogEntry {
        var fields = entry.fields
        if let incomingFields = patch.fields {
            for incoming in incomingFields {
                if let offset = fields.firstIndex(where: { $0.key == incoming.key }) {
                    let current = fields[offset]
                    guard !current.type.isSecret,
                          !incoming.type.isSecret,
                          current.secretRef == nil,
                          incoming.secretRef == nil
                    else {
                        throw SecretCatalogAgentError.approvalRequired
                    }
                    fields[offset] = incoming
                } else {
                    if incoming.type.isSecret {
                        guard incoming.value == nil, incoming.secretRef == nil else {
                            throw SecretCatalogAgentError.approvalRequired
                        }
                    } else {
                        guard incoming.secretRef == nil else {
                            throw SecretCatalogAgentError.approvalRequired
                        }
                    }
                    fields.append(incoming)
                }
            }
        }

        return SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: patch.title ?? entry.title,
            type: entry.type,
            aliases: patch.aliases ?? entry.aliases,
            endpoints: patch.endpoints ?? entry.endpoints,
            fields: fields,
            notes: patch.notes ?? entry.notes,
            tags: patch.tags ?? entry.tags,
            schema: entry.schema
        )
    }

    static func addingSecretPlaceholder(
        to entry: SecretCatalogEntry,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool
    ) throws -> CatalogSecretPlaceholderCandidate {
        guard !entry.fields.contains(where: { $0.key == key }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let field = SecretCatalogFieldValue(
            key: key,
            label: label,
            type: .secret,
            agentVisible: agentVisible,
            searchable: searchable
        )
        return CatalogSecretPlaceholderCandidate(
            field: field,
            entry: SecretCatalogEntry(
                id: entry.id,
                indexId: entry.indexId,
                title: entry.title,
                type: entry.type,
                aliases: entry.aliases,
                endpoints: entry.endpoints,
                fields: entry.fields + [field],
                notes: entry.notes,
                tags: entry.tags,
                schema: entry.schema
            )
        )
    }

    static func sensitiveChangeNeedsApproval(
        from oldEntry: SecretCatalogEntry,
        to newEntry: SecretCatalogEntry
    ) -> Bool {
        let oldFields = Dictionary(uniqueKeysWithValues: oldEntry.fields.map { ($0.key, $0) })
        let newFields = Dictionary(uniqueKeysWithValues: newEntry.fields.map { ($0.key, $0) })
        for key in Set(oldFields.keys).union(newFields.keys) {
            let oldField = oldFields[key]
            let newField = newFields[key]
            if oldField == nil, newField?.type.isSecret == true, newField?.secretRef == nil {
                // A new empty placeholder is intentionally silent; the user
                // fills its value through the secure App-control form later.
                continue
            }
            if oldField?.type.isSecret == true || newField?.type.isSecret == true {
                guard let oldField, let newField else { return true }
                if oldField.type != newField.type || oldField.secretRef != newField.secretRef {
                    return true
                }
            }
        }
        return false
    }
}
