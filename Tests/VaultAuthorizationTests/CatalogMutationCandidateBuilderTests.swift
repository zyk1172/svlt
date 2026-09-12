import Testing
import VaultCore
@testable import VaultService

private let candidateIndexID = "0123456789ABCDEFGHJKMNPQRS"
private let candidateEntryID = "0123456789ABCDEFGHJKMNPQRT"
private let candidateSecretRef = "secret://0123456789ABCDEFGHJKMNPQRS"

@Test func candidateBuilderCreatesAnOpaqueEntryFromSafeMetadata() throws {
    let request = CatalogDraftRequest(
        indexID: candidateIndexID,
        title: "媒体服务器",
        type: "service",
        aliases: ["media"],
        tags: ["home"],
        endpoints: [CatalogEndpoint(type: "https", host: "media.home", port: 443)],
        notes: "普通说明",
        fields: [
            SecretCatalogFieldValue(
                key: "username",
                label: "用户名",
                type: .text,
                value: .string("operator")
            ),
            SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
        ]
    )

    let entry = try CatalogMutationCandidateBuilder.makeEntry(from: request)

    #expect(entry.id.count == SecretCatalogOpaqueID.length)
    #expect(entry.indexId == candidateIndexID)
    #expect(entry.title == request.title)
    #expect(entry.endpoints == request.endpoints)
    #expect(entry.fields == request.fields)
    #expect(entry.fields.first(where: { $0.key == "password" })?.value == nil)
    #expect(entry.fields.first(where: { $0.key == "password" })?.secretRef == nil)
}

@Test func candidateBuilderCreatesOneAtomicStructureAndKeepsClientKeysOutOfTheMutation() throws {
    let candidate = try CatalogMutationCandidateBuilder.makeStructure(from: CatalogCreateStructureRequest(
        index: CatalogStructureIndexRequest(title: "服务"),
        entries: [
            CatalogStructureEntryRequest(
                clientKey: "qnap",
                title: "QNAP",
                endpoints: [CatalogEndpoint(type: "https", host: "nas.home", port: 443)],
                fields: [SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)]
            ),
            CatalogStructureEntryRequest(clientKey: "redis", title: "Redis")
        ]
    ))

    #expect(candidate.index.id.count == SecretCatalogOpaqueID.length)
    #expect(candidate.entries.map(\.clientKey) == ["qnap", "redis"])
    #expect(candidate.entries.allSatisfy { $0.entry.indexId == candidate.index.id })
    #expect(candidate.mutation.operations.count == 3)
    #expect(candidate.mutation.operations.allSatisfy { operation in
        if case .createEntry = operation { return true }
        if case .createIndex = operation { return true }
        return false
    })
    #expect(candidate.entries.first?.entry.fields.first?.secretRef == nil)
}

@Test func candidateBuilderRejectsSecretPayloadsOnTheSafeStructurePath() {
    let plaintextRequest = CatalogCreateStructureRequest(
        index: CatalogStructureIndexRequest(title: "服务"),
        entries: [CatalogStructureEntryRequest(
            clientKey: "qnap",
            title: "QNAP",
            fields: [SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                value: .string("should-not-be-a-catalog-value")
            )]
        )]
    )
    #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try CatalogMutationCandidateBuilder.makeStructure(from: plaintextRequest)
    }

    let referenceRequest = CatalogCreateStructureRequest(
        index: CatalogStructureIndexRequest(title: "服务"),
        entries: [CatalogStructureEntryRequest(
            clientKey: "qnap",
            title: "QNAP",
            fields: [SecretCatalogFieldValue(
                key: "password",
                label: "密码",
                type: .secret,
                secretRef: candidateSecretRef
            )]
        )]
    )
    #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try CatalogMutationCandidateBuilder.makeStructure(from: referenceRequest)
    }
}

@Test func candidateBuilderPatchesMetadataButKeepsSecretTransitionsOnApprovalPath() throws {
    let entry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("operator")),
        SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
    ])
    let patched = try CatalogMutationCandidateBuilder.patchMetadata(
        entry,
        with: CatalogMetadataPatch(
            title: "更新后的服务",
            fields: [
                SecretCatalogFieldValue(key: "username", label: "登录名", type: .text, value: .string("operator")),
                SecretCatalogFieldValue(key: "apiKey", label: "API Key", type: .secret)
            ]
        )
    )

    #expect(patched.title == "更新后的服务")
    #expect(patched.fields.count == 3)
    #expect(patched.fields.first(where: { $0.key == "username" })?.label == "登录名")
    #expect(patched.fields.first(where: { $0.key == "apiKey" })?.secretRef == nil)

    let replacement = CatalogMetadataPatch(fields: [
        SecretCatalogFieldValue(
            key: "password",
            label: "密码",
            type: .secret,
            secretRef: candidateSecretRef
        )
    ])
    #expect(throws: SecretCatalogAgentError.approvalRequired) {
        _ = try CatalogMutationCandidateBuilder.patchMetadata(entry, with: replacement)
    }
}

@Test func candidateBuilderAddsOnlyAnEmptySecretPlaceholder() throws {
    let entry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("operator"))
    ])
    let candidate = try CatalogMutationCandidateBuilder.addingSecretPlaceholder(
        to: entry,
        key: "password",
        label: "密码",
        agentVisible: false,
        searchable: false
    )

    #expect(candidate.field.type == .secret)
    #expect(candidate.field.value == nil)
    #expect(candidate.field.secretRef == nil)
    #expect(candidate.field.agentVisible == false)
    #expect(candidate.entry.fields.last == candidate.field)

    #expect(throws: SecretCatalogAgentError.invalidOperation) {
        _ = try CatalogMutationCandidateBuilder.addingSecretPlaceholder(
            to: candidate.entry,
            key: "password",
            label: "重复密码",
            agentVisible: true,
            searchable: true
        )
    }
}

@Test func candidateBuilderClassifiesSensitiveChangesWithoutTreatingPlaceholdersAsBindings() {
    let metadataEntry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text)
    ])
    let placeholderEntry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text),
        SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
    ])
    #expect(CatalogMutationCandidateBuilder.sensitiveChangeNeedsApproval(
        from: metadataEntry,
        to: placeholderEntry
    ) == false)

    let boundEntry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text),
        SecretCatalogFieldValue(key: "password", label: "密码", type: .secret, secretRef: candidateSecretRef)
    ])
    let relabeledBoundEntry = builderEntry(fields: [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text),
        SecretCatalogFieldValue(key: "password", label: "新的显示名", type: .secret, secretRef: candidateSecretRef)
    ])
    #expect(CatalogMutationCandidateBuilder.sensitiveChangeNeedsApproval(
        from: boundEntry,
        to: relabeledBoundEntry
    ) == false)
    #expect(CatalogMutationCandidateBuilder.sensitiveChangeNeedsApproval(
        from: boundEntry,
        to: metadataEntry
    ) == true)
}

private func builderEntry(fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(
        id: candidateEntryID,
        indexId: candidateIndexID,
        title: "服务",
        fields: fields
    )
}
