import CryptoKit
import Foundation
import os
import VaultAuthorization
import VaultCore
import VaultExecution
import VaultIPC

extension VaultAppServices {
    public func searchSecrets(
        query: String,
        field: SecretCatalogField?,
        limit: Int
    ) async throws -> SecretCatalogSearchResult {
        let snapshot = try await catalogSnapshotForAgent()
        let result = catalogSearchService.search(
            query: query,
            field: field,
            limit: limit,
            document: snapshot.document
        )
        await emitAudit(
            action: "搜索本机敏感信息目录",
            target: "catalog-search",
            referenceCount: result.matches.count,
            result: result.status.rawValue
        )
        return result
    }

    public func getCatalogEntry(entryID: String) async throws -> SecretCatalogSearchResult {
        let snapshot = try await catalogSnapshotForAgent()
        return catalogSearchService.get(entryID: entryID, document: snapshot.document)
    }

    public func listCatalogIndexes() async throws -> SecretCatalogIndexListResult {
        let snapshot = try await catalogSnapshotForAgent()
        return SecretCatalogIndexListResult(
            revision: snapshot.revision,
            indices: catalogSearchService.listIndexes(document: snapshot.document)
        )
    }

    public func listCatalogEntries(indexID: String) async throws -> SecretCatalogEntryListResult {
        let snapshot = try await catalogSnapshotForAgent()
        return catalogSearchService.listEntries(
            indexID: indexID,
            document: snapshot.document,
            revision: snapshot.revision
        )
    }

    /// Applies a batch as one semantic transaction: one authoritative read,
    /// one risk decision/approval, one store lock and one revision increment.
    public func applyCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await performCatalogBatch(
            mutation,
            expectedRevision: expectedRevision,
            requireAgentSafeWrite: true
        )
    }

    private func performCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64,
        requireAgentSafeWrite: Bool,
        authorizationOperation: CatalogAgentWriteOperation = .batchMutation,
        resultIndexID: String? = nil,
        resultEntryID: String? = nil
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            try await performCatalogBatch(
                mutation,
                expectedRevision: expectedRevision,
                requireAgentSafeWrite: requireAgentSafeWrite,
                authorizationOperation: authorizationOperation,
                resultIndexID: resultIndexID,
                resultEntryID: resultEntryID,
                operation: operation
            )
        }
    }

    private func performCatalogBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64,
        requireAgentSafeWrite: Bool,
        authorizationOperation: CatalogAgentWriteOperation,
        resultIndexID: String?,
        resultEntryID: String?,
        operation: CatalogDocumentOperation
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard snapshot.revision == expectedRevision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let next: SecretCatalogDocument
        do {
            next = try mutation.applying(to: snapshot.document)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext: AuditContext
        if requireAgentSafeWrite, !diff.isEmpty {
            let intent = CatalogAgentWriteIntent(
                operation: authorizationOperation,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            )
            operationContext = try await requestAgentCatalogAuthorization(intent, reasonCategory: .bulkImport)
        } else {
            operationContext = agentAuditContext()
        }
        try await authorizeCatalogDiff(
            diff,
            transport: .batchMutation,
            requireAgentSafeWrite: false
        )
        await emitCatalogMutationStarted(
            action: "批量修改目录",
            referenceCount: diff.referencedSecretRefs.count,
            context: operationContext
        )
        do {
            let updated = try await operation.applyBatch(mutation, expectedRevision: expectedRevision)
            await emitAudit(
                action: "批量修改目录",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                indexID: resultIndexID,
                entryID: resultEntryID,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(
                action: "批量修改目录",
                referenceCount: diff.referencedSecretRefs.count,
                context: operationContext
            )
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(
                action: "批量修改目录",
                referenceCount: diff.referencedSecretRefs.count,
                context: operationContext
            )
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Agent catalog creation binds approval to the generated index and the
    /// exact candidate semantic digest before committing it.
    public func createCatalogIndex(
        title: String,
        aliases: [String],
        tags: [String]
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            try await createCatalogIndex(
                title: title,
                aliases: aliases,
                tags: tags,
                operation: operation
            )
        }
    }

    private func createCatalogIndex(
        title: String,
        aliases: [String],
        tags: [String],
        operation: CatalogDocumentOperation
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        let index: SecretCatalogIndex
        do {
            index = try SecretCatalogIndex.generated(title: title, aliases: aliases, tags: tags)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let next = SecretCatalogDocument(indexes: snapshot.document.indexes + [index], entries: snapshot.document.entries)
        do { try next.validate() } catch { throw SecretCatalogAgentError.invalidOperation }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createIndex,
                indexID: index.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createIndex, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "创建目录分组", referenceCount: 0, context: operationContext)
        do {
            let updated = try await operation.createIndex(index, expectedRevision: snapshot.revision)
            await emitAudit(
                action: "创建目录分组",
                target: "catalog",
                referenceCount: 0,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                indexID: index.id,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as VaultCryptoError where error == .randomGenerationFailed {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .identifierGeneration, error: error)
            throw SecretCatalogAgentError.writeFailed
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "创建目录分组", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-index", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Creates one Index and all requested safe Entries as one semantic
    /// operation. The caller supplies only client correlation keys; SVLT
    /// generates every opaque ID before the single authorization and atomic
    /// store commit.
    public func createCatalogStructure(
        _ request: CatalogCreateStructureRequest
    ) async throws -> CatalogStructureWriteResult {
        try await withCatalogOperation { operation in
            try await createCatalogStructure(request, operation: operation)
        }
    }

    private func createCatalogStructure(
        _ request: CatalogCreateStructureRequest,
        operation: CatalogDocumentOperation
    ) async throws -> CatalogStructureWriteResult {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        let expectedRevision = request.expectedRevision ?? snapshot.revision
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }

        let candidate = try CatalogMutationCandidateBuilder.makeStructure(from: request)
        let index = candidate.index
        let generatedEntries = candidate.entries
        let mutation = candidate.mutation
        let next: SecretCatalogDocument
        do {
            next = try mutation.applying(to: snapshot.document)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createStructure,
                indexID: index.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .bulkImport
        )
        try await authorizeCatalogDiff(diff, transport: .batchMutation, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "创建目录结构", referenceCount: 0, context: operationContext)

        do {
            let updated = try await operation.applyBatch(mutation, expectedRevision: expectedRevision)
            await emitAudit(
                action: "创建目录结构",
                target: "catalog",
                referenceCount: 0,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogStructureWriteResult(
                indexID: index.id,
                entries: generatedEntries.map {
                    CatalogStructureEntryResult(clientKey: $0.clientKey, entryID: $0.entry.id)
                },
                revision: updated.revision,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录结构", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-structure", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "创建目录结构", referenceCount: 0, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-structure", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    /// Direct, single-call Agent creation for a safe Entry. Secret fields are
    /// accepted only as empty placeholders. Existing secret references and all
    /// plaintext secret values stay on their separate approval/secure-input
    /// paths.
    public func createCatalogEntry(_ request: CatalogDraftRequest) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            try await createCatalogEntry(request, operation: operation)
        }
    }

    private func createCatalogEntry(
        _ request: CatalogDraftRequest,
        operation: CatalogDocumentOperation
    ) async throws -> CatalogWriteResult {
        do {
            let containsSecretValue = request.fields.contains { $0.type.isSecret && $0.value != nil }
            for reference in request.fields.compactMap(\.secretRef) {
                guard (try? SecretReference(reference)) != nil else {
                    try catalogMutationPolicyEngine.requireSilent(
                        CatalogMutationDescriptor(kind: .forgedSecretReference)
                    )
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
            if containsSecretValue {
                try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .plaintextSecretInCatalog))
            }
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .inputValidation, error: error)
            throw error
        }

        let snapshot: SensitiveCatalogSnapshot
        do {
            snapshot = try await catalogSnapshotForAgent(using: operation)
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .snapshot, error: error)
            throw error
        }

        let entry: SecretCatalogEntry
        do {
            entry = try CatalogMutationCandidateBuilder.makeEntry(from: request)
        } catch {
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .model, error: error)
            throw error
        }

        let next: SecretCatalogDocument
        do {
            next = try snapshot.document.insertingEntryInSourceOrder(entry)
            try next.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .createEntry,
                indexID: entry.indexId,
                entryID: entry.id,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createEntry, requireAgentSafeWrite: false)
        let referenceCount = entry.fields.filter { $0.secretRef != nil }.count
        await emitCatalogMutationStarted(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)

        do {
            let updated = try await operation.createEntry(entry, expectedRevision: snapshot.revision)
            await emitAudit(
                action: "创建目录条目",
                target: "catalog",
                referenceCount: referenceCount,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry,
                entryID: entry.id,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .store, error: error)
            throw catalogAgentError(for: error)
        } catch let error as SecretCatalogAgentError {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            throw error
        } catch {
            await emitCatalogMutationFailed(action: "创建目录条目", referenceCount: referenceCount, context: operationContext)
            Self.logCatalogMutationFailure(operation: "catalog-create-entry", phase: .store, error: error)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func createCatalogDraft(
        _ request: CatalogDraftRequest
    ) async throws -> CatalogDraft {
        let operation = try await beginCatalogOperation()
        do {
            let snapshot = try await catalogSnapshotForAgent(using: operation)
            let containsReference = request.fields.contains { $0.secretRef != nil }
            let containsSecretValue = request.fields.contains { $0.type.isSecret && $0.value != nil }
            for reference in request.fields.compactMap(\.secretRef) {
                guard (try? SecretReference(reference)) != nil else {
                    try catalogMutationPolicyEngine.requireSilent(
                        CatalogMutationDescriptor(kind: .forgedSecretReference)
                    )
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
            if containsSecretValue {
                try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .plaintextSecretInCatalog))
            }
            if containsReference {
                try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .bindExistingSecret))
            }
            guard snapshot.document.indexes.contains(where: { $0.id == request.indexID }) else {
                throw SecretCatalogAgentError.invalidOperation
            }

            let entry = try CatalogMutationCandidateBuilder.makeEntry(from: request)
            let draftID = try SecretCatalogOpaqueID.generate()
            var draftDocument = snapshot.document
            draftDocument = SecretCatalogDocument(
                indexes: draftDocument.indexes,
                entries: draftDocument.entries + [entry]
            )
            try draftDocument.validate()
            pendingCatalogDrafts[draftID] = entry
            guard let match = catalogSearchService.get(entryID: entry.id, document: draftDocument).matches.first else {
                throw SecretCatalogAgentError.invalidOperation
            }
            pendingCatalogDraftDocumentPaths[draftID] = operation.selectedDocumentPath
            await endCatalogOperation(operation)
            return CatalogDraft(draftID: draftID, baseRevision: snapshot.revision, entry: match.entry)
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    public func patchCatalogMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            try await patchCatalogMetadata(
                entryID: entryID,
                patch: patch,
                expectedRevision: expectedRevision,
                operation: operation
            )
        }
    }

    private func patchCatalogMetadata(
        entryID: String,
        patch: CatalogMetadataPatch,
        expectedRevision: UInt64,
        operation: CatalogDocumentOperation
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard let oldEntry = snapshot.document.entries.first(where: { $0.id == entryID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let updated = try CatalogMutationCandidateBuilder.patchMetadata(oldEntry, with: patch)
        var entries = snapshot.document.entries
        guard let offset = entries.firstIndex(where: { $0.id == entryID }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        entries[offset] = updated
        let next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
        do { try next.validate() } catch { throw SecretCatalogAgentError.invalidOperation }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        try catalogMutationPolicyEngine.requireSilent(
            CatalogMutationDescriptor(kind: .patchMetadata)
        )
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .patchMetadata,
                indexID: updated.indexId,
                entryID: entryID,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .patchMetadata, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
        do {
            let updatedSnapshot = try await operation.updateEntry(updated, expectedRevision: expectedRevision)
            await emitAudit(
                action: "修改目录条目元数据",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry,
                entryID: entryID,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "修改目录条目元数据", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func commitCatalogDraft(
        _ draft: CatalogDraft,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        guard let pending = pendingCatalogDrafts[draft.draftID] else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let operation: CatalogDocumentOperation
        if let documentPath = pendingCatalogDraftDocumentPaths[draft.draftID] {
            operation = try await beginCatalogOperation(documentPath: documentPath)
        } else {
            operation = try await beginCatalogOperation()
        }
        var mutationFailureAudit: (referenceCount: Int, context: AuditContext)?
        do {
            let snapshot = try await catalogSnapshotForAgent(using: operation)
            guard expectedRevision == snapshot.revision,
                  draft.baseRevision == snapshot.revision,
                  draft.entry.id == pending.id,
                  draft.entry.indexId == pending.indexId
            else {
                throw SecretCatalogAgentError.revisionConflict
            }
            let next: SecretCatalogDocument
            do {
                next = try snapshot.document.insertingEntryInSourceOrder(pending)
                try next.validate()
            } catch {
                throw SecretCatalogAgentError.invalidOperation
            }
            let operationContext = try await requestAgentCatalogAuthorization(
                CatalogAgentWriteIntent(
                    operation: .commitDraft,
                    indexID: pending.indexId,
                    entryID: pending.id,
                    acceptedRevision: snapshot.revision,
                    candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
                ),
                reasonCategory: .knowledgeMaintenance
            )
            let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
            try await authorizeCatalogDiff(diff, transport: .createEntry, requireAgentSafeWrite: false)
            let referenceCount = diff.referencedSecretRefs.count
            await emitCatalogMutationStarted(action: "提交目录条目草稿", referenceCount: referenceCount, context: operationContext)
            mutationFailureAudit = (referenceCount, operationContext)
            let updatedSnapshot = try await operation.createEntry(pending, expectedRevision: expectedRevision)
            mutationFailureAudit = nil
            pendingCatalogDrafts.removeValue(forKey: draft.draftID)
            pendingCatalogDraftDocumentPaths.removeValue(forKey: draft.draftID)
            await emitAudit(
                action: "提交目录条目草稿",
                target: "catalog",
                referenceCount: referenceCount,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            let result = CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: pending.id, document: updatedSnapshot.document).matches.first?.entry,
                entryID: pending.id,
                validation: await postCommitCatalogValidation(using: operation)
            )
            await endCatalogOperation(operation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            if let audit = mutationFailureAudit {
                await emitCatalogMutationFailed(action: "提交目录条目草稿", referenceCount: audit.referenceCount, context: audit.context)
            }
            await endCatalogOperation(operation)
            throw catalogAgentError(for: error)
        } catch {
            if let audit = mutationFailureAudit {
                await emitCatalogMutationFailed(action: "提交目录条目草稿", referenceCount: audit.referenceCount, context: audit.context)
                await endCatalogOperation(operation)
                throw SecretCatalogAgentError.writeFailed
            }
            await endCatalogOperation(operation)
            throw error
        }
    }

    public func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            try await addCatalogSecretPlaceholder(
                entryID: entryID,
                key: key,
                label: label,
                agentVisible: agentVisible,
                searchable: searchable,
                expectedRevision: expectedRevision,
                operation: operation
            )
        }
    }

    private func addCatalogSecretPlaceholder(
        entryID: String,
        key: String,
        label: String,
        agentVisible: Bool,
        searchable: Bool,
        expectedRevision: UInt64,
        operation: CatalogDocumentOperation
    ) async throws -> CatalogWriteResult {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let candidate: CatalogSecretPlaceholderCandidate
        let next: SecretCatalogDocument
        do {
            guard let existingEntry = snapshot.document.entries.first(where: { $0.id == entryID }),
                  let offset = snapshot.document.entries.firstIndex(where: { $0.id == entryID })
            else { throw SecretCatalogAgentError.invalidOperation }
            candidate = try CatalogMutationCandidateBuilder.addingSecretPlaceholder(
                to: existingEntry,
                key: key,
                label: label,
                agentVisible: agentVisible,
                searchable: searchable
            )
            var entries = snapshot.document.entries
            entries[offset] = candidate.entry
            next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
            try next.validate()
        } catch let error as SecretCatalogAgentError {
            throw error
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        let operationContext = try await requestAgentCatalogAuthorization(
            CatalogAgentWriteIntent(
                operation: .addSecretPlaceholder,
                entryID: entryID,
                fieldKey: key,
                acceptedRevision: snapshot.revision,
                candidateSemanticSHA256: CatalogSemanticDigest.sha256(next)
            ),
            reasonCategory: .knowledgeMaintenance
        )
        try await authorizeCatalogDiff(diff, transport: .createSecretPlaceholder, requireAgentSafeWrite: false)
        await emitCatalogMutationStarted(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
        do {
            let updatedSnapshot = try await operation.addField(
                candidate.field,
                toEntryID: entryID,
                expectedRevision: expectedRevision
            )
            await emitAudit(
                action: "新增目录加密字段占位",
                target: "catalog",
                referenceCount: diff.referencedSecretRefs.count,
                result: "成功",
                context: operationContext,
                operation: .catalogMutation
            )
            return CatalogWriteResult(
                revision: updatedSnapshot.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updatedSnapshot.document).matches.first?.entry,
                entryID: entryID,
                validation: await postCommitCatalogValidation(using: operation)
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await emitCatalogMutationFailed(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw catalogAgentError(for: error)
        } catch {
            await emitCatalogMutationFailed(action: "新增目录加密字段占位", referenceCount: diff.referencedSecretRefs.count, context: operationContext)
            throw SecretCatalogAgentError.writeFailed
        }
    }

    public func bindCatalogExistingSecret(
        entryID _: String,
        key _: String,
        secretRef: String,
        expectedRevision _: UInt64
    ) async throws -> CatalogWriteResult {
        _ = try await catalogSnapshotForAgent()
        guard (try? SecretReference(secretRef)) != nil else {
            throw SecretCatalogAgentError.invalidOperation
        }
        // Binding an existing secret can change the destination/policy meaning
        // of a catalog entry.  It remains an App-approved operation; an Agent
        // cannot turn a self-reported user request into authorization.
        try catalogMutationPolicyEngine.requireSilent(CatalogMutationDescriptor(kind: .bindExistingSecret))
        throw SecretCatalogAgentError.approvalRequired
    }

    /// Every successful Agent-controlled Catalog write returns this summary so
    /// callers do not need a second MCP round trip merely to verify the commit.
    /// The store has already validated the candidate before replacing the
    /// document; this follow-up reads the authoritative post-commit state and
    /// preserves any integrity diagnostics without exposing document content.
    private func postCommitCatalogValidation(
        using operation: CatalogDocumentOperation
    ) async -> CatalogValidationResult {
        guard let report = try? await operation.validationReport() else {
            return CatalogValidationResult(status: .unavailable)
        }
        return CatalogValidationResult(
            status: report.status,
            revision: report.revision,
            rawSHA256: report.rawSHA256,
            pendingExternalChange: report.pendingExternalChange,
            diagnostics: report.diagnostics
        )
    }

    public func validateCatalog() async throws -> CatalogValidationResult {
        do {
            let report = try await withCatalogOperation { operation in
                try await operation.validationReport()
            }
            return CatalogValidationResult(
                status: report.status,
                revision: report.revision,
                rawSHA256: report.rawSHA256,
                pendingExternalChange: report.pendingExternalChange,
                diagnostics: report.diagnostics
            )
        } catch let error as SecretCatalogAgentError {
            switch error {
            case .unavailable:
                return CatalogValidationResult(status: .unavailable)
            default:
                return CatalogValidationResult(status: .invalidCatalog, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_VALIDATION_FAILED",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "敏感信息目录验证失败。",
                    hint: "请在 SVLT App 中检查目录状态。"
                )])
            }
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .noSelectedDocument:
                return CatalogValidationResult(status: .unavailable)
            case .writeFailed:
                return CatalogValidationResult(status: .unavailable, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_READ_UNAVAILABLE",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "无法读取敏感信息目录。",
                    hint: "请检查 App 选择的目录文件。"
                )])
            default:
                return CatalogValidationResult(status: .invalidCatalog, diagnostics: [CatalogValidationDiagnostic(
                    code: "CATALOG_VALIDATION_FAILED",
                    line: 1,
                    column: 1,
                    scope: .document,
                    message: "敏感信息目录验证失败。",
                    hint: "请在 SVLT App 中检查目录状态。"
                )])
            }
        } catch {
            return CatalogValidationResult(status: .unavailable)
        }
    }

    public func catalogStatus() async throws -> CatalogValidationResult {
        try await validateCatalog()
    }

    public func catalogFilePreflight() async throws -> CatalogFilePreflight {
        try await catalogFilePreflightForAgent()
    }

    public func catalogFormatRepairPlan() async throws -> CatalogFormatRepairPlan? {
        let operation = try await beginCatalogOperation()
        do {
            let plan = try await operation.formatRepairPlan()
            catalogFormatRepairDocumentPaths.removeAll(keepingCapacity: true)
            if let plan, plan.canRepair {
                catalogFormatRepairDocumentPaths[plan.currentRawSHA256] = operation.selectedDocumentPath
            }
            await endCatalogOperation(operation)
            await emitAudit(
                action: "检查目录格式",
                target: "catalog-format",
                referenceCount: 0,
                result: {
                    guard let plan else { return "没有选中的目录" }
                    if plan.diagnostics.isEmpty { return "格式正常" }
                    return plan.canRepair ? "发现可修复问题" : "发现需人工处理问题"
                }(),
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .formatCheck
            )
            return plan
        } catch let error as SensitiveCatalogDocumentStoreError {
            await endCatalogOperation(operation)
            throw catalogAgentError(for: error)
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    public func repairCatalogFormat(expectedRawSHA256: String) async throws -> CatalogValidationResult {
        let operation: CatalogDocumentOperation
        if let documentPath = catalogFormatRepairDocumentPaths.removeValue(forKey: expectedRawSHA256) {
            operation = try await beginCatalogOperation(documentPath: documentPath)
        } else {
            operation = try await beginCatalogOperation()
        }
        do {
            _ = try await operation.repairFormat(expectedRawSHA256: expectedRawSHA256)
            await emitAudit(
                action: "修复目录格式",
                target: "catalog-format",
                referenceCount: 0,
                result: "成功",
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .formatRepair
            )
            let report = try await operation.validationReport()
            await endCatalogOperation(operation)
            return CatalogValidationResult(
                status: report.status,
                revision: report.revision,
                rawSHA256: report.rawSHA256,
                pendingExternalChange: report.pendingExternalChange,
                diagnostics: report.diagnostics
            )
        } catch let error as SensitiveCatalogDocumentStoreError {
            await endCatalogOperation(operation)
            throw catalogAgentError(for: error)
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    public func catalogRecentAuditEntries(limit: Int) async throws -> CatalogRecentAuditResult {
        try await auditPersistenceCoordinator.recentCatalogEntries(limit: limit)
    }

    /// A deliberately narrow, non-sensitive health signal. It never contains
    /// paths, payloads, reference IDs, or key material.
    public func catalogAuditHealth() async -> String? {
        await auditPersistenceCoordinator.healthSignal()
    }

    public func pendingCatalogSecureInputRequestIDs() async -> [UUID] {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        return secureInputLifecycle.pendingRequestIDs
    }

    public func catalogSecureInputRequest(id: UUID) async throws -> CatalogAgentSecureInputRequest {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        guard let request = secureInputLifecycle.pendingRequest(id: id)
        else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return request
    }

    public func catalogSecureInputStatus(requestID: UUID) async -> CatalogSecureInputStatus {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        return secureInputLifecycle.status(for: requestID)
    }

    public func requestCatalogSecureInputs(
        entryID: String,
        targets: [CatalogSecureInputTargetRequest],
        expectedRevision: UInt64
    ) async throws -> CatalogSecureInputStatus {
        let operation = try await beginCatalogOperation()
        do {
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard snapshot.revision == expectedRevision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              !targets.isEmpty,
              Set(targets.map(\.id)).count == targets.count,
              targets.allSatisfy({ $0.entryID == entryID })
        else {
            throw SecretCatalogAgentError.revisionConflict
        }
        let fields = Dictionary(uniqueKeysWithValues: entry.fields.map { ($0.key, $0) })
        let resolvedTargets: [CatalogSecureInputTarget] = try targets.map { target in
            guard let field = fields[target.fieldKey] else {
                throw SecretCatalogAgentError.invalidOperation
            }
            switch target.mode {
            case .fillPlaceholder:
                guard field.type.isSecret && field.secretRef == nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            case .replaceSecret:
                guard field.type.isSecret && field.secretRef != nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            case .convertToSecret:
                guard !field.type.isSecret else {
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
            return CatalogSecureInputTarget(
                entryID: entryID,
                fieldKey: field.key,
                label: field.label,
                mode: target.mode,
                required: target.required,
                usesExistingValue: target.mode == .convertToSecret && existingCatalogValueIsNonEmpty(field.value)
            )
        }

        let callerContext = AuditContext.current ?? AuditContext(source: .agent)
        // One opaque ID is the sole correlation key for the UI request, the
        // status receipt, the authentication audit, and the final commit.
        let requestID = UUID()
        let operationContext = callerContext.withRequestID(requestID)
        let createdAt = now()
        let request = CatalogAgentSecureInputRequest(
            id: requestID,
            correlationID: callerContext.correlationID,
            requestID: requestID,
            entryID: entryID,
            entryTitle: entry.title,
            expectedRevision: expectedRevision,
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(180),
            targets: resolvedTargets
        )
        let expiryTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(180))
            guard !Task.isCancelled else { return }
            await self?.expireCatalogSecureInputRequest(id: request.id)
        }
        secureInputLifecycle.insert(
            request,
            auditContext: operationContext,
            expiryTask: expiryTask
        )
        await emitAudit(
            action: "智能体安全输入请求",
            target: "catalog-field",
            referenceCount: resolvedTargets.count,
            result: "请求中",
            context: operationContext,
            operation: .authorization,
            authorizationOutcome: .requested,
            status: .requested
        )
        secureInputNotifier.present(requestID: request.id)
        secureInputCatalogOperations[request.id] = operation
        return CatalogSecureInputStatus(requestID: request.id, status: .pending)
        } catch {
            await endCatalogOperation(operation)
            throw error
        }
    }

    /// Atomically authenticates, encrypts, evaluates the authoritative final
    /// semantic diff, commits, and records completion for one immutable
    /// request. Plaintext never crosses the generic Catalog mutation API.
    public func submitCatalogSecureInput(
        id: UUID,
        submission: CatalogSecureInputSubmission
    ) async throws -> CatalogSecureInputStatus {
        pruneSecureInputReceipts()
        await expireDueSecureInputRequests()
        guard catalogDocumentOwner != nil else {
            throw SecretCatalogAgentError.unavailable
        }
        guard let operation = secureInputCatalogOperations[id] else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let request = try secureInputLifecycle.beginSubmission(id: id, now: now())
        var createdReferences: [SecretReference] = []
        do {
            // This is the one device-owner authentication for this request.
            // The request ID remains in the actor state while the authenticator
            // suspends, so a second submit cannot race or reuse the proof.
            await emitAudit(
                action: "智能体安全输入本机认证请求",
                target: "catalog-field",
                referenceCount: request.targets.count,
                result: "请求中",
                context: secureInputLifecycle.auditContext(for: id),
                operation: .authorization,
                authorizationOutcome: .requested,
                status: .requested
            )
            _ = try await approveWithTimeout(summary: secureInputApprovalSummary(for: request))
            await emitAudit(
                action: "智能体安全输入本机认证完成",
                target: "catalog-field",
                referenceCount: request.targets.count,
                result: "成功",
                context: secureInputLifecycle.auditContext(for: id),
                operation: .authorization,
                authorizationOutcome: .approved,
                status: .completed
            )
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)

            let snapshot = try await catalogSnapshotForAgent(using: operation)
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)
            guard snapshot.revision == request.expectedRevision,
                  let currentEntry = snapshot.document.entries.first(where: { $0.id == request.entryID })
            else {
                throw SecretCatalogAgentError.revisionConflict
            }
            let finalResult = try await makeSecureInputFinalEntry(
                request: request,
                submission: submission,
                currentEntry: currentEntry,
                operation: operation
            )
            let finalEntry = finalResult.entry
            createdReferences = finalResult.references
            var finalEntries = snapshot.document.entries
            guard let offset = finalEntries.firstIndex(where: { $0.id == request.entryID }) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            finalEntries[offset] = finalEntry
            let finalDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: finalEntries)
            try finalDocument.validate()

            let finalDiff = CatalogSemanticDiff.between(old: snapshot.document, new: finalDocument)
            try await validatePreauthorizedCatalogDiff(finalDiff)
            try ensureSecureInputSubmissionIsStillActive(id: id, request: request)
            // This synchronous actor-state transition is the commit
            // linearization point. There is intentionally no await between
            // the active check above and this assignment: cancellation and
            // expiry either win before this point or are rejected after it.
            try secureInputLifecycle.markCommitting(id: id, request: request, now: now())
            let updated = try await operation.updateEntry(
                finalEntry,
                expectedRevision: request.expectedRevision
            )
            await notifySavedReferencesChanged()
            let status = CatalogSecureInputStatus(
                requestID: request.id,
                status: .completed,
                revision: updated.revision
            )
            await finishSecureInputRequest(
                id: id,
                status: status,
                action: "智能体安全输入完成",
                result: "成功",
                authorizationOutcome: .approved,
                auditStatus: .completed
            )
            return status
        } catch let error as CatalogSecureInputAbortError {
            let status: CatalogSecureInputStatus
            let action: String
            let result: String
            let auditStatus: AuditStatus
            switch error {
            case .cancelled:
                status = CatalogSecureInputStatus(requestID: request.id, status: .cancelled, errorCode: "SECURE_INPUT_CANCELLED")
                action = "智能体安全输入取消"
                result = "已取消"
                auditStatus = .cancelled
            case .expired:
                status = CatalogSecureInputStatus(requestID: request.id, status: .expired, errorCode: "SECURE_INPUT_EXPIRED")
                action = "智能体安全输入过期"
                result = "已过期"
                auditStatus = .expired
            }
            _ = await compensateCreatedReferences(createdReferences, operation: operation)
            await finishSecureInputRequest(
                id: id,
                status: status,
                action: action,
                result: result,
                authorizationOutcome: .cancelled,
                auditStatus: auditStatus
            )
            throw SecretCatalogAgentError.invalidOperation
        } catch let error as SensitiveCatalogDocumentStoreError {
            let mapped = catalogAgentError(for: error)
            let finalError = await compensateCreatedReferences(createdReferences, operation: operation) ?? mapped
            await finishSecureInputRequest(
                id: id,
                status: CatalogSecureInputStatus(requestID: request.id, status: .failed, errorCode: secureInputErrorCode(finalError)),
                action: "智能体安全输入失败",
                result: "失败",
                authorizationOutcome: .denied,
                auditStatus: .failure
            )
            throw finalError
        } catch {
            let finalError = await compensateCreatedReferences(createdReferences, operation: operation) ?? (error as Error)
            let code = secureInputErrorCode(finalError)
            await finishSecureInputRequest(
                id: id,
                status: CatalogSecureInputStatus(requestID: request.id, status: .failed, errorCode: code),
                action: "智能体安全输入失败",
                result: "失败",
                authorizationOutcome: .denied,
                auditStatus: .failure
            )
            throw finalError
        }
    }

    public func cancelCatalogSecureInput(id: UUID) async {
        guard let request = secureInputLifecycle.request(id: id),
              let state = secureInputLifecycle.state(for: id),
              state == .awaitingInput || state == .submitting
        else { return }
        if state == .submitting {
            secureInputLifecycle.latchAbort(.cancelled, for: id)
            secureInputNotifier.notifyQueueChanged(requestID: id)
            return
        }
        await finishSecureInputRequest(
            id: id,
            status: CatalogSecureInputStatus(requestID: request.id, status: .cancelled, errorCode: "SECURE_INPUT_CANCELLED"),
            action: "智能体安全输入取消",
            result: "已取消",
            authorizationOutcome: .cancelled,
            auditStatus: .cancelled
        )
    }

    private func expireCatalogSecureInputRequest(id: UUID) async {
        guard let request = secureInputLifecycle.request(id: id),
              let state = secureInputLifecycle.state(for: id),
              state == .awaitingInput || state == .submitting
        else { return }
        if state == .submitting {
            secureInputLifecycle.latchAbort(.expired, for: id)
            secureInputNotifier.notifyQueueChanged(requestID: id)
            return
        }
        await finishSecureInputRequest(
            id: id,
            status: CatalogSecureInputStatus(requestID: request.id, status: .expired, errorCode: "SECURE_INPUT_EXPIRED"),
            action: "智能体安全输入过期",
            result: "已过期",
            authorizationOutcome: .cancelled,
            auditStatus: .cancelled
        )
    }

    private func expireDueSecureInputRequests() async {
        let due = secureInputLifecycle.dueRequestIDs(now: now())
        for id in due { await expireCatalogSecureInputRequest(id: id) }
    }

    private func pruneSecureInputReceipts() {
        if secureInputLifecycle.prune(now: now()) {
            persistSecureInputReceipts()
        }
    }

    func finishSecureInputRequest(
        id: UUID,
        status: CatalogSecureInputStatus,
        action: String,
        result: String,
        authorizationOutcome: AuditAuthorizationOutcome,
        auditStatus: AuditStatus
    ) async {
        let operation = secureInputCatalogOperations.removeValue(forKey: id)
        guard let completion = secureInputLifecycle.finish(
            id: id,
            status: status,
            terminalDate: now()
        ) else {
            if let operation { await endCatalogOperation(operation) }
            return
        }
        if let operation { await endCatalogOperation(operation) }
        let request = completion.request
        persistSecureInputReceipts()
        let context = completion.auditContext
        secureInputNotifier.notifyQueueChanged(requestID: id)
        await emitAudit(
            action: action,
            target: "catalog-field",
            referenceCount: request.targets.count,
            result: result,
            context: context,
            operation: .authorization,
            authorizationOutcome: authorizationOutcome,
            status: auditStatus
        )
    }

    private func secureInputApprovalSummary(for request: CatalogAgentSecureInputRequest) -> String {
        "为 \(safeDisplayLabel(request.entryTitle)) 写入 \(request.targets.count) 个敏感字段"
    }

    private func ensureSecureInputSubmissionIsStillActive(
        id: UUID,
        request: CatalogAgentSecureInputRequest
    ) throws {
        try secureInputLifecycle.ensureSubmissionIsStillActive(
            id: id,
            request: request,
            now: now()
        )
    }

    private func secureInputErrorCode(_ error: Error) -> String {
        if let error = error as? SecretCatalogAgentError {
            switch error {
            case .revisionConflict: return "CATALOG_REVISION_CONFLICT"
            case .invalidOperation: return "CATALOG_INVALID_OPERATION"
            case .writeFailed: return "CATALOG_WRITE_FAILED"
            case .cleanupRequired: return "CATALOG_CLEANUP_REQUIRED"
            default: return "SECURE_INPUT_FAILED"
            }
        }
        if let error = error as? SecretOperationError {
            return error.responseCode
        }
        if let error = error as? OperationAuthorizationError {
            switch error {
            case .cancelled: return "AUTHORIZATION_CANCELLED"
            case .denied: return "AUTHORIZATION_DENIED"
            case .timeout: return "AUTHORIZATION_TIMEOUT"
            case .unavailable: return "AUTHORIZATION_UNAVAILABLE"
            }
        }
        return "SECURE_INPUT_FAILED"
    }

    private func makeSecureInputFinalEntry(
        request: CatalogAgentSecureInputRequest,
        submission: CatalogSecureInputSubmission,
        currentEntry: SecretCatalogEntry,
        operation: CatalogDocumentOperation
    ) async throws -> (entry: SecretCatalogEntry, references: [SecretReference]) {
        let targetsByID = Dictionary(uniqueKeysWithValues: request.targets.map { ($0.id, $0) })
        let selectedIDs = Set(submission.selectedTargetIDs)
        guard selectedIDs.count == submission.selectedTargetIDs.count,
              !selectedIDs.isEmpty,
              selectedIDs.isSubset(of: Set(targetsByID.keys)),
              request.targets.filter(\.required).allSatisfy({ selectedIDs.contains($0.id) })
        else { throw SecretCatalogAgentError.invalidOperation }
        let selectedKeys = Set(selectedIDs.compactMap { targetsByID[$0]?.fieldKey })
        let inputKeys: Set<String> = Set(selectedIDs.compactMap { id in
            guard let target = targetsByID[id], !target.usesExistingValue else { return nil }
            return target.fieldKey
        })
        guard Set(submission.plaintextByFieldKey.keys) == inputKeys,
              selectedKeys.count == selectedIDs.count
        else { throw SecretCatalogAgentError.invalidOperation }

        var encryptedReferences: [String: String] = [:]
        var createdReferences: [SecretReference] = []
        do {
            for id in selectedIDs {
                guard let target = targetsByID[id],
                      let field = currentEntry.fields.first(where: { $0.key == target.fieldKey }),
                      let plaintext = secureInputPlaintext(
                        for: target,
                        field: field,
                        submission: submission
                      ),
                      !plaintext.isEmpty
                else { throw SecretCatalogAgentError.invalidOperation }
                let reference = try await textEncryptor.encryptText(
                    plaintext,
                    label: field.label,
                    policy: .credential
                )
                createdReferences.append(reference)
                encryptedReferences[target.fieldKey] = reference.description
            }
        } catch {
            if let cleanupError = await compensateCreatedReferences(createdReferences, operation: operation) {
                throw cleanupError
            }
            throw error
        }

        let updatedFields = currentEntry.fields.map { field in
            guard let target = request.targets.first(where: { $0.fieldKey == field.key }),
                  selectedIDs.contains(target.id),
                  let reference = encryptedReferences[field.key]
            else { return field }
            return SecretCatalogFieldValue(
                key: field.key,
                label: field.label,
                type: target.mode == .convertToSecret ? .secret : field.type,
                agentVisible: field.agentVisible,
                searchable: field.searchable,
                value: nil,
                secretRef: reference
            )
        }
        let entry = SecretCatalogEntry(
            id: currentEntry.id,
            indexId: currentEntry.indexId,
            title: currentEntry.title,
            type: currentEntry.type,
            aliases: currentEntry.aliases,
            endpoints: currentEntry.endpoints,
            fields: updatedFields,
            notes: currentEntry.notes,
            tags: currentEntry.tags,
            schema: currentEntry.schema
        )
        return (entry, createdReferences)
    }

    private func existingCatalogValueIsNonEmpty(_ value: SecretCatalogValue?) -> Bool {
        guard let value else { return false }
        switch value {
        case .string(let string):
            return !string.isEmpty
        case .number, .boolean:
            return true
        case .list(let values):
            return !values.isEmpty
        }
    }

    private func secureInputPlaintext(
        for target: CatalogSecureInputTarget,
        field: SecretCatalogFieldValue,
        submission: CatalogSecureInputSubmission
    ) -> String? {
        if target.usesExistingValue {
            guard target.mode == .convertToSecret else { return nil }
            switch field.value {
            case .string(let value): return value
            case .number(let value): return String(value)
            case .boolean(let value): return value ? "true" : "false"
            case .list(let values): return values.joined(separator: "\n")
            case nil: return nil
            }
        }
        return submission.plaintextByFieldKey[target.fieldKey]
    }

    private func validatePreauthorizedCatalogDiff(_ diff: CatalogSemanticDiff) async throws {
        guard !diff.isEmpty,
              catalogMutationPolicyEngine.evaluate(diff, transport: .directManagedFileWrite) != .denied
        else { throw SecretCatalogAgentError.invalidOperation }
        let references: [SecretReference]
        do { references = try diff.referencedSecretRefs.map(SecretReference.init) }
        catch { throw SecretCatalogAgentError.invalidOperation }
        if !references.isEmpty {
            let metadata = try await policyMetadata(for: references)
            let descriptor = SecretOperationDescriptor(
                actionType: diff.changesSecretTarget ? .changeDestinationBinding : .changeSecretPolicy,
                secretReferences: references,
                requestedEffects: ["secure-input-final-diff"]
            )
            let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
            guard decision.risk != .denied else { throw SecretOperationError.invalidOperationParameters }
        }
    }

    public func adoptCatalogExternalV2() async throws -> CatalogValidationResult {
        try await withCatalogOperation { operation in
            do {
                let snapshot = try await operation.adoptExternalV2()
                return CatalogValidationResult(status: .found, revision: snapshot.revision)
            } catch let error as SensitiveCatalogDocumentStoreError {
                switch error {
                case .legacyCatalogUnsupported:
                    throw SecretCatalogAgentError.legacyCatalogUnsupported
                case .integrityMissing:
                    throw SecretCatalogAgentError.integrityMissing
                case .externalModification:
                    throw SecretCatalogAgentError.externalModification
                case .pendingExternalChange:
                    throw SecretCatalogAgentError.pendingExternalChange
                case .revisionConflict:
                    throw SecretCatalogAgentError.revisionConflict
                default:
                    throw SecretCatalogAgentError.invalidCatalog
                }
            }
        }
    }

    public func adoptCatalogExternalV3() async throws -> CatalogValidationResult {
        try await withCatalogOperation { operation in
            do {
                let candidate = try await operation.externalV3AdoptionCandidate()
            let references = candidate.semanticDiff.referencedSecretRefs
            if !references.isEmpty {
                guard recordResolver != nil else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                for reference in references {
                    do {
                        _ = try await inspectReference(reference)
                    } catch {
                        // A syntactically valid secret:// handle is not enough
                        // to adopt a catalog. Every binding must point at a
                        // real local record before approval is presented.
                        throw SecretCatalogAgentError.invalidOperation
                    }
                }
                try await authorizeCatalogDiff(
                    candidate.semanticDiff,
                    transport: .bindExistingSecret,
                    requireAgentSafeWrite: false
                )
            }
            let snapshot = try await operation.adoptExternalV3(
                expectedRawSHA256: candidate.rawSHA256,
                expectedSemanticSHA256: candidate.semanticSHA256
            )
            return CatalogValidationResult(status: .found, revision: snapshot.revision)
            } catch let error as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: error)
            }
        }
    }

    /// Approves the currently pending high-risk external semantic change.
    /// The Markdown already exists on disk; approval only moves its semantic
    /// snapshot into the accepted state and never rewrites user formatting.
    public func approveCatalogExternalChange(
        expectedRevision: UInt64,
        expectedRawSHA256: String,
        expectedSemanticSHA256: String
    ) async throws -> CatalogValidationResult {
        try await withCatalogOperation { operation in
            do {
                let pending = try await operation.pendingExternalChange()
            guard pending.acceptedRevision == expectedRevision,
                  pending.rawSHA256 == expectedRawSHA256,
                  pending.semanticSHA256 == expectedSemanticSHA256
            else {
                throw SensitiveCatalogDocumentStoreError.revisionConflict
            }
            try await authorizeCatalogDiff(
                pending.semanticDiff,
                transport: .directManagedFileWrite,
                requireAgentSafeWrite: false
            )
            let accepted = try await operation.acceptPendingExternalChange(
                expectedRevision: expectedRevision,
                expectedRawSHA256: expectedRawSHA256,
                expectedSemanticSHA256: expectedSemanticSHA256
            )
            return CatalogValidationResult(status: .found, revision: accepted.revision)
            } catch let error as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: error)
            }
        }
    }

    public func setCatalogAgentWriteMode(
        mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        try await catalogWriteAccessCoordinator.setMode(mode, duration: duration)
    }

    public func revokeCatalogAgentWrite() async {
        await catalogWriteAccessCoordinator.revoke()
    }

    public func catalogAgentWriteStatus() async -> CatalogAgentWriteAuthorizationStatus {
        await catalogWriteAccessCoordinator.status()
    }

    public func requestCatalogWriteAccess(
        source: CatalogAgentWriteRequestSource,
        reasonCategory: CatalogAgentWriteReasonCategory,
        duration: CatalogAgentWriteAccessDuration
    ) async throws {
        _ = (source, reasonCategory, duration)
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    private func requestAgentCatalogAuthorization(
        _ intent: CatalogAgentWriteIntent,
        reasonCategory: CatalogAgentWriteReasonCategory
    ) async throws -> AuditContext {
        try await catalogWriteAccessCoordinator.requestAuthorization(
            intent,
            reasonCategory: reasonCategory
        )
    }

    public func pendingCatalogWriteAccessRequest(id: UUID) async throws -> CatalogAgentWriteAccessRequest {
        try await catalogWriteAccessCoordinator.pendingRequest(id: id)
    }

    /// App cold-start/foreground discovery. The DistributedNotification path
    /// is only a live accelerator; pending requests remain authoritative in
    /// the Agent until they expire, are denied, or are consumed.
    public func pendingCatalogWriteAccessRequestIDs() async throws -> [UUID] {
        await catalogWriteAccessCoordinator.pendingRequestIDs()
    }

    public func respondToCatalogWriteAccessRequest(id: UUID, approved: Bool) async throws {
        try await catalogWriteAccessCoordinator.respond(id: id, approved: approved)
    }

    public func catalogCreateIndex(
        title: String,
        aliases: [String],
        tags: [String],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
            do {
            let snapshot = try await operation.createIndex(
                title: title,
                aliases: aliases,
                tags: tags,
                expectedRevision: expectedRevision
            )
            let result = CatalogWriteResult(revision: snapshot.revision)
            await emitAudit(action: "创建目录分组", target: "catalog", referenceCount: 0, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                throw catalogAgentError(for: error)
            }
            do {
                let current = try await operation.snapshot()
                let snapshot = try await operation.createIndex(
                    title: title,
                    aliases: aliases,
                    tags: tags,
                    expectedRevision: current.revision
                )
                let result = CatalogWriteResult(revision: snapshot.revision)
                await emitAudit(action: "创建目录分组", target: "catalog", referenceCount: 0, result: "成功", operation: .catalogMutation)
                return result
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: retryError)
            }
            }
        }
    }

    public func catalogCreateEntry(
        _ request: CatalogDraftRequest,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
        if request.fields.contains(where: { $0.type.isSecret && $0.value != nil }) {
            try catalogMutationPolicyEngine.requireSilent(
                CatalogMutationDescriptor(kind: .plaintextSecretInCatalog)
            )
        }
        for reference in request.fields.compactMap(\.secretRef) {
            guard (try? SecretReference(reference)) != nil else {
                try catalogMutationPolicyEngine.requireSilent(
                    CatalogMutationDescriptor(kind: .forgedSecretReference)
                )
                throw SecretCatalogAgentError.invalidOperation
            }
        }
        guard request.fields.allSatisfy({ $0.secretRef == nil }) else {
            throw SecretCatalogAgentError.approvalRequired
        }
        let entry = try SecretCatalogEntry.generated(
            indexId: request.indexID,
            title: request.title,
            type: request.type,
            aliases: request.aliases,
            endpoints: request.endpoints,
            fields: request.fields,
            notes: request.notes,
            tags: request.tags
        )
        do {
            let snapshot = try await operation.createEntry(entry, expectedRevision: expectedRevision)
            let result = CatalogWriteResult(
                revision: snapshot.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
            )
            await emitAudit(action: "创建目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                throw catalogAgentError(for: error)
            }
            do {
                let current = try await operation.snapshot()
                let snapshot = try await operation.createEntry(entry, expectedRevision: current.revision)
                let result = CatalogWriteResult(
                    revision: snapshot.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: snapshot.document).matches.first?.entry
                )
                await emitAudit(action: "创建目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
                return result
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: retryError)
            }
        }
        }
    }

    public func catalogUpdateEntry(
        _ entry: SecretCatalogEntry,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard snapshot.document.entries.contains(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }

        var entries = snapshot.document.entries
        guard let offset = entries.firstIndex(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        entries[offset] = entry
        let next: SecretCatalogDocument
        do {
            next = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: entries)
            try next.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let diff = CatalogSemanticDiff.between(old: snapshot.document, new: next)
        try await authorizeCatalogDiff(
            diff,
            transport: .directManagedFileWrite,
            requireAgentSafeWrite: false
        )

        do {
            let updated = try await operation.updateEntry(entry, expectedRevision: expectedRevision)
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
            await emitAudit(action: "修改目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            throw catalogAgentError(for: error)
        }
        }
    }

    /// Commit one App entry edit together with any newly entered secret
    /// values. Plaintext is consumed here and never becomes a Catalog value;
    /// newly-created records are deleted again if the catalog commit fails.
    public func catalogCommitEntryEdit(
        _ entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput],
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
        // A request-owned Secure Input transaction is the only path allowed
        // to consume plaintext for its Entry. Blocking the generic editor for
        // the lifetime of the request closes the stale-Sheet race.
        guard !secureInputLifecycle.hasRequest(forEntryID: entry.id) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        guard let currentEntry = snapshot.document.entries.first(where: { $0.id == entry.id }),
              currentEntry.indexId == entry.indexId
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        var inputsByKey: [String: CatalogSecretInput] = [:]
        for input in secretInputs {
            guard !input.key.isEmpty,
                  !input.label.isEmpty,
                  !input.plaintext.isEmpty,
                  inputsByKey[input.key] == nil
            else {
                throw SecretCatalogAgentError.invalidOperation
            }
            inputsByKey[input.key] = input
        }

        guard Set(entry.fields.map(\.key)).count == entry.fields.count else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let currentFields = Dictionary(uniqueKeysWithValues: currentEntry.fields.map { ($0.key, $0) })
        let candidateFields = Dictionary(uniqueKeysWithValues: entry.fields.map { ($0.key, $0) })
        for input in secretInputs {
            guard let candidateField = candidateFields[input.key],
                  candidateField.type.isSecret
            else {
                // Filling, converting, and replacing all require a local
                // plaintext input; an opaque reference can never be smuggled
                // through this transaction.
                throw SecretCatalogAgentError.invalidOperation
            }
        }

        for field in entry.fields {
            let oldReference = currentFields[field.key]?.secretRef
            if field.secretRef != oldReference {
                if field.secretRef != nil && inputsByKey[field.key] == nil {
                    // A new opaque reference must be created by this request,
                    // never smuggled in as ordinary Entry metadata.
                    throw SecretCatalogAgentError.invalidOperation
                }
                if oldReference != nil && inputsByKey[field.key] == nil {
                    throw SecretCatalogAgentError.invalidOperation
                }
            }
        }

        let draftFields = entry.fields.map { field in
            guard inputsByKey[field.key] != nil else { return field }
            return SecretCatalogFieldValue(
                key: field.key,
                label: field.label,
                type: field.type,
                agentVisible: field.agentVisible,
                searchable: field.searchable,
                secretRef: nil
            )
        }
        let draftEntry = SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: entry.title,
            type: entry.type,
            aliases: entry.aliases,
            endpoints: entry.endpoints,
            fields: draftFields,
            notes: entry.notes,
            tags: entry.tags,
            schema: entry.schema
        )
        var draftEntries = snapshot.document.entries
        guard let entryOffset = draftEntries.firstIndex(where: { $0.id == entry.id }) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        draftEntries[entryOffset] = draftEntry
        let draftDocument: SecretCatalogDocument
        do {
            draftDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: draftEntries)
            try draftDocument.validate()
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }

        let draftDiff = CatalogSemanticDiff.between(old: snapshot.document, new: draftDocument)
        try await authorizeCatalogDiff(
            draftDiff,
            transport: .directManagedFileWrite,
            requireAgentSafeWrite: false
        )

        guard !secretInputs.isEmpty else {
            guard !secureInputLifecycle.hasRequest(forEntryID: entry.id) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            do {
                let updated = try await operation.updateEntry(entry, expectedRevision: expectedRevision)
                let result = CatalogWriteResult(
                    revision: updated.revision,
                    entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
                )
                await emitAudit(action: "修改目录条目", target: "catalog", referenceCount: entry.fields.filter { $0.secretRef != nil }.count, result: "成功", operation: .catalogMutation)
                return result
            } catch let error as SensitiveCatalogDocumentStoreError {
                throw catalogAgentError(for: error)
            }
        }

        guard recordDeleter != nil else {
            throw SecretCatalogAgentError.invalidOperation
        }

        var createdReferences: [SecretReference] = []
        do {
            for input in secretInputs {
                let reference = try await textEncryptor.encryptText(
                    input.plaintext,
                    label: input.label,
                    policy: .credential
                )
                createdReferences.append(reference)
            }

            // Match generated references to input keys by position rather than
            // exposing any plaintext in a temporary model or error.
            let referencesByKey = Dictionary(uniqueKeysWithValues: zip(secretInputs.map(\.key), createdReferences).map { ($0.0, $0.1) })
            let boundFields = entry.fields.map { field in
                guard let reference = referencesByKey[field.key] else { return field }
                return SecretCatalogFieldValue(
                    key: field.key,
                    label: field.label,
                    type: field.type,
                    agentVisible: field.agentVisible,
                    searchable: field.searchable,
                    secretRef: reference.description
                )
            }
            let finalEntry = SecretCatalogEntry(
                id: entry.id,
                indexId: entry.indexId,
                title: entry.title,
                type: entry.type,
                aliases: entry.aliases,
                endpoints: entry.endpoints,
                fields: boundFields,
                notes: entry.notes,
                tags: entry.tags,
                schema: entry.schema
            )
            var finalEntries = snapshot.document.entries
            finalEntries[entryOffset] = finalEntry
            let finalDocument = SecretCatalogDocument(indexes: snapshot.document.indexes, entries: finalEntries)
            try finalDocument.validate()

            // The actor may have been re-entered while authorizing or
            // encrypting. Re-check immediately before the store call so a
            // Secure Input request that began in that window cannot be
            // bypassed by this generic plaintext-consuming editor.
            guard !secureInputLifecycle.hasRequest(forEntryID: entry.id) else {
                throw SecretCatalogAgentError.invalidOperation
            }
            let updated = try await operation.updateEntry(finalEntry, expectedRevision: expectedRevision)
            await notifySavedReferencesChanged()
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entry.id, document: updated.document).matches.first?.entry
            )
            await emitAudit(
                action: "修改目录条目并写入凭据",
                target: "catalog",
                referenceCount: createdReferences.count,
                result: "成功",
                context: AuditContext.current ?? AuditContext(source: .app),
                operation: .catalogMutation
            )
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            if let cleanupError = await compensateCreatedReferences(createdReferences, operation: operation) {
                throw cleanupError
            }
            throw catalogAgentError(for: error)
        } catch {
            if let cleanupError = await compensateCreatedReferences(createdReferences, operation: operation) {
                throw cleanupError
            }
            throw error
        }
        }
    }

    public func catalogApplyBatch(
        _ mutation: CatalogBatchMutation,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await performCatalogBatch(
            mutation,
            expectedRevision: expectedRevision,
            requireAgentSafeWrite: false
        )
    }

    public func catalogBindExistingSecret(
        entryID: String,
        key: String,
        secretRef: String,
        expectedRevision: UInt64
    ) async throws -> CatalogWriteResult {
        try await withCatalogOperation { operation in
        let parsed: SecretReference
        do {
            parsed = try SecretReference(secretRef)
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }

        let metadata: [SecretPolicyMetadata]
        do {
            metadata = try await policyMetadata(for: [parsed])
        } catch {
            throw SecretCatalogAgentError.invalidOperation
        }
        let descriptor = SecretOperationDescriptor(
            actionType: .changeDestinationBinding,
            secretReferences: [parsed],
            requestedEffects: ["bind-catalog-entry"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        try await authorizeIfNeeded(descriptor, metadata: metadata, decision: decision)

        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard expectedRevision == snapshot.revision else {
            throw SecretCatalogAgentError.revisionConflict
        }
        do {
            let updated = try await operation.bindSecret(
                parsed.description,
                toFieldKey: key,
                entryID: entryID,
                expectedRevision: expectedRevision
            )
            let result = CatalogWriteResult(
                revision: updated.revision,
                entry: catalogSearchService.get(entryID: entryID, document: updated.document).matches.first?.entry
            )
            await emitAudit(action: "绑定目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
            return result
        } catch let error as SensitiveCatalogDocumentStoreError {
            switch error {
            case .revisionConflict:
                throw SecretCatalogAgentError.revisionConflict
            case .invalidOperation:
                throw SecretCatalogAgentError.invalidOperation
            case .writeFailed:
                throw SecretCatalogAgentError.writeFailed
            default:
                throw SecretCatalogAgentError.invalidCatalog
            }
        }
        }
    }

    public func catalogSecureInput(
        entryID: String,
        key: String,
        label: String?,
        plaintext: String,
        policy: SecretPolicy
    ) async throws -> (reference: String, revision: UInt64) {
        try await withCatalogOperation { operation in
        guard !plaintext.isEmpty else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              let field = entry.fields.first(where: { $0.key == key }),
              field.type.isSecret
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let secret = try await textEncryptor.encryptText(plaintext, label: label, policy: policy)
        do {
            if field.secretRef != nil {
                let replacementFields = entry.fields.map { currentField in
                    guard currentField.key == key else { return currentField }
                    return SecretCatalogFieldValue(
                        key: currentField.key,
                        label: currentField.label,
                        type: currentField.type,
                        agentVisible: currentField.agentVisible,
                        searchable: currentField.searchable,
                        value: nil,
                        secretRef: secret.description
                    )
                }
                var candidateEntries = snapshot.document.entries
                guard let entryOffset = candidateEntries.firstIndex(where: { $0.id == entry.id }) else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                candidateEntries[entryOffset] = SecretCatalogEntry(
                    id: entry.id,
                    indexId: entry.indexId,
                    title: entry.title,
                    type: entry.type,
                    aliases: entry.aliases,
                    endpoints: entry.endpoints,
                    fields: replacementFields,
                    notes: entry.notes,
                    tags: entry.tags,
                    schema: entry.schema
                )
                let candidate = SecretCatalogDocument(
                    indexes: snapshot.document.indexes,
                    entries: candidateEntries
                )
                try candidate.validate()
                let diff = CatalogSemanticDiff.between(old: snapshot.document, new: candidate)
                guard diff.changes.contains(where: {
                    $0.kind == .replaceSecret
                        && $0.entryID == entryID
                        && $0.fieldKey == key
                        && $0.oldSecretRef == field.secretRef
                        && $0.newSecretRef == secret.description
                }) else {
                    throw SecretCatalogAgentError.invalidOperation
                }
                try await authorizeCatalogDiff(
                    diff,
                    transport: .directManagedFileWrite,
                    requireAgentSafeWrite: false,
                    requestedEffect: "catalog-replace-secret"
                )
            }

            let updated = try await operation.bindSecret(
                secret.description,
                toFieldKey: key,
                entryID: entryID,
                expectedRevision: snapshot.revision
            )
            await emitAudit(action: "写入目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
            return (secret.description, updated.revision)
        } catch let error as SensitiveCatalogDocumentStoreError {
            guard error == .revisionConflict else {
                if let cleanupError = await compensateCreatedReferences([secret], operation: operation) {
                    throw cleanupError
                }
                throw catalogAgentError(for: error)
            }

            // Filling an empty placeholder is safe to retry with the same
            // already-encrypted reference. Never overwrite a concurrent bind.
            let current: SensitiveCatalogSnapshot
            do {
                current = try await catalogSnapshotForAgent(using: operation)
            } catch {
                if let cleanupError = await compensateCreatedReferences([secret], operation: operation) {
                    throw cleanupError
                }
                throw error
            }
            guard let currentEntry = current.document.entries.first(where: { $0.id == entryID }),
                  let currentField = currentEntry.fields.first(where: { $0.key == key }),
                  currentField.type.isSecret,
                  currentField.secretRef == nil
            else {
                if let cleanupError = await compensateCreatedReferences([secret], operation: operation) {
                    throw cleanupError
                }
                throw SecretCatalogAgentError.revisionConflict
            }
            do {
                let updated = try await operation.bindSecret(
                    secret.description,
                    toFieldKey: key,
                    entryID: entryID,
                    expectedRevision: current.revision
                )
                await emitAudit(action: "写入目录凭据", target: "catalog", referenceCount: 1, result: "成功", operation: .catalogMutation)
                return (secret.description, updated.revision)
            } catch let retryError as SensitiveCatalogDocumentStoreError {
                if let cleanupError = await compensateCreatedReferences([secret], operation: operation) {
                    throw cleanupError
                }
                throw catalogAgentError(for: retryError)
            }
        } catch {
            if let cleanupError = await compensateCreatedReferences([secret], operation: operation) {
                throw cleanupError
            }
            throw error
        }
        }
    }

    /// Reveals one catalog secret field to the local App only.  The field
    /// identity is resolved from the current verified catalog; callers cannot
    /// provide an arbitrary reference or ask the MCP channel for plaintext.
    /// Every reveal goes through the normal device-owner approval path and
    /// resolves the record with fresh key material when the production key
    /// provider is in use.
    public func catalogRevealField(entryID: String, key: String) async throws -> String {
        try await withCatalogOperation { operation in
        let snapshot = try await catalogSnapshotForAgent(using: operation)
        guard let entry = snapshot.document.entries.first(where: { $0.id == entryID }),
              let field = entry.fields.first(where: { $0.key == key }),
              field.type.isSecret,
              let secretRef = field.secretRef
        else {
            throw SecretCatalogAgentError.invalidOperation
        }

        let context = RevealContext(
            reason: "查看敏感信息目录密码字段",
            template: "{{0}}",
            ranges: [ReferenceRange(index: 0, placeholder: "{{0}}")],
            destination: "local-app"
        )
        let (descriptor, metadata) = try await plaintextOperation(
            action: .revealPlaintext,
            references: [secretRef],
            context: context,
            effects: ["display-to-local-user"]
        )
        let decision = operationPolicyEngine.evaluate(descriptor, metadata: metadata)
        let authorizationPath = try await authorizeIfNeeded(
            descriptor,
            metadata: metadata,
            decision: decision
        )

        // Keep the one-field result in the App's caller memory only. The
        // audit event contains no reference ID or resolved value.
        let plaintext = try await resolveReferences(
            references: [secretRef],
            context: context,
            forceFreshAuthorization: true,
            authenticationContext: authorizationPath.authenticationContext
        )
        await emitAudit(
            action: "本机显示目录凭据",
            target: "catalog-field",
            referenceCount: 1,
            result: "已显示",
            context: AuditContext.current ?? AuditContext(source: .app),
            operation: .reveal,
            authorizationOutcome: .approved,
            status: .displayedToUser
        )
        return plaintext
        }
    }
}
