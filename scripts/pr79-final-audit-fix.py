from pathlib import Path

path = Path("Sources/VaultService/VaultAppServices.swift")
text = path.read_text()
start = text.index("    public func commitCatalogDraft(\n")
end = text.index("    public func addCatalogSecretPlaceholder(\n", start)
replacement = '''    public func commitCatalogDraft(
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

'''
text = text[:start] + replacement + text[end:]
old_comment = '''    /// Cancellation/expiry is latched while the one-shot authentication or
    /// store call is suspended. The request is not removed during submission;
    /// this prevents a late SecureField callback from committing after the
    /// App has asked the daemon to cancel it.
'''
new_comment = '''    /// Keep cancellation/expiry latched during suspended submission so a late
    /// SecureField callback cannot commit after App cancellation.
'''
if old_comment not in text:
    raise SystemExit("secure-input lifecycle comment anchor missing")
text = text.replace(old_comment, new_comment, 1)
limit = 253_937
size = len(text.encode())
print(f"VaultAppServices.swift bytes: {size} (limit {limit})")
if size > limit:
    raise SystemExit(f"architecture budget exceeded by {size - limit} bytes")
path.write_text(text)

Path("scripts/pr79-final-audit-fix.py").unlink()
Path(".github/workflows/pr79-final-audit-fix.yml").unlink()
