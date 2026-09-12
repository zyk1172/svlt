import Foundation
import Testing
import VaultCore
@testable import VaultService

@Test func catalogWriteAccessLifecycleKeepsRequestStateTogether() {
    var lifecycle = CatalogWriteAccessLifecycle()
    let id = UUID()
    let intent = CatalogAgentWriteIntent(
        operation: .createEntry,
        entryID: "entry-1",
        acceptedRevision: 7,
        candidateSemanticSHA256: String(repeating: "a", count: 64)
    ).bound(to: id)
    let request = CatalogAgentWriteAccessRequest(
        id: id,
        source: .mcpClient,
        reasonCategory: .knowledgeMaintenance,
        createdAt: "2026-09-12T12:00:00Z",
        intent: intent
    )
    let auditContext = AuditContext(source: .agent)

    let continuation = lifecycle.insert(request, auditContext: auditContext)
    let snapshot = lifecycle.responseSnapshot(id: id)

    #expect(snapshot?.request == request)
    #expect(snapshot?.continuation === continuation)
    #expect(snapshot?.auditContext?.correlationID == auditContext.correlationID)
    #expect(lifecycle.pendingRequest(id: id) == request)
    #expect(lifecycle.pendingRequestIDs == [id])
    #expect(lifecycle.intent(for: id) == intent)
    #expect(lifecycle.state(for: id) == .pending)
}

@Test func catalogWriteAccessLifecycleSortsPendingRequestsAndKeepsAuthenticatingVisible() {
    var lifecycle = CatalogWriteAccessLifecycle()
    let laterID = UUID()
    let earlierID = UUID()
    let context = AuditContext(source: .agent)

    lifecycle.insert(
        CatalogAgentWriteAccessRequest(
            id: laterID,
            source: .mcpClient,
            reasonCategory: .knowledgeMaintenance,
            createdAt: "2026-09-12T12:01:00Z"
        ),
        auditContext: context
    )
    lifecycle.insert(
        CatalogAgentWriteAccessRequest(
            id: earlierID,
            source: .mcpClient,
            reasonCategory: .catalogRepair,
            createdAt: "2026-09-12T12:00:00Z"
        ),
        auditContext: context
    )

    #expect(lifecycle.pendingRequestIDs == [earlierID, laterID])
    let markedAuthenticating = lifecycle.markAuthenticating(id: earlierID)
    #expect(markedAuthenticating)
    #expect(lifecycle.pendingRequest(id: earlierID)?.id == earlierID)
    #expect(lifecycle.pendingRequestIDs == [earlierID, laterID])
    #expect(lifecycle.responseSnapshot(id: earlierID) == nil)
}

@Test func catalogWriteAccessLifecycleExpiryCancellationAndCleanupPreserveTerminalState() {
    var lifecycle = CatalogWriteAccessLifecycle()
    let expiredID = UUID()
    let cancelledID = UUID()
    let context = AuditContext(source: .agent)

    let expiredContinuation = lifecycle.insert(
        CatalogAgentWriteAccessRequest(
            id: expiredID,
            source: .mcpClient,
            reasonCategory: .bulkImport
        ),
        auditContext: context
    )
    let cancelledContinuation = lifecycle.insert(
        CatalogAgentWriteAccessRequest(
            id: cancelledID,
            source: .mcpClient,
            reasonCategory: .bulkImport
        ),
        auditContext: context
    )

    let expiredContinuationFromLifecycle = lifecycle.markExpiredIfActive(id: expiredID)
    let cancelledContinuationFromLifecycle = lifecycle.markCancelledIfActive(id: cancelledID)
    #expect(expiredContinuationFromLifecycle === expiredContinuation)
    #expect(cancelledContinuationFromLifecycle === cancelledContinuation)
    #expect(lifecycle.pendingRequest(id: expiredID) == nil)
    #expect(lifecycle.pendingRequest(id: cancelledID) == nil)

    lifecycle.cleanup(id: expiredID)
    lifecycle.cleanup(id: cancelledID)

    #expect(lifecycle.intent(for: expiredID) == nil)
    #expect(lifecycle.intent(for: cancelledID) == nil)
    #expect(lifecycle.state(for: expiredID) == .expired)
    #expect(lifecycle.state(for: cancelledID) == .cancelled)
}

@Test func catalogWriteAccessLifecycleBoundsRetainedTerminalStates() {
    var lifecycle = CatalogWriteAccessLifecycle()
    let context = AuditContext(source: .agent)

    for offset in 0..<140 {
        let id = UUID()
        lifecycle.insert(
            CatalogAgentWriteAccessRequest(
                id: id,
                source: .mcpClient,
                reasonCategory: .other,
                createdAt: String(format: "2026-09-12T12:%02d:00Z", offset % 60)
            ),
            auditContext: context
        )
        lifecycle.markDenied(id: id)
        lifecycle.cleanup(id: id)
    }

    #expect(lifecycle.retainedStateCount <= 128)
}

@Test func catalogWriteAccessContinuationBoxResumesOnlyOnce() async throws {
    let box = CatalogWriteAccessContinuationBox()

    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
        box.store(continuation)
        box.resume()
        box.resume()
    }
}
