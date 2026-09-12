import Foundation
import Testing
import VaultCore
@testable import VaultService

private let transactionEntryID = "0123456789ABCDEFGHJKMNPQT"
private let transactionFieldKey = "password"

@Test func secureInputTransactionAllowsOneSubmissionAndLatchesCancellation() throws {
    var transaction = CatalogSecureInputTransaction()
    let requestID = UUID()
    let request = secureInputRequest(id: requestID)
    transaction.insert(request)

    #expect(transaction.pendingRequestIDs == [requestID])
    let submitted = try transaction.beginSubmission(id: requestID, now: request.createdAt)
    #expect(submitted == request)
    #expect(transaction.state(for: requestID) == .submitting)

    transaction.latchAbort(.cancelled, for: requestID)
    #expect(throws: CatalogSecureInputAbortError.cancelled) {
        try transaction.ensureSubmissionIsStillActive(
            id: requestID,
            request: request,
            now: request.createdAt
        )
    }

    let status = CatalogSecureInputStatus(
        requestID: requestID,
        status: .cancelled,
        errorCode: "SECURE_INPUT_CANCELLED"
    )
    let finished = transaction.finish(id: requestID, status: status, terminalDate: request.createdAt)
    #expect(finished == request)
    #expect(transaction.hasRequest(forEntryID: request.entryID) == false)
    #expect(transaction.status(for: requestID) == status)
}

@Test func secureInputTransactionKeepsCommittingRequestsOutsideCancellationQueue() throws {
    var transaction = CatalogSecureInputTransaction()
    let requestID = UUID()
    let request = secureInputRequest(id: requestID)
    transaction.insert(request)
    _ = try transaction.beginSubmission(id: requestID, now: request.createdAt)

    try transaction.markCommitting(id: requestID, request: request, now: request.createdAt)

    #expect(transaction.state(for: requestID) == .committing)
    #expect(transaction.pendingRequest(id: requestID) == nil)
    #expect(transaction.pendingRequestIDs.isEmpty)
    #expect(transaction.hasRequest(forEntryID: request.entryID))
}

@Test func secureInputTransactionRestoresOnlyOpaqueTerminalReceiptsAndPrunesThem() {
    let now = Date(timeIntervalSinceReferenceDate: 10_000)
    let requestID = UUID()
    let status = CatalogSecureInputStatus(
        requestID: requestID,
        status: .completed,
        revision: 2
    )
    var transaction = CatalogSecureInputTransaction()
    transaction.insert(secureInputRequest(id: requestID, createdAt: now))
    _ = transaction.finish(id: requestID, status: status, terminalDate: now)

    let records = transaction.receiptRecords(now: now)
    #expect(records.count == 1)
    #expect(records.first?.requestID == requestID)
    #expect(records.first?.status == .completed)
    #expect(records.first?.revision == 2)

    let restored = CatalogSecureInputTransaction(receipts: records)
    #expect(restored.status(for: requestID) == status)
    #expect(restored.pendingRequest(id: requestID) == nil)

    let didPrune = transaction.prune(now: now.addingTimeInterval(15 * 60 + 1))
    #expect(didPrune)
    #expect(transaction.status(for: requestID).status == .unknown)
}

@Test func secureInputTransactionReportsRequestsDueForExpiration() {
    let now = Date(timeIntervalSinceReferenceDate: 20_000)
    var transaction = CatalogSecureInputTransaction()
    let requestID = UUID()
    transaction.insert(secureInputRequest(id: requestID, createdAt: now))

    #expect(transaction.dueRequestIDs(now: now).isEmpty)
    #expect(transaction.dueRequestIDs(now: now.addingTimeInterval(181)) == [requestID])
}

private func secureInputRequest(
    id: UUID,
    createdAt: Date = Date(timeIntervalSinceReferenceDate: 1_000)
) -> CatalogAgentSecureInputRequest {
    CatalogAgentSecureInputRequest(
        id: id,
        correlationID: UUID(),
        requestID: id,
        entryID: transactionEntryID,
        entryTitle: "服务",
        expectedRevision: 1,
        createdAt: createdAt,
        expiresAt: createdAt.addingTimeInterval(180),
        targets: [CatalogSecureInputTarget(
            entryID: transactionEntryID,
            fieldKey: transactionFieldKey,
            label: "密码",
            mode: .fillPlaceholder,
            required: true
        )]
    )
}
