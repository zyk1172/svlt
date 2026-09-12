import CryptoKit
import Foundation
import Testing
@testable import VaultCore

@Test func moduleHasFormatVersion() {
    #expect(VaultFormat.current == 2)
    #expect(VaultFormat.legacyV1 == 1)
}

@Test func explicitPlaintextOverrideHasNoSecretPayload() throws {
    let override = ExplicitPlaintextOverride.userSuppliedForCurrentOperation

    #expect(override.scope == .userExplicitPlaintext)
    #expect(override.source == .userCurrentRequest)
    #expect(override == .userSuppliedForCurrentOperation)

    let encoded = try JSONEncoder().encode(override)
    let decoded = try JSONDecoder().decode(ExplicitPlaintextOverride.self, from: encoded)
    #expect(decoded == override)
    #expect(!String(decoding: encoded, as: UTF8.self).contains("plaintext-value"))
}

@Test func explicitNoSVLTSelectionAlsoUsesUserPlaintextScope() {
    let selection = SVLTCredentialSelection.userPlaintext(.explicitlySelectedNoSVLT)

    #expect(selection.scope == .userExplicitPlaintext)
    #expect(selection.source == .userCurrentRequest)
    #expect(selection.shouldSearchSVLT == false)
    #expect(selection.shouldInvokeSVLT == false)
}

@Test func credentialSelectionIsPerOperationAndDoesNotInheritPreviousSVLT() {
    let previous = SVLTCredentialSelection.svlt
    let current = SVLTCredentialSelection.userPlaintext(.userSuppliedForCurrentOperation)

    #expect(previous.scope == .svltManagedOperation)
    #expect(current.scope == .userExplicitPlaintext)
    #expect(current.source == .userCurrentRequest)
    #expect(current.shouldSearchSVLT == false)
}

@Test func credentialSelectionUsesTheCurrentSourceForEveryOperation() {
    let previousExternal = SVLTCredentialSelection.externalProvider
    let currentSVLT = SVLTCredentialSelection.svlt

    #expect(previousExternal.scope == .externalProviderOperation)
    #expect(currentSVLT.scope == .svltManagedOperation)
    #expect(currentSVLT.source == .explicitSVLTReference)
    #expect(currentSVLT.shouldInvokeSVLT)
}

@Test func SVLTDoesNotCompareIndependentUserPlaintextWithManagedSecret() {
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .userExplicitPlaintext,
        approvedSVLTOperation: false
    ))
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .externalProviderCredential,
        approvedSVLTOperation: false
    ))
    #expect(!SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .svltDerivedPlaintext,
        approvedSVLTOperation: false
    ))
    #expect(SVLTPlaintextBoundary.mayLeaveSVLTOperation(
        provenance: .svltDerivedPlaintext,
        approvedSVLTOperation: true
    ))
}

@Test func auditRecentIndexSeparatesBoundedReadsFromFullIntegrityScan() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-index-smoke-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }

    let log = EncryptedAuditLog(directoryURL: directory)
    let masterKey = SymmetricKey(data: Data(repeating: 0x71, count: 32))
    let events = (0..<130).map { index in
        makeSmokeAuditEvent(timestamp: Date(timeIntervalSince1970: 2_000_000_000 + Double(index)))
    }
    var firstAuditURL: URL?

    for (index, event) in events.enumerated() {
        try await log.append(event, masterKey: masterKey)
        if index == 0 {
            firstAuditURL = try FileManager.default
                .contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .first(where: { $0.lastPathComponent.hasSuffix(".audit.json") })
        }
    }

    let initial = try await log.recentWithDiagnostics(limit: 10, masterKey: masterKey)
    #expect(initial.events == Array(events.suffix(10).reversed()))
    #expect(initial.diagnostics == .none)
    #expect(FileManager.default.fileExists(
        atPath: directory.appending(path: "recent-index.json").path
    ))

    let historicalURL = try #require(firstAuditURL)
    var object = try #require(
        JSONSerialization.jsonObject(with: Data(contentsOf: historicalURL)) as? [String: Any]
    )
    object["createdAt"] = 0
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        .write(to: historicalURL, options: [.atomic])

    let bounded = try await log.recentWithDiagnostics(limit: 10, masterKey: masterKey)
    #expect(bounded.events == Array(events.suffix(10).reversed()))
    #expect(bounded.diagnostics == .none)

    let integrity = try await log.integrityDiagnostics(masterKey: masterKey)
    #expect(integrity.authenticationFailureCount == 1)

    let afterScan = try await log.recentWithDiagnostics(limit: 10, masterKey: masterKey)
    #expect(afterScan.events == Array(events.suffix(10).reversed()))
    #expect(afterScan.diagnostics.authenticationFailureCount == 1)
}

@Test func auditRetentionCanUseIndependentAuditKey() async throws {
    let directory = FileManager.default.temporaryDirectory
        .appending(path: "audit-prune-smoke-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: directory) }

    let now = Date(timeIntervalSince1970: 2_100_000_000)
    let auditKey = SymmetricKey(data: Data(repeating: 0x72, count: 32))
    let log = EncryptedAuditLog(
        directoryURL: directory,
        auditKeyProvider: { auditKey },
        now: { now }
    )
    let old = makeSmokeAuditEvent(timestamp: now.addingTimeInterval(-31 * 24 * 60 * 60))
    let recent = makeSmokeAuditEvent(timestamp: now.addingTimeInterval(-29 * 24 * 60 * 60))

    try await log.append(old)
    try await log.append(recent)
    try await log.prune(retentionDays: 30)

    #expect(try await log.export() == [recent])
}

private func makeSmokeAuditEvent(timestamp: Date) -> AuditEvent {
    AuditEvent(
        timestamp: timestamp,
        integration: "vault-core-smoke",
        referenceID: nil,
        operation: .status,
        risk: 0,
        authorizationOutcome: .notRequired,
        declaredTarget: nil,
        status: .completed,
        exitCode: nil
    )
}
