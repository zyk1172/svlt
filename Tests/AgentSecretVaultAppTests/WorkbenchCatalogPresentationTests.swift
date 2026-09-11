import AppKit
import Foundation
import SwiftUI
import Testing
@testable import AgentSecretVaultApp
import VaultCore

@Test func pendingSecretResolverUsesAuthoritativeSourceOrder() {
    let document = fixtureDocument(
        indexes: ["index-a", "index-b"],
        entries: [
            entry("entry-a", index: "index-a", fields: [
                SecretCatalogFieldValue(key: "filled", label: "已填", type: .secret, secretRef: "secret://filled"),
                SecretCatalogFieldValue(key: "first", label: "密码", type: .secret)
            ]),
            entry("entry-b", index: "index-b", fields: [
                SecretCatalogFieldValue(key: "second", label: "Token", type: .secret)
            ])
        ]
    )

    let pending = PendingCatalogSecretResolver.resolve(in: document)
    #expect(pending?.indexID == "index-a")
    #expect(pending?.entryID == "entry-a")
    #expect(pending?.fieldKey == "first")
    #expect(pending?.remainingCount == 2)
}

@Test func pendingSecretResolverAdvancesAfterFirstPlaceholderIsFilled() {
    let first = SecretCatalogFieldValue(key: "first", label: "密码", type: .secret)
    let second = SecretCatalogFieldValue(key: "second", label: "Token", type: .secret)
    let base = entry("entry", index: "index", fields: [first, second])
    let document = fixtureDocument(indexes: ["index"], entries: [base])
    #expect(PendingCatalogSecretResolver.resolve(in: document)?.remainingCount == 2)

    let filled = entry("entry", index: "index", fields: [
        SecretCatalogFieldValue(key: "first", label: "密码", type: .secret, secretRef: "secret://first"),
        second
    ])
    let advanced = fixtureDocument(indexes: ["index"], entries: [filled])
    #expect(PendingCatalogSecretResolver.resolve(in: advanced)?.fieldKey == "second")
    #expect(PendingCatalogSecretResolver.resolve(in: advanced)?.remainingCount == 1)
}

@Test func catalogFieldDraftEditsHumanLabelWithoutChangingStableKey() {
    let field = SecretCatalogFieldValue(key: "field2", label: "密码", type: .secret, secretRef: "secret://password")
    let draft = CatalogFieldDraft.make(from: [field])[0]
    var edited = draft
    edited.field = SecretCatalogFieldValue(
        key: draft.field.key,
        label: "数据库密码",
        type: draft.field.type,
        agentVisible: draft.field.agentVisible,
        searchable: draft.field.searchable,
        value: draft.field.value,
        secretRef: draft.field.secretRef
    )
    let reopened = CatalogFieldDraft.make(from: [edited.field])[0]

    #expect(edited.id == draft.id)
    #expect(edited.field.key == "field2")
    #expect(edited.field.label == "数据库密码")
    #expect(reopened.field.key == "field2")
    #expect(reopened.field.label == "数据库密码")
    #expect(reopened.field.secretRef == "secret://password")
    #expect(edited.selectionID == draft.selectionID)
}

@Test func catalogFieldDraftKeepsServiceURLIdentityWhenLabelChanges() {
    let field = SecretCatalogFieldValue(
        key: CatalogFieldDraft.serviceAddressKey,
        label: "服务地址",
        type: .url,
        value: .string("http://192.168.2.240:3000")
    )
    let renamed = SecretCatalogFieldValue(
        key: field.key,
        label: "NewAPI 地址",
        type: field.type,
        agentVisible: field.agentVisible,
        searchable: field.searchable,
        value: field.value,
        secretRef: field.secretRef
    )

    let reopened = CatalogFieldDraft.make(
        from: [renamed],
        endpoints: CatalogFieldDraft.endpoints(from: [renamed])
    )

    #expect(reopened.count == 1)
    #expect(reopened[0].field.key == CatalogFieldDraft.serviceAddressKey)
    #expect(reopened[0].field.label == "NewAPI 地址")
    #expect(CatalogFieldDraft.endpoints(from: reopened.map(\.field)) == [
        CatalogEndpoint(type: "http", host: "192.168.2.240", port: 3000)
    ])
}

@Test func catalogFieldDraftGeneratesUniqueStableCustomKeys() {
    let baseFields = [
        SecretCatalogFieldValue(key: "field2", label: "已有字段", type: .text),
        SecretCatalogFieldValue(key: "field3", label: "另一个字段", type: .text)
    ]
    var drafts = CatalogFieldDraft.make(from: baseFields)

    let firstKey = CatalogFieldDraft.nextCustomFieldKey(for: drafts)
    drafts.append(CatalogFieldDraft.newField(key: firstKey))
    let secondKey = CatalogFieldDraft.nextCustomFieldKey(for: drafts)
    drafts.append(CatalogFieldDraft.newField(key: secondKey))

    #expect(firstKey == "field4")
    #expect(secondKey == "field5")
    #expect(!firstKey.isEmpty)
    #expect(Set(drafts.map { $0.field.key }).count == drafts.count)

    let renamed = SecretCatalogFieldValue(key: firstKey, label: "API", type: .text)
    let reopened = CatalogFieldDraft.make(from: [renamed])[0]
    #expect(reopened.field.key == firstKey)
    #expect(reopened.field.label == "API")
}

@Test func catalogRevealLifecycleKeepsTransientFocusLossSeparateFromHardInvalidation() {
    #expect(
        CatalogRevealLifecycleAction.forInterruption(.transientFocusLoss)
            == CatalogRevealLifecycleAction(
                hidePlaintext: true,
                cancelInFlight: false,
                invalidateGeneration: false
            )
    )
    #expect(
        CatalogRevealLifecycleAction.forInterruption(.hardSecurityInvalidation)
            == CatalogRevealLifecycleAction(
                hidePlaintext: true,
                cancelInFlight: true,
                invalidateGeneration: true
            )
    )
}

@Test func catalogRevealHoldsCallbackResultUntilAppBecomesActive() {
    var state = CatalogRevealPresentationState()
    let generation = UUID()

    #expect(
        state.receive(
            "pending-reveal-test-value",
            generation: generation,
            isActive: false
        )
            == .heldPending
    )
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == "pending-reveal-test-value")
    #expect(state.pendingGeneration == generation)

    #expect(state.presentPending(generation: generation) == .presented)
    #expect(state.pendingPlaintext == nil)
    #expect(state.pendingGeneration == nil)
    #expect(state.visiblePlaintext == "pending-reveal-test-value")
}

@Test func catalogRevealInvalidationDropsPendingCallbackResult() {
    var state = CatalogRevealPresentationState()
    let generation = UUID()
    _ = state.receive(
        "pending-reveal-test-value",
        generation: generation,
        isActive: false
    )

    state.invalidate()

    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == nil)
    #expect(state.pendingGeneration == nil)
    #expect(state.presentPending(generation: generation) == .noPending)
}

@Test func catalogRevealPendingResultCannotCrossRevealGeneration() {
    var state = CatalogRevealPresentationState()
    let originalGeneration = UUID()
    let replacementGeneration = UUID()
    _ = state.receive(
        "pending-reveal-test-value",
        generation: originalGeneration,
        isActive: false
    )

    #expect(state.presentPending(generation: replacementGeneration) == .noPending)
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == nil)
}

@Test func catalogRevealPendingPlaintextExpiresBeforeLaterActivation() {
    var state = CatalogRevealPresentationState()
    let generation = UUID()

    let transition = state.receive(
        "pending-reveal-test-value",
        generation: generation,
        isActive: false
    )
    #expect(transition == .heldPending)
    let expired = state.expirePending(generation: generation)
    #expect(expired)
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == nil)
    #expect(state.pendingGeneration == nil)
    let presentation = state.presentPending(generation: generation)
    #expect(presentation == .noPending)
}

@Test func catalogRevealPendingExpiryCannotClearNewerGeneration() {
    var state = CatalogRevealPresentationState()
    let originalGeneration = UUID()
    let replacementGeneration = UUID()

    _ = state.receive(
        "original-pending-reveal-test-value",
        generation: originalGeneration,
        isActive: false
    )
    _ = state.receive(
        "replacement-pending-reveal-test-value",
        generation: replacementGeneration,
        isActive: false
    )

    let expiredOriginal = state.expirePending(generation: originalGeneration)
    #expect(!expiredOriginal)
    #expect(state.pendingPlaintext == "replacement-pending-reveal-test-value")
    #expect(state.pendingGeneration == replacementGeneration)
    let presentation = state.presentPending(generation: replacementGeneration)
    #expect(presentation == .presented)
    #expect(state.visiblePlaintext == "replacement-pending-reveal-test-value")
}

@Test func catalogRevealExpiryStateStartsOnlyAfterPresentation() {
    var state = CatalogRevealPresentationState()
    let generation = UUID()

    _ = state.receive(
        "pending-reveal-test-value",
        generation: generation,
        isActive: false
    )
    state.expire()
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == "pending-reveal-test-value")

    _ = state.presentPending(generation: generation)
    #expect(state.visiblePlaintext == "pending-reveal-test-value")
    state.expire()
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == nil)
}

@Test func catalogRevealRejectsPendingResultFromAnInvalidatedGeneration() {
    var state = CatalogRevealPresentationState()
    let generation = UUID()

    _ = state.receive(
        "pending-reveal-test-value",
        generation: generation,
        isActive: false
    )

    #expect(state.presentPending(generation: UUID()) == .noPending)
    #expect(state.visiblePlaintext == nil)
    #expect(state.pendingPlaintext == nil)
}

@Test func catalogRevealPresentationWiringDefersExpiryForInactiveCallback() throws {
    let source = try workbenchSource()

    #expect(source.contains("@State private var revealPresentationStates"))
    #expect(source.contains("@State private var revealPendingExpiryTasks"))
    #expect(source.contains("isActive: scenePhase == .active && canPresentReveals"))
    #expect(source.contains("generation: generation"))
    #expect(source.contains("schedulePendingRevealExpiry(for: fieldKey, generation: generation)"))
    #expect(source.contains("state.expirePending(generation: generation)"))
    #expect(source.contains("CatalogRevealPresentationTiming.pendingTTL"))
    #expect(source.contains("CatalogRevealPresentationTiming.visibleTTL"))
    #expect(source.contains("private func presentPendingReveals()"))
    #expect(source.contains("state.presentPending(generation: generation)"))
    #expect(source.contains("scheduleRevealExpiry(for: fieldKey, generation: generation)"))
    #expect(source.contains("revealPendingExpiryTasks.values.forEach { $0.cancel() }"))
    #expect(source.contains("revealPresentationStates.removeAll()"))
}

@Test func catalogSecureInputIgnoresParentWindowKeyTransitions() throws {
    let source = try workbenchSource()
    guard let sheetStart = source.range(of: "private struct CatalogAgentSecureInputSheet"),
          let nextView = source.range(of: "private struct OverviewStatusStrip", range: sheetStart.upperBound..<source.endIndex)
    else {
        Issue.record("secure input sheet source not found")
        return
    }

    let sheet = source[sheetStart.lowerBound..<nextView.lowerBound]
    #expect(sheet.contains("NSApplication.didResignActiveNotification"))
    #expect(!sheet.contains("NSWindow.didResignKeyNotification"))
    #expect(!sheet.contains("onChange(of: scenePhase)"))
}

@Test func catalogFieldDraftProjectsExistingEndpointAsAnEditableField() {
    let fields = [
        SecretCatalogFieldValue(key: "username", label: "用户名", type: .text)
    ]
    let drafts = CatalogFieldDraft.make(
        from: fields,
        endpoints: [CatalogEndpoint(type: "http", host: "192.168.2.240", port: 3000)]
    )

    #expect(drafts.count == 2)
    #expect(drafts[0].field.key == CatalogFieldDraft.serviceAddressKey)
    #expect(drafts[0].field.label == "服务地址")
    #expect(drafts[0].field.type == .url)
    #expect(drafts[0].field.value == .string("http://192.168.2.240:3000"))
    #expect(drafts[1].field.key == "username")
}

@Test func catalogFieldDraftDoesNotDuplicateAnAlreadyVisibleServiceAddress() {
    let visibleAddress = SecretCatalogFieldValue(
        key: CatalogFieldDraft.serviceAddressKey,
        label: "服务地址",
        type: .url,
        value: .string("http://192.168.2.240:3000")
    )
    let drafts = CatalogFieldDraft.make(
        from: [visibleAddress],
        endpoints: [CatalogEndpoint(type: "http", host: "192.168.2.240", port: 3000)]
    )

    #expect(drafts.count == 1)
    #expect(drafts[0].field.value == .string("http://192.168.2.240:3000"))
}

@Test func catalogFieldDraftKeepsUnrelatedURLAndProjectsEveryEndpoint() {
    let documentationURL = SecretCatalogFieldValue(
        key: "documentation",
        label: "文档地址",
        type: .url,
        value: .string("https://docs.example.com")
    )
    let drafts = CatalogFieldDraft.make(
        from: [documentationURL],
        endpoints: [
            CatalogEndpoint(type: "http", host: "192.168.2.240", port: 3000),
            CatalogEndpoint(type: "ssh", host: "192.168.2.240", port: 22)
        ]
    )

    #expect(drafts.count == 3)
    #expect(drafts.filter { $0.field.type == .url }.map { $0.field.value } == [
        .string("http://192.168.2.240:3000"),
        .string("ssh://192.168.2.240:22"),
        .string("https://docs.example.com")
    ])
}

@Test func catalogFieldDraftOnlyServiceAddressFieldsWriteCatalogEndpoints() {
    let fields = [
        SecretCatalogFieldValue(
            key: "documentation",
            label: "文档地址",
            type: .url,
            value: .string("https://docs.example.com")
        ),
        SecretCatalogFieldValue(
            key: CatalogFieldDraft.serviceAddressKey,
            label: "服务地址",
            type: .url,
            value: .string("http://192.168.2.240:3000")
        )
    ]

    #expect(CatalogFieldDraft.endpoints(from: fields) == [
        CatalogEndpoint(type: "http", host: "192.168.2.240", port: 3000)
    ])
    let roundTripped = CatalogFieldDraft.make(
        from: fields,
        endpoints: CatalogFieldDraft.endpoints(from: fields)
    )
    #expect(roundTripped.map(\.field) == fields)
}

@Test func batchSelectionHasExplicitBeginSelectAllAndFinishState() {
    var state = CatalogBatchSelectionState()
    state.begin()
    state.toggle("a")
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["a"])
    state.selectAll(["a", "b"])
    #expect(state.selectedIDs == ["a", "b"])
    state.deleteSucceeded(["a"])
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["b"])
    state.finish()
    #expect(!state.isSelecting)
    #expect(state.selectedIDs.isEmpty)
}

@Test func deletionSummaryCountsGroupsEntriesAndSecretFields() {
    let entries = [
        entry("a", index: "one", fields: [SecretCatalogFieldValue(key: "secret", label: "密码", type: .secret)]),
        entry("b", index: "two", fields: [SecretCatalogFieldValue(key: "name", label: "用户名", type: .text)])
    ]
    let document = fixtureDocument(indexes: ["one", "two"], entries: entries)
    #expect(CatalogDeletionSummary.indexes(ids: ["one", "two"], in: document) == .init(itemCount: 2, entryCount: 2, secretFieldCount: 1))
    #expect(CatalogDeletionSummary.entries(ids: ["a", "b"], in: entries) == .init(itemCount: 2, entryCount: 0, secretFieldCount: 1))
}

@Test func catalogFieldPresentationUsesSemanticValuesForOrdinaryFields() {
    let cases: [(SecretCatalogValue, String)] = [
        (.string("QNAP NAS"), "QNAP NAS"),
        (.number(192.0), "192.0"),
        (.boolean(true), "是"),
        (.list(["admin", "operator"]), "admin, operator")
    ]

    for (value, expected) in cases {
        let field = SecretCatalogFieldValue(
            key: "metadata",
            label: "元数据",
            type: .text,
            value: value
        )
        let presentation = CatalogFieldPresentation.resolve(field: field)
        #expect(presentation.displayText == expected)
        #expect(presentation.actionKind == .copy)
        #expect(presentation.allowsCopy)
        #expect(!presentation.isSecret)
    }
}

@Test func catalogFieldPresentationSeparatesSecretPlaceholderBoundAndRevealedStates() {
    let placeholder = SecretCatalogFieldValue(key: "secret", label: "密码", type: .secret)
    let placeholderPresentation = CatalogFieldPresentation.resolve(field: placeholder)
    #expect(placeholderPresentation.displayText == "未填写")
    #expect(placeholderPresentation.actionKind == .fillSecret)
    #expect(!placeholderPresentation.allowsCopy)
    let stalePlaceholderPresentation = CatalogFieldPresentation.resolve(
        field: placeholder,
        revealedPlaintext: "stale-transient-value"
    )
    #expect(stalePlaceholderPresentation.displayText == "未填写")
    #expect(stalePlaceholderPresentation.actionKind == .fillSecret)

    let bound = SecretCatalogFieldValue(
        key: "secret",
        label: "密码",
        type: .secret,
        secretRef: "secret://opaque"
    )
    let boundPresentation = CatalogFieldPresentation.resolve(field: bound)
    #expect(boundPresentation.displayText == "已加密")
    #expect(boundPresentation.actionKind == .reveal)
    #expect(!boundPresentation.allowsCopy)

    let revealedPresentation = CatalogFieldPresentation.resolve(
        field: bound,
        revealedPlaintext: "transient-value"
    )
    #expect(revealedPresentation.displayText == "transient-value")
    #expect(revealedPresentation.isRevealed)
    #expect(revealedPresentation.actionKind == .copy)
    #expect(revealedPresentation.allowsCopy)
}

@Test func catalogDetailColumnWidthsKeepValueColumnAsTheFlexibleColumn() {
    let widths = CatalogDetailColumnWidths.calculate(availableWidth: 760)
    #expect(widths.name < widths.value)
    #expect(widths.action < widths.value)
    #expect(abs((widths.name + widths.value + widths.action) - 728) < 0.001)

    let narrow = CatalogDetailColumnWidths.calculate(availableWidth: 300)
    #expect(narrow.name >= 90)
    #expect(narrow.action >= 72)
    #expect(narrow.value >= 0)
}

@Test func catalogDetailGridWidthLeavesSymmetricHorizontalGuides() {
    let sheetWidth: CGFloat = 760
    let gridWidth = CatalogDetailMetrics.gridAvailableWidth(for: sheetWidth)
    let widths = CatalogDetailColumnWidths.calculate(availableWidth: gridWidth)

    #expect(gridWidth == sheetWidth - CatalogDetailMetrics.horizontalPadding * 2)
    #expect(abs((widths.name + widths.value + widths.action) + CatalogDetailMetrics.gridHorizontalSpacing * 2 - gridWidth) < 0.001)
    #expect(CatalogDetailMetrics.gridAvailableWidth(for: 0) == 0)
}

@Test func catalogGroupPaneWidthUsesRatioWithUsableBounds() {
    #expect(CatalogGroupLayout.paneWidth(availableWidth: 700) == CatalogGroupLayout.minimumPaneWidth)
    #expect(CatalogGroupLayout.paneWidth(availableWidth: 1_000) == 280)
    #expect(CatalogGroupLayout.paneWidth(availableWidth: 1_400) == CatalogGroupLayout.maximumPaneWidth)
}

@Test func auditReadDiagnosticsPreserveDetailedCategoriesAndLegacyWireData() throws {
    let diagnostics = AuditReadDiagnostics(
        recordDecodeFailureCount: 1,
        authenticationFailureCount: 2,
        eventDecodeFailureCount: 3,
        unsupportedMetadataVersionCount: 4,
        legacyCompatibilityFailureCount: 5
    )
    #expect(diagnostics.skippedRecordCount == 15)
    #expect(diagnostics.hasIssues)

    let roundTrip = try JSONDecoder().decode(
        AuditReadDiagnostics.self,
        from: JSONEncoder().encode(diagnostics)
    )
    #expect(roundTrip == diagnostics)

    let wire = try #require(
        JSONSerialization.jsonObject(with: JSONEncoder().encode(diagnostics)) as? [String: Any]
    )
    #expect(wire["unreadableRecordCount"] as? Int == 13)
    #expect(wire["integrityFailureCount"] as? Int == 2)

    let legacy = try JSONDecoder().decode(
        AuditReadDiagnostics.self,
        from: Data("{\"unreadableRecordCount\":1,\"integrityFailureCount\":2}".utf8)
    )
    #expect(legacy.recordDecodeFailureCount == 1)
    #expect(legacy.authenticationFailureCount == 2)
    #expect(legacy.skippedRecordCount == 3)
}

@Test func catalogFieldDraftValidationMatchesCommitBoundaryRules() {
    let validURL = SecretCatalogFieldValue(
        key: "url",
        label: "地址",
        type: .url,
        value: .string("https://example.com")
    )
    let invalidURL = SecretCatalogFieldValue(
        key: "url",
        label: "地址",
        type: .url,
        value: .string("not a URL")
    )
    let validDate = SecretCatalogFieldValue(
        key: "date",
        label: "日期",
        type: .date,
        value: .string("2026-08-29")
    )
    let invalidDate = SecretCatalogFieldValue(
        key: "date",
        label: "日期",
        type: .date,
        value: .string("2026-99-99")
    )

    #expect(CatalogFieldDraftValidation.message(for: validURL) == nil)
    #expect(CatalogFieldDraftValidation.message(for: invalidURL) == "URL 格式不正确")
    #expect(CatalogFieldDraftValidation.message(for: validDate) == nil)
    #expect(CatalogFieldDraftValidation.message(for: invalidDate) == "日期应为 YYYY-MM-DD 或 ISO 8601 格式")
}

@Test func batchSelectionRetainsVisibleIDsAfterAuthoritativeRefresh() {
    var state = CatalogBatchSelectionState()
    state.begin()
    state.selectAll(["still-present", "removed"])
    state.retainVisibleIDs(["still-present", "new"])
    #expect(state.isSelecting)
    #expect(state.selectedIDs == ["still-present"])
}

@Test func auditRefreshReducerPreservesEntriesAcrossIndependentFailures() {
    let previous = [fixtureAuditEntry(target: "previous")]
    let current = [fixtureAuditEntry(target: "current")]

    let healthy = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .normal
    )
    #expect(healthy.entries == current)
    #expect(healthy.warning == nil)

    let partiallyReadable = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .partial(
            entries: current,
            diagnostics: AuditReadDiagnostics(unreadableRecordCount: 1, integrityFailureCount: 2)
        ),
        health: .normal
    )
    #expect(partiallyReadable.entries == current)
    #expect(partiallyReadable.warning?.contains("无法解析 1 条") == true)
    #expect(partiallyReadable.warning?.contains("认证失败 2 条") == true)

    let appendFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .appendFailed
    )
    #expect(appendFailed.entries == current)
    #expect(appendFailed.warning?.contains("写入异常") == true)

    let healthFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .success(current),
        health: .failure
    )
    #expect(healthFailed.entries == current)
    #expect(healthFailed.warning?.contains("AUDIT_HEALTH_READ_FAILED") == true)

    let activityFailed = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .failure(code: "AUDIT_READ_FAILED")
    )
    #expect(activityFailed.entries == previous)
    #expect(activityFailed.warning?.contains("AUDIT_READ_FAILED") == true)

    let unavailable = AuditRefreshState.reduce(
        previousEntries: previous,
        activity: .unavailable
    )
    #expect(unavailable.entries == previous)
    #expect(unavailable.warning?.contains("APP_CONTROL_UNAVAILABLE") == true)
}

@Test func overviewKeepsRecentAutomationBeforeConditionalPendingSecretCard() throws {
    let source = try workbenchSource()
    guard let overviewStart = source.range(of: "private var overviewPage") else {
        Issue.record("overviewPage not found")
        return
    }
    let overview = source[overviewStart.lowerBound...]
    guard let hero = overview.range(of: "OverviewHero("),
          let activity = overview.range(of: "CompactAuditPreviewCard("),
          let pending = overview.range(of: "PendingSecretFillCard(")
    else {
        Issue.record("overview cards not found")
        return
    }
    #expect(hero.lowerBound < activity.lowerBound)
    #expect(activity.lowerBound < pending.lowerBound)
    #expect(overview.contains("minHeight: 160"))
    #expect(overview.contains("minHeight: 120"))
    #expect(overview.contains("idealHeight: 140"))
    #expect(overview.contains(".layoutPriority(1)"))
    #expect(source.contains("bottomPadding: 12"))
    #expect(source.contains("GeometryReader { proxy in"))
    #expect(source.contains(".frame(width: proxy.size.width, height: proxy.size.height, alignment: .topLeading)"))
    #expect(!overview.contains("CompactAuditPreviewCard(entries: auditEntries, errorMessage: auditError)\n                .layoutPriority(1)"))
    #expect(!overview.contains(".workbenchOverviewSection(.pending)\n                .padding(.bottom, 12)"))
    #expect(!overview.contains("PendingSecretFillCard(\n                    pending: pending,\n                    entry: pendingEntry,\n                    commit: commitCatalogEntryEdit\n                )\n                .fixedSize"))
}

@Test func entryCardKeepsIndependentHitRegionsAndFieldEditorHasOneDraftSource() throws {
    let source = try workbenchSource()
    guard let cardStart = source.range(of: "private var normalCard"),
          let detailsStart = source.range(of: "private var entryDetails")
    else {
        Issue.record("entry card regions not found")
        return
    }
    let card = source[cardStart.lowerBound..<detailsStart.lowerBound]
    #expect(!card.contains(".onTapGesture"))
    #expect(card.contains("Button { showingDetails = true }"))
    #expect(card.contains("Button(\"删除\", role: .destructive, action: requestDelete)"))

    #expect(source.contains("ForEach($draftFields)"))
    #expect(source.contains("CatalogFieldDraft"))
    #expect(source.contains("TextField(\"字段名称\", text: labelBinding)"))
    #expect(!source.contains("TextField(\"key\""))
    #expect(!source.contains("keyBinding"))
    #expect(!source.contains("hasUnsavedKeyChange"))
    #expect(!source.contains("originalKey"))
    #expect(!source.contains("字段 key 已修改"))
    #expect(source.contains("key: current.key"))
    #expect(source.contains("let key = field.key"))
    #expect(!source.contains("ForEach($draftFields, id: \\.key)"))
    #expect(source.contains("fieldSelection"))
    #expect(source.contains("deleteSelectedFields()"))
    #expect(!source.contains("应用字段"))
    #expect(!source.contains("取消编辑"))
    #expect(source.contains("CatalogDetailMetrics.horizontalPadding"))
    #expect(source.contains("private var detailActionBar"))
    #expect(source.contains("Button(isSaving ? \"保存中…\" : \"保存条目\")"))
    #expect(source.contains("Button(\"关闭\")"))
    #expect(source.contains("closeDetails()"))
    #expect(source.contains("private func cancelEditing()"))
    #expect(!source.contains("@State private var pendingSecretInputs"))
    #expect(!source.contains("onKeyChange:"))
    #expect(!source.contains(".toolbar"))
    #expect(source.contains("prompt: Text(\"输入密码\").foregroundStyle(.orange)"))

    guard let pendingStart = source.range(of: "struct PendingSecretFillCard"),
          let auditPreviewStart = source.range(of: "struct CompactAuditPreviewCard")
    else {
        Issue.record("pending secret fill card not found")
        return
    }
    let pendingCard = source[pendingStart.lowerBound..<auditPreviewStart.lowerBound]
    #expect(pendingCard.contains("@State private var isPlaintextVisible = true"))
    #expect(pendingCard.contains("TextField("))
    #expect(pendingCard.contains("Image(systemName: isPlaintextVisible ? \"eye.slash\" : \"eye\")"))
    #expect(pendingCard.contains(".frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)"))
}

@MainActor @Test func overviewHostingFitsMinimumAndDefaultWindowWithAndWithoutPendingSecret() throws {
    let status = WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: true
    )
    let pending = PendingCatalogSecret(
        indexID: "index",
        indexTitle: String(repeating: "很长的分组标题 ", count: 8),
        entryID: "entry",
        entryTitle: String(repeating: "很长的条目标题 ", count: 8),
        fieldKey: "password",
        fieldLabel: String(repeating: "密码字段 ", count: 8),
        fieldType: .secret,
        remainingCount: 14
    )
    let pendingEntry = SecretCatalogEntry(
        id: "entry",
        indexId: "index",
        title: pending.entryTitle,
        fields: [SecretCatalogFieldValue(key: pending.fieldKey, label: pending.fieldLabel, type: .secret)]
    )
    let cases: [(size: CGSize, pending: PendingCatalogSecret?, entry: SecretCatalogEntry?, activityCount: Int)] = [
        (CGSize(width: 1_180, height: 760), pending, pendingEntry, 100),
        (CGSize(width: 1_280, height: 820), pending, pendingEntry, 100),
        (CGSize(width: 1_180, height: 760), nil, nil, 0),
        (CGSize(width: 1_280, height: 820), nil, nil, 0)
    ]

    for configuration in cases {
        let probe = OverviewLayoutProbe()
        let content = WorkbenchOverviewContent(
            status: status,
            agentServiceStatus: .running,
            agentServiceActionInFlight: false,
            agentServiceActionErrorMessage: nil,
            enableAgentService: nil,
            disableAgentService: nil,
            restartAgentService: nil,
            auditEntries: (0..<configuration.activityCount).map { fixtureAuditEntry(target: "activity-\($0)") },
            auditError: configuration.activityCount == 100 ? "部分安全活动记录异常" : nil,
            pending: configuration.pending,
            pendingEntry: configuration.entry,
            commitCatalogEntryEdit: nil
        )
        let root = content.onPreferenceChange(WorkbenchOverviewSectionFramesKey.self) { frames in
            probe.frames = frames
        }
        let hostingView = NSHostingView(rootView: root)
        hostingView.frame = NSRect(origin: .zero, size: configuration.size)
        hostingView.layoutSubtreeIfNeeded()
        RunLoop.main.run(until: Date().addingTimeInterval(0.01))
        hostingView.layoutSubtreeIfNeeded()

        let expectedIDs: Set<WorkbenchOverviewSectionID> = configuration.pending == nil
            ? [.hero, .activity]
            : [.hero, .activity, .pending]
        #expect(Set(probe.frames.keys) == expectedIDs)
        #expect(hostingView.frame.size == configuration.size)
        #expect(hostingView.fittingSize.height.isFinite)
        for frame in probe.frames.values {
            #expect(frame.minX >= -1)
            #expect(frame.minY >= -1)
            #expect(frame.maxX <= configuration.size.width + 1)
            #expect(frame.maxY <= configuration.size.height + 1)
        }
        let heroFrame = try #require(probe.frames[.hero])
        let activityFrame = try #require(probe.frames[.activity])
        #expect(activityFrame.minY >= heroFrame.maxY + 11)
        if configuration.pending != nil {
            let pendingFrame = try #require(probe.frames[.pending])
            #expect(pendingFrame.height >= 119)
            #expect(pendingFrame.height <= 171)
            #expect(pendingFrame.minY >= activityFrame.maxY + 11)
            #expect(abs(pendingFrame.maxY - configuration.size.height) <= 1)
        }
        #expect(activityFrame.height >= 159)
    }
}

@MainActor @Test func allWorkbenchPagesFitFixedViewports() throws {
    let status = WorkbenchStatus(
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: true
    )
    let index = SecretCatalogIndex(id: "index", title: String(repeating: "长分组标题 ", count: 5))
    let entries = (0..<13).map { number in
        SecretCatalogEntry(
            id: "entry-\(number)",
            indexId: index.id,
            title: String(repeating: "长条目标题 ", count: 4) + "\(number)",
            fields: [
                SecretCatalogFieldValue(key: "username", label: "用户名", type: .text, value: .string("user")),
                SecretCatalogFieldValue(key: "password", label: "密码", type: .secret)
            ]
        )
    }
    let pending = PendingCatalogSecret(
        indexID: index.id,
        indexTitle: index.title,
        entryID: entries[0].id,
        entryTitle: entries[0].title,
        fieldKey: "password",
        fieldLabel: "密码",
        fieldType: .secret,
        remainingCount: 13
    )
    let activity = (0..<100).map { fixtureAuditEntry(target: "activity-\($0)") }

    let pageFactories: [(String, () -> AnyView)] = [
        ("overview", {
            AnyView(WorkbenchPage(title: "控制台", subtitle: "", systemImage: "square.grid.2x2", bottomPadding: 12) {
                WorkbenchViewportMeasuredContent(id: "content") {
                    WorkbenchOverviewContent(
                        status: status,
                        agentServiceStatus: .running,
                        agentServiceActionInFlight: false,
                        agentServiceActionErrorMessage: nil,
                        enableAgentService: nil,
                        disableAgentService: nil,
                        restartAgentService: nil,
                        auditEntries: activity,
                        auditError: "部分安全活动记录异常",
                        pending: pending,
                        pendingEntry: entries[0],
                        commitCatalogEntryEdit: nil
                    )
                }
            })
        }),
        ("secrets", {
            AnyView(WorkbenchPage(title: "敏感信息", subtitle: "", systemImage: "list.bullet.indent") {
                WorkbenchViewportMeasuredContent(id: "content") {
                    SensitiveCatalogGroupSheet(
                        index: index,
                        entries: entries,
                        createEntry: nil,
                        commitEntryEdit: nil,
                        revealCatalogField: nil,
                        replaceCatalogSecret: nil,
                        entrySelection: .constant(CatalogBatchSelectionState()),
                        requestEntryDeletion: { _ in }
                    )
                }
            })
        }),
        ("automation", {
            AnyView(WorkbenchPage(title: "智能体自动化", subtitle: "", systemImage: "sparkles.rectangle.stack") {
                WorkbenchViewportMeasuredContent(id: "content") {
                    AgentAutomationAuditCard(entries: activity, errorMessage: "部分安全活动记录异常")
                }
            })
        }),
        ("tutorial", {
            AnyView(WorkbenchPage(title: "使用教程", subtitle: "", systemImage: "book") {
                WorkbenchViewportMeasuredContent(id: "content") {
                    TutorialPage()
                }
            })
        }),
        ("faq", {
            AnyView(WorkbenchPage(title: "常见问题", subtitle: "", systemImage: "questionmark.circle") {
                WorkbenchViewportMeasuredContent(id: "content") {
                    FAQPage()
                }
            })
        })
    ]

    for size in [CGSize(width: 1_180, height: 760), CGSize(width: 1_280, height: 820)] {
        for (name, makePage) in pageFactories {
            let probe = WorkbenchViewportProbe()
            let root = makePage()
                .coordinateSpace(name: "workbench-layout-regression")
                .onPreferenceChange(WorkbenchViewportFramesKey.self) { frames in
                    probe.frames = frames
                }
            let hostingView = NSHostingView(rootView: root)
            hostingView.frame = NSRect(origin: .zero, size: size)
            hostingView.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.01))
            hostingView.layoutSubtreeIfNeeded()

            let contentFrame = try #require(probe.frames["content"], "missing frame for \(name)")
            #expect(contentFrame.minX >= -1)
            #expect(contentFrame.minY >= -1)
            #expect(contentFrame.maxX <= size.width + 1)
            #expect(contentFrame.maxY <= size.height + 1)
            #expect(hostingView.fittingSize.width.isFinite)
            #expect(hostingView.fittingSize.height.isFinite)
        }
    }
}

@Test func mainWindowUsesHiddenTitleBarWithoutRemovingMacOSChrome() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)
    #expect(source.contains("Window(\"SVLT\", id: MenuBarPresentation.mainWindowID)"))
    #expect(source.contains(".windowStyle(.hiddenTitleBar)"))
    #expect(source.contains("MenuBarExtra(\"SVLT\""))
}

private func fixtureDocument(indexes: [String], entries: [SecretCatalogEntry]) -> SecretCatalogDocument {
    SecretCatalogDocument(indexes: indexes.map { SecretCatalogIndex(id: $0, title: $0) }, entries: entries)
}

private func workbenchSource() throws -> String {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    return try String(contentsOf: sourceURL, encoding: .utf8)
}

private func entry(_ id: String, index: String, fields: [SecretCatalogFieldValue]) -> SecretCatalogEntry {
    SecretCatalogEntry(id: id, indexId: index, title: id, fields: fields)
}

private func fixtureAuditEntry(target: String) -> CatalogSecurityAuditEntry {
    CatalogSecurityAuditEntry(
        id: UUID(),
        timestamp: Date(timeIntervalSince1970: 0),
        source: .agent,
        operation: .status,
        authorizationOutcome: .notRequired,
        result: .completed,
        target: target,
        referenceCount: 0
    )
}

@MainActor
private final class OverviewLayoutProbe {
    var frames: [WorkbenchOverviewSectionID: CGRect] = [:]
}

private struct WorkbenchViewportFramesKey: PreferenceKey {
    static let defaultValue: [String: CGRect] = [:]

    static func reduce(value: inout [String: CGRect], nextValue: () -> [String: CGRect]) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}

private struct WorkbenchViewportMeasuredContent<Content: View>: View {
    let id: String
    let content: Content

    init(id: String, @ViewBuilder content: () -> Content) {
        self.id = id
        self.content = content()
    }

    var body: some View {
        content.background {
            GeometryReader { proxy in
                Color.clear.preference(
                    key: WorkbenchViewportFramesKey.self,
                    value: [id: proxy.frame(in: .named("workbench-layout-regression"))]
                )
            }
        }
    }
}

@MainActor
private final class WorkbenchViewportProbe {
    var frames: [String: CGRect] = [:]
}
