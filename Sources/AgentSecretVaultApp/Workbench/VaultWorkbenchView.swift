import AppKit
import SwiftUI
import VaultCore
import VaultIPC
import VaultService

/// Ordered, single-consumer state for MCP Catalog approval requests. The App
/// presents only `currentID`; completing it removes exactly that ID and leaves
/// later requests in FIFO order.
public struct PendingCatalogWriteAccessQueue: Equatable, Sendable {
    public private(set) var ids: [UUID] = []

    public init() {}

    public mutating func replace(with ids: [UUID]) {
        self.ids = ids
    }

    public mutating func finish(_ id: UUID) {
        ids.removeAll { $0 == id }
    }

    public var currentID: UUID? { ids.first }
    public var count: Int { ids.count }
}

public enum VaultWorkbenchCopy {
    public static let documentationURL = URL(string: "https://github.com/zyk1172/svlt") ?? URL(fileURLWithPath: "/")

    public static let disconnected = (
        status: "Obsidian 插件未连接",
        primaryAction: "先安装并启用 Obsidian 插件。"
    )

    public static let securityBoundary =
        "目录中的密码默认只显示为“已加密”；点击单个字段的“解密”后，明文只在本应用内短暂显示，并且每次都需要本机授权。"

    public static let simpleUsageSteps = [
        "1. 在“敏感信息”中打开分组和条目；普通字段直接显示，密码字段默认只显示“已加密”。",
        "2. 需要查看密码时，在具体字段点击“解密”，完成本机身份认证后明文短暂显示。",
        "3. 需要修改目录时，在 App 中编辑；Agent 每笔修改都会重新申请一次本机授权。"
    ]

    public static var mcpConfig: String {
        """
        {
          "mcpServers": {
            "SVLT": {
              "command": "/bin/zsh",
              "args": [
                "-lc",
                "exec node \\\"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\\\""
              ]
            }
          }
        }
        """
    }

    public static var agentPrompt: String {
        """
        SVLT 是 opt-in。看到 secret:// 或用户明确要求使用 SVLT 时，使用 SVLT；用户当前明确提供并要求使用的明文不受 SVLT 强制接管。
        不要把 SVLT 解密得到的明文交给普通 shell/curl；也不要把用户明确选择的明文自动转换成 secret://。
        凭据来源标签：SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL。

        \(SVLTAgentCatalogPolicy.text)
        """
    }

    public static let catalogPolicy = SVLTAgentCatalogPolicy.text
    public static let catalogSchema = SVLTAgentCatalogPolicy.schema
}

public struct CatalogMutationUIError: Error, Equatable, Sendable {
    public let code: String
    public let message: String

    public init(code: String, message: String) {
        self.code = code
        self.message = message
    }

    public var displayText: String { "\(message)（\(code)）" }
}

public typealias CatalogMutationUIResult = Result<CatalogWriteResult, CatalogMutationUIError>
public typealias CatalogEntryCreationError = CatalogMutationUIError
public typealias CatalogEntryCreationResult = CatalogMutationUIResult

/// The next authoritative empty secret field in Catalog source order.  This
/// model deliberately carries display metadata only; plaintext never enters
/// the resolver or the view-model it returns.
public struct PendingCatalogSecret: Equatable, Sendable {
    public let indexID: String
    public let indexTitle: String
    public let entryID: String
    public let entryTitle: String
    public let fieldKey: String
    public let fieldLabel: String
    public let fieldType: SecretCatalogFieldType
    public let remainingCount: Int

    public init(
        indexID: String,
        indexTitle: String,
        entryID: String,
        entryTitle: String,
        fieldKey: String,
        fieldLabel: String,
        fieldType: SecretCatalogFieldType,
        remainingCount: Int
    ) {
        self.indexID = indexID
        self.indexTitle = indexTitle
        self.entryID = entryID
        self.entryTitle = entryTitle
        self.fieldKey = fieldKey
        self.fieldLabel = fieldLabel
        self.fieldType = fieldType
        self.remainingCount = remainingCount
    }
}

public enum PendingCatalogSecretResolver {
    public static func resolve(in document: SecretCatalogDocument) -> PendingCatalogSecret? {
        var placeholders: [(SecretCatalogIndex, SecretCatalogEntry, SecretCatalogFieldValue)] = []
        for index in document.indexes {
            for entry in document.entries where entry.indexId == index.id {
                for field in entry.fields where field.type.isSecret && field.secretRef == nil {
                    placeholders.append((index, entry, field))
                }
            }
        }
        guard let first = placeholders.first else { return nil }
        return PendingCatalogSecret(
            indexID: first.0.id,
            indexTitle: first.0.title,
            entryID: first.1.id,
            entryTitle: first.1.title,
            fieldKey: first.2.key,
            fieldLabel: first.2.label,
            fieldType: first.2.type,
            remainingCount: placeholders.count
        )
    }
}

/// Small, shared selection state used by both Catalog batch-delete surfaces.
public struct CatalogBatchSelectionState: Equatable, Sendable {
    public private(set) var selectedIDs: Set<String> = []
    public private(set) var isSelecting = false

    public init() {}

    public mutating func begin() { isSelecting = true; selectedIDs.removeAll() }
    public mutating func toggle(_ id: String) {
        if selectedIDs.contains(id) { selectedIDs.remove(id) } else { selectedIDs.insert(id) }
    }
    public mutating func selectAll(_ ids: [String]) { selectedIDs = Set(ids) }
    public mutating func clear() { selectedIDs.removeAll() }
    public mutating func finish() { selectedIDs.removeAll(); isSelecting = false }
    public mutating func deleteSucceeded(_ ids: [String]) {
        selectedIDs.subtract(ids)
        if selectedIDs.isEmpty { isSelecting = false }
    }

    /// Reconcile selection after an authoritative Catalog refresh. This is
    /// intentionally not a successful delete: batch mode stays visible so the
    /// user must re-confirm a destructive operation after a revision change.
    public mutating func retainVisibleIDs(_ ids: [String]) {
        selectedIDs.formIntersection(Set(ids))
    }
}

public struct CatalogDeletionSummary: Equatable, Sendable {
    public let itemCount: Int
    public let entryCount: Int
    public let secretFieldCount: Int

    public static func indexes(ids: [String], in document: SecretCatalogDocument) -> Self {
        let entries = document.entries.filter { ids.contains($0.indexId) }
        return Self(
            itemCount: ids.count,
            entryCount: entries.count,
            secretFieldCount: entries.flatMap(\.fields).filter { $0.type.isSecret }.count
        )
    }

    public static func entries(ids: [String], in entries: [SecretCatalogEntry]) -> Self {
        let selected = entries.filter { ids.contains($0.id) }
        return Self(
            itemCount: ids.count,
            entryCount: 0,
            secretFieldCount: selected.flatMap(\.fields).filter { $0.type.isSecret }.count
        )
    }
}

/// The presentation state for one Catalog field. Authorization, IPC, and
/// plaintext acquisition stay outside this pure resolver.
public enum CatalogFieldActionKind: String, Equatable, Sendable {
    case copy
    case reveal
    case fillSecret
}

public struct CatalogFieldPresentation: Equatable, Sendable {
    public let displayText: String
    public let isSecret: Bool
    public let isRevealed: Bool
    public let actionKind: CatalogFieldActionKind
    public let allowsCopy: Bool

    public init(
        displayText: String,
        isSecret: Bool,
        isRevealed: Bool,
        actionKind: CatalogFieldActionKind,
        allowsCopy: Bool
    ) {
        self.displayText = displayText
        self.isSecret = isSecret
        self.isRevealed = isRevealed
        self.actionKind = actionKind
        self.allowsCopy = allowsCopy
    }

    public static func resolve(
        field: SecretCatalogFieldValue,
        revealedPlaintext: String? = nil
    ) -> Self {
        if field.type.isSecret {
            if field.secretRef != nil {
                if let revealedPlaintext {
                    return Self(
                        displayText: revealedPlaintext,
                        isSecret: true,
                        isRevealed: true,
                        actionKind: .copy,
                        allowsCopy: !revealedPlaintext.isEmpty
                    )
                }
                return Self(
                    displayText: "已加密",
                    isSecret: true,
                    isRevealed: false,
                    actionKind: .reveal,
                    allowsCopy: false
                )
            }
            return Self(
                displayText: "未填写",
                isSecret: true,
                isRevealed: false,
                actionKind: .fillSecret,
                allowsCopy: false
            )
        }

        let displayText = displayValue(for: field)
        return Self(
            displayText: displayText,
            isSecret: false,
            isRevealed: false,
            actionKind: .copy,
            allowsCopy: !displayText.isEmpty && displayText != "未填写" && displayText != "已隐藏"
        )
    }

    public static func displayValue(for field: SecretCatalogFieldValue) -> String {
        guard field.agentVisible else { return "已隐藏" }
        guard let value = field.value else { return "未填写" }
        switch value {
        case .string(let value): return value
        case .number(let value): return String(value)
        case .boolean(let value): return value ? "是" : "否"
        case .list(let value): return value.joined(separator: ", ")
        }
    }
}

/// Column widths for the three-column detail table. The helper receives only
/// available width, so layout behavior can be tested without rendering a
/// view. The value column receives the remaining space after Grid gaps.
public enum CatalogDetailMetrics {
    public static let horizontalPadding: CGFloat = 22
    public static let verticalPadding: CGFloat = 22
    public static let gridHorizontalSpacing: CGFloat = 16
    public static let gridVerticalSpacing: CGFloat = 12

    /// Keep the detail grid between the two shared horizontal content guides.
    public static func gridAvailableWidth(for sheetWidth: CGFloat) -> CGFloat {
        max(0, sheetWidth - horizontalPadding * 2)
    }
}

public enum CatalogFieldDraftValidation {
    public static func message(for field: SecretCatalogFieldValue) -> String? {
        guard let value = field.value else { return nil }
        switch field.type {
        case .url:
            guard case .string(let text) = value, text.isEmpty || isValidURL(text) else {
                return "URL 格式不正确"
            }
        case .date:
            guard case .string(let text) = value, text.isEmpty || isValidDate(text) else {
                return "日期应为 YYYY-MM-DD 或 ISO 8601 格式"
            }
        default:
            break
        }
        return nil
    }

    private static func isValidURL(_ value: String) -> Bool {
        guard let url = URL(string: value),
              let scheme = url.scheme,
              !scheme.isEmpty,
              let host = url.host,
              !host.isEmpty
        else {
            return false
        }
        return true
    }

    private static func isValidDate(_ value: String) -> Bool {
        if ISO8601DateFormatter().date(from: value) != nil {
            return true
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.dateFormat = "yyyy-MM-dd"
        return formatter.date(from: value) != nil
    }
}

public struct CatalogDetailColumnWidths: Equatable, Sendable {
    public let name: CGFloat
    public let value: CGFloat
    public let action: CGFloat

    public init(name: CGFloat, value: CGFloat, action: CGFloat) {
        self.name = name
        self.value = value
        self.action = action
    }

    public static func calculate(
        availableWidth: CGFloat,
        horizontalSpacing: CGFloat = CatalogDetailMetrics.gridHorizontalSpacing
    ) -> Self {
        let usable = max(0, availableWidth - horizontalSpacing * 2)
        let name = min(max(usable * 0.20, 90), 180)
        let action = min(max(usable * 0.15, 72), 120)
        return Self(
            name: name,
            value: max(0, usable - name - action),
            action: action
        )
    }
}

public enum AuditActivityReadResult: Equatable, Sendable {
    case unavailable
    case success([CatalogSecurityAuditEntry])
    case partial(entries: [CatalogSecurityAuditEntry], diagnostics: AuditReadDiagnostics)
    case failure(code: String)
}

public enum AuditHealthReadResult: Equatable, Sendable {
    case normal
    case appendFailed
    case failure
    case unknown
}

/// Pure reducer for the two independent AppControl reads used by the recent
/// activity cards. A failed read never erases the last verified entries.
public struct AuditRefreshState: Equatable, Sendable {
    public let entries: [CatalogSecurityAuditEntry]
    public let warning: String?

    public init(entries: [CatalogSecurityAuditEntry], warning: String?) {
        self.entries = entries
        self.warning = warning
    }

    public static func reduce(
        previousEntries: [CatalogSecurityAuditEntry],
        activity: AuditActivityReadResult,
        health: AuditHealthReadResult? = nil
    ) -> Self {
        switch activity {
        case .unavailable:
            return Self(
                entries: previousEntries,
                warning: "本机控制服务不可用（APP_CONTROL_UNAVAILABLE）；已保留最近一次可用记录。"
            )
        case let .failure(code):
            return Self(
                entries: previousEntries,
                warning: "安全活动记录读取失败（\(code)）；已保留最近一次可用记录。"
            )
        case let .success(entries):
            return Self(entries: entries, warning: healthWarning(for: health))
        case let .partial(entries, diagnostics):
            return Self(
                entries: entries,
                warning: combinedWarnings(
                    readWarning(for: diagnostics),
                    healthWarning(for: health)
                )
            )
        }
    }

    private static func combinedWarnings(_ warnings: String?...) -> String? {
        let values = warnings.compactMap { $0 }
        return values.isEmpty ? nil : values.joined(separator: " ")
    }

    private static func healthWarning(for health: AuditHealthReadResult?) -> String? {
        switch health ?? .failure {
        case .normal:
            return nil
        case .appendFailed:
            return "安全活动记录写入异常；近期活动可能不完整。"
        case .failure:
            return "无法确认安全活动记录完整性（AUDIT_HEALTH_READ_FAILED）；当前可读取记录仍予以显示。"
        case .unknown:
            return "无法确认安全活动记录完整性（AUDIT_HEALTH_UNKNOWN）；当前可读取记录仍予以显示。"
        }
    }

    private static func readWarning(for diagnostics: AuditReadDiagnostics) -> String? {
        guard diagnostics.hasIssues else { return nil }
        var details: [String] = []
        if diagnostics.recordDecodeFailureCount > 0 {
            details.append("无法解析 \(diagnostics.recordDecodeFailureCount) 条")
        }
        if diagnostics.unsupportedMetadataVersionCount > 0 {
            details.append("不支持的格式版本 \(diagnostics.unsupportedMetadataVersionCount) 条")
        }
        if diagnostics.authenticationFailureCount > 0 {
            details.append("认证失败 \(diagnostics.authenticationFailureCount) 条")
        }
        if diagnostics.eventDecodeFailureCount > 0 {
            details.append("事件解码失败 \(diagnostics.eventDecodeFailureCount) 条")
        }
        if diagnostics.legacyCompatibilityFailureCount > 0 {
            details.append("旧格式不兼容 \(diagnostics.legacyCompatibilityFailureCount) 条")
        }
        return "部分安全活动记录异常（\(details.joined(separator: "、"))）；已显示其余正常记录。"
    }
}

public enum VaultWorkbenchRenderingPolicy {
    public static let usesStableRendering = true
    public static let usesRepeatingAnimations = false
    public static let usesTransientAnimations = true
    public static let usesBlurredBackgrounds = false
    public static let usesMaterialBackgrounds = true
}

public enum VaultWorkbenchMotion {
    public static let interactive = Animation.easeInOut(duration: 0.18)
    public static let authorization = Animation.spring(response: 0.28, dampingFraction: 0.86)
}

private struct CatalogDetailContentHeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

private struct CatalogDetailAvailableWidthKey: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

public enum VaultWorkbenchSection: String, CaseIterable, Identifiable, Sendable {
    case overview
    case secrets
    case automation
    case tutorial
    case faq

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview:
            return "控制台"
        case .secrets:
            return "敏感信息"
        case .automation:
            return "智能体自动化"
        case .tutorial:
            return "使用教程"
        case .faq:
            return "常见问题"
        }
    }

    public var subtitle: String {
        switch self {
        case .overview:
            return "状态、快捷入口和最近动作"
        case .secrets:
            return "分组目录与独立加密记录"
        case .automation:
            return "查看脱敏后的本机使用记录"
        case .tutorial:
            return ""
        case .faq:
            return ""
        }
    }

    public var systemImage: String {
        switch self {
        case .overview:
            return "square.grid.2x2.fill"
        case .secrets:
            return "key.viewfinder"
        case .automation:
            return "sparkles.rectangle.stack.fill"
        case .tutorial:
            return "book.closed.fill"
        case .faq:
            return "questionmark.circle.fill"
        }
    }
}

public extension Notification.Name {
    static let vaultWorkbenchNavigate = Notification.Name("AgentSecretVaultWorkbenchNavigate")
    /// Authentication UI can briefly deactivate the App/window without
    /// representing a lock or sleep security boundary. Catalog detail views
    /// hide already displayed plaintext for this event but keep an in-flight
    /// owner authentication alive.
    static let vaultWorkbenchTransientFocusLost = Notification.Name(
        "AgentSecretVaultWorkbenchTransientFocusLost"
    )
    static let vaultWorkbenchSecurityStateInvalidated = Notification.Name(
        "AgentSecretVaultWorkbenchSecurityStateInvalidated"
    )
}

enum CatalogRevealInterruption: Sendable {
    case transientFocusLoss
    case hardSecurityInvalidation
}

struct CatalogRevealLifecycleAction: Equatable, Sendable {
    let hidePlaintext: Bool
    let cancelInFlight: Bool
    let invalidateGeneration: Bool

    static func forInterruption(_ interruption: CatalogRevealInterruption) -> Self {
        switch interruption {
        case .transientFocusLoss:
            return Self(
                hidePlaintext: true,
                cancelInFlight: false,
                invalidateGeneration: false
            )
        case .hardSecurityInvalidation:
            return Self(
                hidePlaintext: true,
                cancelInFlight: true,
                invalidateGeneration: true
            )
        }
    }
}

/// Keeps a decrypted Catalog result out of the visible state while the App or
/// its window is temporarily inactive for authentication UI.  This state is
/// deliberately separate from the in-flight authentication Task: a transient
/// focus loss may hide existing plaintext without cancelling the owner-auth
/// operation, while a hard security invalidation clears both values.
enum CatalogRevealPresentationTransition: Equatable, Sendable {
    case presented
    case heldPending
    case noPending
}

enum CatalogRevealPresentationTiming {
    /// Pending plaintext is held only briefly while the App returns from a
    /// transient authentication/focus transition. Task.sleep(for:) uses the
    /// continuous (monotonic) clock, so wall-clock changes cannot extend it.
    static let pendingTTL: Duration = .seconds(30)
    static let visibleTTL: Duration = .seconds(45)
}

struct CatalogRevealPresentationState: Equatable, Sendable {
    private(set) var visiblePlaintext: String?
    private(set) var pendingPlaintext: String?
    private(set) var pendingGeneration: UUID?

    init(
        visiblePlaintext: String? = nil,
        pendingPlaintext: String? = nil,
        pendingGeneration: UUID? = nil
    ) {
        self.visiblePlaintext = visiblePlaintext
        self.pendingPlaintext = pendingPlaintext
        self.pendingGeneration = pendingGeneration
    }

    @discardableResult
    mutating func receive(
        _ plaintext: String,
        generation: UUID,
        isActive: Bool
    ) -> CatalogRevealPresentationTransition {
        if isActive {
            pendingPlaintext = nil
            pendingGeneration = nil
            visiblePlaintext = plaintext
            return .presented
        }

        visiblePlaintext = nil
        pendingPlaintext = plaintext
        pendingGeneration = generation
        return .heldPending
    }

    @discardableResult
    mutating func presentPending(
        generation: UUID
    ) -> CatalogRevealPresentationTransition {
        guard let pendingPlaintext,
              pendingGeneration == generation
        else {
            visiblePlaintext = nil
            self.pendingPlaintext = nil
            pendingGeneration = nil
            return .noPending
        }
        self.pendingPlaintext = nil
        pendingGeneration = nil
        visiblePlaintext = pendingPlaintext
        return .presented
    }

    mutating func clearForNewReveal() {
        visiblePlaintext = nil
        pendingPlaintext = nil
        pendingGeneration = nil
    }

    mutating func invalidate() {
        clearForNewReveal()
    }

    mutating func hideVisible() {
        visiblePlaintext = nil
    }

    @discardableResult
    mutating func expirePending(generation: UUID) -> Bool {
        guard pendingPlaintext != nil,
              pendingGeneration == generation
        else { return false }

        pendingPlaintext = nil
        pendingGeneration = nil
        return true
    }

    mutating func expire() {
        visiblePlaintext = nil
    }
}

public struct VaultWorkbenchView: View {
    let status: WorkbenchStatus
    let agentServiceStatus: AgentServiceStatus
    let agentServiceActionInFlight: Bool
    let agentServiceActionErrorMessage: String?
    let enableAgentService: (() async -> Void)?
    let disableAgentService: (() async -> Void)?
    let restartAgentService: (() async -> Void)?
    let auditEntries: [CatalogSecurityAuditEntry]
    let auditError: String?
    let secureInputRequest: CatalogAgentSecureInputRequest?
    let submitSecureInput: ((CatalogAgentSecureInputRequest, [CatalogSecureInputTarget], [String: String]) async -> Void)?
    let cancelSecureInput: ((UUID) async -> Void)?
    let savedReferences: [SecretReferenceMetadata]
    let sensitiveIndexURL: URL?
    let sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    let sensitiveCatalogError: String?
    let sensitiveCatalogCanAdoptV2: Bool
    let sensitiveCatalogCanAdoptV3: Bool
    let refreshSavedReferences: (() async -> Void)?
    let chooseSensitiveIndex: (() -> Void)?
    let refreshSensitiveCatalog: (() async -> Void)?
    let validateSensitiveCatalog: (() async -> Void)?
    let adoptExternalV2Catalog: (() async -> Void)?
    let adoptExternalV3Catalog: (() async -> Void)?
    let approveExternalCatalogChange: (() async -> Void)?
    let formatRepairPlan: CatalogFormatRepairPlan?
    let checkSensitiveCatalogFormat: (() async -> Void)?
    let repairSensitiveCatalogFormat: (() async -> Void)?
    let createCatalogIndex: ((String) async -> CatalogMutationUIResult)?
    let createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitCatalogEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyCatalogBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?
    let showSensitiveCatalogTemplate: (() async -> Void)?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selectedSection: VaultWorkbenchSection = .overview

    public init(
        status: WorkbenchStatus,
        agentServiceStatus: AgentServiceStatus = .unavailable,
        agentServiceActionInFlight: Bool = false,
        agentServiceActionErrorMessage: String? = nil,
        enableAgentService: (() async -> Void)? = nil,
        disableAgentService: (() async -> Void)? = nil,
        restartAgentService: (() async -> Void)? = nil,
        auditEntries: [CatalogSecurityAuditEntry] = [],
        auditError: String? = nil,
        secureInputRequest: CatalogAgentSecureInputRequest? = nil,
        submitSecureInput: ((CatalogAgentSecureInputRequest, [CatalogSecureInputTarget], [String: String]) async -> Void)? = nil,
        cancelSecureInput: ((UUID) async -> Void)? = nil,
        savedReferences: [SecretReferenceMetadata] = [],
        sensitiveIndexURL: URL? = nil,
        sensitiveCatalogSnapshot: SensitiveCatalogSnapshot? = nil,
        sensitiveCatalogError: String? = nil,
        sensitiveCatalogCanAdoptV2: Bool = false,
        sensitiveCatalogCanAdoptV3: Bool = false,
        refreshSavedReferences: (() async -> Void)? = nil,
        chooseSensitiveIndex: (() -> Void)? = nil,
        refreshSensitiveCatalog: (() async -> Void)? = nil,
        validateSensitiveCatalog: (() async -> Void)? = nil,
        adoptExternalV2Catalog: (() async -> Void)? = nil,
        adoptExternalV3Catalog: (() async -> Void)? = nil,
        approveExternalCatalogChange: (() async -> Void)? = nil,
        formatRepairPlan: CatalogFormatRepairPlan? = nil,
        checkSensitiveCatalogFormat: (() async -> Void)? = nil,
        repairSensitiveCatalogFormat: (() async -> Void)? = nil,
        createCatalogIndex: ((String) async -> CatalogMutationUIResult)? = nil,
        createCatalogEntry: ((String, String, String) async -> CatalogMutationUIResult)? = nil,
        commitCatalogEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)? = nil,
        revealCatalogField: ((String, String) async throws -> String)? = nil,
        replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)? = nil,
        applyCatalogBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)? = nil,
        showSensitiveCatalogTemplate: (() async -> Void)? = nil
    ) {
        self.status = status
        self.agentServiceStatus = agentServiceStatus
        self.agentServiceActionInFlight = agentServiceActionInFlight
        self.agentServiceActionErrorMessage = agentServiceActionErrorMessage
        self.enableAgentService = enableAgentService
        self.disableAgentService = disableAgentService
        self.restartAgentService = restartAgentService
        self.auditEntries = auditEntries
        self.auditError = auditError
        self.secureInputRequest = secureInputRequest
        self.submitSecureInput = submitSecureInput
        self.cancelSecureInput = cancelSecureInput
        self.savedReferences = savedReferences
        self.sensitiveIndexURL = sensitiveIndexURL
        self.sensitiveCatalogSnapshot = sensitiveCatalogSnapshot
        self.sensitiveCatalogError = sensitiveCatalogError
        self.sensitiveCatalogCanAdoptV2 = sensitiveCatalogCanAdoptV2
        self.sensitiveCatalogCanAdoptV3 = sensitiveCatalogCanAdoptV3
        self.refreshSavedReferences = refreshSavedReferences
        self.chooseSensitiveIndex = chooseSensitiveIndex
        self.refreshSensitiveCatalog = refreshSensitiveCatalog
        self.validateSensitiveCatalog = validateSensitiveCatalog
        self.adoptExternalV2Catalog = adoptExternalV2Catalog
        self.adoptExternalV3Catalog = adoptExternalV3Catalog
        self.approveExternalCatalogChange = approveExternalCatalogChange
        self.formatRepairPlan = formatRepairPlan
        self.checkSensitiveCatalogFormat = checkSensitiveCatalogFormat
        self.repairSensitiveCatalogFormat = repairSensitiveCatalogFormat
        self.createCatalogIndex = createCatalogIndex
        self.createCatalogEntry = createCatalogEntry
        self.commitCatalogEntryEdit = commitCatalogEntryEdit
        self.revealCatalogField = revealCatalogField
        self.replaceCatalogSecret = replaceCatalogSecret
        self.applyCatalogBatch = applyCatalogBatch
        self.showSensitiveCatalogTemplate = showSensitiveCatalogTemplate
    }

    public var body: some View {
        NavigationSplitView {
            sidebar
        } detail: {
            detail
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 1180, minHeight: 760)
        .onReceive(NotificationCenter.default.publisher(for: .vaultWorkbenchNavigate)) { notification in
            guard
                let rawValue = notification.userInfo?["section"] as? String,
                let section = VaultWorkbenchSection(rawValue: rawValue)
            else {
                return
            }
        selectSection(section)
        }
    }

    private var detail: some View {
        ZStack {
            WorkbenchBackground()
            selectedContent
                .id(selectedSection)
                .transition(pageTransition)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .sheet(isPresented: Binding(
            get: { secureInputRequest != nil },
            set: { isPresented in
                guard !isPresented, let request = secureInputRequest else { return }
                Task { await cancelSecureInput?(request.id) }
            }
        )) {
            if let request = secureInputRequest {
                CatalogAgentSecureInputSheet(
                    request: request,
                    submit: submitSecureInput,
                    cancel: cancelSecureInput
                )
            }
        }
    }

    private var pageTransition: AnyTransition {
        reduceMotion ? .opacity : .opacity.combined(with: .offset(x: 6))
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 10) {
            sidebarHeader

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(VaultWorkbenchSection.allCases) { section in
                        Button {
                            selectSection(section)
                        } label: {
                            WorkbenchSidebarRow(section: section, isSelected: selectedSection == section)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(section.title)
                        .accessibilityValue(selectedSection == section ? "已选中" : "未选中")
                    }
                }
                .padding(.horizontal, 8)
                .padding(.top, 8)
                .padding(.bottom, 12)
            }
        }
        .padding(10)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [
                            Color.indigo.opacity(0.22),
                            Color.blue.opacity(0.16),
                            Color.cyan.opacity(0.14)
                        ],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .allowsHitTesting(false)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.white.opacity(0.08), lineWidth: 1)
        }
        .padding(10)
        .navigationSplitViewColumnWidth(min: 220, ideal: 250, max: 300)
    }

    private var sidebarHeader: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "lock.shield.fill")
                    .font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(.white)
                    .frame(width: 42, height: 42)
                    .background(Color.blue, in: RoundedRectangle(cornerRadius: 12, style: .continuous))

                Text("SVLT")
                    .font(.title3.weight(.bold))
                Spacer()
            }
        }
        .padding(.horizontal, 8)
        .padding(.top, 8)
    }

    @ViewBuilder
    private var selectedContent: some View {
        switch selectedSection {
        case .overview:
            WorkbenchPage(
                title: "控制台",
                subtitle: "",
                systemImage: selectedSection.systemImage,
                bottomPadding: 12,
                showsOverviewActions: true,
                showTemplate: showSensitiveCatalogTemplate
            ) {
                overviewPage
            }
        case .secrets:
            WorkbenchPage(title: "敏感信息", subtitle: "分组卡片 → 条目 → 字段；Markdown 保留为可正常编辑的 Obsidian 文件。", systemImage: selectedSection.systemImage) {
                VStack(spacing: 14) {
                    if sensitiveIndexURL != nil || sensitiveCatalogSnapshot != nil {
                        SensitiveCatalogEditorCard(
                            snapshot: sensitiveCatalogSnapshot,
                            errorMessage: sensitiveCatalogError,
                            canAdoptExternalV2: sensitiveCatalogCanAdoptV2,
                            adoptExternalV2: adoptExternalV2Catalog,
                            canAdoptExternalV3: sensitiveCatalogCanAdoptV3,
                            adoptExternalV3: adoptExternalV3Catalog,
                            approveExternalChange: approveExternalCatalogChange,
                            refresh: refreshSensitiveCatalog,
                            createIndex: createCatalogIndex,
                            createEntry: createCatalogEntry,
                            commitEntryEdit: commitCatalogEntryEdit,
                            revealCatalogField: revealCatalogField,
                            replaceCatalogSecret: replaceCatalogSecret,
                            applyBatch: applyCatalogBatch,
                            indexURL: sensitiveIndexURL,
                            chooseIndex: chooseSensitiveIndex,
                            formatRepairPlan: formatRepairPlan,
                            checkFormat: checkSensitiveCatalogFormat,
                            repairFormat: repairSensitiveCatalogFormat
                        )
                    } else {
                        SensitiveIndexLibraryCard(
                            indexURL: nil,
                            chooseIndex: chooseSensitiveIndex,
                            errorMessage: sensitiveCatalogError
                        )
                    }
                }
            }
        case .automation:
            WorkbenchPage(title: "智能体自动化", subtitle: "", systemImage: selectedSection.systemImage) {
                AgentAutomationAuditCard(entries: auditEntries, errorMessage: auditError)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        case .tutorial:
            WorkbenchPage(title: "使用教程", subtitle: "", systemImage: selectedSection.systemImage) {
                TutorialPage()
            }
        case .faq:
            WorkbenchPage(title: "常见问题", subtitle: "", systemImage: selectedSection.systemImage) {
                FAQPage()
            }
        }
    }

    private var overviewPage: some View {
        let pending = sensitiveCatalogSnapshot.flatMap { snapshot -> (PendingCatalogSecret, SecretCatalogEntry)? in
            guard let pending = PendingCatalogSecretResolver.resolve(in: snapshot.document),
                  let entry = snapshot.document.entries.first(where: { $0.id == pending.entryID })
            else {
                return nil
            }
            return (pending, entry)
        }

        return WorkbenchOverviewContent(
            status: status,
            agentServiceStatus: agentServiceStatus,
            agentServiceActionInFlight: agentServiceActionInFlight,
            agentServiceActionErrorMessage: agentServiceActionErrorMessage,
            enableAgentService: enableAgentService,
            disableAgentService: disableAgentService,
            restartAgentService: restartAgentService,
            auditEntries: auditEntries,
            auditError: auditError,
            pending: pending?.0,
            pendingEntry: pending?.1,
            commitCatalogEntryEdit: commitCatalogEntryEdit
        )
    }

    private func selectSection(_ section: VaultWorkbenchSection) {
        withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
            selectedSection = section
        }
    }
}

/// Shared overview layout used by the production page and the macOS hosting
/// regression harness. Only the activity card receives flexible height; the
/// pending-secret card remains inside a bounded, high-priority region.
struct WorkbenchOverviewContent: View {
    let status: WorkbenchStatus
    let agentServiceStatus: AgentServiceStatus
    let agentServiceActionInFlight: Bool
    let agentServiceActionErrorMessage: String?
    let enableAgentService: (() async -> Void)?
    let disableAgentService: (() async -> Void)?
    let restartAgentService: (() async -> Void)?
    let auditEntries: [CatalogSecurityAuditEntry]
    let auditError: String?
    let pending: PendingCatalogSecret?
    let pendingEntry: SecretCatalogEntry?
    let commitCatalogEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            OverviewHero(
                status: status,
                agentServiceStatus: agentServiceStatus,
                agentServiceActionInFlight: agentServiceActionInFlight,
                agentServiceActionErrorMessage: agentServiceActionErrorMessage,
                enableAgentService: enableAgentService,
                disableAgentService: disableAgentService,
                restartAgentService: restartAgentService
            )
            .fixedSize(horizontal: false, vertical: true)
            .workbenchOverviewSection(.hero)

            CompactAuditPreviewCard(entries: auditEntries, errorMessage: auditError)
                .frame(
                    maxWidth: .infinity,
                    minHeight: 160,
                    maxHeight: .infinity,
                    alignment: .topLeading
                )
                .workbenchOverviewSection(.activity)

            if let pending, let pendingEntry {
                PendingSecretFillCard(
                    pending: pending,
                    entry: pendingEntry,
                    commit: commitCatalogEntryEdit
                )
                .frame(
                    maxWidth: .infinity,
                    minHeight: 120,
                    idealHeight: 140,
                    maxHeight: 170,
                    alignment: .topLeading
                )
                .layoutPriority(1)
                .workbenchOverviewSection(.pending)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .coordinateSpace(name: WorkbenchOverviewCoordinateSpace.name)
    }
}

enum WorkbenchOverviewSectionID: Hashable {
    case hero
    case activity
    case pending
}

enum WorkbenchOverviewCoordinateSpace {
    static let name = "workbench-overview"
}

struct WorkbenchOverviewSectionFramesKey: PreferenceKey {
    static let defaultValue: [WorkbenchOverviewSectionID: CGRect] = [:]

    static func reduce(
        value: inout [WorkbenchOverviewSectionID: CGRect],
        nextValue: () -> [WorkbenchOverviewSectionID: CGRect]
    ) {
        value.merge(nextValue(), uniquingKeysWith: { _, new in new })
    }
}

private extension View {
    func workbenchOverviewSection(_ id: WorkbenchOverviewSectionID) -> some View {
        background {
            GeometryReader { proxy in
                Color.clear.preference(
                    key: WorkbenchOverviewSectionFramesKey.self,
                    value: [id: proxy.frame(in: .named(WorkbenchOverviewCoordinateSpace.name))]
                )
            }
        }
    }
}

private struct WorkbenchBackground: View {
    var body: some View {
        ZStack {
            Color(nsColor: .underPageBackgroundColor)
            LinearGradient(
                colors: [
                    Color.indigo.opacity(0.20),
                    Color.blue.opacity(0.10),
                    Color.cyan.opacity(0.18)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            RadialGradient(
                colors: [Color.blue.opacity(0.16), .clear],
                center: .topTrailing,
                startRadius: 0,
                endRadius: 560
            )
            RadialGradient(
                colors: [Color.cyan.opacity(0.13), .clear],
                center: .bottomLeading,
                startRadius: 0,
                endRadius: 620
            )
        }
        .ignoresSafeArea()
    }
}

struct WorkbenchPage<Content: View>: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let compact: Bool
    let bottomPadding: CGFloat
    let showsOverviewActions: Bool
    let showTemplate: (() async -> Void)?
    @ViewBuilder let content: Content

    init(
        title: String,
        subtitle: String,
        systemImage: String,
        compact: Bool = false,
        bottomPadding: CGFloat = 22,
        showsOverviewActions: Bool = false,
        showTemplate: (() async -> Void)? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.subtitle = subtitle
        self.systemImage = systemImage
        self.compact = compact
        self.bottomPadding = bottomPadding
        self.showsOverviewActions = showsOverviewActions
        self.showTemplate = showTemplate
        self.content = content()
    }

    var body: some View {
        GeometryReader { proxy in
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .center, spacing: 12) {
                    Text(title)
                        .font(.system(size: 24, weight: .bold, design: .rounded))
                    Spacer()
                    if showsOverviewActions {
                        Button {
                            NSWorkspace.shared.open(VaultWorkbenchCopy.documentationURL)
                        } label: {
                            Image("GitHubMark")
                                .resizable()
                                .scaledToFit()
                                .frame(width: 18, height: 18)
                                .foregroundStyle(.primary)
                        }
                        .buttonStyle(.borderless)
                        .help("打开 GitHub 文档")

                        Button {
                            Task { await showTemplate?() }
                        } label: {
                            Image(systemName: "doc.text.magnifyingglass")
                        }
                        .buttonStyle(.borderless)
                        .help("查看敏感信息模板")
                    }
                }
                .fixedSize(horizontal: false, vertical: true)

                content
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .layoutPriority(1)
            }
            .padding(.horizontal, 30)
            .padding(.top, 22)
            .padding(.bottom, bottomPadding)
            .frame(width: proxy.size.width, height: proxy.size.height, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct WorkbenchSidebarRow: View {
    let section: VaultWorkbenchSection
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 10) {
            Capsule(style: .continuous)
                .fill(isSelected ? Color.accentColor : .clear)
                .frame(width: 3)

            Image(systemName: section.systemImage)
                .font(.system(size: 16, weight: .semibold))
                .frame(width: 22)
                .foregroundStyle(isSelected ? Color.accentColor : .secondary)
            Text(section.title)
                .font(.body.weight(isSelected ? .semibold : .regular))
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 10)
        .frame(minHeight: 42)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel(section.title)
        .accessibilityValue(isSelected ? "已选中" : "未选中")
    }
}

private struct CatalogAgentSecureInputSheet: View {
    let request: CatalogAgentSecureInputRequest
    let submit: ((CatalogAgentSecureInputRequest, [CatalogSecureInputTarget], [String: String]) async -> Void)?
    let cancel: ((UUID) async -> Void)?

    @State private var selectedTargets: Set<String> = []
    @State private var values: [String: String] = [:]
    @State private var revealedFields: Set<String> = []
    @State private var isSubmitting = false
    @State private var startError: String?
    @State private var didSubmit = false

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 6) {
                Text("输入敏感信息")
                    .font(.title2.weight(.bold))
                Text("Agent 正在请求 \(request.entryTitle)。明文只在本应用内加密，不会发送给 Agent。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(request.targets) { target in
                        secureInputRow(target)
                    }
                }
                .padding(.vertical, 2)
            }
            .frame(minHeight: 160, maxHeight: 320)

            if let startError {
                Label(startError, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
            }

            HStack {
                Spacer()
                Button("取消") {
                    Task { await cancel?(request.id) }
                }
                .keyboardShortcut(.cancelAction)
                .disabled(isSubmitting)

                Button {
                    submitSelected()
                } label: {
                    if isSubmitting { ProgressView().controlSize(.small) } else { Text("加密并写入") }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isSubmitting || selectedTargets.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 580, height: 540, alignment: .topLeading)
        .onAppear {
            // Required fields are selected by default. Optional fields remain
            // opt-in, and the daemon revalidates this exact set on submit.
            selectedTargets = Set(request.targets.filter(\.required).map(\.id))
        }
        .onDisappear {
            wipePlaintext()
            if !didSubmit {
                Task { await cancel?(request.id) }
            }
        }
        // Presenting a sheet makes the parent window resign key. Observe the
        // application instead so that normal sheet presentation is not treated
        // as the user leaving the app.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            wipePlaintext()
            guard !didSubmit else { return }
            Task { await cancel?(request.id) }
        }
    }

    @ViewBuilder
    private func secureInputRow(_ target: CatalogSecureInputTarget) -> some View {
        HStack(alignment: .center, spacing: 10) {
            Toggle(isOn: Binding(
                get: { selectedTargets.contains(target.id) },
                set: { selected in
                    if selected { selectedTargets.insert(target.id) } else { selectedTargets.remove(target.id) }
                }
            )) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(target.label)
                        .font(.headline.weight(.semibold))
                    Text(modeText(target.mode))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if target.usesExistingValue {
                        Text("当前字段值将由 SVLT 在本机加密")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .toggleStyle(.checkbox)
            .disabled(target.required)
            .accessibilityLabel(target.label)

            Spacer()

            HStack(spacing: 4) {
                Group {
                    if target.usesExistingValue {
                        Text("使用当前值")
                            .foregroundStyle(.secondary)
                    } else if revealedFields.contains(target.id) {
                        TextField("敏感值", text: binding(for: target))
                    } else {
                        SecureField("敏感值", text: binding(for: target))
                    }
                }
                .textFieldStyle(.roundedBorder)
                .frame(width: 240)

                Button {
                    if revealedFields.contains(target.id) {
                        revealedFields.remove(target.id)
                    } else {
                        revealedFields.insert(target.id)
                    }
                } label: {
                    Image(systemName: revealedFields.contains(target.id) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(revealedFields.contains(target.id) ? "隐藏密码" : "显示密码")
                .disabled(target.usesExistingValue)
            }
        }
        .padding(12)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private func modeText(_ mode: CatalogSecureInputMode) -> String {
        switch mode {
        case .fillPlaceholder: return "填充已选中的密码字段"
        case .replaceSecret: return "替换已有密文"
        case .convertToSecret: return "转换为密文字段"
        }
    }

    private func binding(for target: CatalogSecureInputTarget) -> Binding<String> {
        Binding(
            get: { values[target.fieldKey] ?? "" },
            set: { values[target.fieldKey] = $0 }
        )
    }

    private func submitSelected() {
        let targets = request.targets.filter { selectedTargets.contains($0.id) }
        guard !targets.isEmpty else {
            startError = "请至少选择一个字段"
            return
        }
        guard targets.allSatisfy({ target in
            target.usesExistingValue || !(values[target.fieldKey] ?? "").isEmpty
        }) else {
            startError = "已选字段必须填写内容"
            return
        }
        startError = nil
        isSubmitting = true
        didSubmit = true
        Task {
            await submit?(request, targets, values)
            wipePlaintext()
            isSubmitting = false
        }
    }

    private func wipePlaintext() {
        values.removeAll(keepingCapacity: false)
        revealedFields.removeAll()
    }
}

private struct OverviewStatusStrip: View {
    let status: WorkbenchStatus

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            OverviewStatusRow(
                title: "插件",
                value: status.pluginConnected ? "已连接" : "未连接",
                systemImage: status.pluginConnected ? "checkmark.seal.fill" : "exclamationmark.triangle.fill",
                tint: status.pluginConnected ? .green : .orange
            )
            OverviewStatusRow(
                title: "策略引擎",
                value: status.approvalPending ? "待审批" : (status.ready ? "已就绪" : "不可用"),
                systemImage: status.approvalPending ? "person.badge.key.fill" : (status.ready ? "checkmark.shield.fill" : "exclamationmark.shield.fill"),
                tint: status.approvalPending ? .orange : (status.ready ? .green : .red)
            )
            OverviewStatusRow(
                title: "本机通道",
                value: status.ipcAvailable ? "可用" : "未就绪",
                systemImage: status.ipcAvailable ? "bolt.horizontal.circle.fill" : "bolt.slash.circle.fill",
                tint: status.ipcAvailable ? .green : .orange
            )
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct OverviewStatusRow: View {
    let title: String
    let value: String
    let systemImage: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Image(systemName: systemImage)
                .font(.title3.weight(.semibold))
                .foregroundStyle(tint)
                .frame(width: 24, height: 24)
            Text(title)
                .font(.callout.weight(.semibold))
            Text(value)
                .font(.headline.weight(.semibold))
                .foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(
            LinearGradient(
                colors: [tint.opacity(0.18), tint.opacity(0.05)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 12, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(tint.opacity(0.16), lineWidth: 1)
        }
    }
}

struct OverviewHero: View {
    let status: WorkbenchStatus
    let agentServiceStatus: AgentServiceStatus
    let agentServiceActionInFlight: Bool
    let agentServiceActionErrorMessage: String?
    let enableAgentService: (() async -> Void)?
    let disableAgentService: (() async -> Void)?
    let restartAgentService: (() async -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            OverviewAgentControl(
                status: agentServiceStatus,
                actionInFlight: agentServiceActionInFlight,
                actionErrorMessage: agentServiceActionErrorMessage,
                enableAgent: enableAgentService,
                disableAgent: disableAgentService,
                restartAgent: restartAgentService
            )

            Divider()

            OverviewStatusStrip(status: status)
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            LinearGradient(
                colors: [
                    Color.blue.opacity(0.24),
                    Color.indigo.opacity(0.12),
                    Color.cyan.opacity(0.20)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 18, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .stroke(Color.blue.opacity(0.18), lineWidth: 1)
        }
    }
}

private struct OverviewAgentControl: View {
    let status: AgentServiceStatus
    let actionInFlight: Bool
    let actionErrorMessage: String?
    let enableAgent: (() async -> Void)?
    let disableAgent: (() async -> Void)?
    let restartAgent: (() async -> Void)?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("后台 Agent")
                    .font(.title2.weight(.bold))
                Spacer()
                Text(status.displayName)
                    .font(.headline.weight(.semibold))
                    .foregroundStyle(status == .running ? .green : .secondary)
                    .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: status)
            }

            HStack(spacing: 10) {
                Button("启用") { run(enableAgent) }
                    .disabled(actionInFlight || enableAgent == nil || status == .running || status == .registered)
                Button("停用") { run(disableAgent) }
                    .disabled(actionInFlight || disableAgent == nil || status == .disabled || status == .notRegistered)
                Button("重启") { run(restartAgent) }
                    .disabled(actionInFlight || restartAgent == nil || status == .notRegistered)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            if actionInFlight {
                ProgressView()
                    .controlSize(.small)
                    .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: 4)))
            }
            if let actionErrorMessage {
                Text(actionErrorMessage)
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .transition(
                        reduceMotion
                            ? .opacity
                            : .opacity.combined(with: .offset(y: -4))
                    )
            }
        }
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: actionInFlight)
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: actionErrorMessage)
    }

    private func run(_ action: (() async -> Void)?) {
        guard let action else { return }
        Task { await action() }
    }
}

struct TutorialPage: View {
    var body: some View {
        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 22) {
                TutorialSection(title: "开始使用", systemImage: "1.circle.fill", text: "选择一个敏感信息目录，然后在分组中创建条目。普通字段可以直接查看，密码字段始终以加密状态保存。")
                TutorialSection(title: "查看密码", systemImage: "2.circle.fill", text: "打开具体条目，在需要的字段点击“解密”。完成本机身份认证后，明文只会在这个 App 内短暂显示。")
                TutorialSection(title: "交给智能体", systemImage: "3.circle.fill", text: "把 secret:// 引用交给智能体。MCP 和 Obsidian 插件只处理引用与非敏感元数据，不会接收密码、token 或 Authorization header。")
                TutorialSection(title: "批准目录修改", systemImage: "4.circle.fill", text: "智能体每次修改目录都会生成独立请求。只批准你当前确认的那一笔操作，批准会在使用后立即消费。")

            VStack(alignment: .leading, spacing: 10) {
                Text("安全边界")
                    .font(.title3.weight(.semibold))
                ForEach(VaultUICopy.securityBoundaries) { boundary in
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: boundary.symbolName)
                            .foregroundStyle(boundary.isLimitation ? .orange : .green)
                            .frame(width: 22)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(boundary.chineseTitle)
                                .font(.headline.weight(.semibold))
                            Text(boundary.chineseBody)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(14)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
            }
            }
            .padding(.vertical, 2)
        }
        .scrollIndicators(.automatic)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .layoutPriority(1)
    }
}

private struct TutorialSection: View {
    let title: String
    let systemImage: String
    let text: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: systemImage)
                .font(.title3)
                .foregroundStyle(.blue)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 6) {
                Text(title)
                    .font(.headline.weight(.semibold))
                Text(text)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct FAQPage: View {
    private let questions = [
        ("为什么看不到密码？", "这是默认行为。密码字段只有在本机授权后才会短暂显示，MCP 和插件永远不会收到明文。"),
        ("我可以在 Obsidian 里编辑目录吗？", "可以。Obsidian 负责编辑合法的 v3 Markdown，SVLT 负责校验、授权和本机密文记录。"),
        ("为什么智能体每次修改目录都要授权？", "智能体的目录修改可能改变已有密文引用或目标。每笔操作独立授权，避免一次批准扩大到其他修改。"),
        ("智能体会看到什么？", "智能体可以看到 secret:// 引用和允许展示的元数据，但不会看到密码、token、cookie 或解密后的字段值。")
    ]

    var body: some View {
        ScrollView(.vertical, showsIndicators: true) {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Array(questions.enumerated()), id: \.offset) { _, question in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(question.0)
                            .font(.title3.weight(.semibold))
                        Text(question.1)
                            .font(.body)
                            .foregroundStyle(.secondary)
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                }
            }
            .padding(.vertical, 2)
        }
        .scrollIndicators(.automatic)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .layoutPriority(1)
    }
}

private struct OverviewMetricTile: View {
    let title: String
    let value: String
    let systemImage: String
    let tint: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 12) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.system(size: 22, weight: .bold, design: .rounded))
            }
            Spacer()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }
}

private struct QuickMenuCard: View {
    let title: String
    let detail: String
    let systemImage: String
    let tint: Color
    let actionTitle: String
    var compact = false
    let action: () -> Void
    @State private var isHovering = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: compact ? 8 : 14) {
            Image(systemName: systemImage)
                .font(.system(size: compact ? 18 : 24, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: compact ? 34 : 46, height: compact ? 34 : 46)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: compact ? 10 : 14, style: .continuous))

            Text(title)
                .font(compact ? .headline.weight(.semibold) : .title3.weight(.semibold))
            Text(detail)
                .font(compact ? .caption : .callout)
                .foregroundStyle(.secondary)
                .lineLimit(compact ? 2 : 3)

            Spacer(minLength: 0)

            Button(actionTitle, action: action)
                .buttonStyle(.borderedProminent)
        }
        .padding(compact ? 14 : 20)
        .frame(maxWidth: .infinity, minHeight: compact ? 146 : 210, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: compact ? 18 : 22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: compact ? 18 : 22, style: .continuous)
                .stroke(isHovering ? tint.opacity(0.35) : Color.secondary.opacity(0.12))
        )
        .scaleEffect(isHovering && !reduceMotion ? 1.015 : 1)
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: isHovering)
    }
}

private struct WorkbenchPanelSurface<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .background(
                LinearGradient(
                    colors: [Color.cyan.opacity(0.16), Color.blue.opacity(0.08), Color.indigo.opacity(0.06)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ),
                in: RoundedRectangle(cornerRadius: 18, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 18, style: .continuous)
                    .stroke(Color.cyan.opacity(0.16), lineWidth: 1)
            }
    }
}

public enum CatalogGroupLayout {
    /// Shared content guide for the group header and the visible group cards.
    public static let horizontalInset: CGFloat = 6
    public static let minimumPaneWidth: CGFloat = 230
    public static let maximumPaneWidth: CGFloat = 310

    /// Keep the group pane near 28% of the available content while preserving
    /// usable hit targets at the minimum window width.
    public static func paneWidth(availableWidth: CGFloat) -> CGFloat {
        min(max(availableWidth * 0.28, minimumPaneWidth), maximumPaneWidth)
    }
}

private struct SectionActionBar: View {
    let title: String
    let actionTitle: String
    let action: () -> Void
    let disabled: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(title)
                .font(.headline)
            Spacer(minLength: 0)
            Button(actionTitle, action: action)
                .buttonStyle(.plain)
                .disabled(disabled)
        }
        .padding(.horizontal, CatalogGroupLayout.horizontalInset)
    }
}

private struct CatalogBatchActionBar: View {
    let selectedCount: Int
    let totalCount: Int
    let toggleAll: () -> Void
    let deleteSelected: () -> Void
    let finish: () -> Void
    let deleteDisabled: Bool
    let horizontalInset: CGFloat

    init(
        selectedCount: Int,
        totalCount: Int,
        toggleAll: @escaping () -> Void,
        deleteSelected: @escaping () -> Void,
        finish: @escaping () -> Void,
        deleteDisabled: Bool,
        horizontalInset: CGFloat = 0
    ) {
        self.selectedCount = selectedCount
        self.totalCount = totalCount
        self.toggleAll = toggleAll
        self.deleteSelected = deleteSelected
        self.finish = finish
        self.deleteDisabled = deleteDisabled
        self.horizontalInset = horizontalInset
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("已选 \(selectedCount) 项")
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
            Button(selectedCount == totalCount ? "取消全选" : "全选", action: toggleAll)
                .buttonStyle(.plain)
            Button("删除所选", role: .destructive, action: deleteSelected)
                .buttonStyle(.plain)
                .disabled(deleteDisabled)
            Button("完成", action: finish)
                .buttonStyle(.plain)
        }
        .font(.caption.weight(.medium))
        .padding(.horizontal, horizontalInset)
    }
}

struct PendingSecretFillCard: View {
    let pending: PendingCatalogSecret
    let entry: SecretCatalogEntry
    let commit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?

    @Environment(\.scenePhase) private var scenePhase
    @State private var plaintext = ""
    @State private var isPlaintextVisible = true
    @State private var isSubmitting = false
    @State private var errorMessage: String?

    var body: some View {
        WorkbenchPanelSurface {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("待填写密文", systemImage: "lock.badge.plus")
                        .font(.headline.weight(.semibold))
                    Spacer()
                    Text("待填写 \(pending.remainingCount) 项")
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 2) {
                    Text(pending.indexTitle).font(.caption).foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                    Text(pending.entryTitle).font(.body.weight(.semibold))
                        .lineLimit(2)
                        .truncationMode(.tail)
                    Text("\(pending.fieldLabel) · \(pending.fieldType == .secret ? "密文（secret）" : pending.fieldType.rawValue)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }

                HStack(spacing: 10) {
                    Group {
                        if isPlaintextVisible {
                            TextField(
                                text: $plaintext,
                                prompt: Text("输入密码").foregroundStyle(.orange)
                            ) {
                                Text("密码")
                            }
                        } else {
                            SecureField(
                                text: $plaintext,
                                prompt: Text("输入密码").foregroundStyle(.orange)
                            ) {
                                Text("密码")
                            }
                        }
                    }
                        .textFieldStyle(.roundedBorder)
                        .accessibilityLabel("待填写密码")

                    Button {
                        isPlaintextVisible.toggle()
                    } label: {
                        Image(systemName: isPlaintextVisible ? "eye.slash" : "eye")
                            .frame(width: 20, height: 20)
                    }
                        .buttonStyle(.borderless)
                        .help(isPlaintextVisible ? "隐藏明文" : "显示明文")
                        .accessibilityLabel(isPlaintextVisible ? "隐藏密码" : "显示密码")
                        .disabled(isSubmitting)

                    Button(isSubmitting ? "加密中…" : "填写并加密") { submit() }
                        .buttonStyle(.borderedProminent)
                        .disabled(isSubmitting || plaintext.isEmpty || commit == nil)
                }

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .lineLimit(2)
                }
            }
            .padding(14)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .onDisappear(perform: wipePlaintext)
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { wipePlaintext() }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            wipePlaintext()
        }
    }

    private func submit() {
        let value = plaintext
        guard !value.isEmpty, let commit else { return }
        isSubmitting = true
        errorMessage = nil
        Task { @MainActor in
            let result = await commit(
                entry,
                [CatalogSecretInput(key: pending.fieldKey, label: pending.fieldLabel, plaintext: value)]
            )
            wipePlaintext()
            isSubmitting = false
            switch result {
            case .success:
                errorMessage = nil
            case let .failure(error):
                errorMessage = error.displayText
            }
        }
    }

    private func wipePlaintext() { plaintext = "" }
}

struct CompactAuditPreviewCard: View {
    let entries: [CatalogSecurityAuditEntry]
    let errorMessage: String?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        WorkbenchPanelSurface {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("最近自动化", systemImage: "sparkles.rectangle.stack")
                        .font(.headline.weight(.semibold))
                    Spacer()
                    Text(summaryText)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .lineLimit(2)
                }

                ScrollView(.vertical, showsIndicators: true) {
                    if entries.isEmpty, errorMessage == nil {
                        VStack {
                            Spacer(minLength: 24)
                            Label("暂无活动", systemImage: "clock.badge.questionmark")
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                        .frame(maxWidth: .infinity, minHeight: 160)
                    } else if entries.isEmpty {
                        Label("最近活动暂不可用", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, minHeight: 100)
                    } else {
                        VStack(spacing: 6) {
                            ForEach(entries) { entry in
                                HStack(spacing: 8) {
                                    Image(systemName: iconName(for: entry.operation)).foregroundStyle(.blue).frame(width: 18)
                                    Text(entry.operation.displayName).font(.callout.weight(.semibold)).lineLimit(1)
                                    Text(entry.target).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                    Spacer()
                                    Text(entry.caller?.displayLabel ?? entry.source.displayName)
                                        .font(.caption2)
                                        .foregroundStyle(.tertiary)
                                        .lineLimit(1)
                                    Text(entry.result.displayName).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                }
                                .padding(.vertical, 6)
                                .padding(.horizontal, 10)
                                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                                .transition(reduceMotion ? .opacity : .opacity.combined(with: .offset(y: -4)))
                            }
                        }
                    }
                }
                .scrollIndicators(.automatic)
                .frame(maxHeight: .infinity)
            }
            .padding(14)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: entries.map(\.id))
    }

    private var summaryText: String {
        if !entries.isEmpty { return "最近 \(entries.count) 条" }
        return errorMessage == nil ? "暂无记录" : "读取异常"
    }

    private func iconName(for operation: AuditOperation) -> String {
        switch operation {
        case .reveal:
            return "eye"
        case .catalogMutation, .formatCheck, .formatRepair:
            return "doc.badge.gearshape"
        case .authorization:
            return "person.badge.key"
        case .credentialUse:
            return "key.fill"
        case .secureExecute:
            return "cable.connector"
        default:
            return "bolt.horizontal.circle"
        }
    }
}

private struct SensitiveIndexLibraryCard: View {
    let indexURL: URL?
    let chooseIndex: (() -> Void)?
    let errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 10) {
                Label("目录文件选择", systemImage: "doc.badge.lock")
                    .font(.title3.weight(.semibold))
                Spacer()
            }

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            }

            if let indexURL {
                HStack(spacing: 8) {
                    Image(systemName: "folder")
                        .foregroundStyle(.secondary)
                    Text(indexURL.path)
                        .font(.system(.caption, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("更换文件…") { chooseIndex?() }
                        .buttonStyle(.bordered)
                }
                .padding(10)
                .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))

            } else {
                VStack(spacing: 14) {
                    Image(systemName: "folder.badge.questionmark")
                        .font(.system(size: 38, weight: .medium))
                        .foregroundStyle(.secondary)
                    Text("尚未设置敏感信息目录")
                        .font(.title2.weight(.semibold))
                    Button("选择现有敏感信息.md") { chooseIndex?() }
                        .buttonStyle(.borderedProminent)
                }
                .frame(maxWidth: .infinity, minHeight: 190)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct CatalogFormatCheckCard: View {
    let plan: CatalogFormatRepairPlan?
    let check: (() async -> Void)?
    let repair: (() async -> Void)?
    @State private var isWorking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("格式检查", systemImage: "checkmark.shield")
                    .font(.headline.weight(.semibold))
                Spacer()
                Button("检查格式") {
                    Task {
                        isWorking = true
                        await check?()
                        isWorking = false
                    }
                }
                .buttonStyle(.bordered)
                .disabled(isWorking || check == nil)
            }

            if let plan {
                if plan.diagnostics.isEmpty {
                    Label("格式正常", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Label(
                        plan.unrepairableDiagnostics.isEmpty ? "发现可修复格式问题" : "发现不能自动修复的问题",
                        systemImage: plan.unrepairableDiagnostics.isEmpty ? "exclamationmark.triangle" : "xmark.octagon"
                    )
                    .foregroundStyle(plan.unrepairableDiagnostics.isEmpty ? .orange : .red)

                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(plan.diagnostics) { diagnostic in
                            VStack(alignment: .leading, spacing: 3) {
                                Text("第 \(diagnostic.line) 行\(diagnostic.column.map { "、第 \($0) 列" } ?? "") · \(diagnostic.code)")
                                    .font(.caption.weight(.semibold))
                                Text(diagnostic.message)
                                    .font(.callout)
                                if let hint = diagnostic.hint {
                                    Text(hint)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(9)
                            .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        }
                    }

                    if plan.canRepair, let repair {
                        Button("修复格式") {
                            Task {
                                isWorking = true
                                await repair()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isWorking)
                    } else if !plan.unrepairableDiagnostics.isEmpty {
                        Text("当前问题不会自动覆盖，请按上面的精确诊断处理。")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                Text("检查当前选中的敏感信息.md；检查结果只包含安全诊断，不显示正文或密文引用。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

private struct CatalogDeletionRequest: Identifiable {
    enum Kind {
        case indexes
        case entries
    }

    let id: String
    let kind: Kind
    let ids: [String]
    let itemCount: Int
    let entryCount: Int
    let secretFieldCount: Int
}

struct CatalogFieldDraft: Identifiable, Equatable, Sendable {
    static let serviceAddressKey = "serviceURL"

    let id: UUID
    var field: SecretCatalogFieldValue
    var secretInput: String

    init(
        id: UUID = UUID(),
        field: SecretCatalogFieldValue,
        secretInput: String = ""
    ) {
        self.id = id
        self.field = field
        self.secretInput = secretInput
    }

    static func make(
        from fields: [SecretCatalogFieldValue],
        endpoints: [CatalogEndpoint] = []
    ) -> [Self] {
        var drafts = fields.map { field in Self(field: field) }

        guard !endpoints.isEmpty else { return drafts }

        let endpointValues = endpoints.map(Self.endpointURL)
        var usedKeys = Set(drafts.map { $0.field.key })
        var emptyServiceFieldIndices = drafts.indices.filter { index in
            guard drafts[index].field.type == .url,
                  Self.isServiceAddressKey(drafts[index].field.key)
            else { return false }
            guard case let .string(value)? = drafts[index].field.value else { return true }
            return value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
        var projectedFields: [Self] = []

        for (index, endpointValue) in endpointValues.enumerated() {
            let endpointIdentity = Self.urlIdentity(endpointValue)
            let isMatchingField: (Self) -> Bool = { draft in
                guard draft.field.type == .url,
                      Self.isServiceAddressKey(draft.field.key),
                      case let .string(value)? = draft.field.value,
                      !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                else { return false }
                return Self.urlIdentity(value) == endpointIdentity
            }
            let alreadyProjected = drafts.contains(where: isMatchingField)
                || projectedFields.contains(where: isMatchingField)
            if alreadyProjected { continue }

            if let emptyIndex = emptyServiceFieldIndices.first {
                drafts[emptyIndex].field = Self.field(
                    replacing: drafts[emptyIndex].field,
                    value: endpointValue
                )
                emptyServiceFieldIndices.removeFirst()
                continue
            }

            var key = index == 0 ? serviceAddressKey : "\(serviceAddressKey)\(index + 1)"
            var attempt = index + 1
            while usedKeys.contains(key) {
                attempt += 1
                key = "\(serviceAddressKey)\(attempt)"
            }
            usedKeys.insert(key)
            projectedFields.append(
                Self(
                    field: SecretCatalogFieldValue(
                        key: key,
                        label: index == 0 ? "服务地址" : "服务地址 \(index + 1)",
                        type: .url,
                        value: .string(endpointValue)
                    )
                )
            )
        }

        if !projectedFields.isEmpty {
            drafts.insert(contentsOf: projectedFields, at: 0)
        }
        return drafts
    }

    static func isServiceAddressKey(_ key: String) -> Bool {
        guard key.hasPrefix(serviceAddressKey) else { return false }
        let suffix = key.dropFirst(serviceAddressKey.count)
        return suffix.isEmpty || suffix.allSatisfy { $0.isNumber }
    }

    private static func urlIdentity(_ value: String) -> String {
        guard let url = URL(string: value),
              let scheme = url.scheme,
              let host = url.host,
              !host.isEmpty,
              url.user == nil,
              url.password == nil,
              url.query == nil,
              url.fragment == nil,
              url.path.isEmpty || url.path == "/"
        else {
            return value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }
        let normalizedHost = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        let port = url.port.map(String.init) ?? ""
        return "\(scheme.lowercased())|\(normalizedHost)|\(port)"
    }

    private static func field(
        replacing field: SecretCatalogFieldValue,
        value: String
    ) -> SecretCatalogFieldValue {
        SecretCatalogFieldValue(
            key: field.key,
            label: field.label,
            type: field.type,
            agentVisible: field.agentVisible,
            searchable: field.searchable,
            value: .string(value),
            secretRef: field.secretRef
        )
    }

    private static func endpointURL(_ endpoint: CatalogEndpoint) -> String {
        let host = endpoint.host.contains(":") && !endpoint.host.hasPrefix("[")
            ? "[\(endpoint.host)]"
            : endpoint.host
        let port = endpoint.port.map { ":\($0)" } ?? ""
        return "\(endpoint.type.lowercased())://\(host)\(port)"
    }

    static func endpoints(from fields: [SecretCatalogFieldValue]) -> [CatalogEndpoint] {
        var seen = Set<String>()
        return fields.compactMap { field in
            guard field.type == .url,
                  Self.isServiceAddressKey(field.key),
                  case let .string(value)? = field.value,
                  let url = URL(string: value),
                  let scheme = url.scheme,
                  !scheme.isEmpty,
                  let host = url.host,
                  !host.isEmpty,
                  url.user == nil,
                  url.password == nil,
                  url.query == nil,
                  url.fragment == nil,
                  url.path.isEmpty || url.path == "/"
            else { return nil }
            let endpoint = CatalogEndpoint(type: scheme.lowercased(), host: host, port: url.port)
            let identity = "\(endpoint.type.lowercased())|\(endpoint.host.lowercased())|\(endpoint.port.map(String.init) ?? "")"
            guard seen.insert(identity).inserted else { return nil }
            return endpoint
        }
    }

    static func newField(key: String) -> Self {
        Self(field: SecretCatalogFieldValue(key: key, label: "新字段", type: .text))
    }

    static func nextCustomFieldKey(for drafts: [Self]) -> String {
        let usedKeys = Set(drafts.map { $0.field.key })
        var number = drafts.count + 1
        var key = "field\(number)"
        while usedKeys.contains(key) {
            number += 1
            key = "field\(number)"
        }
        return key
    }

    var selectionID: String { id.uuidString }
}

private struct SensitiveCatalogEditorCard: View {
    let snapshot: SensitiveCatalogSnapshot?
    let errorMessage: String?
    let canAdoptExternalV2: Bool
    let adoptExternalV2: (() async -> Void)?
    let canAdoptExternalV3: Bool
    let adoptExternalV3: (() async -> Void)?
    let approveExternalChange: (() async -> Void)?
    let refresh: (() async -> Void)?
    let createIndex: ((String) async -> CatalogMutationUIResult)?
    let createEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let applyBatch: ((CatalogBatchMutation) async -> CatalogMutationUIResult)?
    let indexURL: URL?
    let chooseIndex: (() -> Void)?
    let formatRepairPlan: CatalogFormatRepairPlan?
    let checkFormat: (() async -> Void)?
    let repairFormat: (() async -> Void)?

    @State private var newIndexTitle = ""
    @State private var isWorking = false
    @State private var createIndexError: CatalogMutationUIError?
    @State private var selectedIndexID: String?
    @State private var hoveredIndexID: String?
    @State private var indexSelection = CatalogBatchSelectionState()
    @State private var entrySelection = CatalogBatchSelectionState()
    @State private var pendingDeletion: CatalogDeletionRequest?
    @State private var deletionError: CatalogMutationUIError?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Label("结构化目录", systemImage: "list.bullet.indent")
                    .font(.title3.weight(.semibold))
                Spacer()
                if let refresh {
                    Button {
                        Task {
                            isWorking = true
                            await refresh()
                            isWorking = false
                        }
                    } label: {
                        Label("验证并刷新", systemImage: "checkmark.shield")
                    }
                    .disabled(isWorking)
                }
                if let checkFormat {
                    Button("检查格式") {
                        Task { await checkFormat() }
                    }
                    .buttonStyle(.bordered)
                    .disabled(isWorking)
                }
                if formatRepairPlan?.canRepair == true, let repairFormat {
                    Button("修复格式") {
                        Task { await repairFormat() }
                    }
                    .buttonStyle(.borderedProminent)
                }
                if let chooseIndex {
                    Button("更换文件…", action: chooseIndex)
                        .buttonStyle(.bordered)
                }
            }

            if let indexURL {
                Text(indexURL.lastPathComponent)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(indexURL.path)
            }

            if let formatRepairPlan, !formatRepairPlan.diagnostics.isEmpty {
                Label(
                    formatRepairPlan.unrepairableDiagnostics.isEmpty
                        ? "发现可修复格式问题"
                        : "发现不能自动修复的问题",
                    systemImage: formatRepairPlan.unrepairableDiagnostics.isEmpty
                        ? "exclamationmark.triangle"
                        : "xmark.octagon"
                )
                .font(.caption.weight(.semibold))
                .foregroundStyle(formatRepairPlan.unrepairableDiagnostics.isEmpty ? .orange : .red)
            }

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                if errorMessage.contains("待审批"), let approveExternalChange {
                        Button("批准并接纳外部修改") {
                        Task { await approveExternalChange() }
                    }
                    .buttonStyle(.borderedProminent)
                }
            }

            if snapshot == nil, canAdoptExternalV2, let adoptExternalV2 {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.blue)
                        Text("升级外部 v2 文件")
                            .font(.headline)
                        Spacer()
                        Button("备份、验证并升级") {
                            Task {
                                isWorking = true
                                await adoptExternalV2()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 将严格解析当前 v2 文件，先备份，再转换为 Obsidian 兼容的 v3；失败时原文件保持不变。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            } else if snapshot == nil, canAdoptExternalV3, let adoptExternalV3 {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: "checkmark.shield")
                            .foregroundStyle(.blue)
                        Text("接纳外部 v3 文件")
                            .font(.headline)
                        Spacer()
                        Button("验证并接纳") {
                            Task {
                                isWorking = true
                                await adoptExternalV3()
                                isWorking = false
                            }
                        }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                    }
                    Text("SVLT 将重新解析并校验当前 v3 文件，只建立本机 accepted state，不改写 Markdown。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            } else if snapshot == nil, errorMessage?.contains("旧版格式") == true {
                Label("旧版目录不支持自动升级。请先备份文件，再手动转换为 Catalog v3。", systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let snapshot {
                HStack(spacing: 8) {
                    Text("版本 \(snapshot.revision)")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                    Label("完整性已验证", systemImage: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                    Spacer()
                    Text("分组 \(snapshot.document.indexes.count) · 条目 \(snapshot.document.entries.count)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                HStack(spacing: 8) {
                    TextField("新增分组，例如 QNAP", text: $newIndexTitle)
                        .textFieldStyle(.roundedBorder)
                    Button("新增分组") {
                        let title = newIndexTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !title.isEmpty else { return }
                        Task {
                            isWorking = true
                            let result = await createIndex?(title)
                            switch result {
                            case .success:
                                newIndexTitle = ""
                                createIndexError = nil
                            case .failure(let error):
                                createIndexError = error
                            case nil:
                                createIndexError = CatalogMutationUIError(
                                    code: "APP_CONTROL_UNAVAILABLE",
                                    message: "本机控制服务不可用，无法新增分组"
                                )
                            }
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || createIndex == nil)
                }
                if let createIndexError {
                    Label(createIndexError.displayText, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .padding(.leading, 4)
                }

                if snapshot.document.indexes.isEmpty {
                    ContentUnavailableView(
                        "还没有分组",
                        systemImage: "folder.badge.plus",
                        description: Text("先创建一个分组；条目和字段会在右侧工作区管理。")
                    )
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    GeometryReader { geometry in
                        HStack(alignment: .top, spacing: 0) {
                            VStack(alignment: .leading, spacing: 10) {
                            if indexSelection.isSelecting {
                                CatalogBatchActionBar(
                                    selectedCount: indexSelection.selectedIDs.count,
                                    totalCount: snapshot.document.indexes.count,
                                    toggleAll: {
                                        if indexSelection.selectedIDs.count == snapshot.document.indexes.count {
                                            indexSelection.clear()
                                        } else {
                                            indexSelection.selectAll(snapshot.document.indexes.map(\.id))
                                        }
                                    },
                                    deleteSelected: {
                                        prepareIndexDeletion(ids: indexSelection.selectedIDs.sorted(), snapshot: snapshot)
                                    },
                                    finish: {
                                        withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
                                            indexSelection.finish()
                                        }
                                    },
                                    deleteDisabled: indexSelection.selectedIDs.isEmpty || isWorking,
                                    horizontalInset: CatalogGroupLayout.horizontalInset
                                )
                            } else {
                                SectionActionBar(
                                    title: "分组",
                                    actionTitle: "批量编辑",
                                    action: {
                                        withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
                                            indexSelection.begin()
                                        }
                                    },
                                    disabled: snapshot.document.indexes.isEmpty
                                )
                            }

                            ScrollView(.vertical, showsIndicators: false) {
                                VStack(spacing: 8) {
                                    ForEach(snapshot.document.indexes, id: \.id) { index in
                                        let entries = snapshot.document.entries.filter { $0.indexId == index.id }
                                        indexRow(index: index, entries: entries, snapshot: snapshot)
                                    }
                                }
                            }
                            }
                            .padding(14)
                            .frame(
                                width: CatalogGroupLayout.paneWidth(availableWidth: geometry.size.width),
                                alignment: .topLeading
                            )
                            .frame(maxHeight: .infinity, alignment: .topLeading)

                            Divider()

                            Group {
                            if let selectedIndexID,
                               let index = snapshot.document.indexes.first(where: { $0.id == selectedIndexID }) {
                                SensitiveCatalogGroupSheet(
                                    index: index,
                                    entries: snapshot.document.entries.filter { $0.indexId == index.id },
                                    createEntry: createEntry,
                                    commitEntryEdit: commitEntryEdit,
                                    revealCatalogField: revealCatalogField,
                                    replaceCatalogSecret: replaceCatalogSecret,
                                    entrySelection: $entrySelection,
                                    requestEntryDeletion: { ids in
                                        prepareEntryDeletion(ids: ids, snapshot: snapshot)
                                    }
                                )
                            } else {
                                ContentUnavailableView(
                                    "选择一个分组",
                                    systemImage: "sidebar.left",
                                    description: Text("从左侧选择分组，查看条目和字段。")
                                )
                                .padding(24)
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                            }
                            }
                            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                    .layoutPriority(1)
                    .background(Color(nsColor: .windowBackgroundColor), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

                    if let deletionError {
                        Label(deletionError.displayText, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
            } else if errorMessage == nil {
                    Text("选择现有敏感信息.md 后，SVLT 会在这里显示分组、条目和字段。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .onChange(of: snapshot?.revision) { _, _ in
            guard let snapshot else { return }
            indexSelection.retainVisibleIDs(snapshot.document.indexes.map(\.id))
            if let selectedIndexID,
               !snapshot.document.indexes.contains(where: { $0.id == selectedIndexID }) {
                self.selectedIndexID = nil
            }
        }
        .alert(item: $pendingDeletion) { request in
            switch request.kind {
            case .indexes:
                Alert(
                    title: Text("删除 \(request.itemCount) 个分组？"),
                    message: Text("其中包含 \(request.entryCount) 个条目、\(request.secretFieldCount) 个密码字段。此操作会删除目录引用。"),
                    primaryButton: .destructive(Text("删除")) {
                        delete(request)
                    },
                    secondaryButton: .cancel(Text("取消"))
                )
            case .entries:
                Alert(
                    title: Text("删除 \(request.itemCount) 个条目？"),
                    message: Text("其中包含 \(request.secretFieldCount) 个密码字段。此操作会删除目录引用。"),
                    primaryButton: .destructive(Text("删除")) {
                        delete(request)
                    },
                    secondaryButton: .cancel(Text("取消"))
                )
            }
        }
    }

    private func indexRow(index: SecretCatalogIndex, entries: [SecretCatalogEntry], snapshot: SensitiveCatalogSnapshot) -> some View {
        let isSelected = selectedIndexID == index.id
        let isHovered = hoveredIndexID == index.id
        let isBatchSelected = indexSelection.selectedIDs.contains(index.id)
        return HStack(alignment: .center, spacing: 8) {
            Button {
                withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
                    if indexSelection.isSelecting {
                        indexSelection.toggle(index.id)
                    } else {
                        selectedIndexID = index.id
                    }
                }
            } label: {
            HStack(alignment: .center, spacing: 12) {
                if indexSelection.isSelecting {
                    Image(systemName: isBatchSelected ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(isBatchSelected ? Color.accentColor : .secondary)
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(index.title).font(.callout.weight((isSelected || isBatchSelected) ? .semibold : .regular))
                        .lineLimit(2)
                        .truncationMode(.tail)
                    Text("\(entries.count) 个条目")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 38)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            .frame(maxWidth: .infinity, minHeight: 64, alignment: .center)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
            .accessibilityLabel(index.title)
            .accessibilityValue(indexSelection.isSelecting ? (isBatchSelected ? "已选中" : "未选中") : (isSelected ? "当前分组" : "分组"))
            .accessibilityHint(indexSelection.isSelecting ? "选择分组用于批量删除" : "查看该分组中的条目")

            if !indexSelection.isSelecting {
                Button(role: .destructive) {
                    prepareIndexDeletion(for: index, snapshot: snapshot)
                } label: {
                    Image(systemName: "trash").font(.callout.weight(.semibold)).frame(width: 34, height: 34)
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("删除分组")
                .accessibilityLabel("删除分组")
            }
        }
        .frame(maxWidth: .infinity, minHeight: 64, alignment: .leading)
        .background(
            LinearGradient(
                colors: [
                    Color.blue.opacity((isSelected || isBatchSelected) ? 0.24 : 0.14),
                    Color.indigo.opacity((isSelected || isBatchSelected) ? 0.14 : 0.05)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 10, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(
                    (isSelected || isBatchSelected)
                        ? Color.accentColor.opacity(0.78)
                        : (isHovered ? Color.blue.opacity(0.42) : Color.blue.opacity(0.18)),
                    lineWidth: isSelected ? 2 : (isHovered ? 1.5 : 1)
                )
                .allowsHitTesting(false)
        }
        .padding(.horizontal, CatalogGroupLayout.horizontalInset)
        .scaleEffect(isHovered && !reduceMotion ? 1.01 : 1)
        .onHover { isHovering in
            hoveredIndexID = isHovering ? index.id : nil
        }
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: isHovered)
    }

    private func prepareIndexDeletion(for index: SecretCatalogIndex, snapshot: SensitiveCatalogSnapshot) {
        prepareIndexDeletion(ids: [index.id], snapshot: snapshot)
    }

    private func prepareIndexDeletion(ids: [String], snapshot: SensitiveCatalogSnapshot) {
        guard !ids.isEmpty else { return }
        let summary = CatalogDeletionSummary.indexes(ids: ids, in: snapshot.document)
        pendingDeletion = CatalogDeletionRequest(
            id: ids.joined(separator: ","),
            kind: .indexes,
            ids: ids,
            itemCount: summary.itemCount,
            entryCount: summary.entryCount,
            secretFieldCount: summary.secretFieldCount
        )
    }

    private func prepareEntryDeletion(ids: [String], snapshot: SensitiveCatalogSnapshot) {
        guard !ids.isEmpty else { return }
        let summary = CatalogDeletionSummary.entries(ids: ids, in: snapshot.document.entries)
        pendingDeletion = CatalogDeletionRequest(
            id: ids.joined(separator: ","),
            kind: .entries,
            ids: ids,
            itemCount: summary.itemCount,
            entryCount: summary.entryCount,
            secretFieldCount: summary.secretFieldCount
        )
    }

    private func delete(_ request: CatalogDeletionRequest) {
        Task {
            isWorking = true
            deletionError = nil
            guard let applyBatch else {
                let itemName: String
                switch request.kind {
                case .indexes:
                    itemName = "分组"
                case .entries:
                    itemName = "条目"
                }
                deletionError = CatalogMutationUIError(
                    code: "APP_CONTROL_UNAVAILABLE",
                    message: "本机控制服务不可用，无法删除\(itemName)"
                )
                pendingDeletion = nil
                isWorking = false
                return
            }
            let operations: [CatalogBatchOperation] = request.ids.map { id in
                switch request.kind {
                case .indexes:
                    return .deleteIndex(id: id)
                case .entries:
                    return .deleteEntry(id: id)
                }
            }
            let result = await applyBatch(CatalogBatchMutation(operations: operations))
            switch result {
            case .success:
                switch request.kind {
                case .indexes:
                    if request.ids.contains(selectedIndexID ?? "") {
                        selectedIndexID = nil
                    }
                    indexSelection.deleteSucceeded(request.ids)
                case .entries:
                    entrySelection.deleteSucceeded(request.ids)
                }
            case let .failure(error):
                deletionError = error
            }
            pendingDeletion = nil
            isWorking = false
        }
    }
}

struct SensitiveCatalogGroupSheet: View {
    let index: SecretCatalogIndex
    let entries: [SecretCatalogEntry]
    let createEntry: ((String, String, String) async -> CatalogMutationUIResult)?
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    @Binding var entrySelection: CatalogBatchSelectionState
    let requestEntryDeletion: ([String]) -> Void

    @State private var isAdding = false
    @State private var newEntryTitle = ""
    @State private var selectedPresetID = SensitiveCatalogEntryPreset.all.first?.id ?? "credential"
    @State private var newlyCreatedEntryID: String?
    @State private var isWorking = false
    @State private var createError: CatalogEntryCreationError?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var secretFieldCount: Int {
        entries.reduce(into: 0) { count, entry in
            count += entry.fields.reduce(into: 0) { fieldCount, field in
                if field.type.isSecret {
                    fieldCount += 1
                }
            }
        }
    }

    private var headerSummary: String {
        "条目 \(entries.count) · 密码字段 \(secretFieldCount)"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 10) {
                Image(systemName: "folder.fill")
                    .font(.title2)
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text(index.title)
                        .font(.title2.weight(.semibold))
                    Text(headerSummary)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            HStack(spacing: 8) {
                Button("新增条目") {
                    isAdding = true
                    createError = nil
                }
                .buttonStyle(.borderedProminent)
                .disabled(entrySelection.isSelecting)

                Spacer()
                if entrySelection.isSelecting {
                    CatalogBatchActionBar(
                        selectedCount: entrySelection.selectedIDs.count,
                        totalCount: entries.count,
                        toggleAll: {
                            if entrySelection.selectedIDs.count == entries.count {
                                entrySelection.clear()
                            } else {
                                entrySelection.selectAll(entries.map(\.id))
                            }
                        },
                        deleteSelected: { requestEntryDeletion(entrySelection.selectedIDs.sorted()) },
                        finish: {
                            withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
                                entrySelection.finish()
                            }
                        },
                        deleteDisabled: isWorking || entrySelection.selectedIDs.isEmpty
                    )
                } else {
                    Button("批量编辑") {
                        withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) { entrySelection.begin() }
                    }
                    .buttonStyle(.borderless)
                    .help("批量编辑条目")
                    .accessibilityLabel("批量编辑条目")
                    .disabled(entries.isEmpty)
                }
            }

            if isAdding {
                HStack(spacing: 8) {
                    TextField("条目标题，例如管理后台登录", text: $newEntryTitle)
                        .textFieldStyle(.roundedBorder)
                    Picker("初始字段", selection: $selectedPresetID) {
                        ForEach(SensitiveCatalogEntryPreset.all) { preset in
                            Text(preset.title).tag(preset.id)
                        }
                    }
                    .frame(width: 160)
                    .help("预设只创建一个初始字段，其余字段可按需添加")
                    Button("创建") {
                        let title = newEntryTitle.trimmingCharacters(in: .whitespacesAndNewlines)
                        guard !title.isEmpty else { return }
                        Task {
                            isWorking = true
                            createError = nil
                            let result = await createEntry?(index.id, title, selectedPresetID)
                            switch result {
                            case .success(let writeResult):
                                newlyCreatedEntryID = writeResult.entry?.id
                                isAdding = false
                                newEntryTitle = ""
                            case .failure(let error):
                                createError = error
                            case nil:
                                createError = CatalogEntryCreationError(
                                    code: "APP_CONTROL_UNAVAILABLE",
                                    message: "本机控制服务不可用，无法新增条目"
                                )
                            }
                            isWorking = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || createEntry == nil)
                    Button("取消") {
                        isAdding = false
                        createError = nil
                    }
                    .buttonStyle(.bordered)
                }
                if let createError {
                    Label(createError.displayText, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            if entries.isEmpty {
                ContentUnavailableView(
                    "暂无条目",
                    systemImage: "list.bullet.rectangle"
                )
                .frame(maxWidth: .infinity, minHeight: 180)
            } else {
                ScrollView {
                    let columns = Array(
                        repeating: GridItem(.flexible(minimum: 0, maximum: .infinity), spacing: 14, alignment: .topLeading),
                        count: 2
                    )
                    LazyVGrid(columns: columns, alignment: .leading, spacing: 14) {
                        ForEach(entries, id: \.id) { entry in
                            SensitiveCatalogEntryRow(
                                entry: entry,
                                autoEdit: newlyCreatedEntryID == entry.id,
                                isSelecting: entrySelection.isSelecting,
                                isSelected: entrySelection.selectedIDs.contains(entry.id),
                                toggleSelection: { toggleEntrySelection(entry.id) },
                                commitEntryEdit: commitEntryEdit,
                                revealCatalogField: revealCatalogField,
                                replaceCatalogSecret: replaceCatalogSecret,
                                requestDelete: { requestEntryDeletion([entry.id]) }
                            )
                        }
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .layoutPriority(1)
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .onChange(of: entries.map(\.id)) { _, ids in
            entrySelection.retainVisibleIDs(ids)
        }
    }

    private func toggleEntrySelection(_ id: String) {
        withAnimation(reduceMotion ? nil : VaultWorkbenchMotion.interactive) {
            entrySelection.toggle(id)
        }
    }

}

private struct SensitiveCatalogEntryRow: View {
    let entry: SecretCatalogEntry
    let autoEdit: Bool
    let isSelecting: Bool
    let isSelected: Bool
    let toggleSelection: () -> Void
    let commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?
    let revealCatalogField: ((String, String) async throws -> String)?
    let replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let requestDelete: () -> Void

    @State private var editing = false
    @State private var draftTitle: String
    @State private var draftAliases: String
    @State private var draftTags: String
    @State private var draftNotes: String
    @State private var draftFields: [CatalogFieldDraft]
    @State private var fieldSelection = CatalogBatchSelectionState()
    @State private var isSaving = false
    @State private var editorError: String?
    @State private var showingDetails: Bool
    @State private var revealPresentationStates: [String: CatalogRevealPresentationState] = [:]
    @State private var revealingKeys: Set<String> = []
    @State private var revealTasks: [String: Task<Void, Never>] = [:]
    @State private var revealExpiryTasks: [String: Task<Void, Never>] = [:]
    @State private var revealPendingExpiryTasks: [String: Task<Void, Never>] = [:]
    @State private var revealGenerations: [String: UUID] = [:]
    @State private var revealError: String?
    @State private var canPresentReveals = true
    @State private var isHovering = false
    @State private var detailContentHeight: CGFloat = 260
    @State private var detailAvailableWidth: CGFloat = 760
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private enum Metrics {
        static let firstLineHeight: CGFloat = 24
        static let titleBlockHeight: CGFloat = 40
        static let horizontalPadding: CGFloat = 12
        static let verticalPadding: CGFloat = 10
        static let sectionSpacing: CGFloat = 6
    }

    init(
        entry: SecretCatalogEntry,
        autoEdit: Bool = false,
        isSelecting: Bool = false,
        isSelected: Bool = false,
        toggleSelection: @escaping () -> Void = {},
        commitEntryEdit: ((SecretCatalogEntry, [CatalogSecretInput]) async -> CatalogMutationUIResult)?,
        revealCatalogField: ((String, String) async throws -> String)?,
        replaceCatalogSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?,
        requestDelete: @escaping () -> Void = {}
    ) {
        self.entry = entry
        self.autoEdit = autoEdit
        self.isSelecting = isSelecting
        self.isSelected = isSelected
        self.toggleSelection = toggleSelection
        self.commitEntryEdit = commitEntryEdit
        self.revealCatalogField = revealCatalogField
        self.replaceCatalogSecret = replaceCatalogSecret
        self.requestDelete = requestDelete
        _draftTitle = State(initialValue: entry.title)
        _draftAliases = State(initialValue: entry.aliases.joined(separator: ", "))
        _draftTags = State(initialValue: entry.tags.joined(separator: ", "))
        _draftNotes = State(initialValue: entry.notes ?? "")
        _draftFields = State(initialValue: CatalogFieldDraft.make(from: entry.fields, endpoints: entry.endpoints))
        _editing = State(initialValue: autoEdit)
        _showingDetails = State(initialValue: autoEdit)
    }

    var body: some View {
        Group {
            if isSelecting {
                Button(action: toggleSelection) {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                            .font(.title3)
                            .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                            .frame(width: Metrics.firstLineHeight, height: Metrics.firstLineHeight, alignment: .center)

                        VStack(alignment: .leading, spacing: 8) {
                            entryTitleContent
                            entryCounts
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, Metrics.horizontalPadding)
                    .padding(.vertical, Metrics.verticalPadding)
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(entry.title)
                .accessibilityValue(isSelected ? "已选中" : "未选中")
                .accessibilityHint("选择条目用于批量编辑")
            } else {
                normalCard
            }
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(
            LinearGradient(
                colors: [
                    (isSelecting && isSelected) ? Color.accentColor.opacity(0.22) : Color.cyan.opacity(isHovering ? 0.18 : 0.14),
                    (isSelecting && isSelected) ? Color.indigo.opacity(0.12) : Color.blue.opacity(0.05)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 12, style: .continuous)
        )
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(
                    (isSelecting && isSelected)
                        ? Color.accentColor.opacity(0.78)
                        : (isHovering ? Color.cyan.opacity(0.42) : Color.cyan.opacity(0.18)),
                    lineWidth: isSelecting && isSelected ? 2 : (isHovering ? 1.5 : 1)
                )
                .allowsHitTesting(false)
        }
        .scaleEffect(isHovering && !reduceMotion ? 1.01 : 1)
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: isHovering)
        .sheet(isPresented: $showingDetails, onDismiss: invalidateRevealState) {
            entryDetails
        }
        .onDisappear {
            invalidateRevealState()
        }
        .onChange(of: showingDetails) { _, isPresented in
            if isPresented {
                canPresentReveals = scenePhase == .active
            } else {
                canPresentReveals = false
                cancelEditing()
            }
        }
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .active:
                canPresentReveals = true
                presentPendingReveals()
            case .inactive:
                canPresentReveals = false
                hideRevealedPlaintexts()
            case .background:
                canPresentReveals = false
                invalidateRevealState()
            @unknown default:
                canPresentReveals = false
                invalidateRevealState()
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didResignKeyNotification)) { _ in
            canPresentReveals = false
            hideRevealedPlaintexts()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            guard scenePhase == .active else { return }
            canPresentReveals = true
            presentPendingReveals()
        }
        .onReceive(NotificationCenter.default.publisher(for: .vaultWorkbenchTransientFocusLost)) { _ in
            canPresentReveals = false
            hideRevealedPlaintexts()
        }
        .onReceive(NotificationCenter.default.publisher(for: .vaultWorkbenchSecurityStateInvalidated)) { _ in
            invalidateRevealState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
            invalidateRevealState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
            invalidateRevealState()
        }
        .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
            invalidateRevealState()
        }
    }

    private var normalCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 8) {
                Button { showingDetails = true } label: {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "key.horizontal")
                            .foregroundStyle(.green)
                            .frame(width: Metrics.firstLineHeight, height: Metrics.firstLineHeight, alignment: .center)
                        entryTitleContent
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
                }
                    .buttonStyle(.plain)
                    .accessibilityLabel(entry.title)
                    .accessibilityHint("打开条目详情")
                    .frame(maxWidth: .infinity, alignment: .leading)
                Button {
                    load(entry)
                    editing = true
                    showingDetails = true
                    editorError = nil
                } label: {
                    Image(systemName: "pencil")
                        .font(.callout.weight(.semibold))
                        .frame(width: 34, height: Metrics.firstLineHeight, alignment: .center)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.secondary)
                .help("编辑条目")
                .accessibilityLabel("编辑条目")
            }
            HStack(spacing: 12) {
                Button { showingDetails = true } label: {
                    entryCounts
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(entry.title)
                .accessibilityHint("打开条目详情")
                Button("删除", role: .destructive, action: requestDelete)
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .help("删除条目")
                    .accessibilityLabel("删除条目")
            }
        }
        .padding(.horizontal, Metrics.horizontalPadding)
        .padding(.vertical, Metrics.verticalPadding)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var entryDetails: some View {
        VStack(spacing: 0) {
            ScrollView(.vertical, showsIndicators: true) {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(editing ? draftTitle : entry.title)
                                .font(.title.weight(.bold))
                                .lineLimit(2)
                                .truncationMode(.tail)
                        }
                        Spacer()
                    }
                    if editing {
                        editorBody
                    } else {
                        displayBody
                    }
                    if let revealError {
                        Label(revealError, systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, CatalogDetailMetrics.horizontalPadding)
                .padding(.vertical, CatalogDetailMetrics.verticalPadding)
                .background(
                    GeometryReader { proxy in
                        Color.clear.preference(key: CatalogDetailContentHeightKey.self, value: proxy.size.height)
                    }
                )
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(
                GeometryReader { proxy in
                    Color.clear.preference(key: CatalogDetailAvailableWidthKey.self, value: proxy.size.width)
                }
            )
            .onPreferenceChange(CatalogDetailContentHeightKey.self) { detailContentHeight = $0 }
            .onPreferenceChange(CatalogDetailAvailableWidthKey.self) { width in
                guard width > 0 else { return }
                detailAvailableWidth = width
            }

            Divider()
            detailActionBar
        }
        .frame(
            minWidth: 760,
            idealWidth: 860,
            maxWidth: 900,
            minHeight: editing ? 520 : 320,
            idealHeight: editing ? 640 : min(max(detailContentHeight + 92, 320), 720),
            maxHeight: editing ? 720 : min(max(detailContentHeight + 92, 320), 720)
        )
    }

    private var detailActionBar: some View {
        HStack(spacing: 8) {
            Spacer(minLength: 0)
            if editing {
                Button(isSaving ? "保存中…" : "保存条目") {
                    saveEntry()
                }
                .buttonStyle(.borderedProminent)
                .disabled(isSaving || commitEntryEdit == nil)
            } else {
                Button("编辑") {
                    load(entry)
                    editing = true
                    editorError = nil
                }
                .buttonStyle(.borderedProminent)
            }
            Button("关闭") {
                closeDetails()
            }
            .buttonStyle(.bordered)
            .keyboardShortcut(.cancelAction)
            .disabled(isSaving)
        }
        .padding(.horizontal, CatalogDetailMetrics.horizontalPadding)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .trailing)
        .background(.bar)
    }

    private var entryTitleContent: some View {
        Text(entry.title)
            .font(.headline.weight(.semibold))
            .lineLimit(2)
            .truncationMode(.tail)
            .frame(
                maxWidth: .infinity,
                minHeight: Metrics.titleBlockHeight,
                maxHeight: Metrics.titleBlockHeight,
                alignment: .topLeading
            )
    }

    private var entryCounts: some View {
        HStack(spacing: 12) {
            Label("字段 \(entry.fields.count)", systemImage: "list.bullet")
            Label("密码 \(entry.fields.filter { $0.type.isSecret }.count)", systemImage: "lock.fill")
                .fixedSize(horizontal: false, vertical: true)
        }
        .font(.callout)
        .foregroundStyle(.secondary)
    }

    private var displayBody: some View {
        let sheetWidth = detailAvailableWidth > 0 ? detailAvailableWidth : 760
        let gridAvailableWidth = CatalogDetailMetrics.gridAvailableWidth(for: sheetWidth)
        let widths = CatalogDetailColumnWidths.calculate(
            availableWidth: gridAvailableWidth
        )
        return VStack(alignment: .leading, spacing: 16) {
            Grid(
                horizontalSpacing: CatalogDetailMetrics.gridHorizontalSpacing,
                verticalSpacing: CatalogDetailMetrics.gridVerticalSpacing
            ) {
                ForEach(entry.fields, id: \.key) { field in
                    GridRow(alignment: .top) {
                        Text(field.label)
                            .font(.body.weight(.semibold))
                            .frame(width: widths.name, alignment: .leading)
                        detailValue(for: field)
                            .frame(width: widths.value, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                        detailAction(for: field)
                            .frame(width: widths.action, alignment: .center)
                    }
                }
            }
            .frame(width: gridAvailableWidth, alignment: .leading)
            if let notes = entry.notes, !notes.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("备注").font(.body.weight(.semibold))
                    Text(notes).font(.body).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func detailValue(for field: SecretCatalogFieldValue) -> some View {
        let presentation = CatalogFieldPresentation.resolve(
            field: field,
            revealedPlaintext: revealPresentationStates[field.key]?.visiblePlaintext
        )
        Text(presentation.displayText)
            .font(presentation.isSecret ? .system(.body, design: .monospaced) : .body)
            .foregroundStyle(
                presentation.isSecret
                    ? (presentation.isRevealed ? .orange : .orange)
                    : (presentation.displayText == "未填写" || presentation.displayText == "已隐藏" ? .secondary : .primary)
            )
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder
    private func detailAction(for field: SecretCatalogFieldValue) -> some View {
        let presentation = CatalogFieldPresentation.resolve(
            field: field,
            revealedPlaintext: revealPresentationStates[field.key]?.visiblePlaintext
        )
        Group {
            switch presentation.actionKind {
            case .copy:
                Button("复制") { copy(presentation.displayText) }
                    .buttonStyle(.bordered)
                    .disabled(!presentation.allowsCopy)
            case .reveal:
                Button(revealingKeys.contains(field.key) ? "验证中…" : "解密") { reveal(field) }
                    .buttonStyle(.bordered)
                    .disabled(revealCatalogField == nil || revealingKeys.contains(field.key))
            case .fillSecret:
                Button("填写密码") { editing = true }
                    .buttonStyle(.bordered)
            }
        }
        .id("\(field.key)-\(presentation.actionKind.rawValue)")
        .transition(
            reduceMotion
                ? .opacity
                : .opacity.combined(with: .scale(scale: 0.98))
        )
        .animation(
            reduceMotion ? .easeInOut(duration: 0.12) : .easeInOut(duration: 0.16),
            value: presentation.actionKind
        )
    }

    private func reveal(_ field: SecretCatalogFieldValue) {
        guard field.secretRef != nil, let revealCatalogField else { return }
        let fieldKey = field.key
        revealTasks[fieldKey]?.cancel()
        revealExpiryTasks[fieldKey]?.cancel()
        revealExpiryTasks.removeValue(forKey: fieldKey)
        revealPendingExpiryTasks[fieldKey]?.cancel()
        revealPendingExpiryTasks.removeValue(forKey: fieldKey)
        let generation = UUID()
        revealGenerations[fieldKey] = generation
        var presentationState = revealPresentationStates[fieldKey] ?? CatalogRevealPresentationState()
        presentationState.clearForNewReveal()
        revealPresentationStates[fieldKey] = presentationState
        canPresentReveals = scenePhase == .active
        revealingKeys.insert(fieldKey)
        revealError = nil

        let task: Task<Void, Never> = Task { @MainActor in
            defer {
                if revealGenerations[fieldKey] == generation {
                    revealTasks.removeValue(forKey: fieldKey)
                    revealingKeys.remove(fieldKey)
                }
            }
            do {
                let plaintext = try await revealCatalogField(entry.id, fieldKey)
                // LocalAuthentication may briefly make the App/window
                // inactive while its system UI is on screen. Hard security
                // events invalidate the generation instead; a transient
                // focus change must not discard this successful reveal.
                guard revealGenerations[fieldKey] == generation,
                      showingDetails
                else { return }
                presentRevealResult(
                    plaintext,
                    fieldKey: fieldKey,
                    generation: generation
                )
            } catch is CancellationError {
                return
            } catch {
                guard revealGenerations[fieldKey] == generation,
                      showingDetails
                else { return }
                revealError = "字段解密失败或本机授权未完成"
            }
        }
        revealTasks[fieldKey] = task
    }

    private func presentRevealResult(
        _ plaintext: String,
        fieldKey: String,
        generation: UUID
    ) {
        guard revealGenerations[fieldKey] == generation,
              showingDetails
        else { return }

        var state = revealPresentationStates[fieldKey] ?? CatalogRevealPresentationState()
        let transition = state.receive(
            plaintext,
            generation: generation,
            isActive: scenePhase == .active && canPresentReveals
        )

        if transition == .presented {
            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.16)) {
                revealPresentationStates[fieldKey] = state
            }
        } else {
            revealPresentationStates[fieldKey] = state
        }

        switch transition {
        case .presented:
            revealPendingExpiryTasks[fieldKey]?.cancel()
            revealPendingExpiryTasks.removeValue(forKey: fieldKey)
            scheduleRevealExpiry(for: fieldKey, generation: generation)
        case .heldPending:
            schedulePendingRevealExpiry(for: fieldKey, generation: generation)
        case .noPending:
            break
        }
    }

    private func presentPendingReveals() {
        guard scenePhase == .active,
              canPresentReveals,
              showingDetails
        else { return }

        let pendingKeys = revealPresentationStates.compactMap { key, state in
            state.pendingPlaintext == nil ? nil : key
        }

        for fieldKey in pendingKeys {
            guard let generation = revealGenerations[fieldKey] else {
                revealPresentationStates.removeValue(forKey: fieldKey)
                continue
            }

            revealPendingExpiryTasks[fieldKey]?.cancel()
            revealPendingExpiryTasks.removeValue(forKey: fieldKey)
            var state = revealPresentationStates[fieldKey] ?? CatalogRevealPresentationState()
            guard state.presentPending(generation: generation) == .presented else {
                revealPresentationStates[fieldKey] = state
                continue
            }

            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.16)) {
                revealPresentationStates[fieldKey] = state
            }
            scheduleRevealExpiry(for: fieldKey, generation: generation)
        }
    }

    private func scheduleRevealExpiry(for fieldKey: String, generation: UUID) {
        revealExpiryTasks[fieldKey]?.cancel()
        let expiryTask: Task<Void, Never> = Task { @MainActor in
            do {
                try await Task.sleep(for: CatalogRevealPresentationTiming.visibleTTL)
            } catch is CancellationError {
                return
            } catch {
                return
            }

            guard !Task.isCancelled,
                  revealGenerations[fieldKey] == generation,
                  showingDetails,
                  scenePhase == .active,
                  canPresentReveals
            else { return }

            guard var state = revealPresentationStates[fieldKey] else { return }
            state.expire()
            revealPresentationStates[fieldKey] = state
            revealExpiryTasks.removeValue(forKey: fieldKey)
        }

        guard revealGenerations[fieldKey] == generation,
              showingDetails,
              scenePhase == .active,
              canPresentReveals
        else {
            expiryTask.cancel()
            return
        }
        revealExpiryTasks[fieldKey] = expiryTask
    }

    private func schedulePendingRevealExpiry(for fieldKey: String, generation: UUID) {
        revealPendingExpiryTasks[fieldKey]?.cancel()
        let expiryTask: Task<Void, Never> = Task { @MainActor in
            do {
                // This is an independent pending-result deadline. It starts
                // only after decryption has completed while the App is
                // inactive; it is not the 45-second visible-display TTL.
                try await Task.sleep(for: CatalogRevealPresentationTiming.pendingTTL)
            } catch is CancellationError {
                return
            } catch {
                return
            }

            guard !Task.isCancelled,
                  revealGenerations[fieldKey] == generation,
                  showingDetails,
                  revealPresentationStates[fieldKey]?.pendingGeneration == generation
            else { return }

            guard var state = revealPresentationStates[fieldKey],
                  state.expirePending(generation: generation)
            else { return }
            revealPresentationStates[fieldKey] = state
            revealPendingExpiryTasks.removeValue(forKey: fieldKey)
        }

        guard revealGenerations[fieldKey] == generation,
              showingDetails,
              revealPresentationStates[fieldKey]?.pendingGeneration == generation
        else {
            expiryTask.cancel()
            return
        }
        revealPendingExpiryTasks[fieldKey] = expiryTask
    }

    private func hideRevealedPlaintexts() {
        let action = CatalogRevealLifecycleAction.forInterruption(.transientFocusLoss)
        guard action.hidePlaintext,
              !action.cancelInFlight,
              !action.invalidateGeneration
        else { return }

        canPresentReveals = false
        revealExpiryTasks.values.forEach { $0.cancel() }
        revealExpiryTasks.removeAll()
        // Keep the pending deadline alive across transient focus loss. Only
        // a hard security invalidation may clear a pending plaintext early.
        revealPresentationStates = revealPresentationStates.mapValues { currentState in
            var state = currentState
            state.hideVisible()
            return state
        }
        revealError = nil
    }

    private func invalidateRevealState() {
        let action = CatalogRevealLifecycleAction.forInterruption(.hardSecurityInvalidation)
        guard action.hidePlaintext,
              action.cancelInFlight,
              action.invalidateGeneration
        else { return }

        revealTasks.values.forEach { $0.cancel() }
        revealTasks.removeAll()
        revealPendingExpiryTasks.values.forEach { $0.cancel() }
        revealPendingExpiryTasks.removeAll()
        hideRevealedPlaintexts()
        revealPresentationStates.removeAll()
        revealGenerations.removeAll()
        revealingKeys.removeAll()
    }

    private func copy(_ value: String) {
        guard !value.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    private var editorBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("条目标题", text: $draftTitle)
                .textFieldStyle(.roundedBorder)
            HStack(spacing: 8) {
                TextField("别名（逗号分隔）", text: $draftAliases)
                    .textFieldStyle(.roundedBorder)
                TextField("标签（逗号分隔）", text: $draftTags)
                    .textFieldStyle(.roundedBorder)
            }
            TextEditor(text: $draftNotes)
                .font(.body)
                .frame(minHeight: 56, maxHeight: 100)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))

            HStack {
                if fieldSelection.isSelecting {
                    Text("已选 \(fieldSelection.selectedIDs.count) 项")
                        .font(.headline)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button(fieldSelection.selectedIDs.count == draftFields.count ? "取消全选" : "全选") {
                        if fieldSelection.selectedIDs.count == draftFields.count {
                            fieldSelection.clear()
                        } else {
                            fieldSelection.selectAll(draftFields.map(\.selectionID))
                        }
                    }
                    .buttonStyle(.plain)
                    Button("删除所选", role: .destructive) {
                        deleteSelectedFields()
                    }
                    .buttonStyle(.plain)
                    .disabled(fieldSelection.selectedIDs.isEmpty)
                    Button("完成") {
                        fieldSelection.finish()
                    }
                    .buttonStyle(.plain)
                } else {
                    Text("字段")
                        .font(.headline)
                    Spacer()
                    Button("新增自定义字段") {
                        draftFields.append(
                            CatalogFieldDraft.newField(
                                key: CatalogFieldDraft.nextCustomFieldKey(for: draftFields)
                            )
                        )
                    }
                    .buttonStyle(.bordered)
                    Button("批量编辑") {
                        fieldSelection.begin()
                    }
                    .buttonStyle(.borderless)
                    .disabled(draftFields.isEmpty)
                }
            }

            ForEach($draftFields) { $draft in
                let draftID = draft.id
                let selectionID = draft.selectionID
                SensitiveCatalogFieldEditorRow(
                    draft: $draft,
                    isSelecting: fieldSelection.isSelecting,
                    isSelected: fieldSelection.selectedIDs.contains(selectionID),
                    toggleSelection: { fieldSelection.toggle(selectionID) },
                    replaceSecret: replaceCatalogSecret,
                    entryID: entry.id,
                    onReplacementSuccess: { newReference in
                        let current = $draft.wrappedValue.field
                        $draft.wrappedValue.secretInput = ""
                        $draft.wrappedValue.field = SecretCatalogFieldValue(
                            key: current.key,
                            label: current.label,
                            type: current.type,
                            agentVisible: current.agentVisible,
                            searchable: current.searchable,
                            value: nil,
                            secretRef: newReference
                        )
                        editorError = nil
                    },
                    onDelete: {
                        deleteField(withID: draftID)
                    },
                    onMoveUp: {
                        guard let currentIndex = draftFields.firstIndex(where: { $0.id == draftID }), currentIndex > 0 else { return }
                        draftFields.swapAt(currentIndex, currentIndex - 1)
                    },
                    onMoveDown: {
                        guard let currentIndex = draftFields.firstIndex(where: { $0.id == draftID }), currentIndex + 1 < draftFields.count else { return }
                        draftFields.swapAt(currentIndex, currentIndex + 1)
                    }
                )
            }

            .onChange(of: draftFields.map(\.selectionID)) { _, ids in
                fieldSelection.retainVisibleIDs(ids)
            }

            if let editorError {
                Text(editorError)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    private func deleteSelectedFields() {
        let ids = fieldSelection.selectedIDs
        guard !ids.isEmpty else { return }
        draftFields.removeAll { ids.contains($0.selectionID) }
        fieldSelection.finish()
    }

    private func deleteField(withID id: UUID) {
        draftFields.removeAll { $0.id == id }
    }

    private func saveEntry() {
        guard !isSaving else { return }

        let title = draftTitle.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !title.isEmpty else {
            editorError = "条目标题不能为空"
            return
        }
        let fieldDraftSnapshot = draftFields
        let fields = fieldDraftSnapshot.map(\.field)
        if let fieldError = fields.compactMap(CatalogFieldDraftValidation.message(for:)).first {
            editorError = fieldError
            return
        }
        let updated = SecretCatalogEntry(
            id: entry.id,
            indexId: entry.indexId,
            title: title,
            type: entry.type,
            aliases: Self.csv(draftAliases),
            endpoints: CatalogFieldDraft.endpoints(from: fields),
            fields: fields,
            notes: draftNotes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : draftNotes,
            tags: Self.csv(draftTags),
            schema: entry.schema
        )
        do {
            try SecretCatalogDocument(
                indexes: [SecretCatalogIndex(id: entry.indexId, title: "validation")],
                entries: [updated]
            ).validate()
        } catch {
            editorError = "字段数据无效，请检查字段 key、类型和值"
            return
        }

        let secretInputs = fieldDraftSnapshot.compactMap { draft -> CatalogSecretInput? in
            guard draft.field.type.isSecret,
                  draft.field.secretRef == nil,
                  !draft.secretInput.isEmpty
            else { return nil }
            return CatalogSecretInput(
                key: draft.field.key,
                label: draft.field.label,
                plaintext: draft.secretInput
            )
        }
        let commit = commitEntryEdit
        isSaving = true
        editorError = nil

        Task { @MainActor in
            let result = await commit?(updated, secretInputs)
            isSaving = false
            switch result {
            case .success:
                editing = false
                editorError = nil
                draftFields = CatalogFieldDraft.make(from: updated.fields, endpoints: updated.endpoints)
            case .failure(let error):
                editorError = error.displayText
            case nil:
                editorError = CatalogMutationUIError(
                    code: "APP_CONTROL_UNAVAILABLE",
                    message: "本机控制服务不可用，无法保存条目"
                ).displayText
            }
        }
    }

    private func load(_ value: SecretCatalogEntry) {
        draftTitle = value.title
        draftAliases = value.aliases.joined(separator: ", ")
        draftTags = value.tags.joined(separator: ", ")
        draftNotes = value.notes ?? ""
        draftFields = CatalogFieldDraft.make(from: value.fields, endpoints: value.endpoints)
        fieldSelection.finish()
    }

    private func cancelEditing() {
        if editing {
            load(entry)
        }
        editing = false
        editorError = nil
        invalidateRevealState()
    }

    private func closeDetails() {
        guard !isSaving else { return }
        cancelEditing()
        showingDetails = false
    }

    private static func csv(_ value: String) -> [String] {
        value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

}

private struct SensitiveCatalogFieldEditorRow: View {
    @Binding var draft: CatalogFieldDraft
    let isSelecting: Bool
    let isSelected: Bool
    let toggleSelection: () -> Void
    let replaceSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?
    let entryID: String
    let onReplacementSuccess: (String) -> Void
    let onDelete: () -> Void
    let onMoveUp: () -> Void
    let onMoveDown: () -> Void

    @State private var showsSecret = false
    @State private var isReplacingSecret = false
    @State private var isSubmittingReplacement = false
    @State private var errorMessage: String?

    init(
        draft: Binding<CatalogFieldDraft>,
        isSelecting: Bool = false,
        isSelected: Bool = false,
        toggleSelection: @escaping () -> Void = {},
        replaceSecret: ((String, String, String, String) async -> CatalogMutationUIResult)?,
        entryID: String,
        onReplacementSuccess: @escaping (String) -> Void = { _ in },
        onDelete: @escaping () -> Void,
        onMoveUp: @escaping () -> Void,
        onMoveDown: @escaping () -> Void
    ) {
        self._draft = draft
        self.isSelecting = isSelecting
        self.isSelected = isSelected
        self.toggleSelection = toggleSelection
        self.replaceSecret = replaceSecret
        self.entryID = entryID
        self.onReplacementSuccess = onReplacementSuccess
        self.onDelete = onDelete
        self.onMoveUp = onMoveUp
        self.onMoveDown = onMoveDown
    }

    private var field: SecretCatalogFieldValue {
        get { draft.field }
        nonmutating set { draft.field = newValue }
    }

    private var secretInput: String {
        get { draft.secretInput }
        nonmutating set { draft.secretInput = newValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            if isSelecting {
                Button(action: toggleSelection) {
                    HStack(spacing: 8) {
                        Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(isSelected ? Color.accentColor : .secondary)
                        Text(field.label)
                            .font(.callout.weight(.semibold))
                            .lineLimit(2)
                            .truncationMode(.tail)
                        Spacer(minLength: 0)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(field.label)
                .accessibilityValue(isSelected ? "已选中" : "未选中")
            } else {
                HStack(spacing: 7) {
                    TextField("字段名称", text: labelBinding)
                        .textFieldStyle(.roundedBorder)
                    Picker("类型", selection: typeBinding) {
                        ForEach(SecretCatalogFieldType.allCases, id: \.self) { type in
                            Text(Self.typeName(type)).tag(type)
                        }
                    }
                    .frame(width: 135)
                    Button(action: onMoveUp) { Image(systemName: "chevron.up") }
                        .buttonStyle(.borderless)
                    Button(action: onMoveDown) { Image(systemName: "chevron.down") }
                        .buttonStyle(.borderless)
                    Button(role: .destructive, action: onDelete) { Image(systemName: "trash") }
                        .buttonStyle(.borderless)
                }

                if field.type.isSecret {
                    secretEditor
                } else {
                    valueEditor
                }

                HStack(spacing: 12) {
                    Toggle("智能体可查看", isOn: agentVisibleBinding)
                    Toggle("可搜索", isOn: searchableBinding)
                    Spacer()
                }
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption2)
                    .foregroundStyle(.orange)
                    .lineLimit(2)
            }
        }
        .padding(9)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .onDisappear {
            secretInput = ""
            isReplacingSecret = false
        }
    }

    @ViewBuilder
    private var secretEditor: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                if field.secretRef != nil {
                    Text("已绑定密文")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    if isReplacingSecret {
                        secretInputEditor(prompt: "输入新密码")
                        Button(showsSecret ? "隐藏" : "显示") {
                            showsSecret.toggle()
                        }
                        .buttonStyle(.borderless)
                        Button("取消") {
                            secretInput = ""
                            isReplacingSecret = false
                            errorMessage = nil
                        }
                        .buttonStyle(.borderless)
                        Button(isSubmittingReplacement ? "提交中…" : "提交替换") {
                            submitSecretReplacement()
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isSubmittingReplacement || secretInput.isEmpty || replaceSecret == nil)
                    } else {
                        Text("已绑定")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                        Button("替换密码") {
                            secretInput = ""
                            errorMessage = nil
                            isReplacingSecret = true
                        }
                        .buttonStyle(.bordered)
                        .disabled(replaceSecret == nil)
                    }
                } else {
                    secretInputEditor(prompt: "输入密码")
                    Button(showsSecret ? "隐藏" : "显示") {
                        showsSecret.toggle()
                    }
                    .buttonStyle(.borderless)
                }
            }

        }
    }

    @ViewBuilder
    private func secretInputEditor(prompt: String) -> some View {
        if showsSecret {
            TextField(text: $draft.secretInput, prompt: Text(prompt).foregroundStyle(.orange)) {
                Text("密码")
            }
            .textFieldStyle(.roundedBorder)
        } else {
            SecureField(text: $draft.secretInput, prompt: Text(prompt).foregroundStyle(.orange)) {
                Text("密码")
            }
            .textFieldStyle(.roundedBorder)
        }
    }

    @ViewBuilder
    private var valueEditor: some View {
        switch field.type {
        case .multiline:
            TextEditor(text: textBinding)
                .frame(minHeight: 50, maxHeight: 90)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.25)))
        case .boolean:
            Toggle("值", isOn: booleanBinding)
        case .list:
            TextField("列表值（逗号分隔）", text: listBinding)
                .textFieldStyle(.roundedBorder)
        default:
            TextField(Self.typeName(field.type), text: textBinding)
                .textFieldStyle(.roundedBorder)
        }
    }

    private var labelBinding: Binding<String> {
        Binding(
            get: { field.label },
            set: { field = updatedField(from: field, label: $0) }
        )
    }

    private var typeBinding: Binding<SecretCatalogFieldType> {
        Binding(
            get: { field.type },
            set: { newType in
                if newType != .secret { secretInput = "" }
                let current = field
                field = updatedField(
                    from: current,
                    type: newType,
                    value: newType.isSecret ? nil : current.value,
                    setValue: true,
                    secretRef: newType.isSecret ? current.secretRef : nil,
                    setSecretRef: true
                )
            }
        )
    }

    private var agentVisibleBinding: Binding<Bool> {
        Binding(
            get: { field.agentVisible },
            set: { field = updatedField(from: field, agentVisible: $0) }
        )
    }

    private var searchableBinding: Binding<Bool> {
        Binding(
            get: { field.searchable },
            set: { field = updatedField(from: field, searchable: $0) }
        )
    }

    private var booleanBinding: Binding<Bool> {
        Binding(
            get: {
                guard case .boolean(let value) = field.value else { return false }
                return value
            },
            set: { field = updatedField(from: field, value: .boolean($0), setValue: true) }
        )
    }

    private var listBinding: Binding<String> {
        Binding(
            get: {
                guard case .list(let values) = field.value else { return "" }
                return values.joined(separator: ", ")
            },
            set: { rawValue in
                let values = rawValue
                    .split(separator: ",")
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                    .filter { !$0.isEmpty }
                field = updatedField(
                    from: field,
                    value: values.isEmpty ? nil : .list(values),
                    setValue: true
                )
                errorMessage = nil
            }
        )
    }

    private var textBinding: Binding<String> {
        Binding(
            get: {
                guard let value = field.value else { return "" }
                switch value {
                case .string(let value): return value
                case .number(let value): return String(value)
                case .boolean, .list: return ""
                }
            },
            set: { rawValue in
                switch field.type {
                case .port:
                    guard rawValue.isEmpty || (Int(rawValue).map { (0...65_535).contains($0) } ?? false) else {
                        errorMessage = "端口必须是 0 到 65535 的数字"
                        return
                    }
                    field = updatedField(
                        from: field,
                        value: rawValue.isEmpty ? nil : .number(Double(Int(rawValue) ?? 0)),
                        setValue: true
                    )
                case .number:
                    guard rawValue.isEmpty || Double(rawValue) != nil else {
                        errorMessage = "数字字段格式不正确"
                        return
                    }
                    field = updatedField(
                        from: field,
                        value: rawValue.isEmpty ? nil : .number(Double(rawValue) ?? 0),
                        setValue: true
                    )
                default:
                    field = updatedField(
                        from: field,
                        value: rawValue.isEmpty ? nil : .string(rawValue),
                        setValue: true
                    )
                }
                errorMessage = nil
            }
        )
    }

    private func updatedField(
        from current: SecretCatalogFieldValue,
        label: String? = nil,
        type: SecretCatalogFieldType? = nil,
        agentVisible: Bool? = nil,
        searchable: Bool? = nil,
        value: SecretCatalogValue? = nil,
        setValue: Bool = false,
        secretRef: String? = nil,
        setSecretRef: Bool = false
    ) -> SecretCatalogFieldValue {
        let resolvedType = type ?? current.type
        let resolvedValue = setValue ? value : current.value
        let resolvedSecretRef = setSecretRef ? secretRef : current.secretRef
        return SecretCatalogFieldValue(
            key: current.key,
            label: label ?? current.label,
            type: resolvedType,
            agentVisible: agentVisible ?? current.agentVisible,
            searchable: searchable ?? current.searchable,
            value: resolvedType.isSecret ? nil : resolvedValue,
            secretRef: resolvedType.isSecret ? resolvedSecretRef : nil
        )
    }

    private func submitSecretReplacement() {
        guard let replaceSecret,
              !secretInput.isEmpty,
              field.secretRef != nil
        else { return }
        let plaintext = secretInput
        let key = field.key
        let label = field.label
        isSubmittingReplacement = true
        Task {
            let result = await replaceSecret(entryID, key, label, plaintext)
            secretInput = ""
            isSubmittingReplacement = false
            switch result {
            case .success(let writeResult):
                guard let newReference = writeResult.secretReference else {
                    errorMessage = "替换成功但未收到新的安全引用，请刷新目录"
                    return
                }
                isReplacingSecret = false
                errorMessage = nil
                onReplacementSuccess(newReference)
            case .failure(let error):
                errorMessage = error.displayText
            }
        }
    }

    private static func typeName(_ type: SecretCatalogFieldType) -> String {
        switch type {
        case .text: return "文本"
        case .multiline: return "多行文本"
        case .url: return "URL"
        case .host: return "主机"
        case .port: return "端口"
        case .number: return "数字"
        case .boolean: return "布尔"
        case .date: return "日期"
        case .list: return "列表"
        case .secret: return "密码"
        }
    }
}

private struct SavedSecretReferencesCard: View {
    let references: [SecretReferenceMetadata]
    let refresh: (() async -> Void)?
    @State private var copiedReference: String?
    @State private var isRefreshing = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                Label("已保存密文", systemImage: "key.viewfinder")
                    .font(.title3.weight(.semibold))
                Spacer()
                Text("共 \(references.count) 条")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                if let refresh {
                    Button {
                        Task {
                            isRefreshing = true
                            await refresh()
                            isRefreshing = false
                        }
                    } label: {
                        Label("刷新", systemImage: "arrow.clockwise")
                    }
                    .disabled(isRefreshing)
                }
            }

            Text("这里保存使用过的敏感信息段落模板，只展示段落上下文和 secret:// 引用，不展示明文。复制后可直接交给 agent 或贴回笔记。")
                .font(.callout)
                .foregroundStyle(.secondary)

            if references.isEmpty {
                HStack(spacing: 10) {
                    Image(systemName: "tray")
                        .foregroundStyle(.secondary)
                    Text("还没有保存的密文。通过 Obsidian 插件加密敏感信息后，引用会出现在这里。")
                        .foregroundStyle(.secondary)
                }
                .font(.callout)
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            } else {
                VStack(spacing: 10) {
                    ForEach(references, id: \.reference) { reference in
                        SavedSecretReferenceRow(
                            metadata: reference,
                            isCopied: copiedReference == reference.reference
                        ) { text in
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(text, forType: .string)
                            withAnimation(VaultWorkbenchMotion.interactive) {
                                copiedReference = reference.reference
                            }
                        }
                    }
                }
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

private struct SavedSecretReferenceRow: View {
    let metadata: SecretReferenceMetadata
    let isCopied: Bool
    let copyText: (String) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "lock.doc.fill")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(policyColor)
                .frame(width: 34, height: 34)
                .background(policyColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Text(SavedReferenceDisplay.title(for: metadata))
                        .font(.headline)
                        .lineLimit(1)
                    Text(policyLabel)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(policyColor)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(policyColor.opacity(0.10), in: Capsule())
                    Spacer()
                    Text(metadata.updatedAt.formatted(date: .numeric, time: .shortened))
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                Text(SavedReferenceDisplay.text(for: metadata))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

                HStack {
                    Text("只复制段落上下文和密文引用，不复制明文。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        copyText(SavedReferenceDisplay.text(for: metadata))
                    } label: {
                        Label(isCopied ? "已复制" : "复制可用段落", systemImage: isCopied ? "checkmark" : "doc.on.doc")
                    }
                    .buttonStyle(.bordered)
                }
            }
        }
        .padding(14)
        .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

}

enum SavedReferenceDisplay {
    static let paragraphReferenceMarker = "[[ASV_REFERENCE]]"

    static func title(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return "未命名密文"
        }
        return label.contains(paragraphReferenceMarker) ? "可用段落" : label
    }

    static func text(for metadata: SecretReferenceMetadata) -> String {
        guard let label = metadata.label, !label.isEmpty else {
            return metadata.reference
        }
        if label.contains(paragraphReferenceMarker) {
            return label.replacingOccurrences(of: paragraphReferenceMarker, with: metadata.reference)
        }
        return "\(label)：\(metadata.reference)"
    }

}

private extension SavedSecretReferenceRow {
    var policyLabel: String {
        switch metadata.policy {
        case .read:
            return "读取"
        case .externalSend:
            return "外发"
        case .credential:
            return "凭据"
        }
    }

    private var policyColor: Color {
        switch metadata.policy {
        case .read:
            return .blue
        case .externalSend:
            return .orange
        case .credential:
            return .indigo
        }
    }
}

private struct SecurityBoundaryPanel: View {
    let showTemplate: (() async -> Void)?

    private let rows = [
        ("聊天里保留什么", "只保留 secret:// 引用和非敏感上下文。"),
        ("明文在哪里出现", "只在本机授权后的 App 窗口、MCP 内部 runner 或用户明确导出的本地文件中短暂出现。"),
        ("智能体不能拿什么", "不能拿到密码、token、Authorization header、cookie、解密后的字段值。"),
        ("高风险动作", "删除、改密码、公开网络发送、数据库写入等必须使用更窄的 allowlist 工具和本机授权。")
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(VaultWorkbenchCopy.securityBoundary)
                .font(.title3.weight(.semibold))
                .lineSpacing(4)

            HStack(spacing: 12) {
                Image(systemName: "doc.text")
                    .foregroundStyle(.blue)
                VStack(alignment: .leading, spacing: 3) {
                    Text("敏感信息模板")
                        .font(.headline)
                    Text("打开 SVLT 随应用安装的只读模板副本；不会选择、接管或修改用户目录。")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("查看敏感信息模板") {
                    Task { await showTemplate?() }
                }
                .buttonStyle(.bordered)
                .disabled(showTemplate == nil)
            }
            .padding(14)
            .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 14, style: .continuous))

            LazyVGrid(columns: [
                GridItem(.flexible(), spacing: 16),
                GridItem(.flexible(), spacing: 16)
            ], spacing: 16) {
                ForEach(rows, id: \.0) { row in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(row.0)
                            .font(.headline)
                        Text(row.1)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .padding(18)
                    .frame(maxWidth: .infinity, minHeight: 120, alignment: .topLeading)
                    .background(.background.opacity(0.70), in: RoundedRectangle(cornerRadius: 18, style: .continuous))
                }
            }
        }
        .padding(22)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}

struct AgentAutomationAuditCard: View {
    let entries: [CatalogSecurityAuditEntry]
    let errorMessage: String?

    var body: some View {
        WorkbenchPanelSurface {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .center) {
                    Label("智能体自动化", systemImage: "sparkles.rectangle.stack")
                        .font(.title3.weight(.semibold))
                    Spacer()
                    Text(summaryText)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
                .fixedSize(horizontal: false, vertical: true)

                if let errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .padding(14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        .fixedSize(horizontal: false, vertical: true)
                }

                ScrollView(.vertical, showsIndicators: true) {
                    if entries.isEmpty, errorMessage == nil {
                        VStack {
                            Spacer(minLength: 24)
                            Label("暂无活动", systemImage: "clock.badge.questionmark")
                                .foregroundStyle(.secondary)
                            Spacer()
                        }
                        .frame(maxWidth: .infinity, minHeight: 180)
                    } else if entries.isEmpty {
                        Label("最近活动暂不可用", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, minHeight: 100)
                    } else {
                        VStack(spacing: 10) {
                            ForEach(entries) { entry in
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: iconName(for: entry.operation)).foregroundStyle(.blue).frame(width: 24)
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text(entry.operation.displayName).font(.headline)
                                            Spacer()
                                            Text(entry.result.displayName).font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                                        }
                                        Text(entry.target).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                                        Text("\(entry.caller?.displayLabel ?? entry.source.displayName) · \(entry.authorizationMode?.displayName ?? entry.authorizationOutcome.displayName) · \(entry.referenceCount) 个引用 · \(entry.timestamp.formatted(date: .omitted, time: .standard))")
                                            .font(.caption).foregroundStyle(.tertiary)
                                    }
                                }
                                .padding(14)
                                .background(.background.opacity(0.65), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                            }
                        }
                    }
                }
                .scrollIndicators(.automatic)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                .layoutPriority(1)
            }
            .padding(20)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private var summaryText: String {
        if !entries.isEmpty { return "最近 \(entries.count) 条" }
        return errorMessage == nil ? "暂无记录" : "读取异常"
    }

    private func iconName(for operation: AuditOperation) -> String {
        switch operation {
        case .reveal:
            return "eye"
        case .catalogMutation, .formatCheck, .formatRepair:
            return "doc.badge.gearshape"
        case .authorization:
            return "person.badge.key"
        case .credentialUse:
            return "key.fill"
        case .secureExecute:
            return "cable.connector"
        default:
            return "bolt.horizontal.circle"
        }
    }
}
