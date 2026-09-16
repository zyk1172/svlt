import AppKit
import AgentSecretVaultApp
import SwiftUI
import UniformTypeIdentifiers
import VaultCore
import VaultIPC
import VaultService

@main
struct AgentSecretVaultApplication: App {
    @NSApplicationDelegateAdaptor(AgentSecretVaultAppDelegate.self) private var appDelegate
    @State private var secureViewerModel = SecureViewerModel()
    @StateObject private var runtime: AgentSecretVaultRuntime

    init() {
        let runtime = AgentSecretVaultRuntimeStore.shared
        _runtime = StateObject(wrappedValue: runtime)
        Task { @MainActor in
            await runtime.start()
        }
    }

    var body: some Scene {
        Window("SVLT", id: MenuBarPresentation.mainWindowID) {
            VStack(spacing: 0) {
                VaultApprovalModeBar()
                Divider()
                VaultWorkbenchView(
                    status: runtime.status,
                    agentServiceStatus: runtime.agentServiceStatus,
                    agentServiceActionInFlight: runtime.agentServiceActionInFlight,
                    agentServiceActionErrorMessage: runtime.agentServiceActionErrorMessage,
                    enableAgentService: {
                        await runtime.enableAgentService()
                    },
                    disableAgentService: {
                        await runtime.disableAgentService()
                    },
                    restartAgentService: {
                        await runtime.restartAgentService()
                    },
                    auditEntries: runtime.auditEntries,
                    auditError: runtime.auditError,
                    secureInputRequest: runtime.secureInputRequest,
                    submitSecureInput: { request, selectedTargets, values in
                        await runtime.submitSecureInput(
                            request: request,
                            selectedTargets: selectedTargets,
                            values: values
                        )
                    },
                    cancelSecureInput: { id in
                        await runtime.cancelSecureInput(id: id)
                    },
                    savedReferences: runtime.savedReferences,
                    sensitiveIndexURL: runtime.sensitiveIndexURL,
                    sensitiveCatalogSnapshot: runtime.sensitiveCatalogSnapshot,
                    sensitiveCatalogError: runtime.sensitiveIndexError,
                    sensitiveCatalogCanAdoptV2: runtime.sensitiveCatalogCanAdoptV2,
                    sensitiveCatalogCanAdoptV3: runtime.sensitiveCatalogCanAdoptV3,
                    refreshSavedReferences: {
                        await runtime.refreshSavedReferences()
                    },
                    chooseSensitiveIndex: {
                        runtime.chooseSensitiveIndex()
                    },
                    refreshSensitiveCatalog: {
                        await runtime.refreshSensitiveCatalog()
                    },
                    validateSensitiveCatalog: {
                        await runtime.validateSensitiveCatalog()
                    },
                    adoptExternalV2Catalog: {
                        await runtime.adoptExternalV2Catalog()
                    },
                    adoptExternalV3Catalog: {
                        await runtime.adoptExternalV3Catalog()
                    },
                    approveExternalCatalogChange: {
                        await runtime.approveExternalCatalogChange()
                    },
                    formatRepairPlan: runtime.formatRepairPlan,
                    checkSensitiveCatalogFormat: {
                        await runtime.checkSensitiveCatalogFormat()
                    },
                    repairSensitiveCatalogFormat: {
                        await runtime.repairSensitiveCatalogFormat()
                    },
                    createCatalogIndex: { title in
                        await runtime.createCatalogIndex(title: title)
                    },
                    createCatalogEntry: { indexID, title, presetID in
                        await runtime.createCatalogEntry(indexID: indexID, title: title, presetID: presetID)
                    },
                    commitCatalogEntryEdit: { entry, secretInputs in
                        await runtime.commitCatalogEntryEdit(entry: entry, secretInputs: secretInputs)
                    },
                    revealCatalogField: { entryID, key in
                        try await runtime.revealCatalogField(entryID: entryID, key: key)
                    },
                    replaceCatalogSecret: { entryID, key, label, plaintext in
                        await runtime.replaceCatalogSecret(
                            entryID: entryID,
                            key: key,
                            label: label,
                            plaintext: plaintext
                        )
                    },
                    applyCatalogBatch: { mutation in
                        await runtime.applyCatalogBatch(mutation)
                    },
                    showSensitiveCatalogTemplate: {
                        await runtime.showSensitiveCatalogTemplate()
                    }
                )
            }
                .frame(width: 1280, height: 820)
                .task {
                    await runtime.start()
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                    secureViewerModel.handleFocusChanged(isFocused: false)
                    NotificationCenter.default.post(
                        name: .vaultWorkbenchTransientFocusLost,
                        object: nil
                    )
                    Task {
                        await runtime.clearRevealSessionsForTransientFocusLoss()
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.screensDidSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    Task {
                        await runtime.cancelAllSecureInputRequests()
                        await runtime.clearRevealSessions()
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                    secureViewerModel.handleSleepNotification()
                    Task {
                        await runtime.cancelAllSecureInputRequests()
                        await runtime.clearRevealSessions()
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSWorkspace.sessionDidResignActiveNotification)) { _ in
                    secureViewerModel.handleLockNotification()
                    Task {
                        await runtime.cancelAllSecureInputRequests()
                        await runtime.clearRevealSessions()
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: NSApplication.willTerminateNotification)) { _ in
                    Task {
                        await runtime.cancelAllSecureInputRequests()
                        await runtime.clearRevealSessions()
                    }
                }
        }
            .commands {
                CommandGroup(replacing: .pasteboard) {}
                CommandMenu("导航") {
                    Button("控制台") {
                        navigateWorkbench(to: .overview)
                    }
                    .keyboardShortcut("1", modifiers: [.command])

                    Button("密文库") {
                        navigateWorkbench(to: .secrets)
                    }
                    .keyboardShortcut("2", modifiers: [.command])

                    Button("智能体自动化") {
                        navigateWorkbench(to: .automation)
                    }
                    .keyboardShortcut("3", modifiers: [.command])

                    Button("使用教程") {
                        navigateWorkbench(to: .tutorial)
                    }
                    .keyboardShortcut("4", modifiers: [.command])

                    Button("常见问题") {
                        navigateWorkbench(to: .faq)
                    }
                    .keyboardShortcut("5", modifiers: [.command])
                }
            }
            .defaultSize(width: 1280, height: 820)
            .windowResizability(.contentSize)
            .windowStyle(.hiddenTitleBar)

        MenuBarExtra("SVLT", systemImage: MenuBarPresentation.statusItemSymbol) {
            MenuBarVaultPanel(
                status: runtime.status,
                auditEntries: runtime.auditEntries,
                savedReferences: runtime.savedReferences,
                refreshSavedReferences: {
                    await runtime.refreshSavedReferences()
                },
                clearRevealSessions: { await runtime.clearRevealSessions() },
                requestTermination: {
                    await appDelegate.requestMenuBarTermination()
                }
            )
            .task {
                await runtime.start()
            }
        }
        .menuBarExtraStyle(.window)
    }

    private func navigateWorkbench(to section: VaultWorkbenchSection) {
        NotificationCenter.default.post(
            name: .vaultWorkbenchNavigate,
            object: nil,
            userInfo: ["section": section.rawValue]
        )
    }
}

private struct VaultApprovalModeBar: View {
    @State private var mode = VaultApprovalModeState.shared.mode
    @State private var errorMessage: String?

    var body: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 7) {
                    Image(systemName: mode == .noApproval ? "bolt.shield.fill" : "checkmark.shield.fill")
                        .foregroundStyle(mode == .noApproval ? .orange : .blue)
                    Text("Agent 授权模式")
                        .font(.headline)
                }
                Text(mode == .noApproval
                    ? "SVLT 不再弹出人工审批；是否执行由 Agent、用户意图和宿主审批/安全策略决定。"
                    : "SVLT 保留基于操作效果的本机审批，高风险操作可能要求 Touch ID 或密码。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 20)

            Picker("Agent 授权模式", selection: modeBinding) {
                Text("审批模式").tag(VaultApprovalMode.approvalRequired)
                Text("无审批模式").tag(VaultApprovalMode.noApproval)
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 250)
            .accessibilityIdentifier("vault-approval-mode-picker")

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .padding(.horizontal, 18)
        .frame(height: 58)
        .background(.regularMaterial)
        .onAppear {
            mode = VaultApprovalModeState.shared.mode
        }
    }

    private var modeBinding: Binding<VaultApprovalMode> {
        Binding(
            get: { mode },
            set: { newMode in
                do {
                    mode = try VaultApprovalModeState.shared.setMode(newMode)
                    errorMessage = nil
                } catch {
                    mode = VaultApprovalModeState.shared.mode
                    errorMessage = "模式保存失败"
                }
            }
        )
    }
}

@MainActor
private enum AgentSecretVaultRuntimeStore {
    static let shared = AgentSecretVaultRuntime()
}

@MainActor
private final class AgentSecretVaultRuntime: ObservableObject {
    @Published var status = WorkbenchStatus(
        locked: true,
        ipcAvailable: false,
        activeKnowledgeBaseRoot: nil,
        pluginConnected: false
    )
    @Published var agentServiceStatus: AgentServiceStatus = .notRegistered
    @Published var agentServiceActionInFlight = false
    @Published var agentServiceActionErrorMessage: String?
    @Published var auditEntries: [CatalogSecurityAuditEntry] = []
    @Published var auditError: String?
    @Published var secureInputRequest: CatalogAgentSecureInputRequest?
    @Published var savedReferences: [SecretReferenceMetadata] = []
    @Published var sensitiveIndexURL: URL?
    @Published var sensitiveCatalogSnapshot: SensitiveCatalogSnapshot?
    @Published var sensitiveCatalogCanAdoptV2 = false
    @Published var sensitiveCatalogCanAdoptV3 = false
    @Published var catalogAgentWriteStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled)
    @Published var catalogAgentWriteError: String?
    @Published var sensitiveIndexError: String?
    @Published var formatRepairPlan: CatalogFormatRepairPlan?

    private var agentClient: VaultIPCClient?
    private var appControlClient: AppControlIPCClient?
    private let uiRevealSessionStore = RevealSessionStore(defaultTTLSeconds: 60)
    private var uiRequestObserver: NSObjectProtocol?
    private var writeAccessObserver: NSObjectProtocol?
    private var auditObserver: NSObjectProtocol?
    private var secureInputObserver: NSObjectProtocol?
    private var applicationActivationObserver: NSObjectProtocol?
    private var presentedAgentSessionIDs: Set<String> = []
    private let catalogTemplateStore = SensitiveCatalogTemplateStore()
    private var started = false
    private var isStarting = false
    private var readinessTask: Task<Void, Never>?
    private var pendingWriteAccessQueue = PendingCatalogWriteAccessQueue()
    /// The daemon retains the ordered pending requests. The App is only the
    /// single consumer that advances the current request directly into
    /// device-owner authentication; no separate confirmation button exists.
    private var autoAuthenticatingCatalogRequestID: UUID?
    private var isAutoAuthenticatingCatalogRequest = false
    private var pendingSecureInputQueue: [UUID] = []
    private var presentedSecureInputIDs: Set<UUID> = []

    func start() async {
        guard !started, !isStarting else {
            return
        }
        isStarting = true
        defer { isStarting = false }

        do {
            let registration = AgentServiceRegistration.shared
            try await registration.registerIfNeeded()
            agentServiceStatus = registration.status
            let client = try VaultIPCClient.defaultClient()
            agentClient = client
            appControlClient = try AppControlIPCClient.defaultClient()
            if let appControlClient {
                catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                    ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            }
            startUIRequestObserver()
            startWriteAccessObserver()
            startSecurityAuditObserver()
            startSecureInputObserver()
            startApplicationActivationObserver()
            try? catalogTemplateStore.ensureInstalled()
            await refreshSensitiveCatalog()
            await refreshAuditEntries()
            await refreshPendingCatalogWriteAccessRequests()
            await refreshPendingSecureInputRequests()
            started = true

            if !(await connectToAgent(client)) {
                markAgentDisconnected()
                startReadinessMonitoring(client)
            }
        } catch {
            NSLog("SVLT runtime startup failed [AGENT_START_FAILED]")
            sensitiveIndexError = "无法启动本地服务"
            agentServiceStatus = AgentServiceRegistration.shared.status
            status = WorkbenchStatus(
                locked: true,
                ipcAvailable: false,
                activeKnowledgeBaseRoot: nil,
                pluginConnected: false
            )
        }
    }

    private func connectToAgent(_ client: VaultIPCClient) async -> Bool {
        guard !AgentServiceRegistration.shared.isExplicitlyDisabled else {
            return false
        }

        let retryDelays: [Duration] = [
            .zero,
            .milliseconds(100),
            .milliseconds(250),
            .milliseconds(500),
            .seconds(1),
            .seconds(2),
            .seconds(2),
            .seconds(2)
        ]

        for (index, delay) in retryDelays.enumerated() {
            if index > 0 {
                do {
                    try await Task.sleep(for: delay)
                } catch {
                    return false
                }
            }

            do {
                status = try await client.workbenchStatus()
                agentServiceStatus = .running
                await refreshSavedReferences()
                await refreshAuditEntries()
                await refreshPendingCatalogWriteAccessRequests()
                await refreshPendingSecureInputRequests()
                await presentPendingRevealSessions()
                return true
            } catch {
                continue
            }
        }

        return false
    }

    private func startReadinessMonitoring(_ client: VaultIPCClient) {
        readinessTask?.cancel()
        readinessTask = Task { @MainActor [weak self] in
            let retryDelays: [Duration] = [.seconds(2), .seconds(4), .seconds(8), .seconds(10)]
            var delayIndex = 0
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: retryDelays[delayIndex])
                } catch {
                    return
                }

                guard let self,
                      self.started,
                      !AgentServiceRegistration.shared.isExplicitlyDisabled
                else {
                    return
                }
                if await self.connectToAgent(client) {
                    return
                }
                self.markAgentDisconnected()
                delayIndex = min(delayIndex + 1, retryDelays.count - 1)
            }
        }
    }

    private func markAgentDisconnected() {
        if AgentServiceRegistration.shared.isExplicitlyDisabled {
            markAgentDisabled()
            return
        }
        agentServiceStatus = AgentServiceRegistration.shared.status
        status = WorkbenchStatus(
            locked: true,
            ipcAvailable: false,
            activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
            pluginConnected: false
        )
    }

    private func markAgentDisabled() {
        agentServiceStatus = .disabled
        status = WorkbenchStatus(
            locked: true,
            ipcAvailable: false,
            available: false,
            ready: false,
            activeKnowledgeBaseRoot: status.activeKnowledgeBaseRoot,
            pluginConnected: false
        )
    }

    private func reconnectAfterServiceAction() async {
        readinessTask?.cancel()
        readinessTask = nil

        let registration = AgentServiceRegistration.shared
        agentServiceStatus = registration.status
        guard !registration.isExplicitlyDisabled else {
            agentClient = nil
            appControlClient = nil
            markAgentDisabled()
            return
        }

        do {
            let client = try VaultIPCClient.defaultClient()
            agentClient = client
            appControlClient = try AppControlIPCClient.defaultClient()
            if let appControlClient {
                catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                    ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            }
            if !(await connectToAgent(client)) {
                markAgentDisconnected()
                startReadinessMonitoring(client)
            }
        } catch {
            agentClient = nil
            appControlClient = nil
            markAgentDisconnected()
        }
    }

    private func performAgentServiceAction(
        failureCode: String,
        failureMessage: String,
        operation: () async throws -> Void
    ) async {
        guard !agentServiceActionInFlight else { return }
        agentServiceActionInFlight = true
        agentServiceActionErrorMessage = nil
        defer { agentServiceActionInFlight = false }

        do {
            try await operation()
            await reconnectAfterServiceAction()
        } catch {
            NSLog("SVLT Agent service action failed [\(failureCode)]")
            agentServiceActionErrorMessage = failureMessage
            agentServiceStatus = AgentServiceRegistration.shared.status
        }
    }

    func enableAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_ENABLE_FAILED",
            failureMessage: "无法启用后台智能体服务，请检查本机登录项权限"
        ) {
            try AgentServiceRegistration.shared.register()
        }
    }

    func disableAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_DISABLE_FAILED",
            failureMessage: "无法停用后台智能体服务"
        ) {
            try await AgentServiceRegistration.shared.unregisterAndWait()
        }
    }

    func restartAgentService() async {
        await performAgentServiceAction(
            failureCode: "AGENT_SERVICE_RESTART_FAILED",
            failureMessage: "无法重启后台智能体服务"
        ) {
            try await AgentServiceRegistration.shared.restart()
        }
    }

    func clearRevealSessions() async {
        // The Workbench keeps field-level reveal text in view-local state.
        // Broadcast only the security-state transition so every open detail
        // view clears its transient plaintext immediately.
        NotificationCenter.default.post(
            name: .vaultWorkbenchSecurityStateInvalidated,
            object: nil
        )
        RevealSessionLifecycle.clearAll()
        await uiRevealSessionStore.clearAll()
        presentedAgentSessionIDs.removeAll()
        try? await agentClient?.clearRevealSessions()
    }

    /// Clears already-presented paragraph reveal sessions after the App loses
    /// focus, without invalidating Catalog field authentication in flight.
    /// Authentication UI such as Touch ID can temporarily deactivate this App;
    /// that transient event must still close older standalone plaintext
    /// windows, but it must not broadcast the hard security invalidation that
    /// cancels a Catalog reveal waiting for its owner-authentication result.
    func clearRevealSessionsForTransientFocusLoss() async {
        RevealSessionLifecycle.clearPresentedSessionsForFocusLoss()
        await uiRevealSessionStore.clearAll()
        presentedAgentSessionIDs.removeAll()
        try? await agentClient?.clearRevealSessions()
    }

    func lockVault() async {
        try? await agentClient?.lock()
        await cancelAllSecureInputRequests()
        await clearRevealSessions()
    }

    func shutdown() async {
        // App termination is not Agent termination. launchd keeps the
        // independent SVLTAgent alive for MCP/Obsidian clients.
        readinessTask?.cancel()
        readinessTask = nil
        if let uiRequestObserver {
            DistributedNotificationCenter.default().removeObserver(uiRequestObserver)
            self.uiRequestObserver = nil
        }
        if let writeAccessObserver {
            DistributedNotificationCenter.default().removeObserver(writeAccessObserver)
            self.writeAccessObserver = nil
        }
        if let auditObserver {
            DistributedNotificationCenter.default().removeObserver(auditObserver)
            self.auditObserver = nil
        }
        if let applicationActivationObserver {
            NotificationCenter.default.removeObserver(applicationActivationObserver)
            self.applicationActivationObserver = nil
        }
        RevealSessionLifecycle.clearAll()
        await cancelAllSecureInputRequests()
        await uiRevealSessionStore.clearAll()
        presentedAgentSessionIDs.removeAll()
        // Clear only UI reveal sessions in the independent Agent; this is
        // deliberately fire-and-forget so a dead/hung Agent can never prevent
        // the GUI from terminating.
        let client = agentClient
        Task.detached {
            try? await client?.clearRevealSessions()
        }
        agentClient = nil
        started = false
    }

    private func startUIRequestObserver() {
        guard uiRequestObserver == nil else {
            return
        }
        uiRequestObserver = DistributedNotificationCenter.default().addObserver(
            forName: AgentUIRequestNotifier.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let sessionID = notification.userInfo?["sessionID"] as? String else {
                return
            }
            Task { @MainActor [weak self] in
                await self?.presentAgentRevealSession(sessionID: sessionID)
            }
        }
    }

    private func startWriteAccessObserver() {
        guard writeAccessObserver == nil else { return }
        writeAccessObserver = DistributedNotificationCenter.default().addObserver(
            forName: CatalogAgentWriteAccessRequest.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let rawID = notification.userInfo?["requestID"] as? String,
                  UUID(uuidString: rawID) != nil
            else { return }
            Task { @MainActor [weak self] in
                // Re-query the ordered queue rather than replacing the
                // request currently displayed by this notification.
                await self?.refreshPendingCatalogWriteAccessRequests()
            }
        }
    }

    private func startSecurityAuditObserver() {
        guard auditObserver == nil else { return }
        auditObserver = DistributedNotificationCenter.default().addObserver(
            forName: CatalogSecurityAuditNotifier.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.refreshAuditEntries()
            }
        }
    }

    private func startSecureInputObserver() {
        guard secureInputObserver == nil else { return }
        secureInputObserver = DistributedNotificationCenter.default().addObserver(
            forName: CatalogAgentSecureInputNotifier.notificationName,
            object: nil,
            queue: nil
        ) { [weak self] notification in
            guard let rawID = notification.userInfo?["requestID"] as? String,
                  let id = UUID(uuidString: rawID)
            else { return }
            Task { @MainActor [weak self] in
                await self?.enqueueSecureInputRequest(id: id)
            }
        }
    }

    private func refreshPendingSecureInputRequests() async {
        guard let agentClient,
              let requestIDs = try? await agentClient.pendingCatalogSecureInputRequestIDs()
        else { return }
        for id in requestIDs {
            await enqueueSecureInputRequest(id: id)
        }
    }

    private func enqueueSecureInputRequest(id: UUID) async {
        guard presentedSecureInputIDs.insert(id).inserted else { return }
        pendingSecureInputQueue.append(id)
        await presentNextSecureInputRequest()
    }

    private func presentNextSecureInputRequest() async {
        guard secureInputRequest == nil, let id = pendingSecureInputQueue.first else { return }
        pendingSecureInputQueue.removeFirst()
        guard let appControlClient else {
            presentedSecureInputIDs.remove(id)
            return
        }
        do {
            let request = try await appControlClient.catalogSecureInputRequest(id: id)
            // Lifecycle cancellation can re-enter this MainActor while the
            // AppControl fetch is suspended. Do not resurrect a Sheet for an
            // ID that was removed from the presented set in that window.
            guard presentedSecureInputIDs.contains(id) else {
                try? await appControlClient.cancelCatalogSecureInput(id: id)
                return
            }
            secureInputRequest = request
        } catch {
            presentedSecureInputIDs.remove(id)
            await presentNextSecureInputRequest()
        }
    }

    private func startApplicationActivationObserver() {
        guard applicationActivationObserver == nil else { return }
        applicationActivationObserver = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.refreshPendingCatalogWriteAccessRequests()
                await self?.refreshAuditEntries()
                await self?.refreshPendingSecureInputRequests()
            }
        }
    }

    private func refreshPendingCatalogWriteAccessRequests() async {
        guard let agentClient else {
            pendingWriteAccessQueue.replace(with: [])
            return
        }
        guard let requestIDs = try? await agentClient.pendingCatalogWriteAccessRequestIDs() else {
            // A transient IPC failure must not dismiss the request currently
            // being authenticated or make another request jump its place.
            return
        }
        pendingWriteAccessQueue.replace(with: requestIDs)
        if requestIDs.isEmpty {
            return
        }
        await authenticateNextPendingCatalogWriteAccessRequest()
    }

    private func authenticateNextPendingCatalogWriteAccessRequest() async {
        guard !isAutoAuthenticatingCatalogRequest,
              autoAuthenticatingCatalogRequestID == nil,
              let requestID = pendingWriteAccessQueue.currentID
        else {
            return
        }
        autoAuthenticatingCatalogRequestID = requestID
        await respondToCatalogWriteAccessRequest(id: requestID, approved: true)
    }

    /// After a terminal outcome for one request (approved, denied,
    /// authentication failed/cancelled, expired), clear it and surface the
    /// next pending request on a later main-queue turn instead of replacing
    /// the current banner while its response is still being processed.
    private func scheduleNextPendingCatalogWriteAccessRefresh() {
        Task { @MainActor [weak self] in
            await Task.yield()
            try? await Task.sleep(nanoseconds: 350_000_000)
            guard let self, self.autoAuthenticatingCatalogRequestID == nil else { return }
            await self.refreshPendingCatalogWriteAccessRequests()
        }
    }

    func respondToCatalogWriteAccessRequest(id: UUID, approved: Bool) async {
        guard let appControlClient else { return }
        guard !isAutoAuthenticatingCatalogRequest else { return }
        isAutoAuthenticatingCatalogRequest = true
        defer {
            isAutoAuthenticatingCatalogRequest = false
            autoAuthenticatingCatalogRequestID = nil
        }
        do {
            try await appControlClient.respondToCatalogWriteAccessRequest(id: id, approved: approved)
            catalogAgentWriteStatus = (try? await appControlClient.catalogAgentWriteStatus())
                ?? CatalogAgentWriteAuthorizationStatus(mode: .disabled)
        } catch {
            catalogAgentWriteError = approved ? "授权请求处理失败" : "已保留拒绝结果"
        }
        // Every terminal path lands here: consume exactly this one request
        // and then continue with whatever is still pending.
        pendingWriteAccessQueue.finish(id)
        scheduleNextPendingCatalogWriteAccessRefresh()
    }

    func submitSecureInput(
        request: CatalogAgentSecureInputRequest,
        selectedTargets: [CatalogSecureInputTarget],
        values: [String: String]
    ) async {
        guard let appControlClient else {
            await cancelSecureInput(id: request.id)
            return
        }
        let selectedKeys = Set(selectedTargets.filter { !$0.usesExistingValue }.map(\.fieldKey))
        let submission = CatalogSecureInputSubmission(
            selectedTargetIDs: selectedTargets.map(\.id),
            plaintextByFieldKey: values.filter { selectedKeys.contains($0.key) }
        )

        do {
            let status = try await appControlClient.submitCatalogSecureInput(
                id: request.id,
                submission: submission
            )
            if status.status == .completed {
                await refreshSensitiveCatalog()
            }
        } catch {
            try? await appControlClient.cancelCatalogSecureInput(id: request.id)
            sensitiveIndexError = catalogMutationUIError(for: error, operation: "安全输入").displayText
        }
        finishSecureInputRequest(request.id)
        await presentNextSecureInputRequest()
    }

    func cancelSecureInput(id: UUID) async {
        try? await appControlClient?.cancelCatalogSecureInput(id: id)
        finishSecureInputRequest(id)
        await presentNextSecureInputRequest()
    }

    func cancelAllSecureInputRequests() async {
        var ids = Set(pendingSecureInputQueue)
        ids.formUnion(presentedSecureInputIDs)
        if let id = secureInputRequest?.id { ids.insert(id) }
        for id in ids {
            try? await appControlClient?.cancelCatalogSecureInput(id: id)
        }
        pendingSecureInputQueue.removeAll()
        presentedSecureInputIDs.removeAll()
        secureInputRequest = nil
    }

    private func finishSecureInputRequest(_ id: UUID) {
        if secureInputRequest?.id == id { secureInputRequest = nil }
        presentedSecureInputIDs.remove(id)
        pendingSecureInputQueue.removeAll { $0 == id }
    }

    private func presentPendingRevealSessions() async {
        guard let agentClient,
              let sessionIDs = try? await agentClient.pendingRevealSessionIDs()
        else {
            return
        }
        for sessionID in sessionIDs {
            await presentAgentRevealSession(sessionID: sessionID)
        }
    }

    private func presentAgentRevealSession(sessionID: String) async {
        guard let appControlClient,
              presentedAgentSessionIDs.insert(sessionID).inserted
        else {
            return
        }
        do {
            let paragraph = try await appControlClient.revealSessionData(sessionID: sessionID)
            let localSessionID = await uiRevealSessionStore.create(resolvedParagraph: paragraph)
            await RevealSessionPresenter().present(
                sessionID: localSessionID,
                store: uiRevealSessionStore
            )
        } catch {
            presentedAgentSessionIDs.remove(sessionID)
        }
    }

    func refreshSavedReferences() async {
        guard !AgentServiceRegistration.shared.isExplicitlyDisabled else {
            savedReferences = []
            markAgentDisabled()
            return
        }
        guard let agentClient else {
            savedReferences = []
            return
        }
        do {
            savedReferences = try await agentClient.savedSecretReferences()
            if let currentStatus = try? await agentClient.workbenchStatus() {
                status = currentStatus
                agentServiceStatus = .running
            }
        } catch {
            savedReferences = []
        }
    }

    func refreshAuditEntries() async {
        guard let appControlClient else {
            let state = AuditRefreshState.reduce(
                previousEntries: auditEntries,
                activity: .unavailable
            )
            auditEntries = state.entries
            auditError = state.warning
            return
        }
        let activity: AuditActivityReadResult
        do {
            let result = try await appControlClient.catalogRecentAuditEntries(limit: 100)
            if result.diagnostics.hasIssues {
                activity = .partial(entries: result.entries, diagnostics: result.diagnostics)
            } else {
                activity = .success(result.entries)
            }
        } catch let error as VaultIPCClientError {
            switch error {
            case .endpointUnavailable, .endpointOwnershipInvalid, .endpointPermissionsInvalid,
                    .incompleteFrame, .frameTooLarge:
                activity = .unavailable
            case let .responseFailure(code)
                where code == "APP_CONTROL_UNAUTHORIZED"
                    || code == "INVALID_APP_CONTROL_TOKEN"
                    || code == "APP_CONTROL_PEER_AUTH_FAILED":
                activity = .unavailable
            case let .responseFailure(code):
                activity = .failure(code: code)
            default:
                activity = .failure(code: "AUDIT_READ_FAILED")
            }
        } catch {
            activity = .failure(code: "AUDIT_READ_FAILED")
        }

        var health: AuditHealthReadResult?
        switch activity {
        case .success, .partial:
            do {
                let value = try await appControlClient.catalogAuditHealth()
                if value == "AUDIT_APPEND_FAILED" {
                    health = .appendFailed
                } else if value == nil {
                    health = .normal
                } else {
                    health = .unknown
                }
            } catch {
                health = .failure
            }
        case .unavailable, .failure:
            break
        }

        let state = AuditRefreshState.reduce(
            previousEntries: auditEntries,
            activity: activity,
            health: health
        )
        auditEntries = state.entries
        auditError = state.warning
    }

    func refreshSensitiveCatalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法读取敏感信息目录"
            return
        }
        do {
            applyCatalogPresentationState(try await appControlClient.catalogPresentationState())
        } catch {
            // Keep the last successful projection on transient IPC failure.
            sensitiveIndexError = "无法读取敏感信息目录"
        }
    }

    private func applyCatalogPresentationState(_ state: CatalogPresentationState) {
        sensitiveIndexURL = state.selectedDocumentPath.map {
            URL(fileURLWithPath: $0).standardizedFileURL
        }
        sensitiveCatalogCanAdoptV2 = state.canAdoptV2
        sensitiveCatalogCanAdoptV3 = state.canAdoptV3
        sensitiveCatalogSnapshot = state.snapshot.map {
            SensitiveCatalogSnapshot(
                document: $0.document,
                revision: $0.revision,
                integrity: .verified
            )
        }

        switch state.validation.status {
        case .found:
            sensitiveIndexError = nil
        case .legacyCatalogUnsupported:
            sensitiveIndexError = "当前敏感信息.md 是旧版格式。SVLT 不提供自动升级，请先备份并手动转换为 Catalog v3。"
        case .integrityMissing:
            sensitiveIndexError = state.canAdoptV3
                ? "检测到合法但尚未建立本机 accepted state 的 v3 文件，请验证并接纳。"
                : "检测到合法但尚未被 SVLT 接管的 v2 文件，请验证并升级为 v3。"
        case .externalModification:
            sensitiveIndexError = "检测到目录被外部修改，已暂停使用"
        case .pendingExternalChange:
            sensitiveIndexError = "目录存在待审批的高风险外部变更，已暂停使用"
        case .invalidCatalog:
            sensitiveIndexError = "敏感信息目录校验失败，未继续使用"
        case .notFound:
            sensitiveIndexError = "已选择的敏感信息目录文件不存在"
        case .unavailable:
            sensitiveIndexError = state.selectedDocumentPath == nil
                ? nil
                : "敏感信息目录当前不可用"
        case .invalidQuery:
            sensitiveIndexError = "敏感信息目录当前不可用"
        }
    }

    func validateSensitiveCatalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法验证敏感信息目录"
            return
        }
        do {
            _ = try await appControlClient.catalogStatus()
            applyCatalogPresentationState(try await appControlClient.catalogPresentationState())
        } catch {
            sensitiveIndexError = "无法验证敏感信息目录"
        }
    }

    func adoptExternalV2Catalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法接纳目录"
            return
        }
        do {
            let result = try await appControlClient.adoptCatalogExternalV2()
            guard result.status == .found else {
                sensitiveIndexError = "v2 文件校验失败，原文件保持不变"
                return
            }
            await refreshSensitiveCatalog()
        } catch VaultIPCClientError.responseFailure("LEGACY_CATALOG_UNSUPPORTED") {
            sensitiveIndexError = "当前文件仍是旧版格式，不支持自动升级；请手动转换为 Catalog v3。"
        } catch {
            sensitiveIndexError = "v2 文件升级失败，原文件保持不变"
        }
    }

    func adoptExternalV3Catalog() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法接纳目录"
            return
        }
        do {
            let result = try await appControlClient.adoptCatalogExternalV3()
            guard result.status == .found else {
                sensitiveIndexError = "v3 文件校验失败，原文件保持不变"
                return
            }
            await refreshSensitiveCatalog()
        } catch {
            sensitiveIndexError = "v3 文件接纳失败，原文件保持不变"
        }
    }

    func approveExternalCatalogChange() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法批准目录修改"
            return
        }
        do {
            let status = try await appControlClient.catalogStatus()
            guard let pending = status.pendingExternalChange else {
                sensitiveIndexError = "目录没有可批准的待审批修改"
                return
            }
            let result = try await appControlClient.approveCatalogExternalChange(
                expectedRevision: pending.acceptedRevision,
                expectedRawSHA256: pending.rawSHA256,
                expectedSemanticSHA256: pending.semanticSHA256
            )
            if result.status == .found {
                await refreshSensitiveCatalog()
            } else {
                sensitiveIndexError = "目录外部修改尚未被接纳"
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "批准目录外部修改")
            sensitiveIndexError = uiError.displayText
        }
    }

    func createCatalogIndex(title: String) async -> CatalogMutationUIResult {
        let trimmedTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard !trimmedTitle.isEmpty else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "分组标题不能为空"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }

        func create(expectedRevision: UInt64) async throws -> CatalogWriteResult {
            try await appControlClient.catalogCreateIndex(
                title: trimmedTitle,
                expectedRevision: expectedRevision
            )
        }

        do {
            let result = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            do {
                let retry = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
                return .success(retry)
            } catch {
                let uiError = catalogMutationUIError(for: error, operation: "新增分组")
                sensitiveIndexError = uiError.displayText
                return .failure(uiError)
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "新增分组")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    func createCatalogEntry(
        indexID: String,
        title: String,
        presetID: String
    ) async -> CatalogEntryCreationResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard let preset = SensitiveCatalogEntryPreset.all.first(where: { $0.id == presetID }) else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "条目预设无效"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            let error = CatalogMutationUIError(
                code: "CATALOG_INVALID_OPERATION",
                message: "条目标题不能为空"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }

        let request = CatalogDraftRequest(
            indexID: indexID,
            title: title.trimmingCharacters(in: .whitespacesAndNewlines),
            fields: [preset.makeInitialField()]
        )

        func create(expectedRevision: UInt64) async throws -> CatalogWriteResult {
            try await appControlClient.catalogCreateEntry(request, expectedRevision: expectedRevision)
        }

        do {
            let result = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            do {
                let retry = try await create(expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0)
                await refreshSensitiveCatalog()
                sensitiveIndexError = nil
                return .success(retry)
            } catch {
                let uiError = catalogMutationUIError(for: error, operation: "新增条目")
                sensitiveIndexError = uiError.displayText
                return .failure(uiError)
            }
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "新增条目")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    private func catalogMutationUIError(for error: Error, operation: String) -> CatalogMutationUIError {
        let code: String
        if let error = error as? VaultIPCClientError {
            switch error {
            case .responseFailure(let responseCode):
                code = responseCode
            case .endpointUnavailable, .endpointOwnershipInvalid, .endpointPermissionsInvalid:
                code = "APP_CONTROL_UNAVAILABLE"
            default:
                code = "APP_CONTROL_REQUEST_FAILED"
            }
        } else {
            code = "APP_CONTROL_REQUEST_FAILED"
        }

        let message: String
        switch code {
        case "CATALOG_REVISION_CONFLICT":
            message = "目录刚被其他本机客户端更新，自动重试后仍冲突"
        case "CATALOG_UNAVAILABLE":
            message = "敏感信息目录当前不可用"
        case "CATALOG_INVALID":
            message = "目录数据无效；请检查字段 key、类型和值"
        case "CATALOG_INVALID_OPERATION":
            message = "目录中不存在对应分组或条目，或操作参数无效"
        case "CATALOG_WRITE_FAILED":
            message = "目录写入失败；原目录内容未被安全提交，请稍后重试"
        case "EXTERNAL_CATALOG_MODIFICATION":
            message = "检测到目录被外部修改，已暂停写入"
        case "PENDING_EXTERNAL_CHANGE":
            message = "目录有待审批的高风险外部修改"
        case "APP_CONTROL_UNAUTHORIZED", "INVALID_APP_CONTROL_TOKEN":
            message = "本机控制服务身份校验失败"
        case "APP_CONTROL_UNAVAILABLE":
            message = "本机控制服务不可用"
        case "CATALOG_AGENT_WRITE_NOT_ALLOWED":
            message = "智能体的安全目录编辑已关闭"
        case "CATALOG_APPROVAL_REQUIRED":
            message = "此目录变更需要本机批准"
        case "CATALOG_CLEANUP_REQUIRED":
            message = "目录保存失败；有新的加密记录待清理，请稍后执行清理或孤儿扫描"
        case "CATALOG_OPERATION_DENIED":
            message = "此目录变更被本机策略拒绝"
        case "CATALOG_AUTHORIZATION_CANCELLED":
            message = "本机批准已取消"
        case "CATALOG_AUTHORIZATION_DENIED":
            message = "本机批准被拒绝"
        case "CATALOG_AUTHORIZATION_TIMEOUT":
            message = "本机批准已超时"
        case "CATALOG_AUTHORIZATION_UNAVAILABLE":
            message = "本机批准服务不可用"
        default:
            message = "\(operation)失败"
        }
        return CatalogMutationUIError(code: code, message: message)
    }

    func commitCatalogEntryEdit(
        entry: SecretCatalogEntry,
        secretInputs: [CatalogSecretInput]
    ) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(
                code: "APP_CONTROL_UNAVAILABLE",
                message: "本机控制服务不可用"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogCommitEntryEdit(
                entry,
                secretInputs: secretInputs,
                expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            let error = CatalogMutationUIError(
                code: "CATALOG_REVISION_CONFLICT",
                message: "目录已被其他本机客户端更新，请刷新后重试"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_APPROVAL_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_APPROVAL_REQUIRED",
                message: "此字段安全变化需要本机批准"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch {
            let error = catalogMutationUIError(for: error, operation: "保存条目")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
    }

    func revealCatalogField(entryID: String, key: String) async throws -> String {
        guard let appControlClient else {
            throw AgentSecretVaultRuntimeError.notStarted
        }
        return try await appControlClient.catalogRevealField(entryID: entryID, key: key)
    }

    func replaceCatalogSecret(
        entryID: String,
        key: String,
        label: String,
        plaintext: String
    ) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(code: "APP_CONTROL_UNAVAILABLE", message: "本机控制服务不可用")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogSecureInput(
                entryID: entryID,
                key: key,
                label: label,
                plaintext: plaintext,
                policy: .credential
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(CatalogWriteResult(
                revision: result.revision,
                secretReference: result.reference
            ))
        } catch VaultIPCClientError.responseFailure("CATALOG_CLEANUP_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_CLEANUP_REQUIRED",
                message: "替换失败；新的加密记录未能自动清理，请稍后执行孤儿扫描"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            await refreshSensitiveCatalog()
            let error = CatalogMutationUIError(
                code: "CATALOG_REVISION_CONFLICT",
                message: "目录已被其他本机客户端更新，请刷新后重试"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch VaultIPCClientError.responseFailure("CATALOG_APPROVAL_REQUIRED") {
            let error = CatalogMutationUIError(
                code: "CATALOG_APPROVAL_REQUIRED",
                message: "替换密码需要本机批准"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch {
            let error = catalogMutationUIError(for: error, operation: "替换密码")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
    }

    func applyCatalogBatch(_ mutation: CatalogBatchMutation) async -> CatalogMutationUIResult {
        guard let appControlClient else {
            let error = CatalogMutationUIError(code: "APP_CONTROL_UNAVAILABLE", message: "本机控制服务不可用")
            sensitiveIndexError = error.displayText
            return .failure(error)
        }
        do {
            let result = try await appControlClient.catalogApplyBatch(
                mutation,
                expectedRevision: sensitiveCatalogSnapshot?.revision ?? 0
            )
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
            return .success(result)
        } catch VaultIPCClientError.responseFailure("CATALOG_REVISION_CONFLICT") {
            // Destructive batch operations are never replayed on a newer
            // revision. Refresh the authoritative snapshot, keep the UI's
            // still-existing selections, and require a fresh confirmation.
            await refreshSensitiveCatalog()
            let error = CatalogMutationUIError(
                code: "CATALOG_REVISION_CONFLICT",
                message: "目录已被其他本机客户端更新，已刷新；请重新确认删除"
            )
            sensitiveIndexError = error.displayText
            return .failure(error)
        } catch {
            let uiError = catalogMutationUIError(for: error, operation: "保存批量修改")
            sensitiveIndexError = uiError.displayText
            return .failure(uiError)
        }
    }

    func enableCatalogAgentWrite(mode: CatalogAgentWriteMode) async {
        guard let appControlClient else { return }
        do {
            catalogAgentWriteStatus = try await appControlClient.setCatalogAgentWriteMode(mode: mode)
            catalogAgentWriteError = nil
        } catch {
            catalogAgentWriteError = "无法启用智能体目录编辑权限"
        }
    }

    func revokeCatalogAgentWrite() async {
        guard let appControlClient else { return }
        do {
            try await appControlClient.revokeCatalogAgentWrite()
            catalogAgentWriteStatus = CatalogAgentWriteAuthorizationStatus(mode: .disabled)
            catalogAgentWriteError = nil
        } catch {
            catalogAgentWriteError = "无法撤销智能体目录编辑权限"
        }
    }

    func checkSensitiveCatalogFormat() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法检查格式"
            return
        }
        do {
            formatRepairPlan = try await appControlClient.catalogFormatRepairPlan()
            sensitiveIndexError = nil
        } catch {
            formatRepairPlan = nil
            sensitiveIndexError = "敏感信息目录格式检查失败"
        }
    }

    func repairSensitiveCatalogFormat() async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法修复格式"
            return
        }
        guard let plan = formatRepairPlan, plan.canRepair else {
            sensitiveIndexError = "当前格式没有可安全修复的问题"
            return
        }
        do {
            let result = try await appControlClient.repairCatalogFormat(expectedRawSHA256: plan.currentRawSHA256)
            guard result.status == .found else {
                sensitiveIndexError = "格式修复未完成"
                return
            }
            formatRepairPlan = nil
            await refreshSensitiveCatalog()
            sensitiveIndexError = nil
        } catch {
            sensitiveIndexError = "格式修复失败或文件已发生变化，请重新检查"
            await checkSensitiveCatalogFormat()
        }
    }

    func chooseSensitiveIndex() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText, .plainText]
        panel.message = "选择集中维护的敏感信息.md"
        panel.prompt = "选择"

        guard panel.runModal() == .OK, let url = panel.url else {
            return
        }
        Task { await activateSensitiveIndex(at: url) }
    }

    func showSensitiveCatalogTemplate() async {
        do {
            let url = try catalogTemplateStore.ensureInstalled()
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            sensitiveIndexError = "无法打开敏感信息模板"
        }
    }

    private func activateSensitiveIndex(at url: URL) async {
        guard let appControlClient else {
            sensitiveIndexError = "本机控制服务不可用，无法切换敏感信息目录"
            return
        }
        do {
            let state = try await appControlClient.selectCatalogDocument(path: url.path)
            applyCatalogPresentationState(state)
            await refreshSavedReferences()
        } catch {
            sensitiveIndexError = "所选文件不是有效的敏感信息.md"
        }
    }

}

private enum AgentSecretVaultRuntimeError: Error {
    case notStarted
}

@MainActor
final class AgentSecretVaultAppDelegate: NSObject, NSApplicationDelegate {
    private var terminationInProgress = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            await AgentSecretVaultRuntimeStore.shared.start()
        }
    }

    func applicationShouldSaveApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldRestoreApplicationState(_ app: NSApplication) -> Bool {
        false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    func requestMenuBarTermination() async {
        NSApp.terminate(nil)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard !terminationInProgress else {
            return .terminateLater
        }

        terminationInProgress = true
        Task { @MainActor in
            await AgentSecretVaultRuntimeStore.shared.shutdown()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
