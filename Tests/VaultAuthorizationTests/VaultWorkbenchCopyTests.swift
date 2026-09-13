import Testing
import Foundation
@testable import AgentSecretVaultApp

@Test func workbenchCopyDoesNotPretendDisconnectedToolsAreReady() {
    let copy = VaultWorkbenchCopy.disconnected
    #expect(copy.primaryAction.contains("安装"))
    #expect(copy.primaryAction.contains("Obsidian 插件"))
    #expect(copy.status == "Obsidian 插件未连接")
}

@Test func workbenchCopyDescribesFieldLevelRevealAfterDeviceAuthentication() {
    let boundary = VaultWorkbenchCopy.securityBoundary
    #expect(boundary.contains("已加密"))
    #expect(boundary.contains("解密"))
    #expect(boundary.contains("本机授权"))
    #expect(!boundary.contains("段落"))
}

@Test func workbenchCopyProvidesExternalDocumentationLink() {
    #expect(VaultWorkbenchCopy.documentationURL.absoluteString == "https://github.com/zyk1172/svlt")
}

@Test func workbenchCopyProvidesCopyableMcpConfigAndPrompt() {
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"SVLT\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"command\": \"/bin/zsh\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("\"-lc\""))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js"))
    #expect(VaultWorkbenchCopy.mcpConfig.contains("Library/Application Support/AgentSecretVault/MCP/dist/server.js"))
    #expect(!VaultWorkbenchCopy.mcpConfig.contains("/Users/zhengyunkai/"))
    #expect(VaultWorkbenchCopy.agentPrompt.contains("secret://"))
    #expect(VaultWorkbenchCopy.agentPrompt.contains("不受 SVLT 强制接管"))
    #expect(VaultWorkbenchCopy.agentPrompt.contains("USER_EXPLICIT_PLAINTEXT"))
    #expect(!VaultWorkbenchCopy.agentPrompt.localizedLowercase.contains("qnap"))
}

@Test func workbenchCopyExposesTheManagedCatalogPolicyAndSchema() {
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("## 表示分组，### 表示条目"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("secret_catalog_validate"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("SVLT v3"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("三种写入路径"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("Agent 不能自行开启权限"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("policy block"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("SVLT 是 opt-in"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("USER_EXPLICIT_PLAINTEXT"))
    #expect(VaultWorkbenchCopy.catalogPolicy.contains("不得把 SVLT 解密得到的明文"))
    #expect(VaultWorkbenchCopy.catalogSchema.contains("secretRef"))
    #expect(VaultWorkbenchCopy.catalogSchema.contains("empty placeholder or opaque secretRef"))
    #expect(!VaultWorkbenchCopy.catalogPolicy.contains("ASV_CANARY"))
    #expect(!VaultWorkbenchCopy.catalogSchema.contains("secret://012345"))
}

@Test func workbenchHidesLocalScanFromNormalNavigation() {
    #expect(VaultWorkbenchSection.allCases.map(\.rawValue) == ["overview", "secrets", "automation", "tutorial", "faq"])
}

@Test func primaryWorkbenchCopyAvoidsBilingualSeparators() {
    let visibleCopy = [
        VaultWorkbenchCopy.disconnected.status,
        VaultWorkbenchCopy.disconnected.primaryAction,
        VaultWorkbenchCopy.securityBoundary
    ]

    for text in visibleCopy {
        #expect(!text.contains(" · "))
        #expect(!text.contains("Temporary reveal"))
        #expect(!text.contains("Workbench"))
    }
}

@Test func workbenchProvidesMenuSectionsForMajorTasks() {
    let titles = VaultWorkbenchSection.allCases.map(\.title)

    #expect(titles == [
        "控制台",
        "敏感信息",
        "智能体自动化",
        "使用教程",
        "常见问题"
    ])
    #expect(VaultWorkbenchSection.secrets.subtitle.contains("分组目录"))
    #expect(VaultWorkbenchSection.allCases.allSatisfy { !$0.systemImage.isEmpty })
}

@Test func workbenchShowsMarkdownSensitiveIndexWithoutPlaintext() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("SensitiveIndexLibraryCard("))
    #expect(!source.contains("sensitiveIndexEntries"))
    #expect(source.contains("独立加密记录"))
    #expect(source.contains("复制可用段落"))
    #expect(source.contains("尚未设置敏感信息目录"))
    #expect(!source.contains("需要查看空白模板时，请前往“安全边界”页面"))
    #expect(source.contains("LazyVGrid"))
    #expect(source.contains("SensitiveCatalogGroupSheet"))
    #expect(source.contains("GitHubMark"))
    #expect(source.contains(".regularMaterial"))
    #expect(source.contains("LinearGradient("))
    #expect(source.contains("RadialGradient("))
    #expect(source.contains("VStack(alignment: .leading, spacing: 8)"))
    #expect(source.contains(".font(.body.weight(isSelected ? .semibold : .regular))"))
    #expect(source.contains(".padding(.vertical, 10)"))
    #expect(source.contains(".frame(minHeight: 42)"))
    #expect(source.contains("Color.indigo.opacity(0.22)"))
    #expect(source.contains("Color.cyan.opacity(0.20)"))
    #expect(source.contains(".allowsHitTesting(false)"))
    #expect(!source.contains(".navigationTitle(selectedSection.title)"))
    #expect(source.contains("接纳外部 v3 文件"))
    #expect(source.contains("验证并接纳"))
    #expect(source.contains("检查格式"))
    #expect(source.contains("修复格式"))
    #expect(source.contains("查看敏感信息模板"))
    #expect(source.contains("prepareIndexDeletion(for: index, snapshot: snapshot)"))
    #expect(!source.contains("@State private var writeAccessRequest"))
    #expect(!source.contains(".alert(item: $writeAccessRequest)"))
    #expect(!source.contains("transaction.animation = nil"))
    #expect(source.contains(".transition("))
    #expect(source.contains(".offset(x: 6)"))
    #expect(source.contains("Color.cyan.opacity(0.42)"))
    #expect(!source.contains("CatalogCardPalette"))
    #expect(source.contains("为什么智能体每次修改目录都要授权？"))
    #expect(source.contains(".font(.headline.weight(.semibold))"))
    #expect(source.contains(".font(.callout)"))
    #expect(source.contains("暂无活动"))
    #expect(!source.contains("LocalSensitiveScanCard"))
    #expect(!source.contains("记录维护"))
    #expect(!source.contains("恢复到版本"))
    #expect(source.contains("revealCatalogField"))
    #expect(source.contains("GridItem(.flexible(minimum: 0, maximum: .infinity)"))
    #expect(!source.contains("允许普通目录修改"))
    #expect(!source.contains("SensitiveCatalogPolicyCard"))
}

@Test func overviewKeepsStatusProminentAndCompact() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("OverviewStatusStrip(status: status)"))
    #expect(source.contains("CompactAuditPreviewCard(entries: auditEntries, errorMessage: auditError)"))
    #expect(source.contains("ScrollView(.vertical, showsIndicators: true)"))
    #expect(!source.contains("HeroCard("))
}

@Test func workbenchUsesStableRenderingForBetaMacOSCompatibility() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(VaultWorkbenchRenderingPolicy.usesStableRendering)
    #expect(!VaultWorkbenchRenderingPolicy.usesRepeatingAnimations)
    #expect(!VaultWorkbenchRenderingPolicy.usesBlurredBackgrounds)
    #expect(VaultWorkbenchRenderingPolicy.usesMaterialBackgrounds)
    #expect(VaultWorkbenchRenderingPolicy.usesTransientAnimations)
    #expect(source.contains("VaultWorkbenchMotion.interactive"))
    #expect(source.contains("withAnimation(VaultWorkbenchMotion.interactive)"))
    #expect(source.contains(".animation(reduceMotion ? nil : VaultWorkbenchMotion.interactive, value: isHovering)"))
}

@Test func agentAuthenticationUsesSingleDeviceOwnerConsumerWithoutApprovalBanner() throws {
    let runtimeURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    let runtime = try String(contentsOf: runtimeURL, encoding: .utf8)
    let workbenchURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let workbench = try String(contentsOf: workbenchURL, encoding: .utf8)

    #expect(!runtime.contains("PendingWriteAccessBanner"))
    #expect(!workbench.contains("PendingWriteAccessBanner"))
    #expect(!workbench.contains("验证并授权"))
    #expect(runtime.contains("autoAuthenticatingCatalogRequestID"))
    #expect(runtime.contains("guard !isAutoAuthenticatingCatalogRequest"))
    #expect(runtime.contains("pendingWriteAccessQueue.currentID"))
    #expect(runtime.contains(".defaultSize(width: 1280, height: 820)"))
}

@Test func agentSecureInputUsesLocalSheetAndScrollOwners() throws {
    let runtimeURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift")
    let runtime = try String(contentsOf: runtimeURL, encoding: .utf8)
    let workbenchURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift")
    let workbench = try String(contentsOf: workbenchURL, encoding: .utf8)

    #expect(runtime.contains("refreshPendingSecureInputRequests"))
    #expect(runtime.contains("catalogCommitEntryEdit"))
    #expect(workbench.contains("CatalogAgentSecureInputSheet"))
    #expect(workbench.contains("SecureField(\"敏感值\""))
    #expect(workbench.contains("加密并写入"))
    #expect(workbench.contains("显示密码"))
    #expect(workbench.contains("隐藏密码"))
    #expect(workbench.contains("ScrollView(.vertical, showsIndicators: true)"))
    #expect(!workbench.contains("private struct WorkbenchPage<Content: View>: View {\n    var body: some View {\n        ScrollView"))
}

@Test func numericTelemetryCompatibilityDoesNotInstallGlobalRuntimeHooks() throws {
    let sourceURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("Sources/AgentSecretVaultApp/Compatibility/MetalTelemetryCompatibility.m")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(source.contains("workaround has been retired"))
    #expect(!source.contains("#import <objc/runtime.h>"))
    #expect(!source.contains("class_addMethod"))
    #expect(!source.contains("__attribute__((constructor))"))
}
