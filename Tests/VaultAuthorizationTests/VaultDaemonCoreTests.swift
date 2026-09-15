import Foundation
import Testing
import VaultExecution
import VaultIPC
@testable import VaultService

@Test func daemonConfigurationKeepsCredentialAndExternalSendTTLs() {
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: URL(filePath: "/tmp/svlt-config-vault"),
        auditRootURL: URL(filePath: "/tmp/svlt-config-audit"),
        ipcConfiguration: UnixSocketServerConfiguration(
            directoryURL: URL(filePath: "/tmp/svlt-config-ipc")
        ),
        credentialAuthorizationTTL: 600,
        externalSendAuthorizationTTL: 60
    )
    #expect(configuration.credentialAuthorizationTTL == 600)
    #expect(configuration.externalSendAuthorizationTTL == 60)
}

@Test func daemonConfigurationCarriesOnlyAppOwnedHTTPProjectionProfiles() {
    let profile = HTTPResponseProjectionProfile(
        id: "status-profile",
        origin: "https://qnap.local",
        allowedMethods: [.get],
        path: "/status",
        allowedJSONPointers: ["/status"]
    )
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: URL(filePath: "/tmp/svlt-config-vault"),
        auditRootURL: URL(filePath: "/tmp/svlt-config-audit"),
        ipcConfiguration: UnixSocketServerConfiguration(
            directoryURL: URL(filePath: "/tmp/svlt-config-ipc")
        ),
        httpResponseProjectionProfiles: [profile]
    )

    #expect(configuration.httpResponseProjectionProfiles == [profile])
}

@Test func daemonStartsWithIPCAvailableButVaultLockedWithoutEagerAuthentication() async throws {
    let root = URL(filePath: "/tmp/svlt-vault-\(UUID().uuidString)")
    let audit = URL(filePath: "/tmp/svlt-audit-\(UUID().uuidString)")
    let ipc = URL(filePath: "/tmp/svlt-ipc-\(UUID().uuidString)")
    let configuration = VaultDaemonConfiguration(
        vaultRootURL: root.appending(path: "vault"),
        auditRootURL: audit,
        ipcConfiguration: UnixSocketServerConfiguration(directoryURL: ipc)
    )
    defer {
        try? FileManager.default.removeItem(at: root)
        try? FileManager.default.removeItem(at: audit)
        try? FileManager.default.removeItem(at: ipc)
    }

    let daemon = try VaultDaemonCore(configuration: configuration)
    try await daemon.start()

    let status = await daemon.status()
    #expect(status.ipcAvailable)
    #expect(status.locked)
    #expect(FileManager.default.fileExists(atPath: configuration.ipcConfiguration.socketURL.path))
    #expect(FileManager.default.fileExists(atPath: configuration.ipcConfiguration.tokenURL.path))

    await daemon.stop()
    #expect(!FileManager.default.fileExists(atPath: configuration.ipcConfiguration.socketURL.path))
}

@Test func agentExecutableSourceDoesNotImportGUIFrameworksOrUseUnlockAtStartup() throws {
    let sourceURL = URL(filePath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appending(path: "Sources/SVLTAgent/SVLTAgent.swift")
    let source = try String(contentsOf: sourceURL, encoding: .utf8)

    #expect(!source.contains("SwiftUI"))
    #expect(!source.contains("AppKit"))
    #expect(!source.contains("unlockLowProtection"))
    #expect(source.contains("withCheckedContinuation"))
}
