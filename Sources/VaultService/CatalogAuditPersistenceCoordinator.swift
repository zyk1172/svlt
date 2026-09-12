import CryptoKit
import Foundation
import os
import VaultCore
import VaultIPC

/// Owns encrypted audit persistence, its non-sensitive sticky health
/// sidecar, bounded App-control reads, and path-free failure signaling.
/// Business services provide the semantic audit entry and caller context;
/// this actor owns only durable audit-channel mechanics.
actor CatalogAuditPersistenceCoordinator {
    private let auditLog: EncryptedAuditLog?
    private let fallbackMasterKey: SymmetricKey?
    private let now: @Sendable () -> Date
    private var healthStore: CatalogAuditHealthStore

    init(
        auditLog: EncryptedAuditLog?,
        auditHealthURL: URL?,
        fallbackMasterKey: SymmetricKey?,
        now: @escaping @Sendable () -> Date
    ) {
        self.auditLog = auditLog
        self.fallbackMasterKey = fallbackMasterKey
        self.now = now
        self.healthStore = CatalogAuditHealthStore(url: auditHealthURL)
    }

    func healthSignal() -> String? {
        healthStore.healthSignal
    }

    func recentCatalogEntries(limit: Int) async throws -> CatalogRecentAuditResult {
        guard let auditLog else {
            return CatalogRecentAuditResult(entries: [])
        }
        let readResult = try await auditLog.recentWithDiagnostics(
            limit: min(max(limit, 1), 100)
        )
        return CatalogRecentAuditResult(
            entries: readResult.events.map(Self.safeAuditEntry),
            diagnostics: readResult.diagnostics
        )
    }

    func append(
        entry: AgentAutomationAuditEntry,
        context: AuditContext,
        operation: AuditOperation?,
        authorizationOutcome: AuditAuthorizationOutcome,
        authorizationMode: AuditAuthorizationMode?,
        status: AuditStatus?
    ) async {
        guard let auditLog else { return }
        let event = AuditEvent(
            timestamp: entry.occurredAt,
            source: context.source,
            integration: context.source == .app
                ? "agent-secret-vault-app-control"
                : "agent-secret-vault-mcp",
            correlationID: context.correlationID,
            requestID: context.requestID,
            referenceID: nil,
            referenceCount: entry.referenceCount,
            operation: operation ?? Self.auditOperation(for: entry.action),
            risk: 0,
            authorizationOutcome: authorizationOutcome,
            declaredTarget: Self.safeAuditTarget(entry.target),
            status: status ?? Self.auditStatus(for: entry.result),
            exitCode: nil,
            authorizationMode: authorizationMode,
            caller: context.caller
        )

        do {
            // The production daemon supplies an independent Keychain
            // audit key. Never acquire a vault key merely for audit.
            try await auditLog.append(event)
            recordAppendSuccess()
        } catch {
            guard let fallbackMasterKey else {
                recordAppendFailure()
                return
            }
            do {
                // Explicit test callers may already hold a master key.
                try await auditLog.append(event, masterKey: fallbackMasterKey)
                recordAppendSuccess()
            } catch {
                recordAppendFailure()
            }
        }
    }

    private func recordAppendSuccess() {
        healthStore.recordAppendSuccess()
        CatalogSecurityAuditNotifier.notify()
    }

    private func recordAppendFailure() {
        healthStore.recordAppendFailure(at: now())
        Self.logAuditAppendFailure()
    }

    private static func logAuditAppendFailure() {
        Logger(subsystem: "com.agent-secret-vault.SVLT", category: "audit")
            .error("AUDIT_APPEND_FAILED")
    }

    private static func auditOperation(for action: String) -> AuditOperation {
        if action.contains("格式") {
            return action.contains("修复") ? .formatRepair : .formatCheck
        }
        if action.contains("目录") || action.contains("分组") || action.contains("条目") {
            return .catalogMutation
        }
        if action.contains("凭据") || action.contains("密码") {
            return .credentialUse
        }
        if action.contains("显示") || action.contains("脱密") || action.contains("文件") {
            return .reveal
        }
        if action.contains("扫描") || action.contains("连接") || action.contains("元数据") {
            return .status
        }
        return .secureExecute
    }

    private static func auditStatus(for result: String) -> AuditStatus {
        if result.contains("显示") {
            return .displayedToUser
        }
        if result.contains("失败") {
            return .failure
        }
        return .completed
    }

    private static func safeAuditEntry(_ event: AuditEvent) -> CatalogSecurityAuditEntry {
        CatalogSecurityAuditEntry(
            id: event.id,
            timestamp: event.timestamp,
            source: event.source,
            operation: event.operation,
            authorizationOutcome: event.authorizationOutcome,
            result: event.status,
            target: safeAuditTarget(event.declaredTarget),
            referenceCount: event.referenceCount,
            authorizationMode: event.authorizationMode,
            caller: event.caller
        )
    }

    private static func safeAuditTarget(_ target: String?) -> String {
        guard let target, !target.isEmpty else { return "本机" }
        let normalized = target
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let lowercased = normalized.lowercased()
        if lowercased.contains("secret://") || lowercased.contains("token") ||
            lowercased.contains("password") || lowercased.contains("cookie") ||
            lowercased.contains("authorization") || normalized.contains("密码") {
            return "敏感记录"
        }
        if normalized.contains("/") || normalized.contains("\\") ||
            lowercased.contains("http") || lowercased.contains("api") {
            return "受保护目标"
        }
        return String(normalized.prefix(80))
    }
}
