import Foundation
import VaultCore
import VaultAuthorization

struct CatalogWriteAccessAuditEvent: Sendable {
    let action: String
    let result: String
    let context: AuditContext
    let authorizationOutcome: AuditAuthorizationOutcome
    let status: AuditStatus?
}

/// Owns the request lifecycle for one operation-bound Catalog write grant.
/// The service remains the facade for audit persistence and device-owner
/// approval, while this actor keeps continuations, timeout state, and grant
/// consumption serialized together.
actor CatalogWriteAccessCoordinator {
    private let authorization: CatalogAgentWriteAuthorization
    private let approver: @Sendable (String) async throws -> Void
    private let notifier: CatalogAgentWriteAccessNotifier
    private let now: @Sendable () -> Date
    private let emitAudit: @Sendable (CatalogWriteAccessAuditEvent) async -> Void
    private var lifecycle = CatalogWriteAccessLifecycle()

    init(
        authorization: CatalogAgentWriteAuthorization,
        approver: @escaping @Sendable (String) async throws -> Void,
        notifier: CatalogAgentWriteAccessNotifier,
        now: @escaping @Sendable () -> Date,
        emitAudit: @escaping @Sendable (CatalogWriteAccessAuditEvent) async -> Void
    ) {
        self.authorization = authorization
        self.approver = approver
        self.notifier = notifier
        self.now = now
        self.emitAudit = emitAudit
    }

    func setMode(
        _ mode: CatalogAgentWriteMode,
        duration: TimeInterval?
    ) async throws -> CatalogAgentWriteAuthorizationStatus {
        if mode == .disabled {
            await authorization.revoke()
            return await authorization.status()
        }
        _ = duration
        throw SecretCatalogAgentError.agentWriteNotAllowed
    }

    func revoke() async {
        await authorization.revoke()
    }

    func status() async -> CatalogAgentWriteAuthorizationStatus {
        await authorization.status()
    }

    func requestAuthorization(
        _ intent: CatalogAgentWriteIntent,
        reasonCategory: CatalogAgentWriteReasonCategory
    ) async throws -> AuditContext {
        let requestID = UUID()
        let callerContext = AuditContext.current ?? AuditContext(source: .agent)
        let operationContext = callerContext.withRequestID(requestID)
        let createdAt = now()
        let expiry = createdAt.addingTimeInterval(CatalogAgentWriteAuthorization.ticketLifetime)
        let request = CatalogAgentWriteAccessRequest(
            id: requestID,
            source: .mcpClient,
            reasonCategory: reasonCategory,
            duration: .singleUse,
            createdAt: ISO8601DateFormatter().string(from: createdAt),
            intent: intent.bound(to: requestID),
            expiresAt: ISO8601DateFormatter().string(from: expiry),
            verifiedSource: nil
        )
        let continuationBox = lifecycle.insert(request, auditContext: operationContext)
        await audit(
            action: "智能体目录写入授权请求",
            result: "请求中",
            context: operationContext,
            authorizationOutcome: .requested,
            status: .requested
        )

        var timeoutTask: Task<Void, Never>?
        defer {
            timeoutTask?.cancel()
            lifecycle.cleanup(id: request.id)
        }
        do {
            try await withTaskCancellationHandler(operation: {
                try await withCheckedThrowingContinuation { continuation in
                    continuationBox.store(continuation)
                    timeoutTask = Task { [weak self] in
                        try? await Task.sleep(for: .seconds(CatalogAgentWriteAuthorization.ticketLifetime))
                        guard !Task.isCancelled else { return }
                        await self?.expire(id: request.id)
                    }
                    notifier.present(request)
                }
            }, onCancel: { [weak self] in
                Task { await self?.cancel(id: request.id) }
            })
            guard let boundIntent = lifecycle.intent(for: request.id) else {
                throw SecretCatalogAgentError.agentWriteNotAllowed
            }
            try await authorization.consume(requestID: request.id, intent: boundIntent)
            lifecycle.markConsumed(id: request.id)
        } catch {
            await authorization.revoke(requestID: request.id)
            if error is CancellationError {
                lifecycle.markCancelled(id: request.id)
                await audit(
                    action: "智能体目录写入授权取消",
                    result: "已取消",
                    context: operationContext,
                    authorizationOutcome: .cancelled,
                    status: .cancelled
                )
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            if lifecycle.state(for: request.id) == .expired {
                await audit(
                    action: "智能体目录写入授权超时",
                    result: "已超时",
                    context: operationContext,
                    authorizationOutcome: .expired,
                    status: .expired
                )
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            await audit(
                action: "智能体目录写入授权失败",
                result: "失败",
                context: operationContext,
                authorizationOutcome: .denied,
                status: .failure
            )
            if error is VaultAppServicesRevealError || error is OperationAuthorizationError {
                throw SecretCatalogAgentError.agentWriteApprovalUnavailable
            }
            throw error
        }
        return operationContext
    }

    func pendingRequest(id: UUID) throws -> CatalogAgentWriteAccessRequest {
        guard let request = lifecycle.pendingRequest(id: id) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        return request
    }

    func pendingRequestIDs() -> [UUID] {
        lifecycle.pendingRequestIDs
    }

    func respond(id: UUID, approved: Bool) async throws {
        guard let snapshot = lifecycle.responseSnapshot(id: id) else {
            throw SecretCatalogAgentError.invalidOperation
        }
        let request = snapshot.request
        let continuation = snapshot.continuation
        let originalContext = snapshot.auditContext
        let approvalContext = AuditContext(
            source: .app,
            correlationID: originalContext?.correlationID ?? AuditContext.current?.correlationID ?? UUID(),
            requestID: id
        )
        guard approved else {
            lifecycle.markDenied(id: id)
            continuation.resume(throwing: SecretCatalogAgentError.agentWriteNotAllowed)
            await audit(
                action: "智能体目录写入授权拒绝",
                result: "已拒绝",
                context: approvalContext,
                authorizationOutcome: .denied,
                status: .failure
            )
            return
        }

        _ = lifecycle.markAuthenticating(id: id)
        do {
            try await approver(approvalSummary(for: request))
            guard lifecycle.state(for: id) == .authenticating,
                  let intent = request.intent
            else {
                throw OperationAuthorizationError.cancelled
            }
            _ = await authorization.approve(requestID: id, intent: intent)
            lifecycle.markApproved(id: id)
            continuation.resume()
            await audit(
                action: "智能体目录写入授权完成",
                result: "成功",
                context: approvalContext,
                authorizationOutcome: .approved,
                status: nil
            )
        } catch let error as OperationAuthorizationError {
            lifecycle.markDenied(id: id)
            await authorization.revoke(requestID: id)
            continuation.resume(throwing: error)
            let outcome: AuditAuthorizationOutcome = error == .cancelled ? .cancelled : (error == .timeout ? .expired : .denied)
            let result = error == .cancelled ? "已取消" : (error == .timeout ? "已超时" : "已拒绝")
            let auditStatus: AuditStatus = error == .cancelled ? .cancelled : (error == .timeout ? .expired : .failure)
            await audit(
                action: "智能体目录写入授权结束",
                result: result,
                context: approvalContext,
                authorizationOutcome: outcome,
                status: auditStatus
            )
            throw SecretCatalogAgentError.agentWriteApprovalUnavailable
        } catch {
            lifecycle.markDenied(id: id)
            await authorization.revoke(requestID: id)
            continuation.resume(throwing: SecretCatalogAgentError.agentWriteApprovalUnavailable)
            await audit(
                action: "智能体目录写入授权失败",
                result: "失败",
                context: approvalContext,
                authorizationOutcome: .denied,
                status: .failure
            )
            throw SecretCatalogAgentError.agentWriteApprovalUnavailable
        }
    }

    private func approvalSummary(for request: CatalogAgentWriteAccessRequest) -> String {
        let operation = request.intent?.operation.rawValue ?? "unknown-operation"
        return "SVLT 需要本机身份认证来完成一次目录操作：\(operation)"
    }

    private func expire(id: UUID) {
        guard let continuation = lifecycle.markExpiredIfActive(id: id) else { return }
        Task { await authorization.revoke(requestID: id) }
        notifier.notifyQueueChanged(requestID: id)
        continuation.resume(throwing: VaultAppServicesRevealError.revealUnavailable)
    }

    private func cancel(id: UUID) {
        guard let continuation = lifecycle.markCancelledIfActive(id: id) else { return }
        Task { await authorization.revoke(requestID: id) }
        notifier.notifyQueueChanged(requestID: id)
        continuation.resume(throwing: CancellationError())
    }

    private func audit(
        action: String,
        result: String,
        context: AuditContext,
        authorizationOutcome: AuditAuthorizationOutcome,
        status: AuditStatus?
    ) async {
        await emitAudit(
            CatalogWriteAccessAuditEvent(
                action: action,
                result: result,
                context: context,
                authorizationOutcome: authorizationOutcome,
                status: status
            )
        )
    }
}
