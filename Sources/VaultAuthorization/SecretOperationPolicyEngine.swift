import Foundation
import VaultCore

/// SVLT uses intent-first authorization. The main Agent is the default
/// semantic decision-maker for ordinary user-aligned work. Deterministic
/// policy remains authoritative only for malformed/identity-invalid requests,
/// explicit Secret plaintext exposure, and a small set of genuinely
/// destructive high-impact operations. An independent judge is called by the
/// MCP boundary only for semantic gray zones and arrives here as a structured
/// `AgentRiskAssessment` with `source == .independentJudge`.
public struct SecretOperationPolicyEngine: Sendable {
    public struct Configuration: Sendable {
        public let maxCommandLength: Int
        public let safeDownloadDirectory: URL

        public init(
            maxCommandLength: Int = 65_536,
            safeDownloadDirectory: URL? = nil
        ) {
            self.maxCommandLength = maxCommandLength
            self.safeDownloadDirectory = (safeDownloadDirectory
                ?? FileManager.default.homeDirectoryForCurrentUser
                    .appendingPathComponent("Library/Application Support/AgentSecretVault/Downloads", isDirectory: true))
                .standardizedFileURL
        }
    }

    private let configuration: Configuration
    private let sshCommandClassifier: SSHCommandRiskClassifier
    private let databaseStatementClassifier: DatabaseStatementClassifier

    public init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
        self.sshCommandClassifier = SSHCommandRiskClassifier(maxCommandLength: configuration.maxCommandLength)
        self.databaseStatementClassifier = DatabaseStatementClassifier(maximumLength: configuration.maxCommandLength)
    }

    /// Returns the non-secret operation family used by a reusable database
    /// authorization scope. Read-only statements deliberately share one
    /// family so a normal multi-query workflow does not prompt for every
    /// SELECT; ordinary writes and maintenance statements remain separated by
    /// their narrower family. Fresh/unknown statements never receive a lease.
    public func databaseAuthorizationScopeFamily(for statement: String?) -> String {
        guard let statement else { return "database.fresh.unknown" }
        return databaseStatementClassifier.classify(statement).scopeFamily
    }

    public func semanticPreflight(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata]
    ) -> SecretOperationPreflight {
        let normalizedDestination = descriptor.normalizedDestination
        let local = localDecision(
  descriptor,
  metadata: metadata,
  normalizedDestination: normalizedDestination
        )
        if local.authorizationRequirement == .denied || local.technicalFailure {
  return SecretOperationPreflight(
      route: .denied,
      policyRuleID: local.policyRuleID,
      authorizationRequirement: .denied,
      blastRadius: .unknown,
      reasons: local.reasons,
      technicalFailure: true
  )
        }

        let semantic = descriptor.agentAssessment
        let blastRadius = Self.blastRadius(for: semantic, ruleID: local.policyRuleID)
        if local.authorizationRequirement == .freshApprovalRequired,
 Self.isNonDowngradableFreshRule(local.policyRuleID) {
  return SecretOperationPreflight(
      route: .hard,
      policyRuleID: local.policyRuleID,
      authorizationRequirement: .freshApprovalRequired,
      blastRadius: blastRadius,
      reasons: local.reasons
  )
        }
        if semantic.executionRecommendation == .freshApproval {
  return SecretOperationPreflight(
      route: .hard,
      policyRuleID: local.policyRuleID,
      authorizationRequirement: .freshApprovalRequired,
      blastRadius: blastRadius,
      reasons: local.reasons + ["Main Agent already requests fresh approval"]
  )
        }

        let binding = bindingDecision(
  descriptor,
  metadata: metadata,
  normalizedDestination: normalizedDestination
        )
        let semanticUnresolved = semantic.executionRecommendation == .uncertain
  || semantic.intentAlignment == .unclear
  || semantic.intentAlignment == .unrelated
  || semantic.effectSeverity == .unknown
  || semantic.reversibility == .unknown
  || semantic.secretHandling == .unknown
        let semanticConflict = semantic.executionRecommendation == .automatic
  && Self.automaticRecommendationNeedsReview(semantic)
        let localConflict = semantic.executionRecommendation == .automatic
  && Self.isSemanticGrayRule(local.policyRuleID)
        let scopeConflict = semantic.executionRecommendation == .automatic
  && !binding.reasons.isEmpty
        let opaqueExecution = Self.looksSemanticallyOpaque(descriptor)

        if semanticUnresolved || semanticConflict || localConflict || scopeConflict || opaqueExecution {
  var reasons = local.reasons
  if semanticUnresolved { reasons.append("语义字段仍有未决项") }
  if semanticConflict { reasons.append("主模型 automatic 建议与高影响语义冲突") }
  if localConflict { reasons.append("本地分类器检测到需要独立语义复核的操作族") }
  if scopeConflict { reasons.append("凭据执行目标或协议超出既有绑定范围") }
  if opaqueExecution { reasons.append("操作包含动态或不透明执行") }
  return SecretOperationPreflight(
      route: .gray,
      policyRuleID: local.policyRuleID,
      authorizationRequirement: .freshApprovalRequired,
      blastRadius: blastRadius,
      reasons: reasons
  )
        }

        return SecretOperationPreflight(
  route: .fast,
  policyRuleID: local.policyRuleID,
  authorizationRequirement: Self.normalizedSemanticRequirement(semantic),
  blastRadius: blastRadius,
  reasons: local.reasons
        )
    }

    public func evaluate(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata]
    ) -> PolicyDecision {
        let normalizedDestination = descriptor.normalizedDestination
        let local = localDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination
        )

        var effectiveRequirement = local.authorizationRequirement
        var reasons = local.reasons
        let semantic = descriptor.agentAssessment
        let semanticParticipated = local.authorizationRequirement != .denied
            && !local.technicalFailure
            && !descriptor.secretReferences.isEmpty

        if semanticParticipated {
            if local.authorizationRequirement == .freshApprovalRequired,
               Self.isNonDowngradableFreshRule(local.policyRuleID) {
                effectiveRequirement = .freshApprovalRequired
            } else {
                effectiveRequirement = semantic.executionRecommendation.authorizationRequirement
            }

            reasons.append(
                "语义判断（\(semantic.source.rawValue)）：目标 \(semantic.intentAlignment.rawValue)，影响 \(semantic.effectSeverity.rawValue)，可逆性 \(semantic.reversibility.rawValue)，Secret \(semantic.secretHandling.rawValue)，建议 \(semantic.executionRecommendation.rawValue)，置信度 \(String(format: "%.2f", semantic.confidence))"
            )
            if !semantic.reason.isEmpty {
                reasons.append("语义原因：\(semantic.reason)")
            }
        }

        let effectiveRisk: OperationRisk = {
            switch effectiveRequirement {
            case .none: return .silent
            case .reusableApproval, .freshApprovalRequired: return .approvalRequired
            case .denied: return .denied
            }
        }()

        return PolicyDecision(
            risk: effectiveRisk,
            reasons: reasons.map(Self.sanitizeReason),
            normalizedDestination: normalizedDestination,
            requiredApproval: effectiveRequirement.requiresApproval,
            policyRuleID: semanticParticipated
                ? "\(local.policyRuleID)+intent-first"
                : local.policyRuleID,
            authorizationRequirement: effectiveRequirement,
            requiresFreshApprovalOnFirstUse: false,
            technicalFailure: local.technicalFailure
        )
    }

    private func localDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        normalizedDestination: String?
    ) -> PolicyDecision {
        if let invalidShape = invalidOperationShape(descriptor) {
            return decision(.denied, [invalidShape.reason], invalidShape.ruleID, normalizedDestination, technicalFailure: true)
        }

        let localRisk: OperationRisk
        let localRequirement: AuthorizationRequirement
        var reasons: [String]
        let ruleID: String

        switch descriptor.actionType {
        case .vaultStatus, .usagePolicy, .inspectReference, .checkReferenceExists:
            return decision(.silent, ["状态或非敏感元数据操作"], "metadata.silent", normalizedDestination)
        case .revealPlaintext, .copyPlaintext, .exportPlaintext,
             .deleteSecret, .changeSecretPolicy, .changeDestinationBinding,
             .changeAllowlist, .changeAuthorizationRules, .changeKeychain,
             .migrateMasterKey, .importRecoveryKey, .exportRecoveryKey,
             .restoreVault, .clearVault, .batchDelete, .resetVault:
            localRisk = .approvalRequired
            reasons = ["明文暴露、数据删除或安全设置变更，每次都需要设备所有者重新认证"]
            ruleID = "sensitive-control.fresh-approval"
            localRequirement = .freshApprovalRequired
        case .sshCommand:
            let commandDecision = descriptor.sshCommandBatch == nil
                ? sshCommandClassifier.classify(command: descriptor.command)
                : sshCommandClassifier.classify(batch: descriptor.sshCommandBatch)
            localRisk = commandDecision.risk
            reasons = commandDecision.reasons
            ruleID = commandDecision.ruleID
            localRequirement = commandDecision.authorizationRequirement
        case .httpRequest, .apiRequest:
            let httpOutcome = httpDecision(descriptor)
            localRisk = httpOutcome.risk
            reasons = httpOutcome.reasons
            ruleID = httpOutcome.ruleID
            localRequirement = httpOutcome.requirement
        case .databaseQuery:
            let databaseOutcome = databaseDecision(descriptor.effectiveDatabaseStatement)
            localRisk = databaseOutcome.risk
            reasons = databaseOutcome.reasons
            ruleID = databaseOutcome.ruleID
            localRequirement = databaseOutcome.requirement
        case .sftpTransfer:
            let transferOutcome = sftpDecision(descriptor)
            localRisk = transferOutcome.risk
            reasons = transferOutcome.reasons
            ruleID = transferOutcome.ruleID
            localRequirement = transferOutcome.requirement
        case .ftpTransfer:
            let transferOutcome = ftpDecision()
            localRisk = transferOutcome.risk
            reasons = transferOutcome.reasons
            ruleID = transferOutcome.ruleID
            localRequirement = transferOutcome.requirement
        case .browserLogin, .localAppFill:
            localRisk = .approvalRequired
            reasons = ["浏览器/本地 App 填充属于普通 Secret 操作；独立风险裁判可在低风险时建议自动执行"]
            ruleID = "bound-login.reusable-approval"
            localRequirement = .reusableApproval
        case .localExecution:
            localRisk = .approvalRequired
            reasons = [
                "⚠️ 此操作会把凭据交给本地任意进程；该进程可能读取、保存、转换或传输凭据",
                "批准后 SVLT 无法保证 Agent 不获得该凭据；本次释放会被审计记录为 userApprovedSecretRelease"
            ]
            ruleID = "local-execution.fresh.arbitrary-secret-release"
            localRequirement = .freshApprovalRequired
        case .trustedProcess:
            localRisk = .approvalRequired
            reasons = ["Trusted Process 会把 Secret 交给预先登记的签名进程；独立风险裁判只能在确定性规则允许时降低普通审批"]
            ruleID = "trusted-process.reusable-approval"
            localRequirement = .reusableApproval
        }

        if localRisk == .denied || localRequirement == .denied {
            return decision(
                .denied,
                reasons,
                ruleID,
                normalizedDestination,
                technicalFailure: true
            )
        }

        let binding = bindingDecision(
            descriptor,
            metadata: metadata,
            normalizedDestination: normalizedDestination
        )
        let effectiveRequirement = localRequirement
        if binding.requirement == .denied {
            return decision(
                .denied,
                reasons + binding.reasons,
                binding.ruleID,
                normalizedDestination,
                technicalFailure: true
            )
        }
        let effectiveRisk: OperationRisk = {
            switch effectiveRequirement {
            case .none: return .silent
            case .reusableApproval, .freshApprovalRequired: return .approvalRequired
            case .denied: return .denied
            }
        }()
        return decision(
            effectiveRisk,
            reasons + binding.reasons,
            ruleID,
            normalizedDestination,
            authorizationRequirement: effectiveRequirement
        )
    }

    private func invalidOperationShape(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        guard Set(descriptor.secretReferences).count == descriptor.secretReferences.count else {
            return ("操作不能重复使用同一个 secret:// 引用", "secret-reference.duplicate")
        }
        if let port = descriptor.port, !(1...65_535).contains(port) {
            return ("端口不在有效范围内", "operation.port.invalid")
        }

        if let payloadError = invalidTypedPayload(descriptor) {
            return payloadError
        }
        if let referenceError = invalidExecutionReferenceSet(descriptor) {
            return referenceError
        }

        switch descriptor.actionType {
        case .sshCommand:
            guard descriptor.protocolType == .ssh else {
                return ("SSH 操作必须声明 ssh 协议", "ssh.protocol.invalid")
            }
            guard !(descriptor.command != nil && descriptor.sshCommandBatch != nil) else {
                return ("SSH 操作不能同时提供单条命令和批处理", "ssh.command-forms.ambiguous")
            }
            if let batch = descriptor.sshCommandBatch {
                guard (try? batch.validate()) != nil else {
                    return ("SSH 批处理参数无效", "ssh.batch.invalid")
                }
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("SSH 操作缺少目标主机", "ssh.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "ssh.port-mismatch")
            }
        case .httpRequest, .apiRequest:
            guard let rawURL = descriptor.url,
                  let url = URL(string: rawURL),
                  let scheme = url.scheme?.lowercased(),
                  let host = url.host,
                  !host.isEmpty,
                  scheme == "http" || scheme == "https" else {
                return ("HTTP 操作缺少有效目标 URL", "http.url.invalid")
            }
            let expectedProtocol: SecretOperationProtocol = scheme == "https" ? .https : .http
            guard descriptor.protocolType == expectedProtocol else {
                return ("操作协议与 URL scheme 不一致", "http.protocol-mismatch")
            }
            let effectivePort = url.port ?? (scheme == "https" ? 443 : 80)
            if let declaredPort = descriptor.port, declaredPort != effectivePort {
                return ("操作端口与 URL 实际端口不一致", "http.port-mismatch")
            }
            let actualDestination = SecretOperationDescriptor.normalizeDestination(rawURL)
            if let destination = descriptor.destination,
               SecretOperationDescriptor.normalizeDestination(destination) != actualDestination {
                return ("操作目标与 URL 主机不一致", "http.destination-mismatch")
            }
        case .browserLogin:
            guard descriptor.protocolType == .browser,
                  let rawURL = descriptor.url,
                  let url = URL(string: rawURL),
                  let scheme = url.scheme?.lowercased(),
                  let host = url.host,
                  !host.isEmpty,
                  scheme == "http" || scheme == "https",
                  url.user == nil,
                  url.password == nil else {
                return ("浏览器登录目标无效", "browser.url.invalid")
            }
        case .databaseQuery:
            guard descriptor.protocolType == .postgres || descriptor.protocolType == .mysql else {
                return ("数据库操作必须声明 postgres 或 mysql 协议", "database.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("数据库操作缺少目标主机", "database.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "database.port-mismatch")
            }
        case .sftpTransfer:
            guard descriptor.protocolType == .sftp || descriptor.protocolType == .scp else {
                return ("文件传输必须声明 sftp 或 scp 协议", "sftp.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("文件传输缺少目标主机", "sftp.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "sftp.port-mismatch")
            }
        case .ftpTransfer:
            guard descriptor.protocolType == .ftp else {
                return ("文件传输必须声明 ftp 协议", "ftp.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("文件传输缺少目标主机", "ftp.destination.missing")
            }
            if let destinationPort = explicitPort(in: destination),
               let declaredPort = descriptor.port,
               destinationPort != declaredPort {
                return ("操作端口与目标主机端口不一致", "ftp.port-mismatch")
            }
        case .localAppFill:
            guard descriptor.protocolType == .localApp else {
                return ("本地 App 填充必须声明 localApp 协议", "local-app.protocol.invalid")
            }
            guard let destination = descriptor.destination,
                  !destination.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                return ("本地 App 填充缺少目标", "local-app.destination.missing")
            }
        default:
            break
        }

        return nil
    }

    private func invalidTypedPayload(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        guard let payload = descriptor.payload else { return nil }

        guard referencesMatch(
            payload.referencedSecretReferences,
            descriptor.secretReferences
        ) else {
            return ("typed payload 使用了未声明的 secret:// 引用", "operation.payload.reference-mismatch")
        }

        switch payload {
        case let .http(operation):
            guard (descriptor.actionType == .httpRequest || descriptor.actionType == .apiRequest),
                  descriptor.httpMethod == nil || descriptor.httpMethod?.uppercased() == operation.method.rawValue
            else {
                return ("HTTP payload 只能用于 HTTP/API 操作", "operation.payload.action-mismatch")
            }
        case let .database(operation):
            guard descriptor.actionType == .databaseQuery,
                  descriptor.protocolType == operation.engine,
                  !operation.database.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil),
                  descriptor.databaseStatement == nil || descriptor.databaseStatement == operation.statement,
                  (1...10_000).contains(operation.maxRows)
            else {
                return ("数据库 typed payload 与操作声明不一致", "database.payload.invalid")
            }
            guard operation.parameters.count <= 64,
                  operation.parameters.allSatisfy({ parameter in
                      !parameter.name.isEmpty
                          && parameter.name.utf8.count <= 128
                          && parameter.name.unicodeScalars.allSatisfy { $0.value >= 0x20 && $0.value != 0x7F }
                  }),
                  Set(operation.parameters.map(\.name)).count == operation.parameters.count else {
                return ("数据库参数定义无效", "database.parameters.invalid")
            }
        case let .fileTransfer(operation):
            let actionMatches = (descriptor.actionType == .sftpTransfer
                && (operation.protocolType == .sftp || operation.protocolType == .scp))
                || (descriptor.actionType == .ftpTransfer && operation.protocolType == .ftp)
            guard actionMatches,
                  descriptor.protocolType == operation.protocolType,
                  !operation.remotePath.isEmpty,
                  operation.remotePath.utf8.count <= 4_096,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil),
                  descriptor.fileOperation == nil || descriptor.fileOperation == operation.operation,
                  descriptor.fileTarget == nil || descriptor.fileTarget == operation.localPath
            else {
                return ("文件传输 typed payload 与操作声明不一致", "file-transfer.payload.invalid")
            }
        case let .browser(operation):
            guard descriptor.actionType == .browserLogin,
                  descriptor.protocolType == .browser,
                  let payloadURL = operation.url,
                  !payloadURL.isEmpty,
                  descriptor.url == payloadURL,
                  operation.passwordReference != nil,
                  (operation.username != nil) != (operation.usernameReference != nil)
            else {
                return ("浏览器登录 typed payload 无效", "browser.payload.invalid")
            }
        case let .localApp(operation):
            guard descriptor.actionType == .localAppFill,
                  descriptor.protocolType == .localApp,
                  !operation.bundleID.isEmpty,
                  operation.fields.count <= 64,
                  descriptor.localAppBundleID == nil || descriptor.localAppBundleID == operation.bundleID,
                  operation.fields.allSatisfy({ field in
                      (field.value != nil) != (field.valueReference != nil)
                          && !field.name.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F }
                  })
            else {
                return ("本地 App typed payload 无效", "local-app.payload.invalid")
            }
        case let .export(operation):
            guard descriptor.actionType == .exportPlaintext, !operation.overwrite else {
                return ("导出 typed payload 不允许覆盖目标文件", "export.payload.invalid")
            }
        case let .trustedProcess(operation):
            guard descriptor.actionType == .trustedProcess,
                  !operation.profileID.isEmpty,
                  operation.profileID.utf8.count <= 128,
                  operation.arguments.count <= 32,
                  !operation.profileID.contains("secret://"),
                  operation.profileID.unicodeScalars.allSatisfy(Self.isSafeProcessMetadataScalar),
                  operation.arguments.allSatisfy({ argument in
                      argument.utf8.count <= 4_096
                          && !argument.contains("secret://")
                          && argument.unicodeScalars.allSatisfy(Self.isSafeProcessMetadataScalar)
                  })
            else {
                return ("trusted process typed payload 无效", "trusted-process.payload.invalid")
            }
        case let .localExecution(operation):
            guard descriptor.actionType == .localExecution,
                  !operation.executable.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  operation.executable.utf8.count <= 4_096,
                  operation.arguments.count <= 32,
                  !operation.executable.contains("secret://"),
                  operation.executable.unicodeScalars.allSatisfy(Self.isSafeProcessMetadataScalar),
                  operation.arguments.allSatisfy({ argument in
                      argument.utf8.count <= 4_096
                          && !argument.contains("secret://")
                          && argument.unicodeScalars.allSatisfy(Self.isSafeProcessMetadataScalar)
                  })
            else {
                return ("local execution typed payload 无效", "local-execution.payload.invalid")
            }
        }

        return nil
    }

    private func invalidExecutionReferenceSet(
        _ descriptor: SecretOperationDescriptor
    ) -> (reason: String, ruleID: String)? {
        guard descriptor.payload == nil else { return nil }

        var executionReferences: [SecretReference] = []
        for rawValue in descriptor.parameters.values where rawValue.hasPrefix("secret://") {
            guard let reference = try? SecretReference(rawValue) else {
                return ("执行参数包含无效的 secret:// 引用", "operation.reference.invalid")
            }
            executionReferences.append(reference)
        }

        guard !executionReferences.isEmpty else { return nil }

        guard referencesMatch(executionReferences, descriptor.secretReferences) else {
            return (
                "执行参数中的 secret:// 引用必须与操作声明完全一致",
                "operation.reference-mismatch"
            )
        }
        return nil
    }

    private func bindingDecision(
        _ descriptor: SecretOperationDescriptor,
        metadata: [SecretPolicyMetadata],
        normalizedDestination: String?
    ) -> (requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard actionNeedsSecret(descriptor.actionType) else {
            return (.none, [], "no-secret.required")
        }

        guard !descriptor.secretReferences.isEmpty else {
            return (.denied, ["需要 Secret 的操作没有提供 secret:// 引用"], "secret-reference.missing")
        }

        var metadataByReference: [SecretReference: SecretPolicyMetadata] = [:]
        for item in metadata {
            guard metadataByReference[item.reference] == nil else {
                return (.denied, ["Secret 元数据包含重复引用，无法确认凭据身份"], "secret-metadata.duplicate")
            }
            metadataByReference[item.reference] = item
        }

        var reasons: [String] = []
        for reference in descriptor.secretReferences {
            guard let secret = metadataByReference[reference] else {
                return (.denied, ["Secret 元数据缺失，无法确认凭据身份"], "secret-metadata.missing")
            }

            if let protocolType = descriptor.protocolType,
               !secret.allowedProtocols.isEmpty,
               !isAllowedProtocol(protocolType, for: descriptor, allowedProtocols: secret.allowedProtocols) {
                reasons.append(
                    "提示：凭据未绑定当前协议（已保存：\(secret.allowedProtocols.joined(separator: "/"))；本次：\(protocolType.rawValue)）；本次审批进入新的执行 scope"
                )
            }

            if !isAllowedSecretPolicy(secret.policy, action: descriptor.actionType) {
                reasons.append(
                    "提示：凭据被用户标记为 \(secret.policy.rawValue)；本次副作用由设备所有者在审批中确认"
                )
            }

            guard let normalizedDestination else {
                continue
            }

            let bindingProtocol: SecretOperationProtocol? = {
                if descriptor.protocolType == .browser,
                   let scheme = descriptor.url.flatMap({ URL(string: $0)?.scheme?.lowercased() }) {
                    return SecretOperationProtocol(rawValue: scheme)
                }
                return descriptor.protocolType
            }()
            let exactBinding = bindingProtocol.map { requestedProtocol in
                secret.destinationBindings.contains {
                    $0.matches(
                        requestedProtocol: requestedProtocol,
                        destination: descriptor.destination,
                        url: descriptor.url,
                        port: descriptor.port
                    )
                }
            } ?? false
            if exactBinding {
                continue
            }

            reasons.append("提示：目标 \(normalizedDestination) 不在该凭据已保存的绑定中；本次审批进入新的执行 scope")
        }

        return (.none, reasons, "destination.bound")
    }

    public enum HTTPFreshRules {
        public static let delete = "http.fresh.delete"
        public static let insecureSecretTransport = "http.fresh.insecure-secret-transport"
        public static let credentialInURL = "http.fresh.credential-in-url"
        public static let secretNetworkSend = "http.fresh.secret-network-send"
        public static let explicitSecretRelease = "http.fresh.explicit-secret-release"

        public static let all: [String] = [
            delete,
            insecureSecretTransport,
            credentialInURL,
            secretNetworkSend,
            explicitSecretRelease
        ]
    }

    private func httpDecision(
        _ descriptor: SecretOperationDescriptor
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard let url = descriptor.url,
              let parsedURL = URL(string: url),
              parsedURL.user == nil,
              parsedURL.password == nil,
              parsedURL.host != nil,
              (parsedURL.scheme?.lowercased() == "http" || parsedURL.scheme?.lowercased() == "https")
        else {
            return (.denied, .denied, ["HTTP URL 无效或包含 URL 内嵌凭据"], "http.url.invalid")
        }

        let carriesSecret = !descriptor.secretReferences.isEmpty

        if hasCredentialQueryParameter(parsedURL) {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["URL query 携带凭据类参数，可能被记录在服务器日志或代理中；设备所有者确认后执行"],
                HTTPFreshRules.credentialInURL
            )
        }

        if parsedURL.scheme?.lowercased() == "http", carriesSecret {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["目标使用未加密 HTTP，凭据可能以明文在网络中传输；设备所有者确认后执行"],
                HTTPFreshRules.insecureSecretTransport
            )
        }

        let method = (descriptor.effectiveHTTPMethod ?? "GET").uppercased()
        if method == "DELETE" {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["HTTP DELETE 可能删除远端资源，每次都需要设备所有者重新认证"],
                HTTPFreshRules.delete
            )
        }

        if carriesSecret {
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["Secret 将离开本机发送到 HTTP(S) 目标；没有独立风险裁判时维持每次审批，裁判确认低风险后可按本次实际操作放宽"],
                HTTPFreshRules.secretNetworkSend
            )
        }

        return (
            .approvalRequired,
            .reusableApproval,
            ["HTTP 请求属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
            "http.ordinary.reusable-approval"
        )
    }

    public enum DatabaseFreshRules {
        public static let destructiveWrite = "database.fresh.destructive-write"
        public static let destructiveStructure = "database.fresh.destructive-structure"
        public static let privilegeAccountAdmin = "database.fresh.privilege-account-admin"
        public static let dynamicExecution = "database.fresh.dynamic-execution"
        public static let unknown = "database.fresh.unknown"

        public static let all: [String] = [
            destructiveWrite,
            destructiveStructure,
            privilegeAccountAdmin,
            dynamicExecution,
            unknown
        ]
    }

    private func databaseDecision(
        _ query: String?
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        guard let query, !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return (.denied, .denied, ["数据库查询为空"], "database.query.missing")
        }
        let classification = databaseStatementClassifier.classify(query)
        return (
            .approvalRequired,
            classification.requirement,
            [classification.reason],
            classification.ruleID
        )
    }

    public enum SFTPFreshRules {
        public static let delete = "sftp.fresh.delete"
        public static let overwriteExisting = "sftp.fresh.overwrite-existing"
        public static let replaceExistingTarget = "sftp.fresh.replace-existing-target"

        public static let all: [String] = [
            delete,
            overwriteExisting,
            replaceExistingTarget
        ]
    }

    private func sftpDecision(
        _ descriptor: SecretOperationDescriptor
    ) -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        switch descriptor.effectiveFileOperation {
        case .delete:
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["SFTP 删除远端数据，每次都需要设备所有者重新认证"],
                SFTPFreshRules.delete
            )
        case .overwrite:
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["SFTP 覆盖远端已有数据，每次都需要设备所有者重新认证"],
                SFTPFreshRules.overwriteExisting
            )
        case .write:
            return (
                .approvalRequired,
                .freshApprovalRequired,
                ["SFTP 写入会替换目标内容，每次都需要设备所有者重新认证"],
                SFTPFreshRules.replaceExistingTarget
            )
        case .list, .read, .download, .upload, .move, .none:
            return (
                .approvalRequired,
                .reusableApproval,
                ["SFTP/SCP 操作属于普通操作，首次需要本机审批，之后可在执行窗口内复用"],
                "sftp.ordinary.reusable-approval"
            )
        }
    }

    private enum FTPFreshRules {
        static let plaintextTransport = "ftp.fresh.plaintext-transport"
    }

    private func ftpDecision() -> (risk: OperationRisk, requirement: AuthorizationRequirement, reasons: [String], ruleID: String) {
        (
            .approvalRequired,
            .freshApprovalRequired,
            ["FTP 会以明文传输凭据，仅允许回环或私有地址，并且每次都需要设备所有者重新认证"],
            FTPFreshRules.plaintextTransport
        )
    }

    private func actionNeedsSecret(_ action: SecretOperationAction) -> Bool {
        switch action {
        case .vaultStatus, .usagePolicy, .inspectReference, .checkReferenceExists,
             .deleteSecret, .changeSecretPolicy, .changeDestinationBinding,
             .changeAllowlist, .changeAuthorizationRules, .changeKeychain,
             .migrateMasterKey, .importRecoveryKey, .exportRecoveryKey,
             .restoreVault, .clearVault, .batchDelete, .resetVault:
            return false
        default:
            return true
        }
    }

    private func isAllowedSecretPolicy(_ policy: SecretPolicy, action: SecretOperationAction) -> Bool {
        switch action {
        case .sshCommand, .httpRequest, .apiRequest, .databaseQuery, .sftpTransfer, .ftpTransfer,
             .browserLogin, .localAppFill, .localExecution, .trustedProcess:
            return policy == .credential || policy == .externalSend
        default:
            return true
        }
    }

    private func isAllowedProtocol(
        _ protocolType: SecretOperationProtocol,
        for descriptor: SecretOperationDescriptor,
        allowedProtocols: [String]
    ) -> Bool {
        if allowedProtocols.contains(where: { $0.lowercased() == protocolType.rawValue.lowercased() }) {
            return true
        }
        if protocolType == .http,
           allowedProtocols.contains(where: { $0.lowercased() == "http-loopback" }) {
            return true
        }
        guard descriptor.actionType == .browserLogin,
              let url = descriptor.url,
              let scheme = URL(string: url)?.scheme?.lowercased() else {
            return false
        }
        return allowedProtocols.contains(where: { $0.lowercased() == scheme })
    }

    private func explicitPort(in destination: String) -> Int? {
        let trimmed = destination.trimmingCharacters(in: .whitespacesAndNewlines)
        if let url = URL(string: trimmed), url.scheme != nil {
            return url.port
        }
        return URL(string: "//\(trimmed)")?.port
    }

    private func hasCredentialQueryParameter(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return true
        }
        return components.queryItems?.contains { item in
            item.name.range(of: #"(?i)password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie"#, options: .regularExpression) != nil
        } == true
    }

    private static func isSafeProcessMetadataScalar(_ scalar: UnicodeScalar) -> Bool {
        scalar.value >= 0x20 && scalar.value != 0x7F && scalar.value != 0
    }

    private func referencesMatch(_ lhs: [SecretReference], _ rhs: [SecretReference]) -> Bool {
        lhs.count == rhs.count
            && Set(lhs).count == lhs.count
            && Set(rhs).count == rhs.count
            && Set(lhs) == Set(rhs)
    }

    private func decision(
        _ risk: OperationRisk,
        _ reasons: [String],
        _ ruleID: String,
        _ destination: String?,
        authorizationRequirement: AuthorizationRequirement? = nil,
        technicalFailure: Bool = false
    ) -> PolicyDecision {
        PolicyDecision(
            risk: risk,
            reasons: reasons,
            normalizedDestination: destination,
            requiredApproval: (authorizationRequirement ?? risk.authorizationRequirement).requiresApproval,
            policyRuleID: ruleID,
            authorizationRequirement: authorizationRequirement,
            requiresFreshApprovalOnFirstUse: false,
            technicalFailure: technicalFailure
        )
    }

    private static func isNonDowngradableFreshRule(_ ruleID: String) -> Bool {
        if ruleID == "sensitive-control.fresh-approval"
            || ruleID == "local-execution.fresh.arbitrary-secret-release"
            || ruleID == FTPFreshRules.plaintextTransport {
            return true
        }
        if [
            SSHFreshRules.powerControl,
            SSHFreshRules.blockDeviceFilesystem,
            SSHFreshRules.storageRaidDestruction
        ].contains(ruleID) {
            return true
        }
        if [
            HTTPFreshRules.insecureSecretTransport,
            HTTPFreshRules.credentialInURL,
            HTTPFreshRules.explicitSecretRelease
        ].contains(ruleID) {
            return true
        }
        if [
            DatabaseFreshRules.destructiveStructure,
            DatabaseFreshRules.privilegeAccountAdmin
        ].contains(ruleID) {
            return true
        }
        return false
    }

    private static func sanitizeReason(_ reason: String) -> String {
        String(reason.replacingOccurrences(of: "\n", with: " ").prefix(240))
    }
}
