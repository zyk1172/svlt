from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, text: str) -> None:
    Path(path).write_text(text)


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise SystemExit(f"{path}: marker not found: {old[:160]!r}")
    write(path, text.replace(old, new, 1))


def insert_before(path: str, marker: str, addition: str) -> None:
    text = read(path)
    if marker not in text:
        raise SystemExit(f"{path}: insertion marker not found: {marker[:160]!r}")
    write(path, text.replace(marker, addition + marker, 1))


# ---------------------------------------------------------------------------
# Swift policy: daemon owns FAST/HARD/GRAY/DENIED routing and final invariants.
# ---------------------------------------------------------------------------
path = "Sources/VaultAuthorization/SecretOperationPolicyEngine.swift"
text = read(path)
start = text.index("    public func semanticPreflight(")
end = text.index("    public func evaluate(", start)
preflight = '''    public func semanticPreflight(
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

'''
text = text[:start] + preflight + text[end:]
old_merge = '''            if local.authorizationRequirement == .freshApprovalRequired,
               Self.isNonDowngradableFreshRule(local.policyRuleID) {
                effectiveRequirement = .freshApprovalRequired
            } else {
                effectiveRequirement = semantic.executionRecommendation.authorizationRequirement
            }'''
new_merge = '''            let preflight = semanticPreflight(descriptor, metadata: metadata)
            if local.authorizationRequirement == .freshApprovalRequired,
               Self.isNonDowngradableFreshRule(local.policyRuleID) {
                effectiveRequirement = .freshApprovalRequired
            } else if preflight.route == .gray,
                      semantic.source == .mainAgent,
                      semantic.executionRecommendation == .automatic {
                // A main-Agent automatic recommendation cannot bypass a
                // daemon-owned gray signal. The independent judge must first
                // replace it with source == .independentJudge.
                effectiveRequirement = .freshApprovalRequired
            } else {
                effectiveRequirement = Self.normalizedSemanticRequirement(semantic)
            }'''
if old_merge not in text:
    raise SystemExit("policy evaluate merge marker missing")
text = text.replace(old_merge, new_merge, 1)
helper_marker = "    private static func isNonDowngradableFreshRule(_ ruleID: String) -> Bool {"
if "private static func normalizedSemanticRequirement" not in text:
    helpers = '''    private static func normalizedSemanticRequirement(
        _ assessment: AgentRiskAssessment
    ) -> AuthorizationRequirement {
        if assessment.executionRecommendation == .automatic,
           automaticRecommendationNeedsReview(assessment) {
            return .freshApprovalRequired
        }
        return assessment.executionRecommendation.authorizationRequirement
    }

    private static func automaticRecommendationNeedsReview(_ assessment: AgentRiskAssessment) -> Bool {
        assessment.intentAlignment == .unclear
            || assessment.intentAlignment == .unrelated
            || assessment.effectSeverity == .broad
            || assessment.effectSeverity == .systemic
            || assessment.effectSeverity == .unknown
            || assessment.reversibility == .difficult
            || assessment.reversibility == .irreversible
            || assessment.reversibility == .unknown
            || assessment.secretHandling == .thirdPartyExposure
            || assessment.secretHandling == .plaintextSecretExposure
            || assessment.secretHandling == .unknown
    }

    private static func isSemanticGrayRule(_ ruleID: String) -> Bool {
        [
            SSHFreshRules.filesystemDelete,
            SSHFreshRules.containerDestruction,
            HTTPFreshRules.delete,
            DatabaseFreshRules.destructiveWrite,
            DatabaseFreshRules.dynamicExecution,
            DatabaseFreshRules.unknown,
            SFTPFreshRules.delete,
            SFTPFreshRules.overwriteExisting,
            SFTPFreshRules.replaceExistingTarget
        ].contains(ruleID)
    }

    private static func blastRadius(
        for assessment: AgentRiskAssessment,
        ruleID: String
    ) -> SecretOperationPreflight.BlastRadius {
        if [
            SSHFreshRules.powerControl,
            SSHFreshRules.blockDeviceFilesystem,
            SSHFreshRules.storageRaidDestruction
        ].contains(ruleID) {
            return .systemic
        }
        if [
            DatabaseFreshRules.destructiveStructure,
            DatabaseFreshRules.privilegeAccountAdmin
        ].contains(ruleID) {
            return .broad
        }
        if isSemanticGrayRule(ruleID) {
            switch assessment.effectSeverity {
            case .systemic: return .systemic
            case .broad: return .broad
            default: return .unknown
            }
        }
        switch assessment.effectSeverity {
        case .none: return .none
        case .minor: return .tiny
        case .bounded: return .bounded
        case .broad: return .broad
        case .systemic: return .systemic
        case .unknown: return .unknown
        }
    }

    private static func looksSemanticallyOpaque(_ descriptor: SecretOperationDescriptor) -> Bool {
        let components: [String] = [descriptor.command, descriptor.databaseStatement].compactMap { $0 }
            + (descriptor.sshCommandBatch?.commands.flatMap { [$0.executable] + $0.arguments } ?? [])
        let text = components.joined(separator: "\\n").lowercased()
        guard !text.isEmpty else { return false }
        if text.contains("curl ") && (text.contains("| sh") || text.contains("| bash") || text.contains("| zsh")) { return true }
        if text.contains("wget ") && (text.contains("| sh") || text.contains("| bash") || text.contains("| zsh")) { return true }
        if text.contains("eval ") || text.contains("execute immediate") { return true }
        if text.contains("base64") && (text.contains("| sh") || text.contains("| bash") || text.contains("| zsh")) { return true }
        return false
    }

'''
    if helper_marker not in text:
        raise SystemExit("policy helper marker missing")
    text = text.replace(helper_marker, helpers + helper_marker, 1)
write(path, text)

# ---------------------------------------------------------------------------
# Swift IPC request/response for daemon preflight.
# ---------------------------------------------------------------------------
path = "Sources/VaultIPC/IPCMessage.swift"
text = read(path)
text = text.replace(
    "    case executeSecretOperation(SecretOperationDescriptor)\n    case startSecretOperation(SecretOperationDescriptor)",
    "    case preflightSecretOperation(SecretOperationDescriptor)\n    case executeSecretOperation(SecretOperationDescriptor)\n    case startSecretOperation(SecretOperationDescriptor)",
    1,
)
text = text.replace(
    "        case executeSecretOperation\n        case startSecretOperation",
    "        case preflightSecretOperation\n        case executeSecretOperation\n        case startSecretOperation",
    1,
)
text = text.replace(
    "        case .executeSecretOperation:\n            self = .executeSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))",
    "        case .preflightSecretOperation:\n            self = .preflightSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))\n        case .executeSecretOperation:\n            self = .executeSecretOperation(try container.decode(SecretOperationDescriptor.self, forKey: .descriptor))",
    1,
)
text = text.replace(
    "        case let .executeSecretOperation(descriptor):\n            try container.encode(RequestType.executeSecretOperation, forKey: .type)\n            try container.encode(descriptor, forKey: .descriptor)",
    "        case let .preflightSecretOperation(descriptor):\n            try container.encode(RequestType.preflightSecretOperation, forKey: .type)\n            try container.encode(descriptor, forKey: .descriptor)\n        case let .executeSecretOperation(descriptor):\n            try container.encode(RequestType.executeSecretOperation, forKey: .type)\n            try container.encode(descriptor, forKey: .descriptor)",
    1,
)
text = text.replace(
    "    case secretOperation(SecretOperationOutput)\n    case secretOperationHandle(SecretOperationHandle)",
    "    case secretOperation(SecretOperationOutput)\n    case secretOperationPreflight(SecretOperationPreflight)\n    case secretOperationHandle(SecretOperationHandle)",
    1,
)
text = text.replace(
    "        case secretOperation\n        case secretOperationHandle",
    "        case secretOperation\n        case secretOperationPreflight\n        case secretOperationHandle",
    1,
)
text = text.replace(
    "        case .secretOperation:\n            self = .secretOperation(try container.decode(SecretOperationOutput.self, forKey: .output))\n        case .secretOperationHandle:",
    "        case .secretOperation:\n            self = .secretOperation(try container.decode(SecretOperationOutput.self, forKey: .output))\n        case .secretOperationPreflight:\n            self = .secretOperationPreflight(try container.decode(SecretOperationPreflight.self, forKey: .result))\n        case .secretOperationHandle:",
    1,
)
text = text.replace(
    "        case let .secretOperation(output):\n            try container.encode(ResponseType.secretOperation, forKey: .type)\n            try container.encode(output, forKey: .output)\n        case let .secretOperationHandle(handle):",
    "        case let .secretOperation(output):\n            try container.encode(ResponseType.secretOperation, forKey: .type)\n            try container.encode(output, forKey: .output)\n        case let .secretOperationPreflight(preflight):\n            try container.encode(ResponseType.secretOperationPreflight, forKey: .type)\n            try container.encode(preflight, forKey: .result)\n        case let .secretOperationHandle(handle):",
    1,
)
required = ["preflightSecretOperation", "secretOperationPreflight"]
if any(item not in text for item in required):
    raise SystemExit("IPCMessage preflight insertion failed")
write(path, text)

# ---------------------------------------------------------------------------
# Swift service boundary.
# ---------------------------------------------------------------------------
path = "Sources/VaultIPC/IPCRequestHandler.swift"
text = read(path)
text = text.replace(
    "    func performSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationOutput",
    "    func preflightSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationPreflight\n    func performSecretOperation(_ descriptor: SecretOperationDescriptor) async throws -> SecretOperationOutput",
    1,
)
text = text.replace(
    "    func performSecretOperation(_: SecretOperationDescriptor) async throws -> SecretOperationOutput {\n        throw IPCRequestHandlerError.unsupportedRequest\n    }",
    "    func preflightSecretOperation(_: SecretOperationDescriptor) async throws -> SecretOperationPreflight {\n        throw IPCRequestHandlerError.unsupportedRequest\n    }\n\n    func performSecretOperation(_: SecretOperationDescriptor) async throws -> SecretOperationOutput {\n        throw IPCRequestHandlerError.unsupportedRequest\n    }",
    1,
)
text = text.replace(
    "        case let .executeSecretOperation(descriptor):\n            do {",
    "        case let .preflightSecretOperation(descriptor):\n            do {\n                return .secretOperationPreflight(try await service.preflightSecretOperation(descriptor))\n            } catch let error as SecretOperationError {\n                return .failure(code: error.responseCode)\n            } catch {\n                return .failure(code: \"ACTION_EXECUTION_FAILED\")\n            }\n        case let .executeSecretOperation(descriptor):\n            do {",
    1,
)
if text.count("preflightSecretOperation") < 3:
    raise SystemExit("IPCRequestHandler preflight insertion failed")
write(path, text)

path = "Sources/VaultService/VaultAppServices.swift"
text = read(path)
marker = "    public func performSecretOperation(\n        _ descriptor: SecretOperationDescriptor\n    ) async throws -> SecretOperationOutput {"
if marker not in text:
    raise SystemExit("VaultAppServices perform marker missing")
addition = '''    public func preflightSecretOperation(
        _ descriptor: SecretOperationDescriptor
    ) async throws -> SecretOperationPreflight {
        let metadata = try await policyMetadata(for: descriptor.secretReferences)
        return operationPolicyEngine.semanticPreflight(descriptor, metadata: metadata)
    }

'''
text = text.replace(marker, addition + marker, 1)
write(path, text)

# ---------------------------------------------------------------------------
# TypeScript wire protocol.
# ---------------------------------------------------------------------------
path = "mcp-server/src/protocol.ts"
text = read(path)
marker = "// This is display-only metadata supplied by the MCP client."
if "export const SecretOperationPreflight" not in text:
    addition = '''export const SecretOperationPreflight = z.object({
  route: z.enum(["fast", "hard", "gray", "denied"]),
  policyRuleID: z.string().min(1),
  authorizationRequirement: z.enum(["none", "reusableApproval", "freshApprovalRequired", "denied"]),
  blastRadius: z.enum(["none", "tiny", "bounded", "broad", "systemic", "unknown"]),
  reasons: z.array(z.string()),
  technicalFailure: z.boolean()
}).strict();
export type SecretOperationPreflight = z.infer<typeof SecretOperationPreflight>;

'''
    if marker not in text:
        raise SystemExit("protocol preflight type marker missing")
    text = text.replace(marker, addition + marker, 1)
request_marker = '''  z
    .object({
      type: z.literal("executeSecretOperation"),
      descriptor: SecretOperationDescriptor
    })'''
if request_marker not in text:
    raise SystemExit("protocol execute request marker missing")
text = text.replace(request_marker, '''  z
    .object({
      type: z.literal("preflightSecretOperation"),
      descriptor: SecretOperationDescriptor
    })
    .strict(),
''' + request_marker, 1)
response_marker = '  z.object({ type: z.literal("secretOperation"), output: SecretOperationOutput }).strict(),'
if response_marker not in text:
    raise SystemExit("protocol secretOperation response marker missing")
text = text.replace(response_marker, response_marker + '\n  z.object({ type: z.literal("secretOperationPreflight"), result: SecretOperationPreflight }).strict(),', 1)
write(path, text)

# ---------------------------------------------------------------------------
# Risk judge: daemon preflight is the sole router. Judge only sees GRAY.
# ---------------------------------------------------------------------------
path = "mcp-server/src/risk-judge.ts"
text = read(path)
text = text.replace(
    'import type { AgentRiskAssessment, SecretOperationDescriptor } from "./protocol.js";',
    'import type { AgentRiskAssessment, SecretOperationDescriptor, SecretOperationPreflight } from "./protocol.js";',
    1,
)
start = text.index("export async function applyContextBoundedRiskJudge(")
end = text.index("async function judgeOperation(", start)
new_router = '''export async function applyContextBoundedRiskJudge(
  request: IpcRequest,
  preflight: SecretOperationPreflight,
  configuration: RiskJudgeConfiguration | undefined = riskJudgeConfigurationFromEnvironment(),
  transport: RiskJudgeTransport = defaultTransport
): Promise<IpcRequest> {
  if (request.type !== "executeSecretOperation" && request.type !== "startSecretOperation") return request;

  const main = normalizeAssessment({ ...request.descriptor.agentAssessment, source: "mainAgent" });
  if (preflight.route === "denied") return replaceAssessment(request, main);
  if (preflight.route === "hard") {
    return replaceAssessment(request, normalizeAssessment({
      ...main,
      executionRecommendation: "freshApproval"
    }));
  }
  if (preflight.route === "fast") return replaceAssessment(request, main);

  if (configuration === undefined) {
    return replaceAssessment(request, normalizeAssessment({
      ...main,
      source: "mainAgent",
      reason: `Independent semantic review required but not configured: ${preflight.policyRuleID}`,
      executionRecommendation: "freshApproval",
      confidence: 0
    }));
  }

  try {
    const judged = await judgeOperation(request.descriptor, main, preflight, configuration, transport);
    return replaceAssessment(request, normalizeAssessment({
      ...main,
      ...judged,
      source: "independentJudge"
    }));
  } catch {
    return replaceAssessment(request, normalizeAssessment({
      ...main,
      source: "independentJudge",
      reason: "Independent semantic judge unavailable or returned an invalid response",
      effectSeverity: "unknown",
      reversibility: "unknown",
      secretHandling: "unknown",
      intentAlignment: "unclear",
      executionRecommendation: "freshApproval",
      confidence: 0
    }));
  }
}

'''
text = text[:start] + new_router + text[end:]
text = text.replace(
    "  grayReason: string,\n  configuration: RiskJudgeConfiguration,",
    "  preflight: SecretOperationPreflight,\n  configuration: RiskJudgeConfiguration,",
    1,
)
text = text.replace(
    '''      svltSignals: {
        grayReason,
        operatingPrinciple: "Complete ordinary user-aligned work automatically; confirmation is for genuine destructive/high-impact actions or unnecessary Secret plaintext exposure."
      }''',
    '''      svltSignals: {
        route: preflight.route,
        localRuleID: preflight.policyRuleID,
        localRequirement: preflight.authorizationRequirement,
        blastRadius: preflight.blastRadius,
        reasons: preflight.reasons.slice(0, 12).map((reason) => safeContextText(reason, 1_024)),
        operatingPrinciple: "Complete ordinary user-aligned work automatically; confirmation is for genuine destructive/high-impact actions or unnecessary Secret plaintext exposure."
      }''',
    1,
)
# Remove obsolete TypeScript-only routing functions.
for function_name in ["semanticGrayReason", "looksSemanticallyOpaque"]:
    token = f"function {function_name}("
    if token in text:
        s = text.index(token)
        brace = text.index("{", s)
        depth = 0
        i = brace
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    while i < len(text) and text[i] in "\r\n":
                        i += 1
                    text = text[:s] + text[i:]
                    break
            i += 1
        else:
            raise SystemExit(f"could not remove {function_name}")
# Keep high-impact normalization only as a judge-output invariant.
if "function isClearlyHighImpact" not in text:
    raise SystemExit("isClearlyHighImpact unexpectedly missing")
write(path, text)

# ---------------------------------------------------------------------------
# Client: daemon preflight first, then judge only if route == GRAY.
# ---------------------------------------------------------------------------
path = "mcp-server/src/client.ts"
text = read(path)
old = '''    const riskJudgedRequest = await applyContextBoundedRiskJudge(request);
    const parsedRequest = LifecycleIpcRequest.parse(riskJudgedRequest);
    const effectiveCaller = caller ?? this.declaredCaller;'''
new = '''    const initialRequest = LifecycleIpcRequest.parse(request);
    const effectiveCaller = caller ?? this.declaredCaller;
    let parsedRequest = initialRequest;
    if (initialRequest.type === "executeSecretOperation" || initialRequest.type === "startSecretOperation") {
      const preflightResponse = await this.requestRaw({
        type: "preflightSecretOperation",
        descriptor: initialRequest.descriptor
      }, effectiveCaller);
      if (preflightResponse.type === "failure") {
        return preflightResponse as BaseIpcResponse;
      }
      if (preflightResponse.type !== "secretOperationPreflight") {
        throw new Error("SVLT daemon returned an invalid preflight response");
      }
      parsedRequest = LifecycleIpcRequest.parse(
        await applyContextBoundedRiskJudge(initialRequest, preflightResponse.result)
      );
    }'''
if old not in text:
    raise SystemExit("client judge-first marker missing")
text = text.replace(old, new, 1)
write(path, text)

# ---------------------------------------------------------------------------
# MCP schemas: assessment is mandatory for Agent-initiated operation tools.
# ---------------------------------------------------------------------------
path = "mcp-server/src/server.ts"
text = read(path)
if "const optionalAgentRiskAssessment = AgentRiskProposal.optional();" not in text:
    raise SystemExit("server optional assessment marker missing")
text = text.replace("const optionalAgentRiskAssessment = AgentRiskProposal.optional();", "const requiredAgentRiskAssessment = AgentRiskProposal;", 1)
text = text.replace("agentAssessment: optionalAgentRiskAssessment", "agentAssessment: requiredAgentRiskAssessment")
write(path, text)

# ---------------------------------------------------------------------------
# Judge tests: route comes from daemon, never from duplicated TS heuristics.
# ---------------------------------------------------------------------------
path = "mcp-server/test/risk-judge.test.ts"
text = read(path)
if 'const fastPreflight' not in text:
    marker = 'describe("intent-first semantic routing", () => {'
    fixtures = '''const fastPreflight = {
  route: "fast" as const,
  policyRuleID: "ssh.reusable.ordinary",
  authorizationRequirement: "none" as const,
  blastRadius: "none" as const,
  reasons: ["ordinary status query"],
  technicalFailure: false
};
const grayPreflight = {
  route: "gray" as const,
  policyRuleID: "ssh.fresh.filesystem-delete",
  authorizationRequirement: "freshApprovalRequired" as const,
  blastRadius: "unknown" as const,
  reasons: ["local classifier detected deletion"],
  technicalFailure: false
};
const hardPreflight = {
  route: "hard" as const,
  policyRuleID: "ssh.fresh.storage-raid-destruction",
  authorizationRequirement: "freshApprovalRequired" as const,
  blastRadius: "systemic" as const,
  reasons: ["storage destruction"],
  technicalFailure: false
};

'''
    if marker not in text:
        raise SystemExit("risk judge describe marker missing")
    text = text.replace(marker, fixtures + marker, 1)
# Rewrite calls based on individual test patterns.
text = text.replace("applyContextBoundedRiskJudge(request(), configuration,", "applyContextBoundedRiskJudge(request(), fastPreflight, configuration,")
text = text.replace(
    'applyContextBoundedRiskJudge(\n      request({ intentAlignment: "unclear", executionRecommendation: "uncertain", confidence: 0.55 }),\n      configuration,',
    'applyContextBoundedRiskJudge(\n      request({ intentAlignment: "unclear", executionRecommendation: "uncertain", confidence: 0.55 }),\n      grayPreflight,\n      configuration,',
)
text = text.replace("applyContextBoundedRiskJudge(dynamic, configuration,", "applyContextBoundedRiskJudge(dynamic, grayPreflight, configuration,")
text = text.replace(
    '    }), configuration, { async fetch() { calls += 1; throw new Error("not expected"); } });',
    '    }), hardPreflight, configuration, { async fetch() { calls += 1; throw new Error("not expected"); } });',
    1,
)
text = text.replace(
    'applyContextBoundedRiskJudge(\n      request({ intentAlignment: "unclear", executionRecommendation: "uncertain" }),\n      configuration,',
    'applyContextBoundedRiskJudge(\n      request({ intentAlignment: "unclear", executionRecommendation: "uncertain" }),\n      grayPreflight,\n      configuration,',
)
text = text.replace("applyContextBoundedRiskJudge(request(), undefined)", "applyContextBoundedRiskJudge(request(), fastPreflight, undefined)")
text = text.replace('it("routes dynamic execution to the independent judge"', 'it("routes daemon GRAY preflight to the independent judge"')
write(path, text)

path = "mcp-server/test/risk-judge-context.test.ts"
text = read(path)
old = "    await applyContextBoundedRiskJudge(request, configuration, transport);"
new = '''    await applyContextBoundedRiskJudge(request, {
      route: "gray",
      policyRuleID: "ssh.semantic.opaque",
      authorizationRequirement: "freshApprovalRequired",
      blastRadius: "unknown",
      reasons: ["dynamic execution"],
      technicalFailure: false
    }, configuration, transport);'''
if old not in text:
    raise SystemExit("risk judge context call marker missing")
text = text.replace(old, new, 1)
write(path, text)

# ---------------------------------------------------------------------------
# Swift policy tests: validate daemon routes and preserve classifier coverage.
# ---------------------------------------------------------------------------
path = "Tests/VaultAuthorizationTests/SecretOperationPolicyEngineTests.swift"
text = read(path)
# Existing soft-risk tests now represent post-Judge results.
for old, new in [
    ('''        agentAssessment: semanticAssessment(\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Remove the bounded temporary directory explicitly requested by the user"\n        )''', '''        agentAssessment: semanticAssessment(\n            source: .independentJudge,\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Independent review confirms one bounded task-owned directory"\n        )'''),
    ('''        agentAssessment: semanticAssessment(\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Remove one disposable preview container created for this task"\n        )''', '''        agentAssessment: semanticAssessment(\n            source: .independentJudge,\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Independent review confirms one disposable preview container"\n        )'''),
    ('''        assessment: semanticAssessment(\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Delete one disposable object created by this task"\n        )''', '''        assessment: semanticAssessment(\n            source: .independentJudge,\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Independent review confirms one disposable object"\n        )'''),
    ('''        assessment: semanticAssessment(\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Delete the single task-owned row requested by the user"\n        )''', '''        assessment: semanticAssessment(\n            source: .independentJudge,\n            recommendation: .automatic,\n            severity: .bounded,\n            reversibility: .recoverable,\n            reason: "Independent review confirms one task-owned row"\n        )'''),
    ('''            agentAssessment: semanticAssessment(\n                recommendation: .automatic,\n                severity: .bounded,\n                reversibility: .recoverable,\n                reason: "Bounded task-owned file mutation"\n            )''', '''            agentAssessment: semanticAssessment(\n                source: .independentJudge,\n                recommendation: .automatic,\n                severity: .bounded,\n                reversibility: .recoverable,\n                reason: "Independent review confirms bounded task-owned file mutation"\n            )'''),
]:
    if old in text:
        text = text.replace(old, new, 1)

anchor = "\nprivate func engine() -> SecretOperationPolicyEngine {"
if "preflightRoutesOrdinaryHardAndGrayOperationsBeforeJudge" not in text:
    tests = r'''

@Test func preflightRoutesOrdinaryHardAndGrayOperationsBeforeJudge() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    let policy = engine()

    let fast = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "systemctl status jellyfin",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .none,
                reversibility: .readOnly,
                reason: "Read requested service status"
            )
        ),
        metadata: metadata
    )
    #expect(fast.route == .fast)

    let gray = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "rm -rf /share/photos",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "Deliberately optimistic main-Agent assessment"
            )
        ),
        metadata: metadata
    )
    #expect(gray.route == .gray)
    #expect(gray.blastRadius == .unknown)

    let hard = policy.semanticPreflight(
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "zpool destroy tank",
            agentAssessment: semanticAssessment(
                recommendation: .automatic,
                severity: .minor,
                reversibility: .easy,
                reason: "Deliberately optimistic main-Agent assessment"
            )
        ),
        metadata: metadata
    )
    #expect(hard.route == .hard)
    #expect(hard.blastRadius == .systemic)
}

@Test func mainAgentCannotDirectlyDowngradeGrayDeletionButIndependentJudgeCan() throws {
    let reference = try testReference()
    let metadata = [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    func descriptor(source: AgentRiskAssessment.Source) -> SecretOperationDescriptor {
        SecretOperationDescriptor(
            actionType: .sshCommand,
            secretReferences: [reference],
            destination: "nas.local",
            port: 22,
            protocolType: .ssh,
            command: "rm -rf /share/task-owned-temp",
            agentAssessment: semanticAssessment(
                source: source,
                recommendation: .automatic,
                severity: .bounded,
                reversibility: .recoverable,
                reason: "Delete one task-owned temporary directory"
            )
        )
    }
    #expect(engine().evaluate(descriptor(source: .mainAgent), metadata: metadata).authorizationRequirement == .freshApprovalRequired)
    #expect(engine().evaluate(descriptor(source: .independentJudge), metadata: metadata).authorizationRequirement == .none)
}

@Test func newCredentialScopeRoutesAutomaticRecommendationToGray() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .sshCommand,
        secretReferences: [reference],
        destination: "other-nas.local",
        port: 22,
        protocolType: .ssh,
        command: "hostname",
        agentAssessment: semanticAssessment(
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            reason: "Read hostname from a newly targeted machine"
        )
    )
    let preflight = engine().semanticPreflight(
        descriptor,
        metadata: [policyMetadata(reference, destinations: ["nas.local"], protocols: ["ssh"])]
    )
    #expect(preflight.route == .gray)
}

@Test func plaintextExportIsAlwaysFreshApproval() throws {
    let reference = try testReference()
    let descriptor = SecretOperationDescriptor(
        actionType: .exportPlaintext,
        secretReferences: [reference],
        protocolType: .file,
        agentAssessment: semanticAssessment(
            source: .independentJudge,
            recommendation: .automatic,
            severity: .none,
            reversibility: .readOnly,
            secretHandling: .userVisibleSensitiveData,
            reason: "Explicit plaintext export remains owner-approved"
        )
    )
    let decision = engine().evaluate(
        descriptor,
        metadata: [policyMetadata(reference, destinations: [], protocols: [])]
    )
    #expect(decision.authorizationRequirement == .freshApprovalRequired)
}

@Test func classifierRegressionCoverageSurvivesIntentFirstRouting() {
    let ssh = SSHCommandRiskClassifier()
    let dangerous: [(String, String)] = [
        ("/usr/bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sudo /bin/rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("env MODE=maintenance rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("sh -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("sudo bash -c 'rm -rf /tmp/a'", SSHFreshRules.filesystemDelete),
        ("find /tmp -exec rm -rf {} \\;", SSHFreshRules.filesystemDelete),
        ("xargs rm -rf /tmp/a", SSHFreshRules.filesystemDelete),
        ("bash -c 'reboot'", SSHFreshRules.powerControl),
        ("docker system prune", SSHFreshRules.containerDestruction),
        ("zpool destroy tank", SSHFreshRules.storageRaidDestruction),
        ("mdadm --zero-superblock /dev/md0", SSHFreshRules.storageRaidDestruction),
        ("systemctl isolate rescue.target", SSHFreshRules.powerControl)
    ]
    for (command, rule) in dangerous {
        #expect(ssh.classify(command: command).ruleID == rule, "command: \(command)")
    }

    let ordinary = [
        "bash -c 'echo hello'", "python3 -c 'print(1)'", "find /tmp -exec echo {} \\;",
        "sudo systemctl restart jellyfin", "docker ps", "docker restart web", "zpool status",
        "echo rm", "grep reboot logfile", "cat /backup/dd"
    ]
    for command in ordinary {
        #expect(ssh.classify(command: command).authorizationRequirement == .reusableApproval, "command: \(command)")
    }

    let sql = DatabaseStatementClassifier()
    let expected: [(String, String)] = [
        ("WITH doomed AS (SELECT id FROM logs) DELETE FROM logs USING doomed WHERE logs.id = doomed.id", SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite),
        ("MERGE INTO inventory AS target USING incoming AS source ON target.id = source.id WHEN MATCHED THEN UPDATE SET count = source.count", SecretOperationPolicyEngine.DatabaseFreshRules.destructiveWrite),
        ("CREATE USER app_user IDENTIFIED BY 'fixture'", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("ALTER ROLE app_user SET statement_timeout = 0", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("GRANT SELECT ON app TO app_user", SecretOperationPolicyEngine.DatabaseFreshRules.privilegeAccountAdmin),
        ("DO $$ BEGIN DELETE FROM logs; END $$", SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution),
        ("PREPARE purge AS DELETE FROM logs", SecretOperationPolicyEngine.DatabaseFreshRules.dynamicExecution)
    ]
    for (statement, rule) in expected {
        #expect(sql.classify(statement).ruleID == rule, "statement: \(statement)")
    }
    for statement in ["-- DELETE FROM logs\nSELECT 1", "SELECT 'DROP TABLE logs'", "/* GRANT ALL */ SELECT 1"] {
        #expect(sql.classify(statement).scopeFamily == "database.read", "statement: \(statement)")
    }
}
'''
    if anchor not in text:
        raise SystemExit("Swift policy test anchor missing")
    text = text.replace(anchor, tests + anchor, 1)
write(path, text)

# ---------------------------------------------------------------------------
# Documentation: describe actual two-phase routing.
# ---------------------------------------------------------------------------
path = "docs/security/context-bounded-risk-judge.md"
text = read(path)
start = text.index("## Decision order")
end = text.index("## Sensitive is not dangerous", start)
section = '''## Decision order

1. The main Agent sends a structured semantic assessment with `userGoal`, `taskContext`, `intendedEffect`, `expectedEffect`, `expectedResult`, task alignment, effect severity, reversibility, Secret handling, recommendation, and confidence.
2. The MCP boundary first asks the daemon for deterministic preflight. The daemon returns `FAST`, `HARD`, `GRAY`, or `DENIED` together with the local rule, approval floor, blast radius, and sanitized reasons. TypeScript does not duplicate the Swift classifier registry.
3. `FAST` proceeds with the main Agent assessment and no second model call. `HARD` goes directly to fresh owner approval. `DENIED` stays denied. Only `GRAY` invokes SVLT's separately configured semantic judge.
4. Gray routing includes unresolved Agent semantics, dynamic/opaque execution, a new credential scope, and conflicts between an `automatic` recommendation and deterministic soft-risk families such as deletion or destructive data mutation.
5. The daemon rechecks the deterministic floor on execution. A main-Agent `automatic` assessment cannot directly lower a daemon `GRAY` signal; an independent judgment is required.
6. String marker protocols such as `SVLT_JUDGE_V1`, `SVLT_JUDGE_V2`, and `SVLT_AGENT_V2` are retired rather than preserved for compatibility.

'''
text = text[:start] + section + text[end:]
write(path, text)

print("PR86 remaining source changes applied")
