#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { LocalIpcClient } from "./client.js";
import { credentialSourcePriority } from "./credential-scope.js";
import { AgentRiskProposal, agentAssessment } from "./agent-assessment.js";
import { SshCommandBatchInput, SshCommandInput } from "./ssh-input.js";
import {
  AgentCallerIdentity,
  CatalogCreateEntryRequest,
  CatalogCreateStructureRequest,
  CatalogBatchMutation,
  CatalogEntryListResult,
  CatalogFilePreflight,
  CatalogDraft,
  CatalogDraftRequest,
  CatalogIndexListResult,
  CatalogMetadataPatch,
  CatalogSecureInputStatus,
  CatalogWriteResult,
  CatalogValidationResult,
  IpcRequest,
  IpcResponse,
  SecretCatalogField,
  SecretCatalogMatch,
  SecretCatalogSearchResult,
  SecretPolicy,
  SecretOperationDescriptor,
  SecretOperationAction,
  SecretOperationCapability,
  SecretOperationOutput,
  SecretOperationStage,
  SecretOperationProtocol,
  SecretAllowedProtocol,
  SecretDestinationBinding,
  SecretReference,
  SecretReferenceMetadata,
  UniqueSecretReferences,
  NonEmptyUniqueSecretReferences,
  SSHCommandBatch,
  SSHCommandSpec,
  SSHHost,
  SSHHostKeyPin,
  SSHSessionStatus
} from "./protocol.js";

const requiredAgentRiskAssessment = AgentRiskProposal;

// Keep this text aligned with SVLTAgentCatalogPolicy.text.  The Swift value
// is the App's embedded source of truth; this copy is returned by the
// cross-language MCP policy contract and is covered by policy tests.
const SVLT_AGENT_CATALOG_POLICY = `SVLT 敏感信息目录写入规范

1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
2. ## 表示分组，### 表示条目。
3. 条目和字段必须符合 SVLT v3 marker 与 schema。
4. 已存在的 id 必须保持稳定，禁止随意重新生成。
5. 同一条目不得出现重复 field key。
6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
7. 字段不够时再增加。
8. SVLT 正式支持三种写入路径：App 受控写入、Agent 经 MCP 写入、Obsidian/编辑器/脚本直接修改文件。
9. 无论哪条路径，都必须产生符合 SVLT v3 的结构；直接写文件不会获得更高权限。
10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
12. [[双链]] 属于合法 Markdown 内容，禁止删除或展开成普通文本。
13. 密码字段不得保存明文。
14. 密码字段只能为空 placeholder 或合法 secret://。
15. Token 应写作“令牌”。
16. API Key 推荐显示为“API 密钥”，但这只是推荐显示标签，不是 schema 合法性约束。
17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
19. endpoint.type 可以是任意非空类型字符串，例如 ssh、postgresql、mysql、redis；结构层合法不等于 executor 支持该类型。
20. 禁止伪造 secret://。
21. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
22. 删除包含密码引用的条目或分组需要用户批准。
23. 普通标题、别名、备注、标签、非密码字段等修改不触发额外的高风险 secretRef 批准；由 Agent 提交的 mutation 仍必须走 operation-bound write request。
24. 普通新增分组、条目、字段、空密码 placeholder 不触发额外的高风险 secretRef 批准；不等于无边界或无授权写入。
25. 合法的普通批量操作不因“批量”本身升级为高风险；一次提交的 batch 仍对应一个精确的 operation-bound write request。
26. 每一笔 Agent semantic Catalog mutation 都必须由 Agent 主动发起一次精确绑定、一次消费的 operation-bound write request；Agent 不能自行开启权限、扩大或复用授权。
27. 每笔需要授权的 Agent semantic Catalog mutation 都会直接触发一次精确绑定的 macOS device-owner authentication；该身份认证本身就是本次用户授权，不存在额外的 App 前置确认，认证票据只消费一次。
28. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
29. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
30. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
31. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
32. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 secret://。
33. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
34. 受控 MCP Catalog write 的结果必须带 post-commit validation 摘要；secret_catalog_validate 仍用于外部编辑检查、显式 health check 和详细 diagnostics。
35. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
36. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
37. 不得把 SVLT 解密得到的明文写回敏感信息.md。
38. 凭据来源标签包括 SVLT_MANAGED_OPERATION、USER_EXPLICIT_PLAINTEXT、EXTERNAL_PROVIDER_OPERATION、UNMANAGED_CREDENTIAL；不得因为用户使用其他凭据 provider 而强制接管。
39. SVLT 自己生成或受控插入的 managed Catalog 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局；已有未知 Note、说明、用户 Markdown、callout 与 WikiLink 不属于 Catalog semantic model，必须保持原位。
40. 新建 Index 必须插入最后一个合法 SVLT-INDEX 之后、尾部非托管 Markdown 之前；如果已有用户 Markdown 位于 Index 之间，不为追求连续主体而搬迁它；当前没有 Index 时，插入 policy 和前言之后，不得追加到用户尾注之后。
41. 新生成 Index 之间使用 renderer 的标准 Markdown 分隔 \\n\\n---\\n\\n；已有 --- 没有 provenance 时按用户内容保留，不猜测或全局重写用户自己的分隔线。
42. 同一 Index 内的 Entry 之间使用统一的双空行视觉间距；新增、batch、migration、format repair 和 minimal patch 不得混用一行、两行或三行布局。
43. Catalog 写入遵守最小修改原则；只改目标 source range 和新写入时由 SVLT renderer 明确生成的边界空白，保留用户普通 Markdown、注释、WikiLink、Note 和尾部内容；format repair 不搬迁无法确认来源的 Note/Markdown/WikiLink，也不删除用户 HR。
44. Agent 浏览必须使用 secret_catalog_list_indices、secret_catalog_list_entries、secret_catalog_get、secret_catalog_create_structure 等 MCP 响应发现 opaque ID；不得读取 selection sidecar、敏感信息.md 或 Application Support 文件解析 ID。
45. 需要用户输入秘密时使用 secret_catalog_request_secure_inputs；若 transport 返回 PENDING 与 requestID，只能用 secret_catalog_secure_input_status 轮询同一请求，Agent 永远只能收到状态/非敏感结果，不能收到 plaintext。`;

export interface VaultIpcClient {
  request(request: IpcRequest, caller?: AgentCallerIdentity): Promise<IpcResponse>;
}

export interface VaultToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodType;
  outputSchema: z.ZodType;
  handler(input: unknown): Promise<CallToolResult>;
}

const StatusOutput = z
  .union([
    z
      .object({
        status: z.string().min(1),
        available: z.boolean().optional(),
        ready: z.boolean().optional(),
        approvalPending: z.boolean().optional()
      })
      .strict(),
    z.object({ locked: z.boolean() }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Vault lock status or non-sensitive status code");

const CapabilityManifestOutput = z
  .union([
    z.object({
      status: z.literal("OK"),
      capabilities: z.array(SecretOperationCapability).max(32)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Daemon capability manifest. Unavailable adapters must not be treated as supported.");

const RevealOutput = z
  .object({ status: z.string().min(1) })
  .strict()
  .describe("Reveal request status. Plaintext is shown only inside the macOS app.");

const ExportOutput = z
  .union([
    z.object({ status: z.literal("EXPORTED"), path: z.string().min(1) }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local file export status. Plaintext is never returned.");

const CreateOutput = z
  .union([
    z.object({ reference: SecretReference }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("New secret reference or non-sensitive status code");

const InspectOutput = z
  .union([
    z
      .object({
        reference: SecretReference,
        policy: SecretPolicy,
        label: z.string().nullable(),
        allowedDestinations: z.array(z.string()),
        allowedProtocols: z.array(z.string()),
        allowedBindings: z.array(SecretDestinationBinding).default([]),
        createdAt: z.union([z.string(), z.number()]),
        updatedAt: z.union([z.string(), z.number()])
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Non-sensitive metadata for a secret reference. Plaintext is never returned.");

const DestinationBindingOutput = z
  .union([
    z.object({
      status: z.literal("BOUND"),
      destination: z.string().min(1),
      protocol: SecretOperationProtocol,
      port: z.number().int().min(1).max(65_535).optional(),
      hostKeyPin: SSHHostKeyPin.optional(),
      redacted: z.literal(true)
    }).strict(),
    z.object({
      status: z.string().min(1),
      redacted: z.literal(true)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Owner-approved exact destination binding result. Secret plaintext is never returned.");

const SSHHostKeyReviewOutput = z
  .union([
    z.object({
      status: z.literal("FOUND"),
      host: SSHHost,
      port: z.number().int().min(1).max(65_535),
      pins: z.array(SSHHostKeyPin).min(1).max(32)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Presented SSH host-key algorithms and SHA256 fingerprints only; no Secret is read or returned, and discovery is not an identity guarantee.");

const SecretSearchInput = z
  .object({
    query: z.string().trim().min(1).max(256),
    field: SecretCatalogField.optional(),
    limit: z.number().int().min(1).max(20).default(10)
  })
  .strict();

const SecretSearchOutput = z
  .union([
    z
      .object({
        status: z.enum([
          "FOUND",
          "NOT_FOUND",
          "INVALID_QUERY",
          "CATALOG_UNAVAILABLE",
          "LEGACY_CATALOG_UNSUPPORTED",
          "INTEGRITY_MISSING",
          "EXTERNAL_CATALOG_MODIFICATION",
          "PENDING_EXTERNAL_CHANGE",
          "CATALOG_INVALID"
        ]),
        matches: z.array(SecretCatalogMatch)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Opaque secret catalog matches. Plaintext and catalog file locations are never returned.");

const CatalogGetInput = z.object({ entryID: z.string().length(26) }).strict();
const CatalogListEntriesInput = z.object({ indexID: z.string().length(26) }).strict();

const CatalogCreateDraftInput = z
  .object({ request: CatalogDraftRequest })
  .strict();

const CatalogCreateIndexInput = z
  .object({
    title: z.string().trim().min(1).max(2000),
    aliases: z.array(z.string()).max(64).default([]),
    tags: z.array(z.string()).max(64).default([])
  })
  .strict();

const CatalogCreateEntryInput = CatalogCreateEntryRequest;

const CatalogPatchMetadataInput = z
  .object({
    entryID: z.string().length(26),
    patch: CatalogMetadataPatch,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogCommitInput = z
  .object({
    draft: CatalogDraft,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogPlaceholderInput = z
  .object({
    entryID: z.string().length(26),
    key: z.string().min(1),
    label: z.string().min(1),
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogBindInput = z
  .object({
    entryID: z.string().length(26),
    key: z.string().min(1),
    secretRef: SecretReference,
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogSecureInputRequestInput = z
  .object({
    entryID: z.string().length(26),
    targets: z.array(z.object({
      fieldKey: z.string().min(1).max(128),
      mode: z.enum(["fillPlaceholder", "replaceSecret", "convertToSecret"]),
      required: z.boolean().default(false)
    }).strict()).min(1).max(32),
    expectedRevision: z.number().int().nonnegative()
  })
  .strict();

const CatalogSecureInputStatusOutput = z
  .union([
    z.object({
      requestID: z.string().uuid(),
      status: z.enum(["PENDING", "COMPLETED", "CANCELLED", "EXPIRED", "FAILED", "UNKNOWN"]),
      revision: z.number().int().nonnegative().nullable().optional(),
      errorCode: z.string().min(1).max(128).nullable().optional()
    }).strict(),
    // IPC failures are stable business outcomes, not malformed MCP calls.
    // Keep them in structuredContent so the caller can branch on the code.
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Secure Input status or a stable Catalog error code");

const CatalogBatchInput = CatalogBatchMutation;

const CatalogWriteOutput = z
  .union([
    CatalogWriteResult,
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Catalog write result. Secret plaintext is never accepted or returned.");

const CatalogCreateOutput = z
  .union([
    z.object({
      status: z.literal("CREATED"),
      entryID: z.string().length(26),
      revision: z.number().int().nonnegative(),
      validation: CatalogValidationResult
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Safe Catalog creation result. Secret plaintext and existing secretRef values are never accepted.");

const CatalogIndexCreateOutput = z
  .union([
    z.object({
      status: z.literal("CREATED"),
      indexID: z.string().length(26),
      revision: z.number().int().nonnegative(),
      validation: CatalogValidationResult
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Safe Catalog Index creation result.");

const CatalogIndexListOutput = z
  .union([CatalogIndexListResult, z.object({ status: z.string().min(1) }).strict()])
  .describe("Opaque Catalog Index summaries, including empty Indexes.");

const CatalogEntryListOutput = z
  .union([CatalogEntryListResult, z.object({ status: z.string().min(1) }).strict()])
  .describe("Projected Entries for one opaque Catalog Index.");

const CatalogStructureCreateOutput = z
  .union([
    z.object({
      status: z.literal("CREATED"),
      indexID: z.string().length(26),
      entries: z.array(z.object({
        clientKey: z.string().min(1),
        entryID: z.string().length(26)
      }).strict()),
      revision: z.number().int().nonnegative(),
      validation: CatalogValidationResult
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Atomic safe Catalog Index and Entry creation result.");

const CatalogDraftOutput = z
  .union([CatalogDraft, z.object({ status: z.string().min(1) }).strict()])
  .describe("Catalog draft containing only visible metadata and opaque secret references.");

const CatalogValidationOutput = z
  .union([
    z.object({
      status: z.string().min(1),
      revision: z.number().int().nonnegative().nullable().optional(),
      rawSHA256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
      diagnostics: z.array(z.object({
        id: z.string().min(1),
        severity: z.enum(["error", "warning"]),
        code: z.string().min(1),
        line: z.number().int().positive(),
        column: z.number().int().positive().nullable().optional(),
        endLine: z.number().int().positive().nullable().optional(),
        endColumn: z.number().int().positive().nullable().optional(),
        scope: z.enum(["document", "policy", "index", "entry", "field", "unmanaged"]),
        message: z.string().min(1),
        hint: z.string().nullable().optional()
      }).strict()).default([])
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Catalog validation status; it never returns document content.");

const LocalHttpOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        httpStatus: z.number().int(),
        contentType: z.string().nullable(),
        sessionID: z.string().min(1).max(128).optional(),
        redacted: z.literal(true),
        bodyPreview: z.string().optional()
      })
      .strict(),
    z.object({
      status: z.literal("REDIRECT_REQUIRES_REVIEW"),
      httpStatus: z.number().int().optional(),
      redirectLocation: z.string().url().optional(),
      sessionID: z.string().min(1).max(128).optional(),
      redacted: z.literal(true)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local HTTP result. Secret material is used only inside SVLTAgent and is never returned.");

const LocalSshOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        exitCode: z.number().int().optional(),
        stdout: z.string().optional(),
        stderr: z.string().optional(),
        sessionID: z.string().min(1).max(128).optional(),
        failedIndex: z.number().int().min(0).optional(),
        results: z.array(z.object({
          index: z.number().int().min(0),
          status: z.string().min(1),
          exitCode: z.number().int().optional(),
          stage: SecretOperationStage.optional(),
          stdoutPreview: z.string().optional(),
          stderrPreview: z.string().optional()
        }).strict()).max(32).optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z
      .object({
        status: z.string().min(1),
        exitCode: z.number().int().optional(),
        stage: SecretOperationStage.optional(),
        stdoutPreview: z.string().optional(),
        stderrPreview: z.string().optional(),
        sessionID: z.string().min(1).max(128).optional(),
        failedIndex: z.number().int().min(0).optional(),
        results: z.array(z.object({
          index: z.number().int().min(0),
          status: z.string().min(1),
          exitCode: z.number().int().optional(),
          stage: SecretOperationStage.optional(),
          stdoutPreview: z.string().optional(),
          stderrPreview: z.string().optional()
        }).strict()).max(32).optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local SSH result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const SshSessionStatusInput = z
  .object({
    sessionID: z.string().min(1).max(128).optional()
  })
  .strict();

const SshSessionStatusOutput = z
  .union([
    z
      .object({
        status: z.enum(["ACTIVE", "NO_ACTIVE_SESSIONS"]),
        sessions: z.array(SSHSessionStatus).max(32)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Opaque SSH transport session status. It never grants execution authorization.");

const SshSessionCloseInput = z
  .object({
    sessionID: z.string().min(1).max(128)
  })
  .strict();

const SshSessionCloseOutput = z
  .object({ status: z.string().min(1) })
  .strict()
  .describe("SSH transport session close status. It never changes execution authorization.");

const ApiRequestOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        httpStatus: z.number().int(),
        contentType: z.string().nullable(),
        sessionID: z.string().min(1).max(128).optional(),
        redacted: z.literal(true),
        bodyPreview: z.string().optional()
      })
      .strict(),
    z.object({
      status: z.literal("REDIRECT_REQUIRES_REVIEW"),
      httpStatus: z.number().int().optional(),
      redirectLocation: z.string().url().optional(),
      sessionID: z.string().min(1).max(128).optional(),
      redacted: z.literal(true)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("API request result. Token material is used only inside SVLTAgent and plaintext is never returned.");

const DatabaseQueryOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        rowCount: z.number().int().min(0).optional(),
        rowsPreview: z.string().optional(),
        stderr: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Database query result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const FileTransferOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        listingPreview: z.string().optional(),
        localPath: z.string().optional(),
        remotePath: z.string().optional(),
        stderr: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z
      .object({
        status: z.string().min(1),
        stage: SecretOperationStage.optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("SFTP/SCP/FTP result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const BrowserLoginOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        url: z.string().optional(),
        note: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Browser login fill result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const LocalAppFillOutput = z
  .union([
    z
      .object({
        status: z.literal("COMPLETED"),
        filledFields: z.array(z.string()).optional(),
        note: z.string().optional(),
        redacted: z.literal(true)
      })
      .strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local app form fill result. Secret material is used only inside SVLTAgent and plaintext is never returned.");

const LocalProcessOutput = z
  .union([
    z.object({
      status: z.literal("COMPLETED"),
      redacted: z.literal(true)
    }).strict(),
    z.object({ status: z.string().min(1) }).strict()
  ])
  .describe("Local process result. A secret is never returned to the Agent.");

const AgentPolicyOutput = z
  .object({
    status: z.literal("OK"),
    intendedClients: z.array(z.string().min(1)),
    conversationRule: z.string().min(1),
    referenceRule: z.string().min(1),
    catalogPolicy: z.string().min(1),
    scopeRule: z.object({
      managed: z.string().min(1),
      unmanaged: z.string().min(1),
      explicitPlaintext: z.string().min(1),
      externalProvider: z.string().min(1)
    }).strict(),
    userOverrideRule: z.string().min(1),
    outOfScopeRule: z.array(z.string().min(1)),
    credentialSourcePriority: z.array(z.string().min(1)),
    safeWorkflow: z.array(z.string().min(1)),
    forbidden: z.array(z.string().min(1)),
    safeTools: z.array(z.string().min(1))
  })
  .strict()
  .describe("Non-sensitive usage policy for MCP-capable agents. Plaintext is never returned.");

const AutoHandleOutput = z
  .object({
    status: z.string().min(1),
    action: z.string().min(1),
    referenceCount: z.number().int().min(0),
    references: UniqueSecretReferences,
    redactedText: z.string().optional()
  })
  .strict()
  .describe("Automatic secret:// text handling result. Plaintext is never returned.");

const EmptyInput = z.object({}).strict();

const RevealInput = z
  .object({
    reference: SecretReference,
    reason: z.string().min(1),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict();

const ParagraphRevealInput = z
  .object({
    text: z.string().min(1).optional(),
    references: NonEmptyUniqueSecretReferences.optional(),
    template: z.string().min(1).optional(),
    reason: z.string().min(1),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.text !== undefined || (value.references !== undefined && value.template !== undefined), {
    message: "Provide either text containing secret:// references, or references plus a {{0}} template."
  });

const ExportResolvedTextInput = z
  .object({
    text: z.string().min(1).optional(),
    references: NonEmptyUniqueSecretReferences.optional(),
    template: z.string().min(1).optional(),
    reason: z.string().min(1),
    destinationPath: z.string().min(1),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.text !== undefined || (value.references !== undefined && value.template !== undefined), {
    message: "Provide either text containing secret:// references, or references plus a {{0}} template."
  });

const CreateInput = z
  .object({
    label: z.string().nullable().optional(),
    policy: SecretPolicy,
    allowedDestinations: z.array(z.string().min(1)).max(32).optional(),
    allowedProtocols: z.array(SecretAllowedProtocol).max(16).optional()
  })
  .strict();

const InspectInput = z
  .object({
    reference: SecretReference.describe("The secret:// reference to inspect. Do not pass metadata or label.")
  })
  .strict();

const BindDestinationInput = z
  .object({
    reference: SecretReference,
    destination: z.string().trim().min(1).max(512),
    protocol: SecretOperationProtocol,
    port: z.number().int().min(1).max(65_535).optional(),
    hostKeyAlgorithm: z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/).optional(),
    hostKeySHA256: z.string().trim().regex(/^SHA256:[A-Za-z0-9+/]{43}$/).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .superRefine((value, context) => {
    if (value.destination.includes("secret://")) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["destination"],
        message: "destination must not contain secret:// references."
      });
    }
    if ([...value.destination].some((character) => {
      const codePoint = character.codePointAt(0) ?? 0;
      return codePoint < 0x21 || codePoint === 0x7f;
    })) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["destination"],
        message: "destination must not contain whitespace or control characters."
      });
    }

    const hasHostKeyAlgorithm = value.hostKeyAlgorithm !== undefined;
    const hasHostKeySHA256 = value.hostKeySHA256 !== undefined;
    const hasHostKeyPin = hasHostKeyAlgorithm || hasHostKeySHA256;
    if (hasHostKeyAlgorithm !== hasHostKeySHA256) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [hasHostKeyAlgorithm ? "hostKeySHA256" : "hostKeyAlgorithm"],
        message: "hostKeyAlgorithm and hostKeySHA256 must be provided together."
      });
    }
    if (!hasHostKeyPin && value.port !== undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["port"],
        message: "port is only valid when an SSH host-key pin is supplied."
      });
    }
    if (hasHostKeyPin) {
      if (!(["ssh", "sftp", "scp"] as const).includes(value.protocol as "ssh" | "sftp" | "scp")) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["protocol"],
          message: "Host-key pins are only valid for ssh, sftp, or scp."
        });
      }
      if (value.port === undefined) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["port"],
          message: "An explicit port is required when pinning an SSH host key."
        });
      }
      const colonCount = [...value.destination].filter((character) => character === ":").length;
      const bracketedIPv6 = value.destination.startsWith("[")
        && value.destination.endsWith("]")
        && !value.destination.slice(1, -1).includes("]");
      const hostOnly = value.destination.startsWith("[")
        ? bracketedIPv6
        : colonCount !== 1;
      if (
        value.destination.includes("://")
        || value.destination.includes("/")
        || value.destination.includes("?")
        || value.destination.includes("#")
        || value.destination.includes("@")
        || !hostOnly
      ) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["destination"],
          message: "Pinned SSH destinations must be host-only and must not contain an embedded port."
        });
      }
    }
  });

const ReviewSSHHostKeyInput = z
  .object({
    host: SSHHost,
    port: z.number().int().min(1).max(65_535)
  })
  .strict();

const LocalHttpInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference.optional(),
    sessionID: z.string().min(1).max(128).optional(),
    includeBodyPreview: z.boolean().optional().describe("Return at most 16 KiB of a safe JSON response preview; authenticated responses are quarantined if they contain sensitive fields."),
    responseProfileID: z.string().min(1).max(128).optional(),
    responseFields: z.array(z.string().min(1).max(128)).max(32).optional(),
    timeoutMs: z.number().int().min(100).max(30_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .superRefine((value, context) => {
    if (value.usernameRef !== undefined && value.usernameRef === value.passwordRef) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["passwordRef"],
        message: "usernameRef and passwordRef must be different references."
      });
    }
    const hasProfile = value.responseProfileID !== undefined;
    const hasFields = value.responseFields !== undefined;
    if (hasProfile !== hasFields || (hasProfile && value.responseFields?.length === 0)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["responseProfileID"],
        message: "responseProfileID and non-empty responseFields must be provided together."
      });
    }
  });

const ApiRequestInput = z
  .object({
    url: z.string().url(),
    method: z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]).optional(),
    tokenRef: SecretReference,
    sessionID: z.string().min(1).max(128).optional(),
    headerName: z.string().min(1).max(128).optional(),
    headerScheme: z.string().min(1).max(64).optional(),
    body: z.string().refine((value) => Buffer.byteLength(value, "utf8") <= 65_536, {
      message: "body must be at most 65536 UTF-8 bytes"
    }).optional(),
    includeBodyPreview: z.boolean().optional().describe("Return at most 16 KiB of a safe JSON response preview; authenticated responses are quarantined if they contain sensitive fields."),
    responseProfileID: z.string().min(1).max(128).optional(),
    responseFields: z.array(z.string().min(1).max(128)).max(32).optional(),
    timeoutMs: z.number().int().min(100).max(30_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .superRefine((value, context) => {
    const hasProfile = value.responseProfileID !== undefined;
    const hasFields = value.responseFields !== undefined;
    if (hasProfile !== hasFields || (hasProfile && value.responseFields?.length === 0)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["responseProfileID"],
        message: "responseProfileID and non-empty responseFields must be provided together."
      });
    }
  });

const DatabaseQueryInput = z
  .object({
    engine: z.enum(["postgres", "mysql"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    database: z.string().min(1).max(256),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    query: z.string().min(1).max(20_000),
    maxRows: z.number().int().min(1).max(100).optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .superRefine((value, context) => {
    if (value.usernameRef !== undefined && value.usernameRef === value.passwordRef) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["passwordRef"],
        message: "usernameRef and passwordRef must be different references."
      });
    }
  });

const FileTransferInput = z
  .object({
    protocol: z.enum(["sftp", "scp"]).optional(),
    operation: z.enum(["list", "download", "upload", "overwrite", "delete"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    remotePath: z.string().min(1).max(4_096),
    localPath: z.string().min(1).max(4_096).optional(),
    timeoutMs: z.number().int().min(1_000).max(60_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .refine((value) => value.username !== undefined || value.usernameRef !== undefined, {
    message: "Provide username or usernameRef."
  })
  .superRefine((value, context) => {
    if (value.usernameRef !== undefined && value.usernameRef === value.passwordRef) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["passwordRef"],
        message: "usernameRef and passwordRef must be different references."
      });
    }
  });

const FTPTransferInput = z
  .object({
    protocol: z.literal("ftp").optional(),
    operation: z.enum(["list", "download", "upload", "overwrite", "delete"]),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    remotePath: z.string().min(1).max(4_096),
    localPath: z.string().min(1).max(4_096).optional(),
    timeoutMs: z.number().int().min(1_000).max(60_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .refine((value) => value.username !== undefined || value.usernameRef !== undefined, {
    message: "Provide username or usernameRef."
  })
  .superRefine((value, context) => {
    if (value.usernameRef !== undefined && value.usernameRef === value.passwordRef) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["passwordRef"],
        message: "usernameRef and passwordRef must be different references."
      });
    }
  });

const BrowserLoginInput = z
  .object({
    browser: z.enum(["Safari", "Chrome"]).optional(),
    url: z.string().url(),
    username: z.string().min(1).max(256).optional(),
    usernameRef: SecretReference.optional(),
    passwordRef: SecretReference,
    usernameSelector: z.string().min(1).max(1_024).optional(),
    passwordSelector: z.string().min(1).max(1_024),
    submitSelector: z.string().min(1).max(1_024).optional(),
    submit: z.boolean().optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .refine((value) => value.username === undefined || value.usernameRef === undefined, {
    message: "Use either username or usernameRef, not both."
  })
  .superRefine((value, context) => {
    if (value.usernameRef !== undefined && value.usernameRef === value.passwordRef) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["passwordRef"],
        message: "usernameRef and passwordRef must be different references."
      });
    }
  })
  .refine((value) => value.submit !== true || value.submitSelector !== undefined, {
    message: "submitSelector is required when submit is true."
  });

const LocalAppFillInput = z
  .object({
    appName: z.string().min(1).max(256).optional(),
    bundleId: z.string().min(1).max(256).optional(),
    fields: z.array(z
      .object({
        name: z.string().min(1).max(256),
        value: z.string().max(4_096).optional(),
        valueRef: SecretReference.optional()
      })
      .strict()
      .refine((value) => value.value === undefined || value.valueRef === undefined, {
        message: "Use either value or valueRef, not both."
      })
      .refine((value) => value.value !== undefined || value.valueRef !== undefined, {
        message: "Each field requires value or valueRef."
      })).min(1).max(20),
    submitButton: z.string().min(1).max(256).optional(),
    timeoutMs: z.number().int().min(1_000).max(30_000).optional(),
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .superRefine((value, context) => {
    const seen = new Set<string>();
    value.fields.forEach((field, index) => {
      if (field.valueRef !== undefined && seen.has(field.valueRef)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["fields", index, "valueRef"],
          message: "Each secret:// reference may be used only once in a local App request."
        });
      }
      if (field.valueRef !== undefined) seen.add(field.valueRef);
    });
  })
  .refine((value) => value.appName !== undefined || value.bundleId !== undefined, {
    message: "appName or bundleId is required."
  });

const LocalExecutionInput = z
  .object({
    executable: z.string().trim().min(1).max(4_096),
    arguments: z.array(z.string().max(4_096)).max(32).default([]),
    secretReferences: NonEmptyUniqueSecretReferences,
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .superRefine((value, context) => {
    if (value.executable.includes("secret://") || value.arguments.some((argument) => argument.includes("secret://"))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["arguments"],
        message: "Local process metadata cannot contain secret:// values."
      });
    }
  });

const TrustedProcessInput = z
  .object({
    profileID: z.string().trim().min(1).max(128),
    arguments: z.array(z.string().max(4_096)).max(32).default([]),
    secretReferences: NonEmptyUniqueSecretReferences,
    agentAssessment: requiredAgentRiskAssessment
  })
  .strict()
  .superRefine((value, context) => {
    if (value.profileID.includes("secret://") || value.arguments.some((argument) => argument.includes("secret://"))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["arguments"],
        message: "Trusted process metadata cannot contain secret:// values."
      });
    }
  });

const SecretActionRouterInput = z
  .discriminatedUnion("intent", [
    SshCommandInput.extend({
      intent: z.literal("ssh_command")
    }).strict(),
    SshCommandBatchInput.extend({
      intent: z.literal("ssh_batch")
    }).strict(),
    LocalHttpInput.extend({
      intent: z.literal("local_http_request")
    }).strict(),
    ExportResolvedTextInput.extend({
      intent: z.literal("export_resolved_text")
    }).strict(),
    ApiRequestInput.extend({
      intent: z.literal("api_request")
    }).strict(),
    DatabaseQueryInput.extend({
      intent: z.literal("database_query")
    }).strict(),
    FileTransferInput.extend({
      intent: z.literal("sftp_transfer")
    }).strict(),
    FTPTransferInput.extend({
      intent: z.literal("ftp_transfer")
    }).strict(),
    BrowserLoginInput.extend({
      intent: z.literal("browser_web_login")
    }).strict(),
    LocalAppFillInput.extend({
      intent: z.literal("local_app_form_fill")
    }).strict(),
    LocalExecutionInput.extend({
      intent: z.literal("local_execution")
    }).strict(),
    TrustedProcessInput.extend({
      intent: z.literal("trusted_process")
    }).strict()
  ]);

const AutoHandleTextInput = z
  .object({
    text: z.string().min(1),
    intent: z.enum(["inspect", "reveal_to_user"]).optional(),
    reason: z.string().min(1).optional()
  })
  .strict();

export function createVaultToolDefinitions(client: VaultIpcClient): VaultToolDefinition[] {
  return [
    {
      name: "secret_action_router",
      title: "Secret Local Action Router",
      description:
        "Routes secret:// references to policy-reviewed local actions. Check vault_capabilities before adapter-backed execution: the daemon's manifest, not this tool list, is authoritative for HTTP/API, database, SFTP/SCP/FTP, browser, app form fill, and trusted-process support. Export is an App-owned local file operation. Plaintext is never returned.",
      inputSchema: SecretActionRouterInput,
      outputSchema: z.union([
        LocalSshOutput,
        LocalHttpOutput,
        ExportOutput,
        ApiRequestOutput,
        DatabaseQueryOutput,
        FileTransferOutput,
        BrowserLoginOutput,
        LocalAppFillOutput,
        LocalProcessOutput
      ]),
      async handler(input) {
        const parsed = SecretActionRouterInput.parse(input);
        if (parsed.intent === "ssh_command") {
          return handleSshCommandWithSecret(client, parsed);
        }
        if (parsed.intent === "ssh_batch") {
          return handleSshBatchWithSecret(client, parsed);
        }
        if (parsed.intent === "local_http_request") {
          return handleLocalHttpRequest(client, parsed);
        }
        if (parsed.intent === "export_resolved_text") {
          return handleExportResolvedText(client, parsed);
        }
        if (parsed.intent === "api_request") {
          return handleApiRequestWithToken(client, parsed);
        }
        if (parsed.intent === "database_query") {
          return handleDatabaseQueryWithSecret(client, parsed);
        }
        if (parsed.intent === "sftp_transfer") {
          return handleFileTransferWithSecret(client, parsed, "sftpTransfer");
        }
        if (parsed.intent === "ftp_transfer") {
          return handleFileTransferWithSecret(client, parsed, "ftpTransfer");
        }
        if (parsed.intent === "browser_web_login") {
          return handleBrowserLoginWithSecret(client, parsed);
        }
        if (parsed.intent === "local_execution") {
          return handleLocalExecutionWithSecret(client, parsed);
        }
        if (parsed.intent === "trusted_process") {
          return handleTrustedProcessWithSecret(client, parsed);
        }
        return handleLocalAppFillWithSecret(client, parsed);
      }
    },
    {
      name: "agent_secret_usage_policy",
      title: "SVLT Usage Policy",
      description:
        "Returns non-sensitive rules for using SVLT from Codex, Claude, Hermes, or other MCP-capable agents. Plaintext is never returned.",
      inputSchema: EmptyInput,
      outputSchema: AgentPolicyOutput,
      async handler(input) {
        EmptyInput.parse(input);
        return structuredResult(agentSecretUsagePolicy());
      }
    },
    {
      name: "secret_auto_handle_text",
      title: "Auto Handle Secret References In Text",
      description:
        "Automatically detects secret:// references in text and either reports safe reference handling or opens a local app-owned reveal session. Plaintext is never returned.",
      inputSchema: AutoHandleTextInput,
      outputSchema: AutoHandleOutput,
      async handler(input) {
        const parsed = AutoHandleTextInput.parse(input);
        const references = extractSecretReferences(parsed.text);
        const redactedText = redactSecretReferences(parsed.text);
        if (references.length === 0) {
          return structuredResult({
            status: "NO_REFERENCES",
            action: "NO_ACTION",
            referenceCount: 0,
            references: [],
            redactedText
          });
        }

        if ((parsed.intent ?? "inspect") === "inspect") {
          return structuredResult({
            status: "REFERENCES_DETECTED",
            action: "KEEP_REFERENCES_OPAQUE",
            referenceCount: references.length,
            references,
            redactedText
          });
        }

        const revealRequest = buildRevealRequestFromText(parsed.text);
        const response = await client.request({
          type: "revealReferences",
          references: revealRequest.references,
          context: {
            reason: parsed.reason ?? "Automatic local reveal for secret:// references",
            template: revealRequest.context.template,
            ranges: revealRequest.context.ranges,
            agentAssessment: {
              source: "mainAgent",
              declaredRisk: "approvalRequired",
              reason: "Automatic local reveal request",
              userGoal: "Display the requested Secret to the local device owner",
              taskContext: "Local explicit reveal flow",
              intendedEffect: "display to local user",
              expectedEffect: "Render plaintext only in the protected local reveal surface",
              expectedResult: "The local user can view the requested value",
              intentAlignment: "direct",
              effectSeverity: "bounded",
              reversibility: "readOnly",
              secretHandling: "userVisibleSensitiveData",
              executionRecommendation: "freshApproval",
              confidence: 1
            }
          }
        });

        if (response.type === "revealSessionOpened") {
          return structuredResult({
            status: "DISPLAYED_TO_USER",
            action: "LOCAL_APP_REVEAL",
            referenceCount: references.length,
            references,
            redactedText
          });
        }
        return structuredResult({
          ...statusOnly(response),
          action: "LOCAL_APP_REVEAL_FAILED",
          referenceCount: references.length,
          references,
          redactedText
        });
      }
    },
    {
      name: "vault_status",
      title: "Vault Status",
      description:
        "Checks whether SVLT is available and the local operation policy engine is ready; locked is compatibility-only. Plaintext is never returned.",
      inputSchema: EmptyInput,
      outputSchema: StatusOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "workbenchStatus" });
        if (response.type === "workbenchStatus") {
          return structuredResult({
            status: response.status.ready ? "READY" : "UNAVAILABLE",
            available: response.status.available,
            ready: response.status.ready,
            approvalPending: response.status.approvalPending
          });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "vault_capabilities",
      title: "Vault Operation Capabilities",
      description:
        "Returns the daemon's actual non-sensitive adapter capability manifest. Check this before using HTTP, database, SFTP/SCP, FTP, browser, local-app, export, or trusted-process operations; unavailable entries are not supported and must not be retried as if they were.",
      inputSchema: EmptyInput,
      outputSchema: CapabilityManifestOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "secretOperationCapabilities" });
        if (response.type === "secretOperationCapabilities") {
          return structuredResult({ status: "OK", capabilities: response.capabilities });
        }
        return structuredResult({ status: statusOnly(response).status, capabilities: [] });
      }
    },
    {
      name: "secret_inspect_reference",
      title: "Inspect Secret Reference",
      description:
        "Returns only non-sensitive metadata for one secret:// reference. Input must be { reference }. Do not pass metadata or label. Plaintext is never returned.",
      inputSchema: InspectInput,
      outputSchema: InspectOutput,
      async handler(input) {
        const parsed = InspectInput.parse(input);
        const response = await client.request({
          type: "inspectReference",
          reference: parsed.reference
        });
        if (response.type === "referenceMetadata") {
          return structuredResult(metadataResult(response.metadata));
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_bind_destination",
      title: "Bind Secret Destination",
      description:
        "Adds one exact host/origin and protocol to an existing secret:// record. SVLT shows the exact binding in the macOS app and requires fresh device-owner authentication for every change; the record is re-sealed without returning plaintext. For higher-assurance SSH/SFTP/SCP trust, first use secret_review_ssh_host_key, then pass the selected algorithm, SHA256 fingerprint, and explicit port here; ordinary bindings retain TOFU compatibility.",
      inputSchema: BindDestinationInput,
      outputSchema: DestinationBindingOutput,
      async handler(input) {
        return handleBindDestination(client, BindDestinationInput.parse(input));
      }
    },
    {
      name: "secret_review_ssh_host_key",
      title: "Review SSH Host Key",
      description:
        "Discovers the SSH/SFTP/SCP host keys currently presented by one host and port without reading or sending any Secret. Returns only host, port, algorithm, and SHA256 fingerprints; discovery is not a proof of identity. Use the selected fingerprint with secret_bind_destination for the App-owned owner approval and strict pin.",
      inputSchema: ReviewSSHHostKeyInput,
      outputSchema: SSHHostKeyReviewOutput,
      async handler(input) {
        const parsed = ReviewSSHHostKeyInput.parse(input);
        const response = await client.request({
          type: "reviewSSHHostKey",
          host: parsed.host,
          port: parsed.port
        });
        if (response.type === "sshHostKeyReview") {
          return structuredResult({ status: "FOUND", ...response.review });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_search",
      title: "Search Secret Catalog",
      description:
        "Finds Entry-centric SVLT catalog records by index, entry, alias, tag, endpoint, note, or searchable metadata. It returns visible context and opaque secret:// references; it never returns plaintext or the catalog file path.",
      inputSchema: SecretSearchInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = SecretSearchInput.parse(input);
        const response = await client.request({
          type: "catalogSearch",
          query: parsed.query,
          field: parsed.field,
          limit: parsed.limit
        });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_search",
      title: "Search SVLT Catalog (Entry)",
      description:
        "Entry-centric alias of secret_search. Searches the managed Index→Entry→Field catalog and returns only allowed metadata plus opaque secret:// references.",
      inputSchema: SecretSearchInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = SecretSearchInput.parse(input);
        const response = await client.request({
          type: "catalogSearch",
          query: parsed.query,
          field: parsed.field,
          limit: parsed.limit
        });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_get",
      title: "Get SVLT Catalog Entry",
      description:
        "Gets one Entry by opaque catalog ID. It returns visible metadata and secret:// references only; it never returns plaintext.",
      inputSchema: CatalogGetInput,
      outputSchema: SecretSearchOutput,
      async handler(input) {
        const parsed = CatalogGetInput.parse(input);
        const response = await client.request({ type: "catalogGet", entryID: parsed.entryID });
        if (response.type === "catalogSearchResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_list_indices",
      title: "List SVLT Catalog Indexes",
      description:
        "Lists every managed Catalog Index, including empty Indexes, with opaque IDs, titles, aliases, tags, and Entry counts. Use this MCP result to discover IDs; never read selection sidecars or Catalog Markdown.",
      inputSchema: EmptyInput,
      outputSchema: CatalogIndexListOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "catalogListIndexes" });
        if (response.type === "catalogIndexListResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_list_entries",
      title: "List SVLT Catalog Entries",
      description:
        "Lists projected Entries for one opaque Catalog Index ID, including empty results for a valid empty Index. The ID must come from an MCP list/create response; never read local selection JSON, Markdown, or sidecars.",
      inputSchema: CatalogListEntriesInput,
      outputSchema: CatalogEntryListOutput,
      async handler(input) {
        const parsed = CatalogListEntriesInput.parse(input);
        const response = await client.request({ type: "catalogListEntries", indexID: parsed.indexID });
        if (response.type === "catalogEntryListResult") {
          return structuredResult(response.result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_create_index",
      title: "Create Catalog Index",
      description:
        "Creates a new top-level Catalog Index using safe metadata mutation. It does not accept secrets or secret references and does not require a temporary structure lease.",
      inputSchema: CatalogCreateIndexInput,
      outputSchema: CatalogIndexCreateOutput,
      async handler(input) {
        const parsed = CatalogCreateIndexInput.parse(input);
        const response = await client.request({
          type: "catalogCreateIndex",
          title: parsed.title,
          aliases: parsed.aliases,
          tags: parsed.tags
        });
        if (response.type === "catalogWriteResult") {
          if (response.result.indexID === undefined) {
            return structuredResult({ status: "INDEX_ID_MISSING" });
          }
          if (response.result.validation === undefined) {
            return structuredResult({ status: "POST_COMMIT_VALIDATION_MISSING" });
          }
          return structuredResult({
            status: "CREATED",
            indexID: response.result.indexID,
            revision: response.result.revision,
            validation: response.result.validation
          });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_create_structure",
      title: "Create SVLT Catalog Structure",
      description:
        "Atomically creates one Catalog Index and zero or more safe Entries. SVLT generates all opaque IDs and returns clientKey mappings, revision, and post-commit validation; secret fields may only be empty placeholders and existing secretRef binding remains App-approved.",
      inputSchema: CatalogCreateStructureRequest,
      outputSchema: CatalogStructureCreateOutput,
      async handler(input) {
        const parsed = CatalogCreateStructureRequest.parse(input);
        const response = await client.request({
          type: "catalogCreateStructure",
          request: parsed
        });
        if (response.type === "catalogStructureWriteResult") {
          return structuredResult({ status: "CREATED", ...response.result });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_create_entry",
      title: "Create Catalog Entry",
      description:
        "Creates an Index Entry in one safe operation. Ordinary metadata and empty secret placeholders are allowed; existing secretRef values and plaintext secrets are rejected. No temporary structure lease is required.",
      inputSchema: CatalogCreateEntryInput,
      outputSchema: CatalogCreateOutput,
      async handler(input) {
        const parsed = CatalogCreateEntryInput.parse(input);
        const response = await client.request({
          type: "catalogCreateEntry",
          request: parsed
        });
        if (response.type === "catalogWriteResult") {
          if (response.result.entryID === undefined) {
            return structuredResult({ status: "ENTRY_ID_MISSING" });
          }
          if (response.result.validation === undefined) {
            return structuredResult({ status: "POST_COMMIT_VALIDATION_MISSING" });
          }
          return structuredResult({
            status: "CREATED",
            entryID: response.result.entryID,
            revision: response.result.revision,
            validation: response.result.validation
          });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_create_draft",
      title: "Create Catalog Draft",
      description:
        "Creates an Index Entry draft using safe Catalog mutation. Secret fields may only be placeholders; binding an existing secret:// reference is a separate App-approved operation, and plaintext is never accepted.",
      inputSchema: CatalogCreateDraftInput,
      outputSchema: CatalogDraftOutput,
      async handler(input) {
        const parsed = CatalogCreateDraftInput.parse(input);
        const response = await client.request({
          type: "catalogCreateDraft",
          request: parsed.request
        });
        if (response.type === "catalogDraft") {
          return structuredResult(response.draft);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_patch_metadata",
      title: "Patch Catalog Metadata",
      description:
        "Patches ordinary Entry metadata using the current Catalog risk policy and expected revision. Secret transitions, target changes, and secret replacement remain App-approved operations.",
      inputSchema: CatalogPatchMetadataInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogPatchMetadataInput.parse(input);
        const response = await client.request({
          type: "catalogPatchMetadata",
          entryID: parsed.entryID,
          patch: parsed.patch,
          expectedRevision: parsed.expectedRevision
        });
        return structuredResult(controlledCatalogWriteResult(response));
      }
    },
    {
      name: "secret_catalog_commit",
      title: "Commit Catalog Draft",
      description:
        "Commits a previously created safe catalog draft under optimistic revision. Dangerous secret mutations remain App-approved and the Agent cannot self-approve them.",
      inputSchema: CatalogCommitInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogCommitInput.parse(input);
        const response = await client.request({
          type: "catalogCommit",
          draft: parsed.draft,
          expectedRevision: parsed.expectedRevision
        });
        return structuredResult(controlledCatalogWriteResult(response));
      }
    },
    {
      name: "secret_catalog_add_secret_placeholder",
      title: "Add Secret Placeholder",
      description:
        "Adds an empty secret field placeholder as a safe Catalog mutation. The user must fill the secret in SVLT App secure input; plaintext is never accepted here.",
      inputSchema: CatalogPlaceholderInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogPlaceholderInput.parse(input);
        const response = await client.request({
          type: "catalogAddSecretPlaceholder",
          entryID: parsed.entryID,
          key: parsed.key,
          label: parsed.label,
          agentVisible: parsed.agentVisible,
          searchable: parsed.searchable,
          expectedRevision: parsed.expectedRevision
        });
        return structuredResult(controlledCatalogWriteResult(response));
      }
    },
    {
      name: "secret_catalog_request_secure_inputs",
      title: "Request Secure Input",
      description:
        "Asks SVLT to show a local secure-input sheet for an existing Entry. The Agent supplies only field metadata and never sees plaintext. fillPlaceholder fills an empty secret field; replaceSecret replaces an existing binding after local approval; convertToSecret lets the user select an ordinary field to encrypt.",
      inputSchema: CatalogSecureInputRequestInput,
      outputSchema: CatalogSecureInputStatusOutput,
      async handler(input) {
        const parsed = CatalogSecureInputRequestInput.parse(input);
        const targets = parsed.targets.map(target => ({
          entryID: parsed.entryID,
          fieldKey: target.fieldKey,
          mode: target.mode,
          required: target.required
        }));
        const response = await client.request({
          type: "catalogRequestSecureInputs",
          entryID: parsed.entryID,
          targets,
          expectedRevision: parsed.expectedRevision
        });
        if (response.type === "catalogSecureInputStatus") {
          return structuredResult(secureInputStatusResult(response.status));
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_secure_input_status",
      title: "Get Secure Input Status",
      description:
        "Polls a previously requested secure-input transaction by requestID. Returns only status, revision, and a stable error code; it never returns plaintext or Catalog contents.",
      inputSchema: z.object({ requestID: z.string().uuid() }).strict(),
      outputSchema: CatalogSecureInputStatusOutput,
      async handler(input) {
        const parsed = z.object({ requestID: z.string().uuid() }).strict().parse(input);
        const response = await client.request({
          type: "catalogSecureInputStatus",
          requestID: parsed.requestID
        });
        if (response.type === "catalogSecureInputStatus") {
          return structuredResult(secureInputStatusResult(response.status));
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_bind_existing_secret",
      title: "Bind Existing Secret",
      description:
        "Requests binding an existing opaque secret:// reference to a catalog field. SVLT applies local policy and may require App approval; this tool never accepts plaintext.",
      inputSchema: CatalogBindInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogBindInput.parse(input);
        const response = await client.request({
          type: "catalogBindExistingSecret",
          entryID: parsed.entryID,
          key: parsed.key,
          secretRef: parsed.secretRef,
          expectedRevision: parsed.expectedRevision
        });
        return structuredResult(controlledCatalogWriteResult(response));
      }
    },
    {
      name: "secret_catalog_batch",
      title: "Apply Catalog Batch",
      description:
        "Applies one Catalog batch transaction. Ordinary group/entry deletions are evaluated as safe metadata changes; a batch containing any existing secret reference transition is aggregated into one local approval. Plaintext is never accepted.",
      inputSchema: CatalogBatchInput,
      outputSchema: CatalogWriteOutput,
      async handler(input) {
        const parsed = CatalogBatchInput.parse(input);
        const response = await client.request({
          type: "catalogApplyBatch",
          mutation: { operations: parsed.operations },
          expectedRevision: parsed.expectedRevision
        });
        return structuredResult(controlledCatalogWriteResult(response));
      }
    },
    {
      name: "secret_catalog_validate",
      title: "Validate SVLT Catalog",
      description:
        "Validates the selected managed catalog, including integrity and revision state. It never returns catalog content or plaintext.",
      inputSchema: EmptyInput,
      outputSchema: CatalogValidationOutput,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "catalogValidate" });
        if (response.type === "catalogValidation") {
          const result: {
            status: string;
            revision: number | null;
            rawSHA256?: string | null;
            diagnostics?: typeof response.diagnostics;
          } = {
            status: response.catalogStatus,
            revision: response.revision ?? null,
            rawSHA256: response.rawSHA256 ?? null,
            diagnostics: response.diagnostics ?? []
          };
          return structuredResult(result);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_catalog_file_preflight",
      title: "Probe Catalog File Access",
      description:
        "Runs an explicit, non-destructive parent-directory write probe for the selected catalog. It is intentionally separate from validation and should be used only to diagnose write failures.",
      inputSchema: EmptyInput,
      outputSchema: CatalogFilePreflight,
      async handler(input) {
        EmptyInput.parse(input);
        const response = await client.request({ type: "catalogFilePreflight" });
        if (response.type === "catalogFilePreflight") {
          return structuredResult(response.filePreflight);
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "secret_reveal_request",
      title: "Request Secret Reveal",
      description:
        "Asks the macOS app to reveal a secret to the user locally. Plaintext is never returned.",
      inputSchema: RevealInput,
      outputSchema: RevealOutput,
      async handler(input) {
        const parsed = RevealInput.parse(input);
        const response = await client.request({
          type: "revealReferences",
          references: [parsed.reference],
          context: {
            reason: parsed.reason,
            template: "{{0}}",
            ranges: [{ index: 0, placeholder: "{{0}}" }],
            agentAssessment: parsed.agentAssessment === undefined
              ? agentAssessment({})
              : agentAssessment({ agentAssessment: parsed.agentAssessment })
          }
        });
        if (response.type === "revealSessionOpened") {
          return structuredResult({ status: "DISPLAYED_TO_USER" });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "paragraph_reveal_request",
      title: "Request Paragraph Reveal",
      description:
        "Asks the macOS app to display a paragraph locally with referenced secrets filled in. Prefer input { text, reason } where text contains secret:// references; advanced callers may pass { references, template, reason } with {{0}} placeholders. Plaintext is never returned.",
      inputSchema: ParagraphRevealInput,
      outputSchema: RevealOutput,
      async handler(input) {
        const parsed = ParagraphRevealInput.parse(input);
        const revealRequest = revealRequestFromParagraphInput(parsed);
        const response = await client.request({
          type: "revealReferences",
          references: revealRequest.references,
          context: {
            reason: parsed.reason,
            template: revealRequest.context.template,
            ranges: revealRequest.context.ranges,
            agentAssessment: parsed.agentAssessment === undefined
              ? agentAssessment({})
              : agentAssessment({ agentAssessment: parsed.agentAssessment })
          }
        });
        if (response.type === "revealSessionOpened") {
          return structuredResult({ status: "DISPLAYED_TO_USER" });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "export_resolved_text_to_local_file",
      title: "Export Resolved Text To Local File",
      description:
        "Asks the macOS app to resolve secret:// references and write the filled text to a new .md or .txt file on the user's Desktop. Prefer input { text, reason, destinationPath }. Plaintext is never returned.",
      inputSchema: ExportResolvedTextInput,
      outputSchema: ExportOutput,
      async handler(input) {
        return handleExportResolvedText(client, ExportResolvedTextInput.parse(input));
      }
    },
    {
      name: "ssh_command_with_secret",
      title: "SSH Command With Secret",
      description:
        "Runs a raw SSH command (single-line or multi-line shell script: pipelines, redirects, heredocs, interpreters, sudo) on a local/private-network host using a secret:// password. SVLT classifies the actual effect: ordinary task-aligned work is automatic, while genuinely destructive effects require fresh owner approval. SSH execution has no fixed 30-second deadline; omit deprecated timeoutMs for new calls. Plaintext is never returned.",
      inputSchema: SshCommandInput,
      outputSchema: LocalSshOutput,
      async handler(input) {
        return handleSshCommandWithSecret(client, SshCommandInput.parse(input));
      }
    },
    {
      name: "ssh_batch_with_secret",
      title: "SSH Command Batch With Secret",
      description:
        "Runs a structured SSH command batch (executable + arguments records) through one SVLT-managed ControlMaster session. Prefer raw commands when you need real shell semantics. Batch only reduces connection/protocol overhead; it is not required to avoid approval. SSH execution has no fixed 30-second deadline; omit deprecated timeoutMs for new calls. Plaintext is never returned.",
      inputSchema: SshCommandBatchInput,
      outputSchema: LocalSshOutput,
      async handler(input) {
        return handleSshBatchWithSecret(client, SshCommandBatchInput.parse(input));
      }
    },
    {
      name: "ssh_session_status",
      title: "SSH Session Status",
      description:
        "Returns the calling MCP client's own opaque SVLT-managed SSH transport sessions. It exposes no ControlPath, secret reference, password state, or authorization state; a sessionID is not an authorization token.",
      inputSchema: SshSessionStatusInput,
      outputSchema: SshSessionStatusOutput,
      async handler(input) {
        return handleSshSessionStatus(client, SshSessionStatusInput.parse(input));
      }
    },
    {
      name: "ssh_session_close",
      title: "Close SSH Session",
      description:
        "Closes one of the calling MCP client's own opaque SVLT-managed SSH transport sessions. Closing transport never grants, revokes, or extends execution authorization.",
      inputSchema: SshSessionCloseInput,
      outputSchema: SshSessionCloseOutput,
      async handler(input) {
        return handleSshSessionClose(client, SshSessionCloseInput.parse(input));
      }
    },
    {
      name: "secret_create_request",
      title: "Create Secret From App Selection",
      description:
        "First-release compatibility endpoint for app-side selection encryption. It may return SELECTION_ENCRYPT_UNAVAILABLE until the macOS selection bridge is enabled. Plaintext is never returned.",
      inputSchema: CreateInput,
      outputSchema: CreateOutput,
      async handler(input) {
        const parsed = CreateInput.parse(input);
        const response = await client.request({
          type: "encryptBound",
          label: parsed.label,
          policy: parsed.policy,
          allowedDestinations: parsed.allowedDestinations ?? [],
          allowedProtocols: parsed.allowedProtocols ?? []
        });
        if (response.type === "created") {
          return structuredResult({ reference: response.reference });
        }
        return structuredResult(statusOnly(response));
      }
    },
    {
      name: "local_http_request_with_secret",
      title: "Local HTTP Request With Secret",
      description:
        "Capability-gated typed HTTP request using secret:// credentials inside SVLTAgent. Secret use alone does not require approval: ordinary task-aligned HTTPS is automatic; destructive, insecure, credential-in-URL, or unresolved effects require fresh handling. Plaintext HTTP additionally requires an exact saved origin profile. Plaintext is never returned.",
      inputSchema: LocalHttpInput,
      outputSchema: LocalHttpOutput,
      async handler(input) {
        return handleLocalHttpRequest(client, LocalHttpInput.parse(input));
      }
    },
    {
      name: "api_request_with_token",
      title: "API Request With Token",
      description:
        "Capability-gated typed API request using a secret:// token inside SVLTAgent. Secret use alone does not require approval: ordinary task-aligned HTTPS is automatic; destructive, insecure, credential-in-URL, or unresolved effects require fresh handling. Plaintext HTTP requires an exact saved origin profile. Authorization defaults to Bearer. Plaintext is never returned.",
      inputSchema: ApiRequestInput,
      outputSchema: ApiRequestOutput,
      async handler(input) {
        return handleApiRequestWithToken(client, ApiRequestInput.parse(input));
      }
    },
    {
      name: "database_query_with_secret",
      title: "Database Query With Secret",
      description:
        "Capability-gated database operation using a Secret. Reads and bounded CRUD may be automatic; destructive schema/privilege changes or unresolved effects require fresh handling. Unavailable adapters are not retried or treated as success. Plaintext is never returned.",
      inputSchema: DatabaseQueryInput,
      outputSchema: DatabaseQueryOutput,
      async handler(input) {
        return handleDatabaseQueryWithSecret(client, DatabaseQueryInput.parse(input));
      }
    },
    {
      name: "sftp_transfer_with_secret",
      title: "SFTP/SCP Transfer With Secret",
      description:
        "Capability-gated SFTP/SCP. Ordinary list/read/download/upload and bounded writes are automatic; destructive delete or unresolved high-impact effects require fresh handling. Local and remote paths are not directory-restricted. Plaintext is never returned.",
      inputSchema: FileTransferInput,
      outputSchema: FileTransferOutput,
      async handler(input) {
        return handleFileTransferWithSecret(client, FileTransferInput.parse(input), "sftpTransfer");
      }
    },
    {
      name: "ftp_transfer_with_secret",
      title: "FTP Transfer With Secret",
      description:
        "Capability-gated plaintext FTP for loopback/private destinations. Insecure credential transport retains fresh owner approval for every request. Local and remote paths are not directory-restricted. Plaintext is never returned.",
      inputSchema: FTPTransferInput,
      outputSchema: FileTransferOutput,
      async handler(input) {
        return handleFileTransferWithSecret(client, FTPTransferInput.parse(input), "ftpTransfer");
      }
    },
    {
      name: "browser_web_login_with_secret",
      title: "Browser Web Login With Secret",
      description:
        "Capability-gated browser login. Approval follows the effect, not first Secret use. Use only a signed native-messaging adapter; never fall back to AppleScript, clipboard, or injected JavaScript. Plaintext is never returned.",
      inputSchema: BrowserLoginInput,
      outputSchema: BrowserLoginOutput,
      async handler(input) {
        return handleBrowserLoginWithSecret(client, BrowserLoginInput.parse(input));
      }
    },
    {
      name: "local_app_form_fill_with_secret",
      title: "Local App Form Fill With Secret",
      description:
        "Capability-gated macOS Accessibility form fill. Approval follows the actual effect, not first Secret use. Use only a signed target-aware adapter; never fall back to clipboard or generic scripting. Plaintext is never returned.",
      inputSchema: LocalAppFillInput,
      outputSchema: LocalAppFillOutput,
      async handler(input) {
        return handleLocalAppFillWithSecret(client, LocalAppFillInput.parse(input));
      }
    },
    {
      name: "local_execution_with_secret",
      title: "Local Execution With Secret",
      description:
        "Capability-gated localExecution descriptor. It requires a fresh owner approval and an explicit userApprovedSecretRelease audit boundary; unavailable adapters must not fall back to shell, AppleScript, clipboard, or generic scripting. Plaintext is never returned.",
      inputSchema: LocalExecutionInput,
      outputSchema: LocalProcessOutput,
      async handler(input) {
        return handleLocalExecutionWithSecret(client, LocalExecutionInput.parse(input));
      }
    },
    {
      name: "trusted_process_with_secret",
      title: "Trusted Process With Secret",
      description:
        "Capability-gated signed trusted-process descriptor. It is usable only when the daemon advertises a configured signed process profile; otherwise it returns ACTION_EXECUTOR_UNAVAILABLE and never falls back to localExecution or shell. Plaintext is never returned.",
      inputSchema: TrustedProcessInput,
      outputSchema: LocalProcessOutput,
      async handler(input) {
        return handleTrustedProcessWithSecret(client, TrustedProcessInput.parse(input));
      }
    }
  ];
}

export function createMcpServer(client: VaultIpcClient = new LocalIpcClient()): McpServer {
  const server = new McpServer({
    name: "SVLT",
    version: "0.1.21"
  });

  registerVaultTools(server, client);
  return server;
}

export function registerVaultTools(server: McpServer, client: VaultIpcClient): void {
  const callerAwareClient: VaultIpcClient = {
    request: (request) => client.request(request, declaredCallerIdentity(server))
  };
  for (const tool of createVaultToolDefinitions(callerAwareClient)) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema
      },
      async (input) => {
        let result: CallToolResult;
        try {
          result = await tool.handler(input);
        } catch (error) {
          if (error instanceof z.ZodError) {
            return inputValidationResult(error);
          }
          throw error;
        }
        if (!result.isError) {
          if (result.structuredContent === undefined) {
            throw new Error(`Tool ${tool.name} returned no structuredContent`);
          }
          await tool.outputSchema.parseAsync(result.structuredContent);
        }
        return result;
      }
    );
  }
}

export async function runStdioServer(client: VaultIpcClient = new LocalIpcClient()): Promise<void> {
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}

function declaredCallerIdentity(server: McpServer): AgentCallerIdentity {
  const clientInfo = server.server.getClientVersion();
  const candidate = AgentCallerIdentity.safeParse({
    name: clientInfo?.name ?? process.env.SVLT_AGENT_NAME ?? "Unknown MCP Client",
    ...(clientInfo?.version ?? process.env.SVLT_AGENT_VERSION
      ? { version: clientInfo?.version ?? process.env.SVLT_AGENT_VERSION }
      : {}),
    transport: "mcp"
  });
  return candidate.success
    ? candidate.data
    : { name: "Unknown MCP Client", transport: "mcp" };
}

function structuredResult(structuredContent: Record<string, unknown>): CallToolResult {
  return {
    structuredContent,
    content: [
      {
        type: "text",
        text: JSON.stringify(structuredContent)
      }
    ]
  };
}

function controlledCatalogWriteResult(response: IpcResponse): Record<string, unknown> {
  if (response.type !== "catalogWriteResult") {
    return statusOnly(response);
  }
  if (response.result.validation === undefined) {
    return { status: "POST_COMMIT_VALIDATION_MISSING" };
  }
  return response.result;
}

function inputValidationResult(error: z.ZodError): CallToolResult {
  const errors = error.issues.map((issue) => {
    const path = issue.path.map(String);
    const displayPath = path.length === 0 ? "输入" : path.join(".");
    return {
      path,
      message: issue.message,
      hint: `请检查字段 ${displayPath}。`
    };
  });
  const structuredContent = { status: "INVALID_INPUT", errors };
  return {
    isError: true,
    structuredContent,
    content: [{ type: "text", text: JSON.stringify(structuredContent) }]
  };
}

function statusOnly(response: IpcResponse): Record<string, string> {
  if (response.type === "failure") {
    return { status: response.code };
  }
  return { status: "UNEXPECTED_RESPONSE" };
}

function secureInputStatusResult(status: CatalogSecureInputStatus): Record<string, unknown> {
  return {
    requestID: status.requestID,
    status: status.status.toUpperCase(),
    ...(status.revision === undefined || status.revision === null ? {} : { revision: status.revision }),
    ...(status.errorCode === undefined || status.errorCode === null ? {} : { errorCode: status.errorCode })
  };
}

function statusFromError(error: unknown, fallback: string): string {
  if (error instanceof Error && /^[A-Z0-9_]+$/.test(error.message)) {
    return error.message;
  }
  return fallback;
}

function metadataResult(metadata: SecretReferenceMetadata): Record<string, unknown> {
  return {
    reference: metadata.reference,
    policy: metadata.policy,
    label: metadata.label,
    allowedDestinations: metadata.allowedDestinations,
    allowedProtocols: metadata.allowedProtocols,
    allowedBindings: metadata.allowedBindings,
    createdAt: metadata.createdAt,
    updatedAt: metadata.updatedAt
  };
}

async function handleBindDestination(
  client: VaultIpcClient,
  parsed: z.infer<typeof BindDestinationInput>
): Promise<CallToolResult> {
  const hasHostKeyPin = parsed.hostKeyAlgorithm !== undefined && parsed.hostKeySHA256 !== undefined;
  const output = await executeOpaqueOperation(client, {
    actionType: "changeDestinationBinding",
    secretReferences: [parsed.reference],
    destination: parsed.destination,
    port: parsed.port ?? null,
    protocolType: parsed.protocol,
    command: null,
    httpMethod: null,
    url: null,
    databaseStatement: null,
    fileOperation: null,
    fileTarget: null,
    localAppBundleID: null,
    sessionID: null,
    sshCommandBatch: null,
    payload: null,
    requestedEffects: [hasHostKeyPin ? "pin-ssh-host-key" : "bind-secret-destination"],
    parameters: hasHostKeyPin
      ? {
          hostKeyAlgorithm: parsed.hostKeyAlgorithm!,
          hostKeySHA256: parsed.hostKeySHA256!
        }
      : {},
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  if (output.status !== "BOUND") {
    return structuredResult({ status: output.status, redacted: true });
  }
  if (!output.destination || !output.protocolType) {
    return structuredResult({ status: "BINDING_RESULT_INCOMPLETE", redacted: true });
  }
  return structuredResult({
    status: "BOUND",
    destination: output.destination,
    protocol: output.protocolType,
    ...(output.port === undefined ? {} : { port: output.port }),
    ...(output.hostKeyPin === undefined ? {} : { hostKeyPin: output.hostKeyPin }),
    redacted: true
  });
}

async function handleExportResolvedText(
  client: VaultIpcClient,
  parsed: z.infer<typeof ExportResolvedTextInput>
): Promise<CallToolResult> {
  // Export is an App-owned reveal/write service, not an adapter-backed
  // SecretOperation execution. Do not gate it on an absent export adapter;
  // the App IPC handler performs the authorization and secure write flow.
  const revealRequest = revealRequestFromExportInput(parsed);
  const response = await client.request({
    type: "exportResolvedText",
    references: revealRequest.references,
    destinationPath: parsed.destinationPath,
    context: {
      reason: parsed.reason,
      template: revealRequest.context.template,
      ranges: revealRequest.context.ranges,
      agentAssessment: parsed.agentAssessment === undefined
        ? agentAssessment({})
        : agentAssessment({ agentAssessment: parsed.agentAssessment })
    }
  });
  if (response.type === "exported") {
    return structuredResult({ status: "EXPORTED", path: response.path });
  }
  return structuredResult(statusOnly(response));
}


async function ensureSecretOperationCapability(
  client: VaultIpcClient,
  action: z.infer<typeof SecretOperationAction>
): Promise<string | undefined> {
  const response = await client.request({ type: "secretOperationCapabilities" });
  if (response.type !== "secretOperationCapabilities") {
    return response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE";
  }

  const matching = response.capabilities.filter((capability) => capability.operations.includes(action));
  if (matching.some((capability) => capability.status === "supported")) {
    return undefined;
  }
  if (matching.some((capability) => capability.status === "invalidParameters")) {
    return "ARGUMENT_VALIDATION";
  }
  return "ACTION_EXECUTOR_UNAVAILABLE";
}

async function executeOpaqueOperation(
  client: VaultIpcClient,
  descriptor: z.infer<typeof SecretOperationDescriptor>
): Promise<z.infer<typeof SecretOperationOutput> | { status: string }> {
  // SSH is the only exception because its existing transport tool is already
  // the capability-owned execution boundary. Every other execution must
  // perform a fresh capability preflight for this call; an unavailable
  // adapter stops here and never reaches the daemon's approval/decryption
  // path.
  if (descriptor.actionType !== "sshCommand" && descriptor.actionType !== "changeDestinationBinding") {
    const capabilityStatus = await ensureSecretOperationCapability(client, descriptor.actionType);
    if (capabilityStatus !== undefined) {
      return { status: capabilityStatus };
    }
  }
  const response = await client.request({
    type: "executeSecretOperation",
    descriptor
  });
  if (response.type === "secretOperation") {
    return response.output;
  }
  return { status: response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE" };
}

function isSecretOperationOutput(
  value: z.infer<typeof SecretOperationOutput> | { status: string }
): value is z.infer<typeof SecretOperationOutput> {
  return "redacted" in value;
}

const MAX_SSH_DIAGNOSTIC_PREVIEW_CHARS = 16_384;

function sshDiagnosticPreview(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  return value.length <= MAX_SSH_DIAGNOSTIC_PREVIEW_CHARS
    ? value
    : `${value.slice(0, MAX_SSH_DIAGNOSTIC_PREVIEW_CHARS)}…`;
}

function sshDiagnosticResult(output: z.infer<typeof SecretOperationOutput>): Record<string, unknown> {
  const stdoutPreview = sshDiagnosticPreview(output.stdout);
  const stderrPreview = sshDiagnosticPreview(output.stderr);
  const results = output.results?.map((result) => ({
    index: result.index,
    status: result.status,
    ...(result.exitCode === undefined ? {} : { exitCode: result.exitCode }),
    ...(result.stage === undefined ? {} : { stage: result.stage }),
    ...(result.stdout === undefined ? {} : { stdoutPreview: sshDiagnosticPreview(result.stdout) }),
    ...(result.stderr === undefined ? {} : { stderrPreview: sshDiagnosticPreview(result.stderr) })
  }));
  return {
    status: output.status,
    ...(output.exitCode === undefined ? {} : { exitCode: output.exitCode }),
    ...(output.stage === undefined ? {} : { stage: output.stage }),
    ...(stdoutPreview === undefined ? {} : { stdoutPreview }),
    ...(stderrPreview === undefined ? {} : { stderrPreview }),
    ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
    ...(output.failedIndex === undefined ? {} : { failedIndex: output.failedIndex }),
    ...(results === undefined ? {} : { results }),
    redacted: true
  };
}

function httpRedirectResult(output: z.infer<typeof SecretOperationOutput>): Record<string, unknown> {
  return {
    status: output.status,
    ...(output.httpStatus === undefined ? {} : { httpStatus: output.httpStatus }),
    ...(output.redirectLocation === undefined ? {} : { redirectLocation: output.redirectLocation }),
    ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
    redacted: true
  };
}

async function handleSshSessionStatus(
  client: VaultIpcClient,
  parsed: z.infer<typeof SshSessionStatusInput>
): Promise<CallToolResult> {
  const response = parsed.sessionID === undefined
    ? await client.request({ type: "sshSessionStatus" })
    : await client.request({ type: "sshSessionStatus", sessionID: parsed.sessionID });
  if (response.type !== "sshSessionStatus") {
    return structuredResult(statusOnly(response));
  }
  return structuredResult({
    status: response.sessions.length === 0 ? "NO_ACTIVE_SESSIONS" : "ACTIVE",
    sessions: response.sessions
  });
}

async function handleSshSessionClose(
  client: VaultIpcClient,
  parsed: z.infer<typeof SshSessionCloseInput>
): Promise<CallToolResult> {
  const response = await client.request({
    type: "sshSessionClose",
    sessionID: parsed.sessionID
  });
  return structuredResult(
    response.type === "operationCompleted"
      ? { status: "CLOSED" }
      : statusOnly(response)
  );
}

async function handleSshCommandWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof SshCommandInput>
): Promise<CallToolResult> {
  const refs = [parsed.passwordRef];
  const parameters: Record<string, string> = {
    passwordRef: parsed.passwordRef,
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "sshCommand",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: "ssh",
    command: parsed.command,
    sessionID: parsed.sessionID,
    // Do not label every raw shell command as read-only. The effect model
    // uses the actual command plus structured semantics; this field is only a
    // coarse transport hint and must never become an allowlist bypass.
    requestedEffects: ["ssh-command"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  if (output.status !== "COMPLETED") {
    return structuredResult(sshDiagnosticResult(output));
  }
  return structuredResult({
    status: "COMPLETED",
    exitCode: output.exitCode ?? -1,
    stdout: output.stdout ?? "",
    stderr: output.stderr ?? "",
    ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
    redacted: true
  });
}

async function handleSshBatchWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof SshCommandBatchInput>
): Promise<CallToolResult> {
  const refs = [parsed.passwordRef];
  const parameters: Record<string, string> = {
    passwordRef: parsed.passwordRef,
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
  };
  const batch = SSHCommandBatch.parse({
    commands: parsed.commands,
    stopOnFailure: parsed.stopOnFailure
  });
  const output = await executeOpaqueOperation(client, {
    actionType: "sshCommand",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: "ssh",
    sessionID: parsed.sessionID,
    sshCommandBatch: batch,
    requestedEffects: ["ssh-batch"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  return structuredResult(
    output.status === "COMPLETED"
      ? {
          status: "COMPLETED",
          ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
          ...(output.results === undefined ? {} : {
            results: output.results.map((result) => ({
              index: result.index,
              status: result.status,
              ...(result.exitCode === undefined ? {} : { exitCode: result.exitCode }),
              ...(result.stage === undefined ? {} : { stage: result.stage }),
              ...(result.stdout === undefined ? {} : { stdoutPreview: sshDiagnosticPreview(result.stdout) }),
              ...(result.stderr === undefined ? {} : { stderrPreview: sshDiagnosticPreview(result.stderr) })
            }))
          }),
          redacted: true
        }
      : sshDiagnosticResult(output)
  );
}

async function handleLocalHttpRequest(
  client: VaultIpcClient,
  parsed: z.infer<typeof LocalHttpInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    ...(parsed.passwordRef === undefined ? [] : [parsed.passwordRef])
  ];
  if (url.username !== "" || url.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  if ((parsed.username !== undefined || parsed.usernameRef !== undefined) !== (parsed.passwordRef !== undefined)) {
    return structuredResult({ status: "BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD" });
  }
  const parameters: Record<string, string> = {
    ...(parsed.username === undefined ? {} : { username: parsed.username }),
    ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
    ...(parsed.passwordRef === undefined ? {} : { passwordRef: parsed.passwordRef }),
    ...(parsed.includeBodyPreview === undefined ? {} : { includeBodyPreview: String(parsed.includeBodyPreview) }),
    ...(parsed.responseProfileID === undefined ? {} : { responseProfileID: parsed.responseProfileID }),
    ...(parsed.responseFields === undefined ? {} : { responseFields: JSON.stringify(parsed.responseFields) }),
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "httpRequest",
    secretReferences: refs,
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: url.protocol === "https:" ? "https" : "http",
    httpMethod: parsed.method ?? "GET",
    url: parsed.url,
    sessionID: parsed.sessionID,
    payload: {
      type: "http",
      operation: {
        method: parsed.method ?? "GET",
        auth: parsed.passwordRef === undefined
          ? { kind: "none" }
          : {
              kind: "basic",
              ...(parsed.username === undefined ? {} : { username: parsed.username }),
              ...(parsed.usernameRef === undefined ? {} : { usernameReference: parsed.usernameRef }),
              passwordReference: parsed.passwordRef
            },
        body: { kind: "none", fields: {} },
        responsePolicy: {
          kind: parsed.responseProfileID !== undefined
            ? "projectedJSON"
            : parsed.includeBodyPreview === true ? "sanitizedPreview" : "metadataOnly",
          maxBytes: 16_384,
          fields: parsed.responseFields ?? [],
          ...(parsed.responseProfileID === undefined ? {} : { profileID: parsed.responseProfileID })
        },
      }
    },
    requestedEffects: [(parsed.method ?? "GET") === "GET" || (parsed.method ?? "GET") === "HEAD" ? "read-only" : "remote-write"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  if (output.status === "REDIRECT_REQUIRES_REVIEW") {
    return structuredResult(httpRedirectResult(output));
  }
  if (output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    httpStatus: output.httpStatus ?? 0,
    contentType: output.contentType ?? null,
    ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
    ...(output.bodyPreview === undefined ? {} : { bodyPreview: output.bodyPreview }),
    redacted: true
  });
}

async function handleApiRequestWithToken(
  client: VaultIpcClient,
  parsed: z.infer<typeof ApiRequestInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  if (url.username !== "" || url.password !== "") {
    return structuredResult({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
  }
  if (parsed.body?.includes("secret://") === true) {
    return structuredResult({ status: "PLAINTEXT_REFERENCE_NOT_ALLOWED" });
  }
  const headerName = parsed.headerName ?? "Authorization";
  const headerScheme = parsed.headerScheme
    ?? (headerName.toLowerCase() === "authorization" ? "Bearer" : undefined);
  const parameters: Record<string, string> = {
    tokenRef: parsed.tokenRef,
    headerName,
    ...(headerScheme === undefined ? {} : { headerScheme }),
    ...(parsed.body === undefined ? {} : { body: parsed.body }),
    ...(parsed.includeBodyPreview === undefined ? {} : { includeBodyPreview: String(parsed.includeBodyPreview) }),
    ...(parsed.responseProfileID === undefined ? {} : { responseProfileID: parsed.responseProfileID }),
    ...(parsed.responseFields === undefined ? {} : { responseFields: JSON.stringify(parsed.responseFields) }),
  };
  const output = await executeOpaqueOperation(client, {
    actionType: "apiRequest",
    secretReferences: [parsed.tokenRef],
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: url.protocol === "https:" ? "https" : "http",
    httpMethod: parsed.method ?? "GET",
    url: parsed.url,
    sessionID: parsed.sessionID,
    payload: {
      type: "http",
      operation: {
        method: parsed.method ?? "GET",
        auth: {
          kind: headerName.toLowerCase() === "authorization"
            ? "bearer"
            : "apiKeyHeader",
          valueReference: parsed.tokenRef,
          headerName,
          ...(headerScheme === undefined ? {} : { scheme: headerScheme })
        },
        body: parsed.body === undefined
          ? { kind: "none", fields: {} }
          : { kind: "raw", content: parsed.body, fields: {} },
        responsePolicy: {
          kind: parsed.responseProfileID !== undefined
            ? "projectedJSON"
            : parsed.includeBodyPreview === true ? "sanitizedPreview" : "metadataOnly",
          maxBytes: 16_384,
          fields: parsed.responseFields ?? [],
          ...(parsed.responseProfileID === undefined ? {} : { profileID: parsed.responseProfileID })
        },
      }
    },
    requestedEffects: [(parsed.method ?? "GET") === "GET" || (parsed.method ?? "GET") === "HEAD" ? "read-only" : "remote-write"],
    parameters,
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  if (output.status === "REDIRECT_REQUIRES_REVIEW") {
    return structuredResult(httpRedirectResult(output));
  }
  if (output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    httpStatus: output.httpStatus ?? 0,
    contentType: output.contentType ?? null,
    ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
    ...(output.bodyPreview === undefined ? {} : { bodyPreview: output.bodyPreview }),
    redacted: true
  });
}

async function handleLocalExecutionWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof LocalExecutionInput>
): Promise<CallToolResult> {
  const output = await executeOpaqueOperation(client, {
    actionType: "localExecution",
    secretReferences: parsed.secretReferences,
    destination: parsed.executable,
    payload: {
      type: "localExecution",
      operation: {
        executable: parsed.executable,
        arguments: parsed.arguments,
        secretReferences: parsed.secretReferences
      }
    },
    requestedEffects: ["user-approved-secret-release"],
    parameters: {
      executable: parsed.executable,
      arguments: JSON.stringify(parsed.arguments)
    },
    agentAssessment: agentAssessment(parsed)
  });
  return processActionResult(output);
}

async function handleTrustedProcessWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof TrustedProcessInput>
): Promise<CallToolResult> {
  const output = await executeOpaqueOperation(client, {
    actionType: "trustedProcess",
    secretReferences: parsed.secretReferences,
    destination: parsed.profileID,
    payload: {
      type: "trustedProcess",
      operation: {
        profileID: parsed.profileID,
        arguments: parsed.arguments,
        secretReferences: parsed.secretReferences
      }
    },
    requestedEffects: ["trusted-process-secret-release"],
    parameters: {
      profileID: parsed.profileID,
      arguments: JSON.stringify(parsed.arguments)
    },
    agentAssessment: agentAssessment(parsed)
  });
  return processActionResult(output);
}

function processActionResult(
  output: z.infer<typeof SecretOperationOutput> | { status: string }
): CallToolResult {
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({ status: "COMPLETED", redacted: true });
}

async function handleDatabaseQueryWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof DatabaseQueryInput>
): Promise<CallToolResult> {
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType: "databaseQuery",
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? (parsed.engine === "postgres" ? 5432 : 3306),
    protocolType: parsed.engine,
    databaseStatement: parsed.query,
    payload: {
      type: "database",
      operation: {
        engine: parsed.engine,
        database: parsed.database,
        ...(parsed.username === undefined ? {} : { username: parsed.username }),
        ...(parsed.usernameRef === undefined ? {} : { usernameReference: parsed.usernameRef }),
        passwordReference: parsed.passwordRef,
        statement: parsed.query,
        parameters: [],
        maxRows: parsed.maxRows ?? 100,
      }
    },
    requestedEffects: ["database-read"],
    parameters: {
      database: parsed.database,
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.maxRows === undefined ? {} : { maxRows: String(parsed.maxRows) }),
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({
    status: "COMPLETED",
    ...(output.rowCount === undefined ? {} : { rowCount: output.rowCount }),
    ...(output.rowsPreview === undefined ? {} : { rowsPreview: output.rowsPreview }),
    ...(output.stderr === undefined ? {} : { stderr: output.stderr }),
    redacted: true
  });
}

async function handleFileTransferWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof FileTransferInput> | z.infer<typeof FTPTransferInput>,
  actionType: "sftpTransfer" | "ftpTransfer"
): Promise<CallToolResult> {
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType,
    secretReferences: refs,
    destination: parsed.host,
    port: parsed.port ?? (actionType === "ftpTransfer" ? 21 : 22),
    protocolType: actionType === "ftpTransfer" ? "ftp" : (parsed.protocol ?? "sftp"),
    fileOperation: parsed.operation,
    fileTarget: parsed.localPath ?? null,
    payload: {
      type: "fileTransfer",
      operation: {
        protocolType: actionType === "ftpTransfer" ? "ftp" : (parsed.protocol ?? "sftp"),
        operation: parsed.operation,
        remotePath: parsed.remotePath,
        ...(parsed.localPath === undefined ? {} : { localPath: parsed.localPath }),
        ...(parsed.username === undefined ? {} : { username: parsed.username }),
        ...(parsed.usernameRef === undefined ? {} : { usernameReference: parsed.usernameRef }),
        passwordReference: parsed.passwordRef
      }
    },
    requestedEffects: [parsed.operation === "list" || parsed.operation === "download" ? "read-only" : "remote-write"],
    parameters: {
      remotePath: parsed.remotePath,
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.localPath === undefined ? {} : { localPath: parsed.localPath }),
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output)) {
    return structuredResult({ status: output.status });
  }
  if (output.status !== "COMPLETED") {
    return structuredResult({
      status: output.status,
      ...(output.stage === undefined ? {} : { stage: output.stage }),
      redacted: true
    });
  }
  return structuredResult({
    status: "COMPLETED",
    ...(output.listingPreview === undefined ? {} : { listingPreview: output.listingPreview }),
    ...(output.localPath === undefined ? {} : { localPath: output.localPath }),
    ...(output.remotePath === undefined ? {} : { remotePath: output.remotePath }),
    ...(output.stderr === undefined ? {} : { stderr: output.stderr }),
    redacted: true
  });
}

async function handleBrowserLoginWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof BrowserLoginInput>
): Promise<CallToolResult> {
  const url = new URL(parsed.url);
  const refs = [
    ...(parsed.usernameRef === undefined ? [] : [parsed.usernameRef]),
    parsed.passwordRef
  ];
  const output = await executeOpaqueOperation(client, {
    actionType: "browserLogin",
    secretReferences: refs,
    destination: url.host,
    port: url.port === "" ? null : Number(url.port),
    protocolType: "browser",
    url: parsed.url,
    payload: {
      type: "browser",
      operation: {
        ...(parsed.browser === undefined ? {} : { browser: parsed.browser }),
        url: parsed.url,
        ...(parsed.username === undefined ? {} : { username: parsed.username }),
        ...(parsed.usernameRef === undefined ? {} : { usernameReference: parsed.usernameRef }),
        passwordReference: parsed.passwordRef,
        ...(parsed.usernameSelector === undefined ? {} : { usernameSelector: parsed.usernameSelector }),
        passwordSelector: parsed.passwordSelector,
        ...(parsed.submitSelector === undefined ? {} : { submitSelector: parsed.submitSelector }),
        submit: parsed.submit ?? false
      }
    },
    requestedEffects: [parsed.submit === true ? "submit-form" : "fill-form"],
    parameters: {
      passwordRef: parsed.passwordRef,
      ...(parsed.usernameRef === undefined ? {} : { usernameRef: parsed.usernameRef }),
      ...(parsed.username === undefined ? {} : { username: parsed.username }),
      ...(parsed.browser === undefined ? {} : { browser: parsed.browser }),
      ...(parsed.usernameSelector === undefined ? {} : { usernameSelector: parsed.usernameSelector }),
      passwordSelector: parsed.passwordSelector,
      ...(parsed.submitSelector === undefined ? {} : { submitSelector: parsed.submitSelector }),
      submit: String(parsed.submit ?? false),
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({ status: "COMPLETED", redacted: true });
}

async function handleLocalAppFillWithSecret(
  client: VaultIpcClient,
  parsed: z.infer<typeof LocalAppFillInput>
): Promise<CallToolResult> {
  const refs = parsed.fields.flatMap((field) => field.valueRef === undefined ? [] : [field.valueRef]);
  const output = await executeOpaqueOperation(client, {
    actionType: "localAppFill",
    secretReferences: refs,
    destination: parsed.bundleId ?? parsed.appName ?? null,
    protocolType: "localApp",
    localAppBundleID: parsed.bundleId ?? null,
    payload: {
      type: "localApp",
      operation: {
        bundleID: parsed.bundleId ?? parsed.appName ?? "",
        fields: parsed.fields.map((field) => ({
          name: field.name,
          ...(field.value === undefined ? {} : { value: field.value }),
          ...(field.valueRef === undefined ? {} : { valueReference: field.valueRef })
        })),
        ...(parsed.submitButton === undefined ? {} : { submitButton: parsed.submitButton })
      }
    },
    requestedEffects: ["fill-local-app"],
    parameters: {
      fields: JSON.stringify(parsed.fields),
      ...(parsed.appName === undefined ? {} : { appName: parsed.appName }),
      ...(parsed.submitButton === undefined ? {} : { submitButton: parsed.submitButton }),
    },
    agentAssessment: agentAssessment(parsed)
  });
  if (!isSecretOperationOutput(output) || output.status !== "COMPLETED") {
    return structuredResult({ status: output.status });
  }
  return structuredResult({ status: "COMPLETED", redacted: true });
}

function agentSecretUsagePolicy(): Record<string, unknown> {
  return {
    status: "OK",
    intendedClients: ["Codex", "Claude", "Hermes", "Other MCP-capable agents"],
    conversationRule:
      "Keep secret:// references in the conversation. Do not ask the user to paste decrypted values into chat.",
    referenceRule:
      "Treat every secret:// reference as an opaque handle. Do not infer, classify, summarize, or transform the hidden value.",
    catalogPolicy: SVLT_AGENT_CATALOG_POLICY,
    scopeRule: {
      managed:
        "SVLT_MANAGED_OPERATION: use SVLT only when the user explicitly selects SVLT, an Entry, or a secret:// reference; resolve values only inside an approved SVLT operation.",
      unmanaged:
        "UNMANAGED_CREDENTIAL: if the user has not selected SVLT or another provider, automatic discovery is allowed but SVLT is not the only credential source.",
      explicitPlaintext:
        "USER_EXPLICIT_PLAINTEXT: the user supplied plaintext for this operation or explicitly chose not to use SVLT; do not search, compare, substitute, import, block, or require SVLT approval.",
      externalProvider:
        "EXTERNAL_PROVIDER_OPERATION: the user selected another MCP, connector, logged-in CLI, environment variable, or password manager; SVLT must not take over."
    },
    userOverrideRule:
      "Explicit user choice of plaintext overrides SVLT's default preference for secret:// on that operation. Do not force import, conversion, lookup, substitution, or SVLT authorization. Other repository, tool, logging, persistence, and network-safety rules still apply.",
    outOfScopeRule: [
      "SVLT does not own device MCP credentials, GitHub connector authorization, logged-in CLI credentials, environment variables, third-party password managers, or user-supplied plaintext.",
      "Do not treat user-supplied plaintext as SVLT-managed unless the user explicitly asks to store it in or use it through SVLT.",
      "Do not compare user plaintext with an SVLT secret or infer shared provenance from equal values."
    ],
    credentialSourcePriority: [...credentialSourcePriority],
    safeWorkflow: [
      "Before invoking SVLT, determine whether the user explicitly selected SVLT or explicitly supplied plaintext for this operation.",
      "When the user explicitly supplied plaintext and requested its use, continue with that supplied value under the active tool/workspace rules; do not search for or substitute an SVLT reference unless requested.",
      "Credential source selection is per operation; a later user choice replaces previous SVLT or provider context and is never inherited as sticky authorization.",
      "When text contains secret:// references, call secret_auto_handle_text first unless a narrower safe tool is clearly required and the user did not select another source.",
      "Call vault_status before work that depends on the app.",
      "Call vault_capabilities before adapter-backed non-SSH execution. Treat the daemon capability manifest as authoritative: an unavailable adapter is not supported, must not receive plaintext, and must not be retried as if it succeeded. Export to a local file is an App-owned operation with its own authorization flow.",
      "Treat AgentRiskAssessment as effect evidence, not capability. SVLT re-evaluates every operation: ordinary task-aligned Secret use is automatic even on first use; only high-impact, irreversible, credential-exposing, or unresolved gray effects need review. Agent freshApproval is not binding; verified judge may deny.",
      "A locked compatibility field never replaces per-operation policy evaluation.",
      "When a task names a service, device, host, account, or purpose but no credential source is specified, call secret_search before asking the user for anything; this is automatic discovery, not forced SVLT ownership.",
      "Use secret_catalog_list_indices to browse all Indexes, including empty Indexes; use secret_catalog_list_entries with an indexID returned by MCP, then secret_catalog_get for one Entry. Never read selection JSON, Catalog Markdown, or Application Support sidecars to find IDs.",
      "Use secret_catalog_create_structure for one Index plus multiple safe Entries when appropriate; SVLT generates opaque IDs and returns clientKey mappings, revision, and post-commit validation.",
      "Every Agent Catalog mutation requires one exact operation-bound write request; SVLT raises macOS device-owner authentication directly, and that authentication is the user authorization for that one mutation. There is no extra App confirm button; never invent, extend, reuse, or self-approve authorization.",
      "When an Entry needs a user-supplied password, API key, token, or another secret value, call secret_catalog_request_secure_inputs. SVLT resolves field labels from the accepted Catalog, shows a local SecureField sheet, and immediately returns PENDING/requestID. Poll secret_catalog_secure_input_status until a terminal status; the agent receives only status/revision/errorCode and never receives plaintext. If the result is UNKNOWN, re-read the Catalog/revision to reconcile the outcome and never resubmit the secret automatically.",
      "Treat a controlled write as health-confirmed only when validation.status is FOUND and validation.diagnostics is empty. CREATED with CATALOG_UNAVAILABLE or another validation status may mean the commit succeeded but confirmation did not complete; do not blindly repeat the write, and use secret_catalog_validate after service recovery.",
      "A search is silent and metadata-only; it never grants permission to reveal or export plaintext.",
      "Use secret_inspect_reference for non-sensitive metadata only.",
      "Use secret_review_ssh_host_key to discover non-secret SSH/SFTP/SCP host-key fingerprints before pinning; discovery is not an identity guarantee and never resolves a Secret.",
      "Use secret_bind_destination to add one exact destination/protocol to an existing secret:// record; every binding change requires fresh device-owner authentication and never returns plaintext. For strict SSH/SFTP/SCP pinning, supply the selected fingerprint and explicit port; omitting them keeps the compatibility/TOFU path.",
      "Use secret_reveal_request or paragraph_reveal_request when the user needs to see plaintext locally.",
      "Use secret_action_router for local actions that need decrypted material without exposing it to the agent.",
      "Use ssh_command_with_secret for one restricted local/private-network SSH command. An opaque sessionID may be reused for connection performance, but it is never required for authorization and never changes the risk decision.",
      "SSH commands have no fixed execution deadline. timeoutMs is a deprecated compatibility field and is ignored; omit it for new SSH calls instead of splitting long-running work into artificial 30-second windows or retrying solely because 30 seconds elapsed.",
      "Use ssh_batch_with_secret for multiple SSH commands when one transport request is convenient. Pass structured executable/arguments records; SVLT evaluates the complete batch before executing any command and stops after the first failure by default. Batch changes transport overhead only, not approval policy.",
      "Use ssh_session_status only to inspect your own opaque transport sessions, and ssh_session_close only to close your own session when it is no longer needed. Neither tool changes policy or authorization.",
      "Use ssh_command_with_secret for the actual remote shell command, including single-line or multi-line scripts, ;, &&, ||, |, redirects, heredocs, command substitution, shell/interpreter -c forms, find -exec, xargs, eval, sudo, and unknown NAS CLIs. Do not split or rewrite a command merely to satisfy policy.",
      "Approval is effect-based, not Secret-use-based: safe, task-aligned SSH is automatic regardless of operationID, sessionID, elapsed time, or Secret choice. Only high-impact or unresolved gray effects need fresh handling; batching never changes policy.",
      "Declare the MCP client name/version at connection bootstrap when available. It is self-declared display/audit metadata only; it never becomes the security principal or an authorization signal.",
      "Use local_http_request_with_secret or api_request_with_token only for typed, policy-reviewed HTTP requests. Secret use alone is not an approval reason: ordinary task-aligned HTTPS is automatic when policy permits; destructive, credential-in-URL, insecure-transport, or unresolved effects require fresh handling. Insecure HTTP also needs an exact saved origin profile. Never add an insecure-HTTP flag to a tool call.",
      "HTTP tools reject unsafe/arbitrary secret headers, URL authority credentials, and secret:// body fragments. Credential-shaped URL query parameters receive a fresh owner warning rather than an autonomous Agent-side denial. Authorization defaults to Bearer; a custom API-key header receives the raw token unless a profile/request explicitly supplies a safe scheme.",
      "Authenticated HTTP responses are metadata-only by default. An explicit includeBodyPreview request may return at most 16 KiB of valid JSON only when it contains no sensitive response field names or secret:// references; body, Content-Type, redirect Location, and future server-controlled metadata are fingerprint-checked against the in-process Secret and quarantined on any match. A projectedJSON response is allowed only when the daemon capability manifest advertises it and an App-owned profile ID plus allowlisted JSON fields are supplied; never project token, password, secret, cookie, session, authorization, or similar fields. Derived credential/cookie capture is not available in this release.",
      "The generic localExecution action is a very-high-risk, fresh owner-approval boundary and is audited as userApprovedSecretRelease. trustedProcess is a separate future boundary and is usable only when a signed, allowlisted process profile is advertised; do not use shell, AppleScript, clipboard, or generic scripting as a fallback.",
      "Use database_query_with_secret only when vault_capabilities advertises a real PostgreSQL/MySQL adapter; otherwise stop with ACTION_EXECUTOR_UNAVAILABLE. Never simulate database execution with a shell client, password argv/env, or a connection URI.",
      "Use sftp_transfer_with_secret only when the SFTP/SCP capability is advertised. SVLT does not directory-restrict local absolute paths or remote paths. Do not substitute shell or raw scp.",
      "Use ftp_transfer_with_secret only when vault_capabilities advertises the real FTP adapter. FTP is plaintext: restrict it to loopback/private destinations and let local policy require fresh device-owner authentication on every request. Do not substitute shell, curl, or another unreviewed FTP client.",
      "Use browser_web_login_with_secret only when a signed native-messaging browser adapter is advertised; never use AppleScript, clipboard, or injected page JavaScript for SVLT plaintext.",
      "Use local_app_form_fill_with_secret only when a signed Accessibility adapter is advertised and the target bundle is verified; never use clipboard or generic scripting as a fallback.",
      "Use export_resolved_text_to_local_file when the user explicitly wants the app to write resolved sensitive text into a local file without returning it to the agent.",
      "Use a purpose-built MCP tool that resolves references internally when a local operation needs the real value.",
      "If no SVLT-safe tool exists for an explicitly SVLT-managed operation, stop and ask for a new allowlisted tool instead of requesting decrypted plaintext.",
      "If the user explicitly selected another provider or current plaintext, do not redirect the operation to SVLT merely because a catalog match exists."
    ],
    forbidden: [
      "Do not expose plaintext obtained by decrypting an SVLT-managed secret outside the approved SVLT operation.",
      "Do not echo, log, summarize, or store plaintext obtained by decrypting an SVLT-managed secret.",
      "Do not put SVLT-derived plaintext into ordinary shell, curl, URL, header, environment variable, log, audit, or chat inputs; use the approved SVLT operation instead.",
      "Do not treat encrypted reference text as if it revealed the secret value.",
      "Do not send a Secret to a network target outside the approved typed HTTP/API operation; approved typed requests may be automatic or fresh according to actual effect and saved policy, and the Agent must never receive the Secret.",
      "Do not treat an SSH sessionID as an authorization token or use it to bypass policy, principal, scope, or approval checks.",
      "Do not split, rewrite, or misreport a destructive operation to avoid device-owner authentication."
    ],
    safeTools: [
      "secret_action_router",
      "secret_auto_handle_text",
      "vault_status",
      "vault_capabilities",
      "secret_search",
      "secret_inspect_reference",
      "secret_review_ssh_host_key",
      "secret_bind_destination",
      "secret_reveal_request",
      "paragraph_reveal_request",
      "export_resolved_text_to_local_file",
      "secret_create_request",
      "ssh_command_with_secret",
      "ssh_batch_with_secret",
      "ssh_session_status",
      "ssh_session_close",
      "local_http_request_with_secret",
      "api_request_with_token",
      "database_query_with_secret",
      "sftp_transfer_with_secret",
      "ftp_transfer_with_secret",
      "browser_web_login_with_secret",
      "local_app_form_fill_with_secret"
    ]
  };
}

function extractSecretReferences(text: string): string[] {
  return [...new Set(Array.from(text.matchAll(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g), (match) => match[0]))];
}

function redactSecretReferences(text: string): string {
  return text.replace(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g, "[SECRET_REFERENCE]");
}

function buildRevealRequestFromText(text: string): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  const references: string[] = [];
  const ranges: Array<{ index: number; placeholder: string }> = [];
  const template = text.replace(/secret:\/\/[0-9A-HJKMNP-TV-Z]{26}/g, (reference) => {
    const index = references.length;
    const placeholder = `{{${index}}}`;
    references.push(reference);
    ranges.push({ index, placeholder });
    return placeholder;
  });
  return {
    references,
    context: { template, ranges }
  };
}

function revealRequestFromParagraphInput(parsed: z.infer<typeof ParagraphRevealInput>): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  return parsed.text !== undefined
    ? buildRevealRequestFromText(parsed.text)
    : buildRevealRequestFromTemplate(parsed.references ?? [], parsed.template ?? "");
}

function revealRequestFromExportInput(parsed: z.infer<typeof ExportResolvedTextInput>): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  return parsed.text !== undefined
    ? buildRevealRequestFromText(parsed.text)
    : buildRevealRequestFromTemplate(parsed.references ?? [], parsed.template ?? "");
}

function buildRevealRequestFromTemplate(references: string[], template: string): {
  references: string[];
  context: {
    template: string;
    ranges: Array<{ index: number; placeholder: string }>;
  };
} {
  const rawTextRequest = buildRevealRequestFromText(template);
  if (rawTextRequest.references.length > 0) {
    return rawTextRequest;
  }
  return {
    references,
    context: {
      template,
      ranges: references.map((_, index) => ({
        index,
        placeholder: `{{${index}}}`
      }))
    }
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runStdioServer();
}
