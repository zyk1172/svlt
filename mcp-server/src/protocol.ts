import { z } from "zod";

export const MAX_FRAME_BYTES = 1_048_576;

const secretReferencePattern = /^secret:\/\/[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$/;

export const CapabilityToken = z
  .string()
  .refine((value) => {
    const decoded = Buffer.from(value, "base64");
    return decoded.byteLength === 32 && decoded.toString("base64") === value;
  }, "capability token must be base64 encoded 256-bit data");

export type CapabilityToken = z.infer<typeof CapabilityToken>;

export const SecretReference = z.string().regex(secretReferencePattern);
export type SecretReference = z.infer<typeof SecretReference>;

function rejectDuplicateSecretReferences(
  references: string[],
  context: z.RefinementCtx
): void {
  const seen = new Set<string>();
  references.forEach((reference, index) => {
    if (!seen.add(reference)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: [index],
        message: "Duplicate secret:// references are not allowed."
      });
    }
  });
}

export const UniqueSecretReferences = z
  .array(SecretReference)
  .superRefine(rejectDuplicateSecretReferences);
export const NonEmptyUniqueSecretReferences = z
  .array(SecretReference)
  .min(1)
  .superRefine(rejectDuplicateSecretReferences);

export const SecretPolicy = z.enum(["read", "externalSend", "credential"]);
export type SecretPolicy = z.infer<typeof SecretPolicy>;

export const SecretCatalogField = z.enum([
  "username",
  "password",
  "token",
  "apiKey",
  "cookie",
  "privateKey",
  "other"
]);
export type SecretCatalogField = z.infer<typeof SecretCatalogField>;

export const OperationRisk = z.enum(["silent", "approvalRequired", "denied"]);
export type OperationRisk = z.infer<typeof OperationRisk>;

export const AgentAssessmentSource = z.enum(["mainAgent", "independentJudge"]);
export type AgentAssessmentSource = z.infer<typeof AgentAssessmentSource>;

export const AgentIntentAlignment = z.enum(["direct", "supporting", "unclear", "unrelated"]);
export const AgentEffectSeverity = z.enum(["none", "minor", "bounded", "broad", "systemic", "unknown"]);
export const AgentReversibility = z.enum(["readOnly", "easy", "recoverable", "difficult", "irreversible", "unknown"]);
export const AgentSecretHandling = z.enum([
  "none",
  "credentialUse",
  "userVisibleSensitiveData",
  "thirdPartyExposure",
  "plaintextSecretExposure",
  "unknown"
]);
export const AgentExecutionRecommendation = z.enum([
  "automatic",
  "reusableApproval",
  "freshApproval",
  "denied",
  "uncertain"
]);

export const AgentRiskAssessment = z
  .object({
    source: AgentAssessmentSource,
    declaredRisk: OperationRisk,
    reason: z.string().min(1).max(4_096),
    userGoal: z.string().min(1).max(8_192),
    taskContext: z.string().min(1).max(16_384),
    intendedEffect: z.string().min(1).max(8_192),
    expectedEffect: z.string().min(1).max(8_192),
    expectedResult: z.string().min(1).max(8_192),
    intentAlignment: AgentIntentAlignment,
    effectSeverity: AgentEffectSeverity,
    reversibility: AgentReversibility,
    secretHandling: AgentSecretHandling,
    executionRecommendation: AgentExecutionRecommendation,
    confidence: z.number().min(0).max(1)
  })
  .strict();
export type AgentRiskAssessment = z.infer<typeof AgentRiskAssessment>;

export const SecretOperationPreflight = z.object({
  route: z.enum(["fast", "hard", "gray", "denied"]),
  policyRuleID: z.string().min(1),
  authorizationRequirement: z.enum(["none", "reusableApproval", "freshApprovalRequired", "denied"]),
  blastRadius: z.enum(["none", "tiny", "bounded", "broad", "systemic", "unknown"]),
  reasons: z.array(z.string()),
  technicalFailure: z.boolean(),
  // Only a GRAY preflight should carry this daemon-issued binding. The MCP
  // layer must return a fresh-approval request if an older daemon omits it;
  // it must never invent or trust a judge result without the binding.
  reviewID: z.string().uuid().optional()
}).strict();
export type SecretOperationPreflight = z.infer<typeof SecretOperationPreflight>;

// This is display-only metadata supplied by the MCP client. The Swift IPC
// layer derives the security principal from the peer process and never uses
// this value for authorization or compatibility-scope isolation.
export const AgentCallerIdentity = z
  .object({
    name: z.string().trim().min(1).max(64),
    version: z.string().trim().min(1).max(32).optional(),
    transport: z.string().trim().min(1).max(32).default("mcp")
  })
  .strict();
export type AgentCallerIdentity = z.infer<typeof AgentCallerIdentity>;

export const WorkbenchStatus = z.object({
  locked: z.boolean(),
  ipcAvailable: z.boolean(),
  available: z.boolean().default(true),
  ready: z.boolean().default(true),
  approvalPending: z.boolean().default(false),
  activeKnowledgeBaseRoot: z.string().nullable(),
  pluginConnected: z.boolean()
}).strict();
export type WorkbenchStatus = z.infer<typeof WorkbenchStatus>;

export const ReferenceRange = z.object({
  index: z.number().int(),
  placeholder: z.string().min(1)
}).strict();
export type ReferenceRange = z.infer<typeof ReferenceRange>;

export const RevealContext = z.object({
  reason: z.string().min(1),
  template: z.string().min(1),
  ranges: z.array(ReferenceRange),
  destination: z.string().min(1).optional(),
  agentAssessment: AgentRiskAssessment.optional()
}).strict();
export type RevealContext = z.infer<typeof RevealContext>;

export const OrphanScanResult = z.object({
  missingRecords: z.array(z.string()),
  unreferencedRecords: z.array(z.string())
}).strict();
export type OrphanScanResult = z.infer<typeof OrphanScanResult>;

export const SSHHost = z
  .string()
  .trim()
  .min(1)
  .max(255)
  .refine(
    (value) => !value.startsWith("-") && !/[\s\u0000-\u001f\u007f]/u.test(value) && !value.includes("/") && !value.includes("@"),
    "SSH host must be a single safe host token"
  );
export type SSHHost = z.infer<typeof SSHHost>;

export const SSHHostKeyPin = z.object({
  algorithm: z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/),
  sha256: z.string().trim().regex(/^SHA256:[A-Za-z0-9+/]{43}$/)
}).strict();
export type SSHHostKeyPin = z.infer<typeof SSHHostKeyPin>;

export const SSHHostKeyReview = z.object({
  host: SSHHost,
  port: z.number().int().min(1).max(65_535),
  pins: z.array(SSHHostKeyPin).min(1).max(32)
}).strict();
export type SSHHostKeyReview = z.infer<typeof SSHHostKeyReview>;

export const SecretDestinationBinding = z.object({
  protocolType: z.string().min(1).max(32),
  destination: z.string().min(1).max(512),
  port: z.number().int().min(1).max(65_535).optional(),
  hostKeyPin: SSHHostKeyPin.optional()
}).strict();
export type SecretDestinationBinding = z.infer<typeof SecretDestinationBinding>;

export const SecretReferenceMetadata = z.object({
  reference: SecretReference,
  policy: SecretPolicy,
  label: z.string().nullable(),
  allowedDestinations: z.array(z.string()).default([]),
  allowedProtocols: z.array(z.string()).default([]),
  allowedBindings: z.array(SecretDestinationBinding).default([]),
  createdAt: z.union([z.string().min(1), z.number()]),
  updatedAt: z.union([z.string().min(1), z.number()])
}).strict();
export type SecretReferenceMetadata = z.infer<typeof SecretReferenceMetadata>;

export const SecretCatalogFieldType = z.enum([
  "text",
  "multiline",
  "url",
  "host",
  "port",
  "number",
  "boolean",
  "date",
  "list",
  "secret"
]);
export type SecretCatalogFieldType = z.infer<typeof SecretCatalogFieldType>;

export const SecretCatalogValue = z.union([
  z.string(),
  z.number().finite(),
  z.boolean(),
  z.array(z.string())
]);
export type SecretCatalogValue = z.infer<typeof SecretCatalogValue>;

export const CatalogEndpoint = z.object({
  type: z.string().min(1),
  host: z.string().min(1),
  port: z.number().int().min(0).max(65535).nullable().optional()
}).strict();
export type CatalogEndpoint = z.infer<typeof CatalogEndpoint>;

function validateCatalogFieldSafety(
  value: {
    type: SecretCatalogFieldType;
    value?: SecretCatalogValue;
    secretRef?: string;
  },
  context: z.RefinementCtx
): void {
  if (value.value !== undefined && value.secretRef !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "value and secretRef are mutually exclusive" });
  }
  if (value.type === "secret" && value.value !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "secret fields cannot contain plaintext values" });
  }
  if (value.type !== "secret" && value.secretRef !== undefined) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "only secret fields may contain secretRef" });
  }
}

function validateUniqueFieldKeys(
  fields: Array<{ key: string }>,
  context: z.RefinementCtx,
  pathPrefix: Array<string | number> = ["fields"]
): void {
  const firstIndexByKey = new Map<string, number>();
  fields.forEach((field, index) => {
    const firstIndex = firstIndexByKey.get(field.key);
    if (firstIndex === undefined) {
      firstIndexByKey.set(field.key, index);
      return;
    }
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: [...pathPrefix, index, "key"],
      message: `duplicate field key; the first occurrence is at ${[...pathPrefix, firstIndex, "key"].join(".")}`
    });
  });
}

export const SecretCatalogFieldMatch = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    value: SecretCatalogValue.optional(),
    secretRef: SecretReference.optional()
  })
  .strict()
  .superRefine(validateCatalogFieldSafety);
export type SecretCatalogFieldMatch = z.infer<typeof SecretCatalogFieldMatch>;

export const SecretCatalogIndexMatch = z.object({
  id: z.string().length(26),
  title: z.string().min(1),
  aliases: z.array(z.string()),
  tags: z.array(z.string())
}).strict();
export type SecretCatalogIndexMatch = z.infer<typeof SecretCatalogIndexMatch>;

export const SecretCatalogEntryMatch = z.object({
  id: z.string().length(26),
  indexId: z.string().length(26),
  title: z.string().min(1),
  type: z.string().min(1),
  aliases: z.array(z.string()),
  endpoints: z.array(CatalogEndpoint),
  fields: z.array(SecretCatalogFieldMatch),
  notes: z.string().nullable().optional(),
  tags: z.array(z.string())
}).strict();
export type SecretCatalogEntryMatch = z.infer<typeof SecretCatalogEntryMatch>;

export const SecretCatalogMatch = z.object({
  index: SecretCatalogIndexMatch,
  entry: SecretCatalogEntryMatch
}).strict();
export type SecretCatalogMatch = z.infer<typeof SecretCatalogMatch>;

export const SecretCatalogSearchResult = z.object({
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
}).strict();
export type SecretCatalogSearchResult = z.infer<typeof SecretCatalogSearchResult>;

const CatalogFieldValue = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    value: SecretCatalogValue.optional(),
    secretRef: SecretReference.optional()
  })
  .strict()
  .superRefine(validateCatalogFieldSafety);

export const CatalogDraftRequest = z.object({
  indexID: z.string().length(26),
  title: z.string().min(1).max(2000),
  type: z.string().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});
export type CatalogDraftRequest = z.infer<typeof CatalogDraftRequest>;

// Direct creation is intentionally narrower than a draft. A safe Agent
// mutation may provide ordinary metadata and an empty secret placeholder, but
// it cannot carry an existing secretRef or any secret value.
export const CatalogSafeFieldValue = z
  .object({
    key: z.string().min(1),
    label: z.string().min(1),
    type: SecretCatalogFieldType,
    agentVisible: z.boolean().default(true),
    searchable: z.boolean().default(true),
    value: SecretCatalogValue.optional()
  })
  .strict()
  .superRefine((value, context) => {
    if (value.type === "secret" && value.value !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, message: "secret fields must be empty placeholders" });
    }
  });

export const CatalogCreateEntryRequest = z.object({
  indexID: z.string().length(26),
  title: z.string().min(1).max(2000),
  type: z.string().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogSafeFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});
export type CatalogCreateEntryRequest = z.infer<typeof CatalogCreateEntryRequest>;

export const CatalogMetadataPatch = z.object({
  title: z.string().min(1).max(2000).optional(),
  aliases: z.array(z.string()).max(64).optional(),
  tags: z.array(z.string()).max(64).optional(),
  endpoints: z.array(CatalogEndpoint).max(64).optional(),
  notes: z.string().max(2000).optional(),
  fields: z.array(CatalogFieldValue).max(128).optional()
}).strict().superRefine((value, context) => {
  if (value.fields !== undefined) {
    validateUniqueFieldKeys(value.fields, context);
  }
});
export type CatalogMetadataPatch = z.infer<typeof CatalogMetadataPatch>;

const CatalogStructureIndexRequest = z.object({
  title: z.string().trim().min(1).max(2000),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([])
}).strict();

const CatalogStructureEntryRequest = z.object({
  clientKey: z.string().trim().min(1).max(200),
  title: z.string().trim().min(1).max(2000),
  type: z.string().trim().min(1).max(2000).default("credential"),
  aliases: z.array(z.string()).max(64).default([]),
  tags: z.array(z.string()).max(64).default([]),
  endpoints: z.array(CatalogEndpoint).max(64).default([]),
  notes: z.string().max(2000).nullable().optional(),
  fields: z.array(CatalogSafeFieldValue).max(128).default([])
}).strict().superRefine((value, context) => {
  validateUniqueFieldKeys(value.fields, context);
});

export const CatalogCreateStructureRequest = z.object({
  index: CatalogStructureIndexRequest,
  entries: z.array(CatalogStructureEntryRequest).max(128).default([]),
  expectedRevision: z.number().int().nonnegative().optional()
}).strict().superRefine((value, context) => {
  const firstIndexByClientKey = new Map<string, number>();
  value.entries.forEach((entry, index) => {
    const firstIndex = firstIndexByClientKey.get(entry.clientKey);
    if (firstIndex === undefined) {
      firstIndexByClientKey.set(entry.clientKey, index);
      return;
    }
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["entries", index, "clientKey"],
      message: `duplicate clientKey; the first occurrence is at entries.${firstIndex}.clientKey`
    });
  });
});
export type CatalogCreateStructureRequest = z.infer<typeof CatalogCreateStructureRequest>;

export const CatalogDraft = z.object({
  draftID: z.string().length(26),
  baseRevision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch
}).strict();
export type CatalogDraft = z.infer<typeof CatalogDraft>;

export const CatalogSecureInputTarget = z.object({
  fieldKey: z.string().min(1).max(128),
  mode: z.enum(["fillPlaceholder", "replaceSecret", "convertToSecret"]),
  required: z.boolean().default(false)
}).strict();
export type CatalogSecureInputTarget = z.infer<typeof CatalogSecureInputTarget>;

export const CatalogSecureInputTargetRequest = z.object({
  entryID: z.string().length(26),
  fieldKey: z.string().min(1).max(128),
  mode: z.enum(["fillPlaceholder", "replaceSecret", "convertToSecret"]),
  required: z.boolean().default(false)
}).strict();
export type CatalogSecureInputTargetRequest = z.infer<typeof CatalogSecureInputTargetRequest>;

export const CatalogSecureInputStatus = z.object({
  requestID: z.string().uuid(),
  status: z.enum(["PENDING", "COMPLETED", "CANCELLED", "EXPIRED", "FAILED", "UNKNOWN"]),
  revision: z.number().int().nonnegative().nullable().optional(),
  errorCode: z.string().min(1).max(128).nullable().optional()
}).strict();
export type CatalogSecureInputStatus = z.infer<typeof CatalogSecureInputStatus>;

export const CatalogFilePreflight = z.object({
  read: z.string().min(1).max(128),
  parentTempCreate: z.string().min(1).max(128),
  parentTempFsync: z.string().min(1).max(128),
  parentRename: z.string().min(1).max(128),
  parentFsync: z.string().min(1).max(128)
}).strict();
export type CatalogFilePreflight = z.infer<typeof CatalogFilePreflight>;

export const CatalogAgentWriteIntent = z.object({
  requestID: z.string().uuid().nullable().optional(),
  operation: z.enum([
    "createIndex",
    "createEntry",
    "createStructure",
    "patchMetadata",
    "commitDraft",
    "addSecretPlaceholder",
    "batchMutation"
  ]),
  indexID: z.string().nullable().optional(),
  entryID: z.string().nullable().optional(),
  fieldKey: z.string().nullable().optional(),
  acceptedRevision: z.number().int().nonnegative(),
  candidateSemanticSHA256: z.string().regex(/^[0-9a-f]{64}$/)
}).strict();
export type CatalogAgentWriteIntent = z.infer<typeof CatalogAgentWriteIntent>;

export const CatalogAgentWriteAccessRequest = z.object({
  id: z.string().uuid(),
  source: z.enum(["codex", "claude", "openclaw", "mcp-client"]),
  reasonCategory: z.enum(["knowledge-maintenance", "catalog-repair", "bulk-import", "other"]),
  duration: z.enum(["single-use", "10-minutes", "30-minutes"]),
  createdAt: z.string().datetime(),
  intent: CatalogAgentWriteIntent.nullable().optional(),
  expiresAt: z.string().datetime().nullable().optional(),
  verifiedSource: z.string().nullable().optional()
}).strict();
export type CatalogAgentWriteAccessRequest = z.infer<typeof CatalogAgentWriteAccessRequest>;

export const CatalogValidationDiagnostic = z.object({
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
}).strict();
export type CatalogValidationDiagnostic = z.infer<typeof CatalogValidationDiagnostic>;

export const CatalogValidationResult = z.object({
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
  revision: z.number().int().nonnegative().nullable().optional(),
  rawSHA256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
  diagnostics: z.array(CatalogValidationDiagnostic).default([]),
  filePreflight: CatalogFilePreflight.nullable().optional()
}).strict();
export type CatalogValidationResult = z.infer<typeof CatalogValidationResult>;

export const CatalogWriteResult = z.object({
  revision: z.number().int().nonnegative(),
  entry: SecretCatalogEntryMatch.nullable().optional(),
  indexID: z.string().length(26).optional(),
  entryID: z.string().length(26).optional(),
  validation: CatalogValidationResult.optional()
}).strict();
export type CatalogWriteResult = z.infer<typeof CatalogWriteResult>;

export const CatalogStructureWriteResult = z.object({
  indexID: z.string().length(26),
  entries: z.array(z.object({
    clientKey: z.string().min(1),
    entryID: z.string().length(26)
  }).strict()),
  revision: z.number().int().nonnegative(),
  validation: CatalogValidationResult
}).strict();
export type CatalogStructureWriteResult = z.infer<typeof CatalogStructureWriteResult>;

export const CatalogIndexSummary = z.object({
  id: z.string().length(26),
  title: z.string().min(1),
  aliases: z.array(z.string()),
  tags: z.array(z.string()),
  entryCount: z.number().int().nonnegative()
}).strict();
export type CatalogIndexSummary = z.infer<typeof CatalogIndexSummary>;

export const CatalogIndexListResult = z.object({
  status: SecretCatalogSearchResult.shape.status,
  revision: z.number().int().nonnegative(),
  indices: z.array(CatalogIndexSummary)
}).strict();
export type CatalogIndexListResult = z.infer<typeof CatalogIndexListResult>;

export const CatalogEntryListResult = z.object({
  status: SecretCatalogSearchResult.shape.status,
  revision: z.number().int().nonnegative(),
  indexID: z.string().length(26),
  entries: z.array(SecretCatalogEntryMatch)
}).strict();
export type CatalogEntryListResult = z.infer<typeof CatalogEntryListResult>;

const CatalogBatchIndex = z
  .object({
    schema: z.literal("svlt.catalog.index/v3"),
    id: z.string().length(26),
    title: z.string().min(1).max(2000),
    aliases: z.array(z.string()).max(64),
    tags: z.array(z.string()).max(64)
  })
  .strict();

const CatalogBatchEntry = z
  .object({
    schema: z.literal("svlt.catalog.entry/v3"),
    id: z.string().length(26),
    indexId: z.string().length(26),
    title: z.string().min(1).max(2000),
    type: z.string().min(1).max(2000),
    aliases: z.array(z.string()).max(64),
    endpoints: z.array(CatalogEndpoint).max(64),
    fields: z.array(CatalogFieldValue).max(128),
    notes: z.string().max(2000).nullable().optional(),
    tags: z.array(z.string()).max(64)
  })
  .strict()
  .superRefine((value, context) => {
    validateUniqueFieldKeys(value.fields, context);
  });

export const CatalogBatchOperation = z.discriminatedUnion("type", [
  z.object({ type: z.literal("createIndex"), index: CatalogBatchIndex }).strict(),
  z.object({ type: z.literal("updateIndex"), index: CatalogBatchIndex }).strict(),
  z.object({ type: z.literal("deleteIndex"), id: z.string().length(26) }).strict(),
  z.object({ type: z.literal("createEntry"), entry: CatalogBatchEntry }).strict(),
  z.object({ type: z.literal("updateEntry"), entry: CatalogBatchEntry }).strict(),
  z
    .object({
      type: z.literal("moveEntry"),
      id: z.string().length(26),
      toIndexID: z.string().length(26)
    })
    .strict(),
  z.object({ type: z.literal("deleteEntry"), id: z.string().length(26) }).strict(),
  z
    .object({
      type: z.literal("addField"),
      entryID: z.string().length(26),
      field: CatalogFieldValue
    })
    .strict(),
  z
    .object({
      type: z.literal("updateField"),
      entryID: z.string().length(26),
      field: CatalogFieldValue
    })
    .strict(),
  z
    .object({
      type: z.literal("removeField"),
      entryID: z.string().length(26),
      key: z.string().min(1)
    })
    .strict()
]);
export type CatalogBatchOperation = z.infer<typeof CatalogBatchOperation>;

export const CatalogBatchMutation = z.object({
  operations: z.array(CatalogBatchOperation).min(1).max(128),
  expectedRevision: z.number().int().nonnegative()
}).strict();
export type CatalogBatchMutation = z.infer<typeof CatalogBatchMutation>;

export const SecretOperationAction = z.enum([
  "vaultStatus",
  "usagePolicy",
  "inspectReference",
  "checkReferenceExists",
  "sshCommand",
  "httpRequest",
  "apiRequest",
  "databaseQuery",
  "sftpTransfer",
  "ftpTransfer",
  "browserLogin",
  "localAppFill",
  "revealPlaintext",
  "copyPlaintext",
  "exportPlaintext",
  "deleteSecret",
  "changeSecretPolicy",
  "changeDestinationBinding",
  "changeAllowlist",
  "changeAuthorizationRules",
  "changeKeychain",
  "migrateMasterKey",
  "importRecoveryKey",
  "exportRecoveryKey",
  "restoreVault",
  "clearVault",
  "batchDelete",
  "resetVault",
  "localExecution",
  "trustedProcess"
]);
export type SecretOperationAction = z.infer<typeof SecretOperationAction>;

export const SecretOperationProtocol = z.enum([
  "ssh",
  "http",
  "https",
  "sftp",
  "scp",
  "ftp",
  "postgres",
  "mysql",
  "browser",
  "localApp",
  "file"
]);
export type SecretOperationProtocol = z.infer<typeof SecretOperationProtocol>;

// This is profile configuration, not a descriptor protocol. `http-loopback`
// opts a saved credential profile into HTTP only for loopback hosts; an Agent
// request cannot add it dynamically.
export const SecretAllowedProtocol = z.union([
  SecretOperationProtocol,
  z.literal("http-loopback")
]);
export type SecretAllowedProtocol = z.infer<typeof SecretAllowedProtocol>;

export const SSHCommandSpec = z
  .object({
    executable: z.string().min(1).max(128),
    arguments: z.array(z.string().max(4_096)).max(32).default([])
  })
  .strict();
export type SSHCommandSpec = z.infer<typeof SSHCommandSpec>;

export const SSHCommandBatch = z
  .object({
    commands: z.array(SSHCommandSpec).min(1).max(32),
    stopOnFailure: z.boolean().default(true)
  })
  .strict()
  .superRefine((value, context) => {
    const encodedBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    if (encodedBytes > 256 * 1024) {
      context.addIssue({
        code: z.ZodIssueCode.too_big,
        origin: "string",
        maximum: 256 * 1024,
        type: "string",
        inclusive: true,
        message: "SSH command batch exceeds the encoded size limit"
      });
    }
  });
export type SSHCommandBatch = z.infer<typeof SSHCommandBatch>;

export const SSHSessionStatus = z
  .object({
    sessionID: z.string().min(1).max(128),
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535),
    status: z.literal("active"),
    idleExpiresIn: z.number().finite().min(0).max(1_800)
  })
  .strict();
export type SSHSessionStatus = z.infer<typeof SSHSessionStatus>;

export const SecretOperationExecutionCapability = z.enum([
  "supported",
  "unavailable",
  "invalidParameters"
]);
export type SecretOperationExecutionCapability = z.infer<typeof SecretOperationExecutionCapability>;

export const SecretAdapterKind = z.enum([
  "ssh",
  "http",
  "database",
  "sftp",
  "ftp",
  "browser",
  "localApp",
  "export",
  "localExecution",
  "trustedProcess"
]);
export type SecretAdapterKind = z.infer<typeof SecretAdapterKind>;

export const SecretOperationCapability = z.object({
  version: z.number().int().positive().optional(),
  kind: SecretAdapterKind,
  status: SecretOperationExecutionCapability,
  operations: z.array(SecretOperationAction).max(32),
  reason: z.string().max(240).nullable().optional(),
  features: z.object({
    auth: z.array(z.string().max(64)).max(32),
    body: z.array(z.string().max(64)).max(32),
    response: z.array(z.string().max(64)).max(32),
    transportSessionReuse: z.boolean(),
    derivedCredentialCapture: z.boolean(),
    publicNetworkEgress: z.boolean(),
    insecurePrivateNetworkHTTPProfileOptIn: z.boolean()
  }).strict().optional()
}).strict();
export type SecretOperationCapability = z.infer<typeof SecretOperationCapability>;

export const SecretFileOperation = z.enum([
  "list",
  "read",
  "download",
  "upload",
  "write",
  "overwrite",
  "move",
  "delete"
]);
export type SecretFileOperation = z.infer<typeof SecretFileOperation>;

export const HTTPMethod = z.enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
export type HTTPMethod = z.infer<typeof HTTPMethod>;

export const HTTPAuthStrategy = z.object({
  kind: z.enum([
    "none",
    "basic",
    "bearer",
    "apiKeyHeader",
    "cookie",
    "customHeader",
    "oauth2ClientCredentials",
    "oauth2RefreshToken",
    "clientCertificate",
    "hmacSigning"
  ]),
  username: z.string().max(256).nullable().optional(),
  usernameReference: SecretReference.nullable().optional(),
  passwordReference: SecretReference.nullable().optional(),
  valueReference: SecretReference.nullable().optional(),
  headerName: z.string().max(128).nullable().optional(),
  scheme: z.string().max(64).nullable().optional(),
  cookieName: z.string().max(128).nullable().optional()
}).strict();
export type HTTPAuthStrategy = z.infer<typeof HTTPAuthStrategy>;

export const HTTPBody = z.object({
  kind: z.enum(["none", "raw", "json", "form"]),
  content: z.string().max(65_536).nullable().optional(),
  fields: z.record(z.string().max(256), z.string().max(4_096)).default({})
}).strict();
export type HTTPBody = z.infer<typeof HTTPBody>;

export const HTTPResponsePolicy = z.object({
  kind: z.enum(["metadataOnly", "sanitizedPreview", "structuredFields", "projectedJSON", "captureCredential"]),
  maxBytes: z.number().int().min(0).max(1_048_576).default(16_384),
  fields: z.array(z.string().min(1).max(128)).max(32).default([]),
  source: z.enum(["json", "header"]).nullable().optional(),
  selector: z.string().max(256).nullable().optional(),
  profileID: z.string().min(1).max(128).nullable().optional()
}).strict().superRefine((value, context) => {
  const isProjection = value.kind === "projectedJSON" || value.kind === "structuredFields";
  if (isProjection && (value.profileID === undefined || value.profileID === null || value.fields.length === 0)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["profileID"],
      message: "A profileID and at least one profile-approved field are required for JSON projection."
    });
  }
  if (!isProjection && (value.profileID !== undefined || value.fields.length > 0)) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["fields"],
      message: "Response fields are only valid for JSON projection."
    });
  }
});
export type HTTPResponsePolicy = z.infer<typeof HTTPResponsePolicy>;

export const HTTPOperation = z.object({
  method: HTTPMethod,
  auth: HTTPAuthStrategy,
  body: HTTPBody,
  responsePolicy: HTTPResponsePolicy,
  timeoutMs: z.number().int().min(100).max(30_000).nullable().optional()
}).strict();
export type HTTPOperation = z.infer<typeof HTTPOperation>;

export const DatabaseParameterValue = z.discriminatedUnion("type", [
  z.object({ type: z.literal("string"), value: z.string().max(4_096) }).strict(),
  z.object({ type: z.literal("integer"), value: z.number().int() }).strict(),
  z.object({ type: z.literal("double"), value: z.number().finite() }).strict(),
  z.object({ type: z.literal("boolean"), value: z.boolean() }).strict(),
  z.object({ type: z.literal("secretReference"), value: SecretReference }).strict(),
  z.object({ type: z.literal("null") }).strict()
]);
export type DatabaseParameterValue = z.infer<typeof DatabaseParameterValue>;

export const DatabaseParameter = z.object({
  name: z.string().min(1).max(128),
  value: DatabaseParameterValue
}).strict();
export type DatabaseParameter = z.infer<typeof DatabaseParameter>;

export const DatabaseOperation = z.object({
  engine: z.enum(["postgres", "mysql"]),
  database: z.string().min(1).max(256),
  username: z.string().max(256).nullable().optional(),
  usernameReference: SecretReference.nullable().optional(),
  passwordReference: SecretReference.nullable().optional(),
  statement: z.string().min(1).max(20_000),
  parameters: z.array(DatabaseParameter).max(64).default([]),
  maxRows: z.number().int().min(1).max(10_000).default(100),
  timeoutMs: z.number().int().min(100).max(30_000).nullable().optional()
}).strict();
export type DatabaseOperation = z.infer<typeof DatabaseOperation>;

export const FileTransferOperation = z.object({
  protocolType: z.enum(["sftp", "scp", "ftp"]),
  operation: SecretFileOperation,
  remotePath: z.string().min(1).max(4_096),
  localPath: z.string().max(4_096).nullable().optional(),
  localFileGrantID: z.string().max(128).nullable().optional(),
  username: z.string().max(256).nullable().optional(),
  usernameReference: SecretReference.nullable().optional(),
  passwordReference: SecretReference.nullable().optional()
}).strict();
export type FileTransferOperation = z.infer<typeof FileTransferOperation>;

export const BrowserLoginOperation = z.object({
  profileID: z.string().max(128).nullable().optional(),
  browser: z.string().max(32).nullable().optional(),
  url: z.string().url().nullable().optional(),
  username: z.string().max(256).nullable().optional(),
  usernameReference: SecretReference.nullable().optional(),
  passwordReference: SecretReference.nullable().optional(),
  usernameSelector: z.string().max(256).nullable().optional(),
  passwordSelector: z.string().max(256).nullable().optional(),
  submitSelector: z.string().max(256).nullable().optional(),
  submit: z.boolean()
}).strict();
export type BrowserLoginOperation = z.infer<typeof BrowserLoginOperation>;

export const LocalAppFillField = z.object({
  name: z.string().min(1).max(128),
  value: z.string().max(4_096).nullable().optional(),
  valueReference: SecretReference.nullable().optional()
}).strict();
export type LocalAppFillField = z.infer<typeof LocalAppFillField>;

export const LocalAppFillOperation = z.object({
  bundleID: z.string().min(1).max(256),
  fields: z.array(LocalAppFillField).max(64),
  submitButton: z.string().max(128).nullable().optional()
}).strict();
export type LocalAppFillOperation = z.infer<typeof LocalAppFillOperation>;

export const ExportOperation = z.object({
  kind: z.enum(["persistent", "ephemeral", "directDelivery"]),
  destinationRoot: z.string().max(1_024).nullable().optional(),
  overwrite: z.boolean(),
  secretReferences: UniqueSecretReferences.default([])
}).strict();
export type ExportOperation = z.infer<typeof ExportOperation>;

export const TrustedProcessOperation = z.object({
  profileID: z.string().min(1).max(128),
  arguments: z.array(z.string().max(4_096)).max(32).default([]),
  secretReferences: UniqueSecretReferences.default([])
}).strict();
export type TrustedProcessOperation = z.infer<typeof TrustedProcessOperation>;

export const LocalExecutionOperation = z.object({
  executable: z.string().min(1).max(4_096),
  arguments: z.array(z.string().max(4_096)).max(32).default([]),
  secretReferences: NonEmptyUniqueSecretReferences
}).strict();
export type LocalExecutionOperation = z.infer<typeof LocalExecutionOperation>;

export const SecretOperationPayload = z.discriminatedUnion("type", [
  z.object({ type: z.literal("http"), operation: HTTPOperation }).strict(),
  z.object({ type: z.literal("database"), operation: DatabaseOperation }).strict(),
  z.object({ type: z.literal("fileTransfer"), operation: FileTransferOperation }).strict(),
  z.object({ type: z.literal("browser"), operation: BrowserLoginOperation }).strict(),
  z.object({ type: z.literal("localApp"), operation: LocalAppFillOperation }).strict(),
  z.object({ type: z.literal("export"), operation: ExportOperation }).strict(),
  z.object({ type: z.literal("localExecution"), operation: LocalExecutionOperation }).strict(),
  z.object({ type: z.literal("trustedProcess"), operation: TrustedProcessOperation }).strict()
]);
export type SecretOperationPayload = z.infer<typeof SecretOperationPayload>;

export const SecretOperationDescriptor = z
  .object({
    actionType: SecretOperationAction,
    secretReferences: UniqueSecretReferences,
    destination: z.string().nullable().optional(),
    port: z.number().int().nullable().optional(),
    protocolType: SecretOperationProtocol.nullable().optional(),
    command: z.string().nullable().optional(),
    httpMethod: z.string().nullable().optional(),
    url: z.string().nullable().optional(),
    databaseStatement: z.string().nullable().optional(),
    fileOperation: SecretFileOperation.nullable().optional(),
    fileTarget: z.string().nullable().optional(),
    localAppBundleID: z.string().nullable().optional(),
    sessionID: z.string().min(1).max(128).nullable().optional(),
    sshCommandBatch: SSHCommandBatch.nullable().optional(),
    payload: SecretOperationPayload.nullable().optional(),
    requestedEffects: z.array(z.string()),
    parameters: z.record(z.string(), z.string()),
    reviewID: z.string().uuid().optional(),
    agentAssessment: AgentRiskAssessment
  })
  .strict();
export type SecretOperationDescriptor = z.infer<typeof SecretOperationDescriptor>;

export const IpcRequest = z.discriminatedUnion("type", [
  z.object({ type: z.literal("status") }).strict(),
  z.object({ type: z.literal("workbenchStatus") }).strict(),
  z.object({ type: z.literal("secretOperationCapabilities") }).strict(),
  z
    .object({
      type: z.literal("reviewSSHHostKey"),
      host: SSHHost,
      port: z.number().int().min(1).max(65_535)
    })
    .strict(),
  z
    .object({
      type: z.literal("sshSessionStatus"),
      sessionID: z.string().min(1).max(128).optional()
    })
    .strict(),
  z
    .object({
      type: z.literal("sshSessionClose"),
      sessionID: z.string().min(1).max(128)
    })
    .strict(),
  z
    .object({
      type: z.literal("searchCatalog"),
      query: z.string().trim().min(1).max(256),
      field: SecretCatalogField.optional(),
      limit: z.number().int().min(1).max(20).default(10)
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogSearch"),
      query: z.string().trim().min(1).max(256),
      field: SecretCatalogField.optional(),
      limit: z.number().int().min(1).max(20).default(10)
    })
    .strict(),
  z.object({ type: z.literal("catalogGet"), entryID: z.string().length(26) }).strict(),
  z.object({ type: z.literal("catalogListIndexes") }).strict(),
  z.object({ type: z.literal("catalogListEntries"), indexID: z.string().length(26) }).strict(),
  z
    .object({
      type: z.literal("catalogCreateIndex"),
      title: z.string().min(1).max(2000),
      aliases: z.array(z.string()).max(64).default([]),
      tags: z.array(z.string()).max(64).default([])
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateEntry"),
      request: CatalogDraftRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateStructure"),
      request: CatalogCreateStructureRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCreateDraft"),
      request: CatalogDraftRequest
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogPatchMetadata"),
      entryID: z.string().length(26),
      patch: CatalogMetadataPatch,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogCommit"),
      draft: CatalogDraft,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogAddSecretPlaceholder"),
      entryID: z.string().length(26),
      key: z.string().min(1),
      label: z.string().min(1),
      agentVisible: z.boolean().default(true),
      searchable: z.boolean().default(true),
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogBindExistingSecret"),
      entryID: z.string().length(26),
      key: z.string().min(1),
      secretRef: SecretReference,
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogApplyBatch"),
      mutation: z.object({ operations: z.array(CatalogBatchOperation).min(1).max(128) }).strict(),
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogRequestSecureInputs"),
      entryID: z.string().length(26),
      targets: z.array(CatalogSecureInputTargetRequest).min(1).max(32),
      expectedRevision: z.number().int().nonnegative()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogSecureInputStatus"),
      requestID: z.string().uuid()
    })
    .strict(),
  z.object({ type: z.literal("catalogValidate") }).strict(),
  z.object({ type: z.literal("catalogFilePreflight") }).strict(),
  z.object({ type: z.literal("catalogRequestWriteAccess"), request: CatalogAgentWriteAccessRequest }).strict(),
  z
    .object({
      type: z.literal("inspectReference"),
      reference: SecretReference
    })
    .strict(),
  z
    .object({
      type: z.literal("reveal"),
      reference: SecretReference,
      reason: z.string().min(1)
    })
    .strict(),
  z
    .object({
      type: z.literal("encrypt"),
      label: z.string().nullable().optional(),
      policy: SecretPolicy
    })
    .strict(),
  z
    .object({
      type: z.literal("encryptBound"),
      label: z.string().nullable().optional(),
      policy: SecretPolicy,
      allowedDestinations: z.array(z.string().min(1)).max(32),
      allowedProtocols: z.array(SecretAllowedProtocol).max(16)
    })
    .strict(),
  z
    .object({
      type: z.literal("revealReferences"),
      references: NonEmptyUniqueSecretReferences,
      context: RevealContext
    })
    .strict(),
  z
    .object({
      type: z.literal("exportResolvedText"),
      references: NonEmptyUniqueSecretReferences,
      context: RevealContext,
      destinationPath: z.string().min(1)
    })
    .strict(),
  z
    .object({
      type: z.literal("scanOrphans"),
      markdownReferences: UniqueSecretReferences
    })
    .strict(),
  z
    .object({
      type: z.literal("preflightSecretOperation"),
      descriptor: SecretOperationDescriptor
    })
    .strict(),
  z
    .object({
      type: z.literal("executeSecretOperation"),
      descriptor: SecretOperationDescriptor
    })
    .strict(),
  z
    .object({
      type: z.literal("startSecretOperation"),
      descriptor: SecretOperationDescriptor
    })
    .strict(),
  z
    .object({
      type: z.literal("startSecretOperationIdempotent"),
      descriptor: SecretOperationDescriptor,
      idempotencyKey: z.string().min(1).max(128)
    })
    .strict(),
  z.object({ type: z.literal("secretOperationStatus"), operationID: z.string().uuid() }).strict(),
  z
    .object({
      type: z.literal("secretOperationOutput"),
      operationID: z.string().uuid(),
      cursor: z.number().int().nonnegative(),
      maxChunks: z.number().int().min(1).max(64)
    })
    .strict(),
  z.object({ type: z.literal("cancelSecretOperation"), operationID: z.string().uuid() }).strict()
]);
export type IpcRequest = z.infer<typeof IpcRequest>;

export const AuthenticatedIpcRequest = z
  .object({
    capabilityToken: CapabilityToken,
    caller: AgentCallerIdentity.optional(),
    request: IpcRequest
  })
  .strict();
export type AuthenticatedIpcRequest = z.infer<typeof AuthenticatedIpcRequest>;

export const SecretOperationStage = z.enum([
  "FRAME_READ",
  "FRAME_DECODE",
  "ARGUMENT_VALIDATION",
  "AUTHENTICATION",
  "TIMEOUT",
  "CONNECTION",
  "HOST_KEY",
  "SSH_WRAPPER",
  "REMOTE_COMMAND"
]);
export type SecretOperationStage = z.infer<typeof SecretOperationStage>;

export const SecretOperationOutput = z
  .object({
    status: z.string().min(1),
    exitCode: z.number().int().optional(),
    stage: SecretOperationStage.optional(),
    stdout: z.string().optional(),
    stderr: z.string().optional(),
    httpStatus: z.number().int().optional(),
    contentType: z.string().nullable().optional(),
    bodyPreview: z.string().optional(),
    redirectLocation: z.string().url().optional(),
    rowCount: z.number().int().min(0).optional(),
    rowsPreview: z.string().optional(),
    listingPreview: z.string().optional(),
    localPath: z.string().optional(),
    remotePath: z.string().optional(),
    destination: z.string().min(1).optional(),
    protocolType: z.string().min(1).max(32).optional(),
    port: z.number().int().min(1).max(65_535).optional(),
    hostKeyPin: SSHHostKeyPin.optional(),
    sessionID: z.string().min(1).max(128).optional(),
    failedIndex: z.number().int().min(0).optional(),
    results: z.array(z.object({
      index: z.number().int().min(0),
      status: z.string().min(1),
      exitCode: z.number().int().optional(),
      stage: SecretOperationStage.optional(),
      stdout: z.string().optional(),
      stderr: z.string().optional()
    }).strict()).max(32).optional(),
    redacted: z.literal(true)
  })
  .strict();
export type SecretOperationOutput = z.infer<typeof SecretOperationOutput>;

export const SecretOperationState = z.enum([
  "queued",
  "awaitingApproval",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "outcomeUnknown"
]);
export type SecretOperationState = z.infer<typeof SecretOperationState>;

export const SecretOperationHandle = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  reused: z.boolean().optional()
}).strict();
export type SecretOperationHandle = z.infer<typeof SecretOperationHandle>;

export const SecretOperationStatus = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  output: SecretOperationOutput.nullable().optional(),
  errorCode: z.string().min(1).max(128).nullable().optional(),
  nextOutputCursor: z.number().int().nonnegative().optional()
}).strict();
export type SecretOperationStatus = z.infer<typeof SecretOperationStatus>;

export const SecretOperationOutputChunk = z.object({
  cursor: z.number().int().nonnegative(),
  stream: z.enum(["stdout", "stderr"]),
  text: z.string(),
  commandIndex: z.number().int().nonnegative().nullable().optional()
}).strict();
export type SecretOperationOutputChunk = z.infer<typeof SecretOperationOutputChunk>;

export const SecretOperationOutputPage = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  cursor: z.number().int().nonnegative(),
  nextCursor: z.number().int().nonnegative(),
  chunks: z.array(SecretOperationOutputChunk).max(64),
  hasMore: z.boolean()
}).strict();
export type SecretOperationOutputPage = z.infer<typeof SecretOperationOutputPage>;

export const RevealSessionOpened = z.object({
  type: z.literal("revealSessionOpened"),
  sessionID: z.string().min(1)
}).strict();
export type RevealSessionOpened = z.infer<typeof RevealSessionOpened>;

export const IpcResponse = z.discriminatedUnion("type", [
  z
    .object({
      type: z.literal("status"),
      locked: z.boolean()
    })
    .strict(),
  z
    .object({
      type: z.literal("workbenchStatus"),
      status: WorkbenchStatus
    })
    .strict(),
  z
    .object({
      type: z.literal("secretOperationCapabilities"),
      capabilities: z.array(SecretOperationCapability).max(32)
    })
    .strict(),
  z
    .object({
      type: z.literal("sshHostKeyReview"),
      review: SSHHostKeyReview
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogSearchResult"),
      result: SecretCatalogSearchResult
    })
    .strict(),
  z.object({ type: z.literal("catalogIndexListResult"), result: CatalogIndexListResult }).strict(),
  z.object({ type: z.literal("catalogEntryListResult"), result: CatalogEntryListResult }).strict(),
  z.object({ type: z.literal("catalogDraft"), draft: CatalogDraft }).strict(),
  z.object({ type: z.literal("catalogWriteResult"), result: CatalogWriteResult }).strict(),
  z.object({ type: z.literal("catalogStructureWriteResult"), result: CatalogStructureWriteResult }).strict(),
  z.object({ type: z.literal("catalogSecureInputStatus"), status: CatalogSecureInputStatus }).strict(),
  z
    .object({
      type: z.literal("catalogValidation"),
      catalogStatus: z.enum(["FOUND", "NOT_FOUND", "INVALID_QUERY", "CATALOG_UNAVAILABLE", "LEGACY_CATALOG_UNSUPPORTED", "INTEGRITY_MISSING", "EXTERNAL_CATALOG_MODIFICATION", "PENDING_EXTERNAL_CHANGE", "CATALOG_INVALID"]),
      revision: z.number().int().nonnegative().nullable().optional(),
      rawSHA256: z.string().regex(/^[0-9a-f]{64}$/).nullable().optional(),
      diagnostics: z.array(CatalogValidationDiagnostic).default([]),
      filePreflight: CatalogFilePreflight.optional()
    })
    .strict(),
  z
    .object({
      type: z.literal("catalogFilePreflight"),
      filePreflight: CatalogFilePreflight
    })
    .strict(),
  z
    .object({
      type: z.literal("referenceMetadata"),
      metadata: SecretReferenceMetadata
    })
    .strict(),
  z.object({ type: z.literal("displayedToUser") }).strict(),
  z
    .object({
      type: z.literal("created"),
      reference: SecretReference
    })
    .strict(),
  RevealSessionOpened,
  z.object({ type: z.literal("exported"), path: z.string().min(1) }).strict(),
  z
    .object({
      type: z.literal("orphanScan"),
      result: OrphanScanResult
    })
    .strict(),
  z
    .object({
      type: z.literal("secretOperation"),
      output: SecretOperationOutput
    })
    .strict(),
  z.object({ type: z.literal("secretOperationPreflight"), result: SecretOperationPreflight }).strict(),
  z.object({ type: z.literal("secretOperationHandle"), result: SecretOperationHandle }).strict(),
  z.object({ type: z.literal("secretOperationStatus"), result: SecretOperationStatus }).strict(),
  z.object({ type: z.literal("secretOperationOutput"), result: SecretOperationOutputPage }).strict(),
  z
    .object({
      type: z.literal("sshSessionStatus"),
      sessions: z.array(SSHSessionStatus).max(32)
    })
    .strict(),
  z.object({ type: z.literal("operationCompleted") }).strict(),
  z
    .object({
      type: z.literal("failure"),
      code: z.string().min(1)
    })
    .strict()
]);
export type IpcResponse = z.infer<typeof IpcResponse>;

export class IpcFrameCodec {
  static encode(value: unknown): Buffer {
    const payload = Buffer.from(JSON.stringify(value), "utf8");
    if (payload.byteLength > MAX_FRAME_BYTES) {
      throw new Error("IPC frame too large");
    }

    const frame = Buffer.allocUnsafe(4 + payload.byteLength);
    frame.writeUInt32BE(payload.byteLength, 0);
    payload.copy(frame, 4);
    return frame;
  }

  static decode<T>(frame: Buffer, schema: z.ZodType<T>): T {
    if (frame.byteLength < 4) {
      throw new Error("incomplete IPC frame");
    }

    const payloadLength = frame.readUInt32BE(0);
    if (payloadLength > MAX_FRAME_BYTES) {
      throw new Error("IPC frame too large");
    }

    const actualLength = frame.byteLength - 4;
    if (actualLength !== payloadLength) {
      throw new Error(`IPC frame length mismatch: expected ${payloadLength}, got ${actualLength}`);
    }

    return schema.parse(JSON.parse(frame.subarray(4).toString("utf8")));
  }
}
