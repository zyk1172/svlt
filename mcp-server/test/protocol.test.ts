import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  AgentCallerIdentity,
  AuthenticatedIpcRequest,
  CapabilityToken,
  CatalogCreateEntryRequest,
  CatalogCreateStructureRequest,
  IpcFrameCodec,
  IpcRequest,
  IpcResponse
} from "../src/protocol.js";
import {
  LocalIpcClient,
  appSupportIpcPaths
} from "../src/client.js";

const validReference = "secret://0123456789ABCDEFGHJKMNPQRS";
const validIndexID = "0123456789ABCDEFGHJKMNPQRT";
const validEntryID = "0123456789ABCDEFGHJKMNPQRV";
const validToken = Buffer.alloc(32, 0x4d).toString("base64");
const lifecycleDescriptor = {
  actionType: "sshCommand",
  secretReferences: [validReference],
  destination: "qnap.local",
  port: 22,
  protocolType: "ssh",
  command: "hostname",
  requestedEffects: ["read-only"],
  parameters: { passwordRef: validReference, username: "admin" },
  agentAssessment: {
    source: "mainAgent",
    declaredRisk: "silent",
    reason: "read-only diagnostic",
    userGoal: "read status",
    taskContext: "read-only diagnostic",
    intendedEffect: "read status",
    expectedEffect: "read status",
    expectedResult: "read status",
    intentAlignment: "direct",
    effectSeverity: "none",
    reversibility: "readOnly",
    secretHandling: "credentialUse",
    executionRecommendation: "automatic",
    confidence: 0.9
  }
};



const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true })
    )
  );
});

describe("IPC response schema", () => {
  it("accepts every Swift IPCResponse case", () => {
    const fixtures = [
      { type: "status", locked: false },
      {
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          available: true,
          ready: true,
          approvalPending: false,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        }
      },
      {
        type: "catalogSearchResult",
        result: {
          status: "FOUND",
          matches: [
            {
              index: {
                id: validIndexID,
                title: "QNAP",
                aliases: ["NAS"],
                tags: ["设备"]
              },
              entry: {
                id: validEntryID,
                indexId: validIndexID,
                title: "QNAP 管理后台登录",
                type: "credential",
                aliases: ["QNAP 登录"],
                endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
                fields: [
                  { key: "username", label: "用户名", type: "text", value: "admin" },
                  { key: "password", label: "密码", type: "secret", secretRef: validReference }
                ],
                notes: "媒体管理",
                tags: ["QNAP"]
              }
            }
          ]
        }
      },
      {
        type: "catalogIndexListResult",
        result: {
          status: "FOUND",
          revision: 47,
          indices: [
            { id: validIndexID, title: "QNAP", aliases: [], tags: ["设备"], entryCount: 2 },
            { id: validEntryID, title: "空分组", aliases: [], tags: [], entryCount: 0 }
          ]
        }
      },
      {
        type: "catalogEntryListResult",
        result: {
          status: "FOUND",
          revision: 47,
          indexID: validIndexID,
          entries: []
        }
      },
      {
        type: "catalogDraft",
        draft: {
          draftID: validEntryID,
          baseRevision: 1,
          entry: {
            id: validEntryID,
            indexId: validIndexID,
            title: "Komga",
            type: "credential",
            aliases: [],
            endpoints: [],
            fields: [{ key: "password", label: "密码", type: "secret" }],
            tags: []
          }
        }
      },
      { type: "catalogWriteResult", result: { revision: 2, entry: null } },
      {
        type: "catalogStructureWriteResult",
        result: {
          indexID: validIndexID,
          entries: [{ clientKey: "postgres", entryID: validEntryID }],
          revision: 3,
          validation: { status: "FOUND", revision: 3, diagnostics: [] }
        }
      },
      {
        type: "catalogSecureInputStatus",
        status: {
          requestID: "00000000-0000-4000-8000-000000000023",
          status: "PENDING"
        }
      },
      { type: "catalogValidation", catalogStatus: "FOUND", revision: 2, diagnostics: [] },
      {
        type: "catalogFilePreflight",
        filePreflight: {
          read: "READ_OK",
          parentTempCreate: "PARENT_TEMP_CREATE_OK",
          parentTempFsync: "PARENT_TEMP_FSYNC_OK",
          parentRename: "PARENT_RENAME_OK",
          parentFsync: "PARENT_FSYNC_OK"
        }
      },
      {
        type: "referenceMetadata",
        metadata: {
          reference: validReference,
          policy: "read",
          label: "NAS password",
          allowedDestinations: [],
          allowedProtocols: [],
          allowedBindings: [],
          createdAt: 1,
          updatedAt: 2
        }
      },
      { type: "displayedToUser" },
      { type: "created", reference: validReference },
      { type: "revealSessionOpened", sessionID: "session-1" },
      { type: "exported", path: "/Users/example/Desktop/NAS.md" },
      { type: "orphanScan", result: { missingRecords: [], unreferencedRecords: [] } },
      {
        type: "secretOperation",
        output: {
          status: "COMPLETED",
          httpStatus: 200,
          contentType: "application/json",
          bodyPreview: "{\"status\":\"ok\"}",
          redacted: true
        }
      },
      {
        type: "secretOperation",
        output: {
          status: "REDIRECT_REQUIRES_REVIEW",
          httpStatus: 302,
          redirectLocation: "https://qnap.local/next",
          redacted: true
        }
      },
      {
        type: "secretOperationHandle",
        result: {
          operationID: "00000000-0000-4000-8000-000000000001",
          state: "queued",
          reused: false
        }
      },
      {
        type: "secretOperationStatus",
        result: {
          operationID: "00000000-0000-4000-8000-000000000001",
          state: "running",
          nextOutputCursor: 1
        }
      },
      {
        type: "secretOperationOutput",
        result: {
          operationID: "00000000-0000-4000-8000-000000000001",
          state: "running",
          cursor: 0,
          nextCursor: 1,
          chunks: [{ cursor: 0, stream: "stdout", text: "ready\n", commandIndex: 0 }],
          hasMore: false
        }
      },
      {
        type: "sshSessionStatus",
        sessions: [{
          sessionID: "ssh_session_test",
          host: "qnap.local",
          port: 22,
          status: "active",
          idleExpiresIn: 299
        }]
      },
      { type: "failure", code: "APP_UNAVAILABLE" }
    ];

    for (const fixture of fixtures) {
      expect(IpcResponse.parse(fixture)).toEqual(fixture);
    }
  });

  it("rejects plaintext-shaped fields", () => {
    expect(() => IpcResponse.parse({ plaintext: "leak" })).toThrow();
    expect(() =>
      IpcResponse.parse({ type: "created", reference: validReference, plaintext: "leak" })
    ).toThrow();
    expect(() =>
      IpcResponse.parse({
        type: "workbenchStatus",
        status: {
          locked: false,
          ipcAvailable: true,
          available: true,
          ready: true,
          approvalPending: false,
          activeKnowledgeBaseRoot: null,
          pluginConnected: true
        },
        plaintext: "leak"
      })
    ).toThrow();
  });

  it("accepts a staged, redacted secret operation diagnostic", () => {
    const fixture = {
      type: "secretOperation",
      output: {
        status: "WRAPPER_FAILED",
        exitCode: 122,
        stage: "FRAME_DECODE",
        stderr: "invalid framed input",
        redacted: true
      }
    };

    expect(IpcResponse.parse(fixture)).toEqual(fixture);
  });

  it("keeps catalog search responses metadata-only", () => {
    const response = IpcResponse.parse({
      type: "catalogSearchResult",
      result: {
        status: "FOUND",
        matches: [{
          index: { id: validIndexID, title: "QNAP", aliases: [], tags: [] },
          entry: {
            id: validEntryID,
            indexId: validIndexID,
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: [],
            endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
            fields: [{ key: "password", label: "密码", type: "secret", secretRef: validReference }],
            notes: "媒体管理",
            tags: []
          }
        }]
      }
    });
    expect(JSON.stringify(response)).not.toContain("plaintext");
    expect(JSON.stringify(response)).not.toContain("sensitive-index-selection");
    expect(() => IpcResponse.parse({
      type: "catalogSearchResult",
      result: {
        status: "FOUND",
        matches: [{
          index: { id: validIndexID, title: "QNAP", aliases: [], tags: [] },
          entry: {
            id: validEntryID,
            indexId: validIndexID,
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: [],
            endpoints: [],
            fields: [{ key: "password", label: "密码", type: "secret", secretRef: validReference }],
            notes: null,
            tags: [],
            plaintext: "leak"
          }
        }]
      }
    })).toThrow();
  });

  it("accepts Swift's omitted optional field metadata", () => {
    const response = IpcResponse.parse({
      type: "catalogSearchResult",
      result: {
        status: "FOUND",
        matches: [{
          index: { id: validIndexID, title: "QNAP", aliases: [], tags: [] },
          entry: {
            id: validEntryID,
            indexId: validIndexID,
            title: "QNAP",
            type: "credential",
            aliases: [],
            endpoints: [],
            fields: [{ key: "password", label: "密码", type: "secret", secretRef: validReference }],
            tags: []
          }
        }]
      }
    });
    expect(response.type).toBe("catalogSearchResult");
  });
});

describe("IPC request schema", () => {
  it("rejects legacy plaintext and generic execution request shapes", () => {
    expect(() =>
      IpcRequest.parse({
        type: "encryptText",
        plaintext: "leak",
        label: null,
        policy: "credential"
      })
    ).toThrow();
    expect(() =>
      IpcRequest.parse({
        type: "restoreReferences",
        references: [validReference],
        context: {
          reason: "legacy",
          template: "{{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      })
    ).toThrow();
    expect(() =>
      IpcResponse.parse({ type: "restoredText", text: "leak" })
    ).toThrow();
  });

  it("accepts every public non-plaintext IPCRequest case", () => {
    const fixtures = [
      { type: "status" },
      { type: "workbenchStatus" },
      { type: "sshSessionStatus" },
      { type: "sshSessionStatus", sessionID: "ssh_session_test" },
      { type: "sshSessionClose", sessionID: "ssh_session_test" },
      { type: "searchCatalog", query: "QNAP", field: "password", limit: 10 },
      { type: "catalogSearch", query: "QNAP", limit: 10 },
      { type: "catalogGet", entryID: validEntryID },
      { type: "catalogListIndexes" },
      { type: "catalogListEntries", indexID: validIndexID },
      {
        type: "catalogCreateIndex",
        title: "QNAP",
        aliases: ["NAS"],
        tags: ["设备"]
      },
      {
        type: "catalogCreateEntry",
        request: {
          indexID: validIndexID,
          title: "音乐服务器",
          type: "credential",
          aliases: ["音乐"],
          tags: ["QNAP"],
          endpoints: [{ type: "http", host: "192.168.2.240", port: 4533 }],
          fields: [
            {
              key: "username",
              label: "用户名",
              type: "text",
              agentVisible: true,
              searchable: true,
              value: "zyk"
            },
            {
              key: "password",
              label: "密码",
              type: "secret",
              agentVisible: true,
              searchable: false
            }
          ]
        }
      },
      {
        type: "catalogCreateStructure",
        request: {
          index: { title: "数据库", aliases: [], tags: [] },
          entries: [{
            clientKey: "postgres",
            title: "PostgreSQL",
            type: "credential",
            aliases: [],
            tags: [],
            endpoints: [{ type: "postgresql", host: "db.home", port: 5432 }],
            fields: [{ key: "password", label: "密码", type: "secret", agentVisible: true, searchable: true }]
          }]
        }
      },
      {
        type: "catalogRequestWriteAccess",
        request: {
          id: "00000000-0000-4000-8000-000000000001",
          source: "mcp-client",
          reasonCategory: "bulk-import",
          duration: "single-use",
          createdAt: "2026-08-27T12:00:00.000Z",
          intent: {
            requestID: "00000000-0000-4000-8000-000000000001",
            operation: "createStructure",
            indexID: validIndexID,
            acceptedRevision: 47,
            candidateSemanticSHA256: "a".repeat(64)
          },
          expiresAt: "2026-08-27T12:01:00.000Z"
        }
      },
      {
        type: "catalogCreateDraft",
        request: {
          indexID: validIndexID,
          title: "Komga",
          type: "credential",
          aliases: [],
          tags: [],
          endpoints: [],
          fields: [{ key: "password", label: "密码", type: "secret", agentVisible: true, searchable: true }]
        }
      },
      {
        type: "catalogPatchMetadata",
        entryID: validEntryID,
        patch: { title: "Komga" },
        expectedRevision: 1
      },
      {
        type: "catalogCommit",
        draft: {
          draftID: validEntryID,
          baseRevision: 1,
          entry: {
            id: validEntryID,
            indexId: validIndexID,
            title: "Komga",
            type: "credential",
            aliases: [],
            endpoints: [],
            fields: [{ key: "password", label: "密码", type: "secret" }],
            tags: []
          }
        },
        expectedRevision: 1
      },
      {
        type: "catalogAddSecretPlaceholder",
        entryID: validEntryID,
        key: "token",
        label: "Token",
        agentVisible: true,
        searchable: true,
        expectedRevision: 1
      },
      {
        type: "catalogBindExistingSecret",
        entryID: validEntryID,
        key: "password",
        secretRef: validReference,
        expectedRevision: 1
      },
      {
        type: "catalogRequestSecureInputs",
        entryID: validEntryID,
        targets: [{
          entryID: validEntryID,
          fieldKey: "password",
          mode: "replaceSecret",
          required: true
        }],
        expectedRevision: 1
      },
      {
        type: "catalogSecureInputStatus",
        requestID: "00000000-0000-4000-8000-000000000024"
      },
      { type: "catalogValidate" },
      { type: "inspectReference", reference: validReference },
      { type: "reveal", reference: validReference, reason: "show to user" },
      { type: "encrypt", label: "api token", policy: "externalSend" },
      {
        type: "encryptBound",
        label: "QNAP credential",
        policy: "credential",
        allowedDestinations: ["qnap.local", "192.168.2.240"],
        allowedProtocols: ["ssh", "https", "http-loopback"]
      },
      {
        type: "revealReferences",
        references: [validReference],
        context: {
          reason: "Paragraph reveal",
          template: "Token: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      {
        type: "exportResolvedText",
        references: [validReference],
        destinationPath: "/Users/example/Desktop/NAS.md",
        context: {
          reason: "App writes local file",
          template: "NAS password: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      { type: "scanOrphans", markdownReferences: [validReference] },
      { type: "startSecretOperation", descriptor: lifecycleDescriptor },
      {
        type: "startSecretOperationIdempotent",
        descriptor: lifecycleDescriptor,
        idempotencyKey: "job-001"
      },
      {
        type: "secretOperationStatus",
        operationID: "00000000-0000-4000-8000-000000000001"
      },
      {
        type: "secretOperationOutput",
        operationID: "00000000-0000-4000-8000-000000000001",
        cursor: 0,
        maxChunks: 16
      },
      {
        type: "cancelSecretOperation",
        operationID: "00000000-0000-4000-8000-000000000001"
      },
      {
        type: "executeSecretOperation",
        descriptor: {
          actionType: "sshCommand",
          secretReferences: [validReference],
          destination: "qnap.local",
          port: 22,
          protocolType: "ssh",
          command: "hostname",
          requestedEffects: ["read-only"],
          parameters: { passwordRef: validReference },
          agentAssessment: {
            source: "mainAgent",
            declaredRisk: "silent",
            reason: "read-only diagnostic",
            userGoal: "read status",
            taskContext: "read-only diagnostic",
            intendedEffect: "read status",
            expectedEffect: "read status",
            expectedResult: "read status",
            intentAlignment: "direct",
            effectSeverity: "none",
            reversibility: "readOnly",
            secretHandling: "credentialUse",
            executionRecommendation: "automatic",
            confidence: 0.9
          }
        }
      },
      {
        type: "executeSecretOperation",
        descriptor: {
          actionType: "sshCommand",
          secretReferences: [validReference],
          destination: "qnap.local",
          port: 22,
          protocolType: "ssh",
          sessionID: "ssh_session_test",
          sshCommandBatch: {
            commands: [
              { executable: "whoami", arguments: [] },
              { executable: "df", arguments: ["-h", "/share/a b"] }
            ],
            stopOnFailure: true
          },
          requestedEffects: ["ssh-batch"],
          parameters: { passwordRef: validReference, username: "zyk" },
          agentAssessment: {
            source: "mainAgent",
            declaredRisk: "silent",
            reason: "read-only diagnostic",
            userGoal: "inspect status",
            taskContext: "read-only diagnostic",
            intendedEffect: "inspect status",
            expectedEffect: "inspect status",
            expectedResult: "inspect status",
            intentAlignment: "direct",
            effectSeverity: "none",
            reversibility: "readOnly",
            secretHandling: "credentialUse",
            executionRecommendation: "automatic",
            confidence: 0.9
          }
        }
      }
    ];

    for (const fixture of fixtures) {
      expect(IpcRequest.parse(fixture)).toEqual(fixture);
    }
  });

  it("rejects empty and unbounded catalog queries", () => {
    expect(() => IpcRequest.parse({ type: "searchCatalog", query: "   " })).toThrow();
    expect(() => IpcRequest.parse({ type: "searchCatalog", query: "QNAP", limit: 21 })).toThrow();
    expect(IpcRequest.parse({ type: "searchCatalog", query: " QNAP " })).toEqual({
      type: "searchCatalog",
      query: "QNAP",
      limit: 10
    });
  });

  it("rejects plaintext or conflicting catalog field shapes", () => {
    const base = {
      indexID: validIndexID,
      title: "QNAP",
      fields: []
    };
    expect(() => IpcRequest.parse({
      type: "catalogCreateDraft",
      request: {
        ...base,
        fields: [{ key: "password", label: "密码", type: "secret", value: "plaintext" }]
      }
    })).toThrow();
    expect(() => IpcRequest.parse({
      type: "catalogPatchMetadata",
      entryID: validEntryID,
      patch: {
        fields: [{ key: "username", label: "用户名", type: "text", value: "admin", secretRef: validReference }]
      },
      expectedRevision: 1
    })).toThrow();
  });

  it("reports duplicate field keys at the exact input path", () => {
    const result = CatalogCreateEntryRequest.safeParse({
      indexID: validIndexID,
      title: "重复字段",
      fields: [
        { key: "host", label: "主机", type: "text", value: "db.home" },
        { key: "host", label: "备用主机", type: "text", value: "db2.home" }
      ]
    });
    expect(result.success).toBe(false);
    if (result.success) return;
    expect(result.error.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ path: ["fields", 1, "key"] })
    ]));
  });

  it("accepts empty secret placeholders and non-http endpoint types", () => {
    const request = CatalogCreateStructureRequest.parse({
      index: { title: "数据库" },
      entries: [{
        clientKey: "postgres",
        title: "PostgreSQL",
        endpoints: [{ type: "postgresql", host: "db.home", port: 5432 }],
        fields: [{ key: "password", label: "API Key", type: "secret" }]
      }]
    });
    expect(request.entries[0]?.fields[0]?.value).toBeUndefined();
    expect(() => CatalogCreateStructureRequest.parse({
      index: { title: "数据库" },
      entries: [{
        clientKey: "postgres",
        title: "PostgreSQL",
        fields: [{ key: "password", label: "密码", type: "secret", value: "" }]
      }]
    })).toThrow();
  });
});

describe("authenticated IPC request schema", () => {
  it("requires a base64 encoded 256-bit capability token", () => {
    const valid = AuthenticatedIpcRequest.parse({
      capabilityToken: validToken,
      request: { type: "status" }
    });

    expect(valid.capabilityToken).toBe(validToken);
    expect(() =>
      AuthenticatedIpcRequest.parse({
        capabilityToken: Buffer.alloc(31, 0x00).toString("base64"),
        request: { type: "status" }
      })
    ).toThrow();
  });

  it("accepts authenticated workbench request cases", () => {
    const requests = [
      { type: "workbenchStatus" },
      { type: "searchCatalog", query: "NAS", limit: 10 },
      { type: "inspectReference", reference: validReference },
      {
        type: "encryptBound",
        label: "QNAP credential",
        policy: "credential",
        allowedDestinations: ["qnap.local"],
        allowedProtocols: ["ssh"]
      },
      {
        type: "revealReferences",
        references: [validReference],
        context: {
          reason: "Paragraph reveal",
          template: "Token: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      {
        type: "exportResolvedText",
        references: [validReference],
        destinationPath: "/Users/example/Desktop/NAS.md",
        context: {
          reason: "App writes local file",
          template: "NAS password: {{0}}",
          ranges: [{ index: 0, placeholder: "{{0}}" }]
        }
      },
      { type: "scanOrphans", markdownReferences: [validReference] },
      {
        type: "executeSecretOperation",
        descriptor: {
          actionType: "httpRequest",
          secretReferences: [validReference],
          destination: "qnap.local",
          port: null,
          protocolType: "https",
          httpMethod: "GET",
          url: "https://qnap.local/status",
          requestedEffects: ["read-only"],
          parameters: { passwordRef: validReference },
          agentAssessment: {
            source: "mainAgent",
            declaredRisk: "silent",
            reason: "read-only diagnostic",
            userGoal: "read status",
            taskContext: "read-only diagnostic",
            intendedEffect: "read status",
            expectedEffect: "read status",
            expectedResult: "read status",
            intentAlignment: "direct",
            effectSeverity: "none",
            reversibility: "readOnly",
            secretHandling: "credentialUse",
            executionRecommendation: "automatic",
            confidence: 0.9
          }
        }
      }
    ];

    for (const request of requests) {
      const authenticated = { capabilityToken: validToken, request };
      expect(AuthenticatedIpcRequest.parse(authenticated)).toEqual(authenticated);
    }
  });

  it("keeps caller identity optional and separate from the security token", () => {
    const caller = AgentCallerIdentity.parse({
      name: "Pi",
      version: "1.2.3",
      transport: "mcp"
    });
    const request = AuthenticatedIpcRequest.parse({
      capabilityToken: validToken,
      caller,
      request: { type: "status" }
    });

    expect(request.caller).toEqual(caller);
    expect(() => AgentCallerIdentity.parse({ name: "Codex\nsecret://leak" })).not.toThrow();
  });
});

describe("IPC frame codec", () => {
  it("uses a four-byte big-endian length prefix and round trips JSON", () => {
    const frame = IpcFrameCodec.encode({ type: "status", locked: false });

    expect([...frame.subarray(0, 4)]).toEqual([0, 0, 0, frame.byteLength - 4]);
    expect(IpcFrameCodec.decode(frame, IpcResponse)).toEqual({ type: "status", locked: false });
  });

  it("rejects frames over one MiB", () => {
    const frame = Buffer.alloc(4 + 1_048_577, 0x41);
    frame.writeUInt32BE(1_048_577, 0);

    expect(() => IpcFrameCodec.decode(frame, IpcResponse)).toThrow(/frame too large/i);
  });
});

describe("local IPC client", () => {
  it("derives fixed app-support IPC paths", () => {
    const paths = appSupportIpcPaths();

    expect(paths.directory).toBe(
      path.join(os.homedir(), "Library", "Application Support", "AgentSecretVault", "IPC")
    );
    expect(paths.socket).toBe(path.join(paths.directory, "agent-secret-vault.sock"));
    expect(paths.token).toBe(path.join(paths.directory, "capability.token"));
  });

  it("rejects token files readable by non-owners", async () => {
    const directory = await makeTempDirectory();
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o644 });
    await chmod(tokenPath, 0o644);

    await expect(LocalIpcClient.readCapabilityToken(tokenPath)).rejects.toThrow(
      /token file permissions/i
    );
  });

  it("maps socket connection failures to APP_UNAVAILABLE", async () => {
    const directory = await makeTempDirectory();
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const client = new LocalIpcClient({
      socketPath: path.join(directory, "missing.sock"),
      tokenPath
    });

    await expect(client.request({ type: "status" })).resolves.toEqual({
      type: "failure",
      code: "APP_UNAVAILABLE"
    });
  });

  it("retries while the app socket is starting", async () => {
    const directory = await makeTempDirectory();
    const socketPath = path.join(directory, "agent-secret-vault.sock");
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const server = net.createServer((socket) => {
      socket.on("data", () => {
        socket.end(IpcFrameCodec.encode({ type: "status", locked: false }));
        server.close();
      });
    });

    setTimeout(() => {
      server.listen(socketPath);
    }, 25);

    const client = new LocalIpcClient({
      socketPath,
      tokenPath,
      unavailableRetryCount: 10,
      unavailableRetryDelayMs: 10
    });

    await expect(client.request({ type: "status" })).resolves.toEqual({
      type: "status",
      locked: false
    });
  });

  it("sends authenticated framed requests and validates framed responses", async () => {
    const directory = await makeTempDirectory();
    const socketPath = path.join(directory, "agent-secret-vault.sock");
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const server = net.createServer();
    const received = new Promise<unknown>((resolve, reject) => {
      server.on("connection", (socket) => {
        const chunks: Buffer[] = [];
        socket.on("data", (chunk) => chunks.push(chunk));
        socket.on("end", () => {
          try {
            resolve(IpcFrameCodec.decode(Buffer.concat(chunks), AuthenticatedIpcRequest));
            socket.end(IpcFrameCodec.encode({ type: "status", locked: false }));
          } catch (error) {
            reject(error);
          } finally {
            server.close();
          }
        });
      });
      server.on("error", reject);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
      server.listen(socketPath);
    });

    const client = new LocalIpcClient({ socketPath, tokenPath });
    const response = await client.request({ type: "status" });

    expect(response).toEqual({ type: "status", locked: false });
    await expect(received).resolves.toEqual({
      capabilityToken: validToken,
      request: { type: "status" }
    });
  });

  it("propagates a declared caller in the authenticated envelope", async () => {
    const directory = await makeTempDirectory();
    const socketPath = path.join(directory, "agent-secret-vault.sock");
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const server = net.createServer();
    const received = new Promise<unknown>((resolve, reject) => {
      server.on("connection", (socket) => {
        const chunks: Buffer[] = [];
        socket.on("data", (chunk) => chunks.push(chunk));
        socket.on("end", () => {
          try {
            resolve(IpcFrameCodec.decode(Buffer.concat(chunks), AuthenticatedIpcRequest));
            socket.end(IpcFrameCodec.encode({ type: "status", locked: false }));
          } catch (error) {
            reject(error);
          } finally {
            server.close();
          }
        });
      });
      server.on("error", reject);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
      server.listen(socketPath);
    });

    const client = new LocalIpcClient({
      socketPath,
      tokenPath,
      declaredCaller: { name: "Pi", version: "1.2.3", transport: "mcp" }
    });
    await expect(client.request({ type: "status" })).resolves.toEqual({
      type: "status",
      locked: false
    });
    await expect(received).resolves.toEqual({
      capabilityToken: validToken,
      caller: { name: "Pi", version: "1.2.3", transport: "mcp" },
      request: { type: "status" }
    });
  });

  it("applies the control timeout to lifecycle start instead of holding one long execution IPC", async () => {
    const directory = await makeTempDirectory();
    const socketPath = path.join(directory, "agent-secret-vault.sock");
    const tokenPath = path.join(directory, "capability.token");
    await writeFile(tokenPath, validToken, { mode: 0o600 });
    await chmod(tokenPath, 0o600);

    const receivedRequestTypes: string[] = [];
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.setTimeout(100, () => socket.destroy());
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.on("end", () => {
        const frame = Buffer.concat(chunks);
        const declaredLength = frame.readUInt32BE(0);
        expect(frame.byteLength - 4).toBe(declaredLength);
        const envelope = JSON.parse(frame.subarray(4).toString("utf8")) as {
          request?: { type?: string };
        };
        const requestType = envelope.request?.type;
        if (requestType !== undefined) receivedRequestTypes.push(requestType);
        if (requestType === "preflightSecretOperation") {
          socket.end(IpcFrameCodec.encode({
            type: "secretOperationPreflight",
            result: {
              route: "fast",
              policyRuleID: "test.fast",
              authorizationRequirement: "none",
              blastRadius: "tiny",
              reasons: [],
              technicalFailure: false
            }
          }));
          return;
        }
        // Deliberately do not reply to lifecycle start. A start/status/cancel
        // IPC is a bounded control request; timeout means outcome uncertainty.
      });
    });
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
      server.listen(socketPath);
    });

    const client = new LocalIpcClient({
      socketPath,
      tokenPath,
      requestTimeoutMs: 50,
      unavailableRetryCount: 0
    });
    const result = await client.request({
      type: "executeSecretOperation",
      descriptor: {
        actionType: "sshCommand",
        secretReferences: [validReference],
        destination: "qnap.local",
        port: 22,
        protocolType: "ssh",
        command: "hostname",
        requestedEffects: ["read-only"],
        parameters: {
          passwordRef: validReference,
          username: "admin"
        },
        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "silent",
          reason: "test operation",
          userGoal: "read status",
          taskContext: "test operation",
          intendedEffect: "read status",
          expectedEffect: "read status",
          expectedResult: "read status",
          intentAlignment: "direct",
          effectSeverity: "none",
          reversibility: "readOnly",
          secretHandling: "credentialUse",
          executionRecommendation: "automatic",
          confidence: 0.9
        }
      }
    });

    expect(receivedRequestTypes).toEqual(["preflightSecretOperation", "startSecretOperation"]);
    expect(result).toEqual({
      type: "failure",
      code: "OPERATION_OUTCOME_UNKNOWN"
    });
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});

async function makeTempDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "asv-mcp-"));
  temporaryDirectories.push(directory);
  return directory;
}
