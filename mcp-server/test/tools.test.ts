import { describe, expect, it } from "vitest";

import {
  type IpcRequest,
  type IpcResponse,
  type SecretOperationAction
} from "../src/protocol.js";
import {
  createVaultToolDefinitions,
  type VaultIpcClient
} from "../src/server.js";

const reference = "secret://0123456789ABCDEFGHJKMNPQRS";

class FakeClient implements VaultIpcClient {
  readonly requests: IpcRequest[] = [];

  constructor(private readonly responses: IpcResponse[]) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    this.requests.push(request);
    return this.responses.shift() ?? { type: "failure", code: "NO_FIXTURE" };
  }
}

function operationResponse(extra: Record<string, unknown> = {}): IpcResponse {
  return {
    type: "secretOperation",
    output: { status: "COMPLETED", redacted: true, ...extra }
  } as IpcResponse;
}

function capabilityResponse(
  action: SecretOperationAction,
  status: "supported" | "unavailable" | "invalidParameters" = "supported"
): IpcResponse {
  const kind = action === "apiRequest" || action === "httpRequest"
    ? "http"
      : action === "databaseQuery"
        ? "database"
        : action === "sftpTransfer"
          ? "sftp"
          : action === "ftpTransfer"
            ? "ftp"
          : action === "browserLogin"
          ? "browser"
          : action === "localAppFill"
            ? "localApp"
            : action === "localExecution"
              ? "localExecution"
              : action === "trustedProcess"
                ? "trustedProcess"
                : "export";
  return {
    type: "secretOperationCapabilities",
    capabilities: [{ kind, status, operations: [action], reason: "test fixture" }]
  } as IpcResponse;
}

function tool(client: VaultIpcClient, name: string) {
  const definition = createVaultToolDefinitions(client).find((item) => item.name === name);
  if (definition === undefined) {
    throw new Error(`missing tool ${name}`);
  }
  return definition;
}

describe("MCP tool contracts", () => {
  it("exposes dedicated opaque secret tools", () => {
    const names = createVaultToolDefinitions(new FakeClient([])).map((item) => item.name);
    expect(names).toEqual(expect.arrayContaining([
      "vault_status",
      "vault_capabilities",
      "secret_search",
      "secret_catalog_search",
      "secret_catalog_get",
      "secret_catalog_list_indices",
      "secret_catalog_list_entries",
      "secret_catalog_create_index",
      "secret_catalog_create_structure",
      "secret_catalog_create_entry",
      "secret_catalog_batch",
      "secret_catalog_create_draft",
      "secret_catalog_patch_metadata",
      "secret_catalog_commit",
      "secret_catalog_add_secret_placeholder",
      "secret_catalog_request_secure_inputs",
      "secret_catalog_secure_input_status",
      "secret_catalog_bind_existing_secret",
      "secret_catalog_validate",
      "secret_catalog_file_preflight",
      "secret_inspect_reference",
      "secret_review_ssh_host_key",
      "secret_bind_destination",
      "ssh_command_with_secret",
      "ssh_batch_with_secret",
      "ssh_session_status",
      "ssh_session_close",
      "local_http_request_with_secret",
      "api_request_with_token",
      "database_query_with_secret",
      "sftp_transfer_with_secret",
      "ftp_transfer_with_secret",
      "local_execution_with_secret",
      "trusted_process_with_secret",
      "secret_reveal_request"
    ]));
    expect(names).not.toContain("restore_references");
  });

  it("starts secure input asynchronously without trusting agent labels or returning plaintext", async () => {
    const requestID = "00000000-0000-4000-8000-000000000021";
    const client = new FakeClient([{
      type: "catalogSecureInputStatus",
      status: { requestID, status: "PENDING" }
    }]);

    const result = await tool(client, "secret_catalog_request_secure_inputs").handler({
      entryID: "0123456789ABCDEFGHJKMNPQRV",
      targets: [{ fieldKey: "password", mode: "fillPlaceholder", required: true }],
      expectedRevision: 7
    });

    expect(result.structuredContent).toEqual({ requestID, status: "PENDING" });
    expect(client.requests).toEqual([{
      type: "catalogRequestSecureInputs",
      entryID: "0123456789ABCDEFGHJKMNPQRV",
      targets: [{
        entryID: "0123456789ABCDEFGHJKMNPQRV",
        fieldKey: "password",
        mode: "fillPlaceholder",
        required: true
      }],
      expectedRevision: 7
    }]);
    expect(JSON.stringify(result.structuredContent)).not.toContain("plaintext");
  });

  it("polls secure input status by request ID", async () => {
    const requestID = "00000000-0000-4000-8000-000000000022";
    const client = new FakeClient([{
      type: "catalogSecureInputStatus",
      status: { requestID, status: "COMPLETED", revision: 8 }
    }]);

    const result = await tool(client, "secret_catalog_secure_input_status").handler({ requestID });

    expect(result.structuredContent).toEqual({ requestID, status: "COMPLETED", revision: 8 });
    expect(client.requests).toEqual([{ type: "catalogSecureInputStatus", requestID }]);
  });

  it("preserves secure input business errors as structured status codes", async () => {
    const requestID = "00000000-0000-4000-8000-000000000024";
    const client = new FakeClient([{ type: "failure", code: "CATALOG_REVISION_CONFLICT" }]);
    const definition = tool(client, "secret_catalog_secure_input_status");

    const result = await definition.handler({ requestID });

    expect(result.structuredContent).toEqual({ status: "CATALOG_REVISION_CONFLICT" });
    expect(() => definition.outputSchema.parse(result.structuredContent)).not.toThrow();
  });

  it("accepts UNKNOWN receipts for requests that require Catalog reconciliation", () => {
    const definition = tool(new FakeClient([]), "secret_catalog_secure_input_status");

    expect(() => definition.outputSchema.parse({
      requestID: "00000000-0000-4000-8000-000000000024",
      status: "UNKNOWN",
      errorCode: "SECURE_INPUT_REQUEST_UNKNOWN"
    })).not.toThrow();
  });

  it("does not gate normal work on the compatibility locked field", async () => {
    const client = new FakeClient([{
      type: "workbenchStatus",
      status: {
        locked: true,
        ipcAvailable: true,
        available: true,
        ready: true,
        approvalPending: false,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    } as IpcResponse]);

    const result = await tool(client, "vault_status").handler({});
    expect(result.structuredContent).toEqual({
      status: "READY",
      available: true,
      ready: true,
      approvalPending: false
    });
  });

  it("requests the daemon capability manifest before claiming adapter support", async () => {
    const client = new FakeClient([{
      type: "secretOperationCapabilities",
      capabilities: [{
        kind: "http",
        version: 1,
        status: "supported",
        operations: ["httpRequest"],
        reason: "typed HTTP",
        features: {
          auth: ["basic", "bearer", "apiKeyHeader"],
          body: ["none", "raw", "json", "form"],
          response: ["metadataOnly", "projectedJSON"],
          transportSessionReuse: true,
          derivedCredentialCapture: false,
          publicNetworkEgress: false,
          insecurePrivateNetworkHTTPProfileOptIn: true
        }
      }, {
        kind: "database",
        status: "unavailable",
        operations: ["databaseQuery"],
        reason: "driver unavailable"
      }]
    }]);

    const result = await tool(client, "vault_capabilities").handler({});
    expect(result.structuredContent).toEqual({
      status: "OK",
      capabilities: [{
        kind: "http",
        version: 1,
        status: "supported",
        operations: ["httpRequest"],
        reason: "typed HTTP",
        features: {
          auth: ["basic", "bearer", "apiKeyHeader"],
          body: ["none", "raw", "json", "form"],
          response: ["metadataOnly", "projectedJSON"],
          transportSessionReuse: true,
          derivedCredentialCapture: false,
          publicNetworkEgress: false,
          insecurePrivateNetworkHTTPProfileOptIn: true
        }
      }, {
        kind: "database",
        status: "unavailable",
        operations: ["databaseQuery"],
        reason: "driver unavailable"
      }]
    });
    expect(client.requests).toEqual([{ type: "secretOperationCapabilities" }]);
  });

  it("returns destination binding as non-sensitive metadata", async () => {
    const client = new FakeClient([{
      type: "referenceMetadata",
      metadata: {
        reference,
        policy: "credential",
        label: "QNAP credential",
        allowedDestinations: ["192.168.2.240", "qnap.local"],
        allowedProtocols: ["ssh", "https"],
        allowedBindings: [],
        createdAt: 1,
        updatedAt: 2
      }
    } as IpcResponse]);

    const result = await tool(client, "secret_inspect_reference").handler({ reference });
    expect(result.structuredContent).toEqual({
      reference,
      policy: "credential",
      label: "QNAP credential",
      allowedDestinations: ["192.168.2.240", "qnap.local"],
      allowedProtocols: ["ssh", "https"],
      allowedBindings: [],
      createdAt: 1,
      updatedAt: 2
    });
  });

  it("routes owner-approved destination binding without exposing plaintext", async () => {
    const client = new FakeClient([operationResponse({
      status: "BOUND",
      destination: "http://192.168.2.240:3000",
      protocolType: "http"
    })]);

    const result = await tool(client, "secret_bind_destination").handler({
      reference,
      destination: "http://192.168.2.240:3000",
      protocol: "http"
    });

    expect(result.structuredContent).toEqual({
      status: "BOUND",
      destination: "http://192.168.2.240:3000",
      protocol: "http",
      redacted: true
    });
    expect(client.requests).toHaveLength(1);
    expect(client.requests[0]).toMatchObject({
      type: "executeSecretOperation",
      descriptor: {
        actionType: "changeDestinationBinding",
        secretReferences: [reference],
        destination: "http://192.168.2.240:3000",
        protocolType: "http",
        requestedEffects: ["bind-secret-destination"],
        parameters: {}
      }
    });
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");
  });

  it("reviews SSH host keys through a secret-free metadata request", async () => {
    const pin = { algorithm: "ssh-ed25519", sha256: `SHA256:${"A".repeat(43)}` };
    const client = new FakeClient([{
      type: "sshHostKeyReview",
      review: { host: "qnap.local", port: 2222, pins: [pin] }
    }]);

    const result = await tool(client, "secret_review_ssh_host_key").handler({
      host: "qnap.local",
      port: 2222
    });

    expect(result.structuredContent).toEqual({
      status: "FOUND",
      host: "qnap.local",
      port: 2222,
      pins: [pin]
    });
    expect(client.requests).toEqual([{
      type: "reviewSSHHostKey",
      host: "qnap.local",
      port: 2222
    }]);
    expect(JSON.stringify(result.structuredContent)).not.toContain("secret://");
  });

  it("submits an explicit SSH host-key pin as an owner-approved binding", async () => {
    const pin = { algorithm: "ssh-ed25519", sha256: `SHA256:${"B".repeat(43)}` };
    const client = new FakeClient([operationResponse({
      status: "BOUND",
      destination: "qnap.local",
      protocolType: "ssh",
      port: 2222,
      hostKeyPin: pin
    })]);

    const result = await tool(client, "secret_bind_destination").handler({
      reference,
      destination: "qnap.local",
      protocol: "ssh",
      port: 2222,
      hostKeyAlgorithm: pin.algorithm,
      hostKeySHA256: pin.sha256
    });

    expect(result.structuredContent).toEqual({
      status: "BOUND",
      destination: "qnap.local",
      protocol: "ssh",
      port: 2222,
      hostKeyPin: pin,
      redacted: true
    });
    expect(client.requests[0]).toMatchObject({
      type: "executeSecretOperation",
      descriptor: {
        actionType: "changeDestinationBinding",
        secretReferences: [reference],
        destination: "qnap.local",
        port: 2222,
        protocolType: "ssh",
        requestedEffects: ["pin-ssh-host-key"],
        parameters: {
          hostKeyAlgorithm: pin.algorithm,
          hostKeySHA256: pin.sha256
        }
      }
    });
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");
  });

  it("returns the daemon's canonical bound destination", async () => {
    const client = new FakeClient([operationResponse({
      status: "BOUND",
      destination: "http://example.com:80",
      protocolType: "http"
    })]);

    const result = await tool(client, "secret_bind_destination").handler({
      reference,
      destination: "http://example.com",
      protocol: "http"
    });

    expect(result.structuredContent).toEqual({
      status: "BOUND",
      destination: "http://example.com:80",
      protocol: "http",
      redacted: true
    });
  });

  it("rejects a destination containing a secret reference before IPC", async () => {
    const client = new FakeClient([]);

    await expect(tool(client, "secret_bind_destination").handler({
      reference,
      destination: "http://example.com/secret://token",
      protocol: "http"
    })).rejects.toThrow(/secret:\/\//i);
    expect(client.requests).toHaveLength(0);
  });

  it("rejects incomplete or unscoped SSH pin parameters before IPC", async () => {
    const client = new FakeClient([]);

    await expect(tool(client, "secret_bind_destination").handler({
      reference,
      destination: "qnap.local",
      protocol: "ssh",
      port: 2222,
      hostKeyAlgorithm: "ssh-ed25519"
    })).rejects.toThrow(/hostKeySHA256|provided together/i);

    await expect(tool(client, "secret_bind_destination").handler({
      reference,
      destination: "qnap.local",
      protocol: "ssh",
      port: 2222
    })).rejects.toThrow(/only valid|host-key pin/i);
    expect(client.requests).toHaveLength(0);
  });

  it("searches the local catalog by service and returns opaque metadata only", async () => {
    const client = new FakeClient([{
      type: "catalogSearchResult",
      result: {
        status: "FOUND",
        matches: [{
          index: {
            id: "0123456789ABCDEFGHJKMNPQRT",
            title: "QNAP",
            aliases: ["NAS"],
            tags: ["设备"]
          },
          entry: {
            id: "0123456789ABCDEFGHJKMNPQRV",
            indexId: "0123456789ABCDEFGHJKMNPQRT",
            title: "QNAP 管理后台登录",
            type: "credential",
            aliases: ["QNAP 登录"],
            endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
            fields: [
              { key: "username", label: "用户名", type: "text", value: "admin" },
              { key: "password", label: "密码", type: "secret", secretRef: reference }
            ],
            notes: "媒体管理",
            tags: ["QNAP"]
          }
        }]
      }
    }]);

    const result = await tool(client, "secret_search").handler({
      query: "qnap",
      field: "password",
      limit: 10
    });

    expect(result.structuredContent).toEqual({
      status: "FOUND",
      matches: [{
        index: {
          id: "0123456789ABCDEFGHJKMNPQRT",
          title: "QNAP",
          aliases: ["NAS"],
          tags: ["设备"]
        },
        entry: {
          id: "0123456789ABCDEFGHJKMNPQRV",
          indexId: "0123456789ABCDEFGHJKMNPQRT",
          title: "QNAP 管理后台登录",
          type: "credential",
          aliases: ["QNAP 登录"],
          endpoints: [{ type: "https", host: "192.168.2.240", port: 443 }],
          fields: [
            { key: "username", label: "用户名", type: "text", value: "admin" },
            { key: "password", label: "密码", type: "secret", secretRef: reference }
          ],
          notes: "媒体管理",
          tags: ["QNAP"]
        }
      }]
    });
    expect(client.requests).toEqual([{
      type: "catalogSearch",
      query: "qnap",
      field: "password",
      limit: 10
    }]);
    const serialized = JSON.stringify(result.structuredContent);
    expect(serialized).not.toContain("plaintext-secret-value");
    expect(serialized).not.toContain("sensitive-index-selection");
    expect(serialized).not.toContain("line");
  });

  it("lists empty and populated Indexes without using entry-centric search", async () => {
    const indexID = "0123456789ABCDEFGHJKMNPQRT";
    const client = new FakeClient([{
      type: "catalogIndexListResult",
      result: {
        status: "FOUND",
        revision: 47,
        indices: [
          { id: indexID, title: "QNAP", aliases: [], tags: [], entryCount: 2 },
          { id: "0123456789ABCDEFGHJKMNPQRV", title: "自动化测试", aliases: [], tags: [], entryCount: 0 }
        ]
      }
    }]);

    const result = await tool(client, "secret_catalog_list_indices").handler({});

    expect(result.structuredContent).toMatchObject({
      status: "FOUND",
      revision: 47,
      indices: [
        expect.objectContaining({ title: "QNAP", entryCount: 2 }),
        expect.objectContaining({ title: "自动化测试", entryCount: 0 })
      ]
    });
    expect(client.requests).toEqual([{ type: "catalogListIndexes" }]);
  });

  it("lists projected Entries by an MCP-provided Index ID", async () => {
    const indexID = "0123456789ABCDEFGHJKMNPQRT";
    const entryID = "0123456789ABCDEFGHJKMNPQRS";
    const client = new FakeClient([{
      type: "catalogEntryListResult",
      result: {
        status: "FOUND",
        revision: 48,
        indexID,
        entries: [{
          id: entryID,
          indexId: indexID,
          title: "QNAP",
          type: "credential",
          aliases: [],
          endpoints: [{ type: "ssh", host: "qnap.local", port: 22 }],
          fields: [{ key: "password", label: "密码", type: "secret", secretRef: reference }],
          tags: []
        }]
      }
    }]);

    const result = await tool(client, "secret_catalog_list_entries").handler({ indexID });

    expect(result.structuredContent).toMatchObject({ status: "FOUND", revision: 48, indexID });
    expect(client.requests).toEqual([{ type: "catalogListEntries", indexID }]);
  });

  it("rejects empty catalog queries before touching IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_search").handler({ query: "   " })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("uses App-controlled authorization for metadata writes and never accepts catalog plaintext", async () => {
    const client = new FakeClient([
      {
        type: "catalogWriteResult",
        result: { revision: 2, entry: null, validation: { status: "FOUND", revision: 2, diagnostics: [] } }
      },
      { type: "catalogValidation", catalogStatus: "FOUND", revision: 2 }
    ]);

    const write = await tool(client, "secret_catalog_patch_metadata").handler({
      entryID: "0123456789ABCDEFGHJKMNPQRV",
      patch: { title: "QNAP 管理后台登录" },
      expectedRevision: 1
    });
    expect(write.structuredContent).toEqual({
      revision: 2,
      entry: null,
      validation: { status: "FOUND", revision: 2, diagnostics: [] }
    });
    expect(client.requests[0]).toMatchObject({
      type: "catalogPatchMetadata",
      expectedRevision: 1,
    });
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");

    const validation = await tool(client, "secret_catalog_validate").handler({});
    expect(validation.structuredContent).toEqual({
      status: "FOUND",
      revision: 2,
      rawSHA256: null,
      diagnostics: []
    });
    expect(client.requests[1]).toEqual({ type: "catalogValidate" });
  });

  it("does not report a controlled write as successful without post-commit validation", async () => {
    const client = new FakeClient([{
      type: "catalogWriteResult",
      result: { revision: 2, entry: null }
    }]);

    const result = await tool(client, "secret_catalog_batch").handler({
      expectedRevision: 1,
      operations: [{
        type: "deleteEntry",
        id: "0123456789ABCDEFGHJKMNPQRS"
      }]
    });

    expect(result.structuredContent).toEqual({ status: "POST_COMMIT_VALIDATION_MISSING" });
  });

  it("returns the generated Index ID and post-commit validation", async () => {
    const indexID = "0123456789ABCDEFGHJKMNPQRT";
    const validation = { status: "FOUND", revision: 9, diagnostics: [] };
    const client = new FakeClient([{
      type: "catalogWriteResult",
      result: { revision: 9, indexID, validation }
    }]);

    const result = await tool(client, "secret_catalog_create_index").handler({ title: "数据库" });

    expect(result.structuredContent).toEqual({
      status: "CREATED",
      indexID,
      revision: 9,
      validation
    });
    expect(client.requests).toEqual([{
      type: "catalogCreateIndex",
      title: "数据库",
      aliases: [],
      tags: []
    }]);
  });

  it("creates an Index and multiple Entries atomically with clientKey mappings", async () => {
    const indexID = "0123456789ABCDEFGHJKMNPQRT";
    const firstEntryID = "0123456789ABCDEFGHJKMNPQRS";
    const secondEntryID = "0123456789ABCDEFGHJKMNPQRV";
    const client = new FakeClient([{
      type: "catalogStructureWriteResult",
      result: {
        indexID,
        entries: [
          { clientKey: "postgres", entryID: firstEntryID },
          { clientKey: "redis", entryID: secondEntryID }
        ],
        revision: 12,
        validation: { status: "FOUND", revision: 12, diagnostics: [] }
      }
    }]);

    const result = await tool(client, "secret_catalog_create_structure").handler({
      index: { title: "数据库" },
      entries: [
        {
          clientKey: "postgres",
          title: "PostgreSQL",
          endpoints: [{ type: "postgresql", host: "db.home", port: 5432 }],
          fields: [{ key: "password", label: "密码", type: "secret" }]
        },
        {
          clientKey: "redis",
          title: "Redis",
          endpoints: [{ type: "redis", host: "nas.home", port: 6379 }],
          fields: [{ key: "password", label: "密码", type: "secret" }]
        }
      ]
    });

    expect(result.structuredContent).toMatchObject({
      status: "CREATED",
      indexID,
      entries: [
        { clientKey: "postgres", entryID: firstEntryID },
        { clientKey: "redis", entryID: secondEntryID }
      ],
      revision: 12,
      validation: { status: "FOUND", revision: 12, diagnostics: [] }
    });
    expect(client.requests).toEqual([{
      type: "catalogCreateStructure",
      request: expect.objectContaining({
        index: { title: "数据库", aliases: [], tags: [] },
        entries: expect.arrayContaining([
          expect.objectContaining({ clientKey: "postgres" }),
          expect.objectContaining({ clientKey: "redis" })
        ])
      })
    }]);
    expect(JSON.stringify(client.requests)).not.toMatch(/"id"|secretRef/);
  });

  it("exposes an explicit catalog file preflight tool", async () => {
    const preflight = {
      read: "READ_OK",
      parentTempCreate: "PARENT_TEMP_CREATE_OK",
      parentTempFsync: "PARENT_TEMP_FSYNC_OK",
      parentRename: "PARENT_RENAME_OK",
      parentFsync: "PARENT_FSYNC_OK"
    };
    const client = new FakeClient([{
      type: "catalogFilePreflight",
      filePreflight: preflight
    }]);

    const result = await tool(client, "secret_catalog_file_preflight").handler({});

    expect(client.requests).toEqual([{ type: "catalogFilePreflight" }]);
    expect(result.structuredContent).toEqual(preflight);
  });

  it("serializes a v3 batch as one IPC mutation and keeps secret fields opaque", async () => {
    const client = new FakeClient([{
      type: "catalogWriteResult",
      result: { revision: 8, entry: null, validation: { status: "FOUND", revision: 8, diagnostics: [] } }
    }]);
    const indexID = "0123456789ABCDEFGHJKMNPQRY";
    const entryID = "0123456789ABCDEFGHJKMNPQRW";

    const result = await tool(client, "secret_catalog_batch").handler({
      expectedRevision: 7,
      operations: [
        {
          type: "createIndex",
          index: {
            schema: "svlt.catalog.index/v3",
            id: indexID,
            title: "Obsidian",
            aliases: [],
            tags: ["笔记"]
          }
        },
        {
          type: "createEntry",
          entry: {
            schema: "svlt.catalog.entry/v3",
            id: entryID,
            indexId: indexID,
            title: "本机笔记",
            type: "credential",
            aliases: [],
            endpoints: [],
            fields: [{
              key: "password",
              label: "密码",
              type: "secret",
              agentVisible: true,
              searchable: false
            }],
            tags: []
          }
        }
      ]
    });

    expect(result.structuredContent).toEqual({
      revision: 8,
      entry: null,
      validation: { status: "FOUND", revision: 8, diagnostics: [] }
    });
    expect(client.requests).toEqual([{
      type: "catalogApplyBatch",
      mutation: {
        operations: [
          {
            type: "createIndex",
            index: {
              schema: "svlt.catalog.index/v3",
              id: indexID,
              title: "Obsidian",
              aliases: [],
              tags: ["笔记"]
            }
          },
          {
            type: "createEntry",
            entry: {
              schema: "svlt.catalog.entry/v3",
              id: entryID,
              indexId: indexID,
              title: "本机笔记",
              type: "credential",
              aliases: [],
              endpoints: [],
              fields: [{
                key: "password",
                label: "密码",
                type: "secret",
                agentVisible: true,
                searchable: false
              }],
              tags: []
            }
          }
        ]
      },
      expectedRevision: 7
    }]);
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");
  });

  it("creates a safe Entry in one call without a lease, reference, or plaintext", async () => {
    const client = new FakeClient([{
      type: "catalogWriteResult",
      result: {
        revision: 4,
        entryID: "0123456789ABCDEFGHJKMNPQRS",
        entry: {
          id: "0123456789ABCDEFGHJKMNPQRS",
          indexId: "0123456789ABCDEFGHJKMNPQRT",
          title: "音乐服务器",
          type: "credential",
          aliases: [],
          endpoints: [{ type: "http", host: "192.168.2.240", port: 4533 }],
          fields: [
            { key: "username", label: "用户名", type: "text", agentVisible: true, searchable: true, value: "zyk" },
            { key: "password", label: "密码", type: "secret", agentVisible: true, searchable: false }
          ],
          notes: null,
          tags: []
          },
        validation: {
          status: "FOUND",
          revision: 4,
          diagnostics: []
        }
      }
    } as IpcResponse]);

    const result = await tool(client, "secret_catalog_create_entry").handler({
      indexID: "0123456789ABCDEFGHJKMNPQRT",
      title: "音乐服务器",
      endpoints: [{ type: "http", host: "192.168.2.240", port: 4533 }],
      fields: [
        { key: "username", label: "用户名", type: "text", value: "zyk" },
        { key: "password", label: "密码", type: "secret", searchable: false }
      ]
    });

    expect(result.structuredContent).toEqual({
      status: "CREATED",
      entryID: "0123456789ABCDEFGHJKMNPQRS",
      revision: 4,
      validation: {
        status: "FOUND",
        revision: 4,
        diagnostics: []
      }
    });
    expect(client.requests[0]).toMatchObject({
      type: "catalogCreateEntry",
      request: {
        indexID: "0123456789ABCDEFGHJKMNPQRT",
        title: "音乐服务器"
      }
    });
    expect(JSON.stringify(client.requests)).not.toContain("secretRef");
    expect(JSON.stringify(client.requests)).not.toContain("plaintext");
  });

  it("rejects an existing secretRef on the direct safe create tool before IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_catalog_create_entry").handler({
      indexID: "0123456789ABCDEFGHJKMNPQRT",
      title: "危险绑定",
      fields: [{
        key: "password",
        label: "密码",
        type: "secret",
        secretRef: reference
      }]
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("rejects duplicate field keys before IPC with a precise field path", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_catalog_create_entry").handler({
      indexID: "0123456789ABCDEFGHJKMNPQRT",
      title: "重复字段",
      fields: [
        { key: "host", label: "主机", type: "text", value: "db.home" },
        { key: "host", label: "备用主机", type: "text", value: "db2.home" }
      ]
    })).rejects.toThrow(/duplicate field key|fields.*1.*key/i);
    expect(client.requests).toHaveLength(0);
  });

  it("does not send a draft containing a secret plaintext value", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "secret_catalog_create_draft").handler({
      request: {
        indexID: "0123456789ABCDEFGHJKMNPQRT",
        title: "QNAP",
        fields: [{ key: "password", label: "密码", type: "secret", value: "plaintext" }]
      }
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("sends SSH actions as opaque descriptors and preserves the agent hint", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "qnap", stderr: "" })]);
    const result = await tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname",
      agentAssessment: {
        reason: "read QNAP status",
        userGoal: "Inspect QNAP status",
        taskContext: "The requested step is a read-only host diagnostic",
        intendedEffect: "read-only",
        expectedEffect: "No persistent change",
        expectedResult: "Return the host name",
        intentAlignment: "direct",
        effectSeverity: "none",
        reversibility: "readOnly",
        secretHandling: "credentialUse",
        executionRecommendation: "automatic",
        confidence: 0.98
      }
    });

    expect(result.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor).toMatchObject({
      actionType: "sshCommand",
      secretReferences: [reference],
      destination: "qnap.local",
      command: "hostname",
      protocolType: "ssh",
      agentAssessment: {
        source: "mainAgent",
        declaredRisk: "silent",
        executionRecommendation: "automatic",
        intentAlignment: "direct"
      }
    });
    expect(JSON.stringify(request)).not.toContain("plaintext-secret-value");
    expect(JSON.stringify(request)).not.toContain("restoreReferences");
  });

  it("carries an explicit approvalRequired assessment into the SSH descriptor", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "", stderr: "" })]);
    const result = await tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "mkdir /share/svlt-test",
      agentAssessment: {
        reason: "creates a directory",
        userGoal: "Create the requested remote working directory",
        taskContext: "Bounded reversible filesystem setup",
        intendedEffect: "remote write",
        expectedEffect: "Create one directory",
        expectedResult: "The requested directory exists",
        intentAlignment: "direct",
        effectSeverity: "minor",
        reversibility: "easy",
        secretHandling: "credentialUse",
        executionRecommendation: "automatic",
        confidence: 0.96
      }
    });

    expect(result.structuredContent).toMatchObject({ status: "COMPLETED", redacted: true });
    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    // MCP owns provenance/coarse risk and forwards the main Agent's structured semantics.
    expect(request.descriptor.agentAssessment).toMatchObject({
      source: "mainAgent",
      declaredRisk: "silent",
      reason: "creates a directory",
      userGoal: "Create the requested remote working directory",
      intendedEffect: "remote write",
      effectSeverity: "minor",
      reversibility: "easy",
      secretHandling: "credentialUse",
      executionRecommendation: "automatic",
      confidence: 0.96
    });
  });

  it("fills the conservative default assessment when the agent omits one", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "", stderr: "" })]);
    await tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname"
    });

    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor.agentAssessment).toEqual({
      source: "mainAgent",
      declaredRisk: "approvalRequired",
      reason: "Main Agent did not provide a semantic assessment",
      userGoal: "Complete the requested Secret-backed operation",
      taskContext: "No additional task context supplied",
      intendedEffect: "Perform the requested operation",
      expectedEffect: "Unknown until independently reviewed",
      expectedResult: "Complete the user's requested task",
      intentAlignment: "unclear",
      effectSeverity: "unknown",
      reversibility: "unknown",
      secretHandling: "unknown",
      executionRecommendation: "uncertain",
      confidence: 0
    });
  });

  it("preserves only bounded redacted diagnostics for failed SSH actions", async () => {
    const client = new FakeClient([operationResponse({
      status: "WRAPPER_FAILED",
      exitCode: 122,
      stage: "FRAME_DECODE",
      stdout: "safe stdout",
      stderr: "safe stderr"
    })]);
    const definition = tool(client, "ssh_command_with_secret");
    const result = await definition.handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname"
    });

    expect(result.structuredContent).toEqual({
      status: "WRAPPER_FAILED",
      exitCode: 122,
      stage: "FRAME_DECODE",
      stdoutPreview: "safe stdout",
      stderrPreview: "safe stderr",
      redacted: true
    });
    expect(() => definition.outputSchema.parse(result.structuredContent)).not.toThrow();
    expect(JSON.stringify(result.structuredContent)).not.toContain("plaintext-secret-value");
  });

  it("sends structured SSH batches with an opaque session handle", async () => {
    const client = new FakeClient([operationResponse({
      sessionID: "ssh_session_test",
      results: [
        { index: 0, status: "COMPLETED", exitCode: 0, stdout: "zyk", stderr: "" },
        { index: 1, status: "COMPLETED", exitCode: 0, stdout: "safe", stderr: "" }
      ]
    })]);

    const result = await tool(client, "ssh_batch_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      sessionID: "ssh_session_previous",
      commands: [
        { executable: "whoami", arguments: [] },
        { executable: "printf", arguments: ["a b", "$(id)"] }
      ]
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      sessionID: "ssh_session_test",
      results: [
        { index: 0, status: "COMPLETED", exitCode: 0, stdoutPreview: "zyk", stderrPreview: "" },
        { index: 1, status: "COMPLETED", exitCode: 0, stdoutPreview: "safe", stderrPreview: "" }
      ],
      redacted: true
    });
    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor).toMatchObject({
      actionType: "sshCommand",
      destination: "qnap.local",
      sessionID: "ssh_session_previous",
      sshCommandBatch: {
        stopOnFailure: true,
        commands: [
          { executable: "whoami", arguments: [] },
          { executable: "printf", arguments: ["a b", "$(id)"] }
        ]
      }
    });
    expect(request.descriptor.command).toBeUndefined();
    expect(JSON.stringify(request)).not.toContain("ASV_CANARY_BATCH_PASSWORD");
  });

  it("rejects oversized structured SSH batches before IPC", async () => {
    const client = new FakeClient([]);
    const commands = Array.from({ length: 33 }, () => ({ executable: "hostname", arguments: [] }));

    await expect(tool(client, "ssh_batch_with_secret").handler({
      host: "qnap.local",
      passwordRef: reference,
      commands
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("inspects and closes only opaque SSH transport handles", async () => {
    const client = new FakeClient([
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
      { type: "operationCompleted" }
    ]);

    const statusResult = await tool(client, "ssh_session_status").handler({});
    expect(statusResult.structuredContent).toEqual({
      status: "ACTIVE",
      sessions: [{
        sessionID: "ssh_session_test",
        host: "qnap.local",
        port: 22,
        status: "active",
        idleExpiresIn: 299
      }]
    });

    const closeResult = await tool(client, "ssh_session_close").handler({
      sessionID: "ssh_session_test"
    });
    expect(closeResult.structuredContent).toEqual({ status: "CLOSED" });
    expect(client.requests).toEqual([
      { type: "sshSessionStatus" },
      { type: "sshSessionClose", sessionID: "ssh_session_test" }
    ]);
  });

  it("does not let a low agent hint hide a dangerous SSH command", async () => {
    const client = new FakeClient([{ type: "failure", code: "OPERATION_DENIED" }]);
    const result = await tool(client, "ssh_command_with_secret").handler({
      host: "192.168.2.240",
      passwordRef: reference,
      command: "rm -rf /volume1/@tmp",
      agentAssessment: {
        reason: "maintenance",
        userGoal: "Perform the requested maintenance",
        taskContext: "The command deletes a remote directory tree and therefore needs semantic review",
        intendedEffect: "delete a remote directory tree",
        expectedEffect: "Remove /volume1/@tmp recursively",
        expectedResult: "Temporary data is removed",
        intentAlignment: "direct",
        effectSeverity: "broad",
        reversibility: "irreversible",
        secretHandling: "credentialUse",
        executionRecommendation: "freshApproval",
        confidence: 0.98
      }
    });

    expect(result.structuredContent).toEqual({ status: "OPERATION_DENIED" });
    expect(client.requests[0].type).toBe("executeSecretOperation");
  });

  it("rejects secret-backed SSH usernames before IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      usernameRef: reference,
      passwordRef: reference,
      command: "hostname"
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("rejects option-like SSH usernames before IPC", async () => {
    const client = new FakeClient([]);
    await expect(tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "-oProxyCommand=echo",
      passwordRef: reference,
      command: "hostname"
    })).rejects.toThrow();
    expect(client.requests).toHaveLength(0);
  });

  it("carries HTTP method and destination into the operation descriptor", async () => {
    const client = new FakeClient([
      capabilityResponse("apiRequest"),
      operationResponse({ httpStatus: 200, contentType: "application/json" })
    ]);
    await tool(client, "api_request_with_token").handler({
      url: "https://qnap.local/api/status",
      method: "POST",
      tokenRef: reference,
      body: "{\"probe\":true}"
    });

    const request = client.requests[1];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor).toMatchObject({
      actionType: "apiRequest",
      destination: "qnap.local",
      httpMethod: "POST",
      url: "https://qnap.local/api/status",
      requestedEffects: ["remote-write"]
    });
  });

  it("forwards an explicit safe HTTP response preview", async () => {
    const client = new FakeClient([
      capabilityResponse("apiRequest"),
      operationResponse({
        httpStatus: 200,
        contentType: "application/json",
        bodyPreview: '{"object":"list","data":[{"id":"model-a"}]}'
      })
    ]);
    const result = await tool(client, "api_request_with_token").handler({
      url: "https://qnap.local/v1/models",
      tokenRef: reference,
      includeBodyPreview: true
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: "application/json",
      bodyPreview: '{"object":"list","data":[{"id":"model-a"}]}',
      redacted: true
    });
    const request = client.requests[1];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor.parameters).toMatchObject({ includeBodyPreview: "true" });
    expect(request.descriptor.payload).toMatchObject({
      type: "http",
      operation: { responsePolicy: { kind: "sanitizedPreview" } }
    });
  });

  it("does not add an implicit Bearer scheme to custom API-key headers", async () => {
    const client = new FakeClient([capabilityResponse("apiRequest"), operationResponse({ httpStatus: 200 })]);
    await tool(client, "api_request_with_token").handler({
      url: "https://qnap.local/api/status",
      tokenRef: reference,
      headerName: "X-API-Key"
    });

    const request = client.requests[1];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor.parameters).toMatchObject({
      tokenRef: reference,
      headerName: "X-API-Key"
    });
    expect(request.descriptor.parameters).not.toHaveProperty("headerScheme");
    expect(request.descriptor.payload).toMatchObject({
      type: "http",
      operation: {
        auth: {
          kind: "apiKeyHeader",
          headerName: "X-API-Key",
          valueReference: reference
        }
      }
    });
    expect((request.descriptor.payload as { operation: { auth: { scheme?: string } } }).operation.auth.scheme).toBeUndefined();
  });

  it("routes credential query URLs through owner approval and rejects URL authority credentials", async () => {
    const urlClient = new FakeClient([
      capabilityResponse("apiRequest"),
      operationResponse({ httpStatus: 200 })
    ]);
    const urlResult = await tool(urlClient, "api_request_with_token").handler({
      url: "https://qnap.local/api?token=secret",
      tokenRef: reference
    });
    expect(urlResult.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: null,
      redacted: true
    });
    expect(urlClient.requests).toHaveLength(2);
    expect(urlClient.requests[1]).toMatchObject({
      type: "executeSecretOperation",
      descriptor: { url: "https://qnap.local/api?token=secret" }
    });

    const authorityClient = new FakeClient([]);
    const authorityResult = await tool(authorityClient, "api_request_with_token").handler({
      url: "https://user:pass@qnap.local/api",
      tokenRef: reference
    });
    expect(authorityResult.structuredContent).toEqual({ status: "URL_CREDENTIALS_NOT_ALLOWED" });
    expect(authorityClient.requests).toHaveLength(0);

    const bodyClient = new FakeClient([]);
    const bodyResult = await tool(bodyClient, "api_request_with_token").handler({
      url: "https://qnap.local/api",
      tokenRef: reference,
      body: `value=${reference}`
    });
    expect(bodyResult.structuredContent).toEqual({ status: "PLAINTEXT_REFERENCE_NOT_ALLOWED" });
    expect(bodyClient.requests).toHaveLength(0);
  });

  it("fails closed when a non-SSH capability is unavailable", async () => {
    const client = new FakeClient([
      capabilityResponse("databaseQuery", "unavailable"),
      operationResponse({ rowCount: 1 })
    ]);
    const result = await tool(client, "database_query_with_secret").handler({
      engine: "postgres",
      host: "qnap.local",
      database: "postgres",
      username: "admin",
      passwordRef: reference,
      query: "SELECT 1"
    });

    expect(result.structuredContent).toEqual({ status: "ACTION_EXECUTOR_UNAVAILABLE" });
    expect(client.requests).toHaveLength(1);
    expect(client.requests[0].type).toBe("secretOperationCapabilities");
  });

  it("routes local process intents through capability gating without fallback", async () => {
    const localClient = new FakeClient([capabilityResponse("localExecution", "unavailable")]);
    const localResult = await tool(localClient, "local_execution_with_secret").handler({
      executable: "/private/tmp/svlt-check",
      arguments: ["--check-only"],
      secretReferences: [reference]
    });
    expect(localResult.structuredContent).toEqual({ status: "ACTION_EXECUTOR_UNAVAILABLE" });
    expect(localClient.requests).toHaveLength(1);

    const trustedClient = new FakeClient([capabilityResponse("trustedProcess", "unavailable")]);
    const trustedResult = await tool(trustedClient, "trusted_process_with_secret").handler({
      profileID: "missing-signed-profile",
      arguments: [],
      secretReferences: [reference]
    });
    expect(trustedResult.structuredContent).toEqual({ status: "ACTION_EXECUTOR_UNAVAILABLE" });
    expect(trustedClient.requests).toHaveLength(1);
  });

  it("routes credential query parameters through owner approval for local HTTP", async () => {
    const client = new FakeClient([
      capabilityResponse("httpRequest"),
      operationResponse({ httpStatus: 200 })
    ]);
    const result = await tool(client, "local_http_request_with_secret").handler({
      url: "https://qnap.local/api?token=secret",
      username: "admin",
      passwordRef: reference
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      httpStatus: 200,
      contentType: null,
      redacted: true
    });
    expect(client.requests).toHaveLength(2);
    expect(client.requests[1]).toMatchObject({
      type: "executeSecretOperation",
      descriptor: { url: "https://qnap.local/api?token=secret" }
    });
  });

  it("preserves a sanitized HTTP redirect location at the MCP boundary", async () => {
    const client = new FakeClient([
      capabilityResponse("apiRequest"),
      operationResponse({
        status: "REDIRECT_REQUIRES_REVIEW",
        httpStatus: 302,
        redirectLocation: "https://qnap.local/next",
        contentType: "text/plain",
        bodyPreview: "ignored"
      })
    ]);
    const result = await tool(client, "api_request_with_token").handler({
      url: "https://qnap.local/start",
      tokenRef: reference
    });

    expect(result.structuredContent).toEqual({
      status: "REDIRECT_REQUIRES_REVIEW",
      httpStatus: 302,
      redirectLocation: "https://qnap.local/next",
      redacted: true
    });
  });

  it("uses operation descriptors for database and SFTP actions", async () => {
    const client = new FakeClient([
      capabilityResponse("databaseQuery"),
      operationResponse({ rowCount: 1, rowsPreview: "hostname" }),
      capabilityResponse("sftpTransfer"),
      operationResponse({ listingPreview: "file.txt" })
    ]);

    await tool(client, "database_query_with_secret").handler({
      engine: "postgres",
      host: "qnap.local",
      database: "postgres",
      username: "admin",
      passwordRef: reference,
      query: "SELECT hostname FROM status"
    });
    await tool(client, "sftp_transfer_with_secret").handler({
      operation: "list",
      host: "qnap.local",
      username: "zyk",
      remotePath: "/share",
      passwordRef: reference
    });

    expect(client.requests).toHaveLength(4);
    expect(client.requests[0].type).toBe("secretOperationCapabilities");
    expect(client.requests[2].type).toBe("secretOperationCapabilities");
    const database = client.requests[1];
    if (database.type === "executeSecretOperation") {
      expect(database.descriptor.databaseStatement).toMatch(/^SELECT/i);
    }
    const sftp = client.requests[3];
    if (sftp.type === "executeSecretOperation") {
      expect(sftp.descriptor.fileOperation).toBe("list");
    }
  });

  it("routes FTP through its own capability and protocol action", async () => {
    const client = new FakeClient([
      capabilityResponse("ftpTransfer"),
      operationResponse({ listingPreview: "ftp-file.txt" })
    ]);

    const result = await tool(client, "ftp_transfer_with_secret").handler({
      operation: "list",
      host: "nas.local",
      username: "zyk",
      remotePath: "/share/USBSSD",
      passwordRef: reference
    });

    expect(result.structuredContent).toEqual({
      status: "COMPLETED",
      listingPreview: "ftp-file.txt",
      redacted: true
    });
    expect(client.requests).toHaveLength(2);
    const request = client.requests[1];
    if (request.type === "executeSecretOperation") {
      expect(request.descriptor.actionType).toBe("ftpTransfer");
      expect(request.descriptor.protocolType).toBe("ftp");
      expect(request.descriptor.port).toBe(21);
    }
  });

  it("preserves only the sanitized failure stage for file transfers", async () => {
    const client = new FakeClient([
      capabilityResponse("ftpTransfer"),
      {
        type: "secretOperation",
        output: { status: "FAILED", stage: "REMOTE_COMMAND", redacted: true }
      } as IpcResponse
    ]);

    const definition = tool(client, "ftp_transfer_with_secret");
    const result = await definition.handler({
      operation: "download",
      host: "nas.local",
      username: "zyk",
      remotePath: "/share/file.mp4",
      localPath: "/Users/example/Library/Application Support/AgentSecretVault/Downloads/file.mp4",
      passwordRef: reference
    });

    expect(result.structuredContent).toEqual({
      status: "FAILED",
      stage: "REMOTE_COMMAND",
      redacted: true
    });
    expect(() => definition.outputSchema.parse(result.structuredContent)).not.toThrow();
  });

  it("rejects duplicate secret references in adapter-specific inputs before IPC", async () => {
    const sftpClient = new FakeClient([]);
    await expect(tool(sftpClient, "sftp_transfer_with_secret").handler({
      operation: "list",
      host: "qnap.local",
      remotePath: "/share",
      usernameRef: reference,
      passwordRef: reference
    })).rejects.toThrow(/different references/i);
    expect(sftpClient.requests).toHaveLength(0);

    const localAppClient = new FakeClient([]);
    await expect(tool(localAppClient, "local_app_form_fill_with_secret").handler({
      bundleId: "com.example.App",
      fields: [
        { name: "username", valueRef: reference },
        { name: "password", valueRef: reference }
      ]
    })).rejects.toThrow(/used only once|duplicate/i);
    expect(localAppClient.requests).toHaveLength(0);
  });

  it("keeps local reveal as an app-owned request and never asks MCP for plaintext", async () => {
    const client = new FakeClient([{ type: "revealSessionOpened", sessionID: "session-1" }]);
    const result = await tool(client, "secret_reveal_request").handler({
      reference,
      reason: "show it in the local app"
    });

    expect(result.structuredContent).toEqual({ status: "DISPLAYED_TO_USER" });
    expect(client.requests[0].type).toBe("revealReferences");
    expect(client.requests.some((request) => request.type === "restoreReferences")).toBe(false);
  });

  it("routes local export directly to App IPC without an adapter capability preflight", async () => {
    const client = new FakeClient([{ type: "exported", path: "/Users/example/Desktop/export.md" }]);
    const result = await tool(client, "export_resolved_text_to_local_file").handler({
      text: `Token: ${reference}`,
      reason: "write an approved local export",
      destinationPath: "/Users/example/Desktop/export.md"
    });

    expect(result.structuredContent).toEqual({
      status: "EXPORTED",
      path: "/Users/example/Desktop/export.md"
    });
    expect(client.requests).toEqual([{
      type: "exportResolvedText",
      references: [reference],
      destinationPath: "/Users/example/Desktop/export.md",
      context: {
        reason: "write an approved local export",
        template: "Token: {{0}}",
        ranges: [{ index: 0, placeholder: "{{0}}" }],
        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "approvalRequired",
          reason: "Main Agent did not provide a semantic assessment",
          userGoal: "Complete the requested Secret-backed operation",
          taskContext: "No additional task context supplied",
          intendedEffect: "Perform the requested operation",
          expectedEffect: "Unknown until independently reviewed",
          expectedResult: "Complete the user's requested task",
          intentAlignment: "unclear",
          effectSeverity: "unknown",
          reversibility: "unknown",
          secretHandling: "unknown",
          executionRecommendation: "uncertain",
          confidence: 0
        }
      }
    }]);
    expect(client.requests.some((request) => request.type === "secretOperationCapabilities")).toBe(false);
  });

  it("states the risk-aware workflow without a global unlock instruction", async () => {
    const result = await tool(new FakeClient([]), "agent_secret_usage_policy").handler({});
    const policy = result.structuredContent as { safeWorkflow: string[]; forbidden: string[] };
    expect(policy.safeWorkflow.join(" ")).not.toMatch(/unlock/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/locked/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/secret_search/);
    expect(policy.safeWorkflow.join(" ")).toMatch(/Index.*Entry|entry-centric/i);
    expect(policy.safeWorkflow.join(" ")).toMatch(/secret_catalog_validate/);
    expect(policy.catalogPolicy).toMatch(/敏感信息\.md/);
    expect(policy.catalogPolicy).toMatch(/分组|条目|字段/);
    expect(policy.catalogPolicy).toMatch(/可以使用 App、MCP、Obsidian|最小修改/);
    expect(policy.catalogPolicy).toMatch(/placeholder/);
    expect(policy.forbidden.join(" ")).toMatch(/plaintext|shell|environment/i);
  });
});
