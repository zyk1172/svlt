import { describe, expect, it } from "vitest";

import type { IpcRequest, IpcResponse } from "../src/protocol.js";
import { createVaultToolDefinitions, type VaultIpcClient } from "../src/server.js";

const reference = "secret://0123456789ABCDEFGHJKMNPQRS";

class NoopClient implements VaultIpcClient {
  async request(_request: IpcRequest): Promise<IpcResponse> {
    throw new Error("not used by schema compatibility tests");
  }
}

function inputSchema(name: string) {
  const definition = createVaultToolDefinitions(new NoopClient()).find((item) => item.name === name);
  if (definition === undefined) throw new Error(`missing tool ${name}`);
  return definition.inputSchema;
}

describe("legacy timeoutMs compatibility", () => {
  it("accepts deprecated timeoutMs on every strict tool schema that historically exposed it", () => {
    const cases: Array<[string, Record<string, unknown>]> = [
      ["local_http_request_with_secret", { url: "https://example.com", timeoutMs: 100 }],
      ["ssh_command_with_secret", { host: "example.com", passwordRef: reference, command: "true", timeoutMs: 1_000 }],
      ["ssh_batch_with_secret", { host: "example.com", passwordRef: reference, commands: [{ executable: "true", arguments: [] }], timeoutMs: 1_000 }],
      ["api_request_with_token", { url: "https://example.com", tokenRef: reference, timeoutMs: 100 }],
      ["database_query_with_secret", { engine: "postgres", host: "db.local", database: "app", username: "user", passwordRef: reference, query: "SELECT 1", timeoutMs: 1_000 }],
      ["sftp_transfer_with_secret", { operation: "list", host: "nas.local", username: "user", passwordRef: reference, remotePath: "/", timeoutMs: 1_000 }],
      ["ftp_transfer_with_secret", { operation: "list", host: "nas.local", username: "user", passwordRef: reference, remotePath: "/", timeoutMs: 1_000 }],
      ["browser_web_login_with_secret", { url: "https://example.com", username: "user", passwordRef: reference, passwordSelector: "#password", timeoutMs: 1_000 }],
      ["local_app_form_fill_with_secret", { appName: "Test App", fields: [{ name: "password", valueRef: reference }], timeoutMs: 1_000 }]
    ];

    for (const [name, input] of cases) {
      expect(() => inputSchema(name).parse(input), name).not.toThrow();
    }
  });
});
