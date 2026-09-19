import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { LocalVaultClient } from "../src/ipc/client";

const openServers: net.Server[] = [];
const openSockets: net.Socket[] = [];
const temporaryDirectories: string[] = [];

function encodeFrame(message: unknown): Buffer {
  const payload = Buffer.from(JSON.stringify(message), "utf8");
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  return frame;
}

async function createSocketServer(onConnection: (socket: net.Socket) => void): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "asv-client-test-"));
  temporaryDirectories.push(directory);
  const socketPath = join(directory, "agent-secret-vault.sock");
  const server = net.createServer((socket) => {
    openSockets.push(socket);
    onConnection(socket);
  });
  openServers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
  return socketPath;
}

async function expectWithin<T>(promise: Promise<T>, milliseconds: number): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`timed out after ${milliseconds}ms`)), milliseconds);
      })
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

afterEach(async () => {
  for (const socket of openSockets.splice(0)) {
    socket.destroy();
  }
  await Promise.all(openServers.splice(0).map((server) => new Promise<void>((resolve) => {
    server.close(() => resolve());
  })));
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("LocalVaultClient", () => {
  const uid = typeof process.getuid === "function" ? process.getuid() : 501;
  const fsModule = {
    statSync: () => ({ mode: 0o600, uid }),
    readFileSync: (_path: string, _encoding: BufferEncoding) => "test-capability-token"
  };

  it("resolves after a complete response frame without waiting for socket end", async () => {
    const socketPath = await createSocketServer((socket) => {
      socket.on("data", () => {
        socket.write(encodeFrame({
          type: "workbenchStatus",
          status: {
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: null,
            pluginConnected: true
          }
        }));
      });
    });

    const client = new LocalVaultClient(socketPath, { netModule: net, fsModule });

    await expect(expectWithin(client.request({ type: "workbenchStatus" }), 100)).resolves.toEqual({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });
  });

  it("parses catalog diagnostics without accepting catalog content", async () => {
    const socketPath = await createSocketServer((socket) => {
      socket.on("data", () => {
        socket.write(encodeFrame({
          type: "catalogValidation",
          catalogStatus: "CATALOG_INVALID",
          revision: 4,
          diagnostics: [{
            id: "FIELD_KEY_DUPLICATE:9:1",
            severity: "error",
            code: "FIELD_KEY_DUPLICATE",
            line: 9,
            column: 1,
            scope: "field",
            message: "同一条目中存在重复字段 key。",
            hint: "每个条目的字段 key 必须唯一。"
          }]
        }));
      });
    });

    const client = new LocalVaultClient(socketPath, { netModule: net, fsModule });

    await expect(client.request({ type: "catalogValidate" })).resolves.toEqual({
      type: "catalogValidation",
      catalogStatus: "CATALOG_INVALID",
      revision: 4,
      diagnostics: [{
        id: "FIELD_KEY_DUPLICATE:9:1",
        severity: "error",
        code: "FIELD_KEY_DUPLICATE",
        line: 9,
        column: 1,
        scope: "field",
        message: "同一条目中存在重复字段 key。",
        hint: "每个条目的字段 key 必须唯一。"
      }]
    });
  });

  it("sends an exact framed catalogValidate request", async () => {
    let receivedRequest: unknown;
    const socketPath = await createSocketServer((socket) => {
      socket.on("data", (chunk) => {
        const data = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
        const length = data.readUInt32BE(0);
        receivedRequest = JSON.parse(data.subarray(4, 4 + length).toString("utf8"));
        socket.write(encodeFrame({
          type: "catalogValidation",
          catalogStatus: "FOUND",
          revision: 2
        }));
      });
    });

    const client = new LocalVaultClient(socketPath, { netModule: net, fsModule });

    await expect(client.request({ type: "catalogValidate" })).resolves.toEqual({
      type: "catalogValidation",
      catalogStatus: "FOUND",
      revision: 2,
      diagnostics: []
    });
    expect(receivedRequest).toEqual({
      capabilityToken: "test-capability-token",
      request: { type: "catalogValidate" }
    });
  });

  it("rejects short frames cleanly", async () => {
    const socketPath = await createSocketServer((socket) => {
      socket.write(Buffer.from([0x00, 0x00]));
      socket.end();
    });

    const client = new LocalVaultClient(socketPath, { netModule: net, fsModule });

    await expect(client.request({ type: "workbenchStatus" })).rejects.toThrow("Incomplete IPC frame");
  });

  it("rejects when a connected socket never returns a complete frame", async () => {
    const socketPath = await createSocketServer(() => {
      // Keep the connection open without sending a frame.
    });

    const client = new LocalVaultClient(socketPath, { netModule: net, fsModule, requestTimeoutMs: 10 });

    await expect(client.request({ type: "workbenchStatus" })).rejects.toThrow("IPC request timed out");
  });

  it("retries while the app socket is starting", async () => {
    const directory = await mkdtemp(join(tmpdir(), "asv-client-test-"));
    temporaryDirectories.push(directory);
    const socketPath = join(directory, "agent-secret-vault.sock");
    const server = net.createServer((socket) => {
      openSockets.push(socket);
      socket.on("data", () => {
        socket.end(encodeFrame({
          type: "workbenchStatus",
          status: {
            locked: false,
            ipcAvailable: true,
            activeKnowledgeBaseRoot: null,
            pluginConnected: true
          }
        }));
        server.close();
      });
    });
    openServers.push(server);

    setTimeout(() => {
      server.listen(socketPath);
    }, 25);

    const client = new LocalVaultClient(socketPath, {
      netModule: net,
      fsModule,
      unavailableRetryCount: 10,
      unavailableRetryDelayMs: 10
    });

    await expect(client.request({ type: "workbenchStatus" })).resolves.toEqual({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });
  });

  it("rejects world-readable capability tokens before connecting", async () => {
    const socketPath = await createSocketServer(() => {});
    const client = new LocalVaultClient(socketPath, {
      netModule: net,
      fsModule: {
        statSync: () => ({ mode: 0o644, uid }),
        readFileSync: (_path: string, _encoding: BufferEncoding) => "test-capability-token"
      }
    });

    await expect(client.request({ type: "workbenchStatus" })).rejects.toThrow("permissions");
  });
});
