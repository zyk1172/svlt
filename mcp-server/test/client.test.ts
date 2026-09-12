import { mkdtemp, rm, writeFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { LocalIpcClient } from "../src/client.js";
import { IpcFrameCodec, MAX_FRAME_BYTES } from "../src/protocol.js";

const cleanupDirectories: string[] = [];
const cleanupServers: net.Server[] = [];

afterEach(async () => {
  await Promise.all(cleanupServers.splice(0).map(closeServer));
  await Promise.all(cleanupDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("LocalIpcClient transport bounds", () => {
  it("accepts a normal framed response", async () => {
    const fixture = await makeFixture();
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.once("data", () => {
        socket.end(IpcFrameCodec.encode({ type: "status", locked: false }));
      });
    });
    await listen(server, fixture.socketPath);

    await expect(fixture.client.request({ type: "status" })).resolves.toEqual({
      type: "status",
      locked: false
    });
  });

  it("uses a wall-clock deadline even when the peer keeps sending data", async () => {
    const fixture = await makeFixture(75);
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.once("data", () => {
        let writes = 0;
        const interval = setInterval(() => {
          if (socket.destroyed || writes >= 30) {
            clearInterval(interval);
            return;
          }
          socket.write(Buffer.from([0]));
          writes += 1;
        }, 15);
        socket.once("close", () => clearInterval(interval));
      });
    });
    await listen(server, fixture.socketPath);

    const startedAt = Date.now();
    await expect(fixture.client.request({ type: "status" })).rejects.toThrow("IPC request timed out.");
    expect(Date.now() - startedAt).toBeLessThan(250);
  });

  it("rejects an oversized declared frame before buffering its body", async () => {
    const fixture = await makeFixture(1_000);
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.once("data", () => {
        const header = Buffer.alloc(4);
        header.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
        socket.write(header);
      });
    });
    await listen(server, fixture.socketPath);

    await expect(fixture.client.request({ type: "status" })).rejects.toThrow("IPC frame too large");
  });
});

async function makeFixture(requestTimeoutMs = 500): Promise<{
  client: LocalIpcClient;
  socketPath: string;
}> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "svlt-mcp-client-"));
  cleanupDirectories.push(directory);

  const tokenPath = path.join(directory, "capability.token");
  const socketPath = path.join(directory, "agent-secret-vault.sock");
  await writeFile(tokenPath, Buffer.alloc(32, 0x41).toString("base64"), { mode: 0o600 });

  return {
    socketPath,
    client: new LocalIpcClient({
      socketPath,
      tokenPath,
      unavailableRetryCount: 0,
      requestTimeoutMs
    })
  };
}

function listen(server: net.Server, socketPath: string): Promise<void> {
  cleanupServers.push(server);
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
}

function closeServer(server: net.Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections?.();
  });
}
