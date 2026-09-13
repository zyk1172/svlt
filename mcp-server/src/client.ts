import { readFile, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { z } from "zod";

import {
  AgentCallerIdentity,
  CapabilityToken,
  IpcFrameCodec,
  IpcRequest as BaseIpcRequest,
  IpcResponse as BaseIpcResponse,
  MAX_FRAME_BYTES
} from "./protocol.js";
import {
  executeTrackedOperation,
  isSecretOperationOutput
} from "./secretOperations/index.js";
import type { SecretOperationIpcClient } from "./secretOperations/client.js";
import {
  IpcRequest as LifecycleIpcRequest,
  IpcResponse as LifecycleIpcResponse
} from "./secretOperations/protocol.js";
import { applyContextBoundedRiskJudge } from "./risk-judge.js";

export interface IpcPaths {
  directory: string;
  socket: string;
  token: string;
}

export interface LocalIpcClientOptions {
  socketPath?: string;
  tokenPath?: string;
  unavailableRetryCount?: number;
  unavailableRetryDelayMs?: number;
  requestTimeoutMs?: number;
  declaredCaller?: AgentCallerIdentity;
}

const AuthenticatedIpcRequest = z.object({
  capabilityToken: CapabilityToken,
  caller: AgentCallerIdentity.optional(),
  request: LifecycleIpcRequest
}).strict();

const DEFAULT_UNAVAILABLE_RETRY_COUNT = 8;
const DEFAULT_UNAVAILABLE_RETRY_DELAY_MS = 500;
// This is only a control-request timeout. Secret-operation execution now runs
// behind operationID, so start/status/cancel remain bounded control requests.
// The legacy executeSecretOperation compatibility request is translated to
// that lifecycle before a frame is written to the daemon.
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const FRAME_HEADER_BYTES = 4;
const MAX_WIRE_FRAME_BYTES = FRAME_HEADER_BYTES + MAX_FRAME_BYTES;

export function appSupportIpcPaths(): IpcPaths {
  const directory = path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "AgentSecretVault",
    "IPC"
  );

  return {
    directory,
    socket: path.join(directory, "agent-secret-vault.sock"),
    token: path.join(directory, "capability.token")
  };
}

export class LocalIpcClient {
  private readonly socketPath: string;
  private readonly tokenPath: string;
  private readonly unavailableRetryCount: number;
  private readonly unavailableRetryDelayMs: number;
  private readonly requestTimeoutMs: number;
  private readonly declaredCaller?: AgentCallerIdentity;

  constructor(options: LocalIpcClientOptions = {}) {
    const defaults = appSupportIpcPaths();
    this.socketPath = options.socketPath ?? defaults.socket;
    this.tokenPath = options.tokenPath ?? defaults.token;
    this.unavailableRetryCount = options.unavailableRetryCount ?? DEFAULT_UNAVAILABLE_RETRY_COUNT;
    this.unavailableRetryDelayMs = options.unavailableRetryDelayMs ?? DEFAULT_UNAVAILABLE_RETRY_DELAY_MS;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    this.declaredCaller = options.declaredCaller;
  }

  static async readCapabilityToken(tokenPath: string): Promise<CapabilityToken> {
    const tokenStat = await stat(tokenPath);
    const permissionBits = tokenStat.mode & 0o777;
    if ((permissionBits & 0o077) !== 0) {
      throw new Error("token file permissions allow non-owner access");
    }

    if (typeof process.getuid === "function" && tokenStat.uid !== process.getuid()) {
      throw new Error("token file owner does not match current user");
    }

    const token = (await readFile(tokenPath, "utf8")).trim();
    return CapabilityToken.parse(token);
  }

  // Preserve the established MCP-facing contract. Lifecycle-aware request and
  // response unions are an internal transport detail until server.ts handlers
  // are fully migrated; callers that already speak the legacy contract do not
  // need to widen their types in the same release.
  async request(request: BaseIpcRequest, caller?: AgentCallerIdentity): Promise<BaseIpcResponse> {
    const riskJudgedRequest = await applyContextBoundedRiskJudge(request);
    const parsedRequest = LifecycleIpcRequest.parse(riskJudgedRequest);
    const effectiveCaller = caller ?? this.declaredCaller;

    // Keep the old public request shape for in-process compatibility while
    // removing it from the MCP↔daemon execution path. Existing server handlers
    // may still construct executeSecretOperation, but LocalIpcClient converts
    // that one call into start/status/cancel control requests and then maps the
    // terminal result back to the legacy response shape.
    if (parsedRequest.type === "executeSecretOperation") {
      const rawLifecycleClient: SecretOperationIpcClient = {
        request: (lifecycleRequest) => this.requestRaw(lifecycleRequest, effectiveCaller)
      };
      const result = await executeTrackedOperation(rawLifecycleClient, parsedRequest.descriptor);
      return isSecretOperationOutput(result)
        ? { type: "secretOperation", output: result }
        : { type: "failure", code: result.status };
    }

    const response = await this.requestRaw(parsedRequest, effectiveCaller);
    // A base request other than executeSecretOperation cannot legitimately
    // produce a lifecycle-only response. Parsing here turns any accidental
    // cross-protocol response into an immediate contract failure.
    return BaseIpcResponse.parse(response);
  }

  private async requestRaw(
    parsedRequest: LifecycleIpcRequest,
    caller?: AgentCallerIdentity
  ): Promise<LifecycleIpcResponse> {
    for (let attempt = 0; attempt <= this.unavailableRetryCount; attempt += 1) {
      const response = await this.requestOnce(parsedRequest, caller);
      if (
        response.type !== "failure" ||
        response.code !== "APP_UNAVAILABLE" ||
        attempt >= this.unavailableRetryCount
      ) {
        return response;
      }
      await delay(this.unavailableRetryDelayMs);
    }

    return { type: "failure", code: "APP_UNAVAILABLE" };
  }

  private async requestOnce(
    parsedRequest: LifecycleIpcRequest,
    caller?: AgentCallerIdentity
  ): Promise<LifecycleIpcResponse> {
    let token: CapabilityToken;
    try {
      token = await LocalIpcClient.readCapabilityToken(this.tokenPath);
    } catch (error) {
      if (isUnavailableError(error)) {
        return { type: "failure", code: "APP_UNAVAILABLE" };
      }
      throw error;
    }

    const authenticatedRequest = AuthenticatedIpcRequest.parse({
      capabilityToken: token,
      ...(caller === undefined ? {} : { caller }),
      request: parsedRequest
    });

    try {
      const responseFrame = await sendFramedRequest(
        this.socketPath,
        IpcFrameCodec.encode(authenticatedRequest),
        this.requestTimeoutMs
      );
      return IpcFrameCodec.decode(responseFrame, LifecycleIpcResponse);
    } catch (error) {
      if (isUnavailableError(error)) {
        return { type: "failure", code: "APP_UNAVAILABLE" };
      }
      throw error;
    }
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function sendFramedRequest(
  socketPath: string,
  requestFrame: Buffer,
  timeoutMs: number | undefined
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks: Buffer[] = [];
    const header = Buffer.alloc(FRAME_HEADER_BYTES);
    let headerBytes = 0;
    let receivedBytes = 0;
    let expectedFrameBytes: number | undefined;
    let settled = false;
    let deadlineTimer: ReturnType<typeof setTimeout> | undefined;

    const settle = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      if (deadlineTimer !== undefined) {
        clearTimeout(deadlineTimer);
      }
      socket.destroy();
      callback();
    };

    // net.Socket#setTimeout is an inactivity timeout: a peer can keep the
    // request alive forever by periodically sending a byte. Control requests
    // need a real wall-clock deadline that includes connect/write/read time.
    if (timeoutMs !== undefined) {
      deadlineTimer = setTimeout(() => {
        settle(() => reject(new Error("IPC request timed out.")));
      }, timeoutMs);
    }

    socket.on("connect", () => {
      socket.end(requestFrame);
    });
    socket.on("data", (chunk) => {
      if (settled) {
        return;
      }

      receivedBytes += chunk.byteLength;
      if (receivedBytes > MAX_WIRE_FRAME_BYTES) {
        settle(() => reject(new Error("IPC frame too large")));
        return;
      }

      if (headerBytes < FRAME_HEADER_BYTES) {
        const bytesToCopy = Math.min(FRAME_HEADER_BYTES - headerBytes, chunk.byteLength);
        chunk.copy(header, headerBytes, 0, bytesToCopy);
        headerBytes += bytesToCopy;
      }

      if (headerBytes === FRAME_HEADER_BYTES && expectedFrameBytes === undefined) {
        const payloadLength = header.readUInt32BE(0);
        if (payloadLength > MAX_FRAME_BYTES) {
          settle(() => reject(new Error("IPC frame too large")));
          return;
        }
        expectedFrameBytes = FRAME_HEADER_BYTES + payloadLength;
      }

      if (expectedFrameBytes !== undefined && receivedBytes > expectedFrameBytes) {
        const declaredPayloadBytes = expectedFrameBytes - FRAME_HEADER_BYTES;
        settle(() => reject(new Error(
          `IPC frame length mismatch: expected ${declaredPayloadBytes}, got ${receivedBytes - FRAME_HEADER_BYTES}`
        )));
        return;
      }

      chunks.push(chunk);
    });
    socket.on("end", () => {
      if (expectedFrameBytes !== undefined && receivedBytes !== expectedFrameBytes) {
        const declaredPayloadBytes = expectedFrameBytes - FRAME_HEADER_BYTES;
        settle(() => reject(new Error(
          `IPC frame length mismatch: expected ${declaredPayloadBytes}, got ${receivedBytes - FRAME_HEADER_BYTES}`
        )));
        return;
      }
      settle(() => resolve(Buffer.concat(chunks, receivedBytes)));
    });
    socket.on("error", (error) => {
      settle(() => reject(error));
    });
  });
}

function isUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }

  const errorWithCode = error as NodeJS.ErrnoException;
  return (
    errorWithCode.code === "ENOENT" ||
    errorWithCode.code === "ECONNREFUSED" ||
    errorWithCode.code === "ENOTSOCK" ||
    errorWithCode.code === "EACCES"
  );
}
