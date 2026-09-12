import { readFile, stat } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import {
  AuthenticatedIpcRequest,
  AgentCallerIdentity,
  CapabilityToken,
  IpcFrameCodec,
  IpcRequest,
  IpcResponse,
  MAX_FRAME_BYTES
} from "./protocol.js";
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

const DEFAULT_UNAVAILABLE_RETRY_COUNT = 8;
const DEFAULT_UNAVAILABLE_RETRY_DELAY_MS = 500;
// This is only a control-request timeout. Secret operations have their own
// adapter-owned execution timeout, which starts after any device-owner
// approval completes, so the MCP transport must not reuse this deadline.
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

  async request(request: IpcRequest, caller?: AgentCallerIdentity): Promise<IpcResponse> {
    // A configured judge is invoked here, after the MCP tool has constructed
    // the exact operation but before the descriptor enters the daemon. Each
    // invocation is a fresh stateless model call. It receives only the main
    // agent's short intendedEffect (used as the problem statement) plus the
    // canonical operation fields; chat history and the agent's risk rationale
    // are intentionally excluded.
    const riskJudgedRequest = await applyContextBoundedRiskJudge(request);
    const parsedRequest = IpcRequest.parse(riskJudgedRequest);
    for (let attempt = 0; attempt <= this.unavailableRetryCount; attempt += 1) {
      const response = await this.requestOnce(parsedRequest, caller ?? this.declaredCaller);
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
    parsedRequest: IpcRequest,
    caller?: AgentCallerIdentity
  ): Promise<IpcResponse> {
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
        parsedRequest.type === "executeSecretOperation" ? undefined : this.requestTimeoutMs
      );
      return IpcFrameCodec.decode(responseFrame, IpcResponse);
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
