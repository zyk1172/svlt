import { describe, expect, it } from "vitest";

import type { SecretOperationDescriptor } from "../src/protocol.js";
import {
  executeOpaqueOperation,
  OPERATION_CANCELLED,
  OPERATION_NOT_FOUND,
  OPERATION_OUTCOME_UNKNOWN
} from "../src/secretOperations/index.js";
import { runWithSecretOperationAbortSignal } from "../src/secretOperations/context.js";
import {
  getSecretOperationStatus,
  type SecretOperationIpcClient
} from "../src/secretOperations/client.js";
import type {
  IpcRequest,
  IpcResponse
} from "../src/secretOperations/protocol.js";

const operationID = "00000000-0000-4000-8000-000000000101";
const descriptor: SecretOperationDescriptor = {
  actionType: "sshCommand",
  secretReferences: [],
  requestedEffects: ["read-only"],
  parameters: {},
  agentAssessment: {
    declaredRisk: "silent",
    reason: "test",
    intendedEffect: "test lifecycle"
  }
};

class FakeLifecycleClient implements SecretOperationIpcClient {
  readonly requests: IpcRequest[] = [];

  constructor(private readonly responses: Array<IpcResponse | Error>) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    this.requests.push(request);
    const response = this.responses.shift();
    if (response instanceof Error) throw response;
    return response ?? { type: "failure", code: "NO_FIXTURE" };
  }
}

function handle(state: "queued" | "awaitingApproval" | "running" = "queued"): IpcResponse {
  return { type: "secretOperationHandle", result: { operationID, state } };
}

function status(
  state: "queued" | "awaitingApproval" | "running" | "succeeded" | "failed" | "cancelled" | "outcomeUnknown",
  extra: Record<string, unknown> = {}
): IpcResponse {
  return {
    type: "secretOperationStatus",
    result: { operationID, state, ...extra }
  } as IpcResponse;
}

describe("operationID MCP lifecycle", () => {
  it("polls queued/approval/running until the daemon returns the final output", async () => {
    const client = new FakeLifecycleClient([
      handle(),
      status("queued"),
      status("awaitingApproval"),
      status("running"),
      status("succeeded", { output: { status: "COMPLETED", redacted: true } })
    ]);
    const states: string[] = [];

    const result = await executeOpaqueOperation(client, descriptor, undefined, {
      pollIntervalMs: 0,
      onState: (state) => { states.push(state); }
    });

    expect(result).toEqual({ status: "COMPLETED", redacted: true });
    expect(states).toEqual(["queued", "queued", "awaitingApproval", "running", "succeeded"]);
    expect(client.requests.map((request) => request.type)).toEqual([
      "startSecretOperation",
      "secretOperationStatus",
      "secretOperationStatus",
      "secretOperationStatus",
      "secretOperationStatus"
    ]);
  });

  it("preserves daemon failure codes instead of translating them", async () => {
    const client = new FakeLifecycleClient([
      handle(),
      status("failed", { errorCode: "AUTHORIZATION_CANCELLED" })
    ]);

    await expect(executeOpaqueOperation(client, descriptor, undefined, { pollIntervalMs: 0 }))
      .resolves.toEqual({ status: "AUTHORIZATION_CANCELLED" });
  });

  it("preserves operation-not-found at the direct control-client boundary", async () => {
    const client = new FakeLifecycleClient([
      { type: "failure", code: OPERATION_NOT_FOUND }
    ]);

    await expect(getSecretOperationStatus(client, operationID)).resolves.toEqual({
      kind: "failure",
      code: OPERATION_NOT_FOUND
    });
  });

  it("treats a lost acknowledged handle as outcomeUnknown even if status says not found", async () => {
    const client = new FakeLifecycleClient([
      handle(),
      { type: "failure", code: OPERATION_NOT_FOUND }
    ]);

    await expect(executeOpaqueOperation(client, descriptor, undefined, { pollIntervalMs: 0 }))
      .resolves.toEqual({ status: OPERATION_OUTCOME_UNKNOWN });
  });

  it("cancels definitively before execution when the MCP call is aborted", async () => {
    const controller = new AbortController();
    const client = new FakeLifecycleClient([
      handle(),
      status("awaitingApproval"),
      status("cancelled", { errorCode: OPERATION_CANCELLED })
    ]);

    const result = await executeOpaqueOperation(client, descriptor, controller.signal, {
      pollIntervalMs: 0,
      onState: (state) => {
        if (state === "awaitingApproval") controller.abort();
      }
    });

    expect(result).toEqual({ status: OPERATION_CANCELLED });
    expect(client.requests.at(-1)?.type).toBe("cancelSecretOperation");
  });

  it("inherits the real MCP request AbortSignal through AsyncLocalStorage", async () => {
    const controller = new AbortController();
    const client = new FakeLifecycleClient([
      handle(),
      status("awaitingApproval"),
      status("cancelled", { errorCode: OPERATION_CANCELLED })
    ]);

    const result = await runWithSecretOperationAbortSignal(controller.signal, () =>
      executeOpaqueOperation(client, descriptor, undefined, {
        pollIntervalMs: 0,
        onState: (state) => {
          if (state === "awaitingApproval") controller.abort();
        }
      })
    );

    expect(result).toEqual({ status: OPERATION_CANCELLED });
    expect(client.requests.map((request) => request.type)).toEqual([
      "startSecretOperation",
      "secretOperationStatus",
      "cancelSecretOperation"
    ]);
  });

  it("surfaces outcomeUnknown when cancellation races with execution", async () => {
    const controller = new AbortController();
    const client = new FakeLifecycleClient([
      handle(),
      status("running"),
      status("outcomeUnknown", { errorCode: OPERATION_OUTCOME_UNKNOWN })
    ]);

    const result = await executeOpaqueOperation(client, descriptor, controller.signal, {
      pollIntervalMs: 0,
      onState: (state) => {
        if (state === "running") controller.abort();
      }
    });

    expect(result).toEqual({ status: OPERATION_OUTCOME_UNKNOWN });
    expect(client.requests.at(-1)?.type).toBe("cancelSecretOperation");
  });

  it("treats control-channel loss after start as outcomeUnknown", async () => {
    const client = new FakeLifecycleClient([
      handle(),
      new Error("connection reset after operation start")
    ]);

    await expect(executeOpaqueOperation(client, descriptor, undefined, { pollIntervalMs: 0 }))
      .resolves.toEqual({ status: OPERATION_OUTCOME_UNKNOWN });
  });

  it("does not turn post-start APP_UNAVAILABLE into a retryable failure", async () => {
    const client = new FakeLifecycleClient([
      handle(),
      { type: "failure", code: "APP_UNAVAILABLE" }
    ]);

    await expect(executeOpaqueOperation(client, descriptor, undefined, { pollIntervalMs: 0 }))
      .resolves.toEqual({ status: OPERATION_OUTCOME_UNKNOWN });
  });
});
