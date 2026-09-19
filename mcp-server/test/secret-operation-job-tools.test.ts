import { describe, expect, it } from "vitest";

import type { IpcRequest, IpcResponse } from "../src/protocol.js";
import {
  createSecretOperationJobToolDefinitions,
  type SecretOperationJobClient
} from "../src/secretOperations/job-tools.js";

const reference = "secret://0123456789ABCDEFGHJKMNPQRS";
const operationID = "00000000-0000-4000-8000-000000000101";
const assessment = {
  reason: "Run the requested bounded check",
  userGoal: "Inspect the remote service",
  taskContext: "User requested an SSH check",
  intendedEffect: "Run one remote read-only command",
  expectedEffect: "Read remote status",
  expectedResult: "Return the status",
  intentAlignment: "direct" as const,
  effectSeverity: "minor" as const,
  reversibility: "readOnly" as const,
  secretHandling: "credentialUse" as const,
  executionRecommendation: "automatic" as const,
  confidence: 0.95
};

class FakeClient implements SecretOperationJobClient {
  readonly requests: IpcRequest[] = [];

  constructor(private readonly responses: IpcResponse[]) {}

  async request(request: IpcRequest): Promise<IpcResponse> {
    this.requests.push(request);
    return this.responses.shift() ?? { type: "failure", code: "NO_FIXTURE" };
  }
}

function tool(
  client: SecretOperationJobClient,
  name: string
) {
  const definition = createSecretOperationJobToolDefinitions(client).find((item) => item.name === name);
  if (definition === undefined) throw new Error(`missing tool ${name}`);
  return definition;
}

describe("public secret operation job tools", () => {
  it("starts SSH work with an idempotency key and returns immediately", async () => {
    const client = new FakeClient([
      {
        type: "secretOperationHandle",
        result: { operationID, state: "queued", reused: false }
      }
    ]);

    const result = await tool(client, "ssh_job_start").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname",
      idempotencyKey: "check-001",
      agentAssessment: assessment
    });

    expect(result.structuredContent).toEqual({
      status: "STARTED",
      operationID,
      state: "queued",
      reused: false,
      redacted: true
    });
    expect(client.requests).toHaveLength(1);
    expect(client.requests[0]?.type).toBe("startSecretOperationIdempotent");
    if (client.requests[0]?.type === "startSecretOperationIdempotent") {
      expect(client.requests[0].idempotencyKey).toBe("check-001");
      expect(client.requests[0].descriptor.command).toBe("hostname");
      expect(client.requests[0].descriptor.agentAssessment.source).toBe("mainAgent");
    }
  });

  it("projects lifecycle status without embedding stdout or stderr", async () => {
    const client = new FakeClient([
      {
        type: "secretOperationStatus",
        result: {
          operationID,
          state: "succeeded",
          nextOutputCursor: 2,
          output: {
            status: "COMPLETED",
            exitCode: 0,
            stdout: "sensitive operational output",
            stderr: "",
            sessionID: "session-1",
            redacted: true
          }
        }
      }
    ]);

    const result = await tool(client, "secret_operation_status").handler({ operationID });

    expect(result.structuredContent).toEqual({
      status: "OK",
      operationID,
      state: "succeeded",
      terminal: true,
      nextOutputCursor: 2,
      result: {
        status: "COMPLETED",
        exitCode: 0,
        sessionID: "session-1"
      },
      redacted: true
    });
    expect(JSON.stringify(result.structuredContent)).not.toContain("sensitive operational output");
  });

  it("reads output from the requested cursor and keeps stream metadata", async () => {
    const client = new FakeClient([
      {
        type: "secretOperationOutput",
        result: {
          operationID,
          state: "running",
          cursor: 1,
          nextCursor: 2,
          chunks: [
            {
              cursor: 1,
              stream: "stderr",
              text: "still working\n",
              commandIndex: 0
            }
          ],
          hasMore: false
        }
      }
    ]);

    const result = await tool(client, "secret_operation_output").handler({
      operationID,
      cursor: 1,
      maxChunks: 8
    });

    expect(result.structuredContent).toEqual({
      status: "OK",
      operationID,
      state: "running",
      cursor: 1,
      nextCursor: 2,
      chunks: [
        {
          cursor: 1,
          stream: "stderr",
          text: "still working\n",
          commandIndex: 0
        }
      ],
      hasMore: false,
      redacted: true
    });
    expect(client.requests[0]).toEqual({
      type: "secretOperationOutput",
      operationID,
      cursor: 1,
      maxChunks: 8
    });
  });

  it("preserves conservative outcomeUnknown cancellation semantics", async () => {
    const client = new FakeClient([
      {
        type: "secretOperationStatus",
        result: {
          operationID,
          state: "outcomeUnknown",
          errorCode: "OPERATION_OUTCOME_UNKNOWN"
        }
      }
    ]);

    const result = await tool(client, "secret_operation_cancel").handler({ operationID });
    expect(result.structuredContent).toEqual({
      status: "OK",
      operationID,
      state: "outcomeUnknown",
      terminal: true,
      errorCode: "OPERATION_OUTCOME_UNKNOWN",
      redacted: true
    });
  });
});
