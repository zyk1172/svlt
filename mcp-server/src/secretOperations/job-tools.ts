import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { AgentRiskProposal, agentAssessment } from "../agent-assessment.js";
import {
  IpcRequest,
  IpcResponse,
  SecretOperationState,
  SecretReference,
  SSHCommandBatch,
  SSHCommandSpec
} from "../protocol.js";

export interface SecretOperationJobClient {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export interface SecretOperationJobToolDefinition {
  name: string;
  title: string;
  description: string;
  inputSchema: z.ZodType;
  outputSchema: z.ZodType;
  handler(input: unknown): Promise<CallToolResult>;
}

const IdempotencyKey = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/)
  .describe("Stable caller-chosen key. Reusing it with the exact same operation returns the original operationID; reusing it with different work fails.");

const SSHJobCommon = {
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65_535).optional(),
  username: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/).optional(),
  passwordRef: SecretReference,
  sessionID: z.string().min(1).max(128).optional(),
  idempotencyKey: IdempotencyKey,
  agentAssessment: AgentRiskProposal
};

const SSHJobStartInput = z
  .object({
    ...SSHJobCommon,
    command: z
      .string()
      .min(1)
      .refine((value) => Buffer.byteLength(value, "utf8") <= 65_536, {
        message: "command must be at most 65536 UTF-8 bytes"
      })
  })
  .strict();

const SSHBatchJobStartInput = z
  .object({
    ...SSHJobCommon,
    commands: z.array(SSHCommandSpec).min(1).max(32),
    stopOnFailure: z.boolean().default(true)
  })
  .strict()
  .superRefine((value, context) => {
    try {
      SSHCommandBatch.parse({
        commands: value.commands,
        stopOnFailure: value.stopOnFailure
      });
    } catch (error) {
      if (error instanceof z.ZodError) {
        for (const issue of error.issues) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["commands", ...issue.path],
            message: issue.message
          });
        }
      }
    }
  });

const OperationIDInput = z.object({
  operationID: z.string().uuid()
}).strict();

const OperationOutputInput = z.object({
  operationID: z.string().uuid(),
  cursor: z.number().int().nonnegative().default(0),
  maxChunks: z.number().int().min(1).max(64).default(16)
}).strict();

const JobStartOutput = z.union([
  z.object({
    status: z.enum(["STARTED", "REUSED"]),
    operationID: z.string().uuid(),
    state: SecretOperationState,
    reused: z.boolean(),
    redacted: z.literal(true)
  }).strict(),
  z.object({ status: z.string().min(1) }).strict()
]);

const JobStatusOutput = z.union([
  z.object({
    status: z.literal("OK"),
    operationID: z.string().uuid(),
    state: SecretOperationState,
    terminal: z.boolean(),
    errorCode: z.string().min(1).nullable().optional(),
    nextOutputCursor: z.number().int().nonnegative().optional(),
    result: z.object({
      status: z.string().min(1),
      exitCode: z.number().int().optional(),
      stage: z.string().min(1).optional(),
      sessionID: z.string().min(1).max(128).optional(),
      failedIndex: z.number().int().nonnegative().optional()
    }).strict().optional(),
    redacted: z.literal(true)
  }).strict(),
  z.object({ status: z.string().min(1) }).strict()
]);

const JobOutputPage = z.union([
  z.object({
    status: z.literal("OK"),
    operationID: z.string().uuid(),
    state: SecretOperationState,
    cursor: z.number().int().nonnegative(),
    nextCursor: z.number().int().nonnegative(),
    hasMore: z.boolean(),
    chunks: z.array(z.object({
      cursor: z.number().int().nonnegative(),
      stream: z.enum(["stdout", "stderr"]),
      text: z.string(),
      commandIndex: z.number().int().nonnegative().nullable().optional()
    }).strict()).max(64),
    redacted: z.literal(true)
  }).strict(),
  z.object({ status: z.string().min(1) }).strict()
]);

const JobCancelOutput = z.union([
  z.object({
    status: z.literal("OK"),
    operationID: z.string().uuid(),
    state: SecretOperationState,
    terminal: z.boolean(),
    errorCode: z.string().min(1).nullable().optional(),
    redacted: z.literal(true)
  }).strict(),
  z.object({ status: z.string().min(1) }).strict()
]);

function structuredResult(value: Record<string, unknown>): CallToolResult {
  return {
    structuredContent: value,
    content: [{ type: "text", text: JSON.stringify(value) }]
  };
}

function statusOnly(response: IpcResponse): Record<string, string> {
  return response.type === "failure"
    ? { status: response.code }
    : { status: "UNEXPECTED_RESPONSE" };
}

function isTerminal(state: z.infer<typeof SecretOperationState>): boolean {
  return state === "succeeded"
    || state === "failed"
    || state === "cancelled"
    || state === "outcomeUnknown";
}

function startResult(response: IpcResponse): CallToolResult {
  if (response.type !== "secretOperationHandle") {
    return structuredResult(statusOnly(response));
  }
  const reused = response.result.reused === true;
  return structuredResult({
    status: reused ? "REUSED" : "STARTED",
    operationID: response.result.operationID,
    state: response.result.state,
    reused,
    redacted: true
  });
}

function descriptorFromCommand(parsed: z.infer<typeof SSHJobStartInput>) {
  return {
    actionType: "sshCommand" as const,
    secretReferences: [parsed.passwordRef],
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: "ssh" as const,
    command: parsed.command,
    sessionID: parsed.sessionID,
    requestedEffects: ["ssh-command"],
    parameters: {
      passwordRef: parsed.passwordRef,
      ...(parsed.username === undefined ? {} : { username: parsed.username })
    },
    agentAssessment: agentAssessment(parsed)
  };
}

function descriptorFromBatch(parsed: z.infer<typeof SSHBatchJobStartInput>) {
  return {
    actionType: "sshCommand" as const,
    secretReferences: [parsed.passwordRef],
    destination: parsed.host,
    port: parsed.port ?? 22,
    protocolType: "ssh" as const,
    sessionID: parsed.sessionID,
    sshCommandBatch: {
      commands: parsed.commands,
      stopOnFailure: parsed.stopOnFailure
    },
    requestedEffects: ["ssh-batch"],
    parameters: {
      passwordRef: parsed.passwordRef,
      ...(parsed.username === undefined ? {} : { username: parsed.username })
    },
    agentAssessment: agentAssessment(parsed)
  };
}

export function createSecretOperationJobToolDefinitions(
  client: SecretOperationJobClient
): SecretOperationJobToolDefinition[] {
  return [
    {
      name: "ssh_job_start",
      title: "Start SSH Job",
      description:
        "Starts a long-running raw SSH command without waiting for completion. Returns an operationID immediately. idempotencyKey makes retries safe: the same key plus identical operation reuses the original job; conflicting work fails. Use secret_operation_status/output/cancel to manage it.",
      inputSchema: SSHJobStartInput,
      outputSchema: JobStartOutput,
      async handler(input) {
        const parsed = SSHJobStartInput.parse(input);
        return startResult(await client.request({
          type: "startSecretOperationIdempotent",
          descriptor: descriptorFromCommand(parsed),
          idempotencyKey: parsed.idempotencyKey
        }));
      }
    },
    {
      name: "ssh_batch_job_start",
      title: "Start SSH Batch Job",
      description:
        "Starts a structured SSH batch as an asynchronous job. Sanitized stdout/stderr becomes available through output cursors as each command completes. The required idempotencyKey prevents accidental duplicate starts.",
      inputSchema: SSHBatchJobStartInput,
      outputSchema: JobStartOutput,
      async handler(input) {
        const parsed = SSHBatchJobStartInput.parse(input);
        return startResult(await client.request({
          type: "startSecretOperationIdempotent",
          descriptor: descriptorFromBatch(parsed),
          idempotencyKey: parsed.idempotencyKey
        }));
      }
    },
    {
      name: "secret_operation_status",
      title: "Secret Operation Status",
      description:
        "Returns lifecycle state and non-output completion metadata for one operationID owned by this MCP principal. Read stdout/stderr only through secret_operation_output.",
      inputSchema: OperationIDInput,
      outputSchema: JobStatusOutput,
      async handler(input) {
        const parsed = OperationIDInput.parse(input);
        const response = await client.request({
          type: "secretOperationStatus",
          operationID: parsed.operationID
        });
        if (response.type !== "secretOperationStatus") {
          return structuredResult(statusOnly(response));
        }
        const output = response.result.output;
        return structuredResult({
          status: "OK",
          operationID: response.result.operationID,
          state: response.result.state,
          terminal: isTerminal(response.result.state),
          ...(response.result.errorCode == null ? {} : { errorCode: response.result.errorCode }),
          ...(response.result.nextOutputCursor === undefined
            ? {}
            : { nextOutputCursor: response.result.nextOutputCursor }),
          ...(output === undefined || output === null
            ? {}
            : {
                result: {
                  status: output.status,
                  ...(output.exitCode === undefined ? {} : { exitCode: output.exitCode }),
                  ...(output.stage === undefined ? {} : { stage: output.stage }),
                  ...(output.sessionID === undefined ? {} : { sessionID: output.sessionID }),
                  ...(output.failedIndex === undefined ? {} : { failedIndex: output.failedIndex })
                }
              }),
          redacted: true
        });
      }
    },
    {
      name: "secret_operation_output",
      title: "Secret Operation Output",
      description:
        "Reads already-sanitized stdout/stderr chunks using a monotonic cursor. It never exposes raw pre-sanitization SSH output. Advance with nextCursor until hasMore is false; running jobs may gain more chunks later.",
      inputSchema: OperationOutputInput,
      outputSchema: JobOutputPage,
      async handler(input) {
        const parsed = OperationOutputInput.parse(input);
        const response = await client.request({
          type: "secretOperationOutput",
          operationID: parsed.operationID,
          cursor: parsed.cursor,
          maxChunks: parsed.maxChunks
        });
        if (response.type !== "secretOperationOutput") {
          return structuredResult(statusOnly(response));
        }
        return structuredResult({
          status: "OK",
          ...response.result,
          redacted: true
        });
      }
    },
    {
      name: "secret_operation_cancel",
      title: "Cancel Secret Operation",
      description:
        "Requests cancellation for one operationID owned by this MCP principal. queued/awaitingApproval can cancel definitively; cancellation after execution starts may become outcomeUnknown and must not be retried blindly.",
      inputSchema: OperationIDInput,
      outputSchema: JobCancelOutput,
      async handler(input) {
        const parsed = OperationIDInput.parse(input);
        const response = await client.request({
          type: "cancelSecretOperation",
          operationID: parsed.operationID
        });
        if (response.type !== "secretOperationStatus") {
          return structuredResult(statusOnly(response));
        }
        return structuredResult({
          status: "OK",
          operationID: response.result.operationID,
          state: response.result.state,
          terminal: isTerminal(response.result.state),
          ...(response.result.errorCode == null ? {} : { errorCode: response.result.errorCode }),
          redacted: true
        });
      }
    }
  ];
}
