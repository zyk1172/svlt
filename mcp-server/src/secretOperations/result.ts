import type { SecretOperationOutput } from "../protocol.js";
import type { SecretOperationStatus } from "./protocol.js";
import {
  OPERATION_CANCELLED,
  OPERATION_OUTCOME_UNKNOWN
} from "./protocol.js";

export type SecretOperationExecutionResult =
  | SecretOperationOutput
  | { status: string };

export function terminalSecretOperationResult(
  status: SecretOperationStatus
): SecretOperationExecutionResult {
  switch (status.state) {
    case "succeeded":
      return status.output ?? { status: "UNEXPECTED_RESPONSE" };
    case "failed":
      // Preserve the daemon's stable failure code verbatim. The MCP layer must
      // not invent a second vocabulary for authorization or executor errors.
      return { status: status.errorCode ?? "ACTION_EXECUTION_FAILED" };
    case "cancelled":
      return { status: status.errorCode ?? OPERATION_CANCELLED };
    case "outcomeUnknown":
      return { status: status.errorCode ?? OPERATION_OUTCOME_UNKNOWN };
    case "queued":
    case "awaitingApproval":
    case "running":
      return { status: "UNEXPECTED_RESPONSE" };
  }
}

export function transportOutcomeUnknown(): SecretOperationExecutionResult {
  return { status: OPERATION_OUTCOME_UNKNOWN };
}

export function isSecretOperationOutput(
  value: SecretOperationExecutionResult
): value is SecretOperationOutput {
  return "redacted" in value;
}
