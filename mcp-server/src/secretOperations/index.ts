import type {
  SecretOperationAction,
  SecretOperationDescriptor
} from "../protocol.js";
import {
  startSecretOperation,
  type SecretOperationIpcClient
} from "./client.js";
import {
  pollSecretOperation,
  type SecretOperationPollingOptions
} from "./polling.js";
import {
  OPERATION_CANCELLED
} from "./protocol.js";
import {
  isSecretOperationOutput,
  transportOutcomeUnknown,
  type SecretOperationExecutionResult
} from "./result.js";

export {
  OPERATION_CANCELLED,
  OPERATION_NOT_FOUND,
  OPERATION_OUTCOME_UNKNOWN,
  OUTCOME_UNKNOWN_GUIDANCE
} from "./protocol.js";
export { isSecretOperationOutput } from "./result.js";
export type {
  SecretOperationExecutionResult
} from "./result.js";

export async function executeOpaqueOperation(
  client: SecretOperationIpcClient,
  descriptor: SecretOperationDescriptor,
  signal?: AbortSignal,
  pollingOptions: Omit<SecretOperationPollingOptions, "signal"> = {}
): Promise<SecretOperationExecutionResult> {
  // SSH is the only exception because its transport tool is already the
  // capability-owned execution boundary. Destination binding is App-owned and
  // likewise does not depend on an adapter manifest entry.
  if (descriptor.actionType !== "sshCommand" && descriptor.actionType !== "changeDestinationBinding") {
    const capabilityStatus = await ensureSecretOperationCapability(client, descriptor.actionType);
    if (capabilityStatus !== undefined) {
      return { status: capabilityStatus };
    }
  }

  if (signal?.aborted === true) {
    return { status: OPERATION_CANCELLED };
  }

  let started;
  try {
    started = await startSecretOperation(client, descriptor);
  } catch {
    // A transport exception does not tell us whether the daemon accepted the
    // start frame. Conservatively treat it as outcome-unknown so an Agent does
    // not repeat a potentially side-effecting operation.
    return transportOutcomeUnknown();
  }

  if (started.kind === "failure") {
    return { status: started.code };
  }
  if (started.kind === "unexpected") {
    return transportOutcomeUnknown();
  }

  await pollingOptions.onState?.(started.value.state, started.value.operationID);
  return pollSecretOperation(client, started.value.operationID, {
    ...pollingOptions,
    signal
  });
}

async function ensureSecretOperationCapability(
  client: SecretOperationIpcClient,
  action: SecretOperationAction
): Promise<string | undefined> {
  const response = await client.request({ type: "secretOperationCapabilities" });
  if (response.type !== "secretOperationCapabilities") {
    return response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE";
  }

  const matching = response.capabilities.filter((capability) => capability.operations.includes(action));
  if (matching.some((capability) => capability.status === "supported")) {
    return undefined;
  }
  if (matching.some((capability) => capability.status === "invalidParameters")) {
    return "ARGUMENT_VALIDATION";
  }
  return "ACTION_EXECUTOR_UNAVAILABLE";
}

// Keep a local reference so TypeScript verifies the exported type guard stays
// compatible with the execution result union as this module evolves.
void isSecretOperationOutput;
