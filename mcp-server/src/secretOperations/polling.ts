import type {
  SecretOperationState,
  SecretOperationStatus
} from "./protocol.js";
import {
  cancelSecretOperation,
  getSecretOperationStatus,
  type SecretOperationIpcClient
} from "./client.js";
import { OPERATION_NOT_FOUND } from "./protocol.js";
import {
  terminalSecretOperationResult,
  transportOutcomeUnknown,
  type SecretOperationExecutionResult
} from "./result.js";

export interface SecretOperationPollingOptions {
  signal?: AbortSignal;
  pollIntervalMs?: number;
  onState?: (state: SecretOperationState, operationID: string) => void | Promise<void>;
}

const DEFAULT_POLL_INTERVAL_MS = 100;

export async function pollSecretOperation(
  client: SecretOperationIpcClient,
  operationID: string,
  options: SecretOperationPollingOptions = {}
): Promise<SecretOperationExecutionResult> {
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;

  while (true) {
    if (options.signal?.aborted === true) {
      return cancelTrackedOperation(client, operationID, options);
    }

    let control;
    try {
      control = await getSecretOperationStatus(client, operationID);
    } catch {
      // startSecretOperation was already acknowledged. Losing the control
      // channel now cannot prove whether the executor crossed its side-effect
      // boundary, so fail closed as outcome-unknown rather than retrying.
      return transportOutcomeUnknown();
    }

    if (control.kind === "failure") {
      return controlFailureAfterStart(control.code);
    }
    if (control.kind === "unexpected") {
      return transportOutcomeUnknown();
    }

    const status = control.value;
    if (status.operationID !== operationID) {
      return transportOutcomeUnknown();
    }
    await options.onState?.(status.state, operationID);

    if (isTerminal(status)) {
      return terminalSecretOperationResult(status);
    }

    await waitForNextPoll(pollIntervalMs, options.signal);
  }
}

async function cancelTrackedOperation(
  client: SecretOperationIpcClient,
  operationID: string,
  options: SecretOperationPollingOptions
): Promise<SecretOperationExecutionResult> {
  let control;
  try {
    control = await cancelSecretOperation(client, operationID);
  } catch {
    return transportOutcomeUnknown();
  }

  if (control.kind === "failure") {
    return controlFailureAfterStart(control.code);
  }
  if (control.kind === "unexpected") {
    return transportOutcomeUnknown();
  }

  const status = control.value;
  if (status.operationID !== operationID || !isTerminal(status)) {
    return transportOutcomeUnknown();
  }
  await options.onState?.(status.state, operationID);
  return terminalSecretOperationResult(status);
}

function controlFailureAfterStart(code: string): SecretOperationExecutionResult {
  // OPERATION_NOT_FOUND is an explicit principal-safe lifecycle result from
  // the daemon and is safe to preserve. Other control-plane failures after a
  // start acknowledgement do not establish whether the side effect ran.
  return code === OPERATION_NOT_FOUND
    ? { status: code }
    : transportOutcomeUnknown();
}

function isTerminal(status: SecretOperationStatus): boolean {
  return status.state === "succeeded"
    || status.state === "failed"
    || status.state === "cancelled"
    || status.state === "outcomeUnknown";
}

async function waitForNextPoll(milliseconds: number, signal?: AbortSignal): Promise<void> {
  if (milliseconds <= 0 || signal?.aborted === true) return;

  await new Promise<void>((resolve) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = () => {
      if (timer !== undefined) clearTimeout(timer);
      signal?.removeEventListener("abort", finish);
      resolve();
    };
    timer = setTimeout(finish, milliseconds);
    signal?.addEventListener("abort", finish, { once: true });
  });
}
