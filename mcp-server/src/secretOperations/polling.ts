import type {
  SecretOperationState,
  SecretOperationStatus
} from "./protocol.js";
import {
  cancelSecretOperation,
  getSecretOperationStatus,
  type SecretOperationIpcClient
} from "./client.js";
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

// Cancellation wakes the wait immediately through AbortSignal, so polling does
// not need to run at UI-frame frequency. Four control reads per second keeps
// terminal-result latency low without repeatedly reopening the local IPC socket
// and rereading the capability token during a long approval wait.
const DEFAULT_POLL_INTERVAL_MS = 250;

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

    if (control.kind === "failure" || control.kind === "unexpected") {
      // Once a handle has been acknowledged, even OPERATION_NOT_FOUND cannot
      // prove that nothing happened: the terminal record may have been evicted
      // or daemon state may have been lost after an external side effect.
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

  if (control.kind === "failure" || control.kind === "unexpected") {
    // Failure to obtain a definitive cancellation receipt for an acknowledged
    // operation is itself outcome-unknown, regardless of the control error.
    return transportOutcomeUnknown();
  }

  const status = control.value;
  if (status.operationID !== operationID || !isTerminal(status)) {
    return transportOutcomeUnknown();
  }
  await options.onState?.(status.state, operationID);
  return terminalSecretOperationResult(status);
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
