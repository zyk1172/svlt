import { AsyncLocalStorage } from "node:async_hooks";

const abortSignalContext = new AsyncLocalStorage<AbortSignal>();

export function runWithSecretOperationAbortSignal<T>(
  signal: AbortSignal | undefined,
  operation: () => T
): T {
  return signal === undefined
    ? operation()
    : abortSignalContext.run(signal, operation);
}

export function currentSecretOperationAbortSignal(): AbortSignal | undefined {
  return abortSignalContext.getStore();
}
