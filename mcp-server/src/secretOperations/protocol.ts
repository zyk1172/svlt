export {
  SecretOperationHandle,
  SecretOperationState,
  SecretOperationStatus
} from "../protocol.js";
export type {
  SecretOperationHandle as SecretOperationHandleValue,
  SecretOperationState as SecretOperationStateValue,
  SecretOperationStatus as SecretOperationStatusValue
} from "../protocol.js";

export const OPERATION_NOT_FOUND = "OPERATION_NOT_FOUND";
export const OPERATION_CANCELLED = "OPERATION_CANCELLED";
export const OPERATION_OUTCOME_UNKNOWN = "OPERATION_OUTCOME_UNKNOWN";

export const OUTCOME_UNKNOWN_GUIDANCE =
  "The operation may already have produced an external side effect. Do not retry automatically; reconcile the target state before deciding whether another operation is safe.";
