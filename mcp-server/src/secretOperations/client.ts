import type { SecretOperationDescriptor } from "../protocol.js";
import type {
  IpcRequest,
  IpcResponse,
  SecretOperationHandle,
  SecretOperationStatus
} from "./protocol.js";

export interface SecretOperationIpcClient {
  request(request: IpcRequest): Promise<IpcResponse>;
}

export type LifecycleControlResult<T> =
  | { kind: "value"; value: T }
  | { kind: "failure"; code: string }
  | { kind: "unexpected" };

export async function startSecretOperation(
  client: SecretOperationIpcClient,
  descriptor: SecretOperationDescriptor
): Promise<LifecycleControlResult<SecretOperationHandle>> {
  const response = await client.request({
    type: "startSecretOperation",
    descriptor
  });
  if (response.type === "secretOperationHandle") {
    return { kind: "value", value: response.result };
  }
  return controlFailure(response);
}

export async function getSecretOperationStatus(
  client: SecretOperationIpcClient,
  operationID: string
): Promise<LifecycleControlResult<SecretOperationStatus>> {
  const response = await client.request({
    type: "secretOperationStatus",
    operationID
  });
  if (response.type === "secretOperationStatus") {
    return { kind: "value", value: response.result };
  }
  return controlFailure(response);
}

export async function cancelSecretOperation(
  client: SecretOperationIpcClient,
  operationID: string
): Promise<LifecycleControlResult<SecretOperationStatus>> {
  const response = await client.request({
    type: "cancelSecretOperation",
    operationID
  });
  if (response.type === "secretOperationStatus") {
    return { kind: "value", value: response.result };
  }
  return controlFailure(response);
}

function controlFailure(response: IpcResponse): LifecycleControlResult<never> {
  return response.type === "failure"
    ? { kind: "failure", code: response.code }
    : { kind: "unexpected" };
}
