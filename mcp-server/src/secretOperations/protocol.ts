import { z } from "zod";

import {
  IpcRequest as BaseIpcRequest,
  IpcResponse as BaseIpcResponse,
  SecretOperationDescriptor,
  SecretOperationOutput
} from "../protocol.js";

export const SecretOperationState = z.enum([
  "queued",
  "awaitingApproval",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "outcomeUnknown"
]);
export type SecretOperationState = z.infer<typeof SecretOperationState>;

export const SecretOperationHandle = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  reused: z.boolean().optional()
}).strict();
export type SecretOperationHandle = z.infer<typeof SecretOperationHandle>;

export const SecretOperationStatus = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  output: SecretOperationOutput.nullable().optional(),
  errorCode: z.string().min(1).max(128).nullable().optional(),
  nextOutputCursor: z.number().int().nonnegative().optional()
}).strict();
export type SecretOperationStatus = z.infer<typeof SecretOperationStatus>;

export const SecretOperationOutputChunk = z.object({
  cursor: z.number().int().nonnegative(),
  stream: z.enum(["stdout", "stderr"]),
  text: z.string(),
  commandIndex: z.number().int().nonnegative().nullable().optional()
}).strict();
export type SecretOperationOutputChunk = z.infer<typeof SecretOperationOutputChunk>;

export const SecretOperationOutputPage = z.object({
  operationID: z.string().uuid(),
  state: SecretOperationState,
  cursor: z.number().int().nonnegative(),
  nextCursor: z.number().int().nonnegative(),
  chunks: z.array(SecretOperationOutputChunk).max(64),
  hasMore: z.boolean()
}).strict();
export type SecretOperationOutputPage = z.infer<typeof SecretOperationOutputPage>;

export const SecretOperationLifecycleRequest = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("startSecretOperation"),
    descriptor: SecretOperationDescriptor
  }).strict(),
  z.object({
    type: z.literal("startSecretOperationIdempotent"),
    descriptor: SecretOperationDescriptor,
    idempotencyKey: z.string().min(1).max(128)
  }).strict(),
  z.object({
    type: z.literal("secretOperationStatus"),
    operationID: z.string().uuid()
  }).strict(),
  z.object({
    type: z.literal("secretOperationOutput"),
    operationID: z.string().uuid(),
    cursor: z.number().int().nonnegative(),
    maxChunks: z.number().int().min(1).max(64)
  }).strict(),
  z.object({
    type: z.literal("cancelSecretOperation"),
    operationID: z.string().uuid()
  }).strict()
]);
export type SecretOperationLifecycleRequest = z.infer<typeof SecretOperationLifecycleRequest>;

export const IpcRequest = z.union([
  BaseIpcRequest,
  SecretOperationLifecycleRequest
]);
export type IpcRequest = z.infer<typeof IpcRequest>;

export const SecretOperationLifecycleResponse = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("secretOperationHandle"),
    result: SecretOperationHandle
  }).strict(),
  z.object({
    type: z.literal("secretOperationStatus"),
    result: SecretOperationStatus
  }).strict(),
  z.object({
    type: z.literal("secretOperationOutput"),
    result: SecretOperationOutputPage
  }).strict()
]);
export type SecretOperationLifecycleResponse = z.infer<typeof SecretOperationLifecycleResponse>;

export const IpcResponse = z.union([
  BaseIpcResponse,
  SecretOperationLifecycleResponse
]);
export type IpcResponse = z.infer<typeof IpcResponse>;

export const OPERATION_NOT_FOUND = "OPERATION_NOT_FOUND";
export const OPERATION_CANCELLED = "OPERATION_CANCELLED";
export const OPERATION_OUTCOME_UNKNOWN = "OPERATION_OUTCOME_UNKNOWN";

export const OUTCOME_UNKNOWN_GUIDANCE =
  "The operation may already have produced an external side effect. Do not retry automatically; reconcile the target state before deciding whether another operation is safe.";
