import { z } from "zod";

import { AgentRiskProposal } from "./agent-assessment.js";
import { SecretReference, SSHCommandBatch, SSHCommandSpec } from "./protocol.js";

export const SshCommandInput = z
  .object({
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/).optional(),
    passwordRef: SecretReference,
    // Raw remote command: single-line or multi-line (newlines, quotes,
    // pipelines, redirects, heredocs, interpreters are all allowed). SVLT
    // never parses shell syntax; the remote login shell does. The ceiling is
    // UTF-8 bytes to match the Swift side exactly (§61): Zod's .max() counts
    // UTF-16 code units, which diverges for CJK/emoji input.
    command: z
      .string()
      .min(1)
      .refine((value) => Buffer.byteLength(value, "utf8") <= 65_536, {
        message: "command must be at most 65536 UTF-8 bytes"
      }),
    sessionID: z.string().min(1).max(128).optional(),
    timeoutMs: z.number().int().positive().optional().describe(
      "Deprecated compatibility field; ignored. SSH execution has no fixed deadline."
    ),
    agentAssessment: AgentRiskProposal
  })
  .strict();

export const SshCommandBatchInput = z
  .object({
    host: z.string().min(1).max(253),
    port: z.number().int().min(1).max(65_535).optional(),
    username: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/).optional(),
    passwordRef: SecretReference,
    sessionID: z.string().min(1).max(128).optional(),
    commands: z.array(SSHCommandSpec).min(1).max(32),
    stopOnFailure: z.boolean().default(true),
    timeoutMs: z.number().int().positive().optional().describe(
      "Deprecated compatibility field; ignored. SSH execution has no fixed deadline."
    ),
    agentAssessment: AgentRiskProposal
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
