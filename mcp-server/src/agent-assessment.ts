import { z } from "zod";

import { AgentRiskAssessment } from "./protocol.js";

export const AgentRiskProposal = AgentRiskAssessment
  .omit({ source: true, declaredRisk: true })
  .describe(
    "Main Agent semantic assessment. Sensitive/privileged is distinct from dangerous: ordinary user-aligned work should recommend automatic; use freshApproval only for genuine destructive/high-impact effects or unnecessary Secret plaintext exposure; use uncertain only when effect or task alignment cannot be resolved."
  );

export type AgentRiskInput = { agentAssessment?: z.infer<typeof AgentRiskProposal> };

export function agentAssessment(input: AgentRiskInput): z.infer<typeof AgentRiskAssessment> {
  const proposal = input.agentAssessment ?? {
    reason: "Main Agent did not provide a semantic assessment",
    userGoal: "Complete the requested Secret-backed operation",
    taskContext: "No additional task context supplied",
    intendedEffect: "Perform the requested operation",
    expectedEffect: "Unknown until independently reviewed",
    expectedResult: "Complete the user's requested task",
    intentAlignment: "unclear" as const,
    effectSeverity: "unknown" as const,
    reversibility: "unknown" as const,
    secretHandling: "unknown" as const,
    executionRecommendation: "uncertain" as const,
    confidence: 0
  };
  return {
    source: "mainAgent",
    declaredRisk: proposal.executionRecommendation === "automatic" ? "silent" : "approvalRequired",
    ...proposal
  };
}
