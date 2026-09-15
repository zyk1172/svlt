import { z } from "zod";

import { AgentRiskAssessment } from "./protocol.js";

export const AgentRiskProposal = AgentRiskAssessment
  .omit({ source: true, declaredRisk: true })
  .describe(
    "Main Agent semantic assessment. SVLT authorization is effect-based, not secret-use-based: sensitive/privileged is distinct from dangerous, and ordinary user-aligned work should recommend automatic even on first Secret use. Use freshApproval only for genuine destructive/high-impact effects or credential exposure, denied only when the supplied effect is prohibited or unsafe to execute, and uncertain only when effect or task alignment cannot be resolved. reusableApproval is a legacy compatibility spelling and is normalized to automatic."
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
  const executionRecommendation = proposal.executionRecommendation === "reusableApproval"
    ? "automatic"
    : proposal.executionRecommendation;
  return {
    source: "mainAgent",
    declaredRisk: executionRecommendation === "automatic"
      ? "silent"
      : executionRecommendation === "denied" ? "denied" : "approvalRequired",
    ...proposal,
    executionRecommendation
  };
}
