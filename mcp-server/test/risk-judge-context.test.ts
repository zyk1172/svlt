import { describe, expect, it } from "vitest";
import type { IpcRequest } from "../src/secretOperations/protocol.js";
import { applyContextBoundedRiskJudge, type RiskJudgeConfiguration, type RiskJudgeTransport } from "../src/risk-judge.js";

const configuration: RiskJudgeConfiguration = { endpoint: "https://judge.example/v1/chat/completions", model: "risk-model", timeoutMs: 2_000 };

describe("semantic judge context privacy", () => {
  it("redacts Secret references and common credential-shaped context", async () => {
    const reference = "secret://01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const request = {
      type: "executeSecretOperation",
      descriptor: {
        actionType: "sshCommand",
        secretReferences: [reference],
        destination: "nas.home.arpa",
        port: 22,
        protocolType: "ssh",
        command: `eval \"printf '%s' ${reference}\"`,
        requestedEffects: [],
        parameters: {},
        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "approvalRequired",
          reason: "token=VERY_SECRET_TOKEN_VALUE",
          userGoal: "Diagnose auth using Bearer ABCDEFGHIJKLMNOP",
          taskContext: "Authentication is failing and the next step is opaque dynamic execution",
          intendedEffect: "Inspect the auth failure",
          expectedEffect: "Unknown",
          expectedResult: "Find the cause",
          intentAlignment: "unclear",
          effectSeverity: "unknown",
          reversibility: "unknown",
          secretHandling: "unknown",
          executionRecommendation: "uncertain",
          confidence: 0.4
        }
      }
    } as IpcRequest;

    let body = "";
    const transport: RiskJudgeTransport = {
      async fetch(_input, init) {
        body = String(init?.body ?? "");
        return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify({
          reason: "No destructive effect",
          intentAlignment: "supporting",
          effectSeverity: "minor",
          reversibility: "easy",
          secretHandling: "credentialUse",
          executionRecommendation: "automatic",
          confidence: 0.9
        }) } }] }), { status: 200, headers: { "content-type": "application/json" } });
      }
    };

    await applyContextBoundedRiskJudge(request, {
      route: "gray",
      policyRuleID: "ssh.semantic.opaque",
      authorizationRequirement: "freshApprovalRequired",
      blastRadius: "unknown",
      reasons: ["dynamic execution"],
      technicalFailure: false
    }, configuration, transport);
    expect(body).toContain("<secret-reference>");
    expect(body).not.toContain(reference);
    expect(body).not.toContain("VERY_SECRET_TOKEN_VALUE");
    expect(body).not.toContain("ABCDEFGHIJKLMNOP");
    expect(body).toContain("token=<redacted>");
    expect(body).toContain("Bearer <redacted>");
  });
});
