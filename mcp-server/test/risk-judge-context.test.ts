import { describe, expect, it } from "vitest";

import type { IpcRequest } from "../src/protocol.js";
import {
  applyContextBoundedRiskJudge,
  type RiskJudgeConfiguration,
  type RiskJudgeTransport
} from "../src/risk-judge.js";

const configuration: RiskJudgeConfiguration = {
  endpoint: "https://judge.example/v1/chat/completions",
  model: "risk-model",
  timeoutMs: 2_000
};

describe("risk judge context privacy", () => {
  it("redacts opaque secret references embedded in executable text", async () => {
    const reference = "secret://01ARZ3NDEKTSV4RRFFQ69G5FAV";
    const request = {
      type: "executeSecretOperation",
      descriptor: {
        actionType: "sshCommand",
        secretReferences: [reference],
        destination: "nas.home.arpa",
        port: 22,
        protocolType: "ssh",
        command: `printf '%s' ${reference}`,
        requestedEffects: [],
        parameters: {},
        agentAssessment: {
          declaredRisk: "silent",
          reason: "main-agent hint",
          intendedEffect: "Inspect an opaque credential reference without revealing it"
        }
      }
    } as IpcRequest;

    let body = "";
    const transport: RiskJudgeTransport = {
      async fetch(_input, init) {
        body = String(init?.body ?? "");
        return new Response(JSON.stringify({
          choices: [{ message: { content: JSON.stringify({
            secretSensitivity: "important",
            operationRisk: "readOnly",
            impact: "limited",
            automaticExecution: false,
            approval: "reusable",
            confidence: 0.9,
            reason: "No destructive effect"
          }) } }]
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
    };

    await applyContextBoundedRiskJudge(request, configuration, transport);
    expect(body).toContain("<secret-reference>");
    expect(body).not.toContain(reference);
  });
});
