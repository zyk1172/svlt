import { describe, expect, it } from "vitest";
import type { IpcRequest } from "../src/secretOperations/protocol.js";
import { applyContextBoundedRiskJudge, type RiskJudgeConfiguration, type RiskJudgeTransport } from "../src/risk-judge.js";

const configuration: RiskJudgeConfiguration = {
  endpoint: "https://judge.example/v1/chat/completions",
  model: "risk-model",
  timeoutMs: 2_000
};

const canaries = {
  bearer: "SVLT_BEARER_CANARY_4D1C99A7",
  basic: "U1ZMVDpCQVNJQ19DQU5BUllfNEQxQzk5QTc=",
  password: "SVLT_PASSWORD_CANARY_4D1C99A7",
  cliToken: "SVLT_CLI_TOKEN_CANARY_4D1C99A7",
  apiKey: "SVLT_API_KEY_CANARY_4D1C99A7",
  urlPassword: "SVLT_URL_PASSWORD_CANARY_4D1C99A7",
  queryToken: "SVLT_QUERY_TOKEN_CANARY_4D1C99A7",
  database: "SVLT_DATABASE_KEY_CANARY_4D1C99A7",
  fileTarget: "SVLT_FILE_PASSWORD_CANARY_4D1C99A7",
  effect: "SVLT_EFFECT_TOKEN_CANARY_4D1C99A7",
  sshArgument: "SVLT_SSH_SECRET_CANARY_4D1C99A7",
  context: "SVLT_CONTEXT_SECRET_CANARY_4D1C99A7",
  privateKeyBody: "SVLT_PRIVATE_KEY_CANARY_4D1C99A7"
};

describe("semantic judge canonical operation privacy", () => {
  it("redacts credential-shaped plaintext from every free-text operation surface", async () => {
    const privateKey = [
      "-----BEGIN PRIVATE KEY-----",
      canaries.privateKeyBody,
      "-----END PRIVATE KEY-----"
    ].join("\n");

    const request = {
      type: "executeSecretOperation",
      descriptor: {
        actionType: "sshCommand",
        secretReferences: ["secret://01ARZ3NDEKTSV4RRFFQ69G5FAV"],
        destination: "nas.home.arpa",
        port: 22,
        protocolType: "ssh",
        command: [
          "curl",
          `-H 'Authorization: Bearer ${canaries.bearer}'`,
          `-H 'Authorization: Basic ${canaries.basic}'`,
          `--password ${canaries.password}`,
          `--api-key=${canaries.apiKey}`
        ].join(" "),
        sshCommandBatch: {
          commands: [{
            executable: "sh",
            arguments: [
              "-lc",
              `tool --token ${canaries.cliToken} secret=${canaries.sshArgument}`,
              privateKey
            ]
          }]
        },
        httpMethod: "GET",
        url: `https://user:${canaries.urlPassword}@example.test/resource?token=${canaries.queryToken}&mode=inspect`,
        databaseStatement: `SELECT 'api_key=${canaries.database}' AS credential_probe`,
        fileOperation: "read",
        fileTarget: `/tmp/password=${canaries.fileTarget}/probe.txt`,
        requestedEffects: [
          `Inspect request metadata token=${canaries.effect}`,
          "Preserve bounded diagnostic semantics"
        ],
        parameters: {},
        agentAssessment: {
          source: "mainAgent",
          declaredRisk: "approvalRequired",
          reason: `secret=${canaries.context}`,
          userGoal: "Diagnose a bounded authentication failure",
          taskContext: "Opaque execution requires semantic review",
          intendedEffect: "Inspect authentication behavior",
          expectedEffect: "Read-only diagnostic output",
          expectedResult: "Identify the cause without exposing credentials",
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
        return new Response(JSON.stringify({
          choices: [{
            message: {
              content: JSON.stringify({
                reason: "Bounded diagnostic operation",
                intentAlignment: "supporting",
                effectSeverity: "minor",
                reversibility: "easy",
                secretHandling: "credentialUse",
                executionRecommendation: "automatic",
                confidence: 0.9
              })
            }
          }]
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
    };

    await applyContextBoundedRiskJudge(request, {
      route: "gray",
      policyRuleID: "ssh.semantic.opaque",
      authorizationRequirement: "freshApprovalRequired",
      blastRadius: "unknown",
      reasons: [`dynamic execution secret=${canaries.context}`],
      technicalFailure: false,
      reviewID: "00000000-0000-4000-8000-000000000088"
    }, configuration, transport);

    for (const canary of Object.values(canaries)) {
      expect(body).not.toContain(canary);
    }

    expect(body).not.toContain("secret://01ARZ3NDEKTSV4RRFFQ69G5FAV");
    expect(body).toContain("<secret-reference>");
    expect(body).toContain("Bearer <redacted>");
    expect(body).toContain("Basic <redacted>");
    expect(body).toContain("--password <redacted>");
    expect(body).toContain("--api-key=<redacted>");
    expect(body).toContain("token=<redacted>");
    expect(body).toContain("<private-key-redacted>");

    // Redaction must preserve enough operation semantics for the judge to make
    // an intent/effect decision instead of dropping the complete operation.
    expect(body).toContain("curl");
    expect(body).toContain("SELECT");
    expect(body).toContain("mode=inspect");
    expect(body).toContain("Preserve bounded diagnostic semantics");
  });
});
