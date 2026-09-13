import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import {
  IpcRequest,
  IpcResponse,
  OPERATION_CANCELLED,
  OPERATION_NOT_FOUND,
  OPERATION_OUTCOME_UNKNOWN
} from "../src/secretOperations/protocol.js";

const fixtureRoot = new URL("../../ProtocolFixtures/secret-operations/", import.meta.url);

async function fixtureMap(fileName: string): Promise<Record<string, unknown>> {
  const data = await readFile(new URL(fileName, fixtureRoot), "utf8");
  return JSON.parse(data) as Record<string, unknown>;
}

describe("shared Swift/TypeScript secret-operation protocol fixtures", () => {
  it("parses and serializes every request fixture without protocol drift", async () => {
    const fixtures = await fixtureMap("requests.json");
    expect(Object.keys(fixtures).sort()).toEqual([
      "cancelSecretOperation",
      "executeSecretOperation",
      "secretOperationStatus",
      "startSecretOperation"
    ]);

    for (const [name, fixture] of Object.entries(fixtures)) {
      const parsed = IpcRequest.parse(fixture);
      expect(JSON.parse(JSON.stringify(parsed)), name).toEqual(fixture);
    }
  });

  it("parses and serializes lifecycle response fixtures without protocol drift", async () => {
    const fixtures = await fixtureMap("responses.json");
    for (const [name, fixture] of Object.entries(fixtures)) {
      const parsed = IpcResponse.parse(fixture);
      expect(JSON.parse(JSON.stringify(parsed)), name).toEqual(fixture);
    }
  });

  it("pins lifecycle error semantics used by both language boundaries", async () => {
    const fixtures = await fixtureMap("responses.json");
    expect(JSON.stringify(fixtures.statusNotFoundOrForeignPrincipal)).toContain(OPERATION_NOT_FOUND);
    expect(JSON.stringify(fixtures.statusCancelled)).toContain(OPERATION_CANCELLED);
    expect(JSON.stringify(fixtures.statusOutcomeUnknown)).toContain(OPERATION_OUTCOME_UNKNOWN);
  });
});
