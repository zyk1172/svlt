import { describe, expect, it } from "vitest";

import { annotateOutcomeUnknownResult } from "../src/runtime.js";
import {
  OPERATION_OUTCOME_UNKNOWN,
  OUTCOME_UNKNOWN_GUIDANCE
} from "../src/secretOperations/index.js";

describe("MCP runtime lifecycle presentation", () => {
  it("marks outcomeUnknown as reconciliation-required without changing structured schema", () => {
    const result = annotateOutcomeUnknownResult({
      structuredContent: { status: OPERATION_OUTCOME_UNKNOWN },
      content: [{ type: "text", text: JSON.stringify({ status: OPERATION_OUTCOME_UNKNOWN }) }]
    });

    expect(result.structuredContent).toEqual({ status: OPERATION_OUTCOME_UNKNOWN });
    expect(result.isError).not.toBe(true);
    expect(result.content).toEqual([{
      type: "text",
      text: JSON.stringify({
        status: OPERATION_OUTCOME_UNKNOWN,
        retrySafe: false,
        reconciliationRequired: true,
        guidance: OUTCOME_UNKNOWN_GUIDANCE
      })
    }]);
  });

  it("leaves ordinary results unchanged", () => {
    const result = {
      structuredContent: { status: "COMPLETED", redacted: true },
      content: [{ type: "text" as const, text: "completed" }]
    };
    expect(annotateOutcomeUnknownResult(result)).toBe(result);
  });
});
