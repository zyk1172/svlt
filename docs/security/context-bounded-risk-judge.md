# Context-bounded operation risk judge

SVLT can optionally run a fresh semantic risk classification immediately before an MCP `executeSecretOperation` request enters the daemon. The judge is intentionally narrow: it is not a second general-purpose Agent and it has no tools, memory, conversation history, or Secret plaintext.

## Why this exists

The main Agent knows the user's task, but it is also the component proposing the operation. Its own risk narrative is therefore not an authorization authority. A separate model call gives SVLT a semantic view of the actual operation without inheriting the main conversation's accumulated instructions or prompt-injection surface.

The independent judge complements the deterministic SSH, database, HTTP, and transfer classifiers. It does not replace them.

## Input contract

Each judgment is a new stateless request. The judge receives only:

1. **Problem statement** — the main Agent's concise `intendedEffect`, sanitized and limited to 256 characters. It should describe the problem being solved, not argue that an operation is safe or pre-approved.
2. **Canonical operation** — the concrete operation about to be submitted to SVLT: action type, destination/protocol/port, command or statement, HTTP method/URL, file action, and a bounded list of requested effects as applicable.
3. **Secret count** — only the number of referenced credentials. The judge does not receive `secret://` identifiers or resolved plaintext.

The judge does **not** receive:

- prior chat turns or system/developer prompts from the main Agent;
- Memory or profile context;
- the main Agent's free-form risk reason;
- tools or execution access;
- resolved Secret plaintext;
- credential parameters or opaque Secret IDs.

Command-like fields are bounded to control latency. Embedded `secret://` references are locally replaced with `<secret-reference>` before a remote request.

## Output contract

The response must be one small JSON object:

```json
{
  "secretSensitivity": "low | important | critical",
  "operationRisk": "readOnly | mutating | destructive | catastrophic | unknown",
  "impact": "limited | material | severe | unknown",
  "automaticExecution": true,
  "approval": "none | reusable | fresh",
  "confidence": 0.95,
  "reason": "brief explanation"
}
```

SVLT normalizes the model response before it can affect policy:

- `destructive`, `catastrophic`, and `unknown` always become `fresh` approval and cannot auto-execute;
- confidence below `0.65` always becomes `fresh` approval;
- an automatic result is accepted only when approval is `none`;
- the daemon requires at least `0.80` confidence plus `readOnly` or `mutating` risk before an ordinary reusable operation can be reduced to no approval.

## Policy merge

The deterministic policy engine remains the floor.

- malformed or contradictory requests remain denied;
- deterministic high-impact/fresh rules cannot be downgraded by the judge;
- an independent judge may promote an ordinary operation from reusable to fresh approval;
- an independent judge may reduce an ordinary reusable operation to automatic execution only under the strict conditions above;
- legacy `AgentRiskAssessment` values that were produced by the main Agent remain display/audit hints only.

If the configured judge times out, is unavailable, or returns invalid output, SVLT synthesizes `operationRisk=unknown`, `approval=fresh`, `automaticExecution=false`, and confidence `0`.

## Prompt-injection boundary

The system prompt explicitly treats both the problem and operation text as untrusted data. Instructions embedded inside a command, URL, SQL statement, filename, or problem statement do not become judge instructions.

This reduces cross-agent influence but is not a claim that an LLM is a formal verifier. Deterministic classification and executor validation continue to enforce non-negotiable boundaries.

## Configuration

The MCP server uses an OpenAI-compatible chat-completions endpoint when both of these are set:

- `SVLT_RISK_JUDGE_URL`
- `SVLT_RISK_JUDGE_MODEL`

Optional:

- `SVLT_RISK_JUDGE_API_KEY`
- `SVLT_RISK_JUDGE_TIMEOUT_MS` — default 3500 ms, clamped to 750–10000 ms.

Remote endpoints must use HTTPS. Plain HTTP is accepted only for `localhost` or `127.0.0.1`, which supports a small local model without sending the operation over the network.

If no judge is configured, the existing authorization behavior remains available. A caller-provided `SVLT_JUDGE_V1` marker is stripped at the MCP client boundary rather than being accepted as an independent judgment.

## Latency budget

The judge request is deliberately kept small: a 256-character problem, bounded operation fields, no history, temperature 0, and a maximum response budget of 260 tokens. It runs once for each `executeSecretOperation` request so the judgment is tied to the concrete operation rather than a long-lived conversation state.
