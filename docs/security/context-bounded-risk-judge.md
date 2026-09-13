# Intent-first semantic authorization

SVLT is an Agent collaboration layer, not a generic command firewall. The user supplies the goal, the main Agent chooses the concrete steps, and SVLT keeps a narrow deterministic floor for technical validity, Secret plaintext exposure, and genuinely destructive/high-impact actions.

## Decision order

1. The main Agent sends a structured semantic assessment with `userGoal`, `taskContext`, `intendedEffect`, `expectedEffect`, `expectedResult`, task alignment, effect severity, reversibility, Secret handling, recommendation, and confidence.
2. Ordinary, high-confidence, user-aligned operations use the main-Agent fast path. There is no second model call.
3. SVLT calls its separately configured semantic judge only for a gray zone: uncertainty, unclear/unrelated task alignment, low confidence, unresolved semantic dimensions, dynamic/opaque execution, or an internally contradictory automatic recommendation.
4. The daemon consumes the structured assessment directly. String marker protocols such as `SVLT_JUDGE_V1`, `SVLT_JUDGE_V2`, and `SVLT_AGENT_V2` are retired rather than supported as a compatibility layer.
5. Malformed or identity-invalid operations are still denied. Fixed hard-floor rules still require fresh approval regardless of semantic recommendation.

## Sensitive is not dangerous

`sudo`, root access, sensitive system paths, ordinary credential use, API/database access, configuration edits, service restarts, and other privileged operations are not approval-worthy by vocabulary alone. If the real effect is bounded/reversible, serves the user's goal, and does not expose managed Secret plaintext to an unnecessary recipient or output, the desired recommendation is `automatic`.

## Independent judge isolation

SVLT itself invokes the configured judge endpoint. It does not depend on Hermes, Codex, Claude, OpenClaw, or another Agent framework's sub-agent implementation. The judge receives a bounded redacted packet containing the user's goal, task context, intended/expected effect and result, the main Agent's assessment, SVLT's gray-zone signal, and the canonical concrete operation. The old 256-character problem budget is removed.

The judge never receives managed Secret plaintext or `secret://` identifiers. Common bearer-token, password/token/API-key, and private-key shapes in semantic context are redacted before a remote call. It does not receive the Agent software's system prompt, complete chat history, memory, or tools.

## Hard floor

The semantic layer cannot override malformed/identity-invalid requests. The non-downgradable fresh-approval set is intentionally small:

- explicit Secret/plaintext control paths and vault/security-control mutations;
- plaintext FTP credential transport;
- insecure HTTP credential transport and credentials embedded in URLs;
- arbitrary local-process Secret release;
- machine power control, block-device/filesystem destruction, and storage/RAID destruction;
- destructive database schema changes and privilege/account administration.

Other lexical fresh classifications (for example bounded file deletion, HTTP DELETE, SFTP replacement, container removal, or database data mutation) are semantic signals, not permanent vetoes: a structured assessment may reduce them when the actual operation is bounded and aligned with the user's request.
