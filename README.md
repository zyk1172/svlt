<div align="center">
  <img src="AppAssets/SVLT-icon.svg" width="144" alt="SVLT icon" />

# SVLT

**Local-first secret infrastructure for AI agents on macOS.**

Keep credentials encrypted on-device, expose only opaque `secret://` references to agents, and let approved operations use secrets without returning plaintext to the model.
</div>

SVLT combines a native macOS app, a launchd-managed background Agent, an MCP adapter, and an optional Obsidian Catalog workflow. It is **opt-in**: SVLT only manages credentials the user explicitly places under SVLT control, and it does not claim ownership of credentials supplied through another provider or explicitly provided as plaintext for a specific operation.

```text
Agent / MCP client
      │
      │  opaque secret:// references + structured intent
      ▼
┌──────────────────────────────┐
│          SVLTAgent           │
│ encryption · authorization   │
│ audit · IPC · execution      │
└──────────────┬───────────────┘
               │
     approved local operation
               │
               ▼
 SSH · HTTP/API · DB · SFTP/SCP · FTP · browser · local app
```

## Why SVLT

- **Plaintext stays local.** Agents work with opaque references such as `secret://0123456789ABCDEFGHJKMNPQRS`; MCP tools do not return decrypted credentials.
- **Intent-first authorization.** The main Agent supplies a structured assessment of the user's goal, intended effect, expected result, reversibility, Secret handling, and confidence. SVLT keeps a deterministic safety floor and calls an independent semantic judge only for gray-zone operations.
- **Effect-based approval, not Secret-use approval.** `AUTO` covers ordinary read-only, bounded/reversible, task-aligned work—including controlled use of a saved Secret, normal configuration/file writes, CRUD, Docker/service operations, and HTTPS authentication. A first Secret use, a new operation ID, a new transport session, elapsed time, or the fact that a Secret exists does not create an approval prompt. `GRAY` is reserved for unresolved effect semantics; `HARD`/fresh approval protects genuinely high-impact or irreversible actions; existing `DENIED` boundaries remain denied.
- **User intent matters more than scary words.** `sudo`, root access, sensitive paths, credential-backed API calls, bounded configuration edits, and service restarts are not automatically treated as dangerous simply because of vocabulary.
- **A narrow non-downgradable floor remains.** Explicit plaintext exposure, insecure credential transport, arbitrary local-process Secret release, identity/technical failures, and genuinely destructive/systemic operations still require hard local handling.
- **Long-running work has an operation lifecycle.** Secret operations use `operationID` states such as queued, awaiting approval, running, succeeded, failed, cancelled, and outcome-unknown. Approval validity is separate from execution lifetime; once an operation is approved and running, the authorization window is not used as a wall-clock execution timeout.
- **Batch is a transport optimization only.** SSH batch can reduce connection/protocol overhead, but it is never required to avoid approval. SVLT evaluates each operation's actual effect independently; ordinary operations stay automatic even when they are separate MCP calls.
- **Background service stays independent of the UI.** `SVLT.app` may quit while `SVLTAgent` continues serving Vault, MCP, and Obsidian IPC requests without loading SwiftUI or opening a window.
- **Catalog edits preserve user Markdown.** The daemon owns mutable Catalog state and applies source-range patches rather than rewriting an entire document. Notes, WikiLinks, comments, callouts, whitespace, and unrelated Markdown remain in place.
- **Audit history is bounded on normal reads.** Recent audit access uses an authenticated recent index, while full-history integrity scans run separately at low frequency instead of making every UI read scale with the entire log.

## Components

| Component | Responsibility |
| --- | --- |
| `SVLT.app` | UI, settings, Catalog selection, local reveal presentation, service registration |
| `SVLTAgent` | encryption/decryption, authorization, semantic review coordination, Unix-socket IPC, audit, migration, transaction rollback, controlled execution |
| `mcp-server` | MCP tools, structured Agent assessment, operation lifecycle client, gray-zone judge routing |
| `obsidian-plugin/svlt` | read-only Catalog validation and diagnostics for Obsidian |

## Install

Normal users do **not** need Xcode.

1. Download and unzip `SVLT-release.zip`.
2. Double-click `install.command`. If macOS blocks it, right-click and choose **Open**. Terminal users may run `install.sh`.
3. Open SVLT.
4. Use the generated MCP configuration:

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

5. Add the required [Agent sensitive-information policy](docs/svlt-agent-policy-zh-CN.md) to the MCP client's system prompt, project rule, or workspace instruction.

The installer places the app and embedded Agent in `/Applications/SVLT.app` or `~/Applications/SVLT.app`, installs the MCP server under `~/Library/Application Support/AgentSecretVault/MCP`, and generates the MCP config above.

On first launch, `SVLT.app` registers its embedded LaunchAgent with `SMAppService.agent`. If macOS asks for approval, use **System Settings → General → Login Items**. Do not manually copy the plist into `~/Library/LaunchAgents`.

Requirements for normal use:

- macOS 14 or newer
- Node.js 24 or newer for the MCP server

中文教程：[docs/zh-CN.md](docs/zh-CN.md)
Agent integration: [docs/universal-agent-usage.md](docs/universal-agent-usage.md)

## Catalog and Obsidian workflow

Select an existing `敏感信息.md` as the active **SVLT Catalog v3** document. The Catalog is ordinary Markdown with real `##` group headings, `###` entry headings, stable SVLT markers, visible non-secret metadata, and opaque `secret://` references. Encrypted records remain inside the local Vault.

SVLT treats the selected document as an immutable document identity for each operation. GUI selection changes cannot redirect an in-flight read or write. Agent mutations are validated by semantic diff and patched into the relevant source range instead of canonicalizing the whole document.

The Obsidian plugin is intentionally read-only: it validates Catalog structure and reports diagnostics, but it never encrypts, decrypts, repairs, or writes managed Catalog content and never returns plaintext.

## Agent discovery and Catalog tools

When an Agent knows the service, host, account, or purpose but not the credential source, it may use `secret_search`. The search is metadata-only and returns Entry-centric results with allowed metadata, endpoints, and opaque `secretRef` values. It does not return plaintext, the Catalog path, or the complete `敏感信息.md`.

An explicit user-selected source always wins. If the user chooses a different provider or supplies plaintext for the current operation, SVLT must not silently import, compare, or replace that value with an SVLT-managed Secret.

Use `secret_catalog_batch` for multi-operation Catalog changes under one lock/revision. Creating groups/entries, ordinary metadata, empty password placeholders, and validation are safe by default; binding/replacing/deleting existing Secrets or changing their targets retains the required local authorization boundary.

## Local-use tools

SVLT provides purpose-built tools so a managed Secret can be consumed locally without being returned to the Agent:

- `ssh_command_with_secret`
- `local_http_request_with_secret`
- `api_request_with_token`
- `database_query_with_secret`
- `sftp_transfer_with_secret`
- `ftp_transfer_with_secret`
- `secret_bind_destination`
- `secret_review_ssh_host_key`
- `browser_web_login_with_secret`
- `local_app_form_fill_with_secret`

SFTP/SCP transfers accept explicit absolute local paths outside SVLT storage. Remote transfer paths are not restricted to an SVLT-owned destination directory. `SVLT Downloads` remains only the convenience fallback when a download omits `localPath`.

Tool results are status, metadata, or sanitized previews only. Plaintext credentials, Authorization headers, cookies, and filled field values must not be returned to the Agent.

## Intent-first authorization

SVLT is an Agent collaboration layer, not a generic command firewall.

The main Agent sends a structured assessment containing the user's goal, task context, intended and expected effects, expected result, task alignment, effect severity, reversibility, Secret handling, execution recommendation, and confidence. The daemon performs deterministic preflight and returns one of four semantic routes:

| Route | Meaning |
| --- | --- |
| `FAST` | Deterministic checks are satisfied; proceed without a second model call |
| `GRAY` | The concrete effect is unresolved, dynamic, opaque, low-confidence, contradictory, or outside a verified target/protocol binding; invoke SVLT's independent judge |
| `HARD` | A non-downgradable local approval boundary applies |
| `DENIED` | The request is technically/semantically invalid and stays denied |

The independent judge receives only a bounded, redacted task packet. It never receives SVLT-managed plaintext, `secret://` identifiers, the Agent framework's system prompt, full chat history, memory, or tools. Common password/token/private-key shapes are redacted before any remote judge call.

For the complete model, see [Intent-first semantic authorization](docs/security/context-bounded-risk-judge.md).

## Security model

SVLT's current security boundary is built around these rules:

1. **SVLT-managed plaintext stays inside the local trusted boundary.** The ordinary Agent IPC transport has no plaintext-bearing response path.
2. **Semantic judgment cannot override technical/identity validity.** Malformed or identity-invalid operations remain denied.
3. **Gray-zone judgment is isolated.** The optional remote judge is called by SVLT itself and receives only redacted, bounded context.
4. **The hard floor is intentionally small.** Examples include explicit Secret/plaintext control paths, insecure HTTP/FTP credential transport, arbitrary local-process Secret release, machine power control, block-device/filesystem destruction, storage/RAID destruction, destructive database schema changes, and privilege/account administration.
5. **Ordinary destructive-looking syntax is context-sensitive.** Bounded file deletion, HTTP DELETE, SFTP replacement, container removal, or database data mutation can be treated as semantic signals rather than permanent vetoes when the actual operation is aligned and bounded.
6. **Cancellation is conservative after side effects may have started.** A running operation may end as `outcomeUnknown`; callers must reconcile target state instead of automatically retrying.
7. **Audit and cryptographic state remain local.** Audit writes use an independent Keychain key, recent reads are bounded, and full integrity diagnostics remain available separately.
8. **Runtime authorization is invalidated on security-state changes.** Screen lock, sleep, session changes, explicit lock, and Agent restart clear protected runtime state.

Further security documentation:

- [Threat model](docs/security/threat-model.md)
- [Crypto hardening](docs/security/crypto-hardening.md)
- [Operation authorization](docs/security/operation-authorization.md)
- [Intent-first semantic authorization](docs/security/context-bounded-risk-judge.md)
- [Release checklist](docs/security/release-checklist.md)

## Recovery

Recovery uses a synchronizable iCloud Keychain wrapping key plus wrapped master-key bytes. Recovery does not weaken normal device-local authorization. If required Keychain controls are unavailable, recovery fails closed. The cross-user iCloud Keychain matrix remains a manual release requirement in [docs/security/keychain-matrix.md](docs/security/keychain-matrix.md).

## Developer build

Development requirements:

- macOS 14 or newer
- Xcode or Xcode beta
- Node.js 24 or newer

Normal builds use the checked-in `SVLT.xcodeproj`. XcodeGen is only required when changing `project.yml` or running the parity check.

```bash
xcodebuild test -project SVLT.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/svlt && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/svlt/main.js obsidian-plugin/svlt/dist
git diff --check
```

When intentionally changing `project.yml`:

```bash
xcodegen generate
./scripts/check-xcodegen-parity.sh
git diff --check
```

Create a distributable zip:

```bash
SVLT_SIGNING_IDENTITY='Developer ID Application: ...' ./scripts/package-release.sh
```

Release signing requires `SVLT_SIGNING_IDENTITY` from the local Keychain; the repository does not embed an individual developer certificate.

To inspect the idle background Agent after installation:

```bash
./scripts/check-agent-resources.sh
# or
ps -axo pid,ppid,%cpu,%mem,rss,etime,command | grep '[S]VLTAgent'
```

The Agent blocks on its Unix socket and does not use a heartbeat, periodic network ping, or resident full-vault scan.
