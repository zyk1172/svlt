# Agent Secret Vault for macOS — Design Specification

Date: 2026-06-26  
Status: Approved design  
Initial integration target: Codex on macOS

## 1. Purpose

Build a native macOS application that lets AI agents work with knowledge-base
references and local operations without exposing sensitive plaintext to the
agent or cloud model.

The first release protects both:

- credentials such as passwords, API keys, tokens, and account identifiers;
- sensitive text such as names, addresses, financial data, medical data, and
  other user-selected private content.

The user manually selects content to encrypt. The knowledge base retains useful
non-sensitive context while replacing the selected plaintext with an opaque
reference such as `secret://01J...`.

## 2. Product Boundary

The first release integrates with the original Codex App through a Codex plugin
and a local MCP server. Codex continues to display opaque references in its
conversation. Plaintext is shown only in a separate secure window owned by the
macOS application.

Codex plugins, MCP tools, and hooks cannot replace messages already rendered by
the original Codex App. Inline plaintext rendering would require a custom
Codex client built on Codex app-server and is outside the first-release scope.

## 3. Security Goals

The product must prevent plaintext exposure to:

- Codex and its cloud model;
- the Obsidian knowledge base and its search index;
- knowledge-base and file-sync providers;
- copied encrypted database files;
- application audit logs, system logs, notifications, and crash reports.

The product does not claim to resist:

- malicious software running as the same macOS user;
- screen recording or physical observation while plaintext is visible;
- an attacker with administrator or root control of the Mac;
- compromise of the signed application binary or the developer signing
  identity.

These exclusions must be stated in user-facing security documentation.

## 4. System Architecture

### 4.1 Native macOS Application

The Swift/SwiftUI application is the only component with decryption authority.
It owns:

- Touch ID and system authentication;
- key creation, retrieval, wrapping, and lifecycle management;
- encryption and decryption;
- the secure plaintext viewer;
- authorization policy and short-lived read sessions;
- controlled local execution with credential injection;
- encrypted audit logging;
- orphaned-secret review and deletion.

The application clears plaintext and in-memory key material when the
authorization expires, the screen locks, the Mac sleeps, the user switches,
or the application exits.

### 4.2 Encrypted Store

Knowledge-base Markdown stores only opaque references. Ciphertext and record
metadata live in an application-managed sidecar directory inside the configured
knowledge-base synchronization root.

The synchronized source of truth uses one authenticated, encrypted record file
per secret version. This avoids syncing a live SQLite database, whose page and
write-ahead-log updates can conflict across Macs. A local SQLite database may
be used only as a rebuildable index and cache.

The encrypted store never contains an unwrapped master key. Each record
contains:

- format version;
- opaque record ID;
- ciphertext and authentication tag;
- encryption nonce;
- wrapped per-record data key;
- non-sensitive user-defined label;
- operation policy;
- record version and timestamps.

Labels must be explicitly entered by the user and must not contain plaintext
secrets. The application warns that labels remain searchable metadata.

### 4.3 Codex Plugin and Local MCP Server

The Codex plugin packages:

- instructions requiring Codex to treat `secret://` values as opaque;
- the local MCP server configuration;
- skills describing supported secure workflows;
- optional lifecycle hooks that enforce or validate safe usage.

The MCP server communicates with the macOS application over authenticated,
local-only IPC. It does not persist the master key or plaintext.

MCP tools return references, non-sensitive metadata, authorization state, and
sanitized execution results. They never return decrypted values.

### 4.4 Local Execution Broker

The application can inject secrets into controlled child processes without
placing plaintext in the model context.

The first release permits only user-configured executable paths and structured
command templates. It must not accept arbitrary shell strings. Template
arguments are represented as separate process arguments to avoid shell
interpolation and command injection.

Before any output reaches Codex, the broker filters stdout, stderr, and
structured results using the exact secret values supplied to that operation.
If safe filtering cannot be established, output is shown only in the
application and is not returned through MCP.

## 5. Cryptographic Design

### 5.1 Record Encryption

- Generate a random opaque ID for every secret record.
- Generate a unique random 256-bit data-encryption key for every record.
- Encrypt record plaintext with AES-256-GCM.
- Bind the record ID and format version as authenticated additional data.
- Wrap each record data key using the vault master key.
- Never derive identifiers, nonces, or labels from plaintext.

Per-record keys limit the impact of accidental exposure and permit later key
rotation without changing knowledge-base references.

### 5.2 Master Key and Recovery

- Generate the master key randomly on first setup.
- Do not derive it from a user password.
- Store only wrapped copies of the master key.
- Historical design note: the first draft protected every normal access with a
  device-local wrapping key whose Keychain access control required Touch ID or
  the system authentication fallback. The current implementation separates
  cryptographic key access from operation authorization: the device-local
  `WhenUnlockedThisDeviceOnly` item is read silently for ordinary operations,
  while Touch ID/password is reserved for genuine dangerous effects and local
  reveal/export boundaries.
- Protect a second wrapped copy with a recovery wrapping key stored in an
  application-specific, synchronizable iCloud Keychain item.
- On a recovered Mac, require platform authentication, unwrap the recovery copy,
  and create a new device-local wrapping key before normal use.
- Keep unwrapped key material only for the minimum operation/cache lifetime;
  it is not an approval lease and cannot grant an Agent an execution scope.

iCloud Keychain recovery means the vault is protected by application identity
and Apple account/device authentication rather than being physically bound to
one Mac. Only an application signed with the expected identity and entitled
for the Keychain access group should be able to request the item through normal
platform APIs. The implementation must verify the exact Keychain access-control
and synchronization combination on every supported macOS release; if the
required controls cannot be combined safely, recovery remains disabled rather
than weakening local authorization.

### 5.3 Versioning and Migration

Every encrypted record carries an explicit format version. Encryption
algorithms and wrapping formats must be dispatched by version so a future
release can migrate records without changing `secret://` IDs.

A migration must write and verify the new ciphertext before deleting the old
version. Failed migrations leave the prior valid record intact.

## 6. Knowledge-Base Workflow

### 6.1 Encrypt and Replace

1. The user selects sensitive text in Obsidian or another macOS application.
2. The user invokes a macOS Service or global shortcut named “Encrypt and
   Replace.”
3. The application shows the selected content, target application or file when
   available, and an optional non-sensitive label.
4. The user confirms the operation.
5. The application encrypts the plaintext and creates a secret record.
6. Only after the encrypted record is durably saved, the selected text is
   replaced with `secret://<opaque-id>`.
7. The application verifies the replacement when the integration permits it.

If replacement fails, the encrypted record remains available and is marked as
unlinked. The original selected text is not deleted automatically.

### 6.2 Knowledge-Base Reads

Existing `kb_search` and `kb_get` operations return Markdown containing opaque
references. Codex may reason from surrounding context and non-sensitive labels
but cannot retrieve the referenced values.

When the user asks to see a value:

1. Codex calls `secret_reveal_request` with the reference.
2. The application displays the requesting client, reference label, and reason.
3. The user authenticates.
4. Plaintext appears in the application’s secure viewer.
5. MCP receives only a result such as `DISPLAYED_TO_USER`.

### 6.3 Updates and Deletion

- Updating a value preserves its reference ID and creates a new encrypted
  record version.
- Deleting a reference from Markdown does not immediately delete ciphertext.
- Unreferenced records are marked as orphan candidates.
- Permanent deletion is performed from an explicit orphan-review screen and
  requires per-operation authentication.

## 7. Authorization Policy

Operations are assigned one of three risk classes:

### 7.1 Read

Examples: reveal in the secure viewer, inspect non-sensitive metadata, or run a
locally contained read-only template.

Historical note: this early design used a five-minute read authorization
session. It is superseded by the effect-based approval model. Ordinary,
task-aligned Secret authentication is `AUTO` and creates no authorization
session or lease; local reveal/export and genuinely dangerous effects retain
their exact, one-shot owner-approval boundaries.

### 7.2 Write or External Send

Examples: modify files, update remote data, submit an authenticated API
request, or transmit secret-backed values outside the Mac.

Approval is determined by actual effect, blast radius, reversibility, and
credential exposure—not by the fact that the operation writes or uses a
Secret. Bounded, recoverable writes may be `AUTO`; destructive, high-impact,
unresolved, or credential-exposing effects require the current fresh-approval
or DENIED boundary.

### 7.3 Delete or Credential Change

Examples: permanently delete a secret, rotate a credential, or overwrite a
stored sensitive value.

Every operation requires a separate Touch ID authorization and a clear
confirmation screen.

Every authorization prompt displays:

- requesting client;
- operation class and description;
- executable or destination;
- number and labels of referenced secrets;
- whether data leaves the Mac;
- expected file or remote side effects.

Codex cannot approve an operation, extend an authorization window, or convert
one operation class into another.

## 8. Controlled Execution

An execution request contains:

- a registered template ID;
- typed non-sensitive parameters;
- secret references assigned to declared template fields;
- expected side-effect class;
- declared network destinations and file targets.

The application validates the request against the user-configured template,
performs the required authorization, resolves references only in local memory,
and launches the executable without invoking a shell.

Secrets may be supplied through:

- individual process arguments when the target safely supports them;
- standard input;
- a short-lived in-memory or permission-restricted file;
- environment variables only when unavoidable and explicitly disclosed.

Environment variables are not the preferred transport because other processes
running as the same user may be able to inspect them.

Returned output is:

1. collected with configured size and time limits;
2. checked against every plaintext value used by the operation;
3. redacted where exact matches occur;
4. rejected entirely when safe sanitization is uncertain;
5. stripped of unsafe binary content and normalized into a bounded result.

## 9. Error Handling

The MCP interface uses structured, non-sensitive failures:

- `APP_UNAVAILABLE`
- `APP_LOCKED`
- `AUTH_CANCELLED`
- `AUTH_EXPIRED`
- `SECRET_NOT_FOUND`
- `INTEGRITY_FAILED`
- `POLICY_DENIED`
- `TEMPLATE_NOT_ALLOWED`
- `OUTPUT_QUARANTINED`
- `KEYCHAIN_RECOVERY_REQUIRED`

No failure path falls back to plaintext. Authentication cancellation stops the
operation before any side effect. Integrity failure quarantines the record and
prevents partial decryption.

## 10. Secure Plaintext Viewer

The viewer:

- hides content when it loses focus, the session expires, or the screen locks;
- excludes plaintext from notifications, window restoration, Spotlight, state
  restoration, and diagnostic telemetry;
- disables ordinary copying by default;
- permits explicit user copying only after confirmation;
- clears application-owned clipboard content after 60 seconds when it remains
  unchanged;
- provides no bulk plaintext export.

Clipboard clearing is best-effort because another process may copy or replace
the clipboard before the timeout.

## 11. Audit Logging

The application records:

- timestamp;
- requesting integration;
- secret reference ID;
- operation type and risk class;
- authorization outcome;
- declared target;
- sanitized completion status and process exit code.

It never records plaintext, resolved command arguments, actual credentials,
complete process output, or clipboard data.

Audit logs are encrypted and retained for 30 days by default. Users may choose
a shorter period and may export a redacted report.

## 12. First-Release Scope

Included:

- native SwiftUI macOS application;
- Touch ID and system authentication fallback;
- Keychain and iCloud Keychain recovery;
- AES-256-GCM field-level encryption;
- macOS Service or shortcut for manual encrypt-and-replace;
- secure plaintext viewer;
- Codex plugin and local MCP server;
- Obsidian-compatible `secret://` references;
- allowlisted structured execution templates;
- local credential injection and output sanitization;
- risk-based authorization;
- encrypted audit logging.

Excluded:

- Claude and Hermes integrations;
- automatic sensitive-information detection;
- full-note encryption;
- plaintext rendering inside the original Codex App;
- iPhone or iPad clients;
- team sharing and multi-user access control;
- arbitrary shell execution;
- bulk plaintext export;
- defense against same-user malware or root compromise.

## 13. Verification and Acceptance Criteria

The first release is accepted only when:

1. Test plaintext cannot be found in the knowledge base, search index, audit
   logs, Codex transcript, application logs, notifications, or crash reports.
2. Copying the knowledge base and encrypted sidecar store to an unauthorized Mac
   does not permit decryption.
3. Cancelling Touch ID, locking the application, or modifying ciphertext
   exposes no full or partial plaintext.
4. Simulated credential echoes in stdout and stderr are removed before results
   reach Codex.
5. Ambiguous or unsafe output is quarantined instead of returned.
6. Write, external-send, delete, and credential-change operations cannot reuse
   a read authorization.
7. Lock, sleep, user switch, application exit, and timeout invalidate active
   authorization.
8. A new Mac signed into the same Apple account can recover access only after
   successful platform authentication and installation of the correctly
   signed application.
9. Every MCP success and error response passes automated plaintext-leak tests.
10. Knowledge-base replacement failures preserve the source plaintext and the
    newly encrypted record for manual recovery.
11. Template validation rejects undeclared executables, destinations,
    parameters, and side-effect escalation.
12. Cryptographic migration tests prove that failed migrations preserve the
    last valid record.

## 14. Primary References

- OpenAI Codex plugin packaging, bundled MCP servers, and lifecycle hooks:
  <https://developers.openai.com/codex/plugins/build#bundled-mcp-servers-and-lifecycle-hooks>
- OpenAI Codex app-server boundary for custom clients:
  <https://developers.openai.com/codex/app-server>
- 1Password MCP server design for keeping secrets out of agent context:
  <https://www.1password.dev/environments/mcp-server>
- Microsoft Presidio reversible anonymization:
  <https://microsoft.github.io/presidio/anonymizer/>
- SOPS encrypted file management:
  <https://github.com/getsops/sops>
- age file encryption:
  <https://github.com/FiloSottile/age>
