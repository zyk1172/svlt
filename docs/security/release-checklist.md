# SVLT release checklist

Run this checklist for every release candidate.

## Release gate commands

```bash
export DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer
# The checked-in Xcode project remains the active release definition. Verify
# project.yml parity before changing that policy.
./scripts/check-xcodegen-parity.sh
xcodebuild test -project SVLT.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
cd mcp-server && npm audit --audit-level=high && npm test && npm run typecheck && npm run build
cd ../obsidian-plugin/svlt && npm audit --audit-level=high && npm test && npm run typecheck && npm run build
cd ../..
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist obsidian-plugin/svlt/main.js obsidian-plugin/svlt/dist
git diff --check
git status --short
./scripts/check-agent-resources.sh # after installing/running the release
# Real release-installed Secure Input E2E (manual Touch ID/password; no plaintext output)
SVLT_RELEASE_APP=/Applications/SVLT.app ./scripts/release-e2e.sh
```

For a signed local/internal release package, provide the identity explicitly:

```bash
SVLT_SIGNING_IDENTITY='Developer ID Application: ...' ./scripts/package-release.sh
```

For any public release, notarization is a required gate. Store the notarytool
credentials in a Keychain profile and package with fail-closed notarization:

```bash
SVLT_SIGNING_IDENTITY='Developer ID Application: ...' \
SVLT_NOTARY_PROFILE='svlt-notary' \
SVLT_REQUIRE_NOTARIZATION=1 \
./scripts/package-release.sh
```

The packaging script builds the checked-in Xcode project, forces Hardened Runtime
at release build time, and verifies the Team ID and Hardened Runtime on both the
App and embedded `SVLTAgent`. When notarization is enabled it waits for Apple
notarization, staples the ticket, validates it, runs Gatekeeper assessment, and
rebuilds the final ZIP from the stapled App. The project keeps the Team ID pin
for AppControl verification but never stores an individual certificate identity
or notarization credential in source control.

## Acceptance criteria

1. For SVLT-managed test secrets, test plaintext cannot be found in the knowledge base, search index, audit logs, Codex transcript, application logs, notifications, or crash reports. This criterion does not claim to erase user plaintext explicitly selected for an external current operation.
2. Copying the knowledge base and encrypted sidecar store to an unauthorized Mac does not permit decryption.
3. Cancelling Touch ID, locking the application, or modifying ciphertext exposes no full or partial plaintext.
4. Simulated credential echoes in stdout and stderr are removed before results reach Codex.
5. Ambiguous or unsafe output is quarantined instead of returned.
6. Write, external-send, delete, and credential-change operations cannot reuse a read authorization; credential windows are reused only within their configured scope and external-send is destination-bound.
7. `locked` is compatibility-only; operation readiness is reported by `available`/`ready`/`approvalPending`. Sleep, user switch, and explicit lock invalidate active runtime authorization. Quitting the GUI App does not stop the Agent or create a global Agent gate.
8. A new Mac signed into the same Apple account can recover access only after successful platform authentication and installation of the correctly signed application.
9. Every MCP success and error response passes automated plaintext-leak tests.
10. Knowledge-base replacement failures preserve the source plaintext and the newly encrypted record for manual recovery.
11. Template validation rejects undeclared executables, destinations, parameters, and side-effect escalation.
12. Cryptographic migration tests prove that failed migrations preserve the last valid record.
13. Scan state does not persist full plaintext.
14. Paragraph reveal returns only status to the Obsidian plugin and MCP callers; a native App-owned reveal is delivered through the explicit Agent → App UI bridge.
15. `SVLTAgent` contains no SwiftUI/AppKit/UI framework dependency and the embedded LaunchAgent plist uses `BundleProgram` under `Contents/Library/LaunchAgents`.
16. Obsidian search does not index revealed plaintext.
17. Context-leak warnings trigger for password, token, API key, and 银行卡 candidates.
18. Plaintext canary scans include the shipped Obsidian plugin bundle at `obsidian-plugin/svlt/main.js`.
19. Secure Input starts as `PENDING/requestID`, uses one device-owner authentication, and reaches a terminal status only after final semantic diff/policy and atomic Catalog commit.
20. Audit append health is sticky across a later successful append and daemon restart (`lastFailureAt`, `gapDetected`, and `lastSuccessfulSequence` remain observable through the safe health code).
21. The release-installed App and embedded `SVLTAgent` verify against the pinned Team ID and Hardened Runtime before the manual E2E begins.
22. Public distribution artifacts pass notarization, stapler validation, and Gatekeeper assessment before publishing.
23. SSH host-key trust is stored only in SVLT's owner-only trust store; changed host keys fail instead of being silently replaced.

## Manual checks

- Complete `docs/security/keychain-matrix.md` on real macOS user profiles before
  marking iCloud Keychain recovery as release-ready.
- Verify no UI, README, plugin skill, or MCP description claims protection
  against same-user malware, root/admin compromise, screen recording, physical
  observation, compromised signed binaries, or compromised developer signing
  identity.
- Verify no feature exposes bulk plaintext export.
- Complete `docs/testing/catalog-v3-obsidian-e2e.md`, including the isolated
  `test-artifacts/release-e2e/` run and explicit Touch ID/password evidence.
