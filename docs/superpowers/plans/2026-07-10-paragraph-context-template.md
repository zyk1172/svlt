# Paragraph Context Template Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Save every new Vault record with a sanitized paragraph template and copy the template with its `secret://` reference from the macOS app.

**Architecture:** The Obsidian plugin will build templates before encryption, replacing the target range with `[[ASV_REFERENCE]]` and every other detector-recognized sensitive range with `已隐藏`. The existing encrypted-record `label` transports that authenticated metadata unchanged; the macOS card replaces the marker with its own reference only while displaying and copying.

**Tech Stack:** TypeScript, Obsidian Plugin API, Vitest, Swift 6, SwiftUI, Swift Testing, Xcode.

## Global Constraints

- Preserve paragraph structure and non-sensitive surrounding context only.
- Never save the original selected secret or another detector-recognized sensitive match in a record label.
- Do not infer a secret's meaning beyond the surrounding paragraph.
- Do not alter record crypto, the `SecretPolicy` enum, or legacy record readability. The historical five-minute Agent decrypt authorization reuse is superseded by the current effect-based model: ordinary Secret authentication is automatic when the concrete effect is safe and task-aligned.
- Labels intentionally preserve operational semantics as authenticated metadata, as requested.
- Old labels without the marker remain readable and copy as `label：secret://...`.
- Do not put actual credentials, tokens, or canary values in tests, logs, or docs.

---

## File Structure

- `obsidian-plugin/agent-secret-vault/src/encrypt/paragraphContextTemplate.ts`: builds sanitized templates from a document and target range.
- `obsidian-plugin/agent-secret-vault/test/paragraphContextTemplate.test.ts`: unit tests for target-marker insertion, redaction of additional findings, and paragraph boundaries.
- `obsidian-plugin/agent-secret-vault/src/main.ts`: passes templates as the existing IPC `label` for selected and scanner-driven encryption.
- `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`: asserts selected encryption sends a paragraph template label.
- `obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts`: asserts reviewed scan encryption sends a paragraph template label.
- `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`: renders and copies templates with the record reference substituted.
- `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`: source-level regression coverage for template rendering and safe copy text.

### Task 1: Build Sanitized Paragraph Templates In The Plugin

**Files:**
- Create: `obsidian-plugin/agent-secret-vault/src/encrypt/paragraphContextTemplate.ts`
- Create: `obsidian-plugin/agent-secret-vault/test/paragraphContextTemplate.test.ts`

**Interfaces:**
- Consumes: `extractCurrentParagraph(documentText, cursorOffset)`, `detectSensitiveText(text)`, `applyReplacements(text, replacements)`, and `TextRange`.
- Produces: `PARAGRAPH_REFERENCE_MARKER` and `buildParagraphContextTemplate(documentText, target): string`.

- [ ] **Step 1: Write failing template-builder tests**

```ts
import { describe, expect, it } from "vitest";
import { buildParagraphContextTemplate, PARAGRAPH_REFERENCE_MARKER } from "../src/encrypt/paragraphContextTemplate";

describe("buildParagraphContextTemplate", () => {
  it("keeps the containing paragraph and replaces the target range with the reference marker", () => {
    const text = "NAS 用户名：demo-user\nNAS 密码：demo-password\n\n下一段";
    const start = text.indexOf("demo-password");

    expect(buildParagraphContextTemplate(text, { start, end: start + "demo-password".length, text: "demo-password" }))
      .toBe(`NAS 用户名：demo-user\nNAS 密码：${PARAGRAPH_REFERENCE_MARKER}`);
  });

  it("hides other detector-recognized values in the same paragraph", () => {
    const text = "NAS 密码：demo-password\nAPI token：abcdefghijklmnop";
    const start = text.indexOf("demo-password");

    expect(buildParagraphContextTemplate(text, { start, end: start + "demo-password".length, text: "demo-password" }))
      .toBe(`NAS 密码：${PARAGRAPH_REFERENCE_MARKER}\nAPI token：已隐藏`);
  });

  it("hides unselected portions of a detected match", () => {
    const text = "NAS 密码：demo-password";
    const start = text.indexOf("password");

    expect(buildParagraphContextTemplate(text, { start, end: start + "password".length, text: "password" }))
      .toBe(`NAS 密码：已隐藏${PARAGRAPH_REFERENCE_MARKER}`);
  });
});
```

- [ ] **Step 2: Run the new test and verify it fails**

Run: `npm test -- paragraphContextTemplate.test.ts`

Expected: module-not-found failure for `paragraphContextTemplate`.

- [ ] **Step 3: Implement the builder with reverse-order replacement**

```ts
export const PARAGRAPH_REFERENCE_MARKER = "[[ASV_REFERENCE]]";

export function buildParagraphContextTemplate(documentText: string, target: TextRange): string {
  const paragraph = extractCurrentParagraph(documentText, target.start);
  const relativeTarget = { start: target.start - paragraph.start, end: target.end - paragraph.start };
  const replacements: PlannedReplacement[] = [{
    start: relativeTarget.start,
    end: relativeTarget.end,
    replacementText: PARAGRAPH_REFERENCE_MARKER
  }];

  for (const finding of detectSensitiveText(paragraph.text)) {
    if (finding.end <= relativeTarget.start || finding.start >= relativeTarget.end) {
      replacements.push({ start: finding.start, end: finding.end, replacementText: "已隐藏" });
      continue;
    }
    if (finding.start < relativeTarget.start) {
      replacements.push({ start: finding.start, end: relativeTarget.start, replacementText: "已隐藏" });
    }
    if (relativeTarget.end < finding.end) {
      replacements.push({ start: relativeTarget.end, end: finding.end, replacementText: "已隐藏" });
    }
  }

  return applyReplacements(paragraph.text, suppressOverlappingReplacements(replacements));
}
```

Implement `suppressOverlappingReplacements` in the same file: sort target replacement first, then retain only ranges that do not overlap an already accepted range.

- [ ] **Step 4: Run the builder tests and verify they pass**

Run: `npm test -- paragraphContextTemplate.test.ts`

Expected: the new test file passes and the target value never appears in its returned template.

- [ ] **Step 5: Commit the builder**

```bash
git add obsidian-plugin/agent-secret-vault/src/encrypt/paragraphContextTemplate.ts \
  obsidian-plugin/agent-secret-vault/test/paragraphContextTemplate.test.ts
git commit -m "feat: add sanitized paragraph context templates"
```

### Task 2: Attach Templates To Every New Plugin Encryption Record

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts:1-305, 513-542`
- Modify: `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts:163-187`
- Modify: `obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts:90-112`

**Interfaces:**
- Consumes: `buildParagraphContextTemplate(documentText, target)` from Task 1.
- Produces: `encryptText` IPC requests whose `label` has one marker and no selected plaintext.

- [ ] **Step 1: Write failing integration assertions**

```ts
expect(requests).toContainEqual(expect.objectContaining({
  type: "encryptText",
  label: `token = [[ASV_REFERENCE]]`
}));

expect(requests).toContainEqual(expect.objectContaining({
  type: "encryptText",
  label: `password = [[ASV_REFERENCE]]`
}));
```

Capture requests in the selected-encryption and current-note scan tests. Keep their reference assertions unchanged.

- [ ] **Step 2: Run the focused integration tests and verify they fail**

Run: `npm test -- encryptSelection.test.ts scanCommands.test.ts`

Expected: received labels remain `null` for selection and `filePath:ruleId` for scanner encryption.

- [ ] **Step 3: Pass templates through the existing label field**

Import the builder into `src/main.ts`. Replace both current label sources:

```ts
label: buildParagraphContextTemplate(editor.getValue(), range)
```

and:

```ts
label: buildParagraphContextTemplate(text, {
  start: finding.start,
  end: finding.end,
  text: plaintext
})
```

Do not change the plaintext request field, the `credential` policy, or the replacement text written back to Obsidian.

- [ ] **Step 4: Run the focused integration tests and verify they pass**

Run: `npm test -- encryptSelection.test.ts scanCommands.test.ts`

Expected: selected and scanned encryption both submit template labels; no test response contains selected plaintext in the template assertion.

- [ ] **Step 5: Commit the plugin integration**

```bash
git add obsidian-plugin/agent-secret-vault/src/main.ts \
  obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts \
  obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts
git commit -m "feat: save secret context templates"
```

### Task 3: Display And Copy A Complete Usable Template In The Vault

**Files:**
- Modify: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift:597-742`
- Modify: `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift:66-78`

**Interfaces:**
- Consumes: `SecretReferenceMetadata.label` and `SecretReferenceMetadata.reference`.
- Produces: `displayText` and `copyText` that substitute `[[ASV_REFERENCE]]` with the current opaque reference.

- [ ] **Step 1: Write the failing workbench source test**

```swift
#expect(source.contains("[[ASV_REFERENCE]]"))
#expect(source.contains("replacingOccurrences(of: paragraphReferenceMarker, with: metadata.reference)"))
#expect(source.contains("复制可用段落"))
#expect(source.contains("只复制段落上下文和密文引用，不复制明文。"))
```

- [ ] **Step 2: Run the authorization test target and verify it fails**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests`

Expected: `workbenchShowsSavedSecretReferencesWithoutPlaintext` fails because it only renders and copies the raw reference.

- [ ] **Step 3: Add template substitution and copy behavior**

In `SavedSecretReferenceRow`, add:

```swift
private let paragraphReferenceMarker = "[[ASV_REFERENCE]]"

private var displayText: String {
    guard let label = metadata.label, !label.isEmpty else {
        return metadata.reference
    }
    if label.contains(paragraphReferenceMarker) {
        return label.replacingOccurrences(of: paragraphReferenceMarker, with: metadata.reference)
    }
    return "\\(label)：\\(metadata.reference)"
}
```

Render `displayText` with multiline selection, change the button to `复制可用段落`, and copy `displayText` only. Keep `metadata.reference` available as selectable text through that rendered template.

- [ ] **Step 4: Run the authorization test target and verify it passes**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests`

Expected: all authorization tests pass and the workbench source test proves only context plus opaque reference is copied.

- [ ] **Step 5: Commit the macOS card update**

```bash
git add Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift
git commit -m "feat: copy paragraph secret context"
```

### Task 4: Verify The Complete Secret-Context Flow

**Files:**
- Verify: `obsidian-plugin/agent-secret-vault/test/paragraphContextTemplate.test.ts`
- Verify: `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`
- Verify: `obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts`
- Verify: `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`

- [ ] **Step 1: Run full plugin verification**

Run: `npm test && npm run typecheck && npm run build`

Expected: all plugin tests pass, TypeScript has no errors, and `main.js` contains the new template builder.

- [ ] **Step 2: Run full macOS verification**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'`

Expected: the full macOS test suite passes.

- [ ] **Step 3: Run final safety checks**

Run:

```bash
git diff --check
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' \
  ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist \
  obsidian-plugin/agent-secret-vault/main.js \
  obsidian-plugin/agent-secret-vault/dist
```

Expected: no whitespace errors and no canary findings.

- [ ] **Step 4: Commit the generated plugin artifact**

```bash
git add obsidian-plugin/agent-secret-vault/main.js \
  docs/superpowers/plans/2026-07-10-paragraph-context-template.md
git commit -m "build: package paragraph context templates"
```

Do not stage `docs/project-handoff-2026-07-03.md`.
