# Protection And Obsidian Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the user-facing low-protection path, reduce the Obsidian editor menu to six useful actions, and add stable short interaction feedback to the macOS workbench.

**Architecture:** The Obsidian plugin will always submit new encryptions as `credential` and retain `read` only in the shared protocol for legacy-record compatibility. The workbench will expose one short ease-in-out curve for transient user feedback while preserving the existing ban on repeating animations, transitions, blur, and material backgrounds.

**Tech Stack:** TypeScript, Obsidian Plugin API, Vitest, Swift 6, SwiftUI, Swift Testing, Xcode.

## Global Constraints

- New encryption actions always use the standard `credential` policy.
- Existing `read` records remain decryptable; do not migrate ciphertext or remove the protocol enum case.
- Preserve Secret plaintext and principal boundaries in `VaultAppServices`; the historical five-minute in-memory Agent decrypt authorization reuse is retired. Ordinary Secret operations now use effect-based `AUTO`, while reveal/export and dangerous effects retain fresh approval boundaries.
- The editor context menu contains exactly six actions: encrypt selection, scan current note, reveal selection, restore selection, scan vault, scan orphan references.
- Current-paragraph operations remain available through the command palette, but not the editor context menu.
- Do not add repeating animations, view transitions, blur, or material backgrounds.
- Do not add plaintext to logs, notices, source fixtures, generated artifacts, or documentation.

---

## File Structure

- `obsidian-plugin/agent-secret-vault/src/main.ts`: plugin command registration, editor-menu construction, and all new-record encryption policy choices.
- `obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts`: command palette and editor-menu behavior regression coverage.
- `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts`: default encryption policy coverage without a low-protection override.
- `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift`: stable motion constants plus navigation, hover, and copied-reference feedback.
- `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift`: workbench rendering-policy regression coverage.

### Task 1: Simplify Obsidian Commands And Remove New Low-Protection Encryptions

**Files:**
- Modify: `obsidian-plugin/agent-secret-vault/src/main.ts:15-318`
- Modify: `obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts:130-257`
- Modify: `obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts:189-215`

**Interfaces:**
- Consumes: `encryptTextRange({ documentText, range, label, policy, client })` from `src/encrypt/encryptSelection.ts`.
- Produces: `commandDefinitions` with nine non-low-protection commands and `populateEditorActionMenu(menu, editor)` with six contextual actions.

- [ ] **Step 1: Write the failing plugin command tests**

Replace the expected command arrays with the retained palette actions and the six-item menu. Add a context-menu invocation test that proves the first item encrypts with `credential` and the second item dispatches the current-note flow.

```ts
expect(commandDefinitions.map((command) => command.id)).toEqual([
  "encrypt-selection",
  "encrypt-current-paragraph",
  "scan-current-note",
  "scan-vault",
  "scan-orphans",
  "reveal-selection",
  "reveal-current-paragraph",
  "restore-selection",
  "restore-current-paragraph"
]);

expect(obsidianMock.submenuItems.map((item) => item.title)).toEqual([
  "加密选中文本",
  "扫描当前笔记并加密",
  "临时解密选中文本",
  "还原选中文本",
  "扫描整个知识库",
  "扫描孤立密文引用"
]);

it("uses credential encryption and current-note scanning from the simplified editor menu", async () => {
  const editor = {
    getSelection: () => "sensitive-value",
    getCursor: () => ({ line: 0, ch: 0 }),
    posToOffset: () => 0,
    getValue: () => "sensitive-value",
    getRange: () => "sensitive-value",
    replaceRange: () => undefined
  };
  const requests: Array<{ policy?: string }> = [];
  let scannedEditor: unknown;
  const plugin = new AgentSecretVaultPlugin(makeApp() as never, {} as never) as unknown as {
    createVaultClient: () => unknown;
    scanCurrentNote: (value: unknown) => Promise<void>;
    onload: () => Promise<void>;
  };
  plugin.createVaultClient = () => ({
    request: async (request: { policy?: string }) => {
      requests.push(request);
      return { type: "created", reference: "secret://0123456789ABCDEFGHJKMNPQRS" };
    }
  });
  plugin.scanCurrentNote = async (value) => { scannedEditor = value; };

  await plugin.onload();
  obsidianMock.workspaceEvents.find((event) => event.name === "editor-menu")?.callback(new (await import("obsidian")).Menu(), editor);
  await obsidianMock.submenuItems[0]?.onClick?.();
  await obsidianMock.submenuItems[1]?.onClick?.();

  expect(requests[0]?.policy).toBe("credential");
  expect(scannedEditor).toBe(editor);
});
```

- [ ] **Step 2: Run the focused tests and verify they fail**

Run: `npm test -- pluginCommands.test.ts encryptSelection.test.ts`

Expected: failures that still list `*-low-protection` commands/menu items and accept a `read` policy override.

- [ ] **Step 3: Remove the low-protection entry points and pin encryption to credential policy**

In `src/main.ts`, remove `SecretPolicyName`, all four `*-low-protection` command definitions and registration branches, and the low-protection/menu-current-paragraph actions. Remove policy parameters from plugin-local encryption helpers and pass `policy: "credential"` at each request boundary.

```ts
private async encryptFindingsInText(text: string, findings: ScanFindingState[]): Promise<string> {
  const client = this.createVaultClient();
  const replacements: PlannedReplacement[] = [];
  for (const finding of findings) {
    const plaintext = finding.plaintextForCurrentProcessOnly ?? text.slice(finding.start, finding.end);
    const response = await client.request({
      type: "encryptText",
      plaintext,
      label: `${finding.filePath}:${finding.ruleId}`,
      policy: "credential"
    });
    if (response.type !== "created") {
      throw new Error(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
    }
    replacements.push({ start: finding.start, end: finding.end, replacementText: response.reference });
    finding.plaintextForCurrentProcessOnly = undefined;
  }
  return applyReplacements(text, replacements);
}
```

Keep `SecretPolicy` unchanged in `src/ipc/protocol.ts`: older `read` records must remain parseable and decryptable.

- [ ] **Step 4: Remove the obsolete low-protection unit test and run focused tests**

Delete `sends read policy for low-protection selection encryption` from `test/encryptSelection.test.ts`; its behavior is intentionally removed. Run: `npm test -- pluginCommands.test.ts encryptSelection.test.ts`

Expected: both files pass with no low-protection command or menu references.

- [ ] **Step 5: Commit the focused plugin change**

```bash
git add obsidian-plugin/agent-secret-vault/src/main.ts \
  obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts \
  obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts
git commit -m "feat: simplify obsidian secret actions"
```

### Task 2: Restore Stable, Smooth Workbench Feedback

**Files:**
- Modify: `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift:44-49, 142-163, 257-296, 442-490, 676-702`
- Modify: `Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift:93-98`

**Interfaces:**
- Consumes: SwiftUI `Animation` and existing `selectedSection`, `isHovering`, and `isCopied` state.
- Produces: `VaultWorkbenchMotion.interactive`, a shared short easing curve for transient UI feedback only.

- [ ] **Step 1: Write the failing workbench rendering-policy test**

Extend the stable-rendering test to require the transient animation flag and source-level use of the shared curve.

```swift
#expect(VaultWorkbenchRenderingPolicy.usesTransientAnimations)
#expect(source.contains("VaultWorkbenchMotion.interactive"))
#expect(source.contains("withAnimation(VaultWorkbenchMotion.interactive)"))
```

- [ ] **Step 2: Run the focused macOS test and verify it fails**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests`

Expected: failure because `usesTransientAnimations` and `VaultWorkbenchMotion` do not yet exist.

- [ ] **Step 3: Add the shared curve and apply it only to transient feedback**

Add the motion policy next to `VaultWorkbenchRenderingPolicy`, add `usesTransientAnimations = true`, and use a private section-selection helper so every quick card uses the same short interaction curve.

```swift
public enum VaultWorkbenchMotion {
    public static let interactive = Animation.easeInOut(duration: 0.18)
}

private func selectSection(_ section: VaultWorkbenchSection) {
    withAnimation(VaultWorkbenchMotion.interactive) {
        selectedSection = section
    }
}
```

Use `selectSection(section)` in the notification handler and every quick-card closure. Apply `.animation(VaultWorkbenchMotion.interactive, value: isHovering)` to the existing quick-action hover treatment and replace the copied-reference assignment with:

```swift
withAnimation(VaultWorkbenchMotion.interactive) {
    isCopied = true
}
```

Do not add `.transition`, repeating effects, blur, or material.

- [ ] **Step 4: Run the focused macOS test and verify it passes**

Run: `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/VaultWorkbenchCopyTests`

Expected: `VaultWorkbenchCopyTests` passes while the no-repeating-animation, no-blur, and no-material checks remain true.

- [ ] **Step 5: Commit the workbench change**

```bash
git add Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift
git commit -m "feat: smooth workbench interactions"
```

### Task 3: Verify The Simplified Scan Flow And Full Product Surface

**Files:**
- Verify: `obsidian-plugin/agent-secret-vault/test/scanCommands.test.ts`
- Verify: `obsidian-plugin/agent-secret-vault/test/detectors.test.ts`
- Verify: `obsidian-plugin/agent-secret-vault/test/scanState.test.ts`
- Verify: `Tests/VaultAuthorizationTests/VaultAppServicesOrphanScanTests.swift`

**Interfaces:**
- Consumes: existing scanner, review modal, transactional replacement, reference extraction, IPC orphan scan, and macOS orphan resolver tests.
- Produces: evidence that simplifying the menu does not change scan detection, explicit review, unchanged-file checks, or orphan-reference IPC.

- [ ] **Step 1: Run the full Obsidian verification sequence**

Run: `npm test && npm run typecheck && npm run build`

Expected: all plugin tests pass, TypeScript has no errors, and `main.js` is regenerated from the changed source.

- [ ] **Step 2: Run the focused scan and orphan regression tests**

Run: `npm test -- scanCommands.test.ts scanState.test.ts detectors.test.ts && DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS' -only-testing:VaultAuthorizationTests/VaultAppServicesOrphanScanTests`

Expected: scanner still ignores existing references, preserves plaintext only in process memory, skips changed files, and sends deduplicated references for orphan scans.

- [ ] **Step 3: Run all repository acceptance checks**

Run:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
  xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
git diff --check
ASV_CANARY='ASV_CANARY_7F2D1C9E_DO_NOT_PERSIST' \
  ./scripts/scan-plaintext.sh build test-artifacts mcp-server/dist \
  obsidian-plugin/agent-secret-vault/main.js \
  obsidian-plugin/agent-secret-vault/dist
```

Expected: all macOS tests pass, the diff has no whitespace errors, and the plaintext canary scan returns no findings.

- [ ] **Step 4: Commit only the planned tracked implementation files**

```bash
git add Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift \
  Tests/VaultAuthorizationTests/VaultWorkbenchCopyTests.swift \
  obsidian-plugin/agent-secret-vault/src/main.ts \
  obsidian-plugin/agent-secret-vault/test/pluginCommands.test.ts \
  obsidian-plugin/agent-secret-vault/test/encryptSelection.test.ts \
  obsidian-plugin/agent-secret-vault/main.js
git commit -m "feat: simplify secret protection controls"
```

Do not stage `docs/project-handoff-2026-07-03.md` or unrelated working-tree changes.
