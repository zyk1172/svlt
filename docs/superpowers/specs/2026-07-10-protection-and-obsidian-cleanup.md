# Protection And Obsidian Cleanup

## Goal

Remove the user-facing low-protection choice, shorten the Obsidian editor context menu, and restore restrained motion in the macOS workbench without weakening secret handling or reintroducing the macOS 27 rendering instability.

## Scope

### Protection model

- New encryption actions always use the standard `credential` policy.
- Remove every low-protection command and editor-menu action from the Obsidian plugin.
- Keep `read` as a legacy record policy so existing encrypted records remain decryptable. It is not offered as a new user choice.
- Historical note: the former five-minute, in-memory Agent decrypt authorization reuse was retired by the effect-based approval model. Ordinary Secret authentication is automatic when the concrete effect is safe and task-aligned; plaintext/reveal and genuinely dangerous effects retain their existing fresh approval boundaries without creating a general-purpose lease.

### Obsidian editor menu

Keep six contextual actions, in this order:

1. Encrypt selected text.
2. Scan and encrypt the current note.
3. Temporarily reveal the selection in the Mac app.
4. Restore selected text.
5. Scan the whole vault.
6. Scan orphaned secret references.

Current-paragraph commands remain available through the command palette, but are removed from the editor context menu. This preserves the focused workflow while keeping the right-click path short.

### Workbench motion

- Continue to prohibit repeating animations, transitions, blur, and material backgrounds.
- Add one shared short ease-in-out timing curve for user-initiated navigation and transient button feedback.
- Never animate sensitive text or reveal-session content.
- Keep layout and color changes within the existing SwiftUI design system.

## Scan Review

The Obsidian scanner is retained as-is. It detects the configured sensitive patterns, ignores existing `secret://` references, requires review before replacement, checks that a note has not changed before write-back, and sends only references for orphan scanning. The current plugin suite passes 62 tests, type checking, and production bundling.

## Verification

- Add failing tests that prove low-protection commands and menu items are absent, the six-action editor menu remains ordered, and every menu encryption action requests `credential` policy.
- Add a focused scan command test through the simplified context entry point.
- Add SwiftUI source tests for the shared transient animation policy while retaining the no-repeating-animation invariant.
- Run the full Obsidian test/typecheck/build sequence, full macOS test suite, whitespace validation, and the plaintext canary scan.
