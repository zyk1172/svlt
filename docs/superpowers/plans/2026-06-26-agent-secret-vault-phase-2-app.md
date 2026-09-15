# Agent Secret Vault Phase 2: macOS App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add device-local authorization, short read sessions, encrypt-and-replace orchestration, and a secure plaintext viewer.

**Architecture:** Authorization is abstracted behind protocols so policy tests do not invoke biometric UI. SwiftUI views receive plaintext only through an ephemeral observable session and clear it on lifecycle events.

> Historical design note: the read-session TTL described by this early plan is
> not the current Secret-operation approval model. The current model is
> effect-based: ordinary Secret authentication is automatic, while reveal,
> export, and genuinely dangerous effects keep their own fresh boundaries.

**Tech Stack:** SwiftUI, LocalAuthentication, Security, AppKit Services, XCTest/Swift Testing.

---

### Task 1: Implement risk policy and authorization sessions

**Files:**
- Create: `Sources/VaultAuthorization/RiskClass.swift`
- Create: `Sources/VaultAuthorization/AuthorizationSession.swift`
- Create: `Tests/VaultAuthorizationTests/AuthorizationSessionTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write clock-controlled policy tests**

Test that read authorization lasts exactly 300 seconds, external-send and
delete authorizations are single-use, and a read token cannot authorize a
higher risk class.

- [ ] **Step 2: Run and confirm failure**

```bash
xcodegen generate
xcodebuild test -project AgentSecretVault.xcodeproj -scheme VaultAuthorization -destination 'platform=macOS'
```

Expected: FAIL because the target and types do not exist.

- [ ] **Step 3: Implement the policy**

```swift
public enum RiskClass: Int, Codable, Sendable {
    case read = 0
    case writeOrExternalSend = 1
    case deleteOrCredentialChange = 2
}

public actor AuthorizationSession {
    public init(
        readTTL: TimeInterval = 300,
        now: @escaping @Sendable () -> Date = Date.init
    )
    public func authorizeRead() async
    public func consumeAuthorization(for risk: RiskClass) async -> Bool
    public func invalidate() async
}
```

Only `.read` may reuse a live session. Higher classes always return `false`
until a fresh biometric result is supplied for that exact operation.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add project.yml Sources/VaultAuthorization Tests/VaultAuthorizationTests
git commit -m "feat: add risk-based authorization sessions"
```

### Task 2: Add LocalAuthentication and device key access

**Files:**
- Create: `Sources/VaultAuthorization/BiometricAuthorizing.swift`
- Create: `Sources/VaultAuthorization/LocalAuthenticator.swift`
- Create: `Sources/VaultAuthorization/DeviceKeyStore.swift`
- Create: `Tests/VaultAuthorizationTests/DeviceKeyStoreTests.swift`

- [ ] **Step 1: Write adapter tests with fakes**

Test success, user cancellation, lockout, unavailable biometrics, and system
password fallback. Test that key retrieval is never attempted after cancelled
authentication.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL because the adapters do not exist.

- [ ] **Step 3: Implement adapters**

Define `BiometricAuthorizing.evaluate(reason:) async throws` and a
`DeviceKeyStoring` protocol. Production `LocalAuthenticator` uses
`LAContext.evaluatePolicy(.deviceOwnerAuthentication, ...)`. Production
`DeviceKeyStore` stores a 256-bit wrapping key as a non-synchronizable Keychain
generic-password item with access control requiring user presence.

- [ ] **Step 4: Run unit tests**

Expected: PASS without displaying system biometric UI because tests use fakes.

- [ ] **Step 5: Commit**

```bash
git add Sources/VaultAuthorization Tests/VaultAuthorizationTests
git commit -m "feat: protect device wrapping key"
```

### Task 3: Build encrypt-and-replace orchestration

**Files:**
- Create: `Sources/AgentSecretVaultApp/EncryptSelectionCoordinator.swift`
- Create: `Sources/AgentSecretVaultApp/SelectionReplacing.swift`
- Create: `Sources/AgentSecretVaultApp/Services/EncryptSelectionService.swift`
- Create: `Config/Info.plist`
- Create: `Tests/VaultAuthorizationTests/EncryptSelectionCoordinatorTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write ordering tests**

Assert `recordStore.save` completes before `selectionReplacer.replace` starts.
Assert replacement failure returns an `unlinkedRecord` result and never
deletes or mutates the source through a second call.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement coordinator**

```swift
public enum EncryptSelectionResult: Equatable {
    case replaced(SecretReference)
    case unlinkedRecord(SecretReference)
}

public protocol SelectionReplacing {
    func replaceSelection(with text: String) async throws
}
```

The coordinator validates that plaintext is non-empty and the label contains
none of the plaintext before encrypting, saving, and replacing in that order.
`EncryptSelectionService` registers an `NSServices` entry named “Encrypt and
Replace,” accepts UTF-8 plain text from the services pasteboard, and delegates
to the coordinator. It does not clear or overwrite source pasteboard content
until the encrypted record has been saved.

- [ ] **Step 4: Run tests**

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add project.yml Config/Info.plist Sources/AgentSecretVaultApp Tests/VaultAuthorizationTests
git commit -m "feat: add encrypt and replace workflow"
```

### Task 4: Build the secure viewer and lifecycle clearing

**Files:**
- Create: `Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift`
- Create: `Sources/AgentSecretVaultApp/SecureViewer/SecureViewerModel.swift`
- Create: `Sources/AgentSecretVaultApp/SecureViewer/SecureViewerView.swift`
- Create: `Tests/VaultAuthorizationTests/SecureViewerModelTests.swift`
- Modify: `project.yml`

- [ ] **Step 1: Write model tests**

Test that focus loss, lock notification, sleep notification, session expiry,
and explicit close set plaintext to `nil`. Test clipboard clear occurs only
when the pasteboard change count still matches the app-owned copy.

- [ ] **Step 2: Run and confirm failure**

Expected: FAIL.

- [ ] **Step 3: Implement model and view**

`SecureViewerModel` is `@MainActor @Observable`, stores plaintext as `Data`,
derives a temporary `String` only for rendering, and zeroes the mutable buffer
before release. The view disables state restoration and has no ordinary Copy
command; an explicit “Copy for 60 seconds” action requires confirmation.

- [ ] **Step 4: Run all phase tests and launch**

```bash
xcodebuild test -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -destination 'platform=macOS'
xcodebuild build -project AgentSecretVault.xcodeproj -scheme AgentSecretVault -configuration Debug
```

Expected: tests PASS and app builds.

- [ ] **Step 5: Commit**

```bash
git add project.yml Sources/AgentSecretVaultApp Tests/VaultAuthorizationTests
git commit -m "feat: add secure plaintext viewer"
```
