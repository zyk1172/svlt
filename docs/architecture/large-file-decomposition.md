# Large-file decomposition plan

This document turns the architecture finding about oversized implementation files into an incremental constraint and refactoring sequence. The goal is not to split code by line count. The goal is to reduce the number of unrelated security and product responsibilities that can change inside one compilation unit or one state owner.

## Debt ceilings

The repository currently has five implementation hotspots whose existing size is treated as a **ceiling, not a target**:

| File | Baseline ceiling (bytes) | Primary problem |
| --- | ---: | --- |
| `Sources/VaultService/VaultAppServices.swift` | 270882 | One actor owns catalog mutation, write authorization, audit state, Secure Input, execution approval, key/session state, status, and record-facing orchestration. |
| `Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift` | 190886 | Presentation, state adaptation, actions, and many workbench sections are concentrated in one SwiftUI file. |
| `Sources/VaultService/SensitiveCatalogDocumentStore.swift` | 136876 | Locking, recovery, integrity validation, file I/O, snapshots, and mutation mechanics are colocated. |
| `mcp-server/src/server.ts` | 128848 | MCP tool schemas, registration, argument parsing, policy shaping, and request handlers are concentrated in one module. |
| `Sources/VaultCore/Store/SensitiveCatalogDocumentCodec.swift` | 100279 | Parsing, rendering, validation diagnostics, canonicalization, and format-specific mechanics share one codec implementation. |

`scripts/check-architecture-budgets.sh` enforces these values in CI. A refactor that makes a tracked file smaller must lower its ceiling in the same PR. A PR must not raise a ceiling merely to accommodate more code.

The check intentionally does not impose a repository-wide arbitrary file-size limit. Some dense model or test files can be cohesive. The audited files above are tracked because their size reflects multiple responsibilities, not because large files are automatically defects.

## Refactoring sequence

### 1. `VaultAppServices`: extract state owners, keep the actor as a facade

Do not split the actor into cross-file extensions that require changing `private` state to broader visibility. Extract cohesive stateful collaborators instead. The public service remains the policy/orchestration facade.

Recommended order:

1. **Secure Input lifecycle coordinator**
   - Build on the existing `CatalogSecureInputTransaction` state machine.
   - Move receipt persistence, expiry-task ownership, and request-scoped audit-context bookkeeping behind the same lifecycle owner.
   - Preserve the current commit linearization point: cancellation/expiry may win before `.committing`, never after it.
   - Plaintext must remain outside terminal receipts and generic mutation APIs.
2. **Audit health state**
   - Move append-failure/gap tracking and health sidecar persistence into a focused component.
   - `VaultAppServices` should ask for health state and emit audit events, not own persistence bookkeeping.
3. **Catalog write-access request lifecycle**
   - Move request continuations, states, and request audit-context bookkeeping into a coordinator.
   - Keep the device-owner decision and authorization semantics unchanged.
4. **Secret-operation approval/execution lifecycle**
   - Move approval-flight and in-flight-operation bookkeeping behind one coordinator.
   - Preserve invalidation ordering and generation checks used during lock/sleep/shutdown.

Each extraction should be its own PR unless two pieces share the same state invariant and tests.

### 2. `VaultWorkbenchView`: split presentation by feature boundary

Move self-contained workbench sections and their local presentation logic into focused views/models. Avoid introducing a single replacement “WorkbenchComponents.swift” monolith. Keep shared top-level navigation/state wiring in `VaultWorkbenchView` and move feature-specific actions with the feature that owns them when possible.

### 3. `SensitiveCatalogDocumentStore`: isolate storage mechanisms

Separate mechanisms that have distinct invariants:

- bounded POSIX/file-provider reads and file safety checks;
- catalog lock acquisition and lock deadlines;
- interrupted-recovery journal handling;
- integrity/signature verification and accepted-state reconciliation;
- high-level snapshot/mutation orchestration.

The public store API should remain the synchronization boundary. Do not create multiple independently mutable owners of the same catalog document.

### 4. MCP server: tool families instead of one registry module

Group schemas, validation, and handlers by capability family (catalog read/search, catalog mutation, Secure Input, secret execution, status/control). Keep common caller identity, risk-judge, and IPC dispatch code centralized. Tool-family modules must not bypass the existing `LocalIpcClient` or duplicate authorization logic.

### 5. Catalog codec: split by transformation stage

Prefer boundaries such as parsing, canonical rendering, structural validation/diagnostics, and version-specific conversion. Keep canonicalization rules single-sourced so splitting the file cannot create two subtly different encoders.

## Security invariants for every decomposition PR

A decomposition PR is behavior-preserving unless it explicitly states otherwise. At minimum it must preserve:

- existing IPC request/response contracts and capability-token checks;
- current authorization and device-owner approval boundaries;
- no plaintext secret persistence in logs, receipts, diagnostics, or generic catalog mutation paths;
- cancellation/expiry linearization semantics for Secure Input and secret operations;
- bounded file-provider and IPC waits already enforced by the service and transport layers;
- catalog locking/integrity/recovery ordering;
- security-state invalidation behavior on lock, sleep, or daemon shutdown.

Tests for the responsibility being moved should travel with the extraction. Existing high-level integration tests remain the compatibility gate.

## Completion criterion

F13 is complete only when the large files have been materially reduced and their responsibilities have been separated behind testable boundaries. The CI budget is the first guardrail: it prevents the architecture debt from increasing while those extractions are performed incrementally.
