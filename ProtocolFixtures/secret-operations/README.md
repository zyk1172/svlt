# Secret Operation protocol fixtures

This directory is the cross-language compatibility contract for Secret Operation IPC.

The JSON files are intentionally neutral: neither the Swift implementation nor the TypeScript MCP implementation owns the wire shape. Both test suites must decode, validate, and serialize these same fixtures.

## Contract surface

`requests.json` covers:

- `executeSecretOperation` (legacy compatibility)
- `startSecretOperation`
- `secretOperationStatus`
- `cancelSecretOperation`

`responses.json` covers:

- legacy synchronous output/failure
- operation handle
- every lifecycle state
- terminal output
- invalid parameters
- authorization cancellation
- executor failure
- principal-safe operation-not-found semantics
- definitive cancellation
- outcome unknown

## Change rule

A wire-contract change is complete only when the shared fixture is changed and both Swift and TypeScript tests pass against that same JSON.

Do not copy a fixture into language-specific tests and edit the copies independently. A field rename, enum change, nullability change, payload-shape change, or stable error-code change must fail CI on the side that has not been updated.

## Outcome uncertainty

`OPERATION_OUTCOME_UNKNOWN` is not an ordinary failure and must never imply that retry is safe. It means the operation may have crossed an external side-effect boundary and the caller must reconcile target state before deciding whether another operation is appropriate.

A direct lookup of an unknown or foreign-principal operation is represented as `OPERATION_NOT_FOUND`. Once a caller has received an acknowledged operation handle, losing that handle or its control channel is treated by the MCP lifecycle as outcome-unknown, because absence of the retained record does not prove absence of the side effect.

## Scope

This first contract layer deliberately uses shared fixtures instead of schema/code generation. JSON Schema, OpenAPI, Protobuf, or generated Swift/TypeScript models can be evaluated later if the protocol stabilizes enough to justify the additional build machinery.
