# Crypto hardening notes

This document records the current encryption boundary for maintainers and agent
integrators.

## Current v2 record format

New encrypted records use `VaultFormat.current == 2`.

Each record still uses envelope encryption:

1. Generate a random 256-bit data key per record.
2. Encrypt plaintext with AES-GCM using the data key.
3. Derive a per-record wrapping key with HKDF-SHA256 from:
   - the vault master key,
   - a random per-record derivation salt,
   - authenticated record metadata.
4. Wrap the data key with AES-GCM using the derived wrapping key.

The authenticated metadata includes format version, secret id, record version,
label, policy, creation time, and update time. Tampering with these fields must
fail closed during decryption.

## Vault master key

The app runtime must not use the Keychain device key directly as the record
master key.

Current runtime path:

1. The local device key authorizes and wraps the vault master key.
2. The wrapped vault master key set is stored under the app vault directory at
   `.agent-secret-vault/master-key.json`.
3. Record encryption and decryption use the unwrapped vault master key.
4. Copying the wrapped vault data to a different local device key must not
   decrypt the vault.

The `SVLTAgent` obtains the wrapped master key through the device-local
`WhenUnlockedThisDeviceOnly` Keychain item when a permitted operation needs it.
This cryptographic access is separate from operation authorization: approval is
based on the concrete effect, not on whether a Secret is being used for the
first time. Ordinary task-aligned operations can execute automatically while
the controlled consumer authenticates with the Secret; no lease or session ID
is needed. Genuine destructive, high-impact, or credential-exposing flows use
macOS `deviceOwnerAuthentication`, while the device-local Keychain read itself
does not add a second user-presence prompt. The App and launchd startup path
never calls `unlockLowProtection()`.

Audit events use a separate 256-bit Keychain key with `WhenUnlockedThisDeviceOnly`
and no `.userPresence` flag. The audit key is never used to unwrap Vault data,
and status/connection handling never asks for it merely to report health.

Regression coverage:

- `copiedWrappedMasterKeyFailsWithDifferentLocalDeviceKey`
- `deviceKeyStorePassesOneEvaluatedContextIntoKeychainQuery`
- `existingAccessibleOnlyKeychainItemFailsClosed`
- `statusAuditUsesIndependentKeyAndNeverRequestsVaultMasterKey`
- `fileWrappedMasterKeyStoreRoundTripsWrappedSet`
- `fileWrappedMasterKeyStoreRejectsSymlinkTargetBeforeWriting`

## Legacy v1 records

Legacy v1 records remain decryptable with the correct vault master key.

Migration logic decrypts the previous valid record and writes the next version
using the current v2 format. Failed migration must preserve the prior
decryptable version.

Regression coverage:

- `decryptsLegacyV1RecordAfterFormatBump`
- `successfulMigrationCreatesNextDecryptableVersion`
- `migrationFailureLeavesPriorVersionDecryptable`

## Not yet complete

User-entered passphrase as an additional high-protection factor is not currently
exposed in the app UI or MCP flow. Do not claim passphrase protection in release
notes until there is an end-to-end setting, unlock path, and migration test.
