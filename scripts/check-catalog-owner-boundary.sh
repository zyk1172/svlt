#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME="$ROOT_DIR/Sources/AgentSecretVaultApp/AgentSecretVaultApp.swift"

for forbidden in   'SensitiveCatalogDocumentStore'   'SensitiveInformationDocumentStore'   'SensitiveIndexSelectionStore'   'SecretCatalogSelectionStore'; do
  if grep -nF "$forbidden" "$RUNTIME"; then
    echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden owner symbol: $forbidden" >&2
    exit 1
  fi
done

echo "Catalog ownership boundary verified: GUI runtime has no managed Catalog store or selection owner."
