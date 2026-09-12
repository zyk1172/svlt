#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/Sources/AgentSecretVaultApp"

if ! find "$RUNTIME_DIR" -type f -name '*.swift' -print -quit | grep -q .; then
  echo "No GUI Swift sources found under $RUNTIME_DIR" >&2
  exit 1
fi

for forbidden in \
  'SensitiveCatalogDocumentStore' \
  'SensitiveInformationDocumentStore' \
  'SensitiveIndexSelectionStore' \
  'SecretCatalogSelectionStore'; do
  if find "$RUNTIME_DIR" -type f -name '*.swift' -exec grep -nFH "$forbidden" {} +; then
    echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden owner symbol: $forbidden" >&2
    exit 1
  fi
done

echo "Catalog ownership boundary verified across the complete GUI target."
