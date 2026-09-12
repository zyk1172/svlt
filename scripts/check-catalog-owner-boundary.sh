#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/Sources/AgentSecretVaultApp"

mapfile -d '' swift_files < <(find "$RUNTIME_DIR" -type f -name '*.swift' -print0)
if [ "${#swift_files[@]}" -eq 0 ]; then
  echo "No GUI Swift sources found under $RUNTIME_DIR" >&2
  exit 1
fi

for forbidden in   'SensitiveCatalogDocumentStore'   'SensitiveInformationDocumentStore'   'SensitiveIndexSelectionStore'   'SecretCatalogSelectionStore'; do
  if grep -nFH "$forbidden" "${swift_files[@]}"; then
    echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden owner symbol: $forbidden" >&2
    exit 1
  fi
done

echo "Catalog ownership boundary verified across the complete GUI target."
