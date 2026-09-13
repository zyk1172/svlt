#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$ROOT_DIR/Sources/AgentSecretVaultApp"
LEGACY_STORE="$RUNTIME_DIR/AppServices/SensitiveInformationDocumentStore.swift"
LEGACY_PROBE="$RUNTIME_DIR/AppServices/SensitiveInformationDocumentStore+UIProbe.swift"
LEGACY_SELECTION="$RUNTIME_DIR/AppServices/SensitiveIndexSelectionStore.swift"

if ! find "$RUNTIME_DIR" -type f -name '*.swift' -print -quit | grep -q .; then
  echo "No GUI Swift sources found under $RUNTIME_DIR" >&2
  exit 1
fi

# Search executable Swift lines rather than comments. Legacy non-managed note
# helpers may keep their own type declarations/extensions, but no other GUI
# source may regain ownership of them. Managed Catalog/selection owners have no
# GUI-side implementation exception at all.
check_symbol() {
  local symbol="$1"
  shift
  local found=0
  local file
  while IFS= read -r -d '' file; do
    local skip=0
    local excluded
    for excluded in "$@"; do
      if [[ "$file" == "$excluded" ]]; then
        skip=1
        break
      fi
    done
    (( skip == 1 )) && continue

    if sed '/^[[:space:]]*\/\//d' "$file" | grep -nF "$symbol" >/dev/null; then
      echo "GUI runtime must consume Catalog state through daemon App-control IPC; forbidden caller symbol: $symbol ($file)" >&2
      found=1
    fi
  done < <(find "$RUNTIME_DIR" -type f -name '*.swift' -print0)
  (( found == 0 ))
}

check_symbol 'SensitiveCatalogDocumentStore'
check_symbol 'SecretCatalogSelectionStore'
check_symbol 'SensitiveInformationDocumentStore' "$LEGACY_STORE" "$LEGACY_PROBE"
check_symbol 'SensitiveIndexSelectionStore' "$LEGACY_SELECTION"

echo "Catalog ownership boundary verified across GUI callers."
