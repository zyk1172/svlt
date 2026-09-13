#!/usr/bin/env bash
set -euo pipefail

# These are debt ceilings, not target sizes. They freeze the largest current
# implementation files at their audited main-branch byte counts so new work
# must be extracted behind a responsibility boundary instead of extending the
# existing monoliths. Whenever a refactor shrinks one of these files, lower
# the matching ceiling in the same PR; never raise a ceiling to make CI pass.
readonly budgets=(
  "Sources/VaultService/VaultAppServices.swift:154913"
  "Sources/VaultService/VaultAppServices+CatalogOperations.swift:96246"
  "Sources/AgentSecretVaultApp/Workbench/VaultWorkbenchView.swift:190886"
  "Sources/VaultService/SensitiveCatalogDocumentStore.swift:136876"
  "mcp-server/src/server.ts:128848"
  "Sources/VaultCore/Store/SensitiveCatalogDocumentCodec.swift:100279"
)

failed=0
for entry in "${budgets[@]}"; do
  file="${entry%:*}"
  max_bytes="${entry##*:}"

  if [[ ! -f "$file" ]]; then
    printf 'architecture budget: tracked file missing: %s\n' "$file" >&2
    failed=1
    continue
  fi

  actual_bytes="$(wc -c < "$file" | tr -d '[:space:]')"
  if (( actual_bytes > max_bytes )); then
    printf 'architecture budget exceeded: %s is %s bytes (ceiling %s)\n' \
      "$file" "$actual_bytes" "$max_bytes" >&2
    failed=1
  else
    printf 'architecture budget: %s %s/%s bytes\n' \
      "$file" "$actual_bytes" "$max_bytes"
  fi
done

# Keep Agent-facing Catalog orchestration in its dedicated vertical slice.
# The byte ceilings prevent either side from silently growing back into a God
# file, while these symbol checks stop the primary Agent Catalog entry points
# from drifting back into VaultAppServices.swift during future edits.
readonly catalog_root="Sources/VaultService/VaultAppServices.swift"
readonly catalog_slice="Sources/VaultService/VaultAppServices+CatalogOperations.swift"
readonly extracted_catalog_symbols=(
  "searchSecrets"
  "getCatalogEntry"
  "listCatalogIndexes"
  "listCatalogEntries"
  "applyCatalogBatch"
  "createCatalogIndex"
  "catalogSnapshotForAgent"
)

if [[ ! -f "$catalog_slice" ]]; then
  printf 'architecture boundary: catalog operations slice missing: %s\n' "$catalog_slice" >&2
  failed=1
else
  for symbol in "${extracted_catalog_symbols[@]}"; do
    if grep -Eq "func[[:space:]]+${symbol}[[:space:](]" "$catalog_root"; then
      printf 'architecture boundary: %s must not return to %s\n' "$symbol" "$catalog_root" >&2
      failed=1
    fi
    if ! grep -Eq "func[[:space:]]+${symbol}[[:space:](]" "$catalog_slice"; then
      printf 'architecture boundary: expected %s in %s\n' "$symbol" "$catalog_slice" >&2
      failed=1
    fi
  done
fi

if (( failed != 0 )); then
  cat >&2 <<'EOF'

One or more audited monoliths grew beyond their debt ceiling or crossed an
architecture boundary. Move the responsibility into the focused collaborator
or module instead of raising the ceiling or moving Agent Catalog orchestration
back into VaultAppServices.swift. If a PR genuinely shrinks a tracked file,
lower its ceiling to the new byte count in the same PR.
See docs/architecture/large-file-decomposition.md.
EOF
  exit 1
fi
