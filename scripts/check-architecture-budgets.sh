#!/usr/bin/env bash
set -euo pipefail

# These are debt ceilings, not target sizes. They freeze the largest current
# implementation files at their audited main-branch byte counts so new work
# must be extracted behind a responsibility boundary instead of extending the
# existing monoliths. Whenever a refactor shrinks one of these files, lower
# the matching ceiling in the same PR; never raise a ceiling to make CI pass.
readonly budgets=(
  "Sources/VaultService/VaultAppServices.swift:262940"
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

if (( failed != 0 )); then
  cat >&2 <<'EOF'

One or more audited monoliths grew beyond their debt ceiling.
Move the new responsibility into a focused collaborator/module instead of
raising the ceiling. If this PR genuinely shrinks a tracked file, lower its
ceiling to the new byte count in the same PR.
See docs/architecture/large-file-decomposition.md.
EOF
  exit 1
fi
