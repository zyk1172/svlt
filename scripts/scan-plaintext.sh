#!/usr/bin/env bash
set -u

if [[ -z "${ASV_CANARY:-}" ]]; then
  echo "ASV_CANARY is required" >&2
  exit 2
fi

require_paths=0
if [[ "${1:-}" == "--require-paths" ]]; then
  require_paths=1
  shift
fi

if [[ "$require_paths" -eq 1 && "$#" -eq 0 ]]; then
  echo "--require-paths needs at least one scan path" >&2
  exit 2
fi

if [[ "$#" -gt 0 ]]; then
  scan_paths=("$@")
else
  scan_paths=(
    "build"
    "test-artifacts"
    "mcp-server/test-artifacts"
    "mcp-server/captures"
    "mcp-server/fixtures/transcripts"
    "$HOME/Library/Application Support/AgentSecretVault"
    "$HOME/Library/Logs/AgentSecretVault"
    "$HOME/Library/Logs/DiagnosticReports"
  )
fi

existing_paths=()
missing_paths=()
for path in "${scan_paths[@]}"; do
  if [[ -e "$path" ]]; then
    existing_paths+=("$path")
  else
    missing_paths+=("$path")
  fi
done

if [[ "$require_paths" -eq 1 && "${#missing_paths[@]}" -gt 0 ]]; then
  for path in "${missing_paths[@]}"; do
    printf 'Required plaintext scan path does not exist: %s\n' "$path" >&2
  done
  exit 2
fi

if [[ "${#existing_paths[@]}" -eq 0 ]]; then
  exit 0
fi

if command -v rg >/dev/null 2>&1; then
  matches="$(
    rg \
      -l \
      --fixed-strings \
      --hidden \
      --glob '!**/.git/**' \
      --glob '!**/node_modules/**' \
      --glob '!**/DerivedData/**' \
      --glob '!**/*.xcresult/**' \
      -- \
      "$ASV_CANARY" \
      "${existing_paths[@]}" 2>/dev/null || true
  )"
else
  # GitHub-hosted runners do not guarantee ripgrep. Keep the same safety
  # contract with portable find/grep: only matching file paths are emitted;
  # grep's matching content is always redirected away from the terminal.
  matches=""
  while IFS= read -r candidate; do
    case "$candidate" in
      */.git/*|*/node_modules/*|*/DerivedData/*|*.xcresult/*) continue ;;
    esac
    if grep -IlF -- "$ASV_CANARY" "$candidate" >/dev/null 2>&1; then
      matches+="$candidate"$'\n'
    fi
  done < <(find "${existing_paths[@]}" -type f -print 2>/dev/null)
fi

if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches"
  exit 1
fi

exit 0
