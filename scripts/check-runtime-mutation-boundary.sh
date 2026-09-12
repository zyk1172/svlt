#!/usr/bin/env bash
set -euo pipefail

root="Sources/AgentSecretVaultApp"

# The GUI process must not patch Foundation or other Objective-C classes at
# image load/runtime. The retired macOS 27 beta workaround used these APIs to
# add NSString-like methods to a private NSNumber implementation, changing
# behavior for every caller in the process.
forbidden='class_addMethod|class_replaceMethod|method_exchangeImplementations|method_setImplementation|NSClassFromString[[:space:]]*\([[:space:]]*@"__NS'

matches="$(
  grep -R -n -E \
    --include='*.m' \
    --include='*.mm' \
    --include='*.h' \
    --include='*.swift' \
    "$forbidden" \
    "$root" 2>/dev/null || true
)"

if [[ -n "$matches" ]]; then
  printf '%s\n' "$matches" >&2
  echo "Process-wide Objective-C runtime mutation is not allowed in AgentSecretVaultApp." >&2
  echo "Use supported framework APIs or a narrowly scoped adapter instead." >&2
  exit 1
fi
