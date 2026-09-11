#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$ROOT_DIR/SVLT.xcodeproj"

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "XcodeGen is required for the project parity check. Install it only when changing project.yml or running this check." >&2
  exit 2
fi

for required_path in \
  "$ROOT_DIR/project.yml" \
  "$PROJECT_DIR/project.pbxproj" \
  "$PROJECT_DIR/project.xcworkspace/contents.xcworkspacedata" \
  "$PROJECT_DIR/xcshareddata/xcschemes"; do
  if [[ ! -e "$required_path" ]]; then
    echo "Missing parity input: $required_path" >&2
    exit 1
  fi
done

CHECK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/svlt-xcodegen-parity.XXXXXX")"
cleanup() {
  rm -rf "$CHECK_ROOT"
}
trap cleanup EXIT INT TERM

cp "$ROOT_DIR/project.yml" "$CHECK_ROOT/project.yml"
for source_root in AppAssets Config Resources Sources Tests; do
  if [[ ! -d "$ROOT_DIR/$source_root" ]]; then
    echo "Missing project source root: $ROOT_DIR/$source_root" >&2
    exit 1
  fi
  cp -R "$ROOT_DIR/$source_root" "$CHECK_ROOT/$source_root"
done

xcodegen generate \
  --quiet \
  --spec "$CHECK_ROOT/project.yml" \
  --project "$CHECK_ROOT" \
  --project-root "$CHECK_ROOT" \
  --cache-path "$CHECK_ROOT/xcodegen-cache"

GENERATED_PROJECT="$CHECK_ROOT/SVLT.xcodeproj"
parity_failed=0

canonicalize_pbx_project() {
  local input_path="$1"
  local output_path="$2"

  # XcodeGen 2.45 and 2.46 emit PBXProject.targets in different orders.
  # Target order is presentation-only; the target entries themselves remain
  # in the comparison so additions and removals still fail the check.
  perl -0pe '
    s{
      (\n[ \t]*targets = \(\n)
      (.*?)
      (\n[ \t]*\);)
    }{
      my ($prefix, $body, $suffix) = ($1, $2, $3);
      my @lines = grep { /\S/ } split /\n/, $body;
      @lines = sort {
        my ($a_name) = $a =~ m{/\* (.*?) \*/};
        my ($b_name) = $b =~ m{/\* (.*?) \*/};
        ($a_name // $a) cmp ($b_name // $b) || $a cmp $b;
      } @lines;
      $prefix . join("\n", @lines) . $suffix;
    }gsex
  ' "$input_path" > "$output_path"
}

compare_file() {
  local relative_path="$1"
  if ! diff -u \
    "$PROJECT_DIR/$relative_path" \
    "$GENERATED_PROJECT/$relative_path"; then
    parity_failed=1
  fi
}

compare_directory() {
  local relative_path="$1"
  if ! diff -ru \
    "$PROJECT_DIR/$relative_path" \
    "$GENERATED_PROJECT/$relative_path"; then
    parity_failed=1
  fi
}

canonicalize_pbx_project \
  "$PROJECT_DIR/project.pbxproj" \
  "$CHECK_ROOT/checked-in-project.pbxproj"
canonicalize_pbx_project \
  "$GENERATED_PROJECT/project.pbxproj" \
  "$CHECK_ROOT/generated-project.pbxproj"
if ! diff -u \
  "$CHECK_ROOT/checked-in-project.pbxproj" \
  "$CHECK_ROOT/generated-project.pbxproj"; then
  parity_failed=1
fi

compare_file project.xcworkspace/contents.xcworkspacedata
compare_directory xcshareddata/xcschemes

if [[ "$parity_failed" -ne 0 ]]; then
  cat >&2 <<'MESSAGE'
XcodeGen parity check failed: the checked-in Xcode project differs from the
project definition in project.yml. Review the diff, make an intentional
source-of-truth change, regenerate with XcodeGen, and commit the resulting
project files.
MESSAGE
  exit 1
fi

echo "XcodeGen parity verified: project.yml reproduces the SVLT.xcodeproj definition."
