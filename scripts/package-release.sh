#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
BUILD_DIR="$ROOT_DIR/build/release"
STAGING_DIR="$DIST_DIR/SVLT-release"
MCP_STAGING="$STAGING_DIR/MCP"
OBSIDIAN_PLUGIN_STAGING="$STAGING_DIR/ObsidianPlugin/svlt"
SIGNING_TEAM="JUQXD87P93"
SIGNING_IDENTITY="${SVLT_SIGNING_IDENTITY:-}"
NOTARY_PROFILE="${SVLT_NOTARY_PROFILE:-}"
REQUIRE_NOTARIZATION="${SVLT_REQUIRE_NOTARIZATION:-0}"

if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "SVLT_SIGNING_IDENTITY is required for release signing (for example, a Developer ID Application identity)." >&2
  exit 2
fi

if ! command -v xcodegen >/dev/null 2>&1; then
  echo "xcodegen is required for release packaging so project.yml remains the canonical build definition." >&2
  echo "Install it first (for example: brew install xcodegen)." >&2
  exit 2
fi

cd "$ROOT_DIR"

rm -rf "$BUILD_DIR" "$STAGING_DIR"
mkdir -p "$DIST_DIR" "$BUILD_DIR" "$MCP_STAGING" "$OBSIDIAN_PLUGIN_STAGING"

echo "==> Building MCP server"
(cd "$ROOT_DIR/mcp-server" && npm ci && npm run build)

echo "==> Building Obsidian plugin"
(cd "$ROOT_DIR/obsidian-plugin/svlt" && npm ci && npm run build)

echo "==> Generating Xcode project from project.yml"
xcodegen generate

if [[ -z "${DEVELOPER_DIR:-}" && -d "/Applications/Xcode-beta.app/Contents/Developer" ]]; then
  export DEVELOPER_DIR="/Applications/Xcode-beta.app/Contents/Developer"
fi

echo "==> Building macOS app"
xcodebuild \
  -project "$ROOT_DIR/SVLT.xcodeproj" \
  -scheme AgentSecretVault \
  -configuration Release \
  -derivedDataPath "$BUILD_DIR/DerivedData" \
  DEVELOPMENT_TEAM="$SIGNING_TEAM" \
  CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="$SIGNING_IDENTITY" \
  build

APP_SOURCE="$BUILD_DIR/DerivedData/Build/Products/Release/SVLT.app"
if [[ ! -d "$APP_SOURCE" ]]; then
  echo "Build succeeded but app was not found at $APP_SOURCE" >&2
  exit 1
fi

AGENT_EXECUTABLE="$APP_SOURCE/Contents/MacOS/SVLTAgent"
AGENT_PLIST="$APP_SOURCE/Contents/Library/LaunchAgents/com.agent-secret-vault.SVLT.agent.plist"
if [[ ! -x "$AGENT_EXECUTABLE" || ! -f "$AGENT_PLIST" ]]; then
  echo "Release app is missing the launchd Agent or embedded LaunchAgent plist." >&2
  exit 1
fi

codesign --verify --strict "$AGENT_EXECUTABLE"
codesign --verify --deep --strict "$APP_SOURCE"

assert_team_identifier() {
  local signed_path="$1"
  local team_identifier
  team_identifier="$(codesign --display --verbose=4 "$signed_path" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  if [[ "$team_identifier" != "$SIGNING_TEAM" ]]; then
    echo "Unexpected signing TeamIdentifier for $signed_path: ${team_identifier:-missing}" >&2
    exit 1
  fi
}

assert_hardened_runtime() {
  local signed_path="$1"
  if ! codesign --display --verbose=4 "$signed_path" 2>&1 | grep -Eq '^CodeDirectory .*flags=.*runtime'; then
    echo "Hardened Runtime is missing from $signed_path" >&2
    exit 1
  fi
}

assert_team_identifier "$APP_SOURCE"
assert_team_identifier "$AGENT_EXECUTABLE"
assert_hardened_runtime "$APP_SOURCE"
assert_hardened_runtime "$AGENT_EXECUTABLE"
echo "Embedded SVLTAgent, Team ID, signatures, and Hardened Runtime verified."

echo "==> Staging app and integration bundles"
cp -R "$APP_SOURCE" "$STAGING_DIR/SVLT.app"
cp "$ROOT_DIR/mcp-server/package.json" "$MCP_STAGING/package.json"
cp "$ROOT_DIR/mcp-server/package-lock.json" "$MCP_STAGING/package-lock.json"
cp -R "$ROOT_DIR/mcp-server/dist" "$MCP_STAGING/dist"
cp "$ROOT_DIR/obsidian-plugin/svlt/main.js" "$OBSIDIAN_PLUGIN_STAGING/main.js"
cp "$ROOT_DIR/obsidian-plugin/svlt/manifest.json" "$OBSIDIAN_PLUGIN_STAGING/manifest.json"
cp "$ROOT_DIR/scripts/install-release.sh" "$STAGING_DIR/install.sh"
cp "$ROOT_DIR/scripts/install-release.sh" "$STAGING_DIR/install.command"
cp "$ROOT_DIR/scripts/check-agent-resources.sh" "$STAGING_DIR/check-agent-resources.sh"
cp "$ROOT_DIR/docs/zh-CN.md" "$STAGING_DIR/USER_GUIDE_zh-CN.md"
cp "$ROOT_DIR/docs/svlt-agent-policy-zh-CN.md" "$STAGING_DIR/svlt-agent-policy-zh-CN.md"
cp "$ROOT_DIR/docs/svlt-catalog-schema-v3.md" "$STAGING_DIR/svlt-catalog-schema-v3.md"
cp "$ROOT_DIR/docs/svlt-catalog-schema-v2.md" "$STAGING_DIR/svlt-catalog-schema-v2.md"
chmod +x "$STAGING_DIR/install.sh"
chmod +x "$STAGING_DIR/install.command"
chmod +x "$STAGING_DIR/check-agent-resources.sh"

cat > "$STAGING_DIR/README_INSTALL.txt" <<'TEXT'
SVLT 安装方式

1. 双击 install.command；如果系统拦截，右键点它再选“打开”。
   也可以在终端运行 install.sh。
2. 安装脚本会把包含 SVLTAgent 的 App 复制到 /Applications 或 ~/Applications，
   首次打开时通过 SMAppService 注册内置 LaunchAgent。
3. 安装脚本会把 MCP server 安装到：
   ~/Library/Application Support/AgentSecretVault/MCP
4. 安装脚本会生成可复制的 MCP 配置：
   ~/Library/Application Support/AgentSecretVault/svlt.mcp.json
5. release 包内包含 Obsidian 插件：
   ObsidianPlugin/svlt
   安装脚本会在能唯一识别 Vault 时自动安装。也可以指定：
   ./install.sh "/你的/Obsidian/Vault/路径"
6. 打开 SVLT，再把 MCP 配置粘贴到 Codex / Claude / Hermes / OpenClaw。
7. 必须将 svlt-agent-policy-zh-CN.md 中的代码块粘贴到 Agent 的系统提示、项目规则或工作区规则。
   对 SVLT managed 数据，所有 writer 都必须遵守 v3 marker/schema、保留 Markdown 与双链、禁止秘密明文；安全审批按 semantic diff 判断，不按编辑器或传输渠道判断。
   用户当前明确选择的明文或其他 provider 不由 SVLT 强制接管。
8. Catalog v3 格式与约束见 svlt-catalog-schema-v3.md；v2 仅作为 App 显式迁移输入，迁移前会备份。

完整中文教程见：USER_GUIDE_zh-CN.md

可用 check-agent-resources.sh 检查后台 Agent 的 ps/top/powermetrics 占用。

注意：本版本需要本机已安装 Node.js 24 或更新版本，用于运行 MCP server。
TEXT

ZIP_PATH="$DIST_DIR/SVLT-release.zip"
create_zip() {
  rm -f "$ZIP_PATH"
  (cd "$DIST_DIR" && ditto -c -k --sequesterRsrc --keepParent "SVLT-release" "$ZIP_PATH")
}

create_zip

if [[ -n "$NOTARY_PROFILE" ]]; then
  echo "==> Submitting release package for Apple notarization"
  xcrun notarytool submit "$ZIP_PATH" --keychain-profile "$NOTARY_PROFILE" --wait

  echo "==> Stapling and validating notarization ticket"
  xcrun stapler staple "$STAGING_DIR/SVLT.app"
  xcrun stapler validate "$STAGING_DIR/SVLT.app"
  spctl --assess --type execute --verbose=4 "$STAGING_DIR/SVLT.app"

  # Stapling changes the app bundle, so rebuild the final archive from the
  # stapled artifact rather than shipping the pre-notarization zip.
  create_zip
elif [[ "$REQUIRE_NOTARIZATION" == "1" ]]; then
  echo "SVLT_REQUIRE_NOTARIZATION=1 but SVLT_NOTARY_PROFILE is not configured." >&2
  exit 2
else
  echo "Notarization skipped. Set SVLT_NOTARY_PROFILE to notarize, or SVLT_REQUIRE_NOTARIZATION=1 for public-release fail-closed behavior." >&2
fi

echo "Release package:"
echo "$ZIP_PATH"
