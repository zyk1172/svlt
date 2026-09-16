#!/usr/bin/env bash
set -euo pipefail

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SOURCE="$RELEASE_DIR/SVLT.app"
MCP_SOURCE="$RELEASE_DIR/MCP"
OBSIDIAN_PLUGIN_SOURCE="$RELEASE_DIR/ObsidianPlugin/svlt"
CODEX_SKILL_SOURCE="$RELEASE_DIR/CodexSkill/svlt"

APP_DIR="/Applications"
if [[ ! -w "$APP_DIR" ]]; then
  APP_DIR="$HOME/Applications"
fi
APP_TARGET="$APP_DIR/SVLT.app"

APP_SUPPORT="$HOME/Library/Application Support/AgentSecretVault"
MCP_TARGET="$APP_SUPPORT/MCP"
CONFIG_PATH="$APP_SUPPORT/svlt.mcp.json"
CODEX_HOME="${CODEX_HOME:-"$HOME/.codex"}"
CODEX_SKILL_TARGET="$CODEX_HOME/skills/svlt"
SIGNING_TEAM="JUQXD87P93"

if [[ ! -d "$APP_SOURCE" ]]; then
  echo "找不到 SVLT.app。请从完整 release 包中运行本脚本。" >&2
  exit 1
fi

if [[ ! -d "$MCP_SOURCE" ]]; then
  echo "找不到 MCP 目录。请从完整 release 包中运行本脚本。" >&2
  exit 1
fi

if [[ ! -f "$CODEX_SKILL_SOURCE/SKILL.md" ]]; then
  echo "找不到 CodexSkill/svlt/SKILL.md。请从完整 release 包中运行本脚本。" >&2
  exit 1
fi

if [[ ! -x "$APP_SOURCE/Contents/MacOS/SVLTAgent" || ! -f "$APP_SOURCE/Contents/Library/LaunchAgents/com.agent-secret-vault.SVLT.agent.plist" ]]; then
  echo "SVLT.app 缺少 SVLTAgent 或内置 LaunchAgent，拒绝安装不完整 release。" >&2
  exit 1
fi

codesign --verify --deep --strict "$APP_SOURCE"
for signed_path in "$APP_SOURCE" "$APP_SOURCE/Contents/MacOS/SVLTAgent"; do
  team_identifier="$(codesign --display --verbose=4 "$signed_path" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  if [[ "$team_identifier" != "$SIGNING_TEAM" ]]; then
    echo "release 签名 TeamIdentifier 不匹配，拒绝安装。" >&2
    exit 1
  fi
done

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "需要先安装 Node.js 24 或更新版本。安装后重新运行本脚本。" >&2
  echo "推荐：从 https://nodejs.org 下载 LTS/current 版本。" >&2
  exit 1
fi

mkdir -p "$APP_DIR" "$APP_SUPPORT"

rm -rf "$APP_TARGET"
cp -R "$APP_SOURCE" "$APP_TARGET"

rm -rf "$MCP_TARGET"
mkdir -p "$MCP_TARGET"
cp -R "$MCP_SOURCE"/. "$MCP_TARGET"/

(cd "$MCP_TARGET" && npm ci --omit=dev --ignore-scripts)

# Keep the installed Codex skill in lockstep with the release runtime. A stale
# ~/.codex/skills/svlt copy can otherwise keep teaching the Agent the retired
# approval model even after the App/MCP binaries have been upgraded.
mkdir -p "$(dirname "$CODEX_SKILL_TARGET")"
rm -rf "$CODEX_SKILL_TARGET"
cp -R "$CODEX_SKILL_SOURCE" "$CODEX_SKILL_TARGET"
if ! cmp -s "$CODEX_SKILL_SOURCE/SKILL.md" "$CODEX_SKILL_TARGET/SKILL.md"; then
  echo "Codex Skill 安装校验失败。" >&2
  exit 1
fi

install_obsidian_plugin() {
  local vault_path="$1"
  local plugin_target="$vault_path/.obsidian/plugins/svlt"
  local legacy_plugin_target="$vault_path/.obsidian/plugins/agent-secret-vault"
  local enabled_plugins_path="$vault_path/.obsidian/community-plugins.json"

  if [[ ! -d "$vault_path/.obsidian" ]]; then
    echo "跳过 Obsidian 插件安装：$vault_path 不是有效 Obsidian Vault（缺少 .obsidian）。" >&2
    return 1
  fi

  if [[ ! -d "$OBSIDIAN_PLUGIN_SOURCE" ]]; then
    echo "跳过 Obsidian 插件安装：release 包中缺少 ObsidianPlugin/svlt。" >&2
    return 1
  fi

  if [[ ! -d "$plugin_target" && -d "$legacy_plugin_target" ]]; then
    mv "$legacy_plugin_target" "$plugin_target"
  fi

  mkdir -p "$plugin_target"
  cp "$OBSIDIAN_PLUGIN_SOURCE/main.js" "$plugin_target/main.js"
  cp "$OBSIDIAN_PLUGIN_SOURCE/manifest.json" "$plugin_target/manifest.json"
  if [[ -f "$OBSIDIAN_PLUGIN_SOURCE/styles.css" ]]; then
    cp "$OBSIDIAN_PLUGIN_SOURCE/styles.css" "$plugin_target/styles.css"
  fi

  if [[ -f "$enabled_plugins_path" ]]; then
    if ! node -e '
      const fs = require("fs");
      const filePath = process.argv[1];
      const plugins = JSON.parse(fs.readFileSync(filePath, "utf8"));
      if (!Array.isArray(plugins)) process.exit(0);
      const migrated = plugins.map((plugin) => plugin === "agent-secret-vault" ? "svlt" : plugin);
      if (JSON.stringify(migrated) !== JSON.stringify(plugins)) {
        fs.writeFileSync(filePath, `${JSON.stringify(migrated, null, 2)}\n`);
      }
    ' "$enabled_plugins_path"; then
      echo "未能更新 Obsidian 已启用插件列表，请在设置中手动启用 SVLT。" >&2
    fi
  fi

  echo "Obsidian 插件已安装: $plugin_target"
}

detect_obsidian_vaults() {
  local search_root="$HOME/Documents/obsidian"
  if [[ ! -d "$search_root" ]]; then
    return 0
  fi

  find "$search_root" -maxdepth 4 -type d -name ".obsidian" -print 2>/dev/null | while IFS= read -r obsidian_dir; do
    dirname "$obsidian_dir"
  done
}

OBSIDIAN_INSTALL_STATUS="未安装"
if [[ -n "${1:-}" ]]; then
  if install_obsidian_plugin "$1"; then
    OBSIDIAN_INSTALL_STATUS="已安装到: $1"
  fi
elif [[ -n "${OBSIDIAN_VAULT_PATH:-}" ]]; then
  if install_obsidian_plugin "$OBSIDIAN_VAULT_PATH"; then
    OBSIDIAN_INSTALL_STATUS="已安装到: $OBSIDIAN_VAULT_PATH"
  fi
else
  detected_vaults=()
  while IFS= read -r detected_vault; do
    detected_vaults+=("$detected_vault")
  done < <(detect_obsidian_vaults)

  if [[ "${#detected_vaults[@]}" -eq 1 ]]; then
    if install_obsidian_plugin "${detected_vaults[0]}"; then
      OBSIDIAN_INSTALL_STATUS="已自动安装到: ${detected_vaults[0]}"
    fi
  elif [[ "${#detected_vaults[@]}" -gt 1 ]]; then
    echo "检测到多个 Obsidian Vault，未自动安装插件。请指定 Vault 路径重新运行："
    echo "./install.sh \"/你的/Obsidian/Vault/路径\""
  else
    echo "未检测到 Obsidian Vault。需要时手动复制 ObsidianPlugin/svlt 到 Vault/.obsidian/plugins/。"
  fi
fi

cat > "$CONFIG_PATH" <<JSON
{
  "mcpServers": {
    "SVLT": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"\$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
JSON

echo "安装完成。"
echo "App: $APP_TARGET"
echo "后台 Agent: $APP_TARGET/Contents/MacOS/SVLTAgent"
echo "LaunchAgent: $APP_TARGET/Contents/Library/LaunchAgents/com.agent-secret-vault.SVLT.agent.plist"
echo "MCP 配置: $CONFIG_PATH"
echo "Codex Skill: $CODEX_SKILL_TARGET"
echo "Obsidian 插件: $OBSIDIAN_INSTALL_STATUS"
echo
echo "下一步："
echo "1. 打开 SVLT：open \"$APP_TARGET\"（首次启动会通过 SMAppService 注册后台 Agent）。"
echo "2. 在系统设置 → 通用 → 登录项中批准 SVLT（如 macOS 要求）。"
echo "3. Codex 的 SVLT Skill 已自动安装到 $CODEX_SKILL_TARGET；重启 Codex 或重新加载 skills，确保不继续使用旧版提示词。"
echo "4. 在 Codex / Claude / Hermes / OpenClaw 的 MCP 配置中粘贴 $CONFIG_PATH 的内容。"
echo "5. Claude / Hermes / OpenClaw 等不读取 Codex Skill 的 Agent，将 $RELEASE_DIR/svlt-agent-policy-zh-CN.md 中的代码块加入系统提示、项目规则或工作区规则。"
echo "6. 如需测量后台占用，运行：$RELEASE_DIR/check-agent-resources.sh"
echo "7. 如果安装了 Obsidian 插件，请在 Obsidian 设置 → 第三方插件中启用 SVLT。"

open "$APP_TARGET"
