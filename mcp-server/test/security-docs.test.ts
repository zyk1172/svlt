import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("security documentation", () => {
  it("states every excluded threat and first-release scope exclusion", async () => {
    const threatModel = await readFile(
      path.join(repositoryRoot, "docs/security/threat-model.md"),
      "utf8"
    );

    for (const phrase of [
      "malicious software running as the same macOS user",
      "screen recording or physical observation",
      "administrator or root control",
      "compromise of the signed application binary",
      "developer signing identity",
      "Claude and Hermes integrations",
      "full-note encryption",
      "plaintext rendering inside the original Codex App",
      "iPhone or iPad clients",
      "team sharing and multi-user access control",
      "arbitrary shell execution",
      "bulk plaintext export",
      "defense against same-user malware or root compromise"
    ]) {
      expect(threatModel).toContain(phrase);
    }
  });

  it("lists release checklist acceptance criteria 1 through 17", async () => {
    const checklist = await readFile(
      path.join(repositoryRoot, "docs/security/release-checklist.md"),
      "utf8"
    );

    for (let criterion = 1; criterion <= 17; criterion += 1) {
      expect(checklist).toMatch(new RegExp(`^${criterion}\\.\\s`, "m"));
    }
  });

  it("documents generic Codex Claude Hermes MCP usage without device-brand coupling", async () => {
    const integration = await readFile(
      path.join(repositoryRoot, "docs/agent-integration.md"),
      "utf8"
    );

    for (const phrase of [
      "Codex",
      "Claude",
      "Hermes",
      "agent_secret_usage_policy",
      "secret://",
      "secret_auto_handle_text",
      "local_http_request_with_secret",
      "~/Library/Application Support/AgentSecretVault/MCP/dist/server.js",
      "$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js",
      "USER_EXPLICIT_PLAINTEXT",
      "每个 operation 独立计算",
      "sticky state",
      "opt-in"
    ]) {
      expect(integration).toContain(phrase);
    }
    expect(integration).not.toContain("/Users/zhengyunkai/");
    expect(integration).not.toMatch(/qnap/i);
  });

  it("does not ship executable examples with fabricated references or shell chaining", async () => {
    const usage = await readFile(
      path.join(repositoryRoot, "docs/universal-agent-usage.md"),
      "utf8"
    );

    expect(usage).toContain("不能整段直接执行");
    expect(usage).toContain('"command": "hostname"');
    expect(usage).not.toContain('"command": "hostname && whoami && uptime"');
    expect(usage).not.toContain('"passwordRef": "secret://0123456789ABCDEFGHJKMNPQRS"');
    expect(usage).not.toContain('"tokenRef": "secret://0123456789ABCDEFGHJKMNPQRS"');
  });

  it("retires legacy semantic marker protocols from the intent-first design", async () => {
    const design = await readFile(path.join(repositoryRoot, "docs/security/context-bounded-risk-judge.md"), "utf8");
    expect(design).toContain("String marker protocols");
    expect(design).toContain("retired");
  });

  it("keeps shipped Agent guidance aligned with the two-tier approval model", async () => {
    const skill = await readFile(
      path.join(repositoryRoot, "plugins/svlt/skills/svlt/SKILL.md"),
      "utf8"
    );
    const genericPolicy = await readFile(
      path.join(repositoryRoot, "docs/svlt-agent-policy-zh-CN.md"),
      "utf8"
    );

    for (const document of [skill, genericPolicy]) {
      for (const phrase of [
        "approvalRequired",
        "noApproval",
        "daemon-bound bounded main-Agent fallback",
        "automatic-v2"
      ]) {
        expect(document).toContain(phrase);
      }
    }

    expect(skill).toContain("无审批模式下，是否执行由主 Agent 自己决定");
    expect(genericPolicy).toContain("noApproval 下，是否发起一个危险操作由主 Agent 自己决定");
    expect(genericPolicy).toContain("judge 未配置、超时或临时不可用本身不是危险效果");
    expect(skill).toContain("旧 Keychain 数据迁移，不是 operation approval");
    expect(skill).toContain("device-owner authentication");
    expect(genericPolicy).toContain("该认证属于旧密钥迁移，不代表以后每次 Secret 使用都需要审批");
    expect(skill).not.toContain("`GRAY` 由独立 semantic judge 复核");
    expect(genericPolicy).not.toContain("由独立 semantic judge在");
  });

  it("packages and installs the same Codex skill with every release", async () => {
    const packageRelease = await readFile(
      path.join(repositoryRoot, "scripts/package-release.sh"),
      "utf8"
    );
    const installRelease = await readFile(
      path.join(repositoryRoot, "scripts/install-release.sh"),
      "utf8"
    );

    expect(packageRelease).toContain('CODEX_SKILL_STAGING="$STAGING_DIR/CodexSkill/svlt"');
    expect(packageRelease).toContain('plugins/svlt/skills/svlt');
    expect(installRelease).toContain('CODEX_SKILL_SOURCE="$RELEASE_DIR/CodexSkill/svlt"');
    expect(installRelease).toContain('CODEX_SKILL_TARGET="$CODEX_HOME/skills/svlt"');
    expect(installRelease).toContain('cmp -s "$CODEX_SKILL_SOURCE/SKILL.md" "$CODEX_SKILL_TARGET/SKILL.md"');
  });
});
