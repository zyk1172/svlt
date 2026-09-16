import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("two-tier approval source contract", () => {
  it("keeps the owner mode boundary wired through daemon, approver, Catalog, MCP, and Skill", async () => {
    const [core, semanticReview, approver, catalog, mcpClient, skill] = await Promise.all([
      readFile(path.join(repositoryRoot, "Sources/VaultCore/VaultCore.swift"), "utf8"),
      readFile(path.join(repositoryRoot, "Sources/VaultService/VaultAppServices+SemanticReview.swift"), "utf8"),
      readFile(path.join(repositoryRoot, "Sources/VaultAuthorization/OperationApprover.swift"), "utf8"),
      readFile(path.join(repositoryRoot, "Sources/VaultService/CatalogWriteAccessCoordinator.swift"), "utf8"),
      readFile(path.join(repositoryRoot, "mcp-server/src/client.ts"), "utf8"),
      readFile(path.join(repositoryRoot, "plugins/svlt/skills/svlt/SKILL.md"), "utf8")
    ]);

    expect(core).toContain("case approvalRequired");
    expect(core).toContain("case noApproval");
    expect(core).toContain('appendingPathComponent("approval-mode.json"');
    expect(core).toContain(".posixPermissions: 0o600");

    expect(semanticReview).toContain("guard !preflight.technicalFailure else");
    expect(semanticReview).toContain("VaultApprovalModeState.shared.mode == .noApproval");
    expect(semanticReview).toContain("route: .fast");
    expect(semanticReview).toContain("authorizationRequirement: .none");

    expect(approver).toContain("VaultApprovalModeState.shared.mode == .noApproval");
    expect(approver).toContain("return nil");

    expect(catalog).toContain("VaultApprovalModeState.shared.mode == .noApproval");
    expect(catalog).toContain("无审批模式自动通过");

    expect(mcpClient).toContain('export type VaultApprovalMode = "approvalRequired" | "noApproval"');
    expect(mcpClient).toContain("const approvalMode = await readVaultApprovalMode(this.approvalModePath)");
    expect(mcpClient).toContain('approvalMode === "noApproval"');
    expect(mcpClient).toContain("applyContextBoundedRiskJudge");

    expect(skill).toContain("approvalRequired");
    expect(skill).toContain("noApproval");
    expect(skill).toContain("无审批模式下，是否执行由主 Agent 自己决定");
  });

  it("does not turn malformed preflight requests into no-approval FAST operations", async () => {
    const semanticReview = await readFile(
      path.join(repositoryRoot, "Sources/VaultService/VaultAppServices+SemanticReview.swift"),
      "utf8"
    );
    const technicalGuard = semanticReview.indexOf("guard !preflight.technicalFailure else");
    const noApprovalOverride = semanticReview.indexOf("if VaultApprovalModeState.shared.mode == .noApproval");

    expect(technicalGuard).toBeGreaterThanOrEqual(0);
    expect(noApprovalOverride).toBeGreaterThan(technicalGuard);
  });
});
