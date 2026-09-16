import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { readVaultApprovalMode } from "../src/client.js";

const cleanupDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(cleanupDirectories.splice(0).map((directory) =>
    rm(directory, { recursive: true, force: true })
  ));
});

describe("SVLT approval mode file", () => {
  it("fails closed to approvalRequired when the file is missing", async () => {
    const directory = await makeDirectory();
    await expect(readVaultApprovalMode(path.join(directory, "missing.json")))
      .resolves.toBe("approvalRequired");
  });

  it("accepts an owner-only noApproval mode file", async () => {
    const file = await writeMode({ schemaVersion: 1, mode: "noApproval" }, 0o600);
    await expect(readVaultApprovalMode(file)).resolves.toBe("noApproval");
  });

  it("fails closed when the mode file is group or world readable", async () => {
    const file = await writeMode({ schemaVersion: 1, mode: "noApproval" }, 0o600);
    await chmod(file, 0o644);
    await expect(readVaultApprovalMode(file)).resolves.toBe("approvalRequired");
  });

  it("fails closed for malformed, unknown, or stale schema values", async () => {
    const directory = await makeDirectory();
    const malformed = path.join(directory, "malformed.json");
    await writeFile(malformed, "not-json", { mode: 0o600 });
    await expect(readVaultApprovalMode(malformed)).resolves.toBe("approvalRequired");

    const unknown = path.join(directory, "unknown.json");
    await writeFile(unknown, JSON.stringify({ schemaVersion: 1, mode: "everythingAllowed" }), { mode: 0o600 });
    await expect(readVaultApprovalMode(unknown)).resolves.toBe("approvalRequired");

    const stale = path.join(directory, "stale.json");
    await writeFile(stale, JSON.stringify({ schemaVersion: 0, mode: "noApproval" }), { mode: 0o600 });
    await expect(readVaultApprovalMode(stale)).resolves.toBe("approvalRequired");
  });
});

async function makeDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "svlt-approval-mode-"));
  cleanupDirectories.push(directory);
  return directory;
}

async function writeMode(
  payload: { schemaVersion: number; mode: string },
  mode: number
): Promise<string> {
  const directory = await makeDirectory();
  const file = path.join(directory, "approval-mode.json");
  await writeFile(file, JSON.stringify(payload), { mode });
  return file;
}
