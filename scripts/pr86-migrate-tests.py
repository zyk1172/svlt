from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, text: str) -> None:
    Path(path).write_text(text)


# ---------------------------------------------------------------------------
# MCP tool tests: keep production schemas strict/mandatory, but give legacy
# success-path fixtures an explicit routine assessment. Tests that specifically
# verify omission use rawTool() and therefore still prove the schema rejects it.
# ---------------------------------------------------------------------------
path = "mcp-server/test/tools.test.ts"
text = read(path)
old = '''function tool(client: VaultIpcClient, name: string) {
  const definition = createVaultToolDefinitions(client).find((item) => item.name === name);
  if (definition === undefined) {
    throw new Error(`missing tool ${name}`);
  }
  return definition;
}
'''
new = '''const routineAssessment = {
  reason: "test fixture: routine user-aligned operation",
  userGoal: "Complete the requested test operation",
  taskContext: "MCP contract test fixture",
  intendedEffect: "Perform the bounded requested operation",
  expectedEffect: "Only the requested bounded target changes",
  expectedResult: "The requested operation completes",
  intentAlignment: "direct" as const,
  effectSeverity: "minor" as const,
  reversibility: "easy" as const,
  secretHandling: "credentialUse" as const,
  executionRecommendation: "automatic" as const,
  confidence: 0.95
};

const assessmentToolNames = new Set([
  "secret_bind_destination",
  "ssh_command_with_secret",
  "ssh_batch_with_secret",
  "local_http_request_with_secret",
  "api_request_with_token",
  "database_query_with_secret",
  "sftp_transfer_with_secret",
  "ftp_transfer_with_secret",
  "browser_web_login_with_secret",
  "local_app_form_fill_with_secret",
  "local_execution_with_secret",
  "trusted_process_with_secret",
  "secret_reveal_request",
  "secret_export_resolved_text"
]);

type ToolDefinition = ReturnType<typeof createVaultToolDefinitions>[number];

function rawTool(client: VaultIpcClient, name: string): ToolDefinition {
  const definition = createVaultToolDefinitions(client).find((item) => item.name === name);
  if (definition === undefined) {
    throw new Error(`missing tool ${name}`);
  }
  return definition;
}

function tool(client: VaultIpcClient, name: string): ToolDefinition {
  const definition = rawTool(client, name);
  if (!assessmentToolNames.has(name)) return definition;
  return {
    ...definition,
    async handler(input: unknown) {
      const enriched = typeof input === "object" && input !== null && !("agentAssessment" in input)
        ? { ...(input as Record<string, unknown>), agentAssessment: routineAssessment }
        : input;
      return definition.handler(enriched as never);
    }
  } as ToolDefinition;
}
'''
if old not in text:
    raise SystemExit("tools helper marker missing")
text = text.replace(old, new, 1)
old_test = '''  it("fills the conservative default assessment when the agent omits one", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "", stderr: "" })]);
    await tool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname"
    });

    const request = client.requests[0];
    expect(request.type).toBe("executeSecretOperation");
    if (request.type !== "executeSecretOperation") return;
    expect(request.descriptor.agentAssessment).toEqual({
      source: "mainAgent",
      declaredRisk: "approvalRequired",
      reason: "Main Agent did not provide a semantic assessment",
      userGoal: "Complete the requested Secret-backed operation",
      taskContext: "No additional task context supplied",
      intendedEffect: "Perform the requested operation",
      expectedEffect: "Unknown until independently reviewed",
      expectedResult: "Complete the user's requested task",
      intentAlignment: "unclear",
      effectSeverity: "unknown",
      reversibility: "unknown",
      secretHandling: "unknown",
      executionRecommendation: "uncertain",
      confidence: 0
    });
  });
'''
new_test = '''  it("requires the main Agent assessment instead of silently manufacturing one", async () => {
    const client = new FakeClient([operationResponse({ exitCode: 0, stdout: "", stderr: "" })]);
    await expect(rawTool(client, "ssh_command_with_secret").handler({
      host: "qnap.local",
      username: "admin",
      passwordRef: reference,
      command: "hostname"
    } as never)).rejects.toThrow(/agentAssessment|expected object/i);
    expect(client.requests).toHaveLength(0);
  });
'''
if old_test not in text:
    raise SystemExit("old conservative default test marker missing")
text = text.replace(old_test, new_test, 1)
write(path, text)


# ---------------------------------------------------------------------------
# Legacy timeout compatibility: timeoutMs remains accepted, while the new
# assessment contract remains mandatory. Supply an explicit assessment so this
# test continues to isolate timeout compatibility rather than schema omission.
# ---------------------------------------------------------------------------
path = "mcp-server/test/legacy-timeout-compat.test.ts"
text = read(path)
marker = 'const reference = "secret://0123456789ABCDEFGHJKMNPQRS";\n'
assessment = '''const reference = "secret://0123456789ABCDEFGHJKMNPQRS";
const assessment = {
  reason: "legacy timeout compatibility fixture",
  userGoal: "Exercise the historical timeoutMs input shape",
  taskContext: "Schema compatibility test",
  intendedEffect: "Perform the requested bounded operation",
  expectedEffect: "Only the requested operation runs",
  expectedResult: "The operation input remains accepted",
  intentAlignment: "direct",
  effectSeverity: "minor",
  reversibility: "easy",
  secretHandling: "credentialUse",
  executionRecommendation: "automatic",
  confidence: 0.95
};
'''
if marker not in text:
    raise SystemExit("legacy timeout reference marker missing")
text = text.replace(marker, assessment, 1)
old = '      expect(() => inputSchema(name).parse(input), name).not.toThrow();'
new = '      expect(() => inputSchema(name).parse({ ...input, agentAssessment: assessment }), name).not.toThrow();'
if old not in text:
    raise SystemExit("legacy timeout parse marker missing")
text = text.replace(old, new, 1)
write(path, text)


# ---------------------------------------------------------------------------
# LocalIpcClient lifecycle timeout test: the daemon now owns semantic routing,
# so the client performs a bounded preflight IPC before lifecycle start. Reply
# to preflight, then deliberately withhold the start acknowledgement.
# ---------------------------------------------------------------------------
path = "mcp-server/test/protocol.test.ts"
text = read(path)
old = '''    let receivedRequestType: string | undefined;
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.setTimeout(25, () => socket.destroy());
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.on("end", () => {
        const frame = Buffer.concat(chunks);
        const declaredLength = frame.readUInt32BE(0);
        expect(frame.byteLength - 4).toBe(declaredLength);
        const envelope = JSON.parse(frame.subarray(4).toString("utf8")) as {
          request?: { type?: string };
        };
        receivedRequestType = envelope.request?.type;
        // Deliberately do not reply. A lifecycle start/status/cancel request is
        // a bounded control request; if the daemon does not acknowledge it in
        // time the caller must surface uncertainty rather than hold one long
        // execution socket open or retry the side effect.
      });
    });
'''
new = '''    const receivedRequestTypes: string[] = [];
    const server = net.createServer({ allowHalfOpen: true }, (socket) => {
      socket.setTimeout(100, () => socket.destroy());
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => chunks.push(chunk));
      socket.on("end", () => {
        const frame = Buffer.concat(chunks);
        const declaredLength = frame.readUInt32BE(0);
        expect(frame.byteLength - 4).toBe(declaredLength);
        const envelope = JSON.parse(frame.subarray(4).toString("utf8")) as {
          request?: { type?: string };
        };
        const requestType = envelope.request?.type;
        if (requestType !== undefined) receivedRequestTypes.push(requestType);
        if (requestType === "preflightSecretOperation") {
          socket.end(IpcFrameCodec.encode({
            type: "secretOperationPreflight",
            result: {
              route: "fast",
              policyRuleID: "test.fast",
              authorizationRequirement: "none",
              blastRadius: "tiny",
              reasons: [],
              technicalFailure: false
            }
          }));
          return;
        }
        // Deliberately do not reply to lifecycle start. A start/status/cancel
        // IPC is a bounded control request; timeout means outcome uncertainty.
      });
    });
'''
if old not in text:
    raise SystemExit("protocol lifecycle server marker missing")
text = text.replace(old, new, 1)
text = text.replace('      requestTimeoutMs: 10,', '      requestTimeoutMs: 50,', 1)
old_expect = '    expect(receivedRequestType).toBe("startSecretOperation");'
new_expect = '    expect(receivedRequestTypes).toEqual(["preflightSecretOperation", "startSecretOperation"]);'
if old_expect not in text:
    raise SystemExit("protocol request type expectation marker missing")
text = text.replace(old_expect, new_expect, 1)
write(path, text)

print("PR86 MCP tests migrated to mandatory assessment + daemon preflight")
