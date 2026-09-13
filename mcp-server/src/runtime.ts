#!/usr/bin/env node
import { pathToFileURL } from "node:url";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { LocalIpcClient } from "./client.js";
import { AgentCallerIdentity } from "./protocol.js";
import {
  createVaultToolDefinitions,
  type VaultIpcClient
} from "./server.js";
import { runWithSecretOperationAbortSignal } from "./secretOperations/context.js";
import {
  OPERATION_OUTCOME_UNKNOWN,
  OUTCOME_UNKNOWN_GUIDANCE
} from "./secretOperations/index.js";

export { createVaultToolDefinitions } from "./server.js";
export type { VaultIpcClient, VaultToolDefinition } from "./server.js";

export function createMcpServer(client: VaultIpcClient = new LocalIpcClient()): McpServer {
  const server = new McpServer({
    name: "SVLT",
    version: "0.1.21"
  });

  registerVaultTools(server, client);
  return server;
}

export function registerVaultTools(server: McpServer, client: VaultIpcClient): void {
  const callerAwareClient: VaultIpcClient = {
    request: (request) => client.request(request, declaredCallerIdentity(server))
  };

  for (const tool of createVaultToolDefinitions(callerAwareClient)) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema
      },
      async (input, extra) => runWithSecretOperationAbortSignal(extra.signal, async () => {
        let result: CallToolResult;
        try {
          result = await tool.handler(input);
        } catch (error) {
          if (error instanceof z.ZodError) {
            return inputValidationResult(error);
          }
          throw error;
        }

        if (!result.isError) {
          if (result.structuredContent === undefined) {
            throw new Error(`Tool ${tool.name} returned no structuredContent`);
          }
          await tool.outputSchema.parseAsync(result.structuredContent);
        }
        return annotateOutcomeUnknownResult(result);
      })
    );
  }
}

export async function runStdioServer(client: VaultIpcClient = new LocalIpcClient()): Promise<void> {
  const server = createMcpServer(client);
  await server.connect(new StdioServerTransport());
}

export function annotateOutcomeUnknownResult(result: CallToolResult): CallToolResult {
  const structuredContent = result.structuredContent;
  if (
    structuredContent === undefined
    || structuredContent.status !== OPERATION_OUTCOME_UNKNOWN
  ) {
    return result;
  }

  // Keep structuredContent schema-compatible with the existing MCP tools, but
  // make the non-retry semantics explicit in the human/model-readable content.
  // outcomeUnknown is a business state, not a generic MCP error: the external
  // side effect may already have happened and must be reconciled before retry.
  const agentFacingContent = {
    ...structuredContent,
    retrySafe: false,
    reconciliationRequired: true,
    guidance: OUTCOME_UNKNOWN_GUIDANCE
  };
  return {
    ...result,
    content: [{ type: "text", text: JSON.stringify(agentFacingContent) }]
  };
}

function declaredCallerIdentity(server: McpServer): AgentCallerIdentity {
  const clientInfo = server.server.getClientVersion();
  const candidate = AgentCallerIdentity.safeParse({
    name: clientInfo?.name ?? process.env.SVLT_AGENT_NAME ?? "Unknown MCP Client",
    ...(clientInfo?.version ?? process.env.SVLT_AGENT_VERSION
      ? { version: clientInfo?.version ?? process.env.SVLT_AGENT_VERSION }
      : {}),
    transport: "mcp"
  });
  return candidate.success
    ? candidate.data
    : { name: "Unknown MCP Client", transport: "mcp" };
}

function inputValidationResult(error: z.ZodError): CallToolResult {
  const errors = error.issues.map((issue) => {
    const path = issue.path.map(String);
    const displayPath = path.length === 0 ? "输入" : path.join(".");
    return {
      path,
      message: issue.message,
      hint: `请检查字段 ${displayPath}。`
    };
  });
  const structuredContent = { status: "INVALID_INPUT", errors };
  return {
    isError: true,
    structuredContent,
    content: [{ type: "text", text: JSON.stringify(structuredContent) }]
  };
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runStdioServer();
}
