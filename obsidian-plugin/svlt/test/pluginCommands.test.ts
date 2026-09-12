import { beforeEach, describe, expect, it, vi } from "vitest";

const obsidianMock = vi.hoisted(() => ({
  registeredCommands: [] as Array<{ id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void }>,
  registeredEvents: [] as unknown[],
  vaultEvents: [] as Array<{ name: string; callback: (...args: unknown[]) => void }>,
  workspaceEvents: [] as Array<{ name: string; callback: (...args: unknown[]) => void }>,
  notices: [] as string[],
  statusItems: [] as HTMLElement[],
  savedData: undefined as unknown
}));

vi.mock("obsidian", () => ({
  Notice: class NoticeTestDouble {
    constructor(message: string) {
      obsidianMock.notices.push(message);
    }
  },
  Modal: class ModalTestDouble {
    contentEl = { empty: vi.fn(), createEl: vi.fn() };

    constructor(_app: unknown) {}

    open(): void {}
    close(): void {}
  },
  Plugin: class ObsidianPluginTestDouble {
    app: unknown;

    constructor(app: unknown) {
      this.app = app;
    }

    addStatusBarItem(): HTMLElement {
      const element = { textContent: "", setAttribute: vi.fn() } as unknown as HTMLElement;
      obsidianMock.statusItems.push(element);
      return element;
    }

    addCommand(command: { id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void }): { id: string; name: string; callback?: () => void; editorCallback?: (editor: unknown) => void } {
      obsidianMock.registeredCommands.push(command);
      return command;
    }

    registerEvent(eventRef: unknown): void {
      obsidianMock.registeredEvents.push(eventRef);
    }

    register(callback: () => void): void {
      obsidianMock.registeredEvents.push(callback);
    }

    async loadData(): Promise<unknown> {
      return obsidianMock.savedData;
    }

    async saveData(data: unknown): Promise<void> {
      obsidianMock.savedData = data;
    }
  }
}));

import AgentSecretVaultPlugin, {
  catalogRawSHA256,
  commandDefinitions,
  shouldWatchCatalogFile
} from "../src/main";

function makeApp(options: {
  activeFile?: unknown;
  markdownFiles?: unknown[];
  fileContents?: Record<string, string>;
} = {}) {
  const fileContents = options.fileContents ?? {};
  return {
    vault: {
      on: (name: string, callback: (...args: unknown[]) => void) => {
        const eventRef = { name, callback };
        obsidianMock.vaultEvents.push(eventRef);
        return eventRef;
      },
      getMarkdownFiles: () => options.markdownFiles ?? [],
      cachedRead: async (file: { path: string }) => fileContents[file.path] ?? "",
      readBinary: async (file: { path: string }) => (
        new TextEncoder().encode(fileContents[file.path] ?? "").buffer as ArrayBuffer
      )
    },
    workspace: {
      on: (name: string, callback: (...args: unknown[]) => void) => {
        const eventRef = { name, callback };
        obsidianMock.workspaceEvents.push(eventRef);
        return eventRef;
      },
      getActiveFile: () => options.activeFile ?? null,
      getLeaf: () => ({ openFile: async () => undefined, view: null })
    }
  };
}

function makePlugin(
  clientResponse: unknown = { type: "failure", code: "APP_UNAVAILABLE" },
  appOptions: Parameters<typeof makeApp>[0] = {}
) {
  const plugin = new AgentSecretVaultPlugin(makeApp(appOptions) as never, {} as never) as unknown as {
    createVaultClient: () => unknown;
    onload: () => Promise<void>;
  };
  plugin.createVaultClient = () => ({
    request: async () => clientResponse
  });
  return plugin;
}

type ValidationTestPlugin = {
  createVaultClient: () => unknown;
  invalidateCatalogValidation: () => number;
  validateManagedCatalog: (generation: number) => Promise<void>;
  activeCatalogFile?: unknown;
  activeCatalogRawSHA256?: string;
  latestDiagnostics: unknown[];
  latestValidation?: { status: string; rawSHA256?: string | null; fingerprint: string };
};

async function digest(text: string): Promise<string> {
  return catalogRawSHA256(new TextEncoder().encode(text).buffer as ArrayBuffer);
}

describe("plugin commands", () => {
  beforeEach(() => {
    obsidianMock.registeredCommands = [];
    obsidianMock.registeredEvents = [];
    obsidianMock.vaultEvents = [];
    obsidianMock.workspaceEvents = [];
    obsidianMock.notices = [];
    obsidianMock.statusItems = [];
    obsidianMock.savedData = undefined;
  });

  it("registers validator-only commands", () => {
    expect(commandDefinitions.map((command) => command.id)).toEqual([
      "validate-catalog",
      "show-catalog-diagnostics"
    ]);
  });

  it("uses Chinese command names in the command palette", () => {
    expect(commandDefinitions.map((command) => command.name)).toEqual([
      "验证 SVLT 敏感信息目录",
      "查看 SVLT 目录诊断"
    ]);
  });

  it("keeps watching a catalog after its marker is deleted", () => {
    expect(shouldWatchCatalogFile("managedV3", false)).toBe(true);
    expect(shouldWatchCatalogFile("unmanaged", true)).toBe(true);
    expect(shouldWatchCatalogFile("unmanaged", false)).toBe(false);
  });

  it("accepts only vault-relative tracked catalog paths", async () => {
    const { isSafeTrackedCatalogPath } = await import("../src/main");
    expect(isSafeTrackedCatalogPath("敏感信息.md")).toBe(true);
    expect(isSafeTrackedCatalogPath("folder/敏感信息.md")).toBe(true);
    expect(isSafeTrackedCatalogPath("/Users/example/敏感信息.md")).toBe(false);
    expect(isSafeTrackedCatalogPath("../敏感信息.md")).toBe(false);
    expect(isSafeTrackedCatalogPath("folder\\敏感信息.md")).toBe(false);
  });

  it("binds validation identity to exact catalog bytes", async () => {
    const first = "# catalog\nvalue=a\n";
    const same = "# catalog\nvalue=a\n";
    const changed = "# catalog\nvalue=b\n";

    expect(await digest(first)).toBe(await digest(same));
    expect(await digest(first)).not.toBe(await digest(changed));
  });

  it("validates a tracked Catalog after a cold-start marker deletion", async () => {
    vi.useFakeTimers();
    try {
      const file = { path: "敏感信息.md", extension: "md" };
      const contents = "# 已删除 marker";
      obsidianMock.savedData = { managedCatalogPath: "敏感信息.md" };
      const plugin = makePlugin({
        type: "catalogValidation",
        catalogStatus: "CATALOG_INVALID",
        rawSHA256: await digest(contents),
        diagnostics: [{
          id: "CATALOG_MARKER_MISSING:1:1",
          severity: "error",
          code: "CATALOG_MARKER_MISSING",
          line: 1,
          column: 1,
          scope: "document",
          message: "Catalog marker 缺失。",
          hint: "补齐第一行 marker。"
        }]
      }, {
        markdownFiles: [file],
        fileContents: { "敏感信息.md": contents }
      });
      await plugin.onload();
      await vi.advanceTimersByTimeAsync(350);
      expect(obsidianMock.notices).toContain("SVLT：敏感信息目录有 1 个格式问题，第一个位于 第 1 行、第 1 列。");
    } finally {
      vi.useRealTimers();
    }
  });

  it("updates the persisted tracked path after a Catalog rename", async () => {
    obsidianMock.savedData = { managedCatalogPath: "敏感信息.md" };
    const plugin = makePlugin({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });
    await plugin.onload();

    const rename = obsidianMock.vaultEvents.find((event) => event.name === "rename");
    await rename?.callback({ path: "archive/敏感信息.md", extension: "md" }, "敏感信息.md");
    expect(obsidianMock.savedData).toEqual({ managedCatalogPath: "archive/敏感信息.md" });
  });

  it("registers commands and all catalog lifecycle watchers on load", async () => {
    const plugin = makePlugin({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });

    await plugin.onload();

    expect(obsidianMock.registeredCommands.map((command) => command.id)).toEqual([
      "validate-catalog",
      "show-catalog-diagnostics"
    ]);
    expect(obsidianMock.vaultEvents.map((event) => event.name)).toEqual(["modify", "rename", "delete"]);
    expect(obsidianMock.workspaceEvents.map((event) => event.name)).toEqual(["file-open", "active-leaf-change"]);
  });

  it("updates the status bar from live workbench status", async () => {
    const plugin = makePlugin({
      type: "workbenchStatus",
      status: {
        locked: false,
        ipcAvailable: true,
        activeKnowledgeBaseRoot: null,
        pluginConnected: true
      }
    });

    await plugin.onload();

    expect(obsidianMock.statusItems[0]?.textContent).toBe("ASV: connected, unlocked");
  });

  it("shows a failure notice when the app is unavailable", async () => {
    const plugin = makePlugin();

    await plugin.onload();
    await obsidianMock.registeredCommands.find((command) => command.id === "validate-catalog")?.callback?.();

    expect(obsidianMock.notices).toEqual([
      "SVLT：敏感信息目录验证失败（APP_UNAVAILABLE）。"
    ]);
  });

  it("reports diagnostics count and first location", async () => {
    const file = { path: "敏感信息.md", extension: "md" };
    const contents = "# tracked malformed catalog";
    const rawSHA256 = await digest(contents);
    obsidianMock.savedData = { managedCatalogPath: file.path };
    const plugin = makePlugin({
      type: "catalogValidation",
      catalogStatus: "CATALOG_INVALID",
      revision: 3,
      rawSHA256,
      diagnostics: [
        {
          id: "HEADING_MARKER_MISMATCH:7:1",
          severity: "error",
          code: "HEADING_MARKER_MISMATCH",
          line: 7,
          column: 1,
          scope: "entry",
          message: "heading 与 marker 标题不一致",
          hint: "使 heading 与 marker 中的标题保持一致"
        },
        {
          id: "FIELD_KEY_DUPLICATE:9:1",
          severity: "error",
          code: "FIELD_KEY_DUPLICATE",
          line: 9,
          column: 1,
          scope: "field",
          message: "同一条目中存在重复字段 key。",
          hint: "每个条目的字段 key 必须唯一。"
        }
      ]
    }, {
      markdownFiles: [file],
      fileContents: { [file.path]: contents }
    });

    await plugin.onload();
    await obsidianMock.registeredCommands.find((command) => command.id === "validate-catalog")?.callback?.();

    expect(obsidianMock.notices).toEqual([
      "SVLT：敏感信息目录有 2 个格式问题，第一个位于 第 7 行、第 1 列。"
    ]);
    expect(obsidianMock.statusItems[0]?.textContent).toContain("2 个问题");
  });

  it("updates state when the same failure recurs after a successful validation", async () => {
    const plugin = makePlugin() as unknown as ValidationTestPlugin;
    plugin.activeCatalogFile = { path: "敏感信息.md", extension: "md" };
    plugin.activeCatalogRawSHA256 = "new";
    const responses = [
      { type: "failure", code: "APP_UNAVAILABLE" },
      { type: "catalogValidation", catalogStatus: "FOUND", rawSHA256: "new", diagnostics: [] },
      { type: "failure", code: "APP_UNAVAILABLE" }
    ];
    plugin.createVaultClient = () => ({ request: async () => responses.shift() });

    for (let index = 0; index < 3; index += 1) {
      const generation = plugin.invalidateCatalogValidation();
      await plugin.validateManagedCatalog(generation);
    }

    expect(plugin.latestValidation?.status).toBe("CATALOG_UNAVAILABLE");
    expect(obsidianMock.notices).toEqual([
      "SVLT：敏感信息目录验证失败（APP_UNAVAILABLE）。",
      "SVLT：敏感信息目录验证失败（APP_UNAVAILABLE）。"
    ]);
  });

  it("ignores an older validation response that arrives after a newer result", async () => {
    const plugin = makePlugin() as unknown as ValidationTestPlugin;
    plugin.activeCatalogFile = { path: "敏感信息.md", extension: "md" };
    plugin.activeCatalogRawSHA256 = "new";
    const resolvers: Array<(value: unknown) => void> = [];
    plugin.createVaultClient = () => ({
      request: () => new Promise((resolve) => resolvers.push(resolve))
    });

    const firstGeneration = plugin.invalidateCatalogValidation();
    const first = plugin.validateManagedCatalog(firstGeneration);
    await Promise.resolve();

    const secondGeneration = plugin.invalidateCatalogValidation();
    const second = plugin.validateManagedCatalog(secondGeneration);
    await Promise.resolve();

    resolvers[1]?.({
      type: "catalogValidation",
      catalogStatus: "FOUND",
      rawSHA256: "new",
      diagnostics: []
    });
    await second;

    resolvers[0]?.({
      type: "catalogValidation",
      catalogStatus: "FOUND",
      rawSHA256: "old",
      diagnostics: []
    });
    await first;

    expect(plugin.latestValidation?.rawSHA256).toBe("new");
  });

  it("rejects diagnostics validated against different catalog bytes", async () => {
    const plugin = makePlugin() as unknown as ValidationTestPlugin;
    plugin.activeCatalogFile = { path: "local.md", extension: "md" };
    plugin.activeCatalogRawSHA256 = "local-hash";
    plugin.createVaultClient = () => ({
      request: async () => ({
        type: "catalogValidation",
        catalogStatus: "CATALOG_INVALID",
        rawSHA256: "server-hash",
        diagnostics: [{
          id: "WRONG_DOCUMENT:9:1",
          severity: "error",
          code: "WRONG_DOCUMENT",
          line: 9,
          scope: "document",
          message: "must not be applied"
        }]
      })
    });

    const generation = plugin.invalidateCatalogValidation();
    await plugin.validateManagedCatalog(generation);

    expect(plugin.latestValidation?.status).toBe("CATALOG_UNAVAILABLE");
    expect(plugin.latestDiagnostics).toEqual([]);
    expect(obsidianMock.notices).toEqual([
      "SVLT：当前文件不是正在校验的目录，已忽略这次校验结果。"
    ]);
  });
});
