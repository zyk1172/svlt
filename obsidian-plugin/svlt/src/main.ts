import { MarkdownView, Modal, Notice, Plugin, type App, type EventRef, type TFile } from "obsidian";
import { LocalVaultClient } from "./ipc/client";
import type { CatalogValidationDiagnostic } from "./ipc/protocol";
import { classifyCatalogText } from "./catalog/managedCatalog";
import { interpretWorkbenchStatus } from "./pairing/pairing";
import { updateStatusBar } from "./ui/statusBar";

const DEFAULT_SOCKET_PATH = `${process.env.HOME ?? ""}/Library/Application Support/AgentSecretVault/IPC/agent-secret-vault.sock`;

/**
 * Obsidian is deliberately a validator-only client. It may read Markdown and
 * show source-safe diagnostics, but it never encrypts, decrypts, repairs, or
 * writes a managed catalog. The Swift Core remains the sole parser and
 * mutation authority.
 */
export const commandDefinitions = [
  { id: "validate-catalog", name: "验证 SVLT 敏感信息目录" },
  { id: "show-catalog-diagnostics", name: "查看 SVLT 目录诊断" }
] as const;

export function shouldWatchCatalogFile(classified: string, isTracked: boolean): boolean {
  return isTracked || classified.startsWith("managed");
}

/** Only vault-relative paths are allowed in plugin-local persisted state. */
export function isSafeTrackedCatalogPath(path: string): boolean {
  return path.length > 0
    && !path.startsWith("/")
    && !path.includes("\\")
    && !path.split("/").some((component) => component === ".." || component.length === 0);
}

export async function catalogRawSHA256(bytes: ArrayBuffer): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

type TrackedCatalogData = {
  managedCatalogPath?: unknown;
};

type ValidationResult = Extract<Awaited<ReturnType<LocalVaultClient["request"]>>, { type: "catalogValidation" }>;

export default class AgentSecretVaultPlugin extends Plugin {
  private catalogValidationTimer: ReturnType<typeof setTimeout> | undefined;
  private catalogValidationGeneration = 0;
  private statusBar?: HTMLElement;
  private latestDiagnostics: CatalogValidationDiagnostic[] = [];
  private lastNoticeFingerprint?: string;
  private latestValidation?: {
    status: ValidationResult["catalogStatus"];
    rawSHA256?: string | null;
    fingerprint: string;
  };
  private activeCatalogFile?: TFile;
  private activeCatalogRawSHA256?: string;
  private latestValidatedCatalogFile?: TFile;
  /** The only persisted Catalog identity: a Vault-relative path. */
  private trackedCatalogPath?: string;

  private createVaultClient(): LocalVaultClient {
    return new LocalVaultClient(DEFAULT_SOCKET_PATH);
  }

  async onload(): Promise<void> {
    const pairing = interpretWorkbenchStatus({ reachable: false });
    this.statusBar = this.addStatusBarItem();
    updateStatusBar(this.statusBar, { connected: pairing.canOperate, locked: !pairing.canOperate });

    this.addCommand({
      id: "validate-catalog",
      name: "验证 SVLT 敏感信息目录",
      callback: async () => {
        await this.validateManagedCatalog(this.invalidateCatalogValidation());
      }
    });
    this.addCommand({
      id: "show-catalog-diagnostics",
      name: "查看 SVLT 目录诊断",
      callback: () => this.showCatalogDiagnostics()
    });

    await this.loadTrackedCatalogIdentity();
    await this.initializeTrackedCatalogFile();
    await this.refreshStatus();
    this.registerJumpProtocol();
    this.registerCatalogWatcher();
    this.register(() => {
      if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
      this.catalogValidationTimer = undefined;
      this.invalidateCatalogValidation();
    });
  }

  private registerCatalogWatcher(): void {
    const modifyRef = this.app.vault.on("modify", (file) => {
      if (!(file instanceof Object) || !("extension" in file) || (file as TFile).extension !== "md") return;
      void this.validateModifiedCatalog(file as TFile, this.invalidateCatalogValidation());
    }) as EventRef;
    this.registerEvent(modifyRef);

    const renameRef = this.app.vault.on("rename", (file, oldPath) => {
      const renamed = file as TFile;
      if (!renamed || typeof oldPath !== "string" || oldPath !== this.trackedCatalogPath) return;
      if (!isSafeTrackedCatalogPath(renamed.path)) return;
      this.invalidateCatalogValidation();
      this.trackedCatalogPath = renamed.path;
      this.activeCatalogFile = renamed;
      void this.saveTrackedCatalogIdentity();
    }) as EventRef;
    this.registerEvent(renameRef);

    const deleteRef = this.app.vault.on("delete", (file) => {
      const deleted = file as TFile;
      if (!deleted || deleted.path !== this.trackedCatalogPath) return;
      this.invalidateCatalogValidation();
      this.activeCatalogFile = undefined;
      this.activeCatalogRawSHA256 = undefined;
      new Notice("SVLT：SVLT 管理的敏感信息目录文件已不存在。");
    }) as EventRef;
    this.registerEvent(deleteRef);

    const fileOpenRef = this.app.workspace.on("file-open", (file) => {
      if (!file || !(file instanceof Object) || !("extension" in file)) return;
      void this.validateModifiedCatalog(file as TFile, this.invalidateCatalogValidation());
    }) as EventRef;
    this.registerEvent(fileOpenRef);

    const activeLeafRef = this.app.workspace.on("active-leaf-change", () => {
      const file = this.app.workspace.getActiveFile();
      if (file) void this.validateModifiedCatalog(file, this.invalidateCatalogValidation());
    }) as EventRef;
    this.registerEvent(activeLeafRef);
  }

  private async loadTrackedCatalogIdentity(): Promise<void> {
    const loader = (this as unknown as { loadData?: () => Promise<unknown> }).loadData;
    if (typeof loader !== "function") return;
    try {
      const data = await loader.call(this) as TrackedCatalogData | null;
      const path = typeof data?.managedCatalogPath === "string" ? data.managedCatalogPath : undefined;
      this.trackedCatalogPath = path && isSafeTrackedCatalogPath(path) ? path : undefined;
    } catch {
      this.trackedCatalogPath = undefined;
    }
  }

  private async saveTrackedCatalogIdentity(): Promise<void> {
    const saver = (this as unknown as { saveData?: (data: unknown) => Promise<void> }).saveData;
    if (typeof saver !== "function") return;
    try {
      await saver.call(this, { managedCatalogPath: this.trackedCatalogPath ?? null });
    } catch {
      // Persistence is best-effort; the in-memory identity remains active.
    }
  }

  private async initializeTrackedCatalogFile(): Promise<void> {
    const candidate = this.trackedCatalogPath
      ? this.app.vault.getMarkdownFiles().find((file) => file.path === this.trackedCatalogPath)
      : this.app.workspace.getActiveFile();
    if (!candidate) return;
    await this.validateModifiedCatalog(candidate, this.invalidateCatalogValidation());
  }

  private async validateModifiedCatalog(file: TFile, observationGeneration: number): Promise<void> {
    try {
      const text = await this.app.vault.cachedRead(file);
      if (!this.isCurrentCatalogValidation(observationGeneration)) return;

      const classified = classifyCatalogText(text);
      const isTracked = this.trackedCatalogPath === file.path || this.activeCatalogFile?.path === file.path;
      if (!shouldWatchCatalogFile(classified, isTracked)) return;

      // Bind the upcoming service response to the exact bytes Obsidian sees.
      // The service already returns SHA-256 of the bytes it validated, so no
      // absolute path or new wire-protocol identity is required.
      const rawBytes = await this.app.vault.readBinary(file);
      if (!this.isCurrentCatalogValidation(observationGeneration)) return;
      const rawSHA256 = await catalogRawSHA256(rawBytes);
      if (!this.isCurrentCatalogValidation(observationGeneration)) return;

      if (classified === "managedV3") {
        this.activeCatalogFile = file;
        this.activeCatalogRawSHA256 = rawSHA256;
        if (this.trackedCatalogPath !== file.path) {
          this.trackedCatalogPath = file.path;
          await this.saveTrackedCatalogIdentity();
          if (!this.isCurrentCatalogValidation(observationGeneration)) return;
        }
      } else if (isTracked) {
        this.activeCatalogFile = file;
        this.activeCatalogRawSHA256 = rawSHA256;
      }
      this.scheduleCatalogValidation();
    } catch {
      // The explicit command remains available; watcher failures are silent.
    }
  }

  private scheduleCatalogValidation(): void {
    if (this.catalogValidationTimer) clearTimeout(this.catalogValidationTimer);
    const generation = this.invalidateCatalogValidation();
    this.catalogValidationTimer = setTimeout(() => {
      this.catalogValidationTimer = undefined;
      void this.validateManagedCatalog(generation);
    }, 300);
  }

  private invalidateCatalogValidation(): number {
    this.catalogValidationGeneration += 1;
    this.latestValidatedCatalogFile = undefined;
    return this.catalogValidationGeneration;
  }

  private isCurrentCatalogValidation(generation: number): boolean {
    return generation === this.catalogValidationGeneration;
  }

  private registerJumpProtocol(): void {
    const registerProtocolHandler = (this as unknown as {
      registerObsidianProtocolHandler?: (action: string, handler: (params: Record<string, string>) => Promise<void>) => void;
    }).registerObsidianProtocolHandler;
    if (typeof registerProtocolHandler !== "function") return;

    registerProtocolHandler.call(this, "svlt", async (params) => {
      const fullPath = typeof params.file === "string" ? params.file : "";
      const requestedLine = Number.parseInt(typeof params.line === "string" ? params.line : "1", 10);
      if (fullPath.length === 0 || !Number.isFinite(requestedLine) || requestedLine < 1) {
        new Notice("SVLT：本地跳转请求无效。");
        return;
      }

      const adapter = this.app.vault.adapter as unknown as { getFullPath?: (path: string) => string };
      const file = this.app.vault.getMarkdownFiles().find((candidate) => adapter.getFullPath?.(candidate.path) === fullPath);
      if (!file) {
        new Notice("SVLT：请求的文件不在当前库中。");
        return;
      }

      const leaf = this.app.workspace.getLeaf(false);
      await leaf.openFile(file);
      if (leaf.view instanceof MarkdownView) {
        const line = Math.max(0, requestedLine - 1);
        leaf.view.editor.setCursor({ line, ch: 0 });
        leaf.view.editor.scrollIntoView({ from: { line, ch: 0 }, to: { line, ch: 0 } }, true);
      }
    });
  }

  private async refreshStatus(): Promise<void> {
    if (!this.statusBar) return;
    try {
      const response = await this.createVaultClient().request({ type: "workbenchStatus" });
      if (response.type !== "workbenchStatus") throw new Error("UNEXPECTED_RESPONSE");
      const pairing = interpretWorkbenchStatus({ reachable: true, status: response });
      updateStatusBar(this.statusBar, {
        connected: pairing.canOperate && response.status.pluginConnected,
        locked: response.status.locked
      });
    } catch {
      updateStatusBar(this.statusBar, { connected: false, locked: true });
    }
  }

  private async validateManagedCatalog(generation: number): Promise<void> {
    const expectedFile = this.activeCatalogFile;
    const expectedRawSHA256 = this.activeCatalogRawSHA256;

    try {
      const response = await this.createVaultClient().request({ type: "catalogValidate" });
      if (!this.isCurrentCatalogValidation(generation)) return;

      if (response.type !== "catalogValidation") {
        this.publishValidationFailure(response.type === "failure" ? response.code : "UNEXPECTED_RESPONSE");
        return;
      }

      if (!expectedFile || !expectedRawSHA256 || response.rawSHA256 !== expectedRawSHA256) {
        this.publishValidationDocumentMismatch();
        return;
      }

      this.latestValidatedCatalogFile = expectedFile;
      this.latestDiagnostics = response.diagnostics ?? [];
      this.latestValidation = {
        status: response.catalogStatus,
        rawSHA256: response.rawSHA256,
        fingerprint: validationFingerprint(response)
      };
      this.updateDiagnosticStatusBar();

      if (response.catalogStatus === "FOUND") {
        this.lastNoticeFingerprint = undefined;
        return;
      }

      const noticeFingerprint = validationFingerprint(response);
      if (this.lastNoticeFingerprint === noticeFingerprint) return;
      this.lastNoticeFingerprint = noticeFingerprint;
      this.publishDiagnosticsNotice(response);
    } catch {
      if (!this.isCurrentCatalogValidation(generation)) return;
      this.publishValidationFailure("APP_UNAVAILABLE");
    }
  }

  private publishValidationDocumentMismatch(): void {
    const fingerprint = "failure:CATALOG_DOCUMENT_MISMATCH";
    const shouldPublishNotice = this.lastNoticeFingerprint !== fingerprint;
    this.latestValidatedCatalogFile = undefined;
    this.latestValidation = { status: "CATALOG_UNAVAILABLE", fingerprint };
    this.latestDiagnostics = [];
    this.updateDiagnosticStatusBar();
    this.lastNoticeFingerprint = fingerprint;
    if (shouldPublishNotice) {
      new Notice("SVLT：当前文件不是正在校验的目录，已忽略这次校验结果。");
    }
  }

  private publishDiagnosticsNotice(response: ValidationResult): void {
    const diagnostics = response.diagnostics ?? [];
    const first = response.diagnostics?.[0];
    const location = first ? formatDiagnosticLocation(first) : "未提供位置";
    const count = diagnostics.length > 0 ? `${diagnostics.length} 个格式问题` : `目录状态 ${response.catalogStatus}`;
    new Notice(`SVLT：敏感信息目录有 ${count}，第一个位于 ${location}。`);
  }

  private publishValidationFailure(code: string): void {
    const fingerprint = `failure:${code}`;
    const shouldPublishNotice = this.lastNoticeFingerprint !== fingerprint;
    this.latestValidatedCatalogFile = undefined;
    this.latestValidation = { status: "CATALOG_UNAVAILABLE", fingerprint };
    this.latestDiagnostics = [];
    this.updateDiagnosticStatusBar();
    this.lastNoticeFingerprint = fingerprint;

    if (shouldPublishNotice) {
      new Notice(`SVLT：敏感信息目录验证失败（${code}）。`);
    }
  }

  private showCatalogDiagnostics(): void {
    const diagnostics = this.latestDiagnostics;
    if (diagnostics.length === 0) {
      new Notice("SVLT：当前没有目录诊断；可先运行“验证 SVLT 敏感信息目录”。");
      return;
    }

    new CatalogDiagnosticsModal(this.app, diagnostics, (diagnostic) => {
      void this.jumpToDiagnostic(diagnostic);
    }).open();
  }

  private async jumpToDiagnostic(diagnostic: CatalogValidationDiagnostic): Promise<void> {
    const file = this.latestValidatedCatalogFile;
    if (!file) {
      new Notice("SVLT：当前诊断未绑定到已校验的目录文件，请重新验证。");
      return;
    }
    const leaf = this.app.workspace.getLeaf(false);
    await leaf.openFile(file);
    if (leaf.view instanceof MarkdownView) {
      const line = Math.max(0, diagnostic.line - 1);
      leaf.view.editor.setCursor({ line, ch: diagnostic.column != null ? Math.max(0, diagnostic.column - 1) : 0 });
      leaf.view.editor.scrollIntoView(
        { from: { line, ch: 0 }, to: { line, ch: leaf.view.editor.getLine(line).length } },
        true
      );
    }
  }

  private updateDiagnosticStatusBar(): void {
    if (!this.statusBar) return;
    const issueCount = this.latestDiagnostics.length;
    const baseText = (this.statusBar.textContent ?? "").replace(/ · \d+ 个问题$/, "");
    this.statusBar.textContent = issueCount === 0 ? baseText : `${baseText} · ${issueCount} 个问题`;
    this.statusBar.setAttribute(
      "aria-label",
      issueCount === 0 ? "SVLT 目录校验通过或暂无诊断" : `SVLT 目录有 ${issueCount} 条诊断`
    );
  }
}

function formatDiagnosticLocation(diagnostic: CatalogValidationDiagnostic): string {
  const start = `第 ${diagnostic.line} 行${diagnostic.column ? `、第 ${diagnostic.column} 列` : ""}`;
  if (diagnostic.endLine == null) return start;
  const end = `第 ${diagnostic.endLine} 行${diagnostic.endColumn ? `、第 ${diagnostic.endColumn} 列` : ""}`;
  return `${start} 至 ${end}`;
}

function validationFingerprint(response: ValidationResult): string {
  const diagnostics = (response.diagnostics ?? [])
    .map((diagnostic) => [
      diagnostic.id,
      diagnostic.severity,
      diagnostic.code,
      diagnostic.line,
      diagnostic.column ?? "",
      diagnostic.endLine ?? "",
      diagnostic.endColumn ?? "",
      diagnostic.scope,
      diagnostic.message,
      diagnostic.hint ?? ""
    ].join("|"))
    .sort()
    .join(";");
  return [response.catalogStatus, response.rawSHA256 ?? "", diagnostics].join("::");
}

class CatalogDiagnosticsModal extends Modal {
  constructor(
    app: App,
    private readonly diagnostics: CatalogValidationDiagnostic[],
    private readonly jumpHandler: (diagnostic: CatalogValidationDiagnostic) => void
  ) {
    super(app);
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h3", { text: "SVLT 格式检查" });
    const subtitle = contentEl.createDiv({ text: "诊断只包含错误类型和位置，不包含目录正文、路径或敏感引用。" });
    subtitle.addClass("svlt-diagnostics-subtitle");

    const list = contentEl.createDiv({ cls: "svlt-diagnostics-list" });
    for (const diagnostic of this.diagnostics) {
      const row = list.createDiv({ cls: "svlt-diagnostic-row" });
      const severity = row.createSpan({ cls: "svlt-diagnostic-severity" });
      severity.textContent = diagnostic.severity === "error" ? "🔴" : "🟠";
      const location = row.createSpan({ cls: "svlt-diagnostic-location" });
      location.textContent = formatDiagnosticLocation(diagnostic);
      const code = row.createSpan({ cls: "svlt-diagnostic-code" });
      code.textContent = diagnostic.code;
      const message = row.createSpan({ cls: "svlt-diagnostic-message" });
      message.textContent = diagnostic.message;
      if (diagnostic.hint) {
        const hint = row.createDiv({ cls: "svlt-diagnostic-hint" });
        hint.textContent = `建议：${diagnostic.hint}`;
      }
      const jump = row.createEl("button", { text: "跳转" });
      jump.addClass("svlt-diagnostic-jump");
      jump.addEventListener("click", () => this.jumpHandler(diagnostic));
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}