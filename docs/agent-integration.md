# Agent Integration

SVLT 面向 Codex、Claude、Hermes 和其他 MCP-capable agents。

核心规则：SVLT 管理的秘密在聊天里只保留 `secret://...` 引用。SVLT 是 opt-in，不接管用户明确选择的其他 provider 或当前明文。

日常使用只在用户选择 SVLT 或出现 `secret://...` 时触发。仅出现 password、token、API key 或需要登录、SSH、HTTP 时不会自动接管；如果用户亲自提供明文并明确要求本次使用，必须尊重选择，不得强制转换。

## MCP server

普通用户安装 release 包后，MCP server 固定安装在：

```text
~/Library/Application Support/AgentSecretVault/MCP/dist/server.js
```

安装脚本会生成完整 MCP 配置：

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

在任何 MCP-capable agent 中使用类似配置：

```json
{
  "mcpServers": {
    "SVLT": {
      "command": "/bin/zsh",
      "args": [
        "-lc",
        "exec node \"$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js\""
      ]
    }
  }
}
```

Codex、Claude、Hermes 的 MCP 配置位置可能不同；稳定部分是都启动同一个本机 MCP server。

## Agent 必须遵守

看到 `secret://...` 或用户明确选择 SVLT 时：

1. 把引用当作不透明句柄，不从密文推断隐藏值。
2. Agent 不主动索要明文；用户主动提供并明确要求当前使用时，不得把它改写成 SVLT 引用。
3. 不把解密明文、Authorization header、cookie、session key、填充后的敏感文件内容返回聊天。
4. 文本/段落/工具输出中含引用时，默认先调用 `secret_auto_handle_text`；若任务已经明确是本地动作，则直接用 `secret_action_router` 或更具体的安全工具。用户选了其他来源时不要调用来替换来源。
5. 用户需要亲自查看明文时，用 `secret_reveal_request` 或 `paragraph_reveal_request` 让本地 app 展示；聊天里只报告 `DISPLAYED_TO_USER`。
6. 只用 `secret_inspect_reference` 查看非敏感元数据。
7. 需要为已有 `secret://` 增加精确服务目标和协议时，使用 `secret_bind_destination`；协议、目标、可选 port 和 SSH host-key pin 会作为经过认证的原子 profile 保存，不会由两个独立数组产生交叉授权。它会在 App 中显示本次绑定并要求每次重新进行 device-owner authentication，成功时返回 daemon 的 canonical 非敏感元数据，不返回明文，也不建立执行窗口。需要更高保证的 SSH/SFTP/SCP 流程先调用 `secret_review_ssh_host_key`，再提交设备所有者选定的 algorithm、SHA256 fingerprint 和显式 port；省略 pin 字段则保留兼容/TOFU 路径。
8. 任务提到服务、设备、主机、账号或用途但没有凭据来源时，可以用 `secret_search` 发现 Entry-centric opaque 引用；用户已明确选择 plaintext 或外部 provider 时不要搜索并替换来源。
9. 没有 SVLT 安全工具时，只对明确的 SVLT managed 操作停止并请求新增 allowlisted 工具；不得把 SVLT 派生明文降级到通用命令，也不得因 SVLT 缺失阻断用户已明确选择的外部工具/当前明文。

来源优先级（每个 operation 独立计算）：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 无指定时才自动发现。`USER_EXPLICIT_PLAINTEXT` 不要求 SVLT lookup、comparison、replacement、import 或 authorization；当前用户选择覆盖上一轮的 SVLT/provider 选择，不继承为 sticky state。

## Catalog 浏览与结构创建

Catalog 的浏览和结构写入应通过 MCP API 完成。下面的
`secret_catalog_list_indices`、`secret_catalog_list_entries` 和
`secret_catalog_create_structure` 是当前调用流；实际能力仍以当前 MCP server 的
`tools/list` 为准，不要用读取本地文件来补足未暴露的工具。

1. 浏览分组时调用 `secret_catalog_list_indices`。结果应返回每个 Index 的 opaque
   `id`、标题、aliases、tags 和 `entryCount`，并且必须包含 `entryCount: 0` 的空分组。
2. 浏览指定分组时调用 `secret_catalog_list_entries(indexID)`，使用 MCP 返回的
   `indexID` 获取 Entry ID 和可见 metadata；必要时再用
   `secret_catalog_get(entryID)` 获取单个 Entry。`secret_search` /
   `secret_catalog_search` 用于按查询发现凭据或 Entry，不用 `query: ""` 冒充 list。
3. 创建一组结构时，目标工具 `secret_catalog_create_structure` 接收一个 Index 和多个
   Entry 的普通 metadata、endpoint、字段及空 `secret` placeholder。由 SVLT 生成所有
   opaque ID，以 `clientKey` 对应返回的 `indexID`/`entryID`，作为一次 semantic mutation
   和 atomic commit；绑定已有 `secret://`、替换或删除已有引用仍按单独的高风险流程处理。
4. 目标写入响应应同时返回新对象 ID、`revision` 和 post-commit validation 摘要，例如：

   ```json
   {
     "status": "CREATED",
     "indexID": "12QA95B9PFK0NF5RXT8XDRNYQK",
     "revision": 47,
     "validation": {
       "status": "FOUND",
       "diagnostics": []
     }
   }
   ```

   如果兼容的低层 `secret_catalog_create_index` / `secret_catalog_create_entry`
   在某个版本中仍未返回新对象 ID，Agent 不得猜测、拼接，或从其他文件回读 ID；应报告
   API 缺口，或使用已暴露且能完整返回 ID 的结构创建调用流。
   `CREATED` 表示 semantic commit 已提交；只有 `validation.status == FOUND` 且
   `validation.diagnostics` 为空，才表示提交后的健康确认成功。如果返回
   `CREATED` 但 validation 是 `CATALOG_UNAVAILABLE` 等状态，说明写入可能已经成功，
   只是健康确认未完成；不要盲目重复写入，服务恢复后用 `secret_catalog_validate` 显式确认。
5. 每一笔 Agent Catalog mutation（包括 create、update、delete 和 batch）都必须先由
   Agent 发起精确绑定、一次消费的 operation-bound write authorization；Agent 不能自行
   开启、扩大或复用授权。只读的 list/get 不属于 mutation；绑定、替换或删除已有
   `secret://` 仍需单独的高风险批准。
   SVLT 会直接唤起 macOS device-owner authentication；认证成功就是这一笔 mutation 的
   用户授权。没有额外的 App“验证并授权”按钮。取消、失败或超时都不会执行写入。
   Agent 需要用户提供真实凭据时调用 `secret_catalog_request_secure_inputs`；只发送
   `entryID`、field key、模式和 revision，不发送或覆盖字段 label。SVLT 从 accepted
   Catalog 重建 label，立即返回 `PENDING` 与 `requestID`；随后用
   `secret_catalog_secure_input_status` 轮询终态。`fillPlaceholder`、`replaceSecret`
   和 `convertToSecret` 都由用户在本机 SecureField sheet 中最终选择/输入；SVLT 本机
   加密后在 daemon 单入口事务中完成 final semantic diff、策略检查和 atomic commit，
   Agent 只收到状态、revision 或稳定 errorCode，永远收不到明文。若轮询返回
   `UNKNOWN`，先重新读取 Catalog/revision 做结果对账，禁止自动重新提交明文。替换已有密文仍按
   高风险 semantic diff 走同一笔本机认证，不会被普通 metadata 静默化；请求过期、
   取消、失焦、睡眠或锁定都不会提交。

## Markdown 布局与最小修改

SVLT 自己生成或受控插入的 `敏感信息.md` 结构遵循“前言区 → 连续 Catalog 主体 →
尾部非托管区”。Note、说明、callout、用户段落、备注和 WikiLink 不属于 Catalog semantic
model，也不影响 Index/Entry 搜索、计数或 App UI；已有未知用户 Markdown 即使位于两个
Index 之间也保持原位。存在 Index 时，新 Index 插入最后一个合法 `SVLT-INDEX` 之后、
尾部非托管 Markdown 之前；没有 Index 时插入前言之后，不得 append 到文件绝对末尾。

新生成 Index 之间使用 renderer 生成的 `\n\n---\n\n`；已有 `---` 没有 provenance 时按
用户内容保留，不猜测或全局重写用户分隔线。同一 Index 内 Entry 之间使用统一双空行视觉
间距。App、MCP、Obsidian、编辑器和脚本都可以写合法 v3 Markdown，但受控写入优先
source-range minimal patch，只调整目标块和新写入时由 renderer 明确生成的边界空白，保留
用户内容；format repair 不为追求连续主体而移动无法明确识别来源的 Note、Markdown、
WikiLink 或用户 HR。

Agent 不得读取 `sensitive-index-selection.json`、Catalog Markdown（例如
`敏感信息.md`）或 `Application Support` 中的 integrity/selection sidecar 来查找或验证
Index/Entry ID。它们是本地存储实现细节，不是 Agent 的发现 API；ID 必须来自 MCP 的
list/get/create 响应。

## 工具选择规则

优先使用 `secret_action_router` 或能完成整个动作的具体安全工具：

| 场景 | 首选工具 | 规则 |
| --- | --- | --- |
| 普通文本/笔记片段含 `secret://` | `secret_auto_handle_text` | 检测、脱敏或打开本地 reveal；不返回明文。 |
| 本地网页登录 | `secret_action_router` 的 `browser_web_login`，或 `browser_web_login_with_secret` | 只允许本地/内网 URL；selector 必须明确；不能安全定位就返回状态。 |
| 本地 App 表单 | `secret_action_router` 的 `local_app_form_fill`，或 `local_app_form_fill_with_secret` | 字段必须明确；不用剪贴板；不返回填充值。 |
| SSH 到本机/内网设备 | `secret_action_router` 的 `ssh_command`，或 `ssh_command_with_secret` | 只允许本地/内网主机；普通任务对齐效果（包括只读和有限可恢复写入）自动执行，危险效果按策略处理；密码用 `passwordRef`。 |
| 本地/内网 HTTP(S) | `secret_action_router` 的 `local_http_request`，或 `local_http_request_with_secret` | 只允许 localhost、`.local`、私有 IP；GET/HEAD/POST/PUT/PATCH 等按实际效果判断，输出脱敏。 |
| API token 请求 | `secret_action_router` 的 `api_request`，或 `api_request_with_token` | token 只走 `tokenRef`；拒绝 URL token 参数；redirect manual；输出脱敏。 |
| 数据库操作 | `secret_action_router` 的 `database_query`，或 `database_query_with_secret` | 只允许本地/内网 host 和单条 SQL；普通 bounded CRUD 自动执行，结构/权限/无界破坏按策略处理；先校验再解密。 |
| SFTP/SCP | `secret_action_router` 的 `sftp_transfer`，或 `sftp_transfer_with_secret` | 只允许本地/内网 host；`username`/`usernameRef` 二选一；先校验 operation 和路径；输出脱敏。 |
| 私有/回环 FTP | `secret_action_router` 的 `ftp_transfer`，或 `ftp_transfer_with_secret` | 明文协议；只允许私有/回环 host；`username`/`usernameRef` 二选一；每次需要重新认证；输出脱敏。 |
| 本地文件导出 | `secret_action_router` 的 `export_resolved_text`，或 `export_resolved_text_to_local_file` | 用户明确要求导出时使用；只返回状态和路径。 |
| 用户本地查看明文 | `secret_reveal_request` / `paragraph_reveal_request` | 明文显示在本地 app，不进入聊天。 |
| 元数据检查 | `secret_inspect_reference` | 只返回 reference、policy、label、时间等非敏感字段。 |
| SSH/SFTP/SCP 主机指纹发现 | `secret_review_ssh_host_key` | 传入 host+port；只返回当前展示的算法和 SHA256 fingerprint，不读取 Secret，也不把发现结果当作带外身份保证。 |
| 为已有 Secret 绑定服务目标 | `secret_bind_destination` | 传入已有 `secret://`、精确目标和协议；普通调用保留 TOFU 兼容性，显式 SSH pin 还必须传 port、algorithm 和 SHA256 fingerprint；每次需要 device-owner authentication，重新封装绑定元数据，不返回明文。 |
| 服务/设备/主机发现 | `secret_search` / `secret_catalog_search` | 按 Index、Entry、alias、tag、NAS、endpoint 或允许搜索的字段查询；只返回 Entry-centric opaque 引用和非敏感 catalog metadata，不承担空 Index 浏览。 |
| Catalog 分组浏览 | `secret_catalog_list_indices` | 列出全部 Index，包含空分组；以运行时 MCP 工具目录为准。 |
| 指定分组条目浏览 | `secret_catalog_list_entries` | 传入 MCP 返回的 `indexID` 列出 Entry；不读取本地 Markdown 或 sidecar。 |
| Catalog 结构创建 | `secret_catalog_create_structure` | 一次创建一个 Index 和多个 Entry，由 SVLT 生成 opaque ID，并返回 post-commit validation。 |
| 创建引用 | `secret_create_request` | 从本地 app 选择/输入生成 `secret://`。 |

`secret_action_router` 支持的 intent：

- `ssh_command`
- `local_http_request`
- `api_request`
- `database_query`
- `sftp_transfer`
- `ftp_transfer`
- `browser_web_login`
- `local_app_form_fill`
- `export_resolved_text`

## Tools

| Tool | Use |
| --- | --- |
| `agent_secret_usage_policy` | Returns the non-sensitive operating rules for Codex, Claude, Hermes, or another MCP-capable agent. |
| `secret_action_router` | Routes `secret://` references to allowlisted SSH, HTTP/API, database, SFTP/SCP/FTP, browser/app fill, or local file export. Plaintext is never returned. |
| `secret_auto_handle_text` | First-choice automatic handler for paragraphs or note excerpts containing `secret://`; detects references, redacts text, or opens a local app reveal. |
| `vault_status` | Checks whether the local channel and operation policy engine are ready; `locked` is compatibility-only. |
| `secret_inspect_reference` | Returns metadata only: reference, policy, label, timestamps. |
| `secret_review_ssh_host_key` | Discovers the current SSH/SFTP/SCP host-key algorithms and SHA256 fingerprints for one host/port without reading a Secret; discovery is not an identity guarantee. |
| `secret_bind_destination` | Adds one exact service destination/protocol profile to an existing `secret://` record after fresh device-owner approval; optional explicit SSH pinning requires the selected fingerprint and port, and the record is re-sealed without returning plaintext. |
| `secret_search` / `secret_catalog_search` | Finds Entry-centric opaque references by Index, Entry, alias, tag, endpoint, or searchable metadata without exposing catalog paths or plaintext. |
| `secret_create_request` | Asks the app to encrypt selected local text and return a `secret://` reference. |
| `secret_reveal_request` | Asks the app to display one secret locally to the user. |
| `paragraph_reveal_request` | Asks the app to display a paragraph locally with all referenced secrets filled in. |
| `export_resolved_text_to_local_file` | Resolves references inside the app and writes the filled text to an allowed local file; returns only status/path. |
| `ssh_command_with_secret` | Resolves a password reference internally for restricted local/private-network SSH; returns sanitized stdout/stderr. |
| `local_http_request_with_secret` | Resolves `secret://` credentials internally for a policy-reviewed HTTP(S) request; Secret use alone does not require approval, while destructive, insecure, credential-exposing, or unresolved effects require fresh handling. Plaintext HTTP additionally needs an exact saved origin profile. |
| `api_request_with_token` | Resolves a token reference internally for a policy-reviewed API request; ordinary task-aligned HTTPS is automatic, while destructive/insecure/exposing effects use fresh handling, and results are redacted. |
| `database_query_with_secret` | Resolves database credentials internally for one policy-reviewed statement; reads and bounded CRUD may be automatic, while destructive/privilege/unresolved effects use fresh handling. |
| `sftp_transfer_with_secret` | Resolves transfer credentials internally for policy-reviewed SFTP/SCP list/read/download/upload and bounded writes; destructive or unresolved effects use fresh handling. |
| `ftp_transfer_with_secret` | Resolves transfer credentials internally for private/loopback plaintext FTP; every request requires fresh owner authentication. |
| `browser_web_login_with_secret` | Resolves login credentials internally for a specific local/private browser form fill. |
| `local_app_form_fill_with_secret` | Resolves field values internally for a specific macOS app form fill. |

## 失败处理

- `vault_status` 显示本机通道不可达：让用户打开 SVLT 一次以完成 SMAppService 注册/批准；普通后台 Agent 不要求 App 一直运行。
- `vault_status` 的 `locked` 字段为兼容信息：不要要求用户预先打开 GUI 解锁；直接提交具体操作，由本地策略判断静默、审批或拒绝。
- 返回 `URL_NOT_ALLOWED`、`HOST_NOT_ALLOWED`、`COMMAND_NOT_ALLOWED`：说明目标或动作超出 allowlist；请用户确认目标，或新增更窄的安全工具。
- 返回 `QUERY_NOT_ALLOWED`、`PATH_NOT_ALLOWED`、`URL_TOKEN_NOT_ALLOWED`：说明 SQL、路径或旧工具的 URL 形态不安全；修正非敏感参数后重试，不要索要明文。HTTP Secret 工具对 credential-shaped query 会走 fresh owner approval。
- 返回 `SAFE_AUTOFILL_UNAVAILABLE`、`DATABASE_RUNNER_UNAVAILABLE`、`FILE_TRANSFER_RUNNER_UNAVAILABLE`：说明 SVLT managed 路径的本地 runner 尚不可用；不要把 SVLT 派生明文交给普通工具。用户已选择其他工具时由该工具规则处理。
- 返回 `BASIC_AUTH_REQUIRES_USERNAME_AND_PASSWORD`：要求补充缺失的用户名引用或非敏感用户名；不要要求密码明文。
- 返回 `REQUEST_FAILED`、`SSH_REQUEST_FAILED`：报告失败状态和非敏感上下文，可建议检查网络/服务状态。
- 返回 `SELECTION_ENCRYPT_UNAVAILABLE`：说明当前 SVLT 加密桥接能力不可用；不要强迫用户把本次明文导入 SVLT，也不要把 SVLT 派生明文交给普通工具。
- 返回 `QUARANTINED`：只报告隔离原因，不展示被隔离输出。
- 目标 Catalog 浏览或结构创建工具未出现在当前 MCP 工具目录：说明目标调用流尚未在该版本暴露；不要读取 selection JSON、Catalog Markdown 或 Application Support sidecar 来猜测 ID，也不要自行伪造 opaque ID。
- 受控 MCP Catalog write 的结果应带 post-commit validation 摘要；只有 `status == FOUND` 且 diagnostics 为空才表示健康确认完成。若返回 `CATALOG_UNAVAILABLE` 等状态，写入可能已经提交但确认未完成，不要盲目重复写入；服务恢复后只调用 `secret_catalog_validate`，不要改读本地 sidecar。
- 没有匹配工具：明确选择 SVLT 时请求新增 allowlisted MCP 工具；明确选择其他 provider 或当前明文时不由 SVLT 阻断，遵守该工具和工作区规则。

## 可选兜底提示

仅在客户端无法自动加载 skill 时使用：

```text
看到 secret:// 或用户明确选择 SVLT 时，使用 svlt 的 secret_action_router 或具体安全工具；用户明确选择当前明文或其他 provider 时不要自动改用 SVLT，不要把 SVLT 解密明文返回聊天。
```

## 本地预期

- SVLT.app 已安装；首次启动完成 SMAppService Agent 注册并在系统设置中批准（如 macOS 要求）。
- SVLTAgent 可在 SVLT.app 退出后继续运行；只有需要本机窗口的 reveal 才会按需激活 App。
- MCP server 已安装到 `~/Library/Application Support/AgentSecretVault/MCP`。
- agent 的 MCP entry 指向安装后的 `MCP/dist/server.js`。
- 现有笔记和任务中的敏感值以 `secret://...` 保存，不保存明文。
