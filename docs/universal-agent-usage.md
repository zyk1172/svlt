# SVLT 通用 Agent 使用文档

本文面向 Codex、Claude、Hermes 以及其他支持 MCP 的本地或桌面 Agent。SVLT 是 opt-in：目标是让 Agent 在用户选择 SVLT 管理的秘密时使用 `secret://...` 密文引用，而不是接触这些秘密的明文；SVLT 不接管所有可用凭据。

## 1. Agent 必须理解的边界

SVLT 管理路径的正确使用方式是：

1. SVLT 管理的聊天、笔记、任务描述里只保留 `secret://...`。
2. Agent 不主动索要明文；如果用户亲自提供明文并明确要求本次使用，必须尊重这一选择，不得强制导入 SVLT。
3. Agent 不把解密后的密码、token、Authorization header、cookie、session key、填充后的敏感字段返回聊天。
4. 用户明确选择 SVLT 时，Agent 调用 SVLT MCP 工具；用户明确选择其他 provider 或当前明文时，调用用户选定的工具。
5. 明文只短暂存在于本机 macOS App、MCP server 内部或专用本地 runner 中。

Agent 不应该把 `secret://...` 当成可读信息。它只是一个不透明引用。SVLT 不比较用户独立提供的明文与引用背后的值。

来源优先级（每个 operation 独立计算）：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 没有指定时才自动发现。上一轮的 provider 选择不是永久状态；仅仅出现 password、token、API key 等词不会自动激活 SVLT。

## 2. 普通用户本机安装

普通用户不需要 Xcode，也不需要打开项目源码。

安装方式：

1. 解压 `SVLT-release.zip`。
2. 双击里面的 `install.command`。如果 macOS 拦截，右键点它再选“打开”。终端用户可以运行 `install.sh`。
3. 安装脚本会打开 SVLT。
4. 安装脚本会生成 MCP 配置文件。

安装后的固定位置：

- App：`/Applications/SVLT.app` 或 `~/Applications/SVLT.app`
- MCP server：`~/Library/Application Support/AgentSecretVault/MCP`
- MCP 配置：`~/Library/Application Support/AgentSecretVault/svlt.mcp.json`

普通用户只需要安装 Node.js 24 或更新版本，用来运行 MCP server。不需要安装 Xcode。

## 3. 通用 MCP 配置

安装完成后，打开这个文件：

```text
~/Library/Application Support/AgentSecretVault/svlt.mcp.json
```

它的内容类似：

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

如果客户端是表单配置：

- Name：`svlt`
- Command：`/bin/zsh`
- Args 第一项：`-lc`
- Args 第二项：`exec node "$HOME/Library/Application Support/AgentSecretVault/MCP/dist/server.js"`
- Transport：`stdio`

配置完成后重启或刷新 Agent 客户端。

## 4. Codex 安装方式

### 4.1 安装 Codex skill

如果用户拿到的是 release 包，不需要这一步；直接把第 3 节 MCP 配置粘贴到 Codex 即可。

如果用户是从源码仓库安装 Codex skill：

```bash
./scripts/install-codex-skill.sh
```

然后重启 Codex 或刷新 skills。

### 4.2 使用项目内 Codex plugin

项目内插件目录：

```text
plugins/svlt
```

插件包含：

- `.codex-plugin/plugin.json`
- `.mcp.json`
- `skills/svlt/SKILL.md`
- `hooks/validate_secret_output.js`

如果 Codex 支持从本地目录加载插件，选择上述目录。加载后，Codex 应能看到：

- MCP server：`svlt`
- Skill：`svlt`
- Hook：`validate-secret-output`

## 5. Claude / Hermes / 其他 Agent 安装方式

Claude、Hermes 或其他客户端通常没有 Codex skill 格式。做法是：

1. 安装 MCP server，使用第 3 节的 MCP 配置。
2. 把第 6 节的“敏感信息使用策略”加入该客户端的系统提示、项目规则、profile instruction 或 workspace instruction。
3. 重启客户端。
4. 让 Agent 先调用 `vault_status`，再调用 `agent_secret_usage_policy`。

## 6. Agent 敏感信息使用策略

这是连接 MCP 后的必做步骤。将 [SVLT 敏感信息使用策略](svlt-agent-policy-zh-CN.md) 中的代码块原样交给任何 Agent。

策略要求 Agent：

1. 将 App 选定或已识别的 v3 `敏感信息.md` 视为 SVLT managed catalog；`##` 是分组，`###` 是条目，marker/schema 携带稳定 ID。
2. 普通字段保留为 Markdown；密码字段只能是空 placeholder 或合法 `secret://`，绝不写入秘密明文。
3. 可以使用 App、MCP、Obsidian、编辑器或脚本修改；无论渠道如何，都必须输出符合 v3 的结构。
4. 修改时只改变目标 source range，保留用户原有 Markdown、双链、备注、空行和非目标区域；不要整文件 canonicalize。
5. 不得把 policy block 当作分组、条目、字段、搜索结果或计数，也不得创建同名“SVLT 管理规范”记录。
6. 先判断用户是否选择 SVLT；当前明确提供的明文或明确选择的外部 provider 不需要 SVLT lookup、比较或替换。`locked` 不是全局门禁。
7. 任务提到服务、设备、主机、账号或用途但没有凭据来源时，可以用 `secret_search` / `secret_catalog_search` 按非敏感上下文发现 opaque 引用；需要浏览分组时使用 `secret_catalog_list_indices`（包含空分组），再用 MCP 返回的 `indexID` 调用 `secret_catalog_list_entries`，不得用 `query: ""` 或本地文件猜测 ID；不同 Entry 不得合并。
8. 需要一次建立目录结构时，使用 `secret_catalog_create_structure` 提交一个 Index 和多个安全 Entry；SVLT 生成 opaque ID，以 `clientKey` 返回映射，并在一次 operation-bound 授权和 atomic commit 中完成。Agent 不得提交自造 ID、已有 `secretRef` 或 secret plaintext。
9. 新增分组/条目/字段、普通 metadata 和空 password placeholder 可以不触发额外的高风险 secretRef 批准；但每笔 Agent mutation（包括普通批量操作）仍必须使用精确绑定、一次消费的 operation-bound write request。SVLT 直接弹 macOS device-owner authentication；认证本身是授权，没有额外 App 确认按钮。绑定、替换、删除已有 `secretRef`，改变秘密目标或删除含引用的对象必须本机审批。若只是给已有 `secret://` 增加精确服务地址/协议，使用 `secret_bind_destination`；协议和目标会作为一个原子 profile 重新封装并认证，每次都重新认证，成功返回 canonical 非敏感元数据，不返回明文，也不产生可复用的执行窗口。需要更高保证的 SSH/SFTP/SCP 先用 `secret_review_ssh_host_key` 查看 host/port 的算法和 SHA256 fingerprint，再把设备所有者选定的 fingerprint、algorithm 和显式 port 提交给绑定工具；省略 pin 字段则继续兼容/TOFU 模式。
10. 受控 MCP write 会返回 post-commit validation；只有 `validation.status == FOUND` 且 `validation.diagnostics` 为空才表示健康确认成功。`CREATED` 搭配 `CATALOG_UNAVAILABLE` 等状态表示写入可能已提交但确认未完成，不要盲目重试写入，服务恢复后再用 `secret_catalog_validate` 显式确认。失败时停止，不要猜测修复结构。
11. 低风险操作不代表获得明文导出权限；SVLT 派生明文只能留在获批的专用本地操作中，不能写回 Catalog、shell、日志、聊天或外发。
12. 需要真实密码、API 密钥或 token 时调用 `secret_catalog_request_secure_inputs`；只发送 `entryID`、field key、模式和 revision，不发送或覆盖字段 label。SVLT 会从 accepted Catalog 重建 label，并立即返回 `PENDING` 与 `requestID`。用户在本机 SecureField 中选择/输入后，Agent 只能轮询 `secret_catalog_secure_input_status` 获取 `COMPLETED`、`CANCELLED`、`EXPIRED` 或 `FAILED`（以及 revision/errorCode）；永远收不到明文。请求过期、取消或 App 失焦/睡眠/锁定时不会提交。若返回 `UNKNOWN`，先重新读取 Catalog/revision 做结果对账，禁止自动重新提交明文。

13. SVLT 自己生成或受控插入的 `敏感信息.md` 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局。Note、说明、callout、普通段落、备注和 `[[WikiLink]]` 都是 unmanaged，不属于 Catalog semantic model；已有未知用户 Markdown 即使位于两个 Index 之间也保持原位。存在 Index 时，新 Index 插入最后一个合法 `SVLT-INDEX` 后、尾部非托管 Markdown 前；没有 Index 时插入前言后，不得简单 append 到文件末尾。
14. 新生成 Index 之间使用 renderer 的 `\n\n---\n\n`；已有 `---` 没有 provenance 时按用户内容保留，不猜测或全局重写。同一 Index 内 Entry 使用统一双空行视觉间距。所有合法 writer（App、MCP、Obsidian、编辑器、脚本）都必须遵守 v3 marker/schema，受控写入优先 minimal patch 并保留用户 Markdown。format repair 不为追求连续主体而移动无法确认来源的用户 Note/Markdown/WikiLink，也不删除用户 HR。Agent 不得读取 selection JSON、Catalog Markdown 或 Application Support sidecar 猜测 opaque ID，也不得读取本地 `sensitive-index-selection.json`、integrity sidecar 或其他 Application Support 文件解析 ID。

## 7. Agent 启动自检

Agent 接入后先做：

1. 调用 `vault_status`
2. 调用 `agent_secret_usage_policy`

预期：

- `vault_status` 返回 `available`、`ready` 和 `approvalPending`；`locked` 仅为兼容字段。
- `agent_secret_usage_policy` 返回可用工具和安全规则。

普通操作不要求 SVLT.app 一直运行。若通道不可达，先打开一次 SVLT 完成 SMAppService 注册/批准；如果状态中的 `locked` 为 true，仍应直接提交具体操作，让 Agent 本地策略决定是否需要认证。

## 8. 工具选择规则

| 场景 | 工具 | Agent 输入秘密的方式 |
| --- | --- | --- |
| 文本、笔记片段或工具输出里有 `secret://` | `secret_auto_handle_text` | 原文中保留引用 |
| 查看单个秘密给用户本人 | `secret_reveal_request` | `reference` |
| SSH/SFTP/SCP 主机指纹发现 | `secret_review_ssh_host_key` | `host` + `port`；只返回当前展示的算法和 SHA256 fingerprint，不读取 Secret。 |
| 为已有 Secret 绑定服务目标 | `secret_bind_destination` | `reference` + 精确 `destination` + `protocol`；显式 pin 还需 `port`、`hostKeyAlgorithm`、`hostKeySHA256`；作为原子 profile 保存，每次 fresh device-owner authentication，不返回 plaintext。 |
| 本地显示整段解密文本 | `paragraph_reveal_request` | `references` + `template` |
| 导出填充后的敏感文本到本地文件 | `export_resolved_text_to_local_file` | `references` + `template` + `destinationPath` |
| SSH 到本机或内网设备 | `ssh_command_with_secret` | `passwordRef`，可选非敏感 `username`；普通任务对齐效果自动执行，危险效果按实际影响处理 |
| 本地/内网 HTTP Basic Auth | `local_http_request_with_secret` | `passwordRef`，可选 `usernameRef` |
| API token 请求 | `api_request_with_token` | `tokenRef` |
| 数据库操作 | `database_query_with_secret` | `passwordRef`，可选 `usernameRef`；普通读取和 bounded CRUD 可自动执行 |
| SFTP/SCP | `sftp_transfer_with_secret` | `passwordRef` + `username` 或 `usernameRef`（二选一） |
| 私有/回环 FTP | `ftp_transfer_with_secret` | `passwordRef` + `username` 或 `usernameRef`（二选一）；每次重新认证 |
| 本地/内网页登录填充 | `browser_web_login_with_secret` | `passwordRef`，可选 `usernameRef` |
| 本地 App 表单填充 | `local_app_form_fill_with_secret` | 字段 `valueRef` |
| 自动路由本机动作 | `secret_action_router` | 按 intent 传引用 |

## 9. `secret_action_router` intent

`secret_action_router` 支持：

- `ssh_command`
- `local_http_request`
- `api_request`
- `database_query`
- `sftp_transfer`
- `ftp_transfer`
- `browser_web_login`
- `local_app_form_fill`
- `export_resolved_text`

Agent 不确定用哪个具体工具时，优先使用 router；已经明确场景时，直接使用具体工具。

## 10. 常用输入示例

下面的 JSON 只展示工具输入的字段形状，不能整段直接执行。发送前必须先
通过 SVLT MCP 的搜索/list 响应取得同一 Catalog 中已经存在的 opaque
`secret://` 引用，并把示例中的占位符替换掉；不要手造引用，也不要把
示例主机、路径当成你的 allowlist。替换完成后才会通过输入 schema，也不会把一个
不存在的测试引用误当成真实凭据。

### 10.1 SSH

```json
{
  "host": "192.168.2.240",
  "username": "zyk",
  "passwordRef": "<existing secret:// reference returned by SVLT>",
  "command": "hostname",
  "risk": "read"
}
```

### 10.2 API token

```json
{
  "url": "http://192.168.2.240:8080/api/status",
  "tokenRef": "<existing secret:// reference returned by SVLT>",
  "includeBodyPreview": true
}
```

不要把 SVLT 派生 token 放进 URL query、header 字符串或聊天；如果目标协议确实要求 credential-shaped query，使用 HTTP Secret 工具让本地 policy 触发 fresh owner approval，不要把 Secret 明文拼入 URL。

### 10.3 数据库操作

```json
{
  "engine": "postgres",
  "host": "192.168.2.240",
  "database": "app",
  "username": "readonly_user",
  "passwordRef": "<existing secret:// reference returned by SVLT>",
  "query": "select current_user",
  "maxRows": 20
}
```

只提交一条 SQL。普通任务对齐、范围有限且可恢复的 CRUD 可以自动执行；DROP、TRUNCATE、破坏性结构/权限变化、动态外部文件边界或无法确定实际效果的语句会进入严格 fresh/deny 边界。不要为了避免审批把语句伪装成查询或交给通用 shell。

### 10.4 SFTP list

```json
{
  "operation": "list",
  "host": "192.168.2.240",
  "username": "zyk",
  "passwordRef": "<existing secret:// reference returned by SVLT>",
  "remotePath": "/share"
}
```

路径必须明确，不能使用 `..`、glob 或 shell 字符。

### 10.5 FTP list

```json
{
  "operation": "list",
  "host": "192.168.2.240",
  "username": "zyk",
  "passwordRef": "<existing secret:// reference returned by SVLT>",
  "remotePath": "/share"
}
```

FTP 仅允许回环或私有目标，并且每次请求都需要设备所有者重新认证；本地文件路径仅允许 SVLT Downloads 目录。

### 10.6 本地网页登录填充

```json
{
  "url": "http://192.168.2.240/login",
  "username": "zyk",
  "passwordRef": "<existing secret:// reference returned by SVLT>",
  "usernameSelector": "#user",
  "passwordSelector": "#password",
  "submitSelector": "button[type=submit]",
  "submit": false
}
```

如果返回 `SAFE_AUTOFILL_UNAVAILABLE`，说明 SVLT managed 路径当前没有安全浏览器 runner。不要把 SVLT 派生明文降级到普通工具或剪贴板；用户已经明确选择其他工具或当前明文时，由该工具和工作区规则处理。

## 11. 失败处理

| 状态 | Agent 应该怎么做 |
| --- | --- |
| `APP_UNAVAILABLE` | 让用户打开一次 SVLT 完成后台服务注册/批准后重试；不要要求 GUI 一直保持打开。 |
| `URL_NOT_ALLOWED` / `HOST_NOT_ALLOWED` | 目标不是 localhost、`.local`、私有 IP 或显式 allowlist。请用户确认目标。 |
| `URL_CREDENTIALS_NOT_ALLOWED` | URL 里包含用户名或密码。改用 `usernameRef` / `passwordRef`。 |
| `URL_TOKEN_NOT_ALLOWED` | 其他旧工具拒绝 URL query 中的 token/key/password 参数；HTTP Secret 工具会把这类 query 交给本地 fresh owner approval。优先使用 `tokenRef`，不要把 Secret 明文拼进 URL。 |
| `COMMAND_NOT_ALLOWED` | SSH 命令格式、目标或执行器边界不满足要求。修正非敏感参数；不要为了规避策略改写 destructive 意图。 |
| `QUERY_NOT_ALLOWED` | SQL 不是一条可由当前 adapter 接受的语句，或超出其参数/协议边界。修正语句；不要把 Secret 明文交给 shell client。 |
| `PATH_NOT_ALLOWED` | SFTP/SCP/FTP 路径不安全。改成确定路径。 |
| `SAFE_AUTOFILL_UNAVAILABLE` | SVLT 管理路径的浏览器或本地 App 安全填充 runner 尚不可用；不要把 SVLT 派生明文降级到普通工具。用户已明确选择其他工具或当前明文时，由该工具自己的规则处理。 |
| `*_REQUEST_FAILED` | 报告非敏感失败状态，建议检查服务、网络、权限或 App 状态。 |

## 12. 验证安装是否成功

在 Agent 中发起：

```text
请调用 svlt 的 vault_status，并读取 agent_secret_usage_policy。
```

通过标准：

- Agent 不要求你粘贴密码。
- Agent 能看到 MCP 工具列表。
- Agent 能复述“secret:// 是不透明引用”。
- Agent 不返回任何明文秘密。

## 13. 安全注意事项

- 不要把 `secret://` 对应的明文写入知识库、issue、PR、聊天记录或日志。
- 不要把 bearer token、basic auth、cookie、session id 打印到工具结果。
- 不要把数据库敏感列返回聊天。
- 不要使用通用 shell、curl、剪贴板或浏览器自动填表绕过 MCP 安全工具。
- 对网络发送使用 `local_http_request_with_secret` 或 `api_request_with_token` 的 typed policy-reviewed 路径；普通任务对齐 HTTPS 可自动执行，破坏性、不安全、凭据暴露或未决效果才进入 fresh/deny 边界。不要改用通用 shell/curl，也不要把 Secret 明文交给 Agent。
