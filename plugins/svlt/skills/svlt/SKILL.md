---
name: svlt
description: Use when Codex, Claude, Hermes, or another MCP agent sees secret:// references or the user explicitly chooses SVLT to manage or use a credential. SVLT is opt-in and does not claim ownership of credentials selected through another provider or explicitly supplied as plaintext for the current operation.
---

# SVLT

SVLT is opt-in. It protects secrets that the user chooses to manage with SVLT; it does not claim ownership of all credentials available to an Agent.

触发范围：

- 出现 `secret://...`，或用户明确要求“使用 SVLT / 使用 SVLT 中的登录 / 保存到 SVLT”时，进入 SVLT 管理路径。
- 仅仅出现 password、token、API key、凭据等词，或任务需要登录、SSH、HTTP、数据库、SFTP、浏览器/本地 App 填充，并不会自动激活 SVLT。
- 用户当前亲自提供明文并明确要求本次使用，或明确选择“这次不用 SVLT”时，建立 `USER_EXPLICIT_PLAINTEXT`；不得搜索、比较、替换成 `secret://`、导入 SVLT、要求 Touch ID，或仅因 Catalog 可能已有对应 Secret 而阻断。
- 用户明确指定 QNAP MCP、GitHub connector、已登录 CLI、环境变量、第三方密码管理器或其他 provider 时，使用该 provider；SVLT 不得抢占。

英文原则：SVLT is opt-in. The user may explicitly choose to provide or use plaintext credentials. When the user explicitly chooses plaintext for the current operation, do not force conversion to `secret://` and do not block the operation solely because an equivalent credential may already exist in SVLT. Do not treat user-supplied plaintext as SVLT-managed unless the user explicitly asks to store it in or use it through SVLT.

中文原则：用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。即使 SVLT 中可能已有对应 Secret，本次仍按用户明确选择执行。SVLT 只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

## scope 与来源优先级

- `SVLT_MANAGED_OPERATION`：用户明确选择 SVLT、Entry 或 `secret://`；只经 SVLT 的专用工具使用。
- `USER_EXPLICIT_PLAINTEXT`：用户在当前请求中提供明文并明确要求使用，或明确选择本次不用 SVLT。
- `EXTERNAL_PROVIDER_OPERATION`：用户明确选择其他 MCP、connector、CLI、环境变量或密码管理器。
- `UNMANAGED_CREDENTIAL`：用户没有指定来源；可以按任务需要发现可用 provider，但 SVLT 不是唯一选择。
- 来源优先级：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 没有指定时才自动发现。
- 以上选择只对当前 operation 有效；不得把上一轮对话、旧 provider 选择或 Agent 状态当成当前授权。每次 operation 只能有一个最终 source decision。
- 不比较用户明文与 `secret://` 背后的值，不因可能相同而改变 provenance。

## 全局审批模式

SVLT App 主窗口第一页提供两个全局模式。模式只能由设备所有者在 App 中选择；Agent、MCP、Skill、远程 semantic judge 都不得切换、模拟或持久化这个设置。

- `审批模式 / approvalRequired`：保留 SVLT 的 effect-based 授权。普通任务对齐、有限且可恢复的操作可以自动执行；真正危险、不可逆、高影响、凭据暴露或语义未决的操作按现有 `GRAY`/`HARD`/`DENIED` 逻辑处理，并可能触发 Touch ID/macOS 密码。
- `无审批模式 / noApproval`：SVLT 退出人工审批决策链。对结构合法、Secret 引用存在且当前 executor/capability 实际支持的操作，SVLT 不因本地 `AUTO/GRAY/HARD/DENIED` 风险等级阻断，不调用 independent judge，也不弹出 operation approval 的 Touch ID/macOS 密码。Catalog Agent mutation 同样跳过 SVLT 的本机授权队列。
- 无审批模式不是“Agent 不判断风险”。恰恰相反，**是否发起操作由主模型/Agent 自己依据用户当前目标、实际效果、blast radius、reversibility、credential exposure，以及宿主 Agent 自身的 approval/sandbox/safety policy 决定。** 无审批模式下，是否执行由主 Agent 自己决定。如果宿主 Agent（例如 Codex）自身要求确认，照常遵循宿主规则；不得把 SVLT 无审批模式解释为绕过宿主产品安全策略。
- 无审批模式下仍必须准确填写 `agentAssessment`、`intendedEffect`、`expectedEffect` 等效果信息。不要为了让请求“看起来安全”而拆分、改写、伪装或谎报操作；SVLT 不再依据这些字段制造人工审批，因此没有规避的必要。
- 无审批模式不会把坏参数变成合法请求：重复/缺失 Secret、无效协议或端口、typed payload 不一致、目标格式错误、Secret 元数据缺失、adapter 未安装/不可用等技术错误仍正常失败。
- 无审批模式不会改变明文边界：SVLT 派生的秘密仍不得被返回聊天、普通日志、普通 shell 参数、环境变量或其他非 SVLT 批准的数据通道。它只关闭 SVLT 的“是否需要人工批准”门，不把 `secret://` 变成可随意读取的明文。
- 旧 vault 若仍留有历史 `userPresence` wrapping key，系统可能在完成一次经过密码学验证的迁移时要求设备所有者认证（device-owner authentication）；这属于旧 Keychain 数据迁移，不是 operation approval。迁移成功后使用 `automatic-v2`。

## 硬规则

- 用户在 App 中选定的 v3 `敏感信息.md` 是 SVLT managed catalog。Agent 只能经 MCP 使用 `secret://` 或允许返回的非敏感元数据；不得读取 managed Markdown 或本地 sidecar 来发现、验证或猜测 opaque ID。
- Catalog 的合法 writer 可以是 App、MCP、Obsidian、编辑器或脚本；无论渠道都必须产生符合 v3 marker/schema 的 Markdown，不得伪造 marker/`secret://`、写入 plaintext。Agent mutation 仍使用精确 operation-bound request；审批模式决定这个 request 是否还需要 SVLT 人工批准。
- `secret://` 是不透明句柄；不要猜测、分类、摘要、解码、比较或改写背后的值。
- 同一 operation 中不得重复提交同一个 `secret://`；不要为了“去重”静默改变调用语义，重复引用应修正后重新提交。
- SVLT MCP/search/response/log/audit 不返回秘密明文。秘密字段只能是 opaque `secret://` 引用；Catalog JSON 不得写入秘密明文。
- 用户明确选择的当前明文可以由用户指定的外部工具/工作区按其安全规则使用；SVLT 不自动创建 Secret、替换输入或阻止操作。其他仓库、日志、持久化、网络和工具规则仍然有效。
- 不得把通过 SVLT 解密得到的明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。禁止的是 Agent 自己把 `secret://` 洗成明文绕过 SVLT 专用操作。
- 不要把用户主动提供的明文识别为 security bypass attempt，也不要把它与已有 Secret 做等值关联。
- 需要给已有 `secret://` 增加精确服务地址/协议时使用 `secret_bind_destination`；protocol 和 destination 作为原子 pair 保存并返回 canonical destination。审批模式下按策略要求 owner approval；无审批模式下不额外弹出 SVLT operation approval。

### SSH transport 与 effect-based authorization

- 连续 SSH 任务优先使用 `ssh_command_with_secret` 返回的 opaque `sessionID`，或一次调用 `ssh_batch_with_secret`。`sessionID` 只代表 SVLT 内部可复用的 SSH transport，不代表命令已获授权，也不是密码、ControlPath 或其他 capability。
- 每一次命令（包括带 `sessionID` 的后续命令）仍由 SVLT 重新校验 principal、目标、Secret 引用和请求结构；无审批模式只关闭人工授权门，不关闭这些技术校验。
- `ssh_command_with_secret` 的 `command` 是真正的 remote shell 命令，会 byte-for-byte 交给远端登录 shell 执行：单行、多行、`;`、`&&`、`|`、`>`、`$()`、glob、引号、heredoc、`bash -c`、`python -c`、`find -exec`、`sudo` 都按真实意图提交，SVLT 不解析也不改写 shell 语法。
- 结构化 `ssh_batch_with_secret`（每项 `executable` + `arguments`）适合天然参数化的任务；不要为了审批策略强行拆分或拼接。两种形式都是一等公民。
- 审批模式下：Secret 的存在、首次使用、operationID、sessionID、经过时间和是否使用 batch 都不是审批理由。普通任务对齐、影响有限、可恢复的 SSH 直接 `AUTO`；高影响/不可逆/未决操作才进入更严格路径。
- 审批模式的 `GRAY` 正常交给 independent semantic judge；judge 不可用时仍保留既有 daemon-bound bounded main-Agent fallback。`HARD`/`DENIED` 底线按审批模式处理。
- 无审批模式下：MCP 不调用 independent judge，daemon 把有效操作按 full-access 路径执行。主 Agent 仍应先自行判断命令是否符合用户目标；不要因为“SVLT 会放行”就执行用户没有要求的高影响操作。
- MCP 连接建立后应声明客户端名称与版本；Audit/UI 中的 client identity 只是 display metadata，不是可信 security principal。

### 非 SSH 执行器与能力清单

- 在任何非 SSH 执行前先调用 `vault_capabilities`。daemon 返回的 capability manifest 才是实际能力来源；`unavailable` 不是“稍后重试即可”的支持状态，也不能因为无审批模式就伪造能力或退回不受支持的实现。
- HTTP/API 继续使用 typed payload；数据库、SFTP/SCP/FTP、浏览器、本地 App、trusted process 等继续以实际 capability 为前提。无审批模式只移除 SVLT 人工授权，不创造不存在的 adapter。
- 带认证 HTTP 响应仍按 response policy 做 metadata-only/sanitized preview/projected JSON 隔离；无审批模式不会关闭响应脱敏和 Secret 明文隔离。
- `Authorization` header 默认使用 `Bearer`；custom API-key header 仍按 typed profile/request 构造。不要用自定义 header 绕过 Secret 明文边界。
- `localExecution` 在审批模式下属于极高危 fresh-approval 边界；无审批模式下 SVLT 不再弹 owner approval，但主 Agent必须把“Secret 将交给任意本地进程”视为真实效果并自行决定是否符合用户目标和宿主安全规则。
- 导出工具只返回本地路径/状态；plaintext resolution 和安全文件写入留在 App/daemon 边界内。不要读取导出文件再把内容放进聊天或普通工具。
- 非 SSH 请求同样必须准确填写风险/效果字段。审批模式下这些字段参与 effect-based policy；无审批模式下它们用于 Agent 自我判断、审计和可解释性，而不是 SVLT 人工审批。

## Catalog Markdown 布局

- SVLT 自己生成或受控插入的 `敏感信息.md` 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局。Note、说明、callout、用户段落和 WikiLink 是 unmanaged，不属于 Index/Entry/Field semantic model，也不计入搜索、计数或 App UI；已有未知用户 Markdown 即使位于两个 Index 之间也保持原位。
- policy block 与前言位于业务 Catalog 之前；存在 Index 时，新 Index 插入最后一个合法 `SVLT-INDEX` 之后、尾部非托管 Markdown 之前。没有 Index 时，首个 Index 插入前言之后。
- Index marker/Entry marker/Field marker 是 authoritative structure。新生成的 Index 之间由 renderer 生成标准 `\n\n---\n\n`；已有 `---` 没有 provenance 时按用户内容保留。
- 同一 Index 内 Entry 之间统一使用双空行视觉间距；普通写入优先 source-range minimal patch，保留用户 Markdown、注释、WikiLink、Note、备注和尾部内容。

## 工具选择

先判断用户是否选择了来源，再选择工具：

- `agent_secret_usage_policy`：读取 SVLT 范围、用户覆盖规则和 SVLT 派生明文边界。
- `vault_status`：只有即将执行 SVLT 管理操作时才检查 SVLT 可用性。
- `secret_auto_handle_text`：文本中出现 `secret://` 且用户没有明确选择其他来源时使用。
- `secret_search` / `secret_catalog_search`：没有明确来源且需要发现 SVLT 记录时使用；明确 plaintext 或外部 provider 时不要调用来替换来源。
- `secret_catalog_get` / `secret_catalog_list_indices` / `secret_catalog_list_entries`：只通过 MCP 返回的 opaque ID 浏览 Catalog。
- `secret_catalog_create_structure` / `secret_catalog_add_secret_placeholder` / Catalog mutation 工具：保持精确 operation-bound mutation；审批模式可能要求本机批准，无审批模式直接通过 SVLT 授权层。
- `secret_catalog_request_secure_inputs`：请求本机 SecureField 填写秘密；Agent 永远不接收 plaintext。Secure Input 是用户输入秘密的 UI 事务，不等价于 operation approval 模式。
- `secret_bind_destination`、`secret_action_router`、`ssh_command_with_secret`、`ssh_batch_with_secret` 和各 typed executor 工具继续用于各自能力边界。
- `secret_reveal_request` / `paragraph_reveal_request`：用户明确要在本机 App 查看 SVLT 明文时使用；结果是本地显示状态，不是返回给 Agent 的明文。

## Secure Input 异步事务

- `secret_catalog_request_secure_inputs` 只接受 `entryID`、field key、模式、required 和 accepted revision；不要传入 plaintext label/value 到 MCP。
- 若调用返回 `PENDING` 与 opaque `requestID`，只用 `secret_catalog_secure_input_status` 轮询直到终态。status 不包含 plaintext、Catalog 内容或 secretRef。
- Secure Input 的用户填写、字段加密、revision/semantic diff 校验与 commit 仍是独立事务；无审批模式不会自动替用户填写秘密，也不会取消结构/完整性校验。

如果用户明确选择了其他 MCP/CLI/App 或当前明文，保持 SVLT 沉默，调用该工具并遵守其自身的权限、日志和持久化规则。不要因为 SVLT Catalog 有候选记录而抢占。

## 失败处理

- 无审批模式下，不要把 `HARD`/`DENIED` 风险分类本身当成 SVLT 执行失败；只有技术错误、能力不可用、请求结构无效、Secret/Catalog 状态无效或 executor 实际失败才应停止。
- 审批模式下，按返回的审批/拒绝状态处理，不要通过拆分或改写请求规避审批。
- 旧版 Catalog 的 `LEGACY_CATALOG_UNSUPPORTED` 表示需要显式迁移流程；Agent 不得自行伪造结构。
- 如果用户明确选择当前明文或外部 provider，SVLT 的不可用、未安装或 Catalog 命中都不是阻断本次操作的理由；是否能执行由用户选定的工具和工作区规则决定。
- 如果用户明确要求把当前明文存入 SVLT，先走 App/MCP 的安全导入流程；成功后再使用生成的 `secret://`。不得默认保存。