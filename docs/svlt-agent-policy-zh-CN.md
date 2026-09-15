# SVLT Agent 敏感信息策略

将下面代码块原样放入 Codex、Claude、Hermes、OpenClaw 或其他 MCP Agent 的系统提示、项目规则或工作区规则。SVLT 是 opt-in；这份策略只约束 SVLT 管理路径，不接管用户明确选择的其他凭据来源。

```text
敏感信息访问与使用策略（SVLT）

产品原则：SVLT protects secrets that the user chooses to manage with SVLT. It does not claim ownership of all credentials available to an Agent. The user may explicitly choose plaintext for an operation at any time.

中文原则：SVLT 只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

触发与来源：
1. 出现 secret://，或用户明确说使用 SVLT、使用 SVLT Entry、保存到 SVLT 时，进入 SVLT_MANAGED_OPERATION。
2. 仅出现 password、token、API key、凭据等词，或任务需要登录、SSH、HTTP、数据库、SFTP、FTP、浏览器/本地 App 填充，不会自动激活 SVLT。
3. 用户在当前请求中亲自提供明文并明确要求本次使用，或明确选择“这次不用 SVLT”时，进入 USER_EXPLICIT_PLAINTEXT。
4. 用户明确指定 QNAP MCP、GitHub connector、已登录 CLI、环境变量、第三方密码管理器或其他 provider 时，进入 EXTERNAL_PROVIDER_OPERATION。
5. 没有明确来源时才进入 UNMANAGED_CREDENTIAL，并允许按任务需要自动发现；SVLT 不是唯一选择。
6. 来源优先级：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 无明确选择时才自动发现。
7. 以上选择只对当前 operation 有效；不得从上一轮对话、旧 provider 选择或 Agent 状态继承来源。每个 operation 只能产生一个最终 source decision。

审批模型（effect-based）:
1. SVLT 根据 operation intent、actual effect、blast radius、reversibility 和 credential exposure 判断 `AUTO`、`GRAY`、`HARD` 或 `DENIED`；Secret 的存在不是审批理由。
2. 与任务对齐的普通只读、受控 Secret 认证、有限且可恢复的写入、普通 Docker/服务操作和普通 HTTP/数据库/SFTP 操作默认 `AUTO`。首次使用 Secret、换 Secret、operationID、sessionID、经过 300 秒以及是否使用 batch 都不改变这个结论。
3. 只有真正危险、不可逆或高影响的电源、裸设备/文件系统、RAID/存储、破坏性数据库/Docker、关键身份权限和 credential exposure 才进入 fresh `HARD`/严格边界；已有 `DENIED` 规则保持 `DENIED`，不得用用户批准绕过。
4. 只有无法从受限证据确定实际效果时才进入 `GRAY`，由独立 semantic judge 在不接收 Secret 明文、完整对话、system prompt、memory 或完整工具清单的前提下决定 `AUTO`、fresh `HARD` 或 `DENIED`。Agent 自报 `freshApproval` 只是证据，不能单独制造审批。
5. batch 只能减少连接和协议开销，不是规避审批的必要手段。任何路径都不得把 SVLT 管理的 Secret 明文交给 Agent、日志、远程 judge 或任意无关进程。

Catalog 浏览与 ID 来源：
1. 浏览分组使用目标 MCP `secret_catalog_list_indices`；结果必须包含空分组。浏览指定分组使用 `secret_catalog_list_entries(indexID)`，单条详情使用 `secret_catalog_get(entryID)`。
2. `secret_search` / `secret_catalog_search` 是 Entry-centric 搜索，不得用 `query: ""` 冒充 list。目标工具是否可用以当前 MCP `tools/list` 为准；未暴露的工具不能当作已实现能力。
3. 结构创建的目标调用是 `secret_catalog_create_structure`：一次提交一个 Index 和多个 Entry，由 SVLT 生成 opaque ID，并返回 `indexID`/`entryID`、`revision` 和 post-commit validation；未暴露时不得把它当作已实现能力。
4. Agent 不得读取 `sensitive-index-selection.json`、Catalog Markdown（例如 `敏感信息.md`）或 `Application Support` 中的 integrity/selection sidecar 来查找或验证 Index/Entry ID；必须使用 MCP API 返回的 ID。

SVLT 敏感信息目录写入规范：
1. 本文件是 SVLT 敏感信息目录；SVLT 是 opt-in。
2. `##` 表示分组，`###` 表示条目。
3. 条目和字段必须符合 SVLT v3 marker 与 schema。
4. 已存在的 id 必须保持稳定，禁止随意重新生成。
5. 同一条目不得出现重复 field key。
6. 新建条目默认只建立一个实际需要的字段，不得为了“完整”自动生成一堆空字段。
7. 字段不够时再增加。
8. 可以使用 App、MCP、Obsidian、编辑器、脚本或其他工具修改，不限制写入渠道。
9. 无论使用什么方式，都必须产生符合 SVLT v3 的结构。
10. 修改时采用最小修改原则，禁止为了新增一条记录重排整个文件。
11. 必须保留用户原有 Markdown、双链、备注、空行以及非目标区域内容。
12. `[[双链]]` 属于合法 Markdown 内容，禁止删除或展开成普通文本。
13. 密码字段不得保存明文。
14. `secret` 字段只能为空 placeholder 或合法 `secret://`。创建空 placeholder 时省略 `value`。合法 JSON 示例：
   {"key":"password","label":"密码","type":"secret"}
   反例（不要使用；空字符串仍是 plaintext value）：
   {"key":"password","label":"密码","type":"secret","value":""}
15. Token 应写作“令牌”。
16. API Key 推荐显示为“API 密钥”，但这只是推荐显示标签，不是 schema 合法性约束；schema 不会仅因 label 没有这几个字而判定非法，`secret` 字段仍不得提供 plaintext `value`。
17. password/secret 类型用户界面统一使用“密码”，不要显示“秘密”。
18. 私钥使用“私钥”，Cookie 使用“Cookie”，不要把所有敏感数据粗暴翻译成“秘密”。
19. `endpoint.type` 可以是任意非空类型字符串，例如 `ssh`、`postgresql`、`mysql`、`redis`；结构层合法不等于某个 executor 支持该类型，也不等于绕过 executor 的 allowlist 或操作授权。
20. 禁止伪造 `secret://`。
21. 新绑定、替换、删除已有 secretRef 属于高风险语义操作，需要用户批准。
22. 删除包含密码引用的条目或分组需要用户批准。
23. 普通标题、别名、备注、标签、非密码字段等修改不触发额外的高风险 secretRef 批准；但由 Agent 提交的 mutation 仍必须走 operation-bound write request。
24. 普通新增分组、条目、字段、空密码 placeholder 不触发额外的高风险 secretRef 批准；但不等于无边界或无授权写入。
25. 合法的普通批量操作不因“批量”本身升级为高风险；一次提交的 batch 仍对应一个精确的 operation-bound write request。
26. 每一笔 Agent semantic Catalog mutation（包括 batch）都必须由 Agent 主动发起一次精确绑定、一次消费的 operation-bound write request；Agent 不能自行开启权限、扩大或复用授权。
27. 每笔需要授权的 Agent semantic Catalog mutation 都会直接触发一次精确绑定的 macOS device-owner authentication；该身份认证本身就是本次用户授权，不存在额外的 App 前置确认，认证票据只消费一次。
28. self-reported caller source 只能作为显示提示；未由可信 transport 证明时必须显示为未验证的 MCP 客户端。
29. Agent write authorization 不能替代 secretRef 绑定、替换、删除或删除密码条目的单独高风险批准。
30. App 普通编辑和 External Writer 不走 Agent write gate；Obsidian Plugin 只负责 v3 validator，不是解密 authority。
31. Agent 不得将密码、Token、API Key 或其他明文写入 Markdown、日志或 MCP 响应。
32. 普通 metadata 和合法 WikiLink 是正常编辑；不得用普通字段隐藏 `secret://`。
33. 格式修复只能调整格式，不能改变结构或 opaque 引用，不能生成或展开明文。
34. 受控 MCP Catalog write 的结果必须带 post-commit validation 摘要，至少让 Agent 得到写入状态、revision 和 diagnostics；`secret_catalog_validate` 仍用于用户直接编辑 Markdown 后的检查、Obsidian 问题诊断、显式 health check 或获取详细 diagnostics；不得用本地 sidecar 代替它。
35. policy block 不属于 Catalog 数据，Agent 不得创建同名“SVLT 管理规范”分组或条目。
36. Agent 不得把密码规范、说明文字、示例当成用户敏感信息。
37. 不得把 SVLT 解密得到的明文写回 `敏感信息.md`。
38. 凭据来源标签包括 `SVLT_MANAGED_OPERATION`、`USER_EXPLICIT_PLAINTEXT`、`EXTERNAL_PROVIDER_OPERATION`、`UNMANAGED_CREDENTIAL`；不得因为用户使用其他凭据 provider 而强制接管。
39. SVLT 自己生成或受控插入的 `敏感信息.md` 使用“前言区 → 连续 Catalog 主体 → 尾部非托管区”布局；已有未知 Note、说明、用户 Markdown、callout 与 WikiLink 不属于 Catalog semantic model，必须保持原位。
40. 新建 Index 必须插入最后一个合法 `SVLT-INDEX` 之后、尾部非托管 Markdown 之前；如果已有用户 Markdown 位于 Index 之间，不为追求连续主体而搬迁它；当前没有 Index 时，插入 policy 和前言之后，不得追加到用户尾注之后。
41. 新生成 Index 之间使用 renderer 的标准 Markdown 分隔 `\n\n---\n\n`；已有 `---` 没有 provenance 时按用户内容保留，不猜测或全局重写用户自己的分隔线。
42. 同一 Index 内的 Entry 之间使用统一的双空行视觉间距；新增、batch、migration、format repair 和 minimal patch 不得混用一行、两行或三行布局。
43. Catalog 写入遵守最小修改原则；只改目标 source range 和新写入时由 SVLT renderer 明确生成的边界空白，保留用户普通 Markdown、注释、WikiLink、Note 和尾部内容；format repair 不搬迁无法确认来源的 Note/Markdown/WikiLink，也不删除用户 HR。
44. Agent 浏览必须使用 `secret_catalog_list_indices`、`secret_catalog_list_entries`、`secret_catalog_get`、`secret_catalog_create_structure` 等 MCP 响应发现 opaque ID；不得读取 selection sidecar、`敏感信息.md` 或 Application Support 文件解析 ID。
45. 需要用户输入秘密时使用 `secret_catalog_request_secure_inputs`；若 transport 返回 `PENDING` 与 `requestID`，只能用 `secret_catalog_secure_input_status` 轮询同一请求，Agent 永远只能收到状态/非敏感结果，不能收到 plaintext。

目录状态规则：
- v3 的外部合法编辑由 SVLT coordinator 重新解析；格式/普通语义变化可以接纳，高风险语义变化进入本机审批，不按编辑器或传输渠道一律拒绝。
- `SVLT-POLICY` 是 document-level 折叠 callout，不属于分组、条目、字段、搜索结果或计数。
- v2 仅作为迁移输入。遇到 `LEGACY_CATALOG_UNSUPPORTED` 必须停止；合法 v2 文件只能由 App 的“备份、验证并升级”流程接管，MCP 不得调用接管操作。

## Markdown 结构与写入布局

`敏感信息.md` 的结构分为三个逻辑区（这是 SVLT 自己生成或受控插入时的布局约束）：前言区、连续的 Catalog 主体区、尾部非托管 Markdown。policy block、Note、使用说明、用户段落、callout 和 `[[WikiLink]]` 都是 unmanaged，不计入 Index/Entry/Field 的语义、搜索、计数或 App UI。已有未知用户 Markdown 即使位于两个 Index 之间也保持原位。

新 Index 插入最后一个合法 `SVLT-INDEX` 之后、任何尾部非托管 Markdown 之前；没有 Index 时插入前言之后。新生成的 Index 之间由 renderer 生成 `\n\n---\n\n`，已有 `---` 没有 provenance 时按用户内容保留，不能全局改写用户自有分隔线。同一 Index 内 Entry 之间使用统一双空行视觉间距。

所有合法 writer（App、MCP、Obsidian、编辑器和脚本）都必须输出 v3 marker/schema；受控写入优先 source-range minimal patch，只调整目标块及新写入时 renderer 明确生成的边界空白，保留用户 Markdown、备注、注释、WikiLink、Note 和尾部内容。format repair 不为追求连续主体而移动无法确认来源的用户 Note/Markdown/WikiLink，也不删除用户 HR；只有 migration 能确定来自旧版官方结构化“目录说明”的 Note 时，才可将它放入前言。

用户明文覆盖规则：
1. 用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管。即使上一轮使用 SVLT 或 Catalog 中可能已有对应 Secret，本次仍按用户明确选择执行。
2. 不要搜索、比较、替换、导入 secret://、要求用户删除明文、打开 SVLT、触发 Touch ID，或仅因 Catalog 命中而拒绝本次操作。
3. 不要把用户主动提供的明文识别为 security bypass attempt，也不要判断它与已有 SVLT Secret 相同；SVLT 不做值比对。
4. 如果用户同时明确要求“把这个 Token 存到 SVLT，然后调用”，先走 App/MCP 安全导入流程，之后使用生成的 secret://。

safeWorkflow：
1. 在调用 SVLT 前，先判断用户是否明确选择 SVLT，或是否已经亲自提供并明确要求使用当前明文。
2. 如果用户明确提供明文并要求使用，继续使用该值并遵守当前工具/工作区规则；除非用户要求，不要搜索或替换成 SVLT 引用。
3. 如果用户选择 SVLT，使用 secret_auto_handle_text、secret_search、secret_catalog_search、目标 `secret_catalog_list_indices`、目标 `secret_catalog_list_entries`、`secret_catalog_get` 或专用 secret action；目标工具未暴露时不得用本地文件补足。
4. 搜索只返回非敏感上下文和 opaque 引用，不授予明文展示、导出或外发权限。
5. 每笔 Agent Catalog mutation 先发起精确 operation-bound write request；受控 MCP write 结果必须携带 post-commit validation。`secret_catalog_validate` 保留给外部编辑、显式 health check 和详细 diagnostics，不要读取 sidecar。
6. 无授权、完整性失败或旧版目录状态时停止，不要自行修复文件或猜测 ID。
7. 需要本机使用 SVLT 秘密时，使用 secret_action_router 或更窄的工具；不要把 SVLT 解密明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。

禁止事项：
- Do not expose plaintext obtained by decrypting an SVLT-managed secret outside the approved SVLT operation.
- 不得把 SVLT 派生明文放入普通 shell、curl、URL、header、环境变量、日志、审计或聊天。
- 不得写入不符合 v3 marker/schema 的 Markdown；不得把用户批准高风险语义变化解释为输出 SVLT 解密明文的权限。
- 不得因用户明确选择明文而强制导入 SVLT；也不得因其他 MCP/provider 有凭据而自动抢占。
- 其他仓库、工具和工作区的安全规则仍然有效：用户允许本次使用，不等于允许写入 Git、日志、issue、公开网络或不安全持久化位置。
```

Schema 详见 [`svlt-catalog-schema-v3.md`](svlt-catalog-schema-v3.md)；v2 仅见于 [`svlt-catalog-schema-v2.md`](svlt-catalog-schema-v2.md) 的迁移说明。App 不展示 policy 正文；`SVLTAgentCatalogPolicy` 同时生成文档 policy block 和 MCP `agent_secret_usage_policy` 响应。

受控写入的 `CREATED` 表示 semantic commit 已提交。只有返回的
`validation.status == FOUND` 且 `validation.diagnostics` 为空，才表示提交后的健康确认
成功；若是 `CREATED` 但 validation 为 `CATALOG_UNAVAILABLE` 等状态，表示写入可能已
成功而确认未完成，不要盲目重试写入，服务恢复后用 `secret_catalog_validate` 显式确认。
