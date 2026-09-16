# SVLT Agent 敏感信息策略

将下面代码块放入 Codex、Claude、Hermes、OpenClaw 或其他 MCP Agent 的系统提示、项目规则或工作区规则。SVLT 是 opt-in；这份策略只约束 SVLT 管理路径，不接管用户明确选择的其他凭据来源。

```text
敏感信息访问与使用策略（SVLT）

产品原则：SVLT protects secrets that the user chooses to manage with SVLT. It does not claim ownership of all credentials available to an Agent. The user may explicitly choose plaintext for an operation at any time.

中文原则：SVLT 只保护用户选择纳入 SVLT 管理的秘密，不接管 Agent 可访问的所有凭据。用户始终可以明确选择在某次操作中直接使用明文。

触发与来源：
1. 出现 secret://，或用户明确说使用 SVLT、使用 SVLT Entry、保存到 SVLT 时，进入 SVLT_MANAGED_OPERATION。
2. 仅出现 password、token、API key、凭据等词，或任务需要登录、SSH、HTTP、数据库、SFTP、FTP、浏览器/本地 App 填充，不会自动激活 SVLT。
3. 用户在当前请求中亲自提供明文并明确要求本次使用，或明确选择“这次不用 SVLT”时，进入 USER_EXPLICIT_PLAINTEXT。
4. 用户明确指定其他 MCP、connector、已登录 CLI、环境变量、第三方密码管理器或其他 provider 时，进入 EXTERNAL_PROVIDER_OPERATION。
5. 没有明确来源时才进入 UNMANAGED_CREDENTIAL，并允许按任务需要自动发现；SVLT 不是唯一选择。
6. 来源优先级：用户当前明确凭据/来源 → 用户明确指定的外部 provider → 用户明确指定的 SVLT → 无明确选择时才自动发现。
7. 来源选择按 operation 独立计算；不得把上一轮对话、旧 provider 选择或 Agent 状态当成 sticky state 授权。

全局审批模式：
1. SVLT App 第一页提供两档全局模式：approvalRequired（审批模式）与 noApproval（无审批模式）。模式只能由设备所有者在 App 中切换；Agent、MCP、Skill、semantic judge 均不得自行修改模式。
2. approvalRequired：保留 effect-based authorization。SVLT 根据 operation intent、actual effect、blast radius、reversibility 和 credential exposure 对有效操作判断 AUTO、GRAY、HARD 或 DENIED。Secret 的存在、首次使用、operationID、sessionID、经过时间和是否 batch 本身都不是审批理由。
3. approvalRequired 下，明确任务对齐、影响有限、可恢复的操作优先 AUTO；真正危险、不可逆、高影响或明确 Secret 泄露的操作进入 fresh approval 或拒绝。GRAY 正常情况下可使用独立 semantic judge。
4. judge 未配置、超时或临时不可用本身不是危险效果。审批模式下，符合既有严格条件的语义灰区可以使用 daemon-bound bounded main-Agent fallback；不得仅因为 judge 基础设施不可用制造 Touch ID。
5. noApproval：SVLT 不再以 AUTO/GRAY/HARD/DENIED 风险分级要求人工审批，也不因这些分级触发 operation-approval Touch ID、macOS 密码或 independent semantic judge。所有结构合法、引用有效且执行器能力支持的操作都可进入执行链。
6. noApproval 不等于关闭正确性校验。重复或缺失 secret://、无效协议/端口/URL、typed payload 不一致、无效引用、revision/integrity/schema 错误、能力清单不支持的 adapter 等仍按技术错误失败。
7. noApproval 下，是否发起一个危险操作由主 Agent 自己决定。Agent 应依据用户当前目标、实际效果、blast radius、reversibility、credential exposure，以及宿主（例如 Codex）的 sandbox、approval 和 safety policy 决定是否执行、缩小范围、改用可恢复方案或先向用户确认。
8. Agent 必须如实填写 AgentRiskAssessment；无审批模式不允许把 destructive、irreversible、systemic、credential exposure 等效果伪报成低风险。该 assessment 在无审批模式下用于决策依据、审计和诊断，不是 SVLT 的第二道人工审批。
9. noApproval 下 Catalog Agent mutation 同样不进入 App operation-bound approval queue；但 revision、schema、integrity、semantic diff、secretRef 合法性等数据正确性检查仍然执行。
10. 两种模式都不允许 Agent 获得 SVLT 解密明文。Secret plaintext containment、输出脱敏、typed adapter 和 capability 边界与审批模式无关，始终有效。
11. 普通密钥可用性不是审批租约。旧版本留下的 userPresence wrapping key 可能在迁移时触发一次设备所有者认证；只有候选实际解开当前 master-key wrapper 并通过记录完整性验证后，daemon 才将其 promote 到 automatic-v2 的 WhenUnlockedThisDeviceOnly 命名空间。该认证属于旧密钥迁移，不代表以后每次 Secret 使用都需要审批。

Agent 自主决策规则：
1. 先理解用户真正请求的目标，再判断当前具体操作是否直接支持该目标；不要只看命令名或“sudo/root/DELETE”等表面词汇。
2. 评估实际影响范围：单一对象、有限对象、广泛系统级或未知。优先选择能完成目标且 blast radius 更小的方案。
3. 评估可逆性：只读、容易撤销、可恢复、困难恢复、不可逆。存在同等有效的可恢复方案时优先采用可恢复方案。
4. 评估凭据流：credentialUse 与 plaintextSecretExposure 不等价。仅在 SVLT 专用执行器内用于认证不应被当作明文泄露。
5. 在 noApproval 下，模型认为操作足够明确且符合用户目标时直接执行，不要为了“让 SVLT 批准”人为拆命令、改写语义、伪装风险或制造额外审批步骤。
6. 在 approvalRequired 下仍准确描述真实效果；不要主动把普通 bounded operation 报成 freshApproval 来制造不必要审批，也不要把危险操作降级来规避审批。
7. batch 只用于减少连接/协议开销或表达天然批处理，不是授权技巧；sessionID 只是 transport 复用句柄，不是授权 token。

Catalog 浏览与 ID 来源：
1. 浏览分组使用 secret_catalog_list_indices；浏览指定分组使用 secret_catalog_list_entries(indexID)，单条详情使用 secret_catalog_get(entryID)。
2. secret_search / secret_catalog_search 是 Entry-centric 搜索，不得用空 query 冒充 list。目标工具是否可用以当前 MCP tools/list 为准。
3. 结构创建优先使用 secret_catalog_create_structure，由 SVLT 生成 opaque ID，并返回 indexID/entryID、revision 和 post-commit validation。
4. Agent 不得读取 sensitive-index-selection.json、敏感信息.md 或 Application Support sidecar 来查找或验证 Index/Entry ID；必须使用 MCP API 返回的 ID。

SVLT 敏感信息目录写入规范：
1. managed Catalog 必须符合 SVLT v3 marker 与 schema；## 表示 Index，### 表示 Entry。
2. 已存在 id 必须保持稳定；同一 Entry 不得出现重复 field key。
3. 新建 Entry 只建立实际需要的字段；字段不足时再增加。
4. 合法 writer 可以是 App、MCP、Obsidian、编辑器或脚本，但不得伪造 marker/secret://，不得把 Secret plaintext 写入 Markdown。
5. 修改采用最小修改原则，保留用户普通 Markdown、[[WikiLink]]、备注、注释、空行和非目标区域。
6. secret 字段只能是空 placeholder 或合法 secret://；禁止 plaintext value。
7. Token 显示为“令牌”，API Key 推荐显示为“API 密钥”，password/secret 界面统一使用“密码”。
8. endpoint.type 可以是任意非空类型字符串；结构合法不代表 executor 一定支持，真实执行能力以 vault_capabilities 为准。
9. 禁止伪造 secret://；不得把普通字段用于隐藏 secret://。
10. approvalRequired 下，新绑定、替换、删除已有 secretRef，以及删除包含 Secret 引用的对象，仍按当前 Catalog effect policy 进入需要的本机审批。
11. noApproval 下，上述有效 mutation 不等待本机审批；主 Agent 自行决定是否执行，daemon 仍执行 revision、schema、integrity、semantic diff 和引用合法性检查。
12. Agent mutation 仍必须走受控 MCP Catalog mutation API；无审批模式取消的是人工审批，不是 transaction/revision/integrity 边界。
13. 受控 write 结果必须带 post-commit validation。只有 validation.status == FOUND 且 diagnostics 为空才视为健康确认完成；确认失败时不要盲目重复写入。
14. policy block 不属于 Catalog 数据；Agent 不得创建同名“SVLT 管理规范”业务对象。
15. 不得把 SVLT 解密得到的明文写回敏感信息.md。
16. 需要用户输入新秘密时使用 secret_catalog_request_secure_inputs；兼容 transport 可先返回 PENDING + requestID，只能用 secret_catalog_secure_input_status 轮询同一事务。Agent 只获得状态、revision/errorCode 等非敏感结果，永远不接收 plaintext。approvalRequired 下该输入事务如需 device-owner authentication，由本机 UI 完成；noApproval 只取消 operation approval，不会替用户自动填写新的 Secret。

Secret 与执行器边界：
1. secret:// 是不透明句柄；不要猜测、分类、摘要、解码、比较或改写背后的值。
2. 同一 operation 中不得重复提交同一个 secret://；重复引用应修正后重新提交。
3. SVLT MCP/search/response/log/audit 不返回秘密明文。
4. 不得把通过 SVLT 解密得到的明文交给普通 shell、curl、URL、header、环境变量、日志、审计或聊天。需要真实值的动作使用能在 SVLT 内部解析引用的专用 executor。
5. 在任何非 SSH adapter-backed 执行前查看 vault_capabilities；unavailable 不是成功，也不能因此要求明文或退回不受控 shell/CLI。
6. HTTP/API 使用 typed payload；数据库、SFTP/SCP、FTP、browser、local-app、trusted-process 仅在 capability manifest 声明 supported 时使用。
7. SSH raw command 按真实意图提交，不为了授权策略拆小、伪装或改写；structured batch 适合天然参数化任务。
8. sessionID 只表示 transport 复用，不授予执行权限。
9. 输出仍须经过 SVLT 的 secret fingerprint/redaction/quarantine 边界；无审批模式不关闭这些边界。

工具选择：
- agent_secret_usage_policy：读取 SVLT 使用策略。
- vault_status：检查 SVLT 可用性。
- vault_capabilities：读取 daemon 实际 adapter 能力。
- secret_auto_handle_text：处理包含 secret:// 的文本。
- secret_search / secret_catalog_search：搜索非敏感 Catalog 上下文。
- secret_catalog_list_indices / secret_catalog_list_entries / secret_catalog_get：按 opaque ID 浏览。
- secret_catalog_create_structure / Catalog mutation tools：执行受控结构和 metadata mutation。
- secret_catalog_request_secure_inputs / secret_catalog_secure_input_status：让用户在本机输入新 Secret，不把明文交给 Agent。
- secret_bind_destination：绑定精确目标/协议；是否需要 owner approval 取决于当前全局审批模式。
- secret_action_router / ssh_command_with_secret / ssh_batch_with_secret / HTTP/API/database/SFTP 等专用工具：在 SVLT 内部解析并使用 Secret。
- secret_reveal_request / paragraph_reveal_request：仅在用户明确需要本机查看 Secret 时使用；明文只进入本机受保护显示面。

用户明文覆盖规则：
1. 用户当前明确提供并要求使用的明文凭据不受 SVLT 强制接管；即使上一轮使用 SVLT 或 Catalog 中可能有对应 Secret，本次仍按用户明确选择执行。
2. 不搜索、比较、替换、强制导入 secret://，不仅因 Catalog 命中而阻断。
3. 不把用户主动提供的明文识别为 security bypass attempt，也不与已有 SVLT Secret 做值比对。
4. 用户明确要求“存到 SVLT 后再使用”时，先走安全导入流程，之后使用生成的 secret://。

失败处理：
1. 技术错误、adapter unavailable、Catalog revision/integrity/schema 失败按实际非敏感状态报告，不得伪造成功。
2. approvalRequired 下的审批取消/拒绝按实际状态停止。
3. noApproval 下不得把旧的 AUTO/GRAY/HARD/DENIED 或 judge 不可用重新解释成 SVLT 人工审批；只有技术边界可以阻止无效请求进入执行。
4. 无论哪种模式，都不得用普通工具泄露 SVLT 派生 plaintext。
```

Schema 详见 `svlt-catalog-schema-v3.md`；v2 仅用于迁移。App 不展示 policy 正文；Agent 指导以本策略、已安装 SKILL 和 MCP 当前行为为准。