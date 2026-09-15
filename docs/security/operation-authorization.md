# SVLT 操作授权模型

SVLT 不再把 `locked` 当作 Agent 的全局工作流门禁。`locked` 只保留在兼容状态中；Agent 应读取 `available`、`ready` 和 `approvalPending`，然后直接提交具体的受保护操作。

## 决策流程

每个使用 SVLT-managed Secret 的请求都经过同一条本地路径。审批依据是操作的实际效果，而不是 Secret 是否存在或是否首次使用。用户明确选择其他 provider 或当前明文的操作不由 SVLT 强制接管，也不应被已有 Catalog 记录抢占：

```text
opaque descriptor
  -> normalize destination / command / path
  -> SecretOperationPolicyEngine
  -> effect + blast radius + reversibility + Secret flow
  -> route: AUTO | GRAY | HARD | DENIED
  -> AgentRiskAssessment is evidence, not a self-issued capability
  -> technical failure or (only when required) fresh owner approval
  -> capability preflight
  -> exact device-owner approval for HARD/GRAY-resolved high-risk effects
  -> latest policy check
  -> resolve and execute
```

`AgentRiskAssessment` 是效果证据，不是 Agent 自签发的授权能力。明确安全、任务对齐且可恢复的普通操作可以 `AUTO`；主 Agent 保守填写 `freshApproval` 不能单独制造审批。技术性错误（格式、引用集合、目标字段或身份不可验证）会在认证前失败；只有本地 hard floor 或 GRAY 独立 judge 最终判定为高影响/不可逆的操作才进入 fresh owner approval。

## 风险规则

| 操作 | 默认状态 | 关键条件 |
| --- | --- | --- |
| 状态、使用策略、引用元数据 | `silent` | 不解密、不返回 Secret |
| 明确只读、诊断、状态查询和受控 Secret 认证 | `AUTO` | Secret 只在受控 consumer 内使用；不返回给 Agent、日志、judge 或无关进程；首次使用也不审批 |
| 普通配置/文件写入、下载/上传、Git、HTTP POST/PUT/PATCH、 bounded DB CRUD、Docker/service restart | `AUTO` | 任务对齐、范围有限、可恢复或有明确执行器边界；写入本身不是审批理由 |
| 普通 SSH（包括 shell、sudo、python、docker exec、日志/配置读取） | `AUTO` | 以最终效果和 Secret 流向判断；关键字、operationID、sessionID、时间和 Secret 选择不改变结论 |
| 文件删除、HTTP `DELETE`、SFTP 删除、容器移除、无界/动态 DB 数据变更 | `GRAY` | 交给独立 semantic judge；judge 可以 `AUTO`、fresh `HARD` 或 `DENIED` |
| SSH 电源控制、块设备/文件系统破坏、存储/RAID 破坏、Docker volume 删除/system prune | `HARD` | 固定不可降级安全底线；每次 fresh owner approval |
| HTTP `http://` 携 Secret、凭据 query 参数、FTP 明文凭据传输 | `HARD` | 不因 Agent 建议而降级；执行器仍校验精确 scheme/host/port profile |
| 数据库 DROP/TRUNCATE/破坏性结构变更、权限/账户管理、动态外部文件边界 | `HARD` | 每次 fresh owner approval；技术身份边界和 DENIED 规则仍优先 |
| Secret 明文显示/export、交给任意本地进程或不可信第三方 | `DENIED` 或 `HARD` | 沿用既有严格 boundary；本次模型不把 Secret 泄露变成普通审批 |
| 未知、不可解析或语义冲突的操作 | `GRAY` | 没有独立 judge 证明安全时 fresh；不能用 batch 或 lease 绕过 |
| Secret-bearing 明文 FTP | `HARD` | 仅回环/私有目标；每次重新认证，不建立可复用会话授权 |
| 为已有 Secret 增加精确目标/协议绑定 | `freshApprovalRequired` | App 显示 exact scheme/host/port；在进程内重新封装认证元数据，不解密出 IPC、不建立执行会话授权 |
| 明文显示、复制、删除或安全设置变更 | `freshApprovalRequired` | 使用 `deviceOwnerAuthentication` |
| `localExecution`（交给任意本地进程） | `freshApprovalRequired` | 明确标记 `userApprovedSecretRelease`，由设备所有者决定 |

Secret metadata 保留旧版兼容字段 `allowedDestinations` 和 `allowedProtocols`；新绑定同时写入经过认证的 `allowedBindings`，每个元素把 protocol 和 destination 作为一个不可拆分的 pair。存在 `allowedBindings` 时，HTTP/其他 pair-sensitive 检查只使用它；无法从混合旧数组安全还原 pair 时 fail closed，不生成笛卡尔积。普通目标/协议绑定不匹配是提示并进入目标/协议语义复核，不会因为 Secret 或 transport scope 本身建立审批租约；元数据缺失或引用集合无法验证才是策略层技术性失败。对携 Secret 的明文 HTTP，执行器在设备所有者审批之后还会要求每个引用都匹配保存的精确 `scheme://host:port` profile；这只防止 profile 横向扩大到另一台主机或端口，不把 hostname 当作 DNS/实际 egress 证明。HTTP 不自动跟随任何重定向，发现新目标时必须重新提交一个独立操作；响应 body、`Location`、`Content-Type` 命中 Secret fingerprint 时整次输出 quarantine。认证响应默认只返回元数据；只有明确请求 `includeBodyPreview` 时，才允许最多 16 KiB 且必须是无敏感字段名、无 `secret://` 的合法 JSON 预览，否则 quarantine。更严格的字段投影仍由 App-owned profile 控制。

### SSH host-key trust

SSH 不再复用用户全局 `~/.ssh/known_hosts`。SVLT 在自己的 Application Support 目录维护 owner-only trust store，目录权限收敛为 `0700`、`known_hosts` 收敛为 `0600`，并拒绝把 `known_hosts` 作为 symlink 打开。OpenSSH 同时禁用 global known-hosts 文件、启用 hashed host entries、关闭自动 `UpdateHostKeys`，因此其他 SSH 客户端不会静默扩大或替换 SVLT 的主机信任状态；已记录主机发生 host-key 变化时仍会返回 `HOST_KEY_FAILED`。显式 pin 另存为按 host/port 隔离的 App-owned profile，并由执行器在使用前校验文件内容。

为了不破坏现有首次连接流程，未知主机仍采用 OpenSSH `accept-new` 的 TOFU（trust on first use）语义，并开启 `VerifyHostKeyDNS=yes` 以便在存在安全 SSHFP/DNSSEC 记录时利用该验证。TOFU 不能凭空证明一台从未见过的主机身份，因此这项兼容路径不把首次未知主机宣称为已经完成带外 fingerprint 验证。

需要更高保证时，Agent 先调用 `secret_review_ssh_host_key`，由 App-owned executor 使用 `ssh-keyscan` 发现当前 host/port 展示的算法和 SHA256 fingerprint；这个过程不读取、不解析、也不发送 Secret，发现结果本身也不是带外身份认证。Agent 将设备所有者选定的 algorithm、SHA256 fingerprint 和显式 port 传给 `secret_bind_destination`，App 的审批摘要会显示 host、port、全部当前候选指纹，并将待固定的候选标为“待固定”。设备所有者批准后，SVLT 重新发现并核对同一 fingerprint，再写入严格 profile；后续执行使用 `StrictHostKeyChecking=yes`，不回退到全局或 `/dev/null` 信任。

显式 pin 的替换同样必须提交新的 owner-approved binding；重新发现时未出现选定 fingerprint、profile 被篡改或后续 host key 变化，均 fail closed。这样保留了有意选择 TOFU 的现有 Agent 流程，同时提供可测试的高保证路径。

## ApprovalTicket

审批票据是一次性、默认 90 秒有效的本地 actor 状态。票据绑定：

- operation hash、action、Secret reference IDs
- 规范化目的地、端口、协议
- command hash、HTTP method/path、数据库首操作、file target
- issued/expiry 时间和 nonce

批准完成后，服务只消费与原描述符完全匹配的票据。修改 Secret、目标、命令、URL、HTTP method 或文件目标都会使旧票据失效；消费后不能 replay。

普通 `AUTO` 操作不建立 execution authorization scope，也不读取或检查 300 秒 lease；首次 Secret 使用、operationID/sessionID 变化、时间超过旧窗口或更换同一 principal 允许的 Secret，都不会单独触发审批。`reusableApproval` 仅作为旧 IPC/审计值保留，进入策略边界后归一化为 `none`，不能重新创建普通 lease。

真正需要 owner 决定的操作使用一次性的 `freshApprovalRequired` 票据。票据绑定调用主体、完整的 `secret://` 引用集合、规范化目标和端口、协议、执行动作类型、operation hash 以及 security generation；修改操作效果、Secret 集合、目标、命令、URL、HTTP method 或文件目标会使旧票据失效，消费后不能 replay。安全代际变化仍会撤销 pending approval 和受保护运行时状态。

SSH `sessionID` 只表示 transport reuse hint。它不能授予权限，也不能替代每次 operation 的 principal、Secret catalog binding、executor preflight 和 policy evaluation。SSH batch 同样只是连接/协议开销优化，不是规避审批的必要条件。

本地明文导出属于 non-downgradable `freshApprovalRequired` 操作，每次都需要设备所有者确认，不建立会话级 execution grant。明文显示和复制同样保持 exact、one-shot 认证。

## 明文边界

低风险解密发生在 `SVLTAgent` 的进程内。MCP 只发送 `SecretOperationDescriptor`，其中包含不透明 `secret://` 引用和非敏感参数；普通 Agent IPC 的类型和响应中不存在 `restoreReferences`、`RestoredParagraph` 或其他明文返回形状。需要本地 UI 明文的 session reveal、Catalog 字段 reveal 和 restore 只通过额外的、经过代码签名身份校验的 App-control socket 传输。专用 executor 只返回脱敏结果，并拒绝把 SVLT 派生 Secret 传入通用 shell、CLI 参数、环境变量或日志；HTTP credential-shaped query 只能通过 typed request 进入 fresh owner approval，不能由 Agent 拼接派生明文。用户独立提供的明文不由 SVLT 与 `secret://` 做值比较，但仍受选定工具、仓库和工作区安全规则约束。

危险操作的认证使用 macOS `deviceOwnerAuthentication`，由系统选择 Touch ID 或登录密码 fallback。审批提示只显示动作、目标、Secret label 和风险原因，不显示 Secret 内容。

## 当前边界

SSH、HTTP/API、SFTP/SCP 和私有地址 FTP 的 purpose-built executor 已接入 Agent；数据库、浏览器和本地 App 的策略与不透明 IPC 描述符已接入，但对应 executor 仍返回 `ACTION_EXECUTOR_UNAVAILABLE`，不会降级到明文或通用命令。FTP 不支持公网目标，且每笔请求都需要设备所有者重新认证。已有 Secret 的精确目标/协议绑定通过 `secret_bind_destination` 完成：它以原子 pair 写入经过认证的绑定元数据，只在 Agent 进程内重封装，不建立执行会话授权；成功响应返回实际保存的 canonical destination，并在显式 pin 时返回非敏感的 port/pin 元数据。`secret_review_ssh_host_key` 只返回当前展示的 host-key 指纹，不解析 Secret。真实 SSH/SFTP/FTP 验收需要在有明确绑定的测试 Secret 和设备可达时执行；自动化测试覆盖目标形态与风险决策，不伪造真实设备成功结果。
