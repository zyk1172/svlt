# SVLT 操作授权模型

SVLT 不再把 `locked` 当作 Agent 的全局工作流门禁。`locked` 只保留在兼容状态中；Agent 应读取 `available`、`ready` 和 `approvalPending`，然后直接提交具体的受保护操作。

## 决策流程

每个使用 SVLT-managed Secret 的请求都经过同一条本地路径。用户明确选择其他 provider 或当前明文的操作不由 SVLT 强制接管，也不应被已有 Catalog 记录抢占：

```text
opaque descriptor
  -> normalize destination / command / path
  -> SecretOperationPolicyEngine
  -> local requirement: none | reusableApproval | freshApprovalRequired
  -> AgentRiskAssessment shown as display/audit metadata only
  -> technical failure or owner approval / session-scoped grant
  -> capability preflight
  -> exact device-owner approval or session-scoped execution grant
  -> latest policy check
  -> resolve and execute
```

`AgentRiskAssessment` 只有显示和审计作用，不能升级、降级或拒绝本地策略已经计算出的授权结果。技术性错误（格式、引用集合、目标字段或身份不可验证）会在认证前失败；其他技术上可执行的请求由设备所有者通过 Touch ID/密码决定。

## 风险规则

| 操作 | 默认状态 | 关键条件 |
| --- | --- | --- |
| 状态、使用策略、引用元数据 | `silent` | 不解密、不返回 Secret |
| 已绑定或未绑定目标的 Secret-bearing SSH/数据库/SFTP 操作 | `reusableApproval` | 首次认证建立当前 scope 的会话级授权；不设固定时间超时，目标/协议提示不额外升级 |
| SSH 电源控制、文件删除、块设备/文件系统破坏、存储/RAID 破坏、容器破坏 | `freshApprovalRequired` | 只匹配固定五类；raw shell、多行、wrapper 和未知命令本身不构成额外类别 |
| Secret-bearing HTTP/API 网络发送（包括公网 HTTPS） | `freshApprovalRequired` | 显示精确目标并由设备所有者决定；不按 hostname 推断公网/私网 |
| HTTP `DELETE`、明文 `http://` 携 Secret、凭据 query 参数 | `freshApprovalRequired` | 固定 HTTP fresh registry；明文 HTTP 还须匹配保存的 scheme/host/port profile；任何 redirect 只是 transport stop |
| 数据库明确只读语句（SELECT/SHOW/EXPLAIN 等） | `reusableApproval` | 只读语句共享 `database.read` 操作族，不要求每条查询重新认证 |
| 数据库 INSERT、SELECT INTO、schema/session maintenance | `reusableApproval` | 仅在对应的窄操作族内复用，不能借用 `database.read` 或其他数据库操作族 |
| 数据库 DELETE/UPDATE/MERGE、DROP/TRUNCATE/破坏性 ALTER、权限账户管理、动态执行或外部文件边界 | `freshApprovalRequired` | 固定数据库 fresh registry；CTE 和嵌套语句也会被检查 |
| 未知或不可解析的数据库 SQL | `freshApprovalRequired` | 保守地要求一次性设备所有者认证，不自动拒绝，也不建立普通可复用会话授权 |
| SFTP 删除、覆盖、替换目标 | `freshApprovalRequired` | 固定 SFTP fresh registry |
| Secret-bearing 明文 FTP | `freshApprovalRequired` | 仅回环/私有目标；每次重新认证，不建立可复用会话授权 |
| 为已有 Secret 增加精确目标/协议绑定 | `freshApprovalRequired` | App 显示 exact scheme/host/port；在进程内重新封装认证元数据，不解密出 IPC、不建立执行会话授权 |
| 明文显示、复制、删除或安全设置变更 | `freshApprovalRequired` | 使用 `deviceOwnerAuthentication` |
| `localExecution`（交给任意本地进程） | `freshApprovalRequired` | 明确标记 `userApprovedSecretRelease`，由设备所有者决定 |

Secret metadata 保留旧版兼容字段 `allowedDestinations` 和 `allowedProtocols`；新绑定同时写入经过认证的 `allowedBindings`，每个元素把 protocol 和 destination 作为一个不可拆分的 pair。存在 `allowedBindings` 时，HTTP/其他 pair-sensitive 检查只使用它；无法从混合旧数组安全还原 pair 时 fail closed，不生成笛卡尔积。普通目标/协议绑定不匹配是提示并进入新的 scope，元数据缺失或引用集合无法验证才是策略层技术性失败。对携 Secret 的明文 HTTP，执行器在设备所有者审批之后还会要求每个引用都匹配保存的精确 `scheme://host:port` profile；这只防止 profile 横向扩大到另一台主机或端口，不把 hostname 当作 DNS/实际 egress 证明。HTTP 不自动跟随任何重定向，发现新目标时必须重新提交一个独立操作；响应 body、`Location`、`Content-Type` 命中 Secret fingerprint 时整次输出 quarantine。认证响应默认只返回元数据；只有明确请求 `includeBodyPreview` 时，才允许最多 16 KiB 且必须是无敏感字段名、无 `secret://` 的合法 JSON 预览，否则 quarantine。更严格的字段投影仍由 App-owned profile 控制。

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

对可执行的 `reusableApproval` 操作，设备所有者完成一次认证后，SVLT 建立一个仅存在于当前 Agent 安全会话中的 scope grant。它绑定调用主体、完整的 `secret://` 引用集合、规范化目标和端口、协议、执行动作类型以及 security generation；它不是全局授权，也没有固定 TTL。时间流逝本身不会使授权失效，因此不再存在“300 秒内自动放行、超时后重新审批”的行为。每个后续请求仍会先做 executor capability preflight，再重新读取 metadata 和执行策略；高风险或 `freshApprovalRequired` 操作仍然逐次认证。

会话级授权只会在安全边界变化时失效，包括锁屏、睡眠、用户会话切换/注销、显式锁定、Agent 进程重启、安全代际变化或该 scope 被明确撤销。远端执行失败、transport/session 失败以及普通请求之间的空闲时间都不会撤销已经建立的 owner grant。与 scope 对应的解密 capability 只保存在内存中，并与授权状态一起失效。

这里的 reusable grant 是明确的 scope grant，而不是“只批准屏幕上这一条命令”的 exact-operation grant。这样可以让 Agent 连续完成同一主机/同一凭据任务，而不会因为任意计时器再次打断用户；每个后续请求仍重新经过固定高危规则。数据库 scope 继续按窄操作族隔离；DELETE/UPDATE/MERGE、管理权限、动态执行以及未知 SQL 不会创建 reusable grant。

本地明文导出属于 non-downgradable `freshApprovalRequired` 操作，每次都需要设备所有者确认，不建立会话级 execution grant。明文显示和复制同样保持 exact、one-shot 认证。

## 明文边界

低风险解密发生在 `SVLTAgent` 的进程内。MCP 只发送 `SecretOperationDescriptor`，其中包含不透明 `secret://` 引用和非敏感参数；普通 Agent IPC 的类型和响应中不存在 `restoreReferences`、`RestoredParagraph` 或其他明文返回形状。需要本地 UI 明文的 session reveal、Catalog 字段 reveal 和 restore 只通过额外的、经过代码签名身份校验的 App-control socket 传输。专用 executor 只返回脱敏结果，并拒绝把 SVLT 派生 Secret 传入通用 shell、CLI 参数、环境变量或日志；HTTP credential-shaped query 只能通过 typed request 进入 fresh owner approval，不能由 Agent 拼接派生明文。用户独立提供的明文不由 SVLT 与 `secret://` 做值比较，但仍受选定工具、仓库和工作区安全规则约束。

危险操作的认证使用 macOS `deviceOwnerAuthentication`，由系统选择 Touch ID 或登录密码 fallback。审批提示只显示动作、目标、Secret label 和风险原因，不显示 Secret 内容。

## 当前边界

SSH、HTTP/API、SFTP/SCP 和私有地址 FTP 的 purpose-built executor 已接入 Agent；数据库、浏览器和本地 App 的策略与不透明 IPC 描述符已接入，但对应 executor 仍返回 `ACTION_EXECUTOR_UNAVAILABLE`，不会降级到明文或通用命令。FTP 不支持公网目标，且每笔请求都需要设备所有者重新认证。已有 Secret 的精确目标/协议绑定通过 `secret_bind_destination` 完成：它以原子 pair 写入经过认证的绑定元数据，只在 Agent 进程内重封装，不建立执行会话授权；成功响应返回实际保存的 canonical destination，并在显式 pin 时返回非敏感的 port/pin 元数据。`secret_review_ssh_host_key` 只返回当前展示的 host-key 指纹，不解析 Secret。真实 SSH/SFTP/FTP 验收需要在有明确绑定的测试 Secret 和设备可达时执行；自动化测试覆盖目标形态与风险决策，不伪造真实设备成功结果。
