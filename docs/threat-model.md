# RiskProof 威胁模型与产品故事

最近更新：2026-07-27

## 一句话定位

> **让每一次 MCP 工具调用，带着证据再执行。**

RiskProof 是 MCP/Agent 工具链的确定性执行控制层。它位于 Agent 与真实工具之间，
在不可信内容变成邮件、网络请求、命令、文件、数据库或浏览器副作用之前，组合参数
来源、数据标签、权限范围、调用序列和组织策略，返回 `allow`、`ask_approval` 或
`block`，并生成可审计 proof。

RiskProof 不以“模型永远能识别提示注入”为安全前提。模型负责完成任务；RiskProof
负责决定这条工具链被允许对真实系统做什么。

## 1. 为什么安全单元已经改变

过去，LLM 判断错误通常意味着答案错误。MCP 把 LLM 变成工具编排器后，错误判断
可以获得文件、数据库、网络和命令执行权限。此时，网页、邮件或共享文档中的文本
不再只是数据，也可能成为一段隐藏的工具链控制逻辑。

论文 *Parasites in the Toolchain: A Large-Scale Analysis of Attacks on the MCP
Ecosystem*（arXiv:2509.06572v5，论文附录含 IEEE S&P 2026 meta-review）把这一类
问题形式化为 Parasitic Toolchain Attack，并以 MCP Unintended Privacy Disclosure
（MCP-UPD）为主要实例：

```text
External Ingestion Tool (EIT)
外部网页、邮件、帖子或共享内容进入上下文
                 │
                 ▼
Privacy Access Tool (PAT)
读取本地文件、配置、环境、历史消息或私有业务数据
                 │
                 ▼
Network Access Tool (NAT)
通过邮件、HTTP、协作平台或发布工具把数据送出
```

每个工具都可以是正常、可信、甚至官方示例中的工具。风险来自它们在同一上下文中的
组合，而不是某个组件单独“看起来恶意”。因此：

> **工具可信，不等于工具组合安全。**

真正需要授权的对象是一条具体的数据流和权限跃迁：

```text
什么来源
  → 影响了哪个参数
  → 调用了什么能力
  → 访问了什么资源
  → 数据将流向哪里
```

## 2. 论文结论与证据边界

下表中的数字属于论文样本，不是 RiskProof 自己的产品评测结果。

| 论文观察 | 结果 | 正确解释 |
|---|---:|---|
| 公开样本 | 1,360 个 Server、12,230 个 Tool | 只覆盖作者能够批量部署的公开样本，不等于完整生态 |
| 动态确认的相关 Tool | 1,062 / 12,230（8.7%） | 工具具备可被攻击链利用的能力，不代表工具本身恶意 |
| 至少含一个相关 Tool 的 Server | 370 / 1,360（27.2%） | 生态中可组合的攻击组件并不罕见 |
| 构造的工具链 | 9 / 10 至少成功一次 | 不是“单次攻击成功率 90%”；Table 7 合计为 36/100 次 |
| 代表性跨模型/客户端实验 | 5 / 7 模型、5 / 5 客户端至少出现一次成功 | 只针对一个工具链、三个 prompt、特定版本与自动执行配置 |

论文明确验证的主线是隐私外泄。Remote Command Execution 和任意文件写入/持久化
出现在论文 Future Work 中，不能描述成同等规模的已验证结论。作者提出的
context-tool isolation、least privilege、cross-tool auditing 也是潜在防御方向；论文
没有给出一套防御系统的阻断率或误报率。

## 3. RiskProof 保护的两条禁止流

RiskProof 将论文三阶段攻击归纳为两个互补的信息流约束：

```text
完整性：低可信内容 ─────────────X────────────▶ 高权限动作
         网页/邮件/工具描述                     Shell/写文件/数据库变更

机密性：高敏感数据 ─────────────X────────────▶ 低可信外部目标
         Secret/PII/源码/客户数据               邮件/HTTP/发布工具
```

完整 MCP-UPD 正好把两条禁止流连接起来：

```text
不可信外部内容 → 私密读取 → 敏感数据 → 外部披露
```

这比“扫描 prompt 是否恶意”更稳定，也比“逐个判断工具是否可信”更接近真实执行
边界。

## 4. 当前实现：从单次 proof 到工具链 proof

### 4.1 单次调用控制

当前引擎在执行前完成：

- JSON 边界和复杂度校验；
- provenance 与 taint 传播；
- capability 与 invariant 检查；
- 内建规则、配置规则和 OPA/Rego 单调聚合；
- `allow`、`ask_approval`、`block` 三态裁决；
- 脱敏解释、UI-neutral 结构化风险说明和可选加密/签名 proof。

### 4.2 MCP 上下文追踪

同一代理实例会对 `resources/read`、`prompts/get` 和成功 `tools/call` 的返回建立
有界内存索引。后续参数通过确定性精确子串映射回 `webpage_1`、`source_code_1`
等来源。原始内容不会进入工具链事件历史或诊断接口；只有类型、digest、长度和
上下文 ID 等元数据被保留。

### 4.3 新增的跨工具序列守卫

`ToolchainGuard` 从工具的 name、description 和 inputSchema 保守识别三种能力：

- `external_ingestion`；
- `private_data_access`；
- `external_disclosure`。

分类结果只是风险信号，**永远不能授予权限**。默认序列窗口为最近 12 次调用，历史
最多保留 128 条元数据事件：

| 已观察路径 | 默认动作 | 原因 |
|---|---|---|
| 单工具同时具备 EIT + PAT + NAT | `ask_approval` / critical | 工具可能在内部独立完成攻击链，但仅凭 metadata 尚不能证明攻击 |
| EIT → PAT | `ask_approval` / high | 不可信上下文之后发生私密权限跃迁 |
| EIT → PAT+NAT 组合工具 | `ask_approval` / critical | 中间值可能从未暴露给参数级 provenance |
| EIT → PAT → NAT，未确认数据边 | `ask_approval` / critical | 能力路径完整，但当前证据不足以证明具体外发内容 |
| EIT → PAT → NAT，外发参数携带 PAT 来源或敏感 taint | `block` / critical | 已有完整路径和数据证据，普通审批不能覆盖 |

只有实际转发且成功返回的调用才会成为完成事件；失败调用会回滚事件。并发调用在
转发前先保留 `pending` 元数据事件，降低并行请求绕过序列判断的机会。

### 4.4 其他本轮边界加固

- MCP 示例只向 Agent 暴露 RiskProof 包装入口，原始 Server 不再并列注册；
- 上游 MCP 子进程默认只继承启动所需的最小环境变量，不再继承 AWS、GitHub、npm、
  数据库或任意未知父进程 secret；业务变量必须显式传入；
- 完整 tool descriptor（包括 input/output Schema、annotations、`_meta` 和未来字段）
  进入 canonical SHA-256 commitment；重名、pinned manifest 不匹配、后续新增和
  rug pull 会进入粘滞隔离，直接调用也无法绕过；
- 可选 Host-held `TaskAuthorizationGuard` 将 exact tool、descriptor digest、允许来源、
  expiry、任务/单工具调用预算绑定为不可由工具输出扩张的任务合同；pending 调用先
  reserve，失败释放，成功才消费；
- 双向 MCP 方法使用显式 allowlist：未知 client request 默认 `-32601`，Sampling、
  Elicitation、Roots 和自定义 server request 不会下发客户端，initialize capabilities
  被收窄，未匹配或夹带 method 的 upstream response 被丢弃/规范化；
- `recipient`、`endpoint`、`cmd` 等 sink alias 已纳入策略，并新增云 metadata/link-local
  SSRF 与系统配置、启动项、计划任务等持久化位置的 critical deny；
- 关键词式 tool poisoning 扫描继续作为纵深信号，但不再承担工具身份或来源认证；
- 结构化解释 API 会输出因果风险路径、证据覆盖度、现实后果和降险建议，同时只接收
  已脱敏的裁决结果。

## 5. 当前覆盖矩阵

| 威胁/控制 | 当前状态 | 说明 |
|---|---|---|
| 工具描述/Schema 常见投毒 | 已覆盖一部分 | 关键词隔离是纵深防御，不是恶意 Server 证明 |
| 完整 descriptor rug pull / 同快照重名 | **已覆盖第一版** | 进程内 TOFU 或 pinned manifest；sticky quarantine；分页尚非原子快照 |
| 首次 Server 来源认证 / 后端行为证明 | **未实现** | TOFU 和 descriptor hash 均不能提供这两项保证 |
| Host-held task tool/version/source/expiry/budget | **已覆盖第一版** | 程序化 Host 或 `--task-contract`；结构授权，不是语义目标证明 |
| Task alignment 语义 oracle | **未实现** | `objectiveDigest` 只绑定可信目标表示，不判断轨迹是否真正服务目标 |
| 单次不可信内容 → Shell/变更工具 | 已覆盖 | provenance/taint + 确定性策略 |
| Secret/敏感数据 → 外部邮件/HTTP | 已覆盖 | 支持来源和内容检测；仍需真实 egress/DLP 纵深防御 |
| 同一 proxy 内 EIT → PAT → NAT | 已覆盖第一版 | 有界 metadata 状态机；确认数据边时默认 block |
| 单工具覆盖 EIT/PAT/NAT | 已覆盖第一版 | critical step-up，不凭 metadata 直接认定恶意 |
| 跨多个独立 proxy/Server 的链 | **未完整覆盖** | 各 CLI proxy 进程当前没有共享 session ledger |
| 有损摘要、翻译、编码后的 provenance | 部分覆盖 | 可信集成可声明单调 flows；无法观察 opaque LLM reasoning |
| 真正的 context-tool isolation | **未实现** | 当前是在执行边界提供补偿性信息流约束 |
| 签名、一次性、参数绑定的审批 | **未实现** | unsigned decision 只适合显式开启的本地可信 MVP |
| 恶意 MCP Server 进程沙箱 | **未实现** | 环境已最小化，但仍需容器/OS 沙箱和出站网络策略 |
| HTTP 身份认证、租户隔离、限流 | **未内建** | 只能置于可信本地/sidecar 边界或认证网关之后 |
| Sampling/Elicitation 等双向 MCP 原语 | **默认阻断第一版** | 双向 allowlist 已启用；尚无独立授权处理器和完整版本协商 |
| 未知/custom MCP request 与恶意 response 混淆 | **已覆盖第一版** | 未知方法拒绝、unmatched response 丢弃、合法 response 规范化 |
| 云 metadata SSRF / 系统持久化位置 | **已覆盖规则层** | critical deny；不替代实际 DNS/egress/filesystem sandbox |
| RCE、任意写、持久化 | 部分覆盖 | 危险 Shell/写入规则是纵深防御，不替代 sandbox |

最重要的诚实边界是：一个 stdio CLI proxy 只能看到自己的 upstream。论文典型链可
跨 Web、Filesystem、Gmail 三个 Server；在多个独立 proxy 进程之间没有共享 ledger
前，不能宣称完整防御跨 Server MCP-UPD。程序化 Host 可以共享一个导出的
`ToolchainGuard`，但生产架构仍需要稳定的 session/task 身份和集中 provenance。

## 6. 论文之外不能遗漏的攻击面

MCP-UPD 不是完整的 MCP threat taxonomy。产品路线还必须考虑：

- 恶意 MCP Server 在初始化或启动阶段直接读文件、环境和出网；
- Tool Poisoning、Name Collision、Shadowing、Rug Pull 和依赖投毒；
- OAuth scope 错配、Token 生命周期、Confused Deputy 和跨租户权限；
- Transport/MITM、远程 Server 认证与协议版本降级；
- Resources、Prompts、Sampling、Elicitation 等非 `tools/call` 原语；
- 删除、交易、代码提交、生产发布等完整性风险；
- DoS、Token/云费用、磁盘 proof 容量等可用性与经济风险；
- 长期 memory 污染、跨 session 污点和多 Agent 委托中的权限扩散；
- 审计日志自身的敏感数据、密钥生命周期、回滚与事件响应。

## 7. 产品分层与差异化

```text
Tool Registration Hygiene
        ↓
Tool Identity / Manifest Continuity
        ↓
Trusted Task Contract
        ↓
Provenance & Data Labels
        ↓
Deterministic Per-call Policy
        ↓
Cross-tool Sequence Enforcement
        ↓
Least-Privilege Authorization
        ↓
Chain Proof & Audit
```

- 相比 Prompt Guardrail：它保护模型的文本；RiskProof 保护模型对真实系统的执行权。
- 相比 MCP 静态扫描：它判断组件是否可疑；RiskProof 判断本次具体组合是否形成未经
  授权的数据流。
- 相比普通 HITL：RiskProof 先确定性阻断明确违规，只把证据不足的真实例外升级给
  可信审批者。
- 相比 OPA：OPA 是策略计算器；RiskProof 把 MCP provenance、taint、capability 和
  toolchain state 变成策略能够使用的安全输入。
- 相比 Observability：它回答“昨天发生了什么”；RiskProof 回答“这个动作现在为何
  不应执行”。
- 相比 Sandbox/DLP/Auth：RiskProof 不替代它们，而是生成执行前决策和 proof，与
  它们形成纵深防御。

`proof` 表示结构化决策证据，不是数学形式化证明。HMAC 可以提供共享密钥下的防篡改
检查，但不是公开不可抵赖签名。

## 8. 下一阶段路线

### P0：从 same-proxy 扩展到 host-level toolchain

1. 由一个 Host Gateway 管理多个 MCP upstream，或让多个 proxy 通过本地 sidecar
   共享按 `sessionId/taskId` 隔离的 provenance ledger；
2. 为 Tool 建立 operator-approved `ToolProfile`：EIT/PAT/NAT、读写/执行效果、资源
   root、目标域名、HTTP method、数据类别和账号 scope；
3. 实现签名或本地一次性 approval ticket，绑定 proof ID、server/tool/schema digest、
   canonical args digest、用户/任务、expiry、nonce 和 single-use 状态；
4. 将当前进程内 TOFU 提升为 origin-scoped、可持久化和可签名的 operator manifest，
   并对真正分页的 `tools/list` 做原子 snapshot 聚合；
5. 增加 selection integrity：候选工具按 provider/origin policy 和 capability fit
   确定性路由，安全决策不依赖“best/official/authoritative”等自声明营销语义；
6. 将 evaluation、dispatch、success/failure 连接成连续执行 receipt，而不只记录
   “曾被允许”。

### P1：验证真实可利用性和可用性

- 建立 EIT→PAT→NAT、EIT→RCE、EIT→启动文件写入的 synthetic canary 基准；
- 覆盖直接、礼貌、编码、混入正常内容和有损转换；
- 加入良性相似任务，测量 false block 与审批疲劳；
- 在沙箱中做 Tool 动态能力验证，不把 LLM 分类直接作为阻断事实；
- 与网络 egress、DLP、文件沙箱和企业身份系统联动。

## 9. 北极星指标

| 指标 | 定义 |
|---|---|
| Toolchain Attack Prevention Rate | 攻击试验中 canary 未到达外部、命令未执行、持久化未生效的比例 |
| Stage Containment | 攻击在 ingestion、collection、disclosure 的哪一阶段被阻断 |
| Deterministic Block Share | 无需依赖人工决定即可阻断的攻击比例 |
| Cross-Server Coverage | 跨多个 Server 的攻击链能够连续追踪和阻断的比例 |
| Provenance Precision / Recall | 参数来源映射的正确率与覆盖率 |
| Transformation Survival | 摘要、翻译、拼接、编码后仍保留标签的比例 |
| Benign Task Completion Rate | 合法组合任务最终完成的比例 |
| False Block / Approval Rate | 良性任务被阻断或升级审批的比例 |
| Chain Proof Completeness | proof 是否包含 ingestion 到最终 sink 的必要证据边 |

合成 fixture 全通过只能证明这些固定场景符合预期，不能表述为真实业务“零误报、
零漏报”。论文生态数字也只能用来说明问题广泛，不能当成 RiskProof 的覆盖率。

## 10. 推荐对外文案

### Hero

> **让 MCP 工具调用带着证据再执行**
>
> 外部网页、邮件和工具返回，不应自动获得读取文件、发送数据或执行命令的权力。
> RiskProof 在 Agent 与真实工具之间追踪参数来源、识别不可信与敏感数据、约束跨工具
> 权限跃迁，并在副作用发生前 Allow、Step-up 或 Block，同时生成可审计 Proof。

### 30 秒介绍

MCP 把 LLM 从文本生成器变成了工具链编排器。新的风险不只是某个工具有毒，而是
网页、文件、邮件和 Shell 等正常工具被寄生指令串成攻击链。RiskProof 位于 Agent
和工具之间，追踪调用参数来自哪里、包含什么数据、是否符合当前任务授权，再用确定性
规则和 OPA 在执行前放行、升级审批或阻断。当前版本已经从单次调用 proof 演进到
同一代理内的工具链序列控制；下一阶段是跨 Server 的连续 provenance 和任务级最小
权限。
