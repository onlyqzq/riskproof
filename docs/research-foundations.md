# RiskProof 研究底座：从 MCP 寄生工具链到可验证执行控制

最近核验：2026-07-27

本文不是市场宣传稿，也不是把论文中的攻击成功率换成产品覆盖率。它回答三个更难、也更适合答辩的问题：学术界已经证明或测量了什么；这些证据能支持哪些安全性质；RiskProof 当前代码究竟实现到哪里，下一步怎样形成一套能讲、有深度、能安全演示、也经得住追问的系统。

所有论文数字都保留原始分母和实验边界。本文中的 `proof` 是结构化决策证据，不是数学证明；“形式化安全性质”是可检验的工程规范，不表示当前实现已经通过机器证明。

## 0. 结论先行：产品不应只是一个 MCP scanner

RiskProof 最有说服力的定位不是“再做一个恶意 prompt 分类器”，而是：

> **RiskProof 是 MCP/Agent 的执行证据与控制平面：把工具身份、任务授权、选择路径、参数来源、数据标签、跨工具信息流和实际执行结果连接起来，在副作用发生前做确定性裁决，在副作用发生后给出可核验的连续证据。**

这个定位来自现有研究共同暴露的三个断层：

1. **组件可信不等于组合安全。** 正常的网页读取、私有文件访问和邮件发送工具，可以被组合成 EIT → PAT → NAT 隐私外泄链。
2. **工具被签名不等于工具会被正确选择或忠实执行。** 合法提供方仍可用宣传性描述操纵选择；签名描述符也不证明后端按描述运行。
3. **可疑信号不等于已发生攻击。** metadata 中的危险词、返回中的凭据样式字符串或 `/etc/passwd` 文本，只能产生假设；执行型结论需要安全 canary、沙箱反馈或其他运行时证据。

因此，产品故事应从“发现危险文本”升级为“约束权限如何随任务、来源和数据流动”。六层目标架构如下：

```text
1. Tool Identity & Descriptor Admission
                 ↓
2. Selection Integrity
                 ↓
3. Task-Bound Authorization & Least Privilege
                 ↓
4. Deterministic Per-Call Reference Monitor
                 ↓
5. Cross-Call Provenance Graph & Compositional Policy
                 ↓
6. Bidirectional Evidence, Execution Receipt & Conformance
```

当前代码已经具备第 1 层的“描述符连续性”、第 3 层的 opt-in 任务合同第一版、第 4 层的确定性单次裁决，以及第 5 层的同一 proxy 第一版；第 2 层和第 6 层的完整形态仍是路线图。任务合同已进入真实 proxy 生命周期，但 CLI 只把本地合同文件当作 Host 侧可信输入，不认证用户，预算和事件状态也只存在于当前进程。这个边界本身可以成为可信产品故事的一部分。

## 1. 研究问题

- **RQ1：攻击单元是什么？** 是单个恶意 Tool，还是跨 Tool、跨 Server、跨调用的数据流和权限跃迁？
- **RQ2：谁在获得执行权？** 如何区分工具名称、完整描述符、提供方、Server 实例、后端实现和运行时进程身份？
- **RQ3：为什么选择了这个工具？** 候选集、能力匹配、排序特征和模型选择是否可追溯，是否会被描述性宣传或隐式 metadata 操纵？
- **RQ4：这次调用是否仍属于用户批准的任务？** 用户目标如何绑定到允许的工具、参数、数据来源、调用预算、有效期和目的地？
- **RQ5：数据来自哪里、将去往哪里？** 如何同时约束“不可信输入 → 高权限动作”的完整性流和“敏感数据 → 未授权外部目标”的机密性流？
- **RQ6：跨调用怎样组合？** 单次均合法的调用在组合后是否形成未授权路径；安全证据新增时，权限能否保证只保持或收紧？
- **RQ7：信号怎样升级成证据？** semantic suspicion、静态可达路径、沙箱 canary、真实 dispatch 结果和可审计 receipt 如何分级？
- **RQ8：远程 MCP 的信任入口在哪里？** OAuth issuer/audience、PKCE、redirect URI、DCR、token scope 与 Server admission 如何进入同一个授权模型？
- **RQ9：怎样证明产品有效而不夸大？** benchmark 的 corpus、模型、Host、重复次数、成功定义、技术错误、良性效用和 out-of-scope 如何固定分母？

## 2. 从 *Parasites in the Toolchain* 出发的研究谱系

*Parasites in the Toolchain* 把风险单元从“单个恶意工具”推进到“正常工具组成的寄生链”。后续及相邻研究分别补上 metadata 选择、身份与授权、双向数据流、动态证据、生态测量和 benchmark：

```text
外部内容进入 Agent
  ├─ InjecAgent / AgentDojo / CaMeL：间接注入、动态环境、控制流/数据流隔离
  │
  ├─ MCP-ITP / MPMA / Confused Deputy：metadata 可操纵合法工具选择和参数
  │                                      └─ Selection Integrity
  │
  ├─ Parasites / Les Dissonances / DSCC：风险在跨工具组合中出现
  │                                      └─ Provenance Graph + Composition
  │
  ├─ ETDI / AIP / Formal Policy Enforcement：身份、scope、任务合同、委托
  │                                      └─ Task-Bound Capability
  │
  ├─ MCP Safety Audit / SHIELD / FlowGuard：扫描、运行时守卫、证据确认
  │                                      └─ Signal ≠ Evidence ≠ Receipt
  │
  └─ First Glance / Privilege / Auth / Privacy / Unsafe by Flow
                                         └─ Admission、最小权限、双向 DLP
```

这条谱系带来的核心判断是：**MCP 安全不能只停留在 registration-time scanner，也不能只依赖模型在 planning-time 识别恶意意图；必须在 operation-time 的真实执行边界保留身份、授权、来源和数据流证据。**

## 3. 核心论文：结论、边界与产品含义

### 3.1 组合攻击：*Parasites in the Toolchain*

论文把 MCP Unintended Privacy Disclosure（MCP-UPD）建模为 External Ingestion Tool（EIT）→ Privacy Access Tool（PAT）→ Network Access Tool（NAT）的寄生工具链。它最重要的发现不是“某个 Tool 恶意”，而是模型上下文允许不可信内容把多个各自正常的权限拼接起来。

| 论文观察 | 原始分母 | 可以得出的结论 | 不能泛化为 |
|---|---:|---|---|
| 可批量部署样本 | 1,360 Server、12,230 Tool | 公开生态存在可组合攻击面 | 完整 MCP 生态规模或真实部署占比 |
| 动态确认相关 Tool | 1,062 / 12,230（8.7%） | 一部分工具具备 EIT/PAT/NAT 相关能力 | 8.7% 工具是恶意工具 |
| 至少一个相关 Tool 的 Server | 370 / 1,360（27.2%） | 可组合组件并不罕见 | 27.2% Server 已被利用 |
| 构造工具链 | 9 / 10 至少成功一次；Table 7 合计 36 / 100 | 多种组合在受控实验中可利用 | “单次 ASR 为 90%”或真实生态攻击率 |

论文大规模实证主线是隐私泄漏。RCE、任意写和持久化主要位于 Future Work，不能描述为同等规模的实证结论。它直接支持 RiskProof 的同一 session 跨调用状态、参数 provenance、敏感标签和最终 sink 控制；但当前多个独立 stdio proxy 不共享 ledger，不能声称已完整防御跨 Server MCP-UPD。

### 3.2 Metadata 与选择完整性：MPMA、Confused Deputy、MCP-ITP

**MPMA** 证明工具描述不只是说明文字，也是模型选择器的输入。在每个竞争环境中，1 个恶意工具与 5 个同功能工具竞争，随机基线为 1/6（16.67%）；实验覆盖 8 类真实 MCP Server 功能、每类 10 个查询、5 个 LLM。GAPMA 的模型平均结果从 GPT-4o 的 22.19% 到 Gemini 的 91.88% 不等；DPMA 的 “Best Description”在多数设置达到 100%。这些结果只能说明受控同功能竞争中的 preference manipulation，不能外推为真实市场抢占率，也不等于恶意 payload 已执行。

**Confused Deputy Attack Against MCP** 的正式摘要描述 Puppet 通过 selective requirement enrichment、schema transformation 和 name prioritization 操纵 benign descriptor。论文覆盖 14 个模型、6 个提供方和 2 个 MCP Host，报告工具选择劫持最高 90.89%、端到端恶意 payload 执行最高 86.46%。两个数字都是 **up to**，不是均值；截至本文核验时正文闭源，本结论只基于 ACM/Crossref 正式摘要，不能外推到全部模型、Host 和任务。论文声称绕过 MCP-Scan 与 McpSafetyScanner，说明无明显恶意关键词的 metadata 攻击需要确定性 identity/provenance/routing；它不证明语义扫描毫无价值。

**MCP-ITP** 把攻击推进到“恶意 helper 从未被调用，但其描述诱导模型调用合法高权限工具”。作者在 MCPTox 数据集和 12 个 Agent 上报告最高 84.2% ASR、最低 0.3% malicious-tool detection rate。二者同样是受控设置中的极值；论文是预印本，自动优化器、检测器和数据集共同决定结果。产品含义非常明确：只隔离被调用的恶意工具不够，最终合法调用必须绑定任务、精确参数、允许来源和预期效果。

这组三篇共同指出：**工具身份固定仍不等于选择完整。** 一个合法签名的提供方仍可以写“best”“authoritative”等描述操纵排序；一个未被调用的恶意描述也能把权限借给合法 Deputy。

### 3.3 身份与授权架构：ETDI

ETDI 提出 provider cryptographic identity、完整签名 tool definition、不可变语义版本、descriptor/backend API contract hash、OAuth/JWT scope、OPA/Cedar PBAC 和 call-stack policy。它为 RiskProof 的身份与任务授权层提供了很好的架构语言。

边界必须说清：ETDI 是架构/设计论文，没有攻击阻断率或性能 benchmark；签名只能证明“谁声明了什么”，不证明后端按声明执行；在 schema/contract 不变时后端代码仍可能改变；trust root、密钥生命周期、policy engine 和 faithful enforcement 都属于 TCB。

RiskProof 当前 `ToolIdentityGuard` 对完整 descriptor 做 canonical JSON + SHA-256：对象键排序，但字符串内容、数组顺序、`annotations`、`outputSchema`、`_meta`、不可见 Unicode 和未来字段都保留在 digest 中。默认 TOFU 只检测第一次快照后的连续性变化；pinned mode 表示 operator 对精确 name/digest 的批准。**TOFU 不是 origin authentication，pinned digest 也不自动证明公开发布者身份。** ETDI 式 publisher signature、key ID、scope、expiry 和 revocation 是路线图。

### 3.4 攻击面与防御 benchmark：MCPSecBench、MCP Safety Audit、SHIELD MCP

**MCPSecBench** 覆盖 client/protocol/server/host 四个攻击面、17 类攻击，在 Claude Desktop、OpenAI 和 Cursor 三个平台上每个向量执行 15 次。其受控 protocol-side fixture 在三个平台上均出现 100% ASR；Tool Squatting、Tool Poisoning 多项为 100%，Rug Pull 为 73.3%–93.3%。这表示特定实现、模型和配置下的可利用性，不是野外流行率。两种防御 MCIP/FAN 只适用于 17 类中的 11 类；Table 2 的平均 mitigation 17.9% 和 28.9% 不能称为整个 MCP 攻击面的防御率。对 RiskProof 最有用的产物是把 17 类转成 `prevent / detect / evidence / out-of-scope` conformance matrix。

**MCP Safety Audit** 展示 malicious code execution、remote access control、credential theft，以及被污染检索内容驱动 Filesystem、Slack、Everything、Chroma 多 Server 的 RADE 链。McpSafetyScanner 使用 hacker → security auditor → supervisor 三代理、由 GPT-4o 驱动；作者报告在 M2 Max 上每份报告少于一分钟，并能在作者的演示 Server 上发现对应 exploit。论文没有系统 ASR、precision 或 recall；它是 PoC，且明确承认扫描随机性。LLM 生成的漏洞判断应当是 hypothesis/signal，必须由沙箱 canary 或运行时证据确认。

**SHIELD MCP** 给出四阶段运行时蓝图：descriptor integrity、parameter sanitization、response analysis、session-level cross-call correlation。作者自建 40 个 Server（25 benign、15 adversarial）、487 个 attack case、5 个 LLM backend；每个攻击场景每模型重复 3 次，并使用 200 个 benign task。总体 ASR 从 70.9% 降至 9.5%，benign completion 从 98.5% 降至 96.8%（下降 1.7 个百分点），median latency 118 ms、P95 247 ms。边界是：自建 benchmark、每场景仅 3 次、adversarial Server 未公开、classifier 仅英语；3 位专家对预先平衡的 50 个 alert 有 46/50 一致，不能写成总体 precision。“tool signature”本质是 baseline hash，不是 publisher origin signature。

SHIELD 适合当实现蓝图，不适合单独当产品安全保证。RiskProof 当前覆盖其 descriptor integrity、部分 parameter policy 和同进程 session correlation；response-side DLP、动态 evidence adjudication 与公开 benchmark 仍待补齐。

### 3.5 生态测量：代码健康、权限、远程认证与隐私

**MCP at First Glance** 原始收集 1,899 个项目，但过滤少于 10 stars 后，主要分析集是 583 个（61 official、184 community、338 mined）。SonarQube 在 42 / 583（7.2%）repository 中发现至少一个安全 issue，共 277 个 issue、13 个 CWE。动态 `mcp-scan` 随机抽取 83 个，初始成功 60 个，修复环境后成功 73 个；5.5% potential tool poisoning 的实际分母是成功扫描子集，约 4 / 73，不是 1,899。star 过滤排除了大量小项目；SonarQube issue 不必然可利用；scanner 只观察 reflected metadata，无法证明 source/backend behavior；扫描失败必须记为 incomplete/no evidence，不能算 clean。

**We Urgently Need Privilege Management in MCP** 静态分析 2,562 个 MCP app、23 个类别：1,438 个 Server 使用 Network API，1,237 个使用 System Resource API，613 个使用 File API，25 个使用 Memory API；类别可重叠。“使用敏感 API”不是漏洞，AST/parser/regex 也不能证明运行时可达性。它支持 permission profile、resource/destination scope、sandbox 和 egress policy，而不是自动判恶。

**A First Measurement Study on Authentication Security in Real-World Remote MCP Servers** 从 FOFA/Shodan 得到 7,973 个 validated live remote Server：3,233 / 7,973（40.55%）无认证、2,428 使用 OAuth、1,118 宣告 DCR。最终可完整测试的是 119 个 DCR-enabled OAuth Server；119 / 119 至少有一个确认 flaw，共 325 个 flaw，其中 115 / 119 有 Dynamic Client Registration flaw、102 / 119 有 Open Client Environment flaw，并获得 9 个 CVE。这个 119 子集具有明显 DCR/testability 选择偏差，不能外推为全部 2,428 个 OAuth Server 都有漏洞。公开搜索也遗漏 CDN、私网和防火墙后资产。产品路线应包含 Protected Resource Metadata、issuer/audience、PKCE、redirect URI、state、authorization code single-use，以及 DCR/CIMD admission policy。

**“What Happens Locally, Leaks Globally”** 分析 10,655 个 Server，其中 6,657 个含 privacy-related information，工具标记 1,317 个 leakage risk，即全部样本的 12.4%、含敏感信息样本的 19.8%。作者从预测正例中随机抽 200 个，确认 192 个、8 个 false positive；由于没有抽 predicted negatives，不能声称无 false negative，也不能估计 recall。静态 source→sink 可达路径是风险，不代表泄漏已经发生；API key 被送往预期上游 header 可能是正常功能，必须结合 destination 和 purpose。对 RiskProof 的启示是：Tool return、error、log 和 stdout 都是 egress，也是下游 prompt source，需要 response-side taint、redaction 和证据状态。

### 3.6 支撑理论：CaMeL、FORGE、Agent-BOM、AgentDojo、InjecAgent

- **CaMeL** 把可信控制流与不可信数据分开，用 capability/confinement 思路避免让外部内容直接获得控制权。它支持 RiskProof 的架构方向，但 RiskProof 当前只是工具执行边界上的补偿性信息流控制，不是 CaMeL 式完整 context-tool isolation。
- **Formal Policy Enforcement for Real-World Agentic Systems（FORGE）** 把 policy 作为独立于模型 reasoning 的横切关注点，用 Datalog、assume/guarantee contract 和每个 policy-relevant action 上的 reference monitor 进行确定性执行。它支持“先写安全性质，再编译成运行时检查”的方法；该工作仍是预印本，不能据此声称 RiskProof 已经形式化验证。
- **Agent-BOM** 把模型、工具、长期 memory 等 capability base 与目标、reasoning trajectory、action 等 runtime state 组织成分层有向图，以查询路径支持审计。它直接支持 RiskProof 把零散事件升级为跨调用 provenance graph；论文是 2026 年预印本，其具体图模式和 OpenClaw 原型不是行业标准。
- **AgentDojo** 提供动态环境，同时评估攻击、Agent utility 与防御，支持“安全指标必须与合法任务完成率一起报告”。其 fixture、任务和工具分布不能代表所有企业 MCP workload。
- **InjecAgent** 系统化展示不可信 Tool-integrated 内容可以把间接 prompt injection 带入 Agent 行动路径，支持把 Tool response/source 当成安全边界。它的 benchmark 是受控攻击任务，不是野外攻击率。
- **The Task Shield** 把任务对齐作为运行时安全对象，支持 host-held task contract 和动作前检查；但自然语言目标摘要或 digest 只能绑定一个批准表示，不能证明实际调用在语义上完成了用户意图。

### 3.7 2026 前沿工作：直接转化为下一轮实现

| 研究 | 经核验的核心结果 | 必须保留的边界 | 对 RiskProof 的直接动作 |
|---|---|---|---|
| *Unsafe by Flow* / MCP-BiFlow | 在 32 个 confirmed case 中识别 30 个（93.8% recall）；15,452 个 repository 中人工确认 118 条路径、涉及 87 个 Server | 静态可达路径不等于 Agent 端到端利用；真实集只人工复核候选，不能推导全量 recall | registration-time 双向 source/sink admission；运行时 response taint 与 destination/purpose |
| *Securing Multi-Tool AI Agent Chains* / DSCC | 32 个工具、16 个 NIST SP 800-53 对齐 policy；给出“链扩展只能收紧”的 monotonic composition | 79.2%/95.5% 等是 policy 组合被阻断比例，不是攻击阻断率，也不是误报率；预印本 | 将当前单调 decision merge 提升为显式 tool profile policy composition 和 session taint lattice |
| Unicode TAG-block concealment | 5 个 metadata surface、8 种技术；8/8 到达模型，4/8 绕过示例字符串 scanner，只有 TAG-block 同时不可见且到达模型 | 单作者预印本；特定 renderer/client/harness；不是所有模型或 UI 的成功率 | approval view 与 model bytes 做 fidelity commitment；首次安装也做 Unicode/Cf/TAG fail-closed，而不只检测后续 digest 漂移 |
| *FlowGuard: From Signals to Evidence* | 1,880 个可执行 case；Command Injection / File System Access F1 为 0.879 / 0.942；8,000 个 Server 上报告 523 finding、涉及 326 个 Server | category-specific F1 不能当总精度；真实 finding 是报告结果，不等于全部人工确认；预印本 | finding 状态固定为 `semantic_signal / static_path / runtime_confirmed / contradicted / inconclusive`，用无害 canary 确认执行型结论 |
| *Formal Security Analysis of Agent Protocol Composition* / AgentThread | 用来源关联的 TLA+ invariant、模型检查与 SDK replay 分析协议及组合责任 | 2026 预印本；规范 finding 和实现 test 不能直接等价为可利用漏洞 | 为 MCP 方法和跨协议委托写 invariant；把“规范缺失”“实现违背”“责任未分配”分开报告 |
| AIP | invocation-bound capability token、scope attenuation、最大委托深度、expiry、result hash、append-only delegation chain | 单作者预印本；600/600 是合成 protocol-conformance 攻击；localhost 性能；DNS 自签身份文档不替代外部 trust root | 设计 task/agent delegation receipt，但不把 AIP 当成熟标准 |

## 4. 四个安全性质：Task / Action / Source / Data

### 4.1 调用模型

把一次候选调用写成：

```text
c = (τ, u, g, p, s, t, d, a, G, L, H, e)
```

其中：

- `τ`：可信 Host 分配的 task；`u`：用户/主体；`g`：Agent；
- `p`：provider/publisher；`s`：Server 实例；`t`：Tool 名称；
- `d`：完整 Tool descriptor digest；`a`：canonical arguments；
- `G`：参数、上下文、调用和结果组成的 provenance graph；
- `L`：数据 taint/classification；`H`：此前调用历史；
- `e`：预期 effect、资源和 destination。

保守授权谓词为：

```text
Allow(c) ⇒ TaskOK(c) ∧ ActionOK(c) ∧ SourceOK(c) ∧ DataOK(c)
```

它是工程契约：任何一项无法建立，可转为 `ask_approval`、`block` 或 `inconclusive`，但不得默认为已证明安全。

### 4.2 Task Integrity

目标：执行轨迹不能被 MCP 内容、Tool return 或模型自己扩张到 Host 批准任务之外。

最低可检验条件：

```text
TaskOK(c) :=
  contract(τ).notExpired
  ∧ t ∈ contract(τ).allowedTools
  ∧ completed(τ) + pending(τ) < contract(τ).maxCalls
  ∧ completed(τ,t) + pending(τ,t) < contract(τ,t).maxCalls
```

`TaskAuthorizationGuard` 已支持 host-held `taskId`、可选 `objectiveDigest`、expiry、任务/工具调用预算、允许 Tool、可选 descriptor digest 和允许 provenance；`reserve()` 把授权与并发预算预留合在一个同步操作中。它还拒绝 accessor、Proxy、未知字段和超界结构，并只暴露 digest/metadata 事件。

当前已是**实现第一版**，而不再只是独立原型：guard 与类型已从 package `index.ts` 导出；`ProxyOptions.taskAuthorizationGuard` 可由可信 Host 注入；无副作用的 `riskproof/evaluate` 使用只读 `assess()`；真实 `tools/call` 在转发前原子 `reserve()`，用户拒绝、非交互拒绝、JSON-RPC/MCP error、超时或本地转发异常时 `abort()`，上游成功时 `complete()`。如果上游副作用已经成功、但后续本地 provenance 处理失败，预算仍会被消耗，避免把已发生执行错误地“退回”。CLI 提供 `--task-contract <path>`，将本地 JSON 作为 out-of-band Host 合同加载。

诚实边界仍然重要：没有提供合同的 proxy 不会自动获得任务授权；CLI 不认证合同签发者或最终用户，只适合可信本地/sidecar 边界；程序化 Host 可预载 authenticated `trusted_user` context，但模型/MCP metadata 不能自封为可信用户；预算、reservation 和事件目前是单进程内存状态，重启与多个独立 proxy 之间不共享。`objectiveDigest` 只绑定 Host 批准的目标表示，不证明语义任务对齐。

### 4.3 Action Integrity

目标：实际调用的身份、精确参数、资源、目的地、效果和次数必须处于批准范围；不可信内容不能隐式借用合法 Deputy 的权限。

最低条件包括：

```text
ActionOK(c) :=
  descriptor(c) = approvedDescriptor(τ,t)
  ∧ canonicalArgs(c) ⊆ capability(τ,t)
  ∧ effect(c) ⊆ approvedEffect(τ,t)
  ∧ invariants(c) = true
  ∧ approval(c) binds (τ, p, s, t, d, hash(a), e, expiry, nonce)
```

当前引擎可对 recipient/domain、provenance、taint、数值界限、危险工具和组织 invariant 做单次调用裁决，OPA/Rego 结果只可收紧。缺口是：MCP Tool 被映射到有限内建 ToolName 后可能丢失细粒度效果语义；尚无生产级参数绑定、一次性、可撤销 approval ticket；`ProofStore` 的 HMAC 是共享密钥下 proof 文件的防篡改 envelope，不是签名的人类批准令牌，也不是公开不可抵赖签名。

### 4.4 Source Integrity

目标有两部分：第一，知道“这个工具定义来自谁、是否是批准版本”；第二，知道“哪些来源影响了权限相关参数和选择过程”。

```text
SourceOK(c) :=
  approvedRoute(p,s,t,d)
  ∧ noNameCollision(p,s,t)
  ∧ ∀ x ∈ authorityBearingArgs(a): ancestors(G,x) ⊆ allowedSources(τ,t)
  ∧ selectionProvenance(c) is complete
```

当前完整 descriptor digest、TOFU/pinned baseline、name collision、unexpected addition、sticky quarantine 已接入 `tools/list` 与 `tools/call`：被隔离工具不会暴露给 planning model，直接调用也会 block。TOFU 只能发现连续性破坏；pinned manifest 是 operator 对精确字节语义的批准。publisher origin signature、Server endpoint binding、key lifecycle、provider-aware candidate set 和 ranking provenance 尚未实现。

### 4.5 Data Confidentiality 与 Data Integrity

目标同时保护两条禁止流：

```text
Integrity:       Untrusted Source ─────X─────▶ Privileged Effect
Confidentiality: Sensitive Data   ─────X─────▶ Unapproved Destination
```

```text
DataOK(c) :=
  ¬∃ path_G(untrusted → privileged_sink) without explicit task authorization
  ∧ ¬∃ path_G(sensitive → unapproved_egress)
  ∧ labels(output) ⊒ labels(all influencing inputs)
```

`⊒` 表示标签单调传播：添加 provenance、taint 或显式 `flows` 只能保持或收紧裁决，不能洗掉已有证据。当前 `ContextTracker` 对 `resources/read`、`prompts/get` 和成功 `tools/call` 返回建立有界内存索引；`ProvenanceMapper` 以精确子串把后续参数映射到 `webpage_1`、`source_code_1` 等 ID，未命中为 `agent_generated`。摘要、翻译、编码和 opaque reasoning 不能自动追踪；可信 caller 可提交 additive `flows`，这些边只能增加来源和 taint。

### 4.6 单调裁决不变量

定义：

```text
allow ≺ require_approval ≺ deny
```

对任意额外安全证据 `E+`：

```text
Decision(c, E ∪ E+) ⪰ Decision(c, E)
```

当前 built-in、config、OPA、ToolchainGuard、ToolIdentityGuard 和 TaskAuthorizationGuard 使用单调 merge，方向正确。下一步应把 selection route、response evidence 和跨进程 ledger 也放进同一不变量，并以 property-based / model-based conformance test 验证。语义分类器只能增加 scrutiny，不能成为授予权限的正证据。

## 5. 三个必须成为一等对象的安全结构

### 5.1 Tool Identity：连续性不等于来源真实性

建议统一使用以下身份键，而不是只用 Tool name：

```text
ToolKey = (publisherId, serverId, endpoint/process identity, toolName,
           descriptorDigest, release/version, backendContractDigest)
```

当前代码能回答：“同一 proxy 看到的完整 descriptor 是否从第一次快照或 operator pin 发生变化？”它不能回答：“第一次连接的 Server 是否真是声称的发布者？”两者的保证应明确分层：

| 机制 | 能证明什么 | 不能证明什么 | 当前状态 |
|---|---|---|---|
| TOFU descriptor baseline | 同一进程内第一次观察后的连续性 | 首次 Server 来源、发布者身份、后端忠实性 | 已实现并默认接入 proxy |
| Operator-pinned name/digest | 当前完整 descriptor 与人工批准字节语义一致 | 公开 publisher identity、后端代码未变 | 已实现，可注入 guard；CLI/config 产品化仍需完善 |
| Signed publisher manifest | 声称的 key 对 name/descriptor/version/scope 的签名 | key 是否应受信、后端是否忠实 | 路线图 |
| Backend attestation / sandbox observation | 某构建或进程身份及一部分实际行为 | 所有未来输入上的语义正确性 | 路线图/生态外控制 |

身份事件必须粘性隔离：回滚 descriptor 不应自动恢复信任；重新批准必须绑定当前精确 digest。当前实现符合这一点。

### 5.2 Selection Integrity：解释“为什么是它”

Selection integrity 不是“模型给出一个理由”，而是以下决策输入可重放：

1. 候选集只来自 task contract 和 operator-approved provider/tool inventory；
2. 能力匹配使用结构化 effect/resource/destination profile，而不是宣传性形容词；
3. 同名工具使用 origin-scoped namespace，collision 时 fail closed；
4. 排序记录候选、过滤理由、特征和模型/规则版本；
5. 描述文本可以帮助解释功能，但不能单独扩大权限、scope 或调用预算；
6. 最终调用仍需对精确 descriptor + args + task + source 做 reference-monitor 检查。

当前 RiskProof 能在 `tools/list` 隐藏 poisoned/quarantined descriptor，并在直接调用时阻断；这降低了明显 metadata attack 的暴露面。但它没有 provider-aware router、能力等价类、deterministic candidate policy 或 ranking provenance，不能宣称已防御 MPMA。关键词 scanner 也是纵深信号，不是 selection integrity。

### 5.3 Cross-Call Provenance Graph：从事件列表到连续因果证据

目标图至少包含：

| 节点 | 关键字段 |
|---|---|
| Task / User / Agent | stable ID、objective digest、租户、有效期 |
| Provider / Server / Tool | origin、endpoint/process、完整 descriptor digest、scope |
| Invocation | trace/step/parent、canonical args digest、时间、决策 |
| Context / Argument / Result | context ID、content digest、classification、长度；默认不保存 raw secret |
| Destination / Resource / Effect | domain/account/path/root、method、读/写/执行/披露 |
| Approval / Dispatch | approver、ticket、expiry、nonce、upstream result、effect evidence |

建议边类型为：

```text
selected_from   described_by   derived_from   influenced
authorized_by   invoked        returned       disclosed_to
approved_by     dispatched_as  confirmed_by   contradicted_by
```

当前 `ContextTracker`、`ToolchainGuard`、`ToolIdentityGuard` 和 `TraceContext` 已提供部分节点与 metadata 事件；`AuditProof` 仍主要是单次 tool/trace/decision/rules/evidence，未包含完整跨调用 graph、ToolKey、args commitment、approval ticket 或 dispatch receipt。多个独立 proxy 也不共享 session。下一步应建立 host-level gateway 或按 `(tenant, user, task, session)` 隔离的本地 shared ledger，并采用 Agent-BOM/W3C PROV 兼容的导出层，而不把内部 raw secret 直接持久化。

## 6. 论文 → 安全性质 → 当前实现状态

状态只使用四类：

- **已实现**：已进入实际执行路径并有相应测试；
- **部分实现**：已有机制但保证、集成范围或协议覆盖不完整；
- **路线图**：尚无可依赖的生产实现；
- **生态外控制**：需要 registry、IdP、OS/container、network gateway 或 publisher 配合。

| 研究依据 | 对应性质/控制 | RiskProof 状态 | 代码事实与缺口 |
|---|---|---|---|
| Parasites | DataOK、跨调用组合 | 部分实现 | 同一 proxy 的 EIT/PAT/NAT state + exact provenance；跨独立 proxy/Server 和有损变换不完整 |
| MPMA | Selection Integrity、SourceOK | 部分实现 | collision/quarantine 与明显 poisoning 过滤已接入；provider-aware 候选/排序 provenance 是路线图 |
| Confused Deputy / MCP-ITP | TaskOK、ActionOK、参数来源 | 部分实现 | task-bound Tool/digest/source/budget 已接入 proxy；若 Host 合同正确约束 provenance，可拒绝一部分 helper → legitimate target 路径；精确 resource/destination/effect 与签名 args-bound ticket 尚未完成 |
| The Task Shield | TaskOK、最小任务权限 | 已实现第一版 | Host-held contract、expiry、Tool/digest/source/预算和 dispatch reservation 已接入；objective digest 非语义 oracle，CLI 不认证用户，状态仅单进程 |
| ETDI | Tool origin、descriptor、scope、PBAC | 部分实现 | 完整 descriptor digest、TOFU/pinned 已实现；publisher signature、OAuth scope/call-stack policy 是路线图/生态外控制 |
| MCPSecBench | 跨攻击面 conformance | 部分实现 | 有大量单元/集成 fixture，但尚无按 17 类发布的统一 prevent/detect/evidence/out-of-scope 报告 |
| MCP Safety Audit | 动态 scanner、canary evidence | 路线图 | 当前 semantic scan/proof 不能确认 backend exploit；需要本地沙箱 probe 和 evidence state machine |
| SHIELD MCP | descriptor/parameter/response/session 四阶段 | 部分实现 | descriptor、parameter policy、same-process session 已有；response analysis、公开 benchmark 和全协议 correlation 未完成 |
| MCP at First Glance | Server admission、扫描失败分离 | 路线图 | 产品不是 repository SAST；应接入 registry/admission report，并把 scan failure 单列 |
| Privilege measurement | least privilege、sandbox、destination scope | 部分实现 | capability/invariant、最小子进程环境已实现；OS sandbox、filesystem root、network egress 需要路线图/生态外控制 |
| Remote auth measurement | issuer/audience、PKCE、redirect/DCR | 路线图 | 当前核心 proxy 是本地 stdio 边界；没有 remote MCP OAuth admission scanner |
| Privacy measurement / Unsafe by Flow | 双向 taint、response DLP | 部分实现 | 请求参数与成功 response context 可追踪，proof/输出脱敏；return/error/log/stdout 全面 DLP 与 purpose-aware egress 未实现 |
| CaMeL | control/data separation | 部分实现 | 执行边界的 provenance/taint 是补偿性 IFC；不是完整可信 control plane + 隔离 interpreter |
| FORGE | 独立 reference monitor、历史 policy | 部分实现 | built-in/config/OPA 的确定性单调裁决已实现；Datalog/assume-guarantee 与跨 Agent policy state 是路线图 |
| Agent-BOM | agent/tool/memory/action graph | 部分实现 | trace、context、identity、toolchain metadata 分散存在；统一可查询 graph 与 root-cause path 是路线图 |
| AgentDojo / InjecAgent | attack + utility benchmark | 部分实现 | 有本地 scenario/test 基础；尚未固定公开 attack/benign corpus、seed、模型/Host matrix 和重复次数 |
| DSCC | 单调 compositional policy | 部分实现 | decision merge 与 session taint方向一致；预组合 tool-profile policy 和 shared ledger 是路线图 |
| Unicode approval-view fidelity | human view = model bytes | 部分实现 | digest 会覆盖 TAG/Cf/zero-width 的后续变化；首次基线仍可信，专用 Unicode fail-closed 与双视图 commitment 未实现 |
| FlowGuard | signal → runtime evidence | 路线图 | 当前 `proof` 是决策证据；没有 canary-confirmed/contradicted/inconclusive 状态和真实 effect receipt |
| AIP / AgentThread | delegation、协议组合 invariant | 路线图 | task guard 原型和 trace 字段可承接；签名委托、scope attenuation、最大深度、跨协议 checker 未实现 |

## 7. 六层产品架构与交付顺序

| 层 | 需要建立的保证 | 当前可复用资产 | 下一个可验收交付物 |
|---|---|---|---|
| 1. Identity & Admission | 只把批准的 Server/Tool/version/scope 放进上下文 | 完整 descriptor digest、TOFU/pinned、sticky quarantine、protocol allowlist、最小子进程环境 | origin-scoped `ToolKey`、signed/pinned manifest 文件、Unicode view-fidelity check、remote OAuth admission report |
| 2. Selection Integrity | 候选集与排序不被宣传性 metadata 隐式扩权 | collision 阻断、poisoned descriptor 隐藏 | capability-equivalence candidate set、operator-approved provider、selection trace、metadata 不参与授权 |
| 3. Task-Bound Authorization | Tool、版本、来源、预算、有效期绑定可信任务 | 已导出的 `TaskAuthorizationGuard`、proxy assess/reserve/complete/abort、CLI `--task-contract`、host-injected trusted context、capability/invariant | 合同/用户认证、stable cross-process session、持久化/重放安全预算、精确 resource/destination/effect scope |
| 4. Per-Call Reference Monitor | 每次副作用前 deterministic allow/step-up/block | engine、config、OPA、provenance/taint、schema poisoning guard | canonical args commitment、参数绑定一次性 approval ticket、unknown effect default-deny |
| 5. Cross-Call Composition | 单次合法不能组合成非法；证据只收紧 | `ContextTracker`、`ToolchainGuard`、additive flows | host-level shared provenance graph、tool profile、multi-Server correlation、transformation-aware label propagation |
| 6. Evidence & Conformance | 区分 signal/path/confirmed effect，并连接 decision → dispatch → result | redacted `AuditProof`、可选 AES-GCM/HMAC envelope、metadata event history | execution receipt、sandbox canary adjudication、benchmark adapter、覆盖矩阵与固定分母报告 |

六层不是六个互相替代的产品。Registry scanner 能帮助第 1 层，模型 guard 能帮助第 2/6 层，OPA 能帮助第 3–5 层，sandbox/egress/DLP 能帮助第 4–6 层；RiskProof 的差异化是把这些控制放到同一 task/provenance/evidence 语义中。

### 7.1 优先级

**P0：把第一版任务执行链提升为可部署的信任边界。**

1. 为合同建立可信签发/加载边界，把 authenticated user/tenant/task context 由 Host 注入；明确 CLI `--task-contract` 本身不做用户认证。
2. 建立 stable `(tenantId, userId, taskId, sessionId, traceId)`，并将预算/reservation 做成重启和多进程下仍不可重放、不可超用的状态。
3. 用 `ToolKey` 替代仅 name 级身份；manifest 至少绑定 provider/server/tool/descriptor digest。
4. approval ticket 绑定 task、ToolKey、canonical args digest、effect、expiry、nonce 和 single-use 状态。
5. 把 decision、task reservation、dispatch、MCP result/error、Toolchain completion/abort 连接成 execution receipt。

**P1：补齐选择与双向数据流。**

1. 实现 provider-approved candidate set 和 selection trace；description 只用于 UX/能力说明，不授予权限。
2. Tool registration 时生成结构化 effect/resource/destination profile，并允许 operator 修订。
3. 对 Tool return、MCP error、stderr/log 和 proof export 做 source/destination-aware DLP；保留 `signal/path/confirmed/contradicted/inconclusive`。
4. host gateway 共享跨 Server ledger；独立 proxy 通过本地 sidecar 按 task/session 隔离状态。

**P2：生产信任根与生态联动。**

1. publisher signature、key rotation/revocation、透明度日志和 registry provenance；
2. remote MCP OAuth conformance/admission；
3. 容器/OS sandbox、filesystem root、network egress、secret broker 与企业 IdP；
4. delegation token、scope attenuation、最大委托深度和跨 Agent receipt。

## 8. 本地、无副作用演示矩阵

所有演示必须使用本地假 Server、临时目录、固定 seed 和合成 canary；不得连接真实邮箱、云账号、生产数据库，不得读取用户真实 secret，不得对公网发送数据。`HTTP` sink 仅绑定 `127.0.0.1`，文件 sink 仅写测试临时目录，Shell fixture 只记录参数而不执行命令。

| Demo | 攻击故事 | 安全 fixture 与观察点 | 当前预期 | 状态/诚实边界 |
|---|---|---|---|---|
| D1 Rug Pull | 第一次 `tools/list` 安全，第二次修改 description/schema/default/`_meta` | 同一 fake upstream 依次返回两个完整 descriptor；检查 list 被移除、direct call 未转发、quarantine 回滚后仍粘性 | digest mismatch + block | **已实现可演示**；证明连续性检测，不证明首次 origin |
| D2 Collision / Late Addition | 同名 shadow 或基线后新增工具 | 一次快照含两个同名 Tool，或第二次新增 Tool | fail closed，不让 `Map` 先吞掉 collision | **已实现可演示** |
| D3 Unicode Approval Gap | TAG/Cf/zero-width 对人不可见但进入模型 | 展示 raw code point、可见渲染和 canonical digest；不调用模型也不执行工具 | 后续变化会触发 digest；首次快照不会自动判恶 | **部分实现演示**；专用 view-fidelity firewall 是路线图 |
| D4 Selection Manipulation | 同功能工具之一加入 “best/authoritative” | 固定候选 JSON；记录 naive model/规则选择与 operator-pinned candidate policy 对照 | 当前只可隔离 collision/明显 poisoning | **路线图对照演示**；不得称已防 MPMA |
| D5 Implicit Parameter Tampering | 未调用 helper 的描述诱导合法 `send_email` 把 recipient 改为攻击者 | helper 只提供 metadata；合法 sender 是记录器；参数使用合成地址 | 单次 recipient/provenance policy 可能 block/step-up；精确 task/args ticket 才是完整解 | **部分实现**，直接展示缺口 |
| D6 Same-Proxy Exfiltration | fake web/email → fake private read → local egress recorder | 私密内容只含 `RISKPROOF_CANARY_<seed>`；检查 EIT→PAT→NAT 事件和最终参数 provenance | 未确认数据边 step-up；确认 private provenance/taint 时 block | **已实现第一版** |
| D7 Cross-Proxy Gap | EIT、PAT、NAT 分属三个独立 wrapper | 三个本地 proxy，各自只看自己的 upstream；sink 仍是本地 recorder | 链状态不连续 | **负向诚实演示**；证明为何需要 shared ledger，不宣称防住 |
| D8 Task Budget Race | 两个并发调用争抢最后一个预算 | 用真实本地 proxy/CLI `--task-contract` 驱动 fake child；Tool handler 只计数、不产生副作用 | 只允许一个 reservation；拒绝/失败会 abort，上游成功才 complete | **已实现第一版可演示**；状态只在当前进程，CLI 不认证用户 |
| D9 Signal vs Evidence | 返回中出现 `/etc/passwd` 或 API-key 样式文本 | 三种本地返回：用户回显、permission denied、读取 harmless canary 成功 | 当前只能记录/判断 signal；目标状态分别为 contradicted/inconclusive/confirmed | **路线图演示**，用于解释 `proof` ≠ exploit proof |
| D10 OAuth DCR | 恶意 callback/issuer/audience 混淆 | 纯本地 OAuth stub、固定 token/code，不接外部 IdP | 目标 admission policy 拒绝 | **路线图 fixture**；当前无 remote auth scanner |
| D11 Benign Utility | 合法读取合成报告并发往批准的本地域 | 与攻击 fixture 共享工具和数据形态，但 task contract 明确批准 | 应 allow 或低摩擦 step-up，不应 block | **必须与每个攻击 demo 配对**，用于测 false block/approval fatigue |

### 8.1 一套适合现场讲述的三幕演示

1. **第一幕：正常工具变成寄生链。** 展示 D6：网页、文件、发送工具单独都正常，组合后合成 canary 试图流向本地 sink；RiskProof 在副作用前用路径和数据证据阻断。
2. **第二幕：信任会变化，选择也会被操纵。** 展示 D1/D3/D4：完整 descriptor commitment 能抓 rug pull 和不可见字节变化，但 TOFU 不证明首次来源，identity 也不能替代 selection integrity。
3. **第三幕：从一次裁决升级为任务与 receipt。** 展示 D8/D9：task budget 能确定性阻止并发扩权；可疑字符串只是 signal，下一版 execution receipt 要把批准、dispatch、结果和 canary evidence 连起来。

这套演示的价值在于既展示已有能力，也主动暴露未覆盖边界；经得住追问比“每个攻击都能防”更可信。

## 9. Benchmark 与 conformance：先固定分母，再谈效果

### 9.1 不同论文的数字不可横向拼接

| 工作 | Corpus / fixture | 模型 / Host | 重复或审核分母 | 正确解读 |
|---|---|---|---|---|
| Parasites | 1,360 Server、12,230 Tool；10 条构造工具链 | 代表性实验另覆盖 7 个模型、5 个 client | 10 条链各 10 次，合计 36 / 100；9 / 10 至少一次成功 | `9/10` 是链级“至少一次”，不是单次 90% ASR |
| MPMA | 8 类功能，每类 10 个 query | 5 个 LLM；每格 1 恶意 + 5 同功能竞争者 | 随机 baseline 1/6 | 受控 preference manipulation，不是市场份额或 payload execution |
| MCPSecBench | 17 类攻击、四攻击面 | 3 个 client/model platform | 每向量 15 次；防御只适用 11 / 17 类 | 某 fixture 的 100% 不是生态发生率；防御均值不是全 17 类覆盖 |
| SHIELD MCP | 40 Server、487 attack case、200 benign task | 5 个 backend | 每攻击场景每模型 3 次 | 自建、未公开 adversarial Server；benign utility 必须与 ASR 一起看 |
| MCP at First Glance | 原始 1,899；主要分析 583 | 静态 SonarQube；动态抽 83 | 动态最终成功 73 | 7.2% 分母是 583；5.5% 分母是成功扫描子集；失败不是 clean |
| MCPTox | 45 live Server、353 authentic Tool、1,312 malicious case、10 类风险 | 20 个 Agent setting | 论文 benchmark 分母 | 最高 72.8% 是特定 setting；预印本 fixture 不等于野外攻击率 |
| Remote auth study | 7,973 live；2,428 OAuth；1,118 宣告 DCR | 最终可完整测试 119 | detector 评估 325 TP、54 FP、1 FN、无 TN | 119 全部有 flaw 不能外推到全部 OAuth Server；无 TN 的 precision/recall 不是随机流量表现 |
| Privacy leakage study | 10,655 total；6,657 含相关信息；1,317 predicted risk | 静态工具 | 只抽 200 个预测正例，192 TP、8 FP | 没有预测负例审核，不能估计 recall 或声称无 FN |
| Unsafe by Flow | 32 confirmed case；15,452 repository | MCP-aware static analysis | 30 / 32 benchmark；真实候选人工确认 118 path / 87 Server | confirmed benchmark recall 与真实候选 precision/coverage 是两个分母 |
| FlowGuard | 1,880 executable case、5 类；8,000 real-world Server | 动态/语义组合 | 类别 F1；真实侧报告 523 finding / 326 Server | benchmark F1 不能替代真实 finding 的全面人工确认 |

### 9.2 RiskProof 自己的最小实验记录

每次报告必须固定以下字段，缺失就标 `not measured`，不能用模糊的“全部通过”替代：

```text
benchmark_version / git_commit / fixture_hash
attack_fixtures / benign_fixtures / out_of_scope_fixtures
model_name+version / host+version / MCP SDK+protocol version
server_fixture_version / policy_version / manifest_digest
seed / repetitions_per_cell / temperature or deterministic mode
success_definition / baseline / valid_runs / technical_errors
prevented / step_up / escaped / inconclusive
benign_completed / false_block / approval_required
same_proxy / cross_server / cross_process
```

技术错误、unsupported 和 scanner initialization failure 必须从安全结果中拆开：

```text
valid_attack_runs = launched_runs - technical_errors - unsupported_runs

ASR = unauthorized_consequence_reached / valid_attack_runs

deterministic_prevention_rate = pre_dispatch_blocks / valid_attack_runs

benign_completion_rate = completed_benign_tasks / valid_benign_runs

false_block_rate = blocked_benign_tasks / valid_benign_runs
```

`ask_approval` 既不是自动防住，也不是逃逸，应单独报告：是否在任何副作用前暂停、谁批准、批准是否参数绑定、批准后是否仍被 sandbox/egress containment 限制。

### 9.3 三张必须同时发布的表

1. **攻击结果表**：按 fixture 分 `prevented / step_up / escaped / inconclusive / technical_error`，并给出 canary consequence 定义。
2. **良性效用表**：与攻击共享相似工具和数据形态，报告 completion、false block、approval rate、latency P50/P95。
3. **证据完整性表**：报告 identity、task contract、selection trace、argument provenance、data label、cross-call edges、approval、dispatch/result 各字段是否齐全。

建议的核心指标：

| 指标 | 分子 / 分母 |
|---|---|
| Toolchain Attack Prevention | 未到达未授权 consequence 的 valid attack run / valid attack run；step-up 单列 |
| Stage Containment | 在 registration / selection / task check / per-call / chain / egress 哪层首次阻断 |
| Identity Continuity Detection | 被检测并隔离的已知 descriptor mutation / 注入的 mutation |
| Selection Integrity Coverage | 有完整 approved candidate set + selection trace 的选择 / 全部选择 |
| Provenance Precision / Recall | 正确来源边 / 预测来源边；正确恢复来源边 / ground-truth 来源边 |
| Transformation Survival | 摘要、翻译、拼接、编码后仍保留正确标签的 flow / 对应 ground-truth flow |
| Chain Proof Completeness | 必要节点和边齐全的 receipt / valid run |
| Evidence Confirmation Rate | 被 runtime canary/dispatch 证实的 execution finding / execution finding；semantic risk 另列 |
| Benign Completion / False Block / Approval | 合法任务效用与摩擦，必须与安全率同时给出 |

### 9.4 Conformance 不是一个总分

对每个攻击族分别标记：

```text
PREVENT   副作用前确定性阻断
STEP_UP   副作用前暂停并要求独立授权
DETECT    产生可复查 finding，但不保证阻断
EVIDENCE  有运行时 canary/dispatch 证据
OUT       明确不在当前 trust boundary
ERROR     测试无效，不能算 clean 或 prevented
```

最低覆盖族应包括：name collision、tool squatting、descriptor poisoning、Unicode concealment、rug pull、selection manipulation、implicit tool poisoning/confused deputy、argument tampering、over-privilege、EIT→PAT→NAT、response injection、cross-tool harvesting/pollution、transformation laundering、malicious backend、OAuth/DCR、Sampling/Elicitation/未知方法、Server process secret access、DoS/resource exhaustion 和跨 Agent delegation。

现有测试全部通过只能证明固定代码路径符合断言；只有上述分母、良性对照和 consequence 定义齐全，才可以称为 benchmark 结果。

## 10. Evidence ladder：避免把所有发现都叫“漏洞”

| 等级 | 名称 | 允许的表述 | 例子 |
|---|---|---|---|
| E0 | Semantic signal | “描述/返回包含可疑语义” | metadata 含上传指令、返回含 key-like 字符串 |
| E1 | Static/reachable path | “存在 source→sink 可达风险” | MCP 参数可流向 `exec`，敏感配置可流向 protocol return |
| E2 | Controlled runtime evidence | “在隔离环境用无害 canary 确认行为” | 临时目录 canary 被读取、本地 recorder 收到 canary |
| E3 | Execution receipt | “本次批准、dispatch、result/effect 已连续记录” | args/descriptor/task commitment 与 upstream response 对应 |
| E4 | External attestation | “由独立控制面确认现实副作用/未发生” | egress gateway、secret broker、OS audit 或目标系统回执 |

RiskProof 当前 `AuditProof` 主要记录裁决、风险、规则和 evidence，是 E0/E1 决策证据容器；即使文件使用 AES-GCM/HMAC 保护，也不会自动升级成 E2/E3。下一阶段的核心不是把字段名改成 `proof`，而是把事实来源和 evidence level 写入 schema，并让每个 execution claim 指向可复查证据。

## 11. 答辩与追问清单

### 11.1 论文数字

**问：论文不是说 90% 的攻击都成功吗？**

答：不是。*Parasites* 的 9 / 10 表示十条构造链中九条至少成功一次，每条重复十次；Table 7 合计是 36 / 100。Confused Deputy 的 90.89% 和 86.46% 是正式摘要中的 “up to”。这些都不能当野外攻击率，也不是 RiskProof 的防御率。

**问：为什么不能说 12.4% 的 MCP Server 已泄漏隐私？**

答：12.4% 是静态工具标出的 leakage risk，占 10,655 个样本；静态可达路径可能是正常功能，且只审核了预测正例，没有负例分母，无法估计 recall，更不能证明泄漏已发生。

**问：某 benchmark 的 100% ASR 有多严重？**

答：它证明特定 fixture、client、模型和配置可稳定利用，适合做 conformance regression；它不等于生态中 100% 的部署会中招，也不说明攻击出现频率。

### 11.2 身份与选择

**问：TOFU 是否已经解决 Tool 身份认证？**

答：没有。TOFU 只检测第一次观察后的连续性破坏；首次恶意 Server 会成为基线。更强的当前选择是 operator-pinned 精确 manifest，并隔离 upstream；publisher origin signature、trust root、revocation 仍是路线图。

**问：descriptor 有签名，为什么还会不安全？**

答：签名证明某个 key 声明了这些字节，不证明后端忠实执行、不证明 key 值得信任，也不阻止合法发布者用宣传性 metadata 操纵模型选择。identity、selection、runtime behavior 是三种不同保证。

**问：完整 digest 能防 Unicode 隐藏 payload 吗？**

答：它能检测基线后的任何字节语义变化，包括 TAG/Cf/zero-width；它不能在首次安装时判断不可见内容是否恶意，也不能保证用户看到的审批视图等于模型收到的 bytes。需要首次 admission firewall 和 view-fidelity commitment。

**问：现在是否已经防住 MPMA？**

答：没有。当前能阻断重名、未批准新增、descriptor 漂移和一部分明显投毒；尚无 provider-aware candidate set、能力等价类和 ranking provenance。因此 selection integrity 是明确路线图。

### 11.3 任务与授权

**问：`objectiveDigest` 能证明调用符合用户意图吗？**

答：不能。它只把执行绑定到 Host 批准的任务表示，防止内容事后修改合同；自然语言目标与具体动作之间的语义对齐仍需结构化 effect/resource/destination、reference monitor 和必要的 step-up。

**问：TaskAuthorizationGuard 已经进入真实调用路径了吗？**

答：是，已实现第一版。它已公开导出并可注入 proxy；`riskproof/evaluate` 只读评估，`tools/call` 在真实转发前原子预留预算，并随拒绝/失败 abort、随上游成功 complete；CLI 也支持 `--task-contract`。但它是 opt-in、单进程状态，CLI 不认证用户或合同签发者，`objectiveDigest` 也不是语义 oracle，因此还不能称为企业级分布式授权系统。

**问：人工点了 Approve，为什么还需要参数绑定 ticket？**

答：如果批准不绑定 task、ToolKey、descriptor、精确 args、effect、expiry 和 nonce，Agent 或不可信 client 可以重放、换参数或把一次批准用于另一动作。当前允许 unsigned client decision 的开关默认关闭，而且文档明确它只适用于显式受信的本地 MVP。

### 11.4 Provenance 与组合

**问：RiskProof 能自动恢复所有 provenance 吗？**

答：不能。当前自动映射是成功 MCP response 到后续参数的确定性精确子串匹配；摘要、翻译、编码、模型隐式推理会丢失边。可信集成可提交 additive `flows`，但不能把未知边写成已证明。

**问：为什么不逐个扫描 Tool，而要看工具链？**

答：EIT、PAT、NAT 可能各自正常；违规只在组合中出现。DSCC、Les Dissonances 和 Parasites 都说明 per-tool guardrail 无法覆盖组合产生的权限和数据流。

**问：当前能防跨 Server MCP-UPD 吗？**

答：同一 `McpProxyServer` 或程序化 Host 共享 `ToolchainGuard` 时有第一版；多个独立 CLI proxy 没有共享 ledger，不能宣称完整覆盖。D7 应把这个缺口直接演示出来。

**问：一个 Tool 自己同时读文件又联网怎么办？**

答：metadata 分类只能识别可能同时具备 EIT/PAT/NAT 的能力并升级 critical review，不能证明内部实际数据边。生产解需要 sandbox、egress control、backend evidence 和最小 scope。

### 11.5 Signal、proof 与现实效果

**问：LLM scanner 说有漏洞，算证据吗？**

答：算 E0 signal，不算 execution proof。对 command/file/network 等执行型结论，应在隔离环境用 schema-valid 无害 canary 区分成功、拒绝、用户回显和技术错误。

**问：为什么 `proof` 不是数学证明？**

答：它是结构化决策记录。当前系统没有对完整程序、协议或策略做机器可检验的 soundness/completeness 证明；语义分类也不是 theorem prover。形式化性质的价值是让测试和实现有可证伪的目标。

**问：HMAC 签名 proof 是否等于不可抵赖审批？**

答：不是。HMAC 提供共享密钥持有者之间的 tamper evidence；任何持钥方都能生成记录。公开不可抵赖签名、独立 approver identity、nonce 和 single-use approval 是不同机制。

**问：decision proof 与 execution receipt 有什么差别？**

答：decision proof 说明“当时根据哪些输入和 policy 得到什么裁决”；execution receipt 还要证明“精确调用是否被 dispatch、上游返回什么、reservation 如何结算、可观测 effect 是否发生”。当前主要是前者。

### 11.6 产品边界

**问：有 sandbox 还需要 RiskProof 吗？**

答：需要。sandbox 约束 Server 进程能访问什么；它通常不知道用户任务、参数来源和跨 Tool 数据目的。RiskProof 也不能替代 sandbox，尤其无法单独阻止恶意 Server 在启动时读文件或出网。

**问：为什么不用更强模型判断恶意意图？**

答：MPMA、MCP-ITP 和 adaptive prompt-injection 研究说明攻击可以优化到绕过模型/语义检测；模型判断适合生成 signal 和解释，不应独自授予权限。最终边界应由 deterministic contract、capability、provenance 和 egress policy 执行。

**问：远程 OAuth 问题当前覆盖吗？**

答：没有。当前强项是本地 stdio 执行边界。remote MCP admission、issuer/audience、PKCE、redirect、state、DCR/CIMD 属于下一阶段，并应与企业 IdP/gateway 配合。

**问：你们自己的攻击阻断率和性能是多少？**

答：在固定公开 benchmark、良性对照、重复次数和 consequence 定义完成前，不应给生态级百分比。当前测试证明代码回归与固定 fixture 行为；正式结果应按第 9 节分母报告，并同时给出 benign completion、false block 和 P50/P95。

## 12. 推荐的对外叙事

### 一句话

> **让 MCP 工具调用带着身份、任务、来源和数据流证据再执行。**

### 30 秒

MCP 把模型从文本生成器变成工具链编排器。新的风险不只是某个工具有毒，而是网页、文件、邮件、数据库和 Shell 等正常能力被 metadata 或外部内容串成未经授权的链。RiskProof 位于 Agent 与真实工具之间，把完整 Tool 身份、Host 侧任务合同、精确参数来源、敏感数据标签和跨调用历史组合成确定性 `allow / ask_approval / block`，并记录为什么这样决定。当前版本已经覆盖 descriptor 漂移、opt-in 任务合同的真实 dispatch 生命周期和同一 proxy 的第一版组合控制；下一步是 authenticated task/user context、selection integrity、跨 Server graph 和 decision-to-effect execution receipt。

### 与相邻方案的边界

- Prompt guard 保护文本交互；RiskProof 保护对真实系统的执行权。
- MCP scanner 发现组件或 metadata 风险；RiskProof 判断本次 task + action + source + data 是否被授权。
- OPA/Cedar 计算策略；RiskProof 构造带 Tool identity、provenance、taint 和 chain state 的安全输入，并负责调用生命周期。
- Observability 解释发生了什么；RiskProof 在副作用前裁决，并把裁决连接到后续 receipt。
- Auth、sandbox、DLP、egress gateway 是必须的纵深控制；RiskProof 不替代它们，而是给它们共同的任务和证据语义。

## 13. 参考文献

以下链接优先给出正式 DOI、arXiv 和 ACL Anthology/会议官方页面。仅有预印本的工作明确标注为预印本。

1. Shuli Zhao, Qinsheng Hou, Zihan Zhan, Yanhao Wang, Yuchong Xie, Yu Guo, Libo Chen, Shenghong Li, Zhi Xue. “Parasites in the Toolchain: A Large-Scale Analysis of Attacks on the MCP Ecosystem.” *2026 IEEE Symposium on Security and Privacy*. [DOI](https://doi.org/10.1109/SP63933.2026.00154) · [arXiv:2509.06572](https://arxiv.org/abs/2509.06572)

2. Manish Bhatt, Vineeth Sai Narajala, Idan Habler. “ETDI: Mitigating Tool Squatting and Rug Pull Attacks in Model Context Protocol (MCP) by Using OAuth-Enhanced Tool Definitions and Policy-Based Access Control.” *2025 Cyber Awareness and Research Symposium*. [DOI](https://doi.org/10.1109/CARS67163.2025.11337310) · [arXiv:2506.01333](https://arxiv.org/abs/2506.01333)

3. Zihan Wang, Rui Zhang, Yu Liu, Wenshu Fan, Wenbo Jiang, Qingchuan Zhao, Hongwei Li, Guowen Xu. “MPMA: Preference Manipulation Attack Against Model Context Protocol.” *AAAI 2026*. [DOI](https://doi.org/10.1609/aaai.v40i42.40898) · [arXiv:2505.11154](https://arxiv.org/abs/2505.11154)

4. Yixuan Yang, Cuifeng Gao, Daoyuan Wu, Yufan Chen, Yingjiu Li, Shuai Wang. “MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols.” 预印本. [arXiv:2508.13220](https://arxiv.org/abs/2508.13220)

5. John T. Halloran, Brandon Radosevich, Gavin Black. “MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits.” *Assurance and Security for AI-enabled Systems 2026*. [DOI](https://doi.org/10.1117/12.3097390) · [arXiv:2504.03767](https://arxiv.org/abs/2504.03767)

6. Zhiyuan Li, Jingzheng Wu, Yuhao Peng, Tianyue Luo, Xing Cui, Xiang Ling. “Confused Deputy Attack Against Model Context Protocol.” *ACM Transactions on Software Engineering and Methodology*, 2026. [DOI](https://doi.org/10.1145/3830467)

7. Saurabh Yergattikar. “Securing the Tool Layer: A Threat Taxonomy and Runtime Defense Framework for Model Context Protocol Deployments.” *ACL 2026 Industry Track*. [DOI](https://doi.org/10.18653/v1/2026.acl-industry.58) · [ACL Anthology](https://aclanthology.org/2026.acl-industry.58/)

8. Mohammed Mehedi Hasan, Hao Li, Emad Fallahzadeh, Gopi Krishnan Rajbahadur, Bram Adams, Ahmed E. Hassan. “Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers.” *ACM Transactions on Software Engineering and Methodology*, 2026. [DOI](https://doi.org/10.1145/3814959) · [arXiv:2506.13538](https://arxiv.org/abs/2506.13538)

9. Zhihao Li, Kun Li, Boyang Ma, Minghui Xu, Yue Zhang, Xiuzhen Cheng. “We Urgently Need Privilege Management in MCP: A Measurement of API Usage in MCP Ecosystems.” *IEEE MASS 2025*. [DOI](https://doi.org/10.1109/MASS66014.2025.00090) · [arXiv:2507.06250](https://arxiv.org/abs/2507.06250)

10. Huijun Zhou, Xiaohan Zhang, Haozhe Zhang, Haoyang Zhang, Mi Zhang, Min Yang. “A First Measurement Study on Authentication Security in Real-World Remote MCP Servers.” 预印本. [arXiv:2605.22333](https://arxiv.org/abs/2605.22333)

11. Biwei Yan, Minghui Xu, Yijun Yang, Boyang Ma, Xuelong Dai, Jinku Li, Yue Zhang. “What Happens Locally, Leaks Globally: Detecting Privacy Leakage Risks in MCP Servers.” 预印本. [arXiv:2606.21338](https://arxiv.org/abs/2606.21338)

12. Edoardo Debenedetti, Ilia Shumailov, Tianqi Fan, Jamie Hayes, Nicholas Carlini, Daniel Fabian, Christoph Kern, Chongyang Shi, Andreas Terzis, Florian Tramèr. “Defeating Prompt Injections by Design.” 预印本（CaMeL）. [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)

13. Nils Palumbo, Sarthak Choudhary, Jihye Choi, Guy Amir, Prasad Chalasani, Somesh Jha. “Formal Policy Enforcement for Real-World Agentic Systems.” 预印本（FORGE）. [arXiv:2602.16708](https://arxiv.org/abs/2602.16708)

14. Chaofan Li, Lyuye Zhang, Jintao Zhai, Siyue Feng, Xichun Yang, Huahao Wang, Shihan Dou, Yu Ji, Yutao Hu, Yueming Wu, Yang Liu, Deqing Zou. “Towards Security-Auditable LLM Agents: A Unified Graph Representation.” 预印本（Agent-BOM）. [arXiv:2605.06812](https://arxiv.org/abs/2605.06812)

15. Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr. “AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.” *Advances in Neural Information Processing Systems 37*, 2024. [DOI](https://doi.org/10.52202/079017-2636) · [arXiv:2406.13352](https://arxiv.org/abs/2406.13352)

16. Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang. “InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents.” *Findings of ACL 2024*. [DOI](https://doi.org/10.18653/v1/2024.findings-acl.624) · [ACL Anthology](https://aclanthology.org/2024.findings-acl.624/) · [arXiv:2403.02691](https://arxiv.org/abs/2403.02691)

17. Feiran Jia, Tong Wu, Xin Qin, Anna Squicciarini. “The Task Shield: Enforcing Task Alignment to Defend Against Indirect Prompt Injection in LLM Agents.” *ACL 2025 Long Papers*. [DOI](https://doi.org/10.18653/v1/2025.acl-long.1435) · [ACL Anthology](https://aclanthology.org/2025.acl-long.1435/)

18. Yupei Liu, Yuqi Jia, Runpeng Geng, Jinyuan Jia, Neil Zhenqiang Gong. “Formalizing and Benchmarking Prompt Injection Attacks and Defenses.” *USENIX Security 2024*. [USENIX](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-yupei) · [arXiv:2310.12815](https://arxiv.org/abs/2310.12815)

19. Ruiqi Li, Zhiqiang Wang, Yunhao Yao, Xiang-Yang Li. “MCP-ITP: An Automated Framework for Implicit Tool Poisoning in MCP.” 预印本. [arXiv:2601.07395](https://arxiv.org/abs/2601.07395)

20. Xinyi Hou, Yanjie Zhao, Haoyu Wang. “Unsafe by Flow: Uncovering Bidirectional Data-Flow Risks in MCP Ecosystem.” 预印本. [arXiv:2605.07836](https://arxiv.org/abs/2605.07836)

21. Chris Schneider, Kriti Faujdar, Philipp Schoenegger, Ben Bariach. “Securing Multi-Tool AI Agent Chains With Dynamic, Real-Time Compositional Policies.” 预印本. [arXiv:2607.03423](https://arxiv.org/abs/2607.03423)

22. Mohammadreza Rashidi. “Unicode TAG-Block Concealment of Tool-Metadata Payloads in the Model Context Protocol: An Approval-View Fidelity Gap Across Three Independent Server Implementations.” 预印本. [arXiv:2607.05744](https://arxiv.org/abs/2607.05744)

23. Baichao An, Pei Chen, Geng Hong, Yueyue Chen, Mengying Wu. “FlowGuard: From Signals to Evidence for MCP Security Detection.” 预印本. [arXiv:2607.14754](https://arxiv.org/abs/2607.14754)

24. Shenghan Zheng, Qifan Zhang, Zheng Zhang, Haonan Li, Christophe Hauser. “Formal Security Analysis of Agent Protocol Composition.” 预印本（AgentThread）. [arXiv:2606.28690](https://arxiv.org/abs/2606.28690)

25. Sunil Prakash. “AIP: Agent Identity Protocol for Verifiable Delegation Across MCP and A2A.” 预印本. [arXiv:2603.24775](https://arxiv.org/abs/2603.24775)

26. Jiawen Shi, Zenghui Yuan, Guiyao Tie, Pan Zhou, Neil Gong, Lichao Sun. “Prompt Injection Attack to Tool Selection in LLM Agents.” *NDSS 2026*. [DOI](https://doi.org/10.14722/ndss.2026.230675) · [NDSS](https://www.ndss-symposium.org/ndss-paper/prompt-injection-attack-to-tool-selection-in-llm-agents/)

27. Zichuan Li, Jian Cui, Xiaojing Liao, Luyi Xing. “Les Dissonances: Cross-Tool Harvesting and Polluting in Pool-of-Tools Empowered LLM Agents.” *NDSS 2026*. [DOI](https://doi.org/10.14722/ndss.2026.240577) · [NDSS](https://www.ndss-symposium.org/ndss-paper/les-dissonances-cross-tool-harvesting-and-polluting-in-pool-of-tools-empowered-llm-agents/)

28. Zhiqiang Wang, Yichao Gao, Yanting Wang, Suyuan Liu, Haifeng Sun, Haoran Cheng, Guanquan Shi, Haohua Du, Xiangyang Li. “MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers.” 预印本. [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)

## 14. 最终验收标准

这套研究底座真正落地，不以“引用了多少篇论文”为完成标准，而以以下可验收结果为准：

1. 每一条对外安全主张都能落到 `TaskOK / ActionOK / SourceOK / DataOK` 中至少一项；
2. 每一项写“已实现”的能力都能指向真实执行路径和可重复测试，不以未接入的类或设计稿冒充；
3. 每个 attack demo 都有同形 benign 对照、无副作用 canary、固定 consequence 和技术错误分母；
4. 每个 finding 都带 evidence level，不把 semantic signal、静态路径和运行时确认混为一谈；
5. Tool identity 报告明确区分 TOFU continuity、operator pin、publisher origin 和 backend behavior；
6. 同一 proxy 与跨 Server/跨进程结果分开，scan failure 与 clean 分开，step-up 与 prevented 分开；
7. `proof` 被准确描述为结构化决策证据；只有连接 task/approval/dispatch/result/effect 后才称 execution receipt；
8. 产品演示既能展示当前已防住的路径，也能用负向 fixture 解释下一层架构为什么必要。

满足这些条件，RiskProof 的故事就不再是“我们也能扫 MCP”，而是一个清晰、可证伪、可逐层增强的研究型产品：**模型可以继续不确定地推理，但真实权限必须在确定性的证据边界内流动。**
