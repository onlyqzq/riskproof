# RiskProof

**面向 DeepSeek Harness 的来源感知型 Agent 执行安全插件。**

追踪工具输入从哪里来。发现跨工具的敏感数据流。在副作用发生前阻止危险行为。

[English](README.md) · [简体中文](README.zh-CN.md)

---

## RiskProof 回答的问题

大多数工具权限插件只回答一个问题：*这个工具允许调用吗？*

RiskProof 回答另一个问题：

> **这次工具调用里的数据从哪里来、经过了哪些工具、现在准备流向哪里？**

单次工具调用通常安全，但组合起来就不一定了。

```text
web_fetch          ← UNTRUSTED_WEB
   │
database_query     ← CUSTOMER_DATA
   │
send_email         ← 外部目的地
   │
RiskProof → DENY   （有证据、在副作用发生之前）
```

## 为什么是 RiskProof

| 权限规则                  | RiskProof                        |
| ------------------------- | -------------------------------- |
| 这个工具允许吗？          | 这些数据从哪里来？               |
| 单次调用                  | 跨工具数据流                     |
| 工具名                    | 来源（Provenance）+ 污点（Taint）|
| 静态规则                  | 有状态的攻击链                   |
| 权限决策                  | 有证据支撑的执行决策             |

RiskProof 是 DSH Tool Runtime 之上的一层安全策略，而不是另一套 Agent Runtime。它从不重复实现工具分发、审批或生命周期——它只观察并裁决。

## 快速开始

```bash
# 把插件加入某个 DSH profile
dsh plugin --profile <profile> add dsh-riskproof
```

最小 `cordis.patch.yml`（schema 默认值已经是安全的）：

```yaml
- insert:
    - id: riskproof
      name: dsh-riskproof
```

然后正常使用 DSH 即可。RiskProof 会静默追踪安全上下文，只有当出现危险的跨工具数据流时才会询问或拦截。

如需调整：

```yaml
- insert:
    - id: riskproof
      name: dsh-riskproof
      config:
        mode: enforce            # enforce | observe
        policy:
          sensitiveExternalAction: deny
          untrustedPrivateAccess: ask
        classification:
          overrides:
            gmail_send: [EXTERNAL_ACTION]
            company_db: [PRIVATE_ACCESS]
```

完整配置参考见 [docs/configuration.md](docs/configuration.md)。

## 效果演示

```mermaid
sequenceDiagram
    participant A as Agent
    participant T as DSH ToolRuntime
    participant R as RiskProof

    A->>T: web_fetch(url)
    T->>R: tools/pre-execute
    R-->>T: allow（记录 EXTERNAL_INGESTION）
    T-->>A: 不可信内容

    A->>T: database_query(sql)
    T->>R: tools/pre-execute
    R-->>T: allow（记录 PRIVATE_ACCESS，标记 CUSTOMER_DATA）
    T-->>A: CUST-8842 balance 125000

    A->>T: send_email(to=external, body=CUST-8842…)
    T->>R: tools/pre-execute
    R-->>T: DENY —— 摄入 + 私密访问 + 敏感数据 + 外部动作
    T-->>A: Error: <reason>
```

同样的流程被做成确定性的回归测试，见 [tests/security/attack-chain.test.ts](tests/security/attack-chain.test.ts)。

## 功能

### 追踪数据来源

知道工具输入从哪里来。RiskProof 会把参数映射回产生它们的工具结果。

### 跟随敏感数据

让安全标签——`UNTRUSTED_WEB`、`CUSTOMER_DATA`、`PII`、`SECRET` 等——以加法方式跨工具传播。

### 发现攻击链

识别 `EXTERNAL_INGESTION → PRIVATE_ACCESS → EXTERNAL_ACTION` 这一单工具检查发现不了的模式。

### 在副作用前拦截

通过原生 `tools/pre-execute` 门，在副作用执行前拦截或询问。

### 解释每一次决策

为每一次裁决生成结构化、保护隐私的安全证据。

## 工作原理

RiskProof 接入原生 DSH 工具管线：

```text
tools/pre-execute
    │  能力分类
    │  参数来源映射
    │  污点分析
    │  工具链状态（EIT → PAT → NAT）
    │  确定性策略评估
    ▼
allow / ask / deny   （与其他插件单调合并）
    │
tools/result
    │  更新 ContextTracker
    │  更新工具链状态
    ▼  记录执行证据
```

- **分类**是确定性的（工具名 + 描述 + schema）、可配置的，且从不使用 LLM。
- **来源追踪**使用精确和带边界的子串匹配，基于每个会话的上下文索引。
- **污点**是加法的；普通工具输出无法移除标签。
- **决策**是确定性、可解释、可测试的。

详见 [docs/architecture.md](docs/architecture.md)。

## 安全边界

RiskProof 保护的是 DSH 中**可观测的工具调用流**：

- 经过 `tools/pre-execute` / `tools/result` 支持的路径的 DSH 工具调用
- 可观测的来源追踪（精确 / 带边界子串匹配）
- 配置的敏感数据流与跨工具攻击模式

RiskProof **不能替代**：

- OS 沙箱 / 进程隔离
- 网络防火墙 / SSRF 防护
- 端点安全 / 恶意软件扫描
- 凭据保险库
- 完整语义 DLP

完整威胁模型与已知局限见 [docs/security-model.md](docs/security-model.md)。

## 文档

- [架构](docs/architecture.md)
- [安全模型](docs/security-model.md)
- [来源与污点](docs/provenance.md)
- [工具链模型](docs/toolchain.md)
- [配置](docs/configuration.md)
- [开发](docs/development.md)
- [从 RiskProof (MCP) 迁移](docs/migration-from-riskproof.md)

## 路线图

### v0.1（当前）

- DSH 原生运行时（`tools/pre-execute`、`tools/result`）
- 来源 + 污点追踪
- 跨工具 EIT → PAT → NAT 检测
- 保护隐私的 proof

### v0.2

- 工具身份连续性
- 任务感知策略
- 执行回执

### v0.3

- 输出侧信息流控制
- 可信降密

## 贡献

欢迎提交 Issue、规则、工具能力映射和误报报告。见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全报告

请私下报告漏洞。见 [SECURITY.md](SECURITY.md)。

## License

[Apache-2.0](LICENSE)
