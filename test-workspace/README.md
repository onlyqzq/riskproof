# RiskProof 测试工作区

这里包含 28 个确定性策略场景、一个无真实副作用的 mock MCP server，以及 API、
CLI 和 MCP 代理测试入口。测试直接向 RiskProof 提交合成工具调用，不依赖 Claude
或其他模型，因此不会被模型自身的权限系统干扰。

所有工具实现均为 mock；测试不会执行真实 Shell、发送邮件或发起业务 HTTP 请求。

## 运行

先在仓库根目录安装锁定依赖：

```bash
npm ci
```

然后运行：

```bash
# 28 个场景直接调用公共 evaluate API
npm run test:scenarios

# 相同 28 个场景通过 riskproof check CLI
npm run test:scenarios:cli

# 真实子进程 JSON-RPC 代理测试
npm run test:proxy

# 全部 TypeScript 单元与集成测试
npm run test:all

# 快速 6 场景 smoke 和 shell harness
bash test-workspace/scripts/quick-smoke.sh
bash test-workspace/scripts/run-all-tests.sh
```

MCP 集成测试验证：

- 危险命令被阻断；
- 被投毒工具不出现在模型可见的 `tools/list`，直接调用仍被阻断；
- 裸审批默认被拒绝；
- 非法 JSON-RPC arguments 被拒绝；
- `--config` 在代理真实链路生效；
- `riskproof/evaluate` 不执行上游，只保存脱敏 proof；
- 只有显式 trusted-local 模式才转发预批准调用；
- `--` 可以保留与代理参数同名的上游 flag。

## 目录

```text
test-workspace/
├── mock-server/business-tools-server.ts
├── test-cases/scenarios/01-safe-read.json ... 28-safe-email-internal.json
└── scripts/
    ├── quick-smoke.sh
    ├── run-all-tests.sh
    ├── run-all-tests.ts
    ├── test-via-proxy.sh
    └── test-via-proxy.ts
```

## 28 个场景

| 范围 | 场景 | 期望 |
|---|---|---|
| 基础安全 | S01、S27、S28 | `allow` |
| 危险 Shell | S02–S06、S23、S24、S26 | `block` |
| Secret/API Key 外发 | S07–S09 | `block` |
| 不可信来源影响 | S10、S11、S13、S19 | `ask_approval` |
| 客户数据邮件外发 | S12 | `ask_approval` |
| Capability 约束 | S14–S19 | `block` 或 `ask_approval` |
| Safety invariant | S20–S22、S25 | `block` |

这 28 个文件是稳定的业务场景集，不等同于全部 17 条规则的唯一覆盖来源。新增的
HTTP 敏感数据、嵌套 secret、多个收件人、配置、HTTP 边界、ProofStore 和其他
回归路径由 `packages/riskproof/tests/` 中的 Vitest 测试覆盖。

## 单场景和筛选

```bash
node --import tsx/esm test-workspace/scripts/run-all-tests.ts --scenario S07
node --import tsx/esm test-workspace/scripts/run-all-tests.ts --category block
node --import tsx/esm test-workspace/scripts/run-all-tests.ts --cli --scenario S02
```

手动 CLI 检查：

```bash
node --import tsx/esm packages/riskproof/src/cli.ts check \
  test-workspace/test-cases/scenarios/02-curl-bash.json --pretty
```

退出码为 `0=allow`、`2=ask_approval`、`3=block`、`1=输入/运行错误`。

## 手动 MCP 代理

使用单个 stdio 管道，不要先单独启动 mock server：

```bash
node --import tsx/esm packages/riskproof/src/cli.ts proxy \
  --no-interactive \
  --proof-dir /tmp/riskproof-proxy-proofs \
  --upstream node --import tsx/esm \
  test-workspace/mock-server/business-tools-server.ts
```

建议优先运行 `npm run test:proxy`，因为它会管理进程生命周期、超时、请求 ID 和
临时 proof 清理。

## 添加场景

在 `test-cases/scenarios/` 添加 JSON：

```json
{
  "scenario": "SXX: description → ASK_APPROVAL",
  "tool": "shell_exec",
  "args": { "command": "synthetic command" },
  "provenance": { "command": ["untrusted_webpage"] },
  "taints": { "command": ["UNTRUSTED_WEB"] },
  "capability": { "tool": "shell_exec" },
  "trace": { "traceId": "custom-001", "stepId": "custom-sxx" },
  "expected": { "action": "ask_approval" }
}
```

同时为边界和失败分支添加 Vitest 回归测试。禁止通过删除场景、降低断言、忽略
失败或硬编码结果来让测试通过。
