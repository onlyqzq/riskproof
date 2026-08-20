# Awesome DeepSeek Harness Plugin 收录审核对齐记录

## 1 文档目的

本文记录 RiskProof 面向 Awesome DeepSeek Harness Plugin 收录审核已经完成的工作、`v0.2.0` 迭代、审核规则映射、可复现验证结果和待完成的外部操作，供项目维护者与收录审核者快速核对。

- 对齐基准：[Awesome DeepSeek Harness Plugin contributing.md](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/blob/main/contributing.md)
- 收录申请：[awesome-dsh-plugin/awesome-dsh-plugin#1916](https://github.com/awesome-dsh-plugin/awesome-dsh-plugin/pull/1916)
- 目标仓库：[onlyqzq/dsh-riskproof](https://github.com/onlyqzq/dsh-riskproof)
- 候选版本：`0.2.0`
- 收录状态：PR #1916 已合并
- 状态日期：2026-08-20

本文中的“已完成”表示对应实现和验证已存在于候选代码中；“待外部操作”表示仍需推送、打标签或发布，二者不混用。

## 2 当前审核结论

PR #1916 的 `check` 与 `Submission gate` 均已通过，并于 2026-08-19 22:35（UTC+8）合并到上游 `main`。上游数据文件已收录 `onlyqzq/dsh-riskproof`，URL、名称、`security` 分类和中英文描述均正确。候选代码满足上游强制结构要求，并进一步补齐真实安装、官方 peer dependency、发布一致性、安全边界和回归测试。

收录流程已经完成，但 `v0.2.0` 发布流程尚未结束：本轮候选改动仍需推送到公开仓库并发布到 npm，才能让 registry 中的仓库映射、公开源码与本文验收结果完全一致。

## 3 收录规范逐项对齐

| 上游审核项 | 候选代码状态 | 核对依据 |
| --- | --- | --- |
| 声明 `dsh.bundle` | 已完成 | `package.json` 声明 `dsh.bundle.patch`，对应 `cordis.patch.yml` |
| 插件具有真实可运行功能 | 已完成 | 接入 `tools/pre-execute` 与 `tools/result`；集成测试和演示使用真实 DSH ToolRuntime |
| 仓库建立至少 1 天且至少 10 个提交 | 已满足 | 2026-08-19 快照：仓库创建于 2026-07-13，共 10 个提交 |
| 项目处于维护状态 | 已满足 | 近期提交、Issue 模板、PR 模板、变更记录、发布与 CI 工作流均已配置 |
| GitHub 包含 `dsh-plugin` topic | 已满足 | 仓库 topics 包含 `dsh-plugin`、`agent-security`、`provenance`、`tool-security` |
| 描述准确且不使用营销性最高级 | 已完成 | PR 描述对应来源追踪、跨工具敏感流和执行前拦截的实际实现 |
| 分类准确 | 已完成 | 归入 `security`，与执行安全和信息流控制职责一致 |
| 官方包使用 peer dependency | 已完成 | `@deepseek-ai/cordis`、`dsh-agent`、`dsh-tools`、`schemastery` 均声明为 peer dependency |
| 预发布版本范围可解析 | 已完成 | DSH peer 范围显式包含 `0.1.0-rc.7` 预发布元组 |
| npm 仓库映射与收录 URL 一致 | 代码已完成，待发版 | 候选清单指向 `onlyqzq/dsh-riskproof`；registry 中的 `0.1.0` 仍保留旧的重定向地址 |
| 可从 npm 安装 | 已完成 | 发布包包含预构建 `dist/` 与 bundle patch，不需要安装期构建授权 |
| 可从 Git 源安装 | 已完成 | `prepare` 自动构建；CI 从无 `dist/` 的 Git 源安装并验证入口 |
| PR 只修改本插件条目 | 已满足 | PR 仅新增本插件 YAML，并更新由上游生成的中英文 README |
| 截图 | 不适用，非阻塞 | 本项目是无独立 UI 的被动安全插件；上游将截图列为可选项 |

## 4 已完成功能与代码依据

| 能力 | 已实现内容 | 主要依据 |
| --- | --- | --- |
| DSH 原生接入 | 在执行前完成 `allow`、`ask`、`deny` 裁决，在成功结果后更新状态 | `src/dsh/runtime.ts`、`src/index.ts` |
| 工具能力分类 | 基于名称、描述和 schema 的确定性分类，支持中英文词汇和显式覆盖 | `src/classification/` |
| 来源追踪 | 按会话记录工具结果，支持精确匹配、受限子串匹配和包装文本反向匹配 | `src/provenance/` |
| 嵌套参数分析 | 有界遍历对象和数组，保留稳定叶子路径，拒绝原型污染式键名 | `src/core/arguments.ts` |
| 污点传播 | 对敏感标签执行加法传播，不因普通工具输出自动降密 | `src/core/taint.ts` |
| 工具链检测 | 按真实顺序识别 `EIT -> PAT -> NAT`，避免把 `PAT -> EIT` 误判为攻击链 | `src/toolchain/guard.ts` |
| 目的地判定 | 同时处理 URL 与裸域名，并支持内部域名配置 | `src/core/destination.ts` |
| 安全证据 | 生成脱敏 proof，可选择以权限 `0600` 追加写入 JSONL | `src/proof/proof-store.ts` |
| 配置安全 | 验证数值上限、字段关系、分类覆盖和危险键名 | `src/config.ts`、`src/classification/overrides.ts` |
| 生命周期隔离 | 按 Agent 隔离同名能力缓存，按会话释放或限制状态 | `src/dsh/runtime.ts`、`src/provenance/context-tracker.ts` |
| 策略适配 | 提供 `permissive`、`balanced`、`strict` 预设及逐项覆盖 | `src/config.ts` |
| 敏感路径保护 | 在读取或写入常见凭据文件前执行门控，并排除模板文件 | `src/core/path-policy.ts` |
| 危险命令检测 | 对灾难性操作、破坏性命令、远程脚本管道和凭据网络命令执行有界检查 | `src/core/command-risk.ts`、`src/core/engine.ts` |
| 出口域名策略 | 支持目标 denylist 和可选 allowlist，不把参数扫描宣传为网络防火墙 | `src/core/destination.ts`、`src/core/engine.ts` |
| 可操作证据 | proof 记录脱敏处置建议，并按规则统计命中次数 | `src/proof/proof-store.ts` |

## 5 工程化与社区维护事项

- 提供中英文 README、安装、架构、安全模型、来源与污点、工具链、配置、开发和迁移文档。
- 提供 Apache-2.0 许可证、贡献指南、安全报告流程、Issue 模板和 PR 模板。
- npm 包只发布运行所需的 `dist/`、bundle patch、README 和许可证。
- 发布流程使用 npm OIDC provenance；发布前验证 tag 与 `package.json` 版本完全一致。
- CI 覆盖 Node.js 22.19 与 24，并执行类型检查、构建、覆盖率门槛、打包安装、Git 源安装和真实 DSH plugin manager 安装。
- `npm run check:marketplace` 固化仓库 URL、bundle、发布文件、官方 peer dependency 和预发布范围要求，避免后续改动破坏收录兼容性。

## 6 可复现验证

在仓库根目录执行：

```bash
npm ci
npm run check:marketplace
npm run verify
npm run test:coverage
npm run demo
npm pack --dry-run
```

验收标准如下：

| 验证项 | 通过标准 |
| --- | --- |
| 依赖安装 | `npm ci` 无审计漏洞 |
| 市场规范 | 输出 `Marketplace readiness check passed.` |
| 类型与构建 | 源码和测试类型检查通过，`dist/index.js` 与声明文件生成 |
| 自动化测试 | 单元、集成和安全回归测试全部通过 |
| 覆盖率 | statements >= 85%、branches >= 75%、functions >= 85%、lines >= 88% |
| 攻击链演示 | Web 摄入与私密访问完成后，外部发送在执行前被拒绝 |
| 包内容 | tarball 包含 `dist/` 和 `cordis.patch.yml`，且可导入 `apply` |
| DSH 安装 | `plugin add` 后 profile 包含 `dsh-riskproof` bundle，组合配置出现 `riskproof` 行 |

2026-08-20 本地验收结果：

| 验证项 | 实测结果 |
| --- | --- |
| 依赖安装 | `npm ci` 成功，审计结果为 0 个漏洞 |
| 市场规范 | `npm run check:marketplace` 通过 |
| 自动化测试 | 13 个测试文件、141 项测试全部通过；Node.js 24.19.0 复验通过 |
| 覆盖率 | statements 90.00%、branches 83.12%、functions 92.38%、lines 92.71% |
| 攻击链演示 | 外部发送返回 `deny`，工具主体未执行，生成脱敏 proof ID |
| 干净源码打包 | `prepare` 从无 `dist/` 状态重建成功；tarball 48.3 kB，共 45 个文件 |
| Git 源安装 | 从不含 `dist/` 的临时 Git 快照安装、构建和模块导入成功 |
| DSH 安装 | tarball 经 DSH `0.1.0-rc.7` plugin manager 安装成功，bundle 与 `riskproof` 行均可验证 |
| 代码格式 | `git diff --check` 通过 |

## 7 待完成的外部操作

1. 将候选改动推送至 `onlyqzq/dsh-riskproof` 的公开分支，等待本仓库 CI 全部通过。
2. 在 CI 通过后创建 `v0.2.0` 标签，由发布工作流生成 GitHub Release 并发布 npm `0.2.0`。
3. 核对 `npm view dsh-riskproof repository homepage bugs` 已全部指向 `onlyqzq/dsh-riskproof`。
4. 发布后核对 Awesome 列表与市场详情页能够继续识别 npm 包；普通版本升级无需重复提交收录申请。
5. 仅在仓库 URL、分类或描述需要调整时，按上游规范提交最小范围的元数据变更；截图属于可选增强，不作为阻塞项。

## 8 审核者快速核对路径

建议按以下顺序核对，无需启动模型或提供凭据：

1. 查看 `package.json` 和 `cordis.patch.yml`，确认 DSH bundle 与 peer dependency。
2. 运行 `npm run check:marketplace`，确认收录相关元数据未漂移。
3. 运行 `npm run demo`，观察最后一个外部动作在执行前被拒绝。
4. 查看 `tests/security/attack-chain.test.ts` 与 `tests/integration/plugin-lifecycle.test.ts`，核对真实管线和生命周期行为。
5. 查看 `docs/security-model.md`，确认威胁模型、非目标和已知限制没有被宣传文案掩盖。

## 9 已知边界

RiskProof 只保护经过 DSH `tools/pre-execute` 和 `tools/result` 可观测路径的工具调用。它不替代操作系统沙箱、网络防火墙、SSRF 防护、端点安全、凭据保险库或完整语义 DLP。来源映射是确定性、受限的文本匹配，而不是对任意编码或语义改写的完备追踪。
