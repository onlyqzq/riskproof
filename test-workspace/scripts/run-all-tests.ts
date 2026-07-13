#!/usr/bin/env node
// ============================================================================
// RiskProof Test Workspace — TypeScript 全场景测试引擎
// ============================================================================
// 直接调用 RiskProof API，完全绕过 Claude 权限系统。
//
// 用法:
//   npx tsx test-workspace/scripts/run-all-tests.ts                    # 全部测试
//   npx tsx test-workspace/scripts/run-all-tests.ts --category block   # 按类别
//   npx tsx test-workspace/scripts/run-all-tests.ts --scenario S02     # 单个场景
//   npx tsx test-workspace/scripts/run-all-tests.ts --report markdown  # 输出报告
//   npx tsx test-workspace/scripts/run-all-tests.ts --mcp-proxy        # MCP 代理模式
// ============================================================================

import { readFileSync, readdirSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate, parseEngineInput } from "../../packages/riskproof/src/index.js";

// ─── 测试用例定义 ────────────────────────────────────────────────────────────

interface TestScenario {
  file: string;
  scenario: string;
  expectedAction: "allow" | "block" | "ask_approval";
  event: Record<string, unknown>;
}

interface TestResult {
  scenario: TestScenario;
  pass: boolean;
  actualAction: string;
  exitCode: number;
  decision: string;
  riskLevel: string;
  matchedRules: string[];
  reason: string;
  evidence: string[];
  error?: string;
}

type ScenarioFilter =
  | { type: "scenario"; value: string }
  | { type: "category"; value: TestScenario["expectedAction"] };

// ─── 加载场景 ────────────────────────────────────────────────────────────────

const __dirname = dirname(fileURLToPath(import.meta.url));
const WORKSPACE_DIR = resolve(__dirname, "..");
const SCENARIOS_DIR = resolve(WORKSPACE_DIR, "test-cases", "scenarios");

function loadScenarios(filter?: ScenarioFilter): TestScenario[] {
  const files = readdirSync(SCENARIOS_DIR)
    .filter((f) => f.endsWith(".json"))
    .sort();

  const scenarios: TestScenario[] = [];

  for (const file of files) {
    const filePath = resolve(SCENARIOS_DIR, file);
    const raw = JSON.parse(readFileSync(filePath, "utf-8")) as Record<string, unknown>;

    const scenario = (raw.scenario as string) || file;

    // 提取期望结果
    let expectedAction: TestScenario["expectedAction"] = "allow";
    if (scenario.includes("BLOCK")) expectedAction = "block";
    else if (scenario.includes("ASK_APPROVAL")) expectedAction = "ask_approval";
    else if (scenario.includes("ALLOW")) expectedAction = "allow";

    // 构建 event（移除 scenario 字段）
    const { scenario: _, ...event } = raw;

    scenarios.push({
      file: filePath,
      scenario,
      expectedAction,
      event,
    });
  }

  // 过滤
  if (filter) {
    if (filter.type === "scenario") {
      return scenarios.filter((s) =>
        s.file.includes(filter.value) || s.scenario.includes(filter.value),
      );
    }
    if (filter.type === "category") {
      return scenarios.filter((s) => s.expectedAction === filter.value);
    }
  }

  return scenarios;
}

// ─── 测试方法选择 ────────────────────────────────────────────────────────────

type TestMethod = "api" | "cli";

async function runViaApi(scenario: TestScenario): Promise<TestResult> {
  // Directly call the current public RiskProof API (no external tools execute).
  const result = evaluate(parseEngineInput(scenario.event));
  const proof = result.proof;
  const actualAction = result.action;

  const pass = actualAction === scenario.expectedAction;

  return {
    scenario,
    pass,
    actualAction,
    exitCode: { allow: 0, ask_approval: 2, block: 3 }[actualAction] ?? 1,
    decision: result.decision,
    riskLevel: result.riskLevel,
    matchedRules: proof.matchedRules.map((rule) => rule.id),
    reason: proof.reason,
    evidence: proof.evidence,
  };
}

async function runViaCli(scenario: TestScenario): Promise<TestResult> {
  // Invoke the current riskproof check CLI (still no real tool execution).
  const { spawnSync } = await import("node:child_process");
  const { writeFileSync, unlinkSync, mkdirSync } = await import("node:fs");
  const { randomUUID } = await import("node:crypto");
  const { resolve } = await import("node:path");

  const PROJECT_DIR = resolve(WORKSPACE_DIR, "..");
  const CLI_ENTRY = resolve(PROJECT_DIR, "packages", "riskproof", "src", "cli.ts");
  const tmpDir = resolve(WORKSPACE_DIR, ".tmp");
  mkdirSync(tmpDir, { recursive: true });
  const tmpFile = resolve(tmpDir, `test-${randomUUID()}.json`);
  writeFileSync(tmpFile, JSON.stringify(scenario.event), "utf-8");

  try {
    const result = spawnSync("node", ["--import", "tsx/esm", CLI_ENTRY, "check", tmpFile], {
      encoding: "utf-8",
      timeout: 10_000,
    });

    let output: any = {};
    try { output = JSON.parse(result.stdout || "{}"); } catch { /* ok */ }

    const actualAction = output.action || "unknown";
    const pass = actualAction === scenario.expectedAction;

    return {
      scenario,
      pass,
      actualAction,
      exitCode: result.status ?? 1,
      decision: output.decision || "unknown",
      riskLevel: output.riskLevel || "unknown",
      matchedRules: (output.matchedRules || []).map((r: any) => r.id),
      reason: output.reason || "",
      evidence: output.evidence || [],
      error: result.stderr || undefined,
    };
  } finally {
    try { unlinkSync(tmpFile); } catch { /* ok */ }
  }
}

// ─── 输出格式化 ──────────────────────────────────────────────────────────────

const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[0;31m",
  green: "\x1b[0;32m",
  yellow: "\x1b[1;33m",
  blue: "\x1b[0;34m",
  cyan: "\x1b[0;36m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
};

function color(c: keyof typeof COLORS, text: string): string {
  return `${COLORS[c]}${text}${COLORS.reset}`;
}

function printResult(result: TestResult, index: number): void {
  const icon = result.pass ? color("green", "✓") : color("red", "✗");
  const status = result.pass ? color("green", "PASS") : color("red", "FAIL");

  const num = String(index).padStart(2, "0");
  const actionColors: Record<string, string> = {
    allow: color("green", "ALLOW    "),
    block: color("red", "BLOCK    "),
    ask_approval: color("yellow", "APPROVAL "),
    unknown: color("red", "UNKNOWN  "),
  };

  console.log(
    `  ${icon} ${status} [${num}] ${result.scenario.scenario}`
  );
  console.log(
    `      expected=${result.scenario.expectedAction.padEnd(13)} ` +
    `actual=${(result.actualAction || "error").padEnd(13)} ` +
    `risk=${(result.riskLevel || "?").padEnd(8)} ` +
    `decision=${result.decision || "?"}`
  );
  if (result.matchedRules.length > 0) {
    console.log(`      rules: ${result.matchedRules.join(", ")}`);
  }
  if (result.reason) {
    console.log(`      reason: ${result.reason.slice(0, 120)}`);
  }
  if (result.error) {
    console.log(`      ${color("yellow", "stderr:")} ${result.error.slice(0, 120)}`);
  }
  console.log("");
}

function printSummary(results: TestResult[]): void {
  const pass = results.filter((r) => r.pass).length;
  const fail = results.filter((r) => !r.pass).length;
  const total = results.length;
  const passRate = total > 0 ? ((pass / total) * 100).toFixed(1) : "0";

  console.log(color("bold", "──────────────────────────────────────────────────────────────────────"));
  console.log(`  ${color("bold", "Summary:")}`);
  console.log(`    ${color("green", "PASS:")}  ${pass}`);
  console.log(`    ${color("red", "FAIL:")}  ${fail}`);
  console.log(`    TOTAL: ${total}`);
  console.log(`    ${color("bold", "Pass Rate:")} ${passRate}%`);
  console.log("");

  // 按规则统计
  const allRules = new Map<string, number>();
  for (const r of results) {
    for (const rule of r.matchedRules) {
      allRules.set(rule, (allRules.get(rule) || 0) + 1);
    }
  }
  if (allRules.size > 0) {
    console.log(`  ${color("bold", "Rule Coverage:")}`);
    const sorted = [...allRules.entries()].sort((a, b) => b[1] - a[1]);
    for (const [rule, count] of sorted) {
      const bar = "█".repeat(Math.min(count, 20));
      console.log(`    ${rule.padEnd(40)} ${bar} ${count}`);
    }
    console.log("");
  }

  // 按期望分类统计
  console.log(`  ${color("bold", "Per-Category Accuracy:")}`);
  for (const cat of ["allow", "block", "ask_approval"]) {
    const catResults = results.filter((r) => r.scenario.expectedAction === cat);
    const catPass = catResults.filter((r) => r.pass).length;
    const catTotal = catResults.length;
    if (catTotal > 0) {
      const rate = ((catPass / catTotal) * 100).toFixed(0);
      console.log(`    ${cat.padEnd(15)} ${catPass}/${catTotal}  (${rate}%)`);
    }
  }
  console.log("");
  console.log(color("bold", "──────────────────────────────────────────────────────────────────────"));
}

function printMarkdownReport(results: TestResult[]): void {
  const pass = results.filter((r) => r.pass).length;
  const total = results.length;

  console.log(`# RiskProof Test Report\n`);
  console.log(`**Pass Rate:** ${pass}/${total} (${((pass/total)*100).toFixed(1)}%)\n`);
  console.log(`| # | Scenario | Expected | Actual | Risk | Rules |`);
  console.log(`|---|----------|----------|--------|------|-------|`);

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const icon = r.pass ? "✅" : "❌";
    const name = r.scenario.scenario.slice(0, 60);
    const rules = r.matchedRules.join(", ") || "—";
    console.log(
      `| ${icon} | ${name} | ${r.scenario.expectedAction} | ${r.actualAction} | ${r.riskLevel} | ${rules} |`
    );
  }

  console.log(`\n## Rule Coverage\n`);
  const allRules = new Map<string, number>();
  for (const r of results) {
    for (const rule of r.matchedRules) {
      allRules.set(rule, (allRules.get(rule) || 0) + 1);
    }
  }
  console.log(`| Rule | Hits |`);
  console.log(`|------|------|`);
  for (const [rule, count] of [...allRules.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`| ${rule} | ${count} |`);
  }
}

// ─── 主函数 ──────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  // 解析参数
  let filter: ScenarioFilter | undefined;
  let method: TestMethod = "api"; // 默认使用 API 模式（最快）
  let reportFormat: "terminal" | "markdown" = "terminal";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--category" && args[i + 1]) {
      const category = args[++i];
      const categories: Record<string, TestScenario["expectedAction"]> = {
        allow: "allow",
        block: "block",
        approval: "ask_approval",
        ask_approval: "ask_approval",
      };
      if (!categories[category]) throw new Error(`Unknown category '${category}'`);
      filter = { type: "category", value: categories[category] };
    } else if (args[i] === "--scenario" && args[i + 1]) {
      filter = { type: "scenario", value: args[++i] };
    } else if (args[i] === "--cli") {
      method = "cli";
    } else if (args[i] === "--mcp-proxy") {
      throw new Error("Use test-workspace/scripts/test-via-proxy.sh for the real MCP proxy integration test");
    } else if (args[i] === "--report" && args[i + 1]) {
      const format = args[++i];
      if (format !== "terminal" && format !== "markdown") {
        throw new Error(`Unknown report format '${format}'`);
      }
      reportFormat = format;
    } else {
      throw new Error(`Unknown or incomplete test option '${args[i]}'`);
    }
  }

  const scenarios = loadScenarios(filter);

  if (scenarios.length === 0) {
    console.error("No test scenarios found.");
    process.exit(1);
  }

  const methodLabel = {
    api: "Direct API (evaluate)",
    cli: "CLI (riskproof check)",
  }[method];

  if (reportFormat === "terminal") {
    console.log("");
    console.log(color("bold", color("cyan", "══════════════════════════════════════════════════════════════════════")));
    console.log(color("bold", color("cyan", "  RiskProof Test Harness — 全场景安全策略测试")));
    console.log(color("bold", color("cyan", "══════════════════════════════════════════════════════════════════════")));
    console.log("");
    console.log(`  ${color("blue", "Method:")}   ${methodLabel}`);
    console.log(`  ${color("blue", "Scenarios:")} ${scenarios.length}`);
    console.log(`  ${color("blue", "Bypass:")}   ${color("green", "✓")} 完全绕过 Claude 权限系统`);
    console.log("");
  }

  const results: TestResult[] = [];

  for (let i = 0; i < scenarios.length; i++) {
    const s = scenarios[i];
    let result: TestResult;

    try {
      switch (method) {
        case "cli":
          result = await runViaCli(s);
          break;
        case "api":
        default:
          result = await runViaApi(s);
      }
    } catch (err) {
      result = {
        scenario: s,
        pass: false,
        actualAction: "error",
        exitCode: 1,
        decision: "error",
        riskLevel: "unknown",
        matchedRules: [],
        reason: "",
        evidence: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }

    results.push(result);

    if (reportFormat === "terminal") {
      printResult(result, i + 1);
    }
  }

  if (reportFormat === "terminal") {
    printSummary(results);
  } else if (reportFormat === "markdown") {
    printMarkdownReport(results);
  }

  const failed = results.filter((r) => !r.pass).length;
  if (failed > 0) {
    process.exit(1);
  }
}

main();
