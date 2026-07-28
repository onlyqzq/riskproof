#!/usr/bin/env node
// ============================================================================
// RiskProof CLI
// ============================================================================
// Commands:
//   check <event.json> [--pretty]     Evaluate a single tool call event
//   proxy --upstream <cmd...>         Start MCP transparent proxy
//   serve [--port <n>] [--host <h>]   Start HTTP server (language-agnostic)
//   demo [--proof-dir <dir>]          Run all fixtures, generate proof + report
// ============================================================================

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { basename, resolve } from "node:path";
import { evaluate } from "./engine.js";
import { evaluateWithOpa, OpaPolicyEngine } from "./opa-policy.js";
import { loadConfig } from "./config.js";
import type { RiskProofConfig } from "./config.js";
import { McpProxyServer } from "./proxy-server.js";
import { startHttpServer } from "./http-server.js";
import { ProofStore, type ProofStoreOptions } from "./proof-store.js";
import { ALL_FIXTURES } from "./fixtures.js";
import { parseEngineInput } from "./validation.js";
import type { EngineInput, ToolName, TaintLabel, Capability } from "./types.js";
import type { Fixture } from "./fixtures.js";

// ─── Help Text ─────────────────────────────────────────────────────────────────

function help(exitCode = 0): void {
  console.log(`Usage:
  riskproof check <event-json-file> [--pretty] [--config|-c <path>] [--opa-policy <policy.wasm>]
  riskproof proxy --upstream <command...> [--proof-dir <path>] [--no-interactive] [--allow-client-decisions] [--config|-c <path>] [--opa-policy <policy.wasm>]
  riskproof serve [--port <n>] [--host <host>] [--proof-dir <path>] [--cors-origin <origin>] [--trust-request-context] [--config|-c <path>] [--opa-policy <policy.wasm>]
  riskproof demo [--proof-dir <path>] [--config|-c <path>] [--opa-policy <policy.wasm>]
  riskproof validate-config <config-file>

Global options:
  --config, -c   Path to RiskProof config file (.json or .yaml)
  --opa-policy   Compiled Rego WASM bundle; repeat to load multiple modules

Options (check):
  --pretty        Pretty-print JSON output

Options (proxy):
  --upstream      Command to spawn upstream MCP server (required)
  --proof-dir     Proof store directory (default: .riskproof/proofs)
  --no-interactive Auto-deny ask_approval decisions
  --allow-client-decisions Trust unsigned approve/reject metadata from a trusted client (unsafe on untrusted transports)
  --              Within --upstream, pass remaining arguments verbatim (use for flags that collide with proxy options)

Options (serve):
  --port          HTTP port (default: RISKPROOF_PORT or 9090)
  --host          Bind address (default: RISKPROOF_HOST or 127.0.0.1)
  --proof-dir     Proof store directory (default: RISKPROOF_PROOF_DIR or .riskproof/proofs)
  --cors-origin   Exact browser origin to allow (default: disabled)
  --trust-request-context Accept caller capability/invariants/options (trusted networks only)

Options (demo):
  --proof-dir     Output directory for proofs and report (default: customer-proofs)

Environment: RISKPROOF_CONFIG, RISKPROOF_OPA_POLICY, RISKPROOF_PROOF_DIR,
             RISKPROOF_PROOF_ENCRYPTION_KEY(_FILE),
             RISKPROOF_PROOF_SIGNING_KEY(_FILE),
             RISKPROOF_PROOF_REQUIRE_ENCRYPTION, RISKPROOF_PROOF_REQUIRE_SIGNATURE,
             RISKPROOF_RETENTION_MAX_DAYS, RISKPROOF_RETENTION_MAX_RECORDS,
             RISKPROOF_PORT, RISKPROOF_HOST, RISKPROOF_CORS_ORIGIN

Exit codes: 0=allow, 2=ask_approval, 3=block, 1=error`);
  process.exit(exitCode);
}

// ─── CLI Entry ─────────────────────────────────────────────────────────────────

async function main(argv: string[]): Promise<void> {
  const args = argv.slice(2);
  if (args.length === 0) { help(1); return; }
  if (args[0] === "--help" || args[0] === "-h") { help(0); return; }

  const cmd = args[0];
  const rest = args.slice(1);

  // Extract global config/policy flags before command-specific parsing.
  let configPath: string | undefined = process.env.RISKPROOF_CONFIG || undefined;
  const opaPaths: string[] = process.env.RISKPROOF_OPA_POLICY
    ? process.env.RISKPROOF_OPA_POLICY.split(process.platform === "win32" ? ";" : ":").filter(Boolean)
    : [];
  const filtered: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === "--") {
      filtered.push(...rest.slice(i));
      break;
    }
    if (rest[i] === "--config" || rest[i] === "-c") {
      if (i + 1 >= rest.length) throw new Error(`${rest[i]} requires a file path`);
      configPath = rest[++i];
    } else if (rest[i] === "--opa-policy") {
      if (i + 1 >= rest.length) throw new Error("--opa-policy requires a .wasm file path");
      opaPaths.push(rest[++i]);
    } else {
      filtered.push(rest[i]);
    }
  }

  const opaPolicies = cmd === "validate-config" ? [] : await Promise.all(opaPaths.map((path, index) => {
    const stem = basename(path).replace(/\.wasm$/i, "").replace(/[^A-Za-z0-9_-]/g, "_");
    const id = `policy_${index + 1}_${stem || "rego"}`.slice(0, 128);
    return OpaPolicyEngine.loadFile(path, { id });
  }));
  const proofStoreOptions = ["proxy", "serve", "demo"].includes(cmd)
    ? proofStoreOptionsFromEnvironment()
    : {};

  // Load config once
  let config: RiskProofConfig | undefined;
  if (configPath) {
    try {
      config = loadConfig(resolve(configPath));
    } catch (err) {
      console.error(JSON.stringify({ error: `Failed to load config: ${err instanceof Error ? err.message : err}` }));
      process.exit(1);
    }
  }

  try {
    switch (cmd) {
      case "check": runCheck(filtered, config, opaPolicies); return;
      case "proxy": await runProxy(filtered, config, opaPolicies, proofStoreOptions); return;
      case "serve": runServe(filtered, config, opaPolicies, proofStoreOptions); return;
      case "demo": runDemo(filtered, config, opaPolicies, proofStoreOptions); return;
      case "validate-config": runValidateConfig(filtered); return;
      default:
        console.error(`Unknown command: ${cmd}`);
        help(1);
    }
  } catch (err) {
    console.error(JSON.stringify({ error: err instanceof Error ? err.message : String(err) }));
    process.exit(1);
  }
}

// ─── check ─────────────────────────────────────────────────────────────────────

// Claude Code → RiskProof tool name mapping
const CC_TOOL_MAP: Record<string, string> = {
  Bash: "shell_exec",
  WebFetch: "http_request", WebSearch: "http_request",
  Read: "file_read", Glob: "file_read", Grep: "file_read",
  Write: "file_write", Edit: "file_write", MultiEdit: "file_write",
};

function runCheck(
  args: string[],
  config?: RiskProofConfig,
  opaPolicies: readonly OpaPolicyEngine[] = [],
): void {
  let pretty = false;
  const positional: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--pretty") pretty = true;
    else positional.push(args[i]);
  }

  if (positional.length === 0) {
    console.error("Usage: riskproof check <event-json-file> [--pretty] [--config <path>]");
    process.exit(1);
  }

  const filePath = resolve(positional[0]);
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(filePath, "utf-8")); }
  catch (err) { throw new Error(`Failed to read event file: ${err instanceof Error ? err.message : err}`); }

  // Auto-detect: Claude Code format or RiskProof format
  let input: EngineInput;
  if (isRecord(raw) && typeof raw.tool_name === "string" && raw.tool_input !== undefined) {
    const mapped = CC_TOOL_MAP[raw.tool_name];
    if (!mapped) {
      throw new Error(
        `Unsupported Claude Code tool '${raw.tool_name}'. ` +
        `RiskProof supports shell, web, file read, and file write checks.`,
      );
    }
    input = parseEngineInput({
      tool: mapped,
      args: raw.tool_input,
      provenance: raw.provenance,
      taints: raw.taints,
      capability: raw.capability,
      invariants: raw.invariants,
      trace: raw.trace,
      options: raw.options,
    });
  } else if (isRecord(raw) && raw.tool !== undefined && raw.args !== undefined) {
    input = parseEngineInput(raw);
  } else {
    throw new Error("Invalid event: expected {tool_name, tool_input} or {tool, args}");
  }

  const result = opaPolicies.length > 0
    ? evaluateWithOpa(input, opaPolicies, config)
    : evaluate(input, config);
  const proof = result.proof;

  const output = {
    action: result.action,
    decision: result.decision,
    riskLevel: result.riskLevel,
    proofId: proof.proofId,
    ...(proof.traceId ? { traceId: proof.traceId } : {}),
    ...(proof.stepId ? { stepId: proof.stepId } : {}),
    reason: proof.reason,
    evidence: proof.evidence,
    matchedRules: proof.matchedRules.map((r) => ({ id: r.id, triggeredArgs: r.triggeredArgs, evidence: r.evidence, reason: r.reason })),
  };

  console.log(pretty ? JSON.stringify(output, null, 2) : JSON.stringify(output));

  const exitCode: Record<string, number> = { allow: 0, ask_approval: 2, block: 3 };
  process.exit(exitCode[result.action] ?? 1);
}

// ─── proxy ─────────────────────────────────────────────────────────────────────

async function runProxy(
  args: string[],
  config?: RiskProofConfig,
  opaPolicies: readonly OpaPolicyEngine[] = [],
  proofStoreOptions: Omit<ProofStoreOptions, "baseDir"> = {},
): Promise<void> {
  const upstream: string[] = [];
  let proofDir: string | undefined = process.env.RISKPROOF_PROOF_DIR || undefined;
  let interactive = true;
  let allowClientDecisions = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--upstream") {
      while (i + 1 < args.length && !["--proof-dir", "--no-interactive", "--allow-client-decisions"].includes(args[i + 1])) {
        if (args[i + 1] === "--") {
          i += 1;
          while (i + 1 < args.length) upstream.push(args[++i]);
          break;
        }
        upstream.push(args[++i]);
      }
    } else if (args[i] === "--proof-dir" && i + 1 < args.length) {
      proofDir = args[++i];
    } else if (args[i] === "--no-interactive") {
      interactive = false;
    } else if (args[i] === "--allow-client-decisions") {
      allowClientDecisions = true;
    } else {
      throw new Error(`Unknown proxy option: ${args[i]}`);
    }
  }

  if (upstream.length === 0) {
    console.error("Usage: riskproof proxy --upstream <command...> [--proof-dir <path>] [--no-interactive] [--config <path>]");
    process.exit(1);
  }

  const server = new McpProxyServer({
    upstream,
    proofDir,
    interactive,
    config,
    allowClientDecisions,
    opaPolicies,
    proofStoreOptions,
  });
  const shutdown = () => server.stop();
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
  try {
    await server.start();
    const exitCode = await server.waitForExit();
    if (exitCode !== 0) process.exitCode = exitCode;
  } finally {
    process.off("SIGINT", shutdown);
    process.off("SIGTERM", shutdown);
    server.stop();
  }
}

// ─── serve ─────────────────────────────────────────────────────────────────────

function runServe(
  args: string[],
  config?: RiskProofConfig,
  opaPolicies: readonly OpaPolicyEngine[] = [],
  proofStoreOptions: Omit<ProofStoreOptions, "baseDir"> = {},
): void {
  let port = readPort(process.env.RISKPROOF_PORT, 9090, "RISKPROOF_PORT");
  let host = process.env.RISKPROOF_HOST || "127.0.0.1";
  let proofDir: string | undefined = process.env.RISKPROOF_PROOF_DIR || undefined;
  let corsOrigin: string | undefined = process.env.RISKPROOF_CORS_ORIGIN || undefined;
  let trustRequestContext = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--port" && i + 1 < args.length) {
      port = readPort(args[++i], 9090, "--port");
    } else if (args[i] === "--host" && i + 1 < args.length) {
      host = args[++i];
    } else if (args[i] === "--proof-dir" && i + 1 < args.length) {
      proofDir = args[++i];
    } else if (args[i] === "--cors-origin" && i + 1 < args.length) {
      corsOrigin = args[++i];
    } else if (args[i] === "--trust-request-context") {
      trustRequestContext = true;
    } else {
      throw new Error(`Unknown or incomplete serve option: ${args[i]}`);
    }
  }

  const server = startHttpServer({
    port,
    host,
    proofDir,
    corsOrigin,
    config,
    trustRequestContext,
    opaPolicies,
    proofStoreOptions,
  });

  // Graceful shutdown
  const shutdown = () => {
    process.stderr.write("[riskproof] Shutting down HTTP server...\n");
    server.closeIdleConnections();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000); // Force exit after 5s
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// ─── demo ──────────────────────────────────────────────────────────────────────

function runDemo(
  args: string[],
  config?: RiskProofConfig,
  opaPolicies: readonly OpaPolicyEngine[] = [],
  proofStoreOptions: Omit<ProofStoreOptions, "baseDir"> = {},
): void {
  let proofDir = process.env.RISKPROOF_PROOF_DIR || "customer-proofs";
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--proof-dir" && i + 1 < args.length) {
      proofDir = args[++i];
    } else {
      throw new Error(`Unknown or incomplete demo option: ${args[i]}`);
    }
  }

  const store = new ProofStore({ ...proofStoreOptions, baseDir: resolve(proofDir) });
  console.log(`\n  RiskProof Demo — ${ALL_FIXTURES.length} fixtures\n`);
  console.log("  " + "─".repeat(70));

  let pass = 0;
  let fail = 0;

  for (const f of ALL_FIXTURES) {
    // Register tools (simulate MCP tools/list)
    const isPoisoned = f.setup.some((t) => {
      const text = JSON.stringify([t.description ?? "", t.inputSchema ? JSON.stringify(t.inputSchema) : ""]);
      return /ignore.*previous.*instructions|send.*secrets|exfiltrate|bypass.*security|override.*(system|security)|steal.*(data|credentials)/i.test(text);
    });

    const taints: Record<string, TaintLabel[]> = {};
    const provenance: Record<string, string[]> = {};
    for (const key of Object.keys(f.call.arguments)) {
      provenance[key] = [isPoisoned ? "mcp_schema" : "agent_generated"];
      if (isPoisoned) taints[key] = ["UNTRUSTED_TOOL_SCHEMA"];
    }
    // Merge fixture-provided provenance (don't overwrite, append)
    if (f.call.provenance) {
      for (const key of Object.keys(f.call.provenance)) {
        if (!provenance[key]) provenance[key] = [];
        provenance[key].push(...f.call.provenance[key]);
      }
    }
    if (f.call.taints) {
      for (const key of Object.keys(f.call.taints)) {
        if (!taints[key]) taints[key] = [];
        taints[key].push(...f.call.taints[key]);
      }
    }

    // Construct capability with poisoning consideration
    let capability: Capability | undefined = f.call.capability;
    if (isPoisoned) {
      capability = {
        tool: capability?.tool ?? "shell_exec",
        forbiddenTaints: ["UNTRUSTED_TOOL_SCHEMA", ...(capability?.forbiddenTaints ?? [])],
      };
    }

    const input: EngineInput = {
      tool: f.call.capability?.tool ?? "shell_exec",
      args: f.call.arguments,
      provenance,
      taints: Object.keys(taints).length > 0 ? taints : undefined,
      capability,
      invariants: f.call.invariants,
      trace: f.call.trace,
    };

    // Tool name mapping
    if (f.call.toolName) {
      const mapped = mapToolForDemo(f.call.toolName, f.call.capability?.tool);
      if (mapped) input.tool = mapped;
    }

    const result = opaPolicies.length > 0
      ? evaluateWithOpa(input, opaPolicies, config)
      : evaluate(input, config);
    const ok = result.action === f.expectedAction;
    const rulesOk = f.expectedRules.every((r) => result.matchedPolicies.some((p) => p.id === r));
    const passed = ok && rulesOk;

    if (passed) pass++; else fail++;

    const icon = passed ? "✅" : "❌";
    const actionColor = result.action === "block" ? "🔴" : result.action === "ask_approval" ? "🟡" : "🟢";
    console.log(`  ${icon} ${actionColor} [${result.action.toUpperCase().padEnd(13)}] ${f.name.padEnd(30)} | ${result.matchedPolicies.map((p) => p.id).join(", ") || "none"}`);

    // Save proof
    store.save(result, f.expectedAction === "allow" ? "approve" : undefined);
  }

  console.log("  " + "─".repeat(70));
  console.log(`  Pass: ${pass}  Fail: ${fail}  Total: ${ALL_FIXTURES.length}\n`);

  // Generate summary report
  const summary = generateSummary(ALL_FIXTURES, pass, fail);
  const reportDir = resolve(proofDir, "reports");
  mkdirSync(reportDir, { recursive: true });
  writeFileSync(resolve(reportDir, "demo-summary.md"), summary, "utf-8");
  console.log(`  Report: ${reportDir}/demo-summary.md`);
  console.log(`  Proofs: ${proofDir}/\n`);

  process.exit(fail > 0 ? 1 : 0);
}

// ─── validate-config ────────────────────────────────────────────────────────────

function runValidateConfig(args: string[]): void {
  if (args.length === 0) {
    console.error("Usage: riskproof validate-config <config-file>");
    process.exit(1);
  }

  const configPath = resolve(args[0]);

  try {
    loadConfig(configPath);
    console.log(`Config is valid: ${configPath}`);
    process.exit(0);
  } catch (err) {
    console.error(`Config validation failed: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

function mapToolForDemo(toolName: string, capTool?: string): ToolName | undefined {
  if (capTool) return capTool as ToolName;
  const lower = toolName.toLowerCase().replace(/[_-]+/g, " ");
  if (/\b(sql|database|db|query|postgres|mysql|sqlite)\b/.test(lower)) return "database_query";
  if (/\b(browser|navigate|click|playwright|selenium)\b/.test(lower)) return "browser_action";
  if (/\b(write file|save file|edit file|replace file|create file)\b/.test(lower)) return "file_write";
  if (/\b(read file|open file|list files|glob files)\b/.test(lower)) return "file_read";
  if (/(\bshell\b|\bbash\b|\bexec\b|command|deploy|config|apply|run|script|restart|patch|commit|push|pipeline|generate|build|compile|install|update|list|parse|clean|rotate|setup|fix|process|execute|network)/.test(lower)) return "shell_exec";
  if (/(\bhttp\b|fetch|request|\bweb\b|\bapi\b|\burl\b|export|report|upload|download|gateway|proxy|\bsync\b|\btag\b)/.test(lower)) return "http_request";
  if (/(\bemail\b|\bmail\b|send|notify|notification|\balert\b|message|publish|post|campaign)/.test(lower)) return "send_email";
  return "shell_exec";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readPort(value: string | undefined, fallback: number, source: string): number {
  if (value === undefined || value === "") return fallback;
  if (!/^\d+$/.test(value)) throw new Error(`Invalid ${source}: ${value}`);
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid ${source}: ${value}`);
  }
  return port;
}

function proofStoreOptionsFromEnvironment(): Omit<ProofStoreOptions, "baseDir"> {
  const encryptionKey = readSecretSetting(
    "RISKPROOF_PROOF_ENCRYPTION_KEY",
    "RISKPROOF_PROOF_ENCRYPTION_KEY_FILE",
  );
  const signingKey = readSecretSetting(
    "RISKPROOF_PROOF_SIGNING_KEY",
    "RISKPROOF_PROOF_SIGNING_KEY_FILE",
  );
  const maxAgeDays = readOptionalInteger(process.env.RISKPROOF_RETENTION_MAX_DAYS, "RISKPROOF_RETENTION_MAX_DAYS");
  const maxRecords = readOptionalInteger(process.env.RISKPROOF_RETENTION_MAX_RECORDS, "RISKPROOF_RETENTION_MAX_RECORDS");
  const retention = maxAgeDays === undefined && maxRecords === undefined
    ? undefined
    : { maxAgeDays, maxRecords };
  return {
    ...(encryptionKey === undefined ? {} : { encryptionKey }),
    ...(signingKey === undefined ? {} : { signingKey }),
    requireEncryption: readBooleanEnvironment("RISKPROOF_PROOF_REQUIRE_ENCRYPTION"),
    requireSignature: readBooleanEnvironment("RISKPROOF_PROOF_REQUIRE_SIGNATURE"),
    ...(retention === undefined ? {} : { retention, pruneOnSave: true }),
  };
}

function readSecretSetting(valueName: string, fileName: string): string | undefined {
  const direct = process.env[valueName];
  const file = process.env[fileName];
  if (direct && file) throw new Error(`${valueName} and ${fileName} are mutually exclusive`);
  if (file) return readFileSync(resolve(file), "utf-8").trim();
  return direct || undefined;
}

function readBooleanEnvironment(name: string): boolean {
  const value = process.env[name];
  if (value === undefined || value === "" || value === "0" || value.toLowerCase() === "false") return false;
  if (value === "1" || value.toLowerCase() === "true") return true;
  throw new Error(`${name} must be true, false, 1, or 0`);
}

function readOptionalInteger(value: string | undefined, name: string): number | undefined {
  if (value === undefined || value === "") return undefined;
  if (!/^\d+$/.test(value)) throw new Error(`${name} must be a positive integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} must be a positive integer`);
  return parsed;
}

function generateSummary(fixtures: Fixture[], pass: number, fail: number): string {
  const attackCount = fixtures.filter((f) => f.category === "attack").length;
  const benignCount = fixtures.filter((f) => f.category === "benign").length;
  const attackBlocked = fixtures.filter((f) => f.category === "attack" && f.expectedAction === "block").length;
  const benignAllowed = fixtures.filter((f) => f.category === "benign" && f.expectedAction === "allow").length;

  return `# RiskProof Demo Summary

## Overall
- **Total Fixtures**: ${fixtures.length}
- **Pass**: ${pass}  **Fail**: ${fail}
- **Pass Rate**: ${((pass / fixtures.length) * 100).toFixed(1)}%

## Coverage
- **Attack Fixtures**: ${attackCount} (${attackBlocked} blocked, ${fixtures.filter((f) => f.category === "attack" && f.expectedAction === "ask_approval").length} require approval)
- **Benign Fixtures**: ${benignCount} (${benignAllowed} allowed)
- **False Positive Rate**: ${((fixtures.filter((f) => f.category === "benign" && f.expectedAction !== "allow").length / benignCount) * 100).toFixed(1)}%

## Protection Categories
${[...new Set(fixtures.filter((f) => f.category === "attack").map((f) => f.preventedRisk))].filter(Boolean).map((r) => `- ${r}`).join("\n")}

## Per-Fixture Results
${fixtures.map((f) => {
  const icon = f.category === "attack" ? "🔴" : "🟢";
  return `- ${icon} **${f.name}** [${f.category}/${f.expectedAction}] — ${f.description}`;
}).join("\n")}
`;
}

// ─── Run ───────────────────────────────────────────────────────────────────────

void main(process.argv).catch((error: unknown) => {
  console.error(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
