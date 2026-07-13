// ============================================================================
// RiskProof — MCP Proxy Server (v2 cleaned)
// ============================================================================
// Transparent JSON-RPC proxy: Agent → RiskProof → Upstream MCP Server.
// Intercepts tools/call, evaluates risk, routes by decision.
// ============================================================================

import { spawn, type ChildProcess } from "node:child_process";
import { closeSync, createReadStream, openSync } from "node:fs";
import { createInterface, type Interface } from "node:readline";
import type { Readable } from "node:stream";
import { evaluate } from "./engine.js";
import { ProofStore } from "./proof-store.js";
import { formatCard, formatCompact, sanitizeTerminal } from "./explainer.js";
import { redactEngineOutput, redactLogText } from "./redaction.js";
import type { RiskProofConfig } from "./config.js";
import type { EngineInput, EngineOutput, TaintLabel, SafetyInvariant, Capability, UserAction } from "./types.js";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface ProxyOptions {
  upstream: string[];
  proofDir?: string;
  interactive?: boolean;
  env?: Record<string, string>;
  invariants?: SafetyInvariant[];
  config?: RiskProofConfig;
  /** Trust unsigned approval metadata supplied by the MCP client. Disabled by default. */
  allowClientDecisions?: boolean;
}

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: number | string;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

interface PendingRequest {
  resolve: (r: JsonRpcResponse) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface MCPToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

// ─── Constants ─────────────────────────────────────────────────────────────────

const FORWARD_TIMEOUT = 30_000;
export const MCP_MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MCP_SHUTDOWN_GRACE_MS = 1_000;
export const MCP_MAX_PENDING_REQUESTS = 128;
export const MCP_MAX_OUTPUT_QUEUE_BYTES = 8 * 1024 * 1024;
export const MCP_BACKPRESSURE_TIMEOUT_MS = 5_000;
const ERR = { BLOCKED: -32000, REQUIRES_APPROVAL: -32001, INTERNAL: -32603, INVALID_PARAMS: -32602 };
const SENSITIVE_PARENT_ENV = [
  "OPENAI_API_KEY",
  "DEEPSEEK_API_KEY",
  "ANTHROPIC_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "GOOGLE_API_KEY",
];
const FORWARDABLE_CLIENT_NOTIFICATIONS = new Set([
  "notifications/initialized",
  "notifications/cancelled",
  "notifications/progress",
  "notifications/roots/list_changed",
]);
const SCHEMA_POISONING_EVIDENCE_ARG = "__riskproof_tool_schema_evidence__";

// MCP stdio messages are newline-delimited JSON. node:readline has no input
// bound, so an unterminated line can otherwise grow until the process runs out
// of memory. This reader enforces the limit while bytes are still arriving.
class LimitedLineReader {
  private readonly input: Readable;
  private readonly onLine: (line: string) => void;
  private readonly onEnd: () => void;
  private readonly onFailure: (error: Error) => void;
  private readonly parts: Buffer[] = [];
  private byteLength = 0;
  private closed = false;

  constructor(
    input: Readable,
    onLine: (line: string) => void,
    onEnd: () => void,
    onFailure: (error: Error) => void,
  ) {
    this.input = input;
    this.onLine = onLine;
    this.onEnd = onEnd;
    this.onFailure = onFailure;
    input.on("data", this.handleData);
    input.once("end", this.handleEnd);
    input.once("error", this.handleError);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.parts.length = 0;
    this.byteLength = 0;
    this.detach();
    this.input.pause();
  }

  private readonly handleData = (chunk: Buffer | string): void => {
    if (this.closed) return;
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf-8");
    let start = 0;

    while (!this.closed) {
      const newline = buffer.indexOf(0x0a, start);
      if (newline === -1) {
        this.append(buffer.subarray(start));
        return;
      }
      if (!this.append(buffer.subarray(start, newline))) return;
      this.emitLine();
      start = newline + 1;
      if (start >= buffer.length) return;
    }
  };

  private readonly handleEnd = (): void => {
    if (this.closed) return;
    if (this.byteLength > 0) this.emitLine();
    if (this.closed) return;
    this.closed = true;
    this.detach();
    this.onEnd();
  };

  private readonly handleError = (error: Error): void => {
    this.fail(error);
  };

  private append(part: Buffer): boolean {
    if (part.length === 0) return true;
    if (this.byteLength + part.length > MCP_MAX_LINE_BYTES) {
      this.fail(new Error(`JSON-RPC line exceeds ${MCP_MAX_LINE_BYTES} byte limit`));
      return false;
    }
    this.parts.push(part);
    this.byteLength += part.length;
    return true;
  }

  private emitLine(): void {
    const buffer = this.parts.length === 1
      ? this.parts[0]
      : Buffer.concat(this.parts, this.byteLength);
    const end = buffer.length > 0 && buffer[buffer.length - 1] === 0x0d
      ? buffer.length - 1
      : buffer.length;
    this.parts.length = 0;
    this.byteLength = 0;
    this.onLine(buffer.toString("utf-8", 0, end));
  }

  private fail(error: Error): void {
    if (this.closed) return;
    this.closed = true;
    this.parts.length = 0;
    this.byteLength = 0;
    this.detach();
    this.input.pause();
    this.onFailure(error);
  }

  private detach(): void {
    this.input.off("data", this.handleData);
    this.input.off("end", this.handleEnd);
    this.input.off("error", this.handleError);
  }
}

// ─── Tool name mapping (MCP → RiskProof) ──────────────────────────────────────

function mapToolName(name: string): string {
  const lower = name.toLowerCase();
  if (/(\bshell\b|\bbash\b|\bexec\b|command|deploy|config|apply|run|script|terminal|restart|patch|commit|push|pipeline|generate|build|compile|install|update)/.test(lower)) return "shell_exec";
  if (/(\bhttp\b|fetch|request|\bweb\b|\bapi\b|\burl\b|export|report|upload|download|gateway|proxy|\bsync\b|\btag\b|dashboard|marketing|crm)/.test(lower)) return "http_request";
  if (/(\bemail\b|\bmail\b|send|notify|notification|\balert\b|message|publish|post)/.test(lower)) return "send_email";
  return "shell_exec"; // default: treat unknown commands as shell
}

// ─── Schema poisoning detection ────────────────────────────────────────────────

const SUSPICIOUS_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /ignore\s+(all\s+)?previous\s+instructions/i, label: "ignore_previous_instructions" },
  { re: /send\s+(the\s+)?secrets?\b/i, label: "send_secrets" },
  { re: /\bexfiltrate\b/i, label: "exfiltrate" },
  { re: /bypass\s+(security|policy|approval)/i, label: "bypass_security" },
  { re: /override\s+(system|security)\b/i, label: "override_security" },
  { re: /steal\s+(data|credentials|secrets)/i, label: "steal_data" },
];

function scanTool(def: MCPToolDef): string[] {
  const text = JSON.stringify([def.description ?? "", def.inputSchema ? JSON.stringify(def.inputSchema) : ""]);
  return SUSPICIOUS_PATTERNS.filter(({ re }) => re.test(text)).map((p) => p.label);
}

// ─── Proxy Server ─────────────────────────────────────────────────────────────

export class McpProxyServer {
  private upstream: string[];
  private proofStore: ProofStore;
  private interactive: boolean;
  private env: Record<string, string>;
  private invariants: SafetyInvariant[];
  private config?: RiskProofConfig;
  private allowClientDecisions: boolean;
  private proc: ChildProcess | null = null;
  private toolCache = new Map<string, MCPToolDef>();
  private pending = new Map<number | string, PendingRequest>();
  private poisonedTools = new Set<string>();
  private upstreamReader: LimitedLineReader | null = null;
  private inputReader: LimitedLineReader | null = null;
  private promptReadlines = new Set<Interface>();
  private started = false;
  private stopped = false;
  private readonly exitPromise: Promise<number>;
  private resolveExit!: (code: number) => void;
  private stderrListener?: (chunk: Buffer) => void;
  private processExitListener?: (code: number | null, signal: NodeJS.Signals | null) => void;
  private processErrorListener?: (error: Error) => void;
  private stdinErrorListener?: (error: Error) => void;
  private upstreamDrainListener?: () => void;
  private outputDrainListener?: () => void;
  private upstreamDrainTimer?: ReturnType<typeof setTimeout>;
  private outputDrainTimer?: ReturnType<typeof setTimeout>;
  private readonly outputQueue: string[] = [];
  private outputQueueHead = 0;
  private outputQueueBytes = 0;
  private outputFailed = false;

  constructor(opts: ProxyOptions) {
    if (!opts.upstream?.length) throw new Error("--upstream is required");
    this.upstream = opts.upstream;
    this.proofStore = new ProofStore(opts.proofDir);
    this.interactive = opts.interactive !== false;
    this.env = opts.env ?? {};
    this.invariants = opts.invariants ?? [];
    this.config = opts.config;
    this.allowClientDecisions = opts.allowClientDecisions === true;
    this.exitPromise = new Promise((resolve) => { this.resolveExit = resolve; });
  }

  async start(): Promise<void> {
    if (this.started) throw new Error("MCP proxy has already been started");
    if (this.stopped) throw new Error("MCP proxy has already been stopped");
    this.started = true;
    this.proc = this.spawnUpstream();
    const log = (msg: string) => {
      const safe = sanitizeTerminal(redactLogText(msg), 4000);
      if (safe) process.stderr.write(`[riskproof] ${safe}\n`);
    };
    const proc = this.proc;

    this.processExitListener = (code, signal) => {
      log(`upstream exited (${code ?? signal ?? "unknown"})`);
      const reason = new Error(`upstream exited (${code ?? signal ?? "unknown"})`);
      this.finish(reason, code === 0 && this.pending.size === 0 ? 0 : 1, false);
    };
    this.processErrorListener = (error) => {
      log(`upstream error: ${sanitizeTerminal(redactLogText(error.message), 1000)}`);
      this.finish(new Error(`upstream error: ${error.message}`), 1, false);
    };
    this.stdinErrorListener = (error) => {
      log(`upstream stdin error: ${sanitizeTerminal(redactLogText(error.message), 1000)}`);
      this.finish(new Error(`upstream stdin error: ${error.message}`), 1, true);
    };
    proc.once("exit", this.processExitListener);
    proc.once("error", this.processErrorListener);
    proc.stdin?.once("error", this.stdinErrorListener);

    // Upstream stdout → parse responses
    this.upstreamReader = new LimitedLineReader(proc.stdout!, (line) => {
      try {
        const obj = JSON.parse(line.trim());
        if (!obj || !line.trim()) return;
        if (obj.id !== undefined && (obj.result !== undefined || obj.error !== undefined)) {
          const p = this.pending.get(obj.id);
          if (p) { clearTimeout(p.timer); this.pending.delete(obj.id); p.resolve(obj); }
          else this.writeOutput(line.trim() + "\n");
        } else {
          this.writeOutput(line.trim() + "\n");
        }
      } catch {
        const safe = sanitizeTerminal(redactLogText(line), 1000);
        if (safe) log(`upstream: ${safe}`);
      }
    }, () => {
      log("upstream stdout closed");
      const reason = new Error("upstream stdout closed");
      // ChildProcess normally emits `exit` before the streams' final `close`,
      // but stdout can end first. Give the exit event one turn to preserve a
      // clean upstream exit code; otherwise EOF is a protocol failure.
      setImmediate(() => this.finish(reason, 1, true));
    }, (error) => {
      log(`upstream protocol error: ${error.message}`);
      this.finish(new Error(`upstream protocol error: ${error.message}`), 1, true);
    });

    // Upstream stderr forwarding
    this.stderrListener = (chunk: Buffer) => {
      const safe = sanitizeTerminal(redactLogText(chunk.toString("utf-8")), 4000);
      if (safe) process.stderr.write(`[upstream] ${safe}\n`);
    };
    proc.stderr?.on("data", this.stderrListener);

    // Stdin: Agent → Proxy
    this.inputReader = new LimitedLineReader(process.stdin, (line) => {
      const msg = this.parseMessage(line);
      if (!msg) { if (line.trim()) log(`skipped: ${line.slice(0, 80)}`); return; }
      void this.handle(msg, log).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        log(`client handling error: ${message}`);
        this.finish(new Error(`client handling error: ${message}`), 1, true);
      });
    }, () => {
      log("client input closed");
      this.finish(new Error("client input closed"), 0, true);
    }, (error) => {
      log(`client protocol error: ${error.message}`);
      this.finish(new Error(`client protocol error: ${error.message}`), 1, true);
    });

    log(`proxy started → ${sanitizeTerminal(redactLogText(this.upstream.join(" ")), 1000)}`);
  }

  stop(): void {
    this.finish(new Error("MCP proxy stopped"), 0, true);
  }

  waitForExit(): Promise<number> {
    return this.exitPromise;
  }

  // ── Message routing ──────────────────────────────────────────────────────────

  private async handle(msg: JsonRpcRequest, log: (s: string) => void): Promise<void> {
    const { method, id, params } = msg;

    // JSON-RPC notifications cannot receive a policy error response. Only the
    // explicit client→server MCP protocol notifications are safe to forward.
    // In particular, never let an id-less tools/call bypass evaluation/proof.
    if (id === undefined || id === null) {
      if (FORWARDABLE_CLIENT_NOTIFICATIONS.has(method)) {
        this.writeToUpstream(msg);
      } else {
        log(`dropped id-less request method: ${sanitizeTerminal(method, 200)}`);
      }
      return;
    }

    try {
      switch (method) {
        case "initialize": await this.forward(id, msg); break;
        case "tools/list": await this.handleToolsList(id, log); break;
        case "tools/call": await this.handleToolsCall(id, params ?? {}, log); break;
        case "riskproof/evaluate": this.handleRiskproofEvaluate(id, params ?? {}, log); break;
        default: await this.forward(id, msg);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`error: ${msg}`);
      this.write(makeError(id, ERR.INTERNAL, msg));
    }
  }

  // ── tools/list: scan + cache ─────────────────────────────────────────────────

  private async handleToolsList(id: number | string, log: (s: string) => void): Promise<void> {
    const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/list" };
    let resp: JsonRpcResponse;
    try { resp = await this.forwardRequest(req); }
    catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); return; }

    if (resp.result && typeof resp.result === "object") {
      const tools = (resp.result as any).tools as Array<Record<string, unknown>> | undefined;
      if (Array.isArray(tools)) {
        this.toolCache.clear();
        this.poisonedTools.clear();
        for (const t of tools) {
          const def: MCPToolDef = { name: t.name as string, description: t.description as string | undefined, inputSchema: t.inputSchema as any };
          this.toolCache.set(def.name, def);
          const hits = scanTool(def);
          if (hits.length > 0) {
            this.poisonedTools.add(def.name);
            log(`⚠ poisoned: ${sanitizeTerminal(def.name, 200)} → ${hits.join(", ")}`);
          }
        }
        // Do not expose poisoned descriptions/schemas to the planning model.
        // Direct calls remain blocked because the full cache is retained.
        (resp.result as { tools: Array<Record<string, unknown>> }).tools = tools.filter(
          (tool) => typeof tool.name === "string" && !this.poisonedTools.has(tool.name),
        );
      }
    }
    this.write(resp);
  }

  // ── tools/call: intercept + evaluate ─────────────────────────────────────────

  private handleRiskproofEvaluate(
    id: number | string,
    params: Record<string, unknown>,
    log: (s: string) => void,
  ): void {
    const parsed = parseToolCallParams(params);
    if ("error" in parsed) {
      this.write(makeError(id, ERR.INVALID_PARAMS, parsed.error));
      return;
    }
    const { result } = this.evaluateToolCall(parsed.toolName, parsed.args, id);
    log(`riskproof/evaluate: ${sanitizeTerminal(parsed.toolName, 200)} → ${result.action}`);
    this.proofStore.save(result);
    this.write({ jsonrpc: "2.0", id, result: redactEngineOutput(result) });
  }

  private async handleToolsCall(id: number | string, params: Record<string, unknown>, log: (s: string) => void): Promise<void> {
    const parsed = parseToolCallParams(params);
    if ("error" in parsed) {
      this.write(makeError(id, ERR.INVALID_PARAMS, parsed.error));
      return;
    }
    const { toolName, args } = parsed;
    const { cached, result } = this.evaluateToolCall(toolName, args, id);
    const safeToolName = sanitizeTerminal(toolName, 200);
    log(`tools/call: ${safeToolName} → ${result.action} [${result.matchedPolicies.map((p) => p.id).join(", ") || "no rules"}]`);

    // Route
    switch (result.action) {
      case "allow": {
        this.proofStore.save(result);
        process.stderr.write(`  [PASS] ${safeToolName}\n`);
        const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
        try { this.write(await this.forwardRequest(req)); }
        catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); }
        break;
      }

      case "block": {
        this.proofStore.save(result);
        const card = formatCard(result, { toolName, toolDesc: cached?.description });
        process.stderr.write("\n" + card + "\n");
        this.write(makeError(id, ERR.BLOCKED, formatCompact(result, { toolName })));
        break;
      }

      case "ask_approval": {
        // ── Pre-approval signal from agent (LangGraph interrupt flow) ──────
        const meta = (params as any)?._meta;
        const userDecision: string | undefined = meta?.riskproof_user_decision;

        if (this.allowClientDecisions && userDecision === "approve") {
          this.proofStore.save(result, "approve");
          process.stderr.write(`  [APPROVED] User pre-approved via agent — forwarding\n\n`);
          const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
          try { this.write(await this.forwardRequest(req)); }
          catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); }
          return;
        }

        if (this.allowClientDecisions && userDecision === "reject") {
          this.proofStore.save(result, "reject");
          process.stderr.write(`  [REJECTED] User rejected via agent\n\n`);
          this.write(makeError(id, ERR.BLOCKED, "Rejected by user"));
          return;
        }

        if (!this.interactive) {
          const card = formatCompact(result, { toolName });
          process.stderr.write("\n" + card + "\n  [REVIEW] Non-interactive — auto-denied.\n\n");
          this.proofStore.save(result, "reject", "Auto-denied in non-interactive mode");
          this.write(makeError(id, ERR.REQUIRES_APPROVAL, card));
          return;
        }

        const card = formatCard(result, { toolName, toolDesc: cached?.description });
        process.stderr.write("\n" + card + "\n");
        const decision = await this.promptUser();

        if (decision === "approve") {
          this.proofStore.save(result, "approve");
          process.stderr.write("  [APPROVED] Forwarding...\n\n");
          const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
          try { this.write(await this.forwardRequest(req)); }
          catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); }
        } else {
          this.proofStore.save(result, "reject");
          process.stderr.write("  [REJECTED] Blocked by user.\n\n");
          this.write(makeError(id, ERR.BLOCKED, "Rejected by user"));
        }
        break;
      }
    }
  }

  private evaluateToolCall(
    toolName: string,
    args: Record<string, unknown>,
    requestId: number | string,
  ): { cached?: MCPToolDef; result: EngineOutput } {
    const cached = this.toolCache.get(toolName);
    const isPoisoned = this.poisonedTools.has(toolName);
    const mappedTool = mapToolName(toolName);

    // Schema poisoning is a property of the tool definition, not of any one
    // business argument. Always add internal evidence so a zero-argument
    // poisoned tool cannot evade the forbidden-taint rule and default-allow.
    let schemaEvidenceArg = SCHEMA_POISONING_EVIDENCE_ARG;
    while (Object.hasOwn(args, schemaEvidenceArg)) schemaEvidenceArg = `_${schemaEvidenceArg}`;
    const evaluationArgs: Record<string, unknown> = isPoisoned
      ? { ...args, [schemaEvidenceArg]: toolName }
      : args;

    // Build EngineInput
    const taints: Record<string, TaintLabel[]> = {};
    const provenance: Record<string, string[]> = {};
    for (const key of Object.keys(evaluationArgs)) {
      provenance[key] = [isPoisoned ? "mcp_schema" : "mcp_tool"];
      if (isPoisoned) taints[key] = ["UNTRUSTED_TOOL_SCHEMA"];
    }

    const input: EngineInput = {
      tool: mappedTool as EngineInput["tool"],
      args: evaluationArgs,
      provenance,
      taints: Object.keys(taints).length > 0 ? taints : undefined,
      capability: isPoisoned
        ? { tool: mappedTool as Capability["tool"], forbiddenTaints: ["UNTRUSTED_TOOL_SCHEMA"] }
        : undefined,
      invariants: this.invariants.length > 0 ? [...this.invariants] : undefined,
      trace: { traceId: `proxy-${Date.now()}`, stepId: String(requestId) },
    };

    const result = evaluate(input, this.config);
    return { cached, result };
  }

  // ── Interactive prompt ───────────────────────────────────────────────────────

  private promptUser(): Promise<UserAction> {
    return new Promise((resolve) => {
      if (this.promptReadlines.size > 0) {
        process.stderr.write("  [REVIEW] Another interactive approval is active; rejecting this concurrent request.\n");
        resolve("reject");
        return;
      }
      let ttyInput: ReturnType<typeof createReadStream>;
      let ttyFd: number | undefined;
      try {
        ttyFd = openSync("/dev/tty", "r");
        ttyInput = createReadStream("/dev/tty", { fd: ttyFd, autoClose: true });
      } catch {
        if (ttyFd !== undefined) {
          try { closeSync(ttyFd); } catch { /* descriptor was not opened or already closed */ }
        }
        process.stderr.write("  [REVIEW] No independent TTY is available; rejecting instead of reading approval from protocol stdin.\n");
        resolve("reject");
        return;
      }
      const rl = createInterface({ input: ttyInput, crlfDelay: Infinity });
      this.promptReadlines.add(rl);
      const closeOnInputError = () => rl.close();
      ttyInput.once("error", closeOnInputError);

      const prompt = () => process.stderr.write("  Choice: [A]pprove  [R]eject\n  > ");

      rl.on("line", (line: string) => {
        const c = line.trim().toLowerCase();
        if (c === "a" || c === "approve") { rl.close(); resolve("approve"); }
        else if (c === "r" || c === "reject") { rl.close(); resolve("reject"); }
        else { process.stderr.write("  Invalid choice. Enter A or R.\n"); prompt(); }
      });

      rl.on("close", () => {
        this.promptReadlines.delete(rl);
        ttyInput.off("error", closeOnInputError);
        ttyInput.destroy();
        resolve("reject");
      });
      prompt();
    });
  }

  // ── IO helpers ───────────────────────────────────────────────────────────────

  private parseMessage(line: string): JsonRpcRequest | null {
    const t = line.trim();
    if (!t) return null;
    try {
      const o = JSON.parse(t) as Record<string, unknown>;
      if (o.jsonrpc !== "2.0" || typeof o.method !== "string" || o.method.length === 0) {
        return null;
      }
      if (Object.hasOwn(o, "id")) {
        if (typeof o.id !== "string" && typeof o.id !== "number") return null;
        if (typeof o.id === "number" && !Number.isFinite(o.id)) return null;
      }
      return o as unknown as JsonRpcRequest;
    }
    catch { return null; }
  }

  private write(msg: JsonRpcResponse): void {
    this.writeOutput(JSON.stringify(msg) + "\n");
  }

  private writeOutput(value: string): void {
    if (this.outputFailed) return;
    if (this.outputDrainListener) {
      this.enqueueOutput(value);
      return;
    }
    if (process.stdout.write(value)) return;
    this.beginOutputBackpressure();
  }

  private enqueueOutput(value: string): void {
    const bytes = Buffer.byteLength(value, "utf-8");
    if (this.outputQueueBytes + bytes > MCP_MAX_OUTPUT_QUEUE_BYTES) {
      this.outputFailed = true;
      process.stderr.write("[riskproof] client output queue exceeded its byte limit\n");
      this.finish(new Error("client output queue exceeded its byte limit"), 1, true);
      return;
    }
    this.outputQueue.push(value);
    this.outputQueueBytes += bytes;
  }

  private beginOutputBackpressure(): void {
    if (this.outputDrainListener) return;
    this.proc?.stdout?.pause();
    process.stdin.pause();
    this.outputDrainListener = () => {
      if (this.outputDrainTimer) clearTimeout(this.outputDrainTimer);
      this.outputDrainTimer = undefined;
      this.outputDrainListener = undefined;
      this.flushOutputQueue();
    };
    process.stdout.once("drain", this.outputDrainListener);
    this.outputDrainTimer = setTimeout(() => {
      this.outputFailed = true;
      process.stderr.write("[riskproof] client output backpressure timed out\n");
      this.finish(new Error("client output backpressure timed out"), 1, true);
    }, MCP_BACKPRESSURE_TIMEOUT_MS);
  }

  private flushOutputQueue(): void {
    while (this.outputQueueHead < this.outputQueue.length) {
      const value = this.outputQueue[this.outputQueueHead++];
      this.outputQueueBytes -= Buffer.byteLength(value, "utf-8");
      if (!process.stdout.write(value)) {
        this.compactOutputQueue();
        this.beginOutputBackpressure();
        return;
      }
    }
    this.outputQueue.length = 0;
    this.outputQueueHead = 0;
    this.outputQueueBytes = 0;
    if (!this.stopped) {
      this.proc?.stdout?.resume();
      if (!this.upstreamDrainListener) process.stdin.resume();
    }
  }

  private compactOutputQueue(): void {
    if (this.outputQueueHead === 0) return;
    this.outputQueue.splice(0, this.outputQueueHead);
    this.outputQueueHead = 0;
  }

  private writeToUpstream(msg: JsonRpcRequest): void {
    if (!this.proc?.stdin || this.proc.killed) throw new Error("upstream not available");
    if (this.upstreamDrainListener) throw new Error("upstream stdin is backpressured");
    if (this.proc.stdin.write(JSON.stringify(msg) + "\n")) return;
    process.stdin.pause();
    const upstreamStdin = this.proc.stdin;
    this.upstreamDrainListener = () => {
      if (this.upstreamDrainTimer) clearTimeout(this.upstreamDrainTimer);
      this.upstreamDrainTimer = undefined;
      this.upstreamDrainListener = undefined;
      if (!this.stopped && !this.outputDrainListener) process.stdin.resume();
    };
    upstreamStdin.once("drain", this.upstreamDrainListener);
    this.upstreamDrainTimer = setTimeout(() => {
      this.finish(new Error("upstream stdin backpressure timed out"), 1, true);
    }, MCP_BACKPRESSURE_TIMEOUT_MS);
  }

  private async forward(id: number | string, req: JsonRpcRequest): Promise<void> {
    try { this.write(await this.forwardRequest(req)); }
    catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); }
  }

  private forwardRequest(req: JsonRpcRequest): Promise<JsonRpcResponse> {
    return new Promise((resolve, reject) => {
      const id = req.id!;
      if (this.pending.has(id)) {
        reject(new Error(`duplicate in-flight JSON-RPC id: ${id}`));
        return;
      }
      if (this.pending.size >= MCP_MAX_PENDING_REQUESTS) {
        reject(new Error(`too many in-flight JSON-RPC requests (max ${MCP_MAX_PENDING_REQUESTS})`));
        return;
      }
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`timeout: ${id}`)); }, FORWARD_TIMEOUT);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.writeToUpstream(req);
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private spawnUpstream(): ChildProcess {
    const [cmd, ...args] = this.upstream;
    const childEnv = { ...process.env };
    for (const name of SENSITIVE_PARENT_ENV) delete childEnv[name];
    return spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...childEnv, ...this.env },
    });
  }

  private finish(reason: Error, exitCode: number, killUpstream: boolean): void {
    if (this.stopped) return;
    this.stopped = true;

    for (const [, request] of this.pending) {
      clearTimeout(request.timer);
      request.reject(reason);
    }
    this.pending.clear();

    this.upstreamReader?.close();
    this.upstreamReader = null;
    this.inputReader?.close();
    this.inputReader = null;
    for (const readline of this.promptReadlines) readline.close();
    this.promptReadlines.clear();

    const proc = this.proc;
    this.proc = null;
    if (proc) {
      if (this.stderrListener) proc.stderr?.off("data", this.stderrListener);
      if (this.processExitListener) proc.off("exit", this.processExitListener);
      if (this.processErrorListener) proc.off("error", this.processErrorListener);
      if (this.stdinErrorListener) proc.stdin?.off("error", this.stdinErrorListener);
      if (this.upstreamDrainListener) proc.stdin?.off("drain", this.upstreamDrainListener);
      proc.stdin?.destroy();
      if (killUpstream && proc.exitCode === null && proc.signalCode === null) {
        let settled = false;
        let forceTimer: ReturnType<typeof setTimeout> | undefined;
        const settleAfterChildExit = (): void => {
          if (settled) return;
          settled = true;
          if (forceTimer) clearTimeout(forceTimer);
          proc.off("exit", settleAfterChildExit);
          proc.stdout?.destroy();
          proc.stderr?.destroy();
          this.resolveExit(exitCode);
        };

        proc.once("exit", settleAfterChildExit);
        forceTimer = setTimeout(() => {
          if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGKILL");
        }, MCP_SHUTDOWN_GRACE_MS);
        proc.kill("SIGTERM");
        if (proc.exitCode !== null || proc.signalCode !== null) settleAfterChildExit();
        return;
      }
      proc.stdout?.destroy();
      proc.stderr?.destroy();
    }
    this.stderrListener = undefined;
    this.processExitListener = undefined;
    this.processErrorListener = undefined;
    this.stdinErrorListener = undefined;
    this.upstreamDrainListener = undefined;
    if (this.upstreamDrainTimer) clearTimeout(this.upstreamDrainTimer);
    this.upstreamDrainTimer = undefined;
    if (this.outputDrainListener) process.stdout.off("drain", this.outputDrainListener);
    this.outputDrainListener = undefined;
    if (this.outputDrainTimer) clearTimeout(this.outputDrainTimer);
    this.outputDrainTimer = undefined;
    this.outputQueue.length = 0;
    this.outputQueueHead = 0;
    this.outputQueueBytes = 0;
    this.resolveExit(exitCode);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeError(id: number | string, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function parseToolCallParams(params: Record<string, unknown>):
  | { toolName: string; args: Record<string, unknown> }
  | { error: string } {
  const toolName = params.name;
  const rawArgs = params.arguments ?? {};
  if (typeof toolName !== "string" || toolName.length === 0) {
    return { error: "Missing or invalid param: name" };
  }
  if (typeof rawArgs !== "object" || rawArgs === null || Array.isArray(rawArgs)) {
    return { error: "Invalid param: arguments must be an object" };
  }
  return { toolName, args: rawArgs as Record<string, unknown> };
}
