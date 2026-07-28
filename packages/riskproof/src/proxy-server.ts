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
import { evaluate, mergePolicyDecisions, type AdditionalPolicyDecision } from "./engine.js";
import { ProofStore, type ProofStoreOptions } from "./proof-store.js";
import { formatCard, formatCompact, sanitizeTerminal } from "./explainer.js";
import { redactEngineOutput, redactLogText } from "./redaction.js";
import { ContextTracker, ProvenanceMapper, type ContextEntry, type ContextTrackerOptions } from "./provenance.js";
import { parseEngineInput } from "./validation.js";
import { evaluateWithOpa, type OpaPolicyEngine } from "./opa-policy.js";
import {
  applyToolchainGuard,
  ToolchainGuard,
  type McpToolDescriptor,
  type ToolchainCapability,
  type ToolchainEvent,
} from "./toolchain-guard.js";
import {
  ToolIdentityGuard,
  digestToolDescriptor,
  type McpToolIdentityDescriptor,
  type ToolIdentityObservation,
} from "./tool-identity-guard.js";
import {
  TaskAuthorizationGuard,
  type TaskAuthorizationEvent,
  type TaskAuthorizationRequest,
} from "./task-authorization-guard.js";
import {
  digestToolKey,
  parseToolKey,
  type ToolKey,
  type ToolBindingVerificationResult,
  type VerifiedPinnedToolManifest,
} from "./tool-manifest.js";
import {
  ToolSelectionGuard,
  type SelectionReason,
  type ToolSelectionEvent,
} from "./tool-selection-guard.js";
import {
  ApprovalTicketVerifier,
  type ApprovalTicketAuditEvent,
  type ApprovalTicketBinding,
  type ApprovalTicketBindingField,
  type ApprovalTicketFailureCode,
  type SignedApprovalTicket,
} from "./approval-ticket.js";
import {
  PersistentTaskLedger,
  type PersistentLedgerEvent,
} from "./persistent-task-ledger.js";
import {
  digestCanonicalValue,
  ExecutionReceiptStore,
  type EffectEvidence,
  type ExecutionOutcome,
  type ExecutionReceiptDiagnostic,
  type ExecutionScope,
  type NoDispatchReason,
} from "./execution-receipt.js";
import type { RiskProofConfig } from "./config.js";
import type { EngineInput, EngineOutput, ProvenanceFlow, TaintLabel, SafetyInvariant, Capability, UserAction } from "./types.js";

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface ProxyToolNamespace {
  /** Operator-defined provider/publisher namespace. This is not inferred from tool metadata. */
  providerId: string;
  /** Stable identity for the exact upstream MCP Server deployment. */
  serverId: string;
}

export interface ProxyApprovalBindingContext {
  requestId: number | string;
  toolName: string;
  toolKey: Readonly<ToolKey>;
  descriptorDigest: string;
  args: Readonly<Record<string, unknown>>;
  result: Readonly<EngineOutput>;
  policyDigest: string;
  contractDigest?: string;
}

export interface ProxySelectionContext {
  requestId: number | string;
  toolName: string;
  toolKey: Readonly<ToolKey>;
  descriptorDigest: string;
  args: Readonly<Record<string, unknown>>;
  mappedCapability: string;
}

export interface ProxyEffectEvidenceContext {
  requestId: number | string;
  toolName: string;
  toolKey: Readonly<ToolKey>;
  descriptorDigest: string;
  args: Readonly<Record<string, unknown>>;
  response?: Readonly<JsonRpcResponse>;
  outcome: ExecutionOutcome;
}

export interface ProxyOptions {
  upstream: string[];
  proofDir?: string;
  interactive?: boolean;
  env?: Record<string, string>;
  invariants?: SafetyInvariant[];
  config?: RiskProofConfig;
  /** Trust unsigned approval metadata supplied by the MCP client. Disabled by default. */
  allowClientDecisions?: boolean;
  /** Bounds for the in-memory MCP response provenance index. */
  contextTracker?: ContextTrackerOptions;
  /**
   * Optional host-owned tracker preloaded with authenticated user/task input.
   * Mutually exclusive with contextTracker bounds.
   */
  contextTrackerInstance?: ContextTracker;
  /** Precompiled Rego/OPA WASM modules, aggregated after built-in policies. */
  opaPolicies?: readonly OpaPolicyEngine[];
  /** Encryption, signing, and retention settings for audit proofs. */
  proofStoreOptions?: Omit<ProofStoreOptions, "baseDir">;
  /** Optional shared host-level chain monitor. A private monitor is created by default. */
  toolchainGuard?: ToolchainGuard;
  /** Tool-descriptor continuity monitor. A private in-process TOFU guard is created by default. */
  toolIdentityGuard?: ToolIdentityGuard;
  /**
   * Optional host-held task contract. It is intentionally injected out of
   * band instead of being accepted from model-controlled tools/call metadata.
   */
  taskAuthorizationGuard?: TaskAuthorizationGuard;
  /** Host-defined provider/server scope used for ToolKey identity. */
  toolNamespace?: ProxyToolNamespace;
  /** Successfully verified, operator-pinned manifest. Raw/unverified manifests are never accepted here. */
  verifiedToolManifest?: VerifiedPinnedToolManifest;
  /** Optional operator candidate-set policy for tool-selection integrity. */
  toolSelectionGuard?: ToolSelectionGuard;
  /** Host-side capability/selection-reason resolver; MCP metadata is never consulted. */
  selectionResolver?: (
    context: ProxySelectionContext,
  ) => { requestedCapability?: string; reason?: SelectionReason };
  /** Signed approval verifier. Successful verification is consumed immediately before dispatch. */
  approvalTicketVerifier?: ApprovalTicketVerifier;
  /** Host-owned resolver for principal, scope and effect. It must not trust model-provided authority metadata. */
  approvalBindingResolver?: (
    context: ProxyApprovalBindingContext,
  ) => ApprovalTicketBinding | Promise<ApprovalTicketBinding>;
  /** Durable, host-scoped cross-process reservation and replay ledger. */
  persistentTaskLedger?: PersistentTaskLedger;
  /** Metadata-only decision→dispatch→result receipt store. */
  executionReceiptStore?: ExecutionReceiptStore;
  /** Host-authenticated scope committed into execution receipts. */
  executionScope?: ExecutionScope;
  /** Optional trusted external attestation collector; raw MCP metadata is never used as effect evidence. */
  effectEvidenceResolver?: (
    context: ProxyEffectEvidenceContext,
  ) => readonly EffectEvidence[] | Promise<readonly EffectEvidence[]>;
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

interface MCPToolDef extends McpToolDescriptor {}

interface ObservedToolBinding {
  toolKey: Readonly<ToolKey>;
  toolKeyDigest: string;
  descriptorDigest: string;
  manifestDecision?: AdditionalPolicyDecision;
}

interface DispatchReservations {
  localTaskReservation?: number;
  persistentReservationToken?: string;
}

interface DispatchEvidence {
  receiptId?: string;
  proofId: string;
  approvalTicketDigest?: string;
}

// ─── Constants ─────────────────────────────────────────────────────────────────

const FORWARD_TIMEOUT = 30_000;
export const MCP_MAX_LINE_BYTES = 4 * 1024 * 1024;
export const MCP_SHUTDOWN_GRACE_MS = 1_000;
export const MCP_MAX_PENDING_REQUESTS = 128;
export const MCP_MAX_OUTPUT_QUEUE_BYTES = 8 * 1024 * 1024;
export const MCP_BACKPRESSURE_TIMEOUT_MS = 5_000;
export const MCP_MAX_TOOL_LIST_PAGES = 32;
export const MCP_MAX_AGGREGATED_TOOLS = 2_048;
const ERR = {
  BLOCKED: -32000,
  REQUIRES_APPROVAL: -32001,
  INTERNAL: -32603,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
};
// Upstream MCP servers are part of the evaluated attack surface. Inheriting the
// complete parent environment would silently grant them every cloud, registry,
// database, and developer credential present in the host process. Preserve only
// variables required to launch ordinary local programs; integrations must pass
// all additional values explicitly through ProxyOptions.env/CLI configuration.
const SAFE_PARENT_ENV = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL",
  "TMPDIR", "TMP", "TEMP",
  "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "NO_COLOR",
  "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "APPDATA", "LOCALAPPDATA", "ProgramData",
];
const FORWARDABLE_CLIENT_NOTIFICATIONS = new Set([
  "notifications/initialized",
  "notifications/cancelled",
  "notifications/progress",
  "notifications/roots/list_changed",
]);
// Requests not listed here never cross the client→server trust boundary.
// Mutating tool execution is deliberately absent because tools/call has its own
// evaluated path below.
const FORWARDABLE_CLIENT_REQUESTS = new Set([
  "ping",
  "completion/complete",
  "logging/setLevel",
  "resources/list",
  "resources/templates/list",
  "resources/subscribe",
  "resources/unsubscribe",
  "prompts/list",
]);
// Server notifications have no response channel, so only standard messages
// with notification-only semantics may reach the client.
const FORWARDABLE_SERVER_NOTIFICATIONS = new Set([
  "notifications/cancelled",
  "notifications/progress",
  "notifications/message",
  "notifications/resources/updated",
  "notifications/resources/list_changed",
  "notifications/prompts/list_changed",
  "notifications/tools/list_changed",
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
  const lower = name.toLowerCase().replace(/[_-]+/g, " ");
  if (/\b(sql|database|db|query|postgres|mysql|sqlite)\b/.test(lower)) return "database_query";
  if (/\b(browser|navigate|click|page action|playwright|selenium)\b/.test(lower)) return "browser_action";
  if (/\b(write file|save file|edit file|replace file|create file)\b/.test(lower)) return "file_write";
  if (/\b(read file|open file|list files|glob files)\b/.test(lower)) return "file_read";
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
  private readonly contextTracker: ContextTracker;
  private readonly provenanceMapper: ProvenanceMapper;
  private readonly opaPolicies: readonly OpaPolicyEngine[];
  private readonly toolchainGuard: ToolchainGuard;
  private readonly toolIdentityGuard: ToolIdentityGuard;
  private readonly taskAuthorizationGuard?: TaskAuthorizationGuard;
  private readonly toolNamespace?: Readonly<ProxyToolNamespace>;
  private readonly verifiedToolManifest?: VerifiedPinnedToolManifest;
  private readonly toolSelectionGuard?: ToolSelectionGuard;
  private readonly selectionResolver?: ProxyOptions["selectionResolver"];
  private readonly approvalTicketVerifier?: ApprovalTicketVerifier;
  private readonly approvalBindingResolver?: ProxyOptions["approvalBindingResolver"];
  private readonly persistentTaskLedger?: PersistentTaskLedger;
  private readonly executionReceiptStore?: ExecutionReceiptStore;
  private readonly executionScope?: Readonly<ExecutionScope>;
  private readonly effectEvidenceResolver?: ProxyOptions["effectEvidenceResolver"];
  private proc: ChildProcess | null = null;
  private toolCache = new Map<string, MCPToolDef>();
  private toolBindings = new Map<string, ObservedToolBinding>();
  private selectionAdmissionDecisions: AdditionalPolicyDecision[] = [];
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
    this.proofStore = new ProofStore({ ...opts.proofStoreOptions, baseDir: opts.proofDir });
    this.interactive = opts.interactive !== false;
    this.env = opts.env ?? {};
    this.invariants = opts.invariants ?? [];
    this.config = opts.config;
    this.allowClientDecisions = opts.allowClientDecisions === true;
    if (opts.contextTracker !== undefined && opts.contextTrackerInstance !== undefined) {
      throw new TypeError("contextTracker and contextTrackerInstance are mutually exclusive");
    }
    this.contextTracker = opts.contextTrackerInstance ?? new ContextTracker(opts.contextTracker);
    this.provenanceMapper = new ProvenanceMapper(this.contextTracker);
    this.opaPolicies = [...(opts.opaPolicies ?? [])];
    this.toolchainGuard = opts.toolchainGuard ?? new ToolchainGuard();
    this.toolIdentityGuard = opts.toolIdentityGuard ?? new ToolIdentityGuard();
    this.taskAuthorizationGuard = opts.taskAuthorizationGuard;
    this.toolNamespace = normalizeToolNamespace(opts.toolNamespace);
    this.verifiedToolManifest = opts.verifiedToolManifest;
    this.toolSelectionGuard = opts.toolSelectionGuard;
    this.selectionResolver = opts.selectionResolver;
    this.approvalTicketVerifier = opts.approvalTicketVerifier;
    this.approvalBindingResolver = opts.approvalBindingResolver;
    this.persistentTaskLedger = opts.persistentTaskLedger;
    this.executionReceiptStore = opts.executionReceiptStore;
    this.executionScope = opts.executionScope === undefined
      ? undefined
      : Object.freeze({ ...opts.executionScope });
    this.effectEvidenceResolver = opts.effectEvidenceResolver;
    if ((
      this.verifiedToolManifest || this.toolSelectionGuard || this.approvalTicketVerifier ||
      this.executionReceiptStore
    ) && !this.toolNamespace) {
      throw new TypeError(
        "toolNamespace is required with verifiedToolManifest, toolSelectionGuard, or executionReceiptStore",
      );
    }
    if ((this.approvalTicketVerifier === undefined) !== (this.approvalBindingResolver === undefined)) {
      throw new TypeError("approvalTicketVerifier and approvalBindingResolver must be configured together");
    }
    if (this.executionReceiptStore && !this.executionScope) {
      throw new TypeError("executionScope is required with executionReceiptStore");
    }
    if (this.effectEvidenceResolver && !this.executionReceiptStore) {
      throw new TypeError("effectEvidenceResolver requires executionReceiptStore");
    }
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

    // Upstream stdout → correlate responses and firewall unsolicited traffic.
    this.upstreamReader = new LimitedLineReader(proc.stdout!, (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      let value: unknown;
      try {
        value = JSON.parse(trimmed);
      } catch {
        const safe = sanitizeTerminal(redactLogText(line), 1000);
        if (safe) log(`upstream: ${safe}`);
        return;
      }
      if (!isRecord(value) || value.jsonrpc !== "2.0") {
        log("dropped invalid upstream JSON-RPC message");
        return;
      }

      const hasId = Object.hasOwn(value, "id");
      const id = isJsonRpcId(value.id) ? value.id : undefined;
      const hasResponseMember = Object.hasOwn(value, "result") || Object.hasOwn(value, "error");

      // Only a response associated with a request sent by this proxy can cross
      // back to the client. Normalize it so an upstream cannot smuggle a method
      // field alongside a legitimate response and confuse permissive clients.
      if (hasId && id !== undefined && hasResponseMember) {
        const pending = this.pending.get(id);
        if (!pending) {
          log(`dropped unmatched upstream response id: ${sanitizeTerminal(String(id), 200)}`);
          return;
        }
        clearTimeout(pending.timer);
        this.pending.delete(id);
        const response = normalizeUpstreamResponse(value, id);
        if (response) {
          pending.resolve(response);
        } else {
          log(`rejected invalid upstream response id: ${sanitizeTerminal(String(id), 200)}`);
          pending.resolve(makeError(id, ERR.INTERNAL, "Invalid upstream JSON-RPC response"));
        }
        return;
      }

      if (typeof value.method !== "string" || value.method.length === 0) {
        log("dropped unsolicited upstream JSON-RPC message");
        return;
      }

      if (hasId) {
        if (id === undefined) {
          log(`dropped upstream request with invalid id: ${sanitizeTerminal(value.method, 200)}`);
          return;
        }
        // MCP ping is intentionally terminated at the proxy. Every other
        // server-initiated request (sampling, elicitation, roots, and future or
        // custom methods) fails closed and is never exposed to the client.
        const response = value.method === "ping"
          ? { jsonrpc: "2.0" as const, id, result: {} }
          : makeError(id, ERR.METHOD_NOT_FOUND, "Method not found");
        try {
          this.writeToUpstream(response);
          if (value.method !== "ping") {
            log(`blocked server-initiated request: ${sanitizeTerminal(value.method, 200)}`);
          }
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          this.finish(new Error(`failed to reject upstream request: ${message}`), 1, true);
        }
        return;
      }

      if (FORWARDABLE_SERVER_NOTIFICATIONS.has(value.method)) {
        this.writeOutput(trimmed + "\n");
      } else {
        log(`dropped upstream notification: ${sanitizeTerminal(value.method, 200)}`);
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

  /** Metadata-only view for diagnostics; raw indexed context is never exposed. */
  listContextEntries(): ContextEntry[] {
    return this.contextTracker.list();
  }

  /** Metadata-only cross-tool history; raw tool results are never retained here. */
  listToolchainEvents(): ToolchainEvent[] {
    return this.toolchainGuard.list();
  }

  /** Metadata-only tool-identity history; raw descriptors are never exposed. */
  listToolIdentityEvents(): ToolIdentityObservation[] {
    return this.toolIdentityGuard.listEvents();
  }

  /** Metadata-only task authorization history; task IDs and raw arguments stay hidden. */
  listTaskAuthorizationEvents(): TaskAuthorizationEvent[] {
    return this.taskAuthorizationGuard?.listEvents() ?? [];
  }

  /** Metadata-only tool-selection admission and choice history. */
  listToolSelectionEvents(): ToolSelectionEvent[] {
    return this.toolSelectionGuard?.listEvents() ?? [];
  }

  /** Metadata-only approval verification/consumption history. */
  listApprovalTicketEvents(): ApprovalTicketAuditEvent[] {
    return this.approvalTicketVerifier?.listEvents() ?? [];
  }

  /** Validated durable ledger events; bearer reservation tokens are never persisted or returned here. */
  async listPersistentLedgerEvents(limit?: number): Promise<PersistentLedgerEvent[]> {
    return this.persistentTaskLedger?.listEvents(limit) ?? [];
  }

  /** Receipt health including incomplete/corrupt states; no raw arguments or results are exposed. */
  listExecutionReceiptDiagnostics(limit?: number): ExecutionReceiptDiagnostic[] {
    return this.executionReceiptStore?.listDiagnostics(limit) ?? [];
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
        case "initialize": await this.forward(id, narrowInitializeRequest(msg)); break;
        case "tools/list": await this.handleToolsList(id, params, log); break;
        case "tools/call": await this.handleToolsCall(id, params ?? {}, log); break;
        case "riskproof/evaluate": this.handleRiskproofEvaluate(id, params ?? {}, log); break;
        case "resources/read":
        case "prompts/get":
          await this.forwardTracked(id, msg);
          break;
        default:
          if (FORWARDABLE_CLIENT_REQUESTS.has(method)) {
            await this.forward(id, msg);
          } else {
            log(`blocked client request method: ${sanitizeTerminal(method, 200)}`);
            this.write(makeError(id, ERR.METHOD_NOT_FOUND, "Method not found"));
          }
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`error: ${msg}`);
      this.write(makeError(id, ERR.INTERNAL, msg));
    }
  }

  // ── tools/list: scan + cache ─────────────────────────────────────────────────

  private async handleToolsList(
    id: number | string,
    params: Record<string, unknown> | undefined,
    log: (s: string) => void,
  ): Promise<void> {
    const atomicToolSnapshot = this.verifiedToolManifest !== undefined || this.toolSelectionGuard !== undefined;
    if (atomicToolSnapshot && params?.cursor !== undefined) {
      this.write(makeError(
        id,
        ERR.INVALID_PARAMS,
        "RiskProof returns one atomically aggregated tools/list snapshot; client cursors are not accepted",
      ));
      return;
    }
    let resp: JsonRpcResponse;
    try {
      resp = atomicToolSnapshot
        ? await this.fetchCompleteToolList(id, params)
        : await this.forwardRequest({
          jsonrpc: "2.0",
          id,
          method: "tools/list",
          ...(params === undefined ? {} : { params }),
        });
    }
    catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); return; }

    if (resp.result && typeof resp.result === "object") {
      const tools = (resp.result as Record<string, unknown>).tools;
      if (Array.isArray(tools)) {
        // Commit the complete upstream objects before reducing them for the
        // poisoning scanner/cache. This intentionally covers annotations,
        // outputSchema, `_meta`, and future MCP descriptor fields.
        const descriptors = tools.map((tool, index): McpToolIdentityDescriptor => {
          if (!isRecord(tool) || typeof tool.name !== "string" || tool.name.length === 0) {
            throw new TypeError(`invalid MCP tool descriptor at index ${index}`);
          }
          return tool as McpToolIdentityDescriptor;
        });
        const identityObservations = this.toolIdentityGuard.observeSnapshot(descriptors);
        for (const observation of identityObservations) {
          if (observation.status !== "quarantined") continue;
          log(
            `⚠ identity quarantine: ${sanitizeTerminal(observation.name, 200)} → ` +
            observation.violations.join(", "),
          );
        }

        this.toolCache.clear();
        this.toolBindings.clear();
        this.poisonedTools.clear();
        const namespace = this.toolNamespace;
        for (const t of descriptors) {
          const def: MCPToolDef = {
            name: t.name,
            ...(typeof t.description === "string" ? { description: t.description } : {}),
            ...(isRecord(t.inputSchema) ? { inputSchema: t.inputSchema } : {}),
          };
          this.toolCache.set(def.name, def);
          if (namespace) {
            const toolKey = parseToolKey({
              providerId: namespace.providerId,
              serverId: namespace.serverId,
              toolName: t.name,
            });
            const descriptorDigest = digestToolDescriptor(t);
            const manifestBinding = this.verifiedToolManifest?.verifyTool(toolKey, descriptorDigest);
            this.toolBindings.set(t.name, {
              toolKey,
              toolKeyDigest: digestToolKey(toolKey),
              descriptorDigest,
              ...(manifestBinding
                ? { manifestDecision: manifestBindingDecision(manifestBinding) }
                : {}),
            });
          }
          const hits = scanTool(def);
          if (hits.length > 0) {
            this.poisonedTools.add(def.name);
            log(`⚠ poisoned: ${sanitizeTerminal(def.name, 200)} → ${hits.join(", ")}`);
          }
        }

        let selectionApproved: Set<number> | undefined;
        this.selectionAdmissionDecisions = [];
        if (this.toolSelectionGuard) {
          const observed = descriptors.map((tool) => {
            const binding = this.toolBindings.get(tool.name);
            if (!binding) throw new Error(`missing ToolKey binding for '${tool.name}'`);
            return {
              toolKeyDigest: binding.toolKeyDigest,
              descriptorDigest: binding.descriptorDigest,
            };
          });
          const admission = this.toolSelectionGuard.admitSnapshot(observed);
          selectionApproved = new Set(admission.approvedIndices);
          this.selectionAdmissionDecisions = admission.decisions.filter(
            ({ policy }) => policy.id === "selection_candidate_set_mismatch",
          );
        }
        // Do not expose poisoned or identity-quarantined descriptors to the
        // planning model. Signed-manifest and selection filters operate on the
        // same atomically aggregated snapshot. Direct calls recheck every guard.
        (resp.result as Record<string, unknown>).tools = descriptors.filter(
          (tool, index) => {
            const manifestDecision = this.toolBindings.get(tool.name)?.manifestDecision;
            return !this.poisonedTools.has(tool.name) &&
              !this.toolIdentityGuard.isQuarantined(tool.name) &&
              manifestDecision?.decision !== "deny" &&
              (selectionApproved === undefined || selectionApproved.has(index)) &&
              this.selectionAdmissionDecisions.length === 0;
          },
        );
      }
    }
    this.write(resp);
  }

  /**
   * MCP permits paginated tool lists, but identity and candidate-set policy are
   * snapshot properties. Aggregate pages inside the reference monitor so no
   * page is independently TOFU-pinned or exposed before the complete set is
   * available. The client receives one cursor-free snapshot.
   */
  private async fetchCompleteToolList(
    id: number | string,
    params: Record<string, unknown> | undefined,
  ): Promise<JsonRpcResponse> {
    const baseParams = params === undefined ? {} : { ...params };
    delete baseParams.cursor;
    const tools: unknown[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    let firstResult: Record<string, unknown> | undefined;

    for (let page = 0; page < MCP_MAX_TOOL_LIST_PAGES; page += 1) {
      const requestParams = {
        ...baseParams,
        ...(cursor === undefined ? {} : { cursor }),
      };
      const response = await this.forwardRequest({
        jsonrpc: "2.0",
        id,
        method: "tools/list",
        ...(Object.keys(requestParams).length === 0 ? {} : { params: requestParams }),
      });
      if (response.error !== undefined || !isRecord(response.result)) return response;
      const pageTools = response.result.tools;
      if (!Array.isArray(pageTools)) throw new TypeError("upstream tools/list result.tools must be an array");
      if (tools.length + pageTools.length > MCP_MAX_AGGREGATED_TOOLS) {
        throw new RangeError(`aggregated tools/list exceeds ${MCP_MAX_AGGREGATED_TOOLS} tools`);
      }
      tools.push(...pageTools);
      if (!firstResult) firstResult = { ...response.result };

      const nextCursor = response.result.nextCursor;
      if (nextCursor === undefined || nextCursor === null || nextCursor === "") {
        const result: Record<string, unknown> = { ...(firstResult ?? {}), tools };
        delete result.nextCursor;
        return { jsonrpc: "2.0", id, result };
      }
      if (typeof nextCursor !== "string") throw new TypeError("upstream tools/list nextCursor must be a string");
      if (seenCursors.has(nextCursor)) throw new Error("upstream tools/list repeated a pagination cursor");
      seenCursors.add(nextCursor);
      cursor = nextCursor;
    }
    throw new RangeError(`upstream tools/list exceeds ${MCP_MAX_TOOL_LIST_PAGES} page limit`);
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
    const evaluated = this.evaluateToolCall(parsed.toolName, parsed.args, id, parsed.flows);
    const result = this.taskAuthorizationGuard
      ? mergePolicyDecisions(
        evaluated.result,
        this.taskAuthorizationGuard.assess(evaluated.taskRequest),
      )
      : evaluated.result;
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
    const { toolName, flows } = parsed;
    const evaluated = this.evaluateToolCall(toolName, parsed.args, id, flows);
    const args = evaluated.args;
    const { cached } = evaluated;
    let result = evaluated.result;
    let localTaskReservation: number | undefined;
    let persistentReservationToken: string | undefined;
    if (this.taskAuthorizationGuard) {
      // A call already denied by a stronger policy needs only a read-only task
      // assessment. Otherwise authorize and reserve budget atomically so two
      // parallel calls cannot both pass the final available slot.
      if (result.action === "block") {
        result = mergePolicyDecisions(
          result,
          this.taskAuthorizationGuard.assess(evaluated.taskRequest),
        );
      } else {
        const authorization = this.taskAuthorizationGuard.reserve(evaluated.taskRequest);
        result = mergePolicyDecisions(result, authorization.decisions);
        if ("reservation" in authorization) localTaskReservation = authorization.reservation;
      }
    }

    if (this.persistentTaskLedger && result.action !== "block") {
      const durable = await this.persistentTaskLedger.reserve({
        toolName,
        ...(evaluated.binding?.descriptorDigest
          ? { descriptorDigest: evaluated.binding.descriptorDigest }
          : {}),
        requestDigest: digestCanonicalValue({ method: "tools/call", name: toolName, arguments: args }),
        ...(evaluated.binding?.toolKeyDigest
          ? { toolKeyDigest: evaluated.binding.toolKeyDigest }
          : {}),
      });
      if (durable.status === "reserved") {
        persistentReservationToken = durable.reservationToken;
        result = mergePolicyDecisions(result, [persistentLedgerAuthorization(
          this.persistentTaskLedger.getScopeDigest(),
          this.persistentTaskLedger.getPolicyDigest(),
          durable.reservationDigest,
        )]);
      } else {
        result = mergePolicyDecisions(result, [persistentLedgerDenial(durable.violation)]);
        if (localTaskReservation !== undefined) {
          this.taskAuthorizationGuard?.abort(localTaskReservation);
          localTaskReservation = undefined;
        }
      }
    }

    const binding = evaluated.binding ?? (this.toolNamespace
      ? this.syntheticUnobservedBinding(toolName)
      : undefined);
    const policyDigest = digestDecisionPolicy(result);
    const contractDigest = this.taskAuthorizationGuard?.getContractDigest();
    let signedApprovalAccepted = false;
    let approvalTicketDigest: string | undefined;

    if (result.action === "ask_approval" && this.approvalTicketVerifier && this.approvalBindingResolver) {
      if (!evaluated.binding) {
        result = mergePolicyDecisions(result, [snapshotNotObservedDecision(
          "approval_tool_snapshot_not_observed",
          "审批票据不能授权未在完整 tools/list 快照中观察到的工具身份",
        )]);
      } else {
        const ticket = approvalTicketFromParams(params);
        if (ticket === undefined) {
          result = mergePolicyDecisions(result, [approvalRequiredDecision()]);
        } else {
          const resolved = await this.approvalBindingResolver({
            requestId: id,
            toolName,
            toolKey: evaluated.binding.toolKey,
            descriptorDigest: evaluated.binding.descriptorDigest,
            args,
            result,
            policyDigest,
            ...(contractDigest ? { contractDigest } : {}),
          });
          const expected: ApprovalTicketBinding = {
            ...resolved,
            tool: {
              providerId: evaluated.binding.toolKey.providerId,
              serverId: evaluated.binding.toolKey.serverId,
              toolName: evaluated.binding.toolKey.toolName,
            },
            descriptorDigest: evaluated.binding.descriptorDigest,
            arguments: args,
            // The resolver is a trusted host boundary and supplies the pinned
            // policy-artifact commitment used at ticket issuance. The computed
            // outcome digest is provided in context for comparison/auditing but
            // is not substituted for a deployment policy bundle digest.
            policyDigest: resolved.policyDigest,
            contractDigest: contractDigest ?? resolved.contractDigest,
          };
          const verified = await this.approvalTicketVerifier.verifyAndConsume(ticket, expected);
          if (verified.ok) {
            signedApprovalAccepted = true;
            approvalTicketDigest = verified.ticketDigest;
          } else {
            result = mergePolicyDecisions(result, [approvalTicketDenial(verified.code, verified.binding)]);
          }
        }
      }
    }

    const safeToolName = sanitizeTerminal(toolName, 200);
    log(`tools/call: ${safeToolName} → ${result.action} [${result.matchedPolicies.map((p) => p.id).join(", ") || "no rules"}]`);

    let receiptId: string | undefined;
    if (this.executionReceiptStore && this.executionScope) {
      try {
        if (!binding) throw new Error("execution receipt requires a ToolKey binding");
        receiptId = this.executionReceiptStore.start({
          scope: this.executionScope,
          toolKeyDigest: binding.toolKeyDigest,
          descriptorDigest: binding.descriptorDigest,
          args,
          proofId: result.proof.proofId,
          decision: result.decision,
          riskLevel: result.riskLevel,
          matchedRuleIds: [...new Set(result.matchedPolicies.map(({ id: ruleId }) => ruleId))],
          policyDigest: digestDecisionPolicy(result),
          ...(contractDigest ? { contractDigest } : {}),
          ...(this.verifiedToolManifest
            ? { toolManifestDigest: this.verifiedToolManifest.manifestDigest }
            : {}),
          ...(this.toolSelectionGuard
            ? { selectionPolicyDigest: this.toolSelectionGuard.getPolicyDigest() }
            : {}),
          ...(this.persistentTaskLedger
            ? { ledgerPolicyDigest: this.persistentTaskLedger.getPolicyDigest() }
            : {}),
          ...(approvalTicketDigest ? { approvalTicketDigest } : {}),
        }).receiptId;
      } catch (error) {
        this.proofStore.save(result, "reject", "Execution receipt creation failed before dispatch");
        const message = error instanceof Error ? error.message : String(error);
        log(`execution receipt failed before dispatch: ${sanitizeTerminal(message, 500)}`);
        this.write(makeError(id, ERR.INTERNAL, "Execution evidence could not be persisted; call was not dispatched"));
        await this.abortDispatchReservations({ localTaskReservation, persistentReservationToken }, log);
        return;
      }
    }

    const dispatchEvidence: DispatchEvidence = {
      receiptId,
      proofId: result.proof.proofId,
      ...(approvalTicketDigest ? { approvalTicketDigest } : {}),
    };

    const forwardAuthorized = async (req: JsonRpcRequest): Promise<JsonRpcResponse> => {
      // Ownership transfers to forwardTrackedRequest, which completes or
      // aborts both reservations from the actual MCP result lifecycle.
      const reservations: DispatchReservations = {
        localTaskReservation,
        persistentReservationToken,
      };
      localTaskReservation = undefined;
      persistentReservationToken = undefined;
      return this.forwardTrackedRequest(req, reservations, dispatchEvidence, binding, args);
    };

    const recordNoDispatch = (reason: NoDispatchReason): void => {
      if (receiptId) this.executionReceiptStore?.recordNotDispatched(receiptId, { reason });
    };

    // Route
    try {
      switch (result.action) {
        case "allow": {
          this.proofStore.save(result);
          process.stderr.write(`  [PASS] ${safeToolName}\n`);
          const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
          try { this.write(await forwardAuthorized(req)); }
          catch (err) { this.write(evidenceError(id, ERR.INTERNAL, String(err), dispatchEvidence)); }
          break;
        }

        case "block": {
          this.proofStore.save(result);
          recordNoDispatch(policyNoDispatchReason(result));
          const card = formatCard(result, { toolName, toolDesc: cached?.description, locale: this.config?.options?.locale });
          process.stderr.write("\n" + card + "\n");
          this.write(evidenceError(id, ERR.BLOCKED, formatCompact(result, { toolName }), dispatchEvidence));
          break;
        }

        case "ask_approval": {
          if (signedApprovalAccepted) {
            this.proofStore.save(result, "approve", "Verified exact single-use approval ticket");
            process.stderr.write("  [APPROVED] Verified signed single-use ticket — forwarding\n\n");
            const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
            try { this.write(await forwardAuthorized(req)); }
            catch (err) { this.write(evidenceError(id, ERR.INTERNAL, String(err), dispatchEvidence)); }
            return;
          }

          if (this.approvalTicketVerifier) {
            recordNoDispatch(approvalTicketDigest ? "approval_rejected" : "approval_required");
            const card = formatCompact(result, { toolName, locale: this.config?.options?.locale });
            this.proofStore.save(result, "reject", "A valid exact single-use approval ticket was not available");
            this.write(evidenceError(id, ERR.REQUIRES_APPROVAL, card, dispatchEvidence));
            return;
          }

          // ── Pre-approval signal from agent (LangGraph interrupt flow) ──────
          const meta = isRecord(params._meta) ? params._meta : undefined;
          const userDecision = typeof meta?.riskproof_user_decision === "string"
            ? meta.riskproof_user_decision
            : undefined;

          if (this.allowClientDecisions && userDecision === "approve") {
            this.proofStore.save(result, "approve");
            process.stderr.write(`  [APPROVED] User pre-approved via agent — forwarding\n\n`);
            const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
            try { this.write(await forwardAuthorized(req)); }
            catch (err) { this.write(evidenceError(id, ERR.INTERNAL, String(err), dispatchEvidence)); }
            return;
          }

          if (this.allowClientDecisions && userDecision === "reject") {
            this.proofStore.save(result, "reject");
            recordNoDispatch("approval_rejected");
            process.stderr.write(`  [REJECTED] User rejected via agent\n\n`);
            this.write(evidenceError(id, ERR.BLOCKED, "Rejected by user", dispatchEvidence));
            return;
          }

          if (!this.interactive) {
            const card = formatCompact(result, { toolName, locale: this.config?.options?.locale });
            process.stderr.write("\n" + card + "\n  [REVIEW] Non-interactive — auto-denied.\n\n");
            this.proofStore.save(result, "reject", "Auto-denied in non-interactive mode");
            recordNoDispatch("approval_required");
            this.write(evidenceError(id, ERR.REQUIRES_APPROVAL, card, dispatchEvidence));
            return;
          }

          const card = formatCard(result, { toolName, toolDesc: cached?.description, locale: this.config?.options?.locale });
          process.stderr.write("\n" + card + "\n");
          const decision = await this.promptUser();

          if (decision === "approve") {
            this.proofStore.save(result, "approve");
            process.stderr.write("  [APPROVED] Forwarding...\n\n");
            const req: JsonRpcRequest = { jsonrpc: "2.0", id, method: "tools/call", params: { name: toolName, arguments: args } };
            try { this.write(await forwardAuthorized(req)); }
            catch (err) { this.write(evidenceError(id, ERR.INTERNAL, String(err), dispatchEvidence)); }
          } else {
            this.proofStore.save(result, "reject");
            recordNoDispatch("approval_rejected");
            process.stderr.write("  [REJECTED] Blocked by user.\n\n");
            this.write(evidenceError(id, ERR.BLOCKED, "Rejected by user", dispatchEvidence));
          }
          break;
        }
      }
    } finally {
      // Any route that did not transfer ownership to dispatch (policy block,
      // human reject, non-interactive step-up, or local exception) releases
      // its pending call budget.
      await this.abortDispatchReservations({ localTaskReservation, persistentReservationToken }, log);
    }
  }

  private syntheticUnobservedBinding(toolName: string): ObservedToolBinding {
    if (!this.toolNamespace) {
      throw new Error("a ToolKey namespace is required to create execution evidence");
    }
    const toolKey = parseToolKey({ ...this.toolNamespace, toolName });
    return {
      toolKey,
      toolKeyDigest: digestToolKey(toolKey),
      descriptorDigest: digestCanonicalValue({ format: "riskproof.unobserved-descriptor.v1", toolName }),
    };
  }

  private async abortDispatchReservations(
    reservations: DispatchReservations,
    log: (s: string) => void,
  ): Promise<void> {
    if (reservations.localTaskReservation !== undefined) {
      this.taskAuthorizationGuard?.abort(reservations.localTaskReservation);
    }
    if (reservations.persistentReservationToken !== undefined) {
      try {
        const aborted = await this.persistentTaskLedger?.abort(reservations.persistentReservationToken);
        if (aborted === false) log("persistent reservation was already finalized or unavailable");
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        log(`persistent reservation abort failed closed: ${sanitizeTerminal(message, 500)}`);
      }
    }
  }

  private evaluateToolCall(
    toolName: string,
    args: Record<string, unknown>,
    requestId: number | string,
    flows?: ProvenanceFlow[],
  ): {
    cached?: MCPToolDef;
    binding?: ObservedToolBinding;
    args: Record<string, unknown>;
    result: EngineOutput;
    taskRequest: TaskAuthorizationRequest;
  } {
    const cached = this.toolCache.get(toolName);
    const isPoisoned = this.poisonedTools.has(toolName);
    const mappedTool = mapToolName(toolName);

    // Schema poisoning is a property of the tool definition, not of any one
    // business argument. Always add internal evidence so a zero-argument
    // poisoned tool cannot evade the forbidden-taint rule and default-allow.
    let schemaEvidenceArg = SCHEMA_POISONING_EVIDENCE_ARG;
    while (Object.hasOwn(args, schemaEvidenceArg)) schemaEvidenceArg = `_${schemaEvidenceArg}`;
    // Snapshot client arguments before the provenance mapper inspects them. This
    // preserves the public boundary's Proxy/getter/TOCTOU protections.
    const snapshot = parseEngineInput({
      tool: mappedTool,
      args,
      ...(flows?.length ? { flows } : {}),
    });
    const evaluationArgs: Record<string, unknown> = isPoisoned
      ? { ...snapshot.args, [schemaEvidenceArg]: toolName }
      : snapshot.args;

    // Build EngineInput
    const mapped = this.provenanceMapper.mapArguments(snapshot.args);
    const taints: Record<string, TaintLabel[]> = { ...mapped.taints };
    const provenance: Record<string, string[]> = { ...mapped.provenance };
    for (const key of Object.keys(evaluationArgs)) {
      if (!provenance[key]) provenance[key] = [];
      if (!taints[key]) taints[key] = [];
      if (isPoisoned) {
        provenance[key] = [...new Set([...provenance[key], "mcp_schema"])];
        taints[key] = [...new Set<TaintLabel>([...taints[key], "UNTRUSTED_TOOL_SCHEMA"])];
      }
    }

    const input: EngineInput = {
      tool: mappedTool as EngineInput["tool"],
      args: evaluationArgs,
      provenance,
      taints: Object.keys(taints).length > 0 ? taints : undefined,
      flows: snapshot.flows,
      capability: isPoisoned
        ? { tool: mappedTool as Capability["tool"], forbiddenTaints: ["UNTRUSTED_TOOL_SCHEMA"] }
        : undefined,
      invariants: this.invariants.length > 0 ? [...this.invariants] : undefined,
      trace: { traceId: `proxy-${Date.now()}`, stepId: String(requestId) },
    };

    const perCallResult = this.opaPolicies.length > 0
      ? evaluateWithOpa(input, this.opaPolicies, this.config)
      : evaluate(input, this.config);
    const descriptor: McpToolDescriptor = cached ?? { name: toolName };
    const toolchainResult = applyToolchainGuard(perCallResult, this.toolchainGuard, descriptor);
    let result = mergePolicyDecisions(
      toolchainResult,
      this.toolIdentityGuard.assess(toolName),
    );
    const binding = this.toolBindings.get(toolName);
    const boundaryDecisions: AdditionalPolicyDecision[] = [];
    if (this.verifiedToolManifest) {
      boundaryDecisions.push(binding?.manifestDecision ?? snapshotNotObservedDecision(
        "tool_manifest_snapshot_not_observed",
        "签名 manifest 尚未在完整 tools/list 快照中绑定该工具，禁止直接调用",
      ));
    }
    if (this.toolSelectionGuard) {
      if (!binding) {
        boundaryDecisions.push(snapshotNotObservedDecision(
          "selection_snapshot_not_observed",
          "工具没有出现在最近一次已准入候选快照中",
        ));
      } else {
        const selection = this.selectionResolver?.({
          requestId,
          toolName,
          toolKey: binding.toolKey,
          descriptorDigest: binding.descriptorDigest,
          args: snapshot.args,
          mappedCapability: mappedTool,
        }) ?? {};
        boundaryDecisions.push(...this.toolSelectionGuard.assessSelection({
          selected: {
            toolKeyDigest: binding.toolKeyDigest,
            descriptorDigest: binding.descriptorDigest,
          },
          ...(selection.requestedCapability === undefined
            ? {}
            : { requestedCapability: selection.requestedCapability }),
          ...(selection.reason === undefined ? {} : { reason: selection.reason }),
        }));
      }
      boundaryDecisions.push(...this.selectionAdmissionDecisions);
    }
    result = mergePolicyDecisions(result, boundaryDecisions);
    const descriptorDigest = binding?.descriptorDigest ?? this.toolIdentityGuard.currentDigest(toolName);
    const taskRequest: TaskAuthorizationRequest = {
      toolName,
      ...(descriptorDigest ? { descriptorDigest } : {}),
      provenance,
    };
    return { cached, binding, args: snapshot.args, result, taskRequest };
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

  private writeToUpstream(msg: JsonRpcRequest | JsonRpcResponse): void {
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

  private async forwardTracked(id: number | string, req: JsonRpcRequest): Promise<void> {
    try { this.write(await this.forwardTrackedRequest(req)); }
    catch (err) { this.write(makeError(id, ERR.INTERNAL, String(err))); }
  }

  private async forwardTrackedRequest(
    req: JsonRpcRequest,
    reservations: DispatchReservations = {},
    evidence?: DispatchEvidence,
    binding?: ObservedToolBinding,
    args: Readonly<Record<string, unknown>> = {},
  ): Promise<JsonRpcResponse> {
    const toolName = req.method === "tools/call" && typeof req.params?.name === "string"
      ? req.params.name
      : undefined;
    const toolchainReservation = toolName === undefined
      ? undefined
      : this.toolchainGuard.begin(this.toolCache.get(toolName) ?? { name: toolName });
    let receiptDispatched = false;

    if (evidence?.receiptId) {
      try {
        this.executionReceiptStore?.markDispatched(evidence.receiptId, { request: req });
        receiptDispatched = true;
      } catch (error) {
        if (toolchainReservation !== undefined) this.toolchainGuard.abort(toolchainReservation);
        await this.abortReservationsStrict(reservations);
        try {
          this.executionReceiptStore?.recordNotDispatched(evidence.receiptId, { reason: "local_error" });
        } catch {
          // If the dispatch event reached stable storage before the local error,
          // preserve that incomplete state instead of claiming non-dispatch.
        }
        throw error;
      }
    }

    let response: JsonRpcResponse;
    try {
      response = await this.forwardRequest(req);
    } catch (error) {
      if (toolchainReservation !== undefined) this.toolchainGuard.abort(toolchainReservation);
      let reservationError: unknown;
      try {
        await this.abortReservationsStrict(reservations);
      } catch (failure) {
        reservationError = failure;
      }
      if (receiptDispatched && evidence?.receiptId) {
        const outcome: ExecutionOutcome = error instanceof Error && /^timeout:/u.test(error.message)
          ? "timeout"
          : "transport_error";
        await this.settleExecutionReceipt(
          evidence.receiptId,
          outcome,
          binding,
          args,
          req.id!,
        );
      }
      if (reservationError) throw new AggregateError(
        [error, reservationError],
        "transport failed and durable reservation cleanup failed closed",
      );
      throw error;
    }

    const mcpToolError = req.method === "tools/call" &&
      isRecord(response.result) && response.result.isError === true;
    if (response.error !== undefined || response.result === undefined || mcpToolError) {
      if (toolchainReservation !== undefined) this.toolchainGuard.abort(toolchainReservation);
      await this.abortReservationsStrict(reservations);
      const outcome: ExecutionOutcome = response.error !== undefined
        ? "jsonrpc_error"
        : mcpToolError
          ? "mcp_error"
          : "transport_error";
      if (receiptDispatched && evidence?.receiptId) {
        await this.settleExecutionReceipt(
          evidence.receiptId,
          outcome,
          binding,
          args,
          req.id!,
          response,
          response.error?.code,
        );
      }
      return attachExecutionEvidence(response, evidence);
    }

    // An upstream success may already have produced a real side effect. From
    // this point onward never replenish either budget, even if local evidence
    // processing fails. Durable ledger completion happens before the local
    // in-memory counter so a storage failure cannot be disguised as success.
    let durableCompleted = reservations.persistentReservationToken === undefined;
    try {
      if (reservations.persistentReservationToken !== undefined) {
        durableCompleted = await this.persistentTaskLedger?.complete(
          reservations.persistentReservationToken,
        ) === true;
        if (!durableCompleted) throw new Error("persistent task reservation could not be completed");
      }
      if (reservations.localTaskReservation !== undefined &&
          this.taskAuthorizationGuard?.complete(reservations.localTaskReservation) !== true) {
        throw new Error("in-memory task reservation could not be completed");
      }
      const entries = this.contextTracker.recordResponse(req.method, req.params, response.result);
      const contextIds = entries.map(({ id }) => id);
      if (toolchainReservation !== undefined) {
        this.toolchainGuard.complete(toolchainReservation, contextIds);
      } else {
        const capabilities = contextCapabilities(req.method, entries);
        if (capabilities.length > 0) {
          this.toolchainGuard.recordContext(req.method, capabilities, contextIds);
        }
      }
      if (receiptDispatched && evidence?.receiptId) {
        await this.settleExecutionReceipt(
          evidence.receiptId,
          "success",
          binding,
          args,
          req.id!,
          response,
        );
      }
      return attachExecutionEvidence(response, evidence);
    } catch (error) {
      if (toolchainReservation !== undefined) this.toolchainGuard.complete(toolchainReservation);
      if (reservations.localTaskReservation !== undefined) {
        this.taskAuthorizationGuard?.complete(reservations.localTaskReservation);
      }
      // A failed durable complete deliberately remains pending. Operators may
      // recover it only after fencing the old dispatcher; aborting here could
      // replenish budget for an effect that already happened.
      if (receiptDispatched && evidence?.receiptId) {
        try {
          const current = this.executionReceiptStore?.load(evidence.receiptId);
          if (current?.state === "dispatched") {
            await this.settleExecutionReceipt(
              evidence.receiptId,
              durableCompleted ? "local_error" : "success",
              binding,
              args,
              req.id!,
              response,
            );
          }
        } catch {
          // Preserve an incomplete dispatched receipt if settlement itself is
          // the failing subsystem. Never manufacture a not-dispatched claim.
        }
      }
      throw new Error(
        `upstream may have completed but local execution evidence failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  private async abortReservationsStrict(reservations: DispatchReservations): Promise<void> {
    if (reservations.localTaskReservation !== undefined &&
        this.taskAuthorizationGuard?.abort(reservations.localTaskReservation) !== true) {
      throw new Error("in-memory task reservation could not be aborted");
    }
    if (reservations.persistentReservationToken !== undefined &&
        await this.persistentTaskLedger?.abort(reservations.persistentReservationToken) !== true) {
      throw new Error("persistent task reservation could not be aborted");
    }
  }

  private async settleExecutionReceipt(
    receiptId: string,
    outcome: ExecutionOutcome,
    binding: ObservedToolBinding | undefined,
    args: Readonly<Record<string, unknown>>,
    requestId: number | string,
    response?: JsonRpcResponse,
    errorCode?: number | string,
  ): Promise<void> {
    const effectEvidence = this.effectEvidenceResolver && binding
      ? await this.effectEvidenceResolver({
        requestId,
        toolName: binding.toolKey.toolName,
        toolKey: binding.toolKey,
        descriptorDigest: binding.descriptorDigest,
        args,
        ...(response ? { response } : {}),
        outcome,
      })
      : [];
    this.executionReceiptStore?.settle(receiptId, {
      outcome,
      ...(response === undefined ? {} : { result: response }),
      ...(errorCode === undefined ? {} : { errorCode }),
      effectEvidence,
    });
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
    const childEnv: NodeJS.ProcessEnv = {};
    for (const name of SAFE_PARENT_ENV) {
      if (process.env[name] !== undefined) childEnv[name] = process.env[name];
    }
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

function normalizeToolNamespace(
  value: ProxyToolNamespace | undefined,
): Readonly<ProxyToolNamespace> | undefined {
  if (value === undefined) return undefined;
  const parsed = parseToolKey({
    providerId: value.providerId,
    serverId: value.serverId,
    toolName: "riskproof_namespace_validation",
  });
  return Object.freeze({ providerId: parsed.providerId, serverId: parsed.serverId });
}

function manifestBindingDecision(
  binding: ToolBindingVerificationResult,
): AdditionalPolicyDecision {
  if (binding.verified) {
    return {
      decision: "allow",
      riskLevel: "low",
      policy: {
        id: "signed_tool_manifest_matched",
        triggeredArgs: [],
        evidence: [
          `signed manifest sha256=${binding.manifestDigest}`,
          `ToolKey sha256=${binding.toolKeyDigest}`,
          `descriptor sha256=${binding.observedDescriptorDigest}`,
        ],
        reason: "工具的 provider/server/name 身份与完整 descriptor 均匹配已验签的 pinned manifest",
      },
    };
  }
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id: `signed_manifest_${binding.code}`,
      triggeredArgs: [],
      evidence: [
        `signed manifest sha256=${binding.manifestDigest}`,
        ...(binding.toolKeyDigest ? [`ToolKey sha256=${binding.toolKeyDigest}`] : []),
        ...(binding.expectedDescriptorDigest
          ? [`expected descriptor sha256=${binding.expectedDescriptorDigest}`]
          : []),
        ...(binding.observedDescriptorDigest
          ? [`observed descriptor sha256=${binding.observedDescriptorDigest}`]
          : []),
      ],
      reason: manifestBindingReason(binding.code),
    },
  };
}

function manifestBindingReason(code: ToolBindingVerificationResult["code"]): string {
  switch (code) {
    case "tool_binding_verified": return "签名工具身份绑定验证通过";
    case "tool_not_pinned": return "工具不在已验签的 provider-aware pinned manifest 中";
    case "tool_descriptor_mismatch": return "工具完整 descriptor 与签名 manifest 的固定摘要不一致";
    case "manifest_expired": return "签名工具 manifest 已过期";
    case "tool_verification_input_invalid": return "工具身份绑定输入不合法";
    case "verifier_clock_invalid": return "manifest 验证所依赖的 Host 时钟无效";
  }
}

function snapshotNotObservedDecision(id: string, reason: string): AdditionalPolicyDecision {
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id,
      triggeredArgs: [],
      evidence: ["no exact identity was committed by the latest complete tools/list snapshot"],
      reason,
    },
  };
}

function persistentLedgerDenial(
  violation: "task_budget_exhausted" | "tool_budget_exhausted" | "pending_reservation_limit",
): AdditionalPolicyDecision {
  const reason = violation === "task_budget_exhausted"
    ? "跨进程任务调用预算已经耗尽"
    : violation === "tool_budget_exhausted"
      ? "跨进程单工具调用预算已经耗尽"
      : "跨进程待执行 reservation 已达到安全上限";
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id: `persistent_${violation}`,
      triggeredArgs: [],
      evidence: ["durable task/session ledger denied the reservation before dispatch"],
      reason,
    },
  };
}

function persistentLedgerAuthorization(
  scopeDigest: string,
  policyDigest: string,
  reservationDigest: string,
): AdditionalPolicyDecision {
  return {
    decision: "allow",
    riskLevel: "low",
    policy: {
      id: "persistent_task_reservation_matched",
      triggeredArgs: [],
      evidence: [
        `ledger scope sha256=${scopeDigest}`,
        `ledger policy sha256=${policyDigest}`,
        `reservation sha256=${reservationDigest}`,
      ],
      reason: "跨进程 task/session 账本已原子预留本次调用预算",
    },
  };
}

/**
 * Commitment to this exact aggregate policy outcome. It is deliberately not
 * described as a source-code or policy-bundle digest: deployments that need
 * that property should additionally pin their Rego/config artifacts.
 */
export function digestDecisionPolicy(output: EngineOutput): string {
  return digestCanonicalValue({
    format: "riskproof.decision-policy-outcome.v1",
    decision: output.decision,
    riskLevel: output.riskLevel,
    matchedPolicies: output.matchedPolicies
      .map(({ id, triggeredArgs }) => ({ id, triggeredArgs: [...triggeredArgs].sort() }))
      .sort((left, right) => left.id.localeCompare(right.id)),
  });
}

function approvalTicketFromParams(
  params: Record<string, unknown>,
): string | SignedApprovalTicket | undefined {
  if (!isRecord(params._meta)) return undefined;
  const value = params._meta.riskproof_approval_ticket;
  if (value === undefined) return undefined;
  return value as string | SignedApprovalTicket;
}

function approvalRequiredDecision(): AdditionalPolicyDecision {
  return {
    decision: "require_approval",
    riskLevel: "high",
    policy: {
      id: "signed_approval_ticket_required",
      triggeredArgs: [],
      evidence: ["no exact signed single-use approval ticket was supplied"],
      reason: "该调用需要绑定 ToolKey、descriptor、参数、任务、主体、effect、有效期和 nonce 的签名审批票据",
    },
  };
}

function approvalTicketDenial(
  code: ApprovalTicketFailureCode,
  binding?: ApprovalTicketBindingField,
): AdditionalPolicyDecision {
  return {
    decision: "deny",
    riskLevel: "critical",
    policy: {
      id: `approval_ticket_${code}`,
      triggeredArgs: [],
      evidence: [
        `signed approval verification failed: ${code}`,
        ...(binding ? [`mismatched binding category: ${binding}`] : []),
      ],
      reason: code === "replayed"
        ? "审批票据 nonce 已被消费，重放请求被拒绝"
        : code === "binding_mismatch"
          ? "审批票据与即将 dispatch 的精确调用绑定不一致"
          : "审批票据未通过签名、时间、信任根或原子消费验证",
    },
  };
}

function policyNoDispatchReason(result: EngineOutput): NoDispatchReason {
  return result.matchedPolicies.some(({ id }) =>
    id.startsWith("task_") || id.startsWith("persistent_") ||
    id.startsWith("approval_") || id.startsWith("signed_approval_"))
    ? "authorization_failed"
    : "policy_block";
}

function evidenceMetadata(evidence: DispatchEvidence | undefined): Record<string, string> | undefined {
  if (!evidence) return undefined;
  return {
    proofId: evidence.proofId,
    ...(evidence.receiptId ? { receiptId: evidence.receiptId } : {}),
    ...(evidence.approvalTicketDigest
      ? { approvalTicketDigest: evidence.approvalTicketDigest }
      : {}),
  };
}

function evidenceError(
  id: number | string,
  code: number,
  message: string,
  evidence?: DispatchEvidence,
): JsonRpcResponse {
  const metadata = evidenceMetadata(evidence);
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
      ...(metadata ? { data: { riskproof: metadata } } : {}),
    },
  };
}

function attachExecutionEvidence(
  response: JsonRpcResponse,
  evidence: DispatchEvidence | undefined,
): JsonRpcResponse {
  const metadata = evidenceMetadata(evidence);
  if (!metadata) return response;
  if (response.error) {
    const existing = isRecord(response.error.data) ? response.error.data : {};
    return {
      ...response,
      error: {
        ...response.error,
        data: { ...existing, riskproof: metadata },
      },
    };
  }
  if (isRecord(response.result)) {
    const existingMeta = isRecord(response.result._meta) ? response.result._meta : {};
    return {
      ...response,
      result: {
        ...response.result,
        _meta: { ...existingMeta, riskproof: metadata },
      },
    };
  }
  return response;
}

function makeError(id: number | string, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function narrowInitializeRequest(request: JsonRpcRequest): JsonRpcRequest {
  const params = isRecord(request.params) ? request.params : {};
  // RiskProof intentionally exposes no server→client request capability. An
  // empty allowlist also strips experimental and future capability names until
  // the proxy grows a corresponding, policy-enforced handler for them.
  return {
    ...request,
    params: { ...params, capabilities: {} },
  };
}

function normalizeUpstreamResponse(
  value: Record<string, unknown>,
  id: number | string,
): JsonRpcResponse | null {
  const hasResult = Object.hasOwn(value, "result");
  const hasError = Object.hasOwn(value, "error");
  if (hasResult === hasError) return null;
  if (hasResult) return { jsonrpc: "2.0", id, result: value.result };

  if (!isRecord(value.error) || !Number.isInteger(value.error.code) || typeof value.error.message !== "string") {
    return null;
  }
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: value.error.code as number,
      message: value.error.message,
      ...(Object.hasOwn(value.error, "data") ? { data: value.error.data } : {}),
    },
  };
}

function isJsonRpcId(value: unknown): value is number | string {
  return typeof value === "string" || (typeof value === "number" && Number.isFinite(value));
}

function parseToolCallParams(params: Record<string, unknown>):
  | { toolName: string; args: Record<string, unknown>; flows?: ProvenanceFlow[] }
  | { error: string } {
  const toolName = params.name;
  const rawArgs = params.arguments ?? {};
  if (typeof toolName !== "string" || toolName.length === 0) {
    return { error: "Missing or invalid param: name" };
  }
  if (typeof rawArgs !== "object" || rawArgs === null || Array.isArray(rawArgs)) {
    return { error: "Invalid param: arguments must be an object" };
  }
  const flowResult = parseFlowMetadata(params._meta);
  if ("error" in flowResult) return flowResult;
  return {
    toolName,
    args: rawArgs as Record<string, unknown>,
    ...(flowResult.flows === undefined ? {} : { flows: flowResult.flows }),
  };
}

function parseFlowMetadata(value: unknown): { flows?: ProvenanceFlow[] } | { error: string } {
  if (value === undefined) return {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const raw = (value as Record<string, unknown>).riskproof_flows;
  if (raw === undefined) return {};
  if (!Array.isArray(raw)) return { error: "Invalid _meta.riskproof_flows: expected an array" };
  const flows: ProvenanceFlow[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    const item = raw[index];
    if (typeof item !== "object" || item === null || Array.isArray(item)) {
      return { error: `Invalid _meta.riskproof_flows[${index}]: expected an object` };
    }
    const flow = item as Record<string, unknown>;
    if (typeof flow.from !== "string" || typeof flow.to !== "string") {
      return { error: `Invalid _meta.riskproof_flows[${index}]: from/to must be strings` };
    }
    if (flow.via !== undefined && typeof flow.via !== "string") {
      return { error: `Invalid _meta.riskproof_flows[${index}].via: expected a string` };
    }
    flows.push({ from: flow.from, to: flow.to, ...(flow.via === undefined ? {} : { via: flow.via }) });
  }
  return { flows };
}

function contextCapabilities(
  method: string,
  entries: readonly ContextEntry[],
): ToolchainCapability[] {
  const capabilities = new Set<ToolchainCapability>();
  if (method === "prompts/get") capabilities.add("external_ingestion");
  for (const entry of entries) {
    if (["webpage", "email", "resource", "mcp_prompt"].includes(entry.kind)) {
      capabilities.add("external_ingestion");
    }
    if ([
      "email", "internal_doc", "customer_data", "source_code",
      "financial_data", "patient_data",
    ].includes(entry.kind)) {
      capabilities.add("private_data_access");
    }
  }
  return [...capabilities];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
