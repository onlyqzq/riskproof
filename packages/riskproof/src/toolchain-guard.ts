// ============================================================================
// RiskProof — deterministic cross-tool MCP toolchain guard
// ============================================================================
//
// A single MCP tool can look harmless while a sequence of complementary tools
// forms an attack path. This module keeps a bounded metadata-only history of
// successful (and currently in-flight) calls and detects the three stages used
// by parasitic toolchain attacks:
//
//   external ingestion -> private-data access -> external disclosure
//
// It never stores raw tool results. The guard only retains tool labels,
// capability classes, and ContextTracker IDs so callers can share one guard at
// the host interception boundary without creating a second sensitive-data log.

import { mergePolicyDecisions, type AdditionalPolicyDecision } from "./engine.js";
import type { ArgumentEvidence, EngineOutput, TaintLabel } from "./types.js";

export type ToolchainCapability =
  | "external_ingestion"
  | "private_data_access"
  | "external_disclosure";

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface ToolchainGuardOptions {
  /** Maximum completed/pending metadata events retained in memory. */
  maxEvents?: number;
  /** Number of most recent call events considered one composable chain. */
  chainWindow?: number;
  /** Maximum ContextTracker IDs retained for one event. */
  maxContextIdsPerEvent?: number;
}

export interface ToolchainEvent {
  sequence: number;
  toolName: string;
  capabilities: ToolchainCapability[];
  contextIds: string[];
  status: "pending" | "completed";
}

export const TOOLCHAIN_GUARD_LIMITS = Object.freeze({
  maxEvents: 128,
  chainWindow: 12,
  maxContextIdsPerEvent: 32,
});

const CAPABILITY_ORDER: readonly ToolchainCapability[] = [
  "external_ingestion",
  "private_data_access",
  "external_disclosure",
];

const SENSITIVE_TAINTS = new Set<TaintLabel>([
  "INTERNAL_DOC",
  "CUSTOMER_DATA",
  "PII",
  "SECRET",
  "API_KEY",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
]);

const COMMAND_TOOL = /\b(?:shell|bash|zsh|powershell|terminal|command|exec(?:ute)?|script|desktop commander)\b/;
const INGEST_ACTION = /\b(?:fetch|search|scrape|crawl|browse|visit|download|retrieve|read|get|list|watch|subscribe)\b/;
const EXTERNAL_SOURCE = /\b(?:web|webpage|url|uri|http|internet|remote|feed|social|post|issue|channel|slack|teams|discord|mail|email|inbox|message|news|browser)\b/;
const PRIVATE_ACTION = /\b(?:read|get|list|search|query|inspect|retrieve|load|open|print|show|view|export)\b/;
const PRIVATE_SOURCE = /\b(?:file|filesystem|directory|folder|path|workspace|repository|repo|config(?:uration)?|environment|env|credential|secret|keychain|history|clipboard|contact|mail|email|inbox|message|database|sql|record|customer|client|patient|medical|financial|invoice|log|excel|sheet|board)\b/;
const DISCLOSURE_ACTION = /\b(?:send|post|publish|upload|notify|forward|deliver|transmit|webhook|request|patch|put|create|append|write)\b/;
const DISCLOSURE_TARGET = /\b(?:mail|email|message|slack|teams|discord|issue|comment|campaign|document|page|api|url|uri|http|endpoint|network|remote|webhook|web|notion|lark|feishu)\b/;
const URL_REQUEST = /\b(?:fetch|http|request|webhook|upload|download|proxy)\b/;
const SCHEMA_NETWORK_SINK = /\b(?:url|uri|endpoint|recipient|recipients|to|body|payload|content|message|query|webhook)\b/;

/**
 * Conservatively classify an MCP tool from metadata already visible to the
 * host. Classification can only add scrutiny; it never grants a capability.
 */
export function classifyToolchainCapabilities(
  descriptor: McpToolDescriptor,
): ToolchainCapability[] {
  if (!descriptor || typeof descriptor !== "object" || typeof descriptor.name !== "string") {
    throw new TypeError("MCP tool descriptor must contain a string name");
  }
  const name = normalizeText(descriptor.name).slice(0, 1_024);
  const description = normalizeText(
    typeof descriptor.description === "string" ? descriptor.description : "",
  ).slice(0, 8_192);
  const schema = normalizeText(safeSchemaText(descriptor.inputSchema)).slice(0, 16_384);
  const semantic = `${name} ${description}`.trim();
  const all = `${semantic} ${schema}`.trim();
  const capabilities = new Set<ToolchainCapability>();

  // General-purpose command execution can implement every phase (curl/read/
  // send) even when its natural-language description only mentions execution.
  if (COMMAND_TOOL.test(semantic)) {
    CAPABILITY_ORDER.forEach((capability) => capabilities.add(capability));
  }

  if (
    (INGEST_ACTION.test(semantic) && EXTERNAL_SOURCE.test(all)) ||
    /\b(?:fetch url|web search|visit page|scrape|crawl|read mail|read email|channel history|social feed)\b/.test(semantic)
  ) {
    capabilities.add("external_ingestion");
  }

  if (
    (PRIVATE_ACTION.test(semantic) && PRIVATE_SOURCE.test(all)) ||
    /\b(?:read file|print env|get config|search history|recent tool calls|execute query|read data from excel)\b/.test(semantic)
  ) {
    capabilities.add("private_data_access");
  }

  if (
    (DISCLOSURE_ACTION.test(semantic) && DISCLOSURE_TARGET.test(all)) ||
    /\b(?:send mail|send email|post message|publish post|create issue|create campaign|upload file)\b/.test(semantic) ||
    (URL_REQUEST.test(semantic) && SCHEMA_NETWORK_SINK.test(schema))
  ) {
    capabilities.add("external_disclosure");
  }

  return CAPABILITY_ORDER.filter((capability) => capabilities.has(capability));
}

/**
 * Bounded sequence monitor. Call assess() before execution, begin() when a call
 * is forwarded, then complete()/abort() based on the upstream result.
 */
export class ToolchainGuard {
  private readonly limits: Required<ToolchainGuardOptions>;
  private readonly events: ToolchainEvent[] = [];
  private nextSequence = 0;

  constructor(options: ToolchainGuardOptions = {}) {
    this.limits = validateOptions(options);
  }

  assess(
    descriptor: McpToolDescriptor,
    argumentsByName: Record<string, ArgumentEvidence> = {},
  ): AdditionalPolicyDecision[] {
    const currentCapabilities = classifyToolchainCapabilities(descriptor);
    if (currentCapabilities.length === 0) return [];

    const recent = this.events.slice(-this.limits.chainWindow);
    const ingress = findLast(recent, (event) =>
      event.capabilities.includes("external_ingestion"));
    const privateAccess = ingress
      ? findLast(recent, (event) =>
        event.sequence > ingress.sequence && event.capabilities.includes("private_data_access"))
      : undefined;
    const currentName = safeToolLabel(descriptor.name);

    // A single general-purpose tool can internally perform the entire chain.
    // Metadata alone does not prove exploitation, so this is a critical review
    // rather than an unconditional block.
    if (
      currentCapabilities.includes("external_ingestion") &&
      currentCapabilities.includes("private_data_access") &&
      currentCapabilities.includes("external_disclosure") &&
      !ingress
    ) {
      return [{
        decision: "require_approval",
        riskLevel: "critical",
        policy: {
          id: "self_contained_toolchain_capability",
          triggeredArgs: [],
          evidence: [
            `tool '${currentName}' can ingest external content, access private data, and disclose externally`,
          ],
          reason: "单个工具同时具备外部摄入、私密访问和对外发送能力，可能独立完成寄生工具链攻击",
        },
      }];
    }

    if (ingress && currentCapabilities.includes("external_disclosure") && privateAccess) {
      const confirmedArguments = findConfirmedDisclosureArguments(
        argumentsByName,
        privateAccess.contextIds,
      );
      const path = formatPath(ingress, privateAccess, currentName);
      if (confirmedArguments.length > 0) {
        return [{
          decision: "deny",
          riskLevel: "critical",
          policy: {
            id: "parasitic_toolchain_data_exfiltration",
            triggeredArgs: confirmedArguments,
            evidence: [
              `observed capability path: ${path}`,
              `outbound argument(s) carry private-access evidence: ${confirmedArguments.join(", ")}`,
            ],
            reason: "检测到外部内容摄入、私密数据访问和携带私密证据的对外发送完整链路，默认阻断",
          },
        }];
      }
      return [{
        decision: "require_approval",
        riskLevel: "critical",
        policy: {
          id: "parasitic_toolchain_disclosure_path",
          triggeredArgs: [],
          evidence: [`observed capability path: ${path}`],
          reason: "当前对外操作紧随外部内容摄入和私密数据访问，形成潜在寄生工具链，需要独立可信审批",
        },
      }];
    }

    // Some tools combine collection and disclosure internally, leaving no
    // intermediate result for substring provenance to observe.
    if (
      ingress &&
      currentCapabilities.includes("private_data_access") &&
      currentCapabilities.includes("external_disclosure")
    ) {
      return [{
        decision: "require_approval",
        riskLevel: "critical",
        policy: {
          id: "parasitic_toolchain_combined_sink",
          triggeredArgs: [],
          evidence: [
            `observed capability path: ${eventLabel(ingress)} [external_ingestion] -> ` +
            `${currentName} [private_data_access+external_disclosure]`,
          ],
          reason: "不可信外部内容之后调用了可同时读取私密数据并对外发送的工具，可能在单步内完成泄露",
        },
      }];
    }

    if (ingress && currentCapabilities.includes("private_data_access")) {
      return [{
        decision: "require_approval",
        riskLevel: "high",
        policy: {
          id: "cross_tool_private_access_after_ingestion",
          triggeredArgs: [],
          evidence: [
            `observed capability transition: ${eventLabel(ingress)} [external_ingestion] -> ` +
            `${currentName} [private_data_access]`,
          ],
          reason: "私密数据访问发生在不可信外部内容进入上下文之后，可能是寄生指令驱动的权限跃迁",
        },
      }];
    }

    return [];
  }

  /** Reserve an event immediately before forwarding a real tools/call. */
  begin(descriptor: McpToolDescriptor): number {
    const event: ToolchainEvent = {
      sequence: ++this.nextSequence,
      toolName: safeToolLabel(descriptor.name),
      capabilities: classifyToolchainCapabilities(descriptor),
      contextIds: [],
      status: "pending",
    };
    this.events.push(event);
    this.trim();
    return event.sequence;
  }

  /** Mark an upstream call successful and bind only metadata context IDs. */
  complete(sequence: number, contextIds: readonly string[] = []): void {
    const event = this.events.find((candidate) => candidate.sequence === sequence);
    if (!event) return;
    event.status = "completed";
    event.contextIds = normalizeContextIds(contextIds, this.limits.maxContextIdsPerEvent);
    this.trim();
  }

  /** Remove an event whose upstream call failed or was cancelled. */
  abort(sequence: number): void {
    const index = this.events.findIndex((candidate) => candidate.sequence === sequence);
    if (index >= 0) this.events.splice(index, 1);
  }

  /** Record a successful non-tools/call context operation such as prompts/get. */
  recordContext(
    sourceName: string,
    capabilities: readonly ToolchainCapability[],
    contextIds: readonly string[] = [],
  ): number {
    const uniqueCapabilities = CAPABILITY_ORDER.filter((capability) =>
      capabilities.includes(capability));
    const event: ToolchainEvent = {
      sequence: ++this.nextSequence,
      toolName: safeToolLabel(sourceName),
      capabilities: uniqueCapabilities,
      contextIds: normalizeContextIds(contextIds, this.limits.maxContextIdsPerEvent),
      status: "completed",
    };
    this.events.push(event);
    this.trim();
    return event.sequence;
  }

  /** Metadata-only snapshot, ordered oldest to newest. */
  list(): ToolchainEvent[] {
    return this.events.map((event) => ({
      ...event,
      capabilities: [...event.capabilities],
      contextIds: [...event.contextIds],
    }));
  }

  clear(): void {
    this.events.length = 0;
  }

  private trim(): void {
    while (this.events.length > this.limits.maxEvents) {
      const completedIndex = this.events.findIndex((event) => event.status === "completed");
      if (completedIndex < 0) break;
      this.events.splice(completedIndex, 1);
    }
  }
}

/** Merge chain findings monotonically and regenerate an internally consistent proof. */
export function applyToolchainGuard(
  output: EngineOutput,
  guard: ToolchainGuard,
  descriptor: McpToolDescriptor,
): EngineOutput {
  return mergePolicyDecisions(output, guard.assess(descriptor, output.arguments));
}

function findConfirmedDisclosureArguments(
  argumentsByName: Record<string, ArgumentEvidence>,
  privateContextIds: readonly string[],
): string[] {
  const contextIds = new Set(privateContextIds);
  const confirmed: string[] = [];
  for (const [name, argument] of Object.entries(argumentsByName)) {
    const carriesPrivateContext = argument.source.some((source) => contextIds.has(source));
    const carriesSensitiveTaint = argument.taints.some((taint) => SENSITIVE_TAINTS.has(taint));
    if (carriesPrivateContext || carriesSensitiveTaint) confirmed.push(name);
  }
  return confirmed;
}

function findLast<T>(items: readonly T[], predicate: (item: T) => boolean): T | undefined {
  for (let index = items.length - 1; index >= 0; index -= 1) {
    if (predicate(items[index])) return items[index];
  }
  return undefined;
}

function formatPath(
  ingress: ToolchainEvent,
  privateAccess: ToolchainEvent,
  disclosureName: string,
): string {
  return `${eventLabel(ingress)} [external_ingestion] -> ` +
    `${eventLabel(privateAccess)} [private_data_access] -> ` +
    `${disclosureName} [external_disclosure]`;
}

function eventLabel(event: ToolchainEvent): string {
  return `${event.toolName}#${event.sequence}`;
}

function normalizeContextIds(values: readonly string[], max: number): string[] {
  const result: string[] = [];
  for (const value of values) {
    if (typeof value !== "string" || value.length === 0) continue;
    const normalized = value.slice(0, 256);
    if (!result.includes(normalized)) result.push(normalized);
    if (result.length >= max) break;
  }
  return result;
}

function safeToolLabel(value: string): string {
  return normalizeText(typeof value === "string" ? value : "invalid_tool")
    .replace(/[^a-z0-9 .:/_-]/g, "_")
    .slice(0, 128) || "unnamed_tool";
}

function normalizeText(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function safeSchemaText(schema: Record<string, unknown> | undefined): string {
  if (!schema) return "";
  try {
    return JSON.stringify(schema);
  } catch {
    return "";
  }
}

function validateOptions(options: ToolchainGuardOptions): Required<ToolchainGuardOptions> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new TypeError("ToolchainGuard options must be an object");
  }
  const allowed = new Set(["maxEvents", "chainWindow", "maxContextIdsPerEvent"]);
  if (Object.keys(options).some((key) => !allowed.has(key))) {
    throw new TypeError("ToolchainGuard options contain unsupported field(s)");
  }
  const merged = { ...TOOLCHAIN_GUARD_LIMITS, ...options };
  for (const [name, value] of Object.entries(merged)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 4_096) {
      throw new RangeError(`${name} must be an integer between 1 and 4096`);
    }
  }
  if (merged.chainWindow > merged.maxEvents) {
    throw new RangeError("chainWindow must not exceed maxEvents");
  }
  return merged;
}
