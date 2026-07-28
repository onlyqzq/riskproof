// ============================================================================
// RiskProof — bounded MCP context tracking and deterministic provenance mapping
// ============================================================================

import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import type { TaintLabel } from "./types.js";

export type ContextEntryKind =
  | "trusted_user"
  | "webpage"
  | "email"
  | "tool_output"
  | "mcp_prompt"
  | "resource"
  | "internal_doc"
  | "customer_data"
  | "source_code"
  | "financial_data"
  | "patient_data";

/** Public metadata deliberately excludes raw context, which may contain secrets. */
export interface ContextEntry {
  id: string;
  kind: ContextEntryKind;
  label?: string;
  taints: TaintLabel[];
  contentDigest: string;
  characterCount: number;
  sequence: number;
}

interface StoredContextEntry extends ContextEntry {
  searchable: string[];
}

export interface ContextTrackerOptions {
  maxEntries?: number;
  maxEntryCharacters?: number;
  maxTotalCharacters?: number;
  minSubstringLength?: number;
  maxNodes?: number;
  maxDepth?: number;
}

export interface ProvenanceMapping {
  provenance: Record<string, string[]>;
  taints: Record<string, TaintLabel[]>;
}

export const CONTEXT_TRACKER_LIMITS = Object.freeze({
  maxEntries: 256,
  maxEntryCharacters: 256 * 1024,
  maxTotalCharacters: 2 * 1024 * 1024,
  minSubstringLength: 4,
  maxNodes: 10_000,
  maxDepth: 64,
});

const KIND_TAINTS: Partial<Record<ContextEntryKind, TaintLabel[]>> = {
  webpage: ["UNTRUSTED_WEB"],
  email: ["UNTRUSTED_EMAIL"],
  internal_doc: ["INTERNAL_DOC"],
  customer_data: ["CUSTOMER_DATA"],
  source_code: ["SOURCE_CODE"],
  financial_data: ["FINANCIAL_DATA"],
  patient_data: ["PATIENT_DATA"],
};

/**
 * Maintains a bounded, in-memory index of content returned to an MCP client.
 * Raw content is never exposed by the public inspection API or persisted.
 */
export class ContextTracker {
  private readonly limits: Required<ContextTrackerOptions>;
  private readonly counters = new Map<ContextEntryKind, number>();
  private readonly entries: StoredContextEntry[] = [];
  private totalCharacters = 0;
  private sequence = 0;

  constructor(options: ContextTrackerOptions = {}) {
    this.limits = validateOptions(options);
  }

  recordResponse(
    method: string,
    params: Record<string, unknown> | undefined,
    result: unknown,
  ): ContextEntry[] {
    if (method === "resources/read") return this.recordResources(params, result);
    if (method === "prompts/get") {
      const entry = this.record("mcp_prompt", result, stringField(params, "name"));
      return entry ? [entry] : [];
    }
    if (method === "tools/call") {
      const toolName = stringField(params, "name") ?? "tool";
      const entry = this.record(inferToolResultKind(toolName), result, toolName);
      return entry ? [entry] : [];
    }
    return [];
  }

  record(
    kind: ContextEntryKind,
    value: unknown,
    label?: string,
    declaredTaints: readonly TaintLabel[] = [],
  ): ContextEntry | null {
    const searchable = extractSearchable(
      value,
      this.limits.maxEntryCharacters,
      this.limits.maxNodes,
      this.limits.maxDepth,
    );
    if (searchable.length === 0) return null;
    const characterCount = searchable.reduce((sum, text) => sum + text.length, 0);
    const next = (this.counters.get(kind) ?? 0) + 1;
    this.counters.set(kind, next);
    this.sequence += 1;
    if (label !== undefined && typeof label !== "string") throw new TypeError("context label must be a string");
    const normalizedLabel = label?.slice(0, 256);
    const stored: StoredContextEntry = {
      id: `${kind}_${next}`,
      kind,
      ...(normalizedLabel ? { label: normalizedLabel } : {}),
      taints: [...new Set([...(KIND_TAINTS[kind] ?? []), ...declaredTaints])],
      contentDigest: createHash("sha256").update(searchable.join("\u0000")).digest("hex"),
      characterCount,
      sequence: this.sequence,
      searchable,
    };
    this.entries.push(stored);
    this.totalCharacters += characterCount;
    this.evictOldest();
    return publicEntry(stored);
  }

  /** Metadata-only snapshot, ordered from oldest to newest. */
  list(): ContextEntry[] {
    return this.entries.map(publicEntry);
  }

  clear(): void {
    this.entries.length = 0;
    this.totalCharacters = 0;
  }

  /** Internal lookup used by ProvenanceMapper; returned arrays are copies. */
  match(value: unknown): Array<{ entry: ContextEntry; score: number }> {
    const needles = extractNeedles(
      value,
      this.limits.maxEntryCharacters,
      this.limits.maxNodes,
      this.limits.maxDepth,
    );
    if (needles.length === 0) return [];
    const exactOnly = typeof value !== "string" && (value === null || typeof value !== "object");
    const matches: Array<{ entry: ContextEntry; score: number }> = [];
    for (const stored of this.entries) {
      let score = 0;
      for (const needle of needles) {
        if (matchesNeedle(
          stored.searchable,
          needle,
          exactOnly ? Number.POSITIVE_INFINITY : this.limits.minSubstringLength,
        )) {
          score = Math.max(score, needle.length);
        }
      }
      if (score > 0) matches.push({ entry: publicEntry(stored), score });
    }
    return matches.sort((left, right) =>
      right.score - left.score || right.entry.sequence - left.entry.sequence ||
      left.entry.id.localeCompare(right.entry.id));
  }

  private recordResources(
    params: Record<string, unknown> | undefined,
    result: unknown,
  ): ContextEntry[] {
    const fallbackUri = stringField(params, "uri");
    const contents = isRecord(result) && Array.isArray(result.contents) ? result.contents : [result];
    const recorded: ContextEntry[] = [];
    for (const content of contents) {
      const uri = isRecord(content) && typeof content.uri === "string" ? content.uri : fallbackUri;
      const entry = this.record(inferResourceKind(uri, content), content, uri);
      if (entry) recorded.push(entry);
    }
    return recorded;
  }

  private evictOldest(): void {
    while (
      this.entries.length > this.limits.maxEntries ||
      this.totalCharacters > this.limits.maxTotalCharacters
    ) {
      const removed = this.entries.shift();
      if (!removed) break;
      this.totalCharacters -= removed.characterCount;
    }
  }
}

/** Maps argument values back to exact context substrings, conservatively. */
export class ProvenanceMapper {
  constructor(private readonly tracker: ContextTracker) {}

  mapArguments(args: Record<string, unknown>): ProvenanceMapping {
    const provenance: Record<string, string[]> = {};
    const taints: Record<string, TaintLabel[]> = {};
    for (const [name, value] of Object.entries(args)) {
      const matches = this.tracker.match(value);
      if (matches.length === 0) {
        provenance[name] = ["agent_generated"];
        taints[name] = [];
        continue;
      }
      provenance[name] = [...new Set(matches.map(({ entry }) => entry.id))];
      taints[name] = [...new Set(matches.flatMap(({ entry }) => entry.taints))];
    }
    return { provenance, taints };
  }
}

function inferResourceKind(uri: string | undefined, content: unknown): ContextEntryKind {
  const target = `${uri ?? ""} ${isRecord(content) && typeof content.mimeType === "string" ? content.mimeType : ""}`.toLowerCase();
  if (/^https?:|\bhtml\b|\bweb(page)?\b/.test(target)) return "webpage";
  if (/^mailto:|\bemail\b|\bmail\b|message\/rfc822/.test(target)) return "email";
  if (/\b(patient|medical|clinical|health)\b/.test(target)) return "patient_data";
  if (/\b(finance|financial|invoice|payment|bank)\b/.test(target)) return "financial_data";
  if (/\b(customer|client|crm)\b/.test(target)) return "customer_data";
  if (/\b(repo|source|code|git)\b|\.(?:ts|js|py|go|rs|java|c|cpp)(?:\b|$)/.test(target)) return "source_code";
  if (/^file:|\b(internal|document|knowledge|wiki)\b/.test(target)) return "internal_doc";
  return "resource";
}

function inferToolResultKind(toolName: string): ContextEntryKind {
  const name = toolName.toLowerCase().replace(/[_-]+/g, " ");
  if (/\b(web|browser|search|crawl|scrape|fetch|url|webpage)\b/.test(name)) return "webpage";
  if (/\b(email|mail|inbox|message)\b/.test(name)) return "email";
  if (/\b(patient|medical|clinical|health)\b/.test(name)) return "patient_data";
  if (/\b(finance|financial|invoice|payment|bank)\b/.test(name)) return "financial_data";
  if (/\b(customer|client|crm|salesforce)\b/.test(name)) return "customer_data";
  if (/\b(repo|source|code|github|gitlab)\b|\bread file\b/.test(name)) return "source_code";
  if (/\b(internal|document|knowledge|wiki)\b/.test(name)) return "internal_doc";
  return "tool_output";
}

function extractSearchable(
  value: unknown,
  maxCharacters: number,
  maxNodes: number,
  maxDepth: number,
): string[] {
  const values: string[] = [];
  let remaining = maxCharacters;
  const add = (text: string): void => {
    if (remaining <= 0 || text.length === 0) return;
    const bounded = text.slice(0, remaining);
    values.push(bounded);
    remaining -= bounded.length;
  };
  const pending: Array<{ item: unknown; depth: number }> = [{ item: value, depth: 0 }];
  const seen = new Set<object>();
  let nodes = 0;
  while (pending.length > 0 && remaining > 0) {
    const { item, depth } = pending.pop()!;
    nodes += 1;
    if (nodes > maxNodes) throw new RangeError(`context value exceeds maximum node count of ${maxNodes}`);
    if (depth > maxDepth) throw new RangeError(`context value exceeds maximum depth of ${maxDepth}`);
    if (item === null || item === undefined) continue;
    if (typeof item === "string") { add(item); continue; }
    if (typeof item === "number" || typeof item === "boolean") { add(JSON.stringify(item)); continue; }
    if (typeof item !== "object") throw new TypeError("context value must contain only JSON-compatible values");
    if (utilTypes.isProxy(item)) throw new TypeError("context value must not contain a Proxy");
    if (seen.has(item)) throw new TypeError("context value must not contain circular or aliased objects");
    seen.add(item);
    const prototype = Object.getPrototypeOf(item);
    if (!Array.isArray(item) && prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("context value must contain only plain objects and arrays");
    }
    const descriptors = Object.getOwnPropertyDescriptors(item);
    const children: unknown[] = [];
    for (const [key, descriptor] of Object.entries(descriptors)) {
      if (Array.isArray(item) && key === "length") continue;
      if (!("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("context value must contain only enumerable data properties");
      }
      children.push(descriptor.value);
    }
    for (let index = children.length - 1; index >= 0; index -= 1) {
      pending.push({ item: children[index], depth: depth + 1 });
    }
  }
  return [...new Set(values)];
}

function extractNeedles(
  value: unknown,
  maxCharacters: number,
  maxNodes: number,
  maxDepth: number,
): string[] {
  return extractSearchable(value, maxCharacters, maxNodes, maxDepth)
    .map((text) => text.trim())
    .filter(Boolean)
    .sort((left, right) => right.length - left.length);
}

function matchesNeedle(haystacks: readonly string[], needle: string, minLength: number): boolean {
  if (needle.length < minLength) return haystacks.some((text) => text === needle);
  return haystacks.some((text) => text.includes(needle));
}

function publicEntry(entry: StoredContextEntry): ContextEntry {
  return {
    id: entry.id,
    kind: entry.kind,
    ...(entry.label ? { label: entry.label } : {}),
    taints: [...entry.taints],
    contentDigest: entry.contentDigest,
    characterCount: entry.characterCount,
    sequence: entry.sequence,
  };
}

function validateOptions(options: ContextTrackerOptions): Required<ContextTrackerOptions> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new TypeError("ContextTracker options must be an object");
  }
  const allowed = new Set([
    "maxEntries", "maxEntryCharacters", "maxTotalCharacters", "minSubstringLength",
    "maxNodes", "maxDepth",
  ]);
  const unknown = Object.keys(options).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new TypeError("ContextTracker options contain unsupported field(s)");
  const merged = { ...CONTEXT_TRACKER_LIMITS, ...options };
  for (const [name, value] of Object.entries(merged)) {
    if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive integer`);
  }
  if (merged.maxEntryCharacters > merged.maxTotalCharacters) {
    throw new RangeError("maxEntryCharacters must not exceed maxTotalCharacters");
  }
  return merged;
}

function stringField(value: Record<string, unknown> | undefined, key: string): string | undefined {
  return value && typeof value[key] === "string" ? value[key] : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
