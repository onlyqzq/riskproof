// ============================================================================
// dsh-riskproof — bounded context tracking
// ============================================================================
// Maintains a bounded, in-memory index of content returned to the model. Raw
// content is never exposed by the public inspection API or persisted; only
// metadata (id, kind, taints, digest, size, sequence) leaves this class.
// ============================================================================

import { createHash } from "node:crypto";
import { types as utilTypes } from "node:util";
import type { TaintLabel } from "../core/types.js";
import { TAINT_BY_KIND, type ContextKind } from "../core/taint.js";

export interface ContextEntry {
  id: string;
  kind: ContextKind;
  label?: string;
  taints: TaintLabel[];
  contentDigest: string;
  byteCount: number;
  sequence: number;
}

interface StoredContextEntry extends ContextEntry {
  searchable: string[];
}

export interface ContextTrackerOptions {
  maxEntries?: number;
  maxEntryBytes?: number;
  maxTotalBytes?: number;
  minMatchLength?: number;
  maxNodes?: number;
  maxDepth?: number;
}

export const CONTEXT_TRACKER_LIMITS = Object.freeze({
  maxEntries: 256,
  maxEntryBytes: 256 * 1024,
  maxTotalBytes: 2 * 1024 * 1024,
  minMatchLength: 4,
  maxNodes: 10_000,
  maxDepth: 64,
});

export class ContextTracker {
  private readonly limits: Required<ContextTrackerOptions>;
  private readonly counters = new Map<ContextKind, number>();
  private readonly entries: StoredContextEntry[] = [];
  private totalBytes = 0;
  private sequence = 0;

  constructor(options: ContextTrackerOptions = {}) {
    this.limits = validateOptions(options);
  }

  record(
    kind: ContextKind,
    value: unknown,
    label?: string,
    declaredTaints: readonly TaintLabel[] = [],
  ): ContextEntry | null {
    const searchable = extractSearchable(
      value,
      this.limits.maxEntryBytes,
      this.limits.maxNodes,
      this.limits.maxDepth,
    );
    if (searchable.length === 0) return null;
    const byteCount = searchable.reduce((sum, text) => sum + Buffer.byteLength(text, "utf-8"), 0);
    const next = (this.counters.get(kind) ?? 0) + 1;
    this.counters.set(kind, next);
    this.sequence += 1;
    if (label !== undefined && typeof label !== "string") {
      throw new TypeError("context label must be a string");
    }
    const normalizedLabel = label?.slice(0, 256);
    const stored: StoredContextEntry = {
      id: `${kind}_${next}`,
      kind,
      ...(normalizedLabel ? { label: normalizedLabel } : {}),
      taints: [...new Set([...(TAINT_BY_KIND[kind] ?? []), ...declaredTaints])],
      contentDigest: createHash("sha256").update(searchable.join("\u0000")).digest("hex"),
      byteCount,
      sequence: this.sequence,
      searchable,
    };
    this.entries.push(stored);
    this.totalBytes += byteCount;
    this.evictOldest();
    return publicEntry(stored);
  }

  list(): ContextEntry[] {
    return this.entries.map(publicEntry);
  }

  clear(): void {
    this.entries.length = 0;
    this.totalBytes = 0;
  }

  /** Internal lookup used by ProvenanceMapper; returned arrays are copies. */
  match(value: unknown): Array<{ entry: ContextEntry; score: number }> {
    const needles = extractNeedles(
      value,
      this.limits.maxEntryBytes,
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
          exactOnly ? Number.POSITIVE_INFINITY : this.limits.minMatchLength,
        )) {
          score = Math.max(score, needle.length);
        }
      }
      if (score > 0) matches.push({ entry: publicEntry(stored), score });
    }
    return matches.sort((left, right) =>
      right.score - left.score ||
      right.entry.sequence - left.entry.sequence ||
      left.entry.id.localeCompare(right.entry.id));
  }

  private evictOldest(): void {
    while (
      this.entries.length > this.limits.maxEntries ||
      this.totalBytes > this.limits.maxTotalBytes
    ) {
      const removed = this.entries.shift();
      if (!removed) break;
      this.totalBytes -= removed.byteCount;
    }
  }
}

function publicEntry(entry: StoredContextEntry): ContextEntry {
  return {
    id: entry.id,
    kind: entry.kind,
    ...(entry.label ? { label: entry.label } : {}),
    taints: [...entry.taints],
    contentDigest: entry.contentDigest,
    byteCount: entry.byteCount,
    sequence: entry.sequence,
  };
}

function extractSearchable(
  value: unknown,
  maxBytes: number,
  maxNodes: number,
  maxDepth: number,
): string[] {
  const values: string[] = [];
  let remaining = maxBytes;
  const add = (text: string): void => {
    if (remaining <= 0 || text.length === 0) return;
    // Bound by bytes: slice conservatively by characters until under budget.
    let slice = text;
    while (Buffer.byteLength(slice, "utf-8") > remaining) {
      slice = slice.slice(0, Math.max(1, slice.length - 1));
    }
    values.push(slice);
    remaining -= Buffer.byteLength(slice, "utf-8");
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
  maxBytes: number,
  maxNodes: number,
  maxDepth: number,
): string[] {
  return extractSearchable(value, maxBytes, maxNodes, maxDepth)
    .map((text) => text.trim())
    .filter(Boolean)
    .sort((left, right) => right.length - left.length);
}

function matchesNeedle(haystacks: readonly string[], needle: string, minLength: number): boolean {
  if (needle.length < minLength) return haystacks.some((text) => text === needle);
  return haystacks.some((text) => text.includes(needle));
}

function validateOptions(options: ContextTrackerOptions): Required<ContextTrackerOptions> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new TypeError("ContextTracker options must be an object");
  }
  const allowed = new Set([
    "maxEntries", "maxEntryBytes", "maxTotalBytes", "minMatchLength", "maxNodes", "maxDepth",
  ]);
  const unknown = Object.keys(options).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new TypeError("ContextTracker options contain unsupported field(s)");
  const merged = { ...CONTEXT_TRACKER_LIMITS, ...options };
  for (const [name, value] of Object.entries(merged)) {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new RangeError(`${name} must be a positive integer`);
    }
  }
  if (merged.maxEntryBytes > merged.maxTotalBytes) {
    throw new RangeError("maxEntryBytes must not exceed maxTotalBytes");
  }
  return merged;
}
