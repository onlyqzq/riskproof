// ============================================================================
// dsh-riskproof — cross-tool toolchain guard
// ============================================================================
// A single tool call can look harmless while a sequence of complementary tools
// forms an attack path. This module keeps a bounded, metadata-only history of
// successful calls and derives the EIT → PAT → NAT state used by the engine.
// It never stores raw tool results — only tool labels, capability classes, and
// ContextTracker ids.
// ============================================================================

import type { SecurityCapability, ToolchainState } from "../core/types.js";
import { EMPTY_TOOLCHAIN_STATE } from "../core/types.js";
import { capabilityLabel } from "../classification/capabilities.js";

export interface ToolchainGuardOptions {
  maxEvents?: number;
  chainWindow?: number;
  maxContextIdsPerEvent?: number;
}

export interface ToolchainEvent {
  sequence: number;
  toolName: string;
  capabilities: SecurityCapability[];
  contextIds: string[];
}

export const TOOLCHAIN_GUARD_LIMITS = Object.freeze({
  maxEvents: 128,
  chainWindow: 12,
  maxContextIdsPerEvent: 32,
});

export class ToolchainGuard {
  private readonly limits: Required<ToolchainGuardOptions>;
  private readonly events: ToolchainEvent[] = [];
  private nextSequence = 0;

  constructor(options: ToolchainGuardOptions = {}) {
    this.limits = validateOptions(options);
  }

  /** Record a successful tool call with the ContextTracker ids it produced. */
  recordEvent(
    toolName: string,
    capabilities: readonly SecurityCapability[],
    contextIds: readonly string[] = [],
  ): void {
    this.events.push({
      sequence: ++this.nextSequence,
      toolName: safeToolLabel(toolName),
      capabilities: [...capabilities],
      contextIds: normalizeContextIds(contextIds, this.limits.maxContextIdsPerEvent),
    });
    this.trim();
  }

  /** The EIT/PAT/NAT state observed before the pending call. */
  snapshot(): ToolchainState {
    const recent = this.events.slice(-this.limits.chainWindow);
    let sawIngestion = false;
    let sawPrivateAccess = false;
    let sawIngestionThenPrivateAccess = false;
    let sawExternalAction = false;
    const path: string[] = [];
    for (const event of recent) {
      // Check PAT before updating EIT for this event: one multi-capability tool
      // is not by itself a cross-tool EIT -> PAT sequence.
      if (event.capabilities.includes("PRIVATE_ACCESS")) {
        sawPrivateAccess = true;
        if (sawIngestion) sawIngestionThenPrivateAccess = true;
      }
      if (event.capabilities.includes("EXTERNAL_INGESTION")) sawIngestion = true;
      if (event.capabilities.includes("EXTERNAL_ACTION")) sawExternalAction = true;
      for (const capability of event.capabilities) {
        const label = capabilityLabel(capability);
        path.push(label);
      }
    }
    if (!sawIngestion && !sawPrivateAccess && !sawExternalAction && path.length === 0) {
      return EMPTY_TOOLCHAIN_STATE;
    }
    return {
      sawIngestion,
      sawPrivateAccess,
      sawIngestionThenPrivateAccess,
      sawExternalAction,
      path,
    };
  }

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
      this.events.shift();
    }
  }
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
  return value
    .replace(/[^a-zA-Z0-9 .:/_-]/g, "_")
    .slice(0, 128) || "unnamed_tool";
}

function validateOptions(options: ToolchainGuardOptions): Required<ToolchainGuardOptions> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new TypeError("ToolchainGuard options must be an object");
  }
  const allowed = new Set(["maxEvents", "chainWindow", "maxContextIdsPerEvent"]);
  const unknown = Object.keys(options).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new TypeError("ToolchainGuard options contain unsupported field(s)");
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
