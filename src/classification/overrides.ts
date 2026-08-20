// ============================================================================
// dsh-riskproof — user capability overrides
// ============================================================================
// Explicit operator overrides always win over heuristic classification. A
// user who pins a vendor tool to a capability set does so with intent; the
// config loader validates the values so a typo cannot silently weaken the
// boundary.
// ============================================================================

import type { SecurityCapability } from "../core/types.js";
import { normalizeCapabilities } from "./capabilities.js";

export type CapabilityOverrides = Record<string, SecurityCapability[]>;

/** Validate a raw overrides object into normalized capability lists. */
export function normalizeOverrides(raw: unknown): CapabilityOverrides {
  if (raw === undefined) return Object.create(null) as CapabilityOverrides;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new TypeError("classification.overrides must be an object mapping tool names to capability lists");
  }
  const result = Object.create(null) as CapabilityOverrides;
  for (const [toolName, value] of Object.entries(raw as Record<string, unknown>)) {
    if (toolName.length === 0 || toolName.length > 256) {
      throw new TypeError("classification.overrides tool names must be 1-256 characters");
    }
    if (!Array.isArray(value)) {
      throw new TypeError(`classification.overrides['${toolName}'] must be an array of capability strings`);
    }
    result[toolName] = normalizeCapabilities(value, `classification.overrides['${toolName}']`);
  }
  return result;
}

/** Whether a tool name has an explicit override. */
export function hasOverride(overrides: CapabilityOverrides, toolName: string): boolean {
  return Object.hasOwn(overrides, toolName);
}
