// ============================================================================
// dsh-riskproof — security capability vocabulary
// ============================================================================

import {
  ALL_CAPABILITIES,
  type SecurityCapability,
} from "../core/types.js";

export const CAPABILITIES: readonly SecurityCapability[] = ALL_CAPABILITIES;

const CAPABILITY_SET = new Set<string>(CAPABILITIES);

/**
 * Cross-tool attack-chain aliases. These three capabilities form the
 * "parasitic toolchain" model:
 *
 *   EXTERNAL_INGESTION → PRIVATE_ACCESS → EXTERNAL_ACTION
 *
 * A single tool call is usually safe; the composition is not.
 */
export const EIT: SecurityCapability = "EXTERNAL_INGESTION";
export const PAT: SecurityCapability = "PRIVATE_ACCESS";
export const NAT: SecurityCapability = "EXTERNAL_ACTION";

/** Canonical ordering used for stable path strings. */
export const CAPABILITY_ORDER: readonly SecurityCapability[] = [
  "EXTERNAL_INGESTION",
  "PRIVATE_ACCESS",
  "EXTERNAL_ACTION",
  "LOCAL_MUTATION",
  "CODE_EXECUTION",
  "CREDENTIAL_ACCESS",
];

export function isSecurityCapability(value: unknown): value is SecurityCapability {
  return typeof value === "string" && CAPABILITY_SET.has(value);
}

/**
 * Validate and normalize a list of capability strings. Rejects unknown values
 * so a typo in a config override fails loudly at load rather than silently
 * weakening the security boundary.
 */
export function normalizeCapabilities(
  values: readonly unknown[],
  label: string,
): SecurityCapability[] {
  const result: SecurityCapability[] = [];
  const seen = new Set<SecurityCapability>();
  for (const value of values) {
    if (!isSecurityCapability(value)) {
      throw new TypeError(`${label} contains unsupported capability '${String(value)}'`);
    }
    if (!seen.has(value)) {
      seen.add(value);
      result.push(value);
    }
  }
  return CAPABILITY_ORDER.filter((capability) => seen.has(capability));
}

/** Stable, human-readable path fragment for one capability. */
export function capabilityLabel(capability: SecurityCapability): string {
  return capability.toLowerCase();
}
