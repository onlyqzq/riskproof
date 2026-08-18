// ============================================================================
// dsh-riskproof — Schemastery configuration
// ============================================================================
// Every deployment-tunable parameter lives here. Invalid values fail at
// plugin load; there is no half-configured startup. The exported `Config` is
// a real Schemastery schema (not a plain object), so DSH validates and
// defaults it before `apply` runs.
// ============================================================================

import z from "@deepseek-ai/schemastery";

/** DSH-facing decision. Internal `require_approval` maps from `ask`. */
export type ConfigDecision = "allow" | "ask" | "deny";

function decisionSchema(defaultValue: ConfigDecision) {
  return z.union([z.const("allow"), z.const("ask"), z.const("deny")]).default(defaultValue);
}

function positiveInt(defaultValue: number) {
  return z.natural().min(1).default(defaultValue);
}

export const PROVENANCE_DEFAULTS = {
  enabled: true,
  maxEntries: 256,
  maxEntryBytes: 256 * 1024,
  maxTotalBytes: 2 * 1024 * 1024,
  minMatchLength: 4,
};

export const TOOLCHAIN_DEFAULTS = {
  enabled: true,
  maxEvents: 128,
  chainWindow: 12,
};

export const POLICY_DEFAULTS = {
  sensitiveExternalAction: "deny" as ConfigDecision,
  untrustedPrivateAccess: "ask" as ConfigDecision,
  untrustedCodeExecution: "deny" as ConfigDecision,
  unknownTool: "ask" as ConfigDecision,
  internalDomains: [] as string[],
};

export const PROOF_DEFAULTS = {
  enabled: true,
  maxRecords: 1_000,
};

export const Config = z.object({
  /** observe records + warns without changing execution; enforce applies the decision. */
  mode: z.union([z.const("observe"), z.const("enforce")]).default("enforce"),

  provenance: z.object({
    enabled: z.boolean().default(PROVENANCE_DEFAULTS.enabled),
    maxEntries: positiveInt(PROVENANCE_DEFAULTS.maxEntries),
    maxEntryBytes: positiveInt(PROVENANCE_DEFAULTS.maxEntryBytes),
    maxTotalBytes: positiveInt(PROVENANCE_DEFAULTS.maxTotalBytes),
    minMatchLength: positiveInt(PROVENANCE_DEFAULTS.minMatchLength),
  }).default(PROVENANCE_DEFAULTS),

  taint: z.object({
    enabled: z.boolean().default(true),
  }).default({ enabled: true }),

  toolchain: z.object({
    enabled: z.boolean().default(TOOLCHAIN_DEFAULTS.enabled),
    maxEvents: positiveInt(TOOLCHAIN_DEFAULTS.maxEvents),
    chainWindow: positiveInt(TOOLCHAIN_DEFAULTS.chainWindow),
  }).default(TOOLCHAIN_DEFAULTS),

  classification: z.object({
    overrides: z.dict(z.array(z.string())).default({}),
  }).default({ overrides: {} }),

  policy: z.object({
    sensitiveExternalAction: decisionSchema(POLICY_DEFAULTS.sensitiveExternalAction),
    untrustedPrivateAccess: decisionSchema(POLICY_DEFAULTS.untrustedPrivateAccess),
    untrustedCodeExecution: decisionSchema(POLICY_DEFAULTS.untrustedCodeExecution),
    unknownTool: decisionSchema(POLICY_DEFAULTS.unknownTool),
    internalDomains: z.array(z.string()).default([]),
  }).default(POLICY_DEFAULTS),

  proof: z.object({
    enabled: z.boolean().default(PROOF_DEFAULTS.enabled),
    maxRecords: positiveInt(PROOF_DEFAULTS.maxRecords),
  }).default(PROOF_DEFAULTS),
});

/** The validated, fully-defaulted config handed to `apply`. */
export interface RiskProofConfig {
  mode: "observe" | "enforce";
  provenance: typeof PROVENANCE_DEFAULTS;
  taint: { enabled: boolean };
  toolchain: typeof TOOLCHAIN_DEFAULTS;
  classification: { overrides: Record<string, string[]> };
  policy: {
    sensitiveExternalAction: ConfigDecision;
    untrustedPrivateAccess: ConfigDecision;
    untrustedCodeExecution: ConfigDecision;
    unknownTool: ConfigDecision;
    internalDomains: string[];
  };
  proof: typeof PROOF_DEFAULTS;
}
