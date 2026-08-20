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
export type PolicyPreset = "permissive" | "balanced" | "strict";

function decisionSchema() {
  return z.union([z.const("allow"), z.const("ask"), z.const("deny")]);
}

function positiveInt(defaultValue: number) {
  return z.natural().min(1).default(defaultValue);
}

function boundedPositiveInt(defaultValue: number, maximum: number) {
  return positiveInt(defaultValue).max(maximum);
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

export const POLICY_PRESETS = Object.freeze({
  permissive: {
    sensitiveExternalAction: "ask",
    untrustedPrivateAccess: "allow",
    untrustedCodeExecution: "ask",
    untrustedLocalMutation: "allow",
    credentialAccessAfterUntrusted: "ask",
    sensitivePathRead: "ask",
    sensitivePathMutation: "ask",
    destructiveOperation: "ask",
    remoteScriptExecution: "ask",
    unlistedExternalAction: "ask",
    unknownTool: "allow",
  },
  balanced: {
    sensitiveExternalAction: "deny",
    untrustedPrivateAccess: "ask",
    untrustedCodeExecution: "deny",
    untrustedLocalMutation: "ask",
    credentialAccessAfterUntrusted: "deny",
    sensitivePathRead: "ask",
    sensitivePathMutation: "deny",
    destructiveOperation: "ask",
    remoteScriptExecution: "deny",
    unlistedExternalAction: "ask",
    unknownTool: "ask",
  },
  strict: {
    sensitiveExternalAction: "deny",
    untrustedPrivateAccess: "deny",
    untrustedCodeExecution: "deny",
    untrustedLocalMutation: "deny",
    credentialAccessAfterUntrusted: "deny",
    sensitivePathRead: "deny",
    sensitivePathMutation: "deny",
    destructiveOperation: "deny",
    remoteScriptExecution: "deny",
    unlistedExternalAction: "deny",
    unknownTool: "deny",
  },
} satisfies Record<PolicyPreset, Record<string, ConfigDecision>>);

export const POLICY_DEFAULTS = {
  preset: "balanced" as PolicyPreset,
  ...POLICY_PRESETS.balanced,
  internalDomains: [] as string[],
  blockedDomains: [] as string[],
  allowedExternalDomains: [] as string[],
  sensitivePathPatterns: [] as string[],
};

export const PROOF_DEFAULTS = {
  enabled: true,
  maxRecords: 1_000,
};

export const CONFIG_LIMITS = Object.freeze({
  maxEntries: 4_096,
  maxEntryBytes: 4 * 1024 * 1024,
  maxTotalBytes: 64 * 1024 * 1024,
  minMatchLength: 4_096,
  maxEvents: 4_096,
  chainWindow: 4_096,
  maxProofRecords: 10_000,
  maxPolicyListEntries: 256,
  maxPolicyEntryLength: 512,
});

export interface RiskProofPolicy extends Record<string, unknown> {
  preset: PolicyPreset;
  sensitiveExternalAction: ConfigDecision;
  untrustedPrivateAccess: ConfigDecision;
  untrustedCodeExecution: ConfigDecision;
  untrustedLocalMutation: ConfigDecision;
  credentialAccessAfterUntrusted: ConfigDecision;
  sensitivePathRead: ConfigDecision;
  sensitivePathMutation: ConfigDecision;
  destructiveOperation: ConfigDecision;
  remoteScriptExecution: ConfigDecision;
  unlistedExternalAction: ConfigDecision;
  unknownTool: ConfigDecision;
  internalDomains: string[];
  blockedDomains: string[];
  allowedExternalDomains: string[];
  sensitivePathPatterns: string[];
}

export interface RiskProofConfig {
  mode: "observe" | "enforce";
  provenance: typeof PROVENANCE_DEFAULTS;
  taint: { enabled: boolean };
  toolchain: typeof TOOLCHAIN_DEFAULTS;
  classification: { overrides: Record<string, string[]> };
  policy: RiskProofPolicy;
  proof: typeof PROOF_DEFAULTS & { file?: string };
}

const optionalProofFile = z.transform(
  z.string(),
  (value): string | undefined => value,
  true,
);

const policyPresetSchema = z.union([
  z.const("permissive"),
  z.const("balanced"),
  z.const("strict"),
]).default("balanced");

const policyList = z.array(z.string())
  .max(CONFIG_LIMITS.maxPolicyListEntries)
  .default([]);

const BaseConfig = z.object({
  /** observe records + warns without changing execution; enforce applies the decision. */
  mode: z.union([z.const("observe"), z.const("enforce")]).default("enforce"),

  provenance: z.object({
    enabled: z.boolean().default(PROVENANCE_DEFAULTS.enabled),
    maxEntries: boundedPositiveInt(PROVENANCE_DEFAULTS.maxEntries, CONFIG_LIMITS.maxEntries),
    maxEntryBytes: boundedPositiveInt(PROVENANCE_DEFAULTS.maxEntryBytes, CONFIG_LIMITS.maxEntryBytes),
    maxTotalBytes: boundedPositiveInt(PROVENANCE_DEFAULTS.maxTotalBytes, CONFIG_LIMITS.maxTotalBytes),
    minMatchLength: boundedPositiveInt(PROVENANCE_DEFAULTS.minMatchLength, CONFIG_LIMITS.minMatchLength),
  }).default(PROVENANCE_DEFAULTS),

  taint: z.object({
    enabled: z.boolean().default(true),
  }).default({ enabled: true }),

  toolchain: z.object({
    enabled: z.boolean().default(TOOLCHAIN_DEFAULTS.enabled),
    maxEvents: boundedPositiveInt(TOOLCHAIN_DEFAULTS.maxEvents, CONFIG_LIMITS.maxEvents),
    chainWindow: boundedPositiveInt(TOOLCHAIN_DEFAULTS.chainWindow, CONFIG_LIMITS.chainWindow),
  }).default(TOOLCHAIN_DEFAULTS),

  classification: z.object({
    overrides: z.dict(z.array(z.string())).default({}),
  }).default({ overrides: {} }),

  policy: z.object({
    preset: policyPresetSchema,
    sensitiveExternalAction: decisionSchema(),
    untrustedPrivateAccess: decisionSchema(),
    untrustedCodeExecution: decisionSchema(),
    untrustedLocalMutation: decisionSchema(),
    credentialAccessAfterUntrusted: decisionSchema(),
    sensitivePathRead: decisionSchema(),
    sensitivePathMutation: decisionSchema(),
    destructiveOperation: decisionSchema(),
    remoteScriptExecution: decisionSchema(),
    unlistedExternalAction: decisionSchema(),
    unknownTool: decisionSchema(),
    internalDomains: policyList,
    blockedDomains: policyList,
    allowedExternalDomains: policyList,
    sensitivePathPatterns: policyList,
  }).default({ preset: "balanced" } as never),

  proof: z.object({
    enabled: z.boolean().default(PROOF_DEFAULTS.enabled),
    maxRecords: boundedPositiveInt(PROOF_DEFAULTS.maxRecords, CONFIG_LIMITS.maxProofRecords),
    file: optionalProofFile,
  }).default({ ...PROOF_DEFAULTS, file: undefined }),
});

/** The validated, fully-defaulted config handed to `apply`. */
export const Config = z.transform(BaseConfig, (value) => {
  const config = value as unknown as RiskProofConfig;
  const rawPolicy = value.policy as unknown as Partial<RiskProofPolicy> & { preset: PolicyPreset };
  const preset = POLICY_PRESETS[rawPolicy.preset];
  config.policy = {
    preset: rawPolicy.preset,
    ...preset,
    ...decisionOverrides(rawPolicy),
    internalDomains: normalizePolicyList(rawPolicy.internalDomains, "policy.internalDomains", "domain"),
    blockedDomains: normalizePolicyList(rawPolicy.blockedDomains, "policy.blockedDomains", "domain"),
    allowedExternalDomains: normalizePolicyList(rawPolicy.allowedExternalDomains, "policy.allowedExternalDomains", "domain"),
    sensitivePathPatterns: normalizePolicyList(rawPolicy.sensitivePathPatterns, "policy.sensitivePathPatterns", "path"),
  };
  if (config.provenance.maxEntryBytes > config.provenance.maxTotalBytes) {
    throw new TypeError("provenance.maxEntryBytes must not exceed provenance.maxTotalBytes");
  }
  if (config.toolchain.chainWindow > config.toolchain.maxEvents) {
    throw new TypeError("toolchain.chainWindow must not exceed toolchain.maxEvents");
  }
  if (config.proof.file !== undefined && typeof config.proof.file !== "string") {
    throw new TypeError("proof.file must be a string when configured");
  }
  if (config.proof.file !== undefined && config.proof.file.trim().length === 0) {
    throw new TypeError("proof.file must be a non-empty path when configured");
  }
  return config;
}, true);

const DECISION_FIELDS = [
  "sensitiveExternalAction",
  "untrustedPrivateAccess",
  "untrustedCodeExecution",
  "untrustedLocalMutation",
  "credentialAccessAfterUntrusted",
  "sensitivePathRead",
  "sensitivePathMutation",
  "destructiveOperation",
  "remoteScriptExecution",
  "unlistedExternalAction",
  "unknownTool",
] as const;

function decisionOverrides(policy: Partial<RiskProofPolicy>): Partial<RiskProofPolicy> {
  const overrides: Partial<RiskProofPolicy> = {};
  for (const field of DECISION_FIELDS) {
    const value = policy[field];
    if (value !== undefined) Object.assign(overrides, { [field]: value });
  }
  return overrides;
}

function normalizePolicyList(
  values: readonly string[] | undefined,
  label: string,
  kind: "domain" | "path",
): string[] {
  const result: string[] = [];
  for (const raw of values ?? []) {
    const value = raw.trim();
    if (value.length === 0 || value.length > CONFIG_LIMITS.maxPolicyEntryLength) {
      throw new TypeError(`${label} entries must contain 1-${CONFIG_LIMITS.maxPolicyEntryLength} characters`);
    }
    if (/[\u0000-\u001f\u007f]/.test(value)) {
      throw new TypeError(`${label} entries must not contain control characters`);
    }
    if (kind === "domain") {
      const domain = value.toLowerCase().replace(/\.+$/, "");
      if (/[:/]\//.test(domain) || domain.includes("/") || domain.includes("@") ||
          (!/^(?:\*\.)?[a-z0-9._:-]+$/i.test(domain)) || domain.includes("*", 2)) {
        throw new TypeError(`${label} entries must be domains, IP literals, or leading '*.' wildcards`);
      }
      if (!result.includes(domain)) result.push(domain);
    } else if (!result.includes(value)) {
      result.push(value);
    }
  }
  return result;
}
