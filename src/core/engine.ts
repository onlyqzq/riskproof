// ============================================================================
// dsh-riskproof — deterministic risk engine
// ============================================================================
// Pure, deterministic policy evaluation over a ToolSecurityContext. No IO, no
// LLM, no DSH imports. The DSH adapter translates tool executions into the
// context, and translates the returned decision back into allow/ask/deny.
//
// Rule evaluation is priority-ordered (hard invariants first) and aggregated
// with a strictest-decision / highest-risk monotonic fold, so additional
// findings can only ever tighten the outcome.
// ============================================================================

import type {
  Decision,
  MatchedRule,
  RiskLevel,
  SecurityCapability,
  SecurityDecision,
  TaintLabel,
  ToolSecurityContext,
} from "./types.js";
import {
  higherRisk,
  SENSITIVE_TAINTS,
  stricterDecision,
  UNTRUSTED_TAINTS,
} from "./types.js";
import { extractHosts, findExternalDestinations, isCloudMetadataOrLinkLocalHost } from "./destination.js";

export interface EnginePolicy {
  sensitiveExternalAction: Decision;
  untrustedPrivateAccess: Decision;
  untrustedCodeExecution: Decision;
  unknownTool: Decision;
  internalDomains: string[];
}

export const DEFAULT_POLICY: EnginePolicy = Object.freeze({
  sensitiveExternalAction: "deny",
  untrustedPrivateAccess: "require_approval",
  untrustedCodeExecution: "deny",
  unknownTool: "require_approval",
  internalDomains: [],
});

const SENSITIVE_TAINTS_SET = new Set<string>(SENSITIVE_TAINTS);
const UNTRUSTED_TAINTS_SET = new Set<string>(UNTRUSTED_TAINTS);

/** Recognized sink fields (email recipient / URL target) excluded from the
 *  sensitive-argument scan so a recipient address is not mistaken for data. */
const SINK_FIELD_ALIASES = new Set([
  "to", "cc", "bcc", "mailto", "recipient", "recipients", "recipientlist",
  "email", "emails", "address", "addresses", "target", "targets",
  "recipientemail", "recipientemails", "recipientaddress", "recipientaddresses",
  "emailaddress", "emailaddresses", "targetemail", "targetemails",
  "targetaddress", "targetaddresses", "toemail", "toemails", "toaddress", "toaddresses",
  "url", "uri", "endpoint", "targeturl", "targeturi", "targetendpoint",
  "webhook", "webhookurl", "webhookuri", "requesturl", "requesturi",
  "destination", "destinationurl", "destinationuri", "callbackurl", "callbackuri",
  "baseurl", "apiendpoint", "host", "hostname", "origin", "channel", "topic",
]);

interface ArgumentView {
  value: unknown;
  source: string[];
  taints: TaintLabel[];
}

interface RuleResult {
  id: string;
  decision: Decision;
  riskLevel: RiskLevel;
  triggeredArgs: string[];
  evidence: string[];
  reason: string;
}

interface ExtendedToolSecurityContext extends ToolSecurityContext {
  policy: EnginePolicy;
}

type Rule = (ctx: ExtendedToolSecurityContext, view: Record<string, ArgumentView>) => RuleResult | null;

function normalizeFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function buildView(ctx: ToolSecurityContext): Record<string, ArgumentView> {
  const view: Record<string, ArgumentView> = {};
  for (const name of Object.keys(ctx.args)) {
    view[name] = {
      value: ctx.args[name],
      source: ctx.provenance[name] ?? [],
      taints: ctx.taints[name] ?? [],
    };
  }
  return view;
}

function hasCapability(ctx: ToolSecurityContext, capability: SecurityCapability): boolean {
  return ctx.tool.capabilities.includes(capability);
}

function isSensitive(taint: TaintLabel): boolean {
  return SENSITIVE_TAINTS_SET.has(taint);
}

function isUntrusted(taint: TaintLabel): boolean {
  return UNTRUSTED_TAINTS_SET.has(taint);
}

function sensitiveArgs(view: Record<string, ArgumentView>): string[] {
  return Object.entries(view)
    .filter(([name, argument]) =>
      !SINK_FIELD_ALIASES.has(normalizeFieldName(name)) &&
      argument.taints.some(isSensitive))
    .map(([name]) => name);
}

function untrustedArgs(view: Record<string, ArgumentView>): string[] {
  return Object.entries(view)
    .filter(([, argument]) => argument.taints.some(isUntrusted))
    .map(([name]) => name);
}

function credentialArgs(view: Record<string, ArgumentView>): string[] {
  return Object.entries(view)
    .filter(([, argument]) => argument.taints.includes("SECRET") || argument.taints.includes("API_KEY"))
    .map(([name]) => name);
}

// ── Rules ─────────────────────────────────────────────────────────────────────

/** Hard invariant: cloud metadata and link-local hosts are never reachable. */
const ruleCloudMetadataLinkLocal: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const restricted: string[] = [];
  for (const [name, argument] of Object.entries(view)) {
    if (!SINK_FIELD_ALIASES.has(normalizeFieldName(name))) continue;
    for (const host of extractHosts(argument.value)) {
      if (isCloudMetadataOrLinkLocalHost(host)) {
        restricted.push(name);
        break;
      }
    }
  }
  if (restricted.length === 0) return null;
  return {
    id: "cloud_metadata_link_local",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: restricted,
    evidence: restricted.map((field) => `arg '${field}' targets a cloud metadata or link-local address`),
    reason: "external action targets a cloud metadata or link-local address, which can leak instance credentials",
  };
};

/** Credentials flowing to an external action. */
const ruleCredentialExternalAction: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const args = credentialArgs(view);
  if (args.length === 0) return null;
  return {
    id: "credential_external_action",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: args,
    evidence: args.map((field) => `arg '${field}' carries SECRET/API_KEY`),
    reason: "credential material is being sent to an external action",
  };
};

/** Sensitive data flowing to a confirmed external destination. */
const ruleSensitiveExternalAction: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const destinations = findExternalDestinations(ctx.args, ctx.internalDomains);
  if (destinations.length === 0) return null;
  const sensitive = sensitiveArgs(view);
  if (sensitive.length === 0) return null;
  const targets = [...new Set(destinations.map((d) => d.target))];
  return {
    id: "sensitive_data_external_action",
    decision: ctx.policy.sensitiveExternalAction,
    riskLevel: "critical",
    triggeredArgs: [...new Set([...sensitive, ...destinations.map((d) => d.field)])],
    evidence: [
      ...sensitive.map((field) => `arg '${field}' carries sensitive data`),
      `external destination(s): ${targets.join(", ")}`,
    ],
    reason: `sensitive data is being sent to an external destination (${targets.join(", ")})`,
  };
};

/** Untrusted content influencing code execution. */
const ruleUntrustedCodeExecution: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "CODE_EXECUTION")) return null;
  const args = untrustedArgs(view);
  if (args.length === 0) return null;
  return {
    id: "untrusted_code_execution",
    decision: ctx.policy.untrustedCodeExecution,
    riskLevel: "critical",
    triggeredArgs: args,
    evidence: args.map((field) => `arg '${field}' carries untrusted content`),
    reason: "code execution is influenced by untrusted content (possible indirect prompt injection)",
  };
};

/** Full EIT → PAT → NAT chain with sensitive data actually in the outbound args. */
const rulePrivateDataExfiltrationChain: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const state = ctx.toolchain;
  if (!state.sawIngestion || !state.sawPrivateAccess) return null;
  const sensitive = sensitiveArgs(view);
  if (sensitive.length === 0) return null;
  return {
    id: "private_data_exfiltration_chain",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: sensitive,
    evidence: [
      `observed capability path: ${state.path.join(" -> ")} -> external_action`,
      `outbound argument(s) carry private evidence: ${sensitive.join(", ")}`,
    ],
    reason: "external ingestion, private access, and outbound sensitive data form a complete exfiltration chain",
  };
};

/** EIT → PAT → NAT chain without confirmed sensitive data in the outbound args. */
const ruleSuspiciousDisclosureChain: Rule = (ctx) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const state = ctx.toolchain;
  if (!state.sawIngestion || !state.sawPrivateAccess) return null;
  return {
    id: "suspicious_disclosure_chain",
    decision: "require_approval",
    riskLevel: "high",
    triggeredArgs: [],
    evidence: [`observed capability path: ${state.path.join(" -> ")} -> external_action`],
    reason: "external action follows external ingestion and private access, forming a potential exfiltration chain",
  };
};

/** Private access immediately after untrusted ingestion. */
const ruleUntrustedPrivateAccess: Rule = (ctx) => {
  if (!hasCapability(ctx, "PRIVATE_ACCESS")) return null;
  if (!ctx.toolchain.sawIngestion) return null;
  return {
    id: "untrusted_private_access",
    decision: ctx.policy.untrustedPrivateAccess,
    riskLevel: "high",
    triggeredArgs: [],
    evidence: [`observed capability transition: external_ingestion -> private_access`],
    reason: "private data access follows untrusted external ingestion",
  };
};

/** Fail-closed posture for tools the classifier could not place. */
const ruleUnknownTool: Rule = (ctx) => {
  if (ctx.tool.capabilities.length > 0) return null;
  return {
    id: "unknown_tool",
    decision: ctx.policy.unknownTool,
    riskLevel: "medium",
    triggeredArgs: [],
    evidence: [`tool '${ctx.tool.name}' has no classified security capability`],
    reason: `tool '${ctx.tool.name}' could not be classified into a security capability`,
  };
};

const RULES: readonly Rule[] = [
  ruleCloudMetadataLinkLocal,
  ruleCredentialExternalAction,
  ruleSensitiveExternalAction,
  ruleUntrustedCodeExecution,
  rulePrivateDataExfiltrationChain,
  ruleSuspiciousDisclosureChain,
  ruleUntrustedPrivateAccess,
  ruleUnknownTool,
];

// ── Evaluation ────────────────────────────────────────────────────────────────

export function evaluate(
  context: ToolSecurityContext,
  policy: EnginePolicy = DEFAULT_POLICY,
  referenceTime?: string,
): SecurityDecision {
  const view = buildView(context);
  const ctx: ExtendedToolSecurityContext = { ...context, policy };
  const results: RuleResult[] = [];

  for (const rule of RULES) {
    const result = rule(ctx, view);
    if (result) results.push(result);
  }

  let decision: Decision = "allow";
  let riskLevel: RiskLevel = "low";
  for (const result of results) {
    decision = stricterDecision(decision, result.decision);
    riskLevel = higherRisk(riskLevel, result.riskLevel);
  }

  const matchedRules: MatchedRule[] = results.map((result) => ({
    id: result.id,
    triggeredArgs: [...result.triggeredArgs],
    evidence: [...result.evidence],
    reason: result.reason,
  }));

  const evidence = matchedRules.flatMap((rule) => rule.evidence);
  const reasons = matchedRules.map((rule) => rule.reason).filter(Boolean);
  const reason = reasons.length > 0
    ? reasons.join("; ")
    : "no security policy matched; execution allowed";

  return {
    decision,
    riskLevel,
    matchedRules,
    reason,
    evidence,
    provenance: copyStringMap(context.provenance),
    taints: copyTaintMap(context.taints),
    toolchain: { ...context.toolchain, path: [...context.toolchain.path] },
    timestamp: referenceTime ?? new Date().toISOString(),
  };
}

function copyStringMap(map: Record<string, string[]>): Record<string, string[]> {
  return Object.fromEntries(Object.entries(map).map(([key, value]) => [key, [...value]]));
}

function copyTaintMap(map: Record<string, TaintLabel[]>): Record<string, TaintLabel[]> {
  return Object.fromEntries(Object.entries(map).map(([key, value]) => [key, [...value]]));
}

/** Re-exported for the adapter and tests. */
export { SENSITIVE_TAINTS, UNTRUSTED_TAINTS };
