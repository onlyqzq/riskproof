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
import {
  extractHosts,
  findDestinations,
  isCloudMetadataOrLinkLocalHost,
  isExternalDomain,
  matchesDomainPattern,
  type NetworkDestination,
} from "./destination.js";
import { argumentLeaves } from "./arguments.js";
import { analyzeCommandRisks, type CommandRiskFinding } from "./command-risk.js";
import { findSensitivePaths, type SensitivePathFinding } from "./path-policy.js";

export interface EnginePolicy {
  sensitiveExternalAction: Decision;
  untrustedPrivateAccess: Decision;
  untrustedCodeExecution: Decision;
  untrustedLocalMutation: Decision;
  credentialAccessAfterUntrusted: Decision;
  sensitivePathRead: Decision;
  sensitivePathMutation: Decision;
  destructiveOperation: Decision;
  remoteScriptExecution: Decision;
  unlistedExternalAction: Decision;
  unknownTool: Decision;
  internalDomains: string[];
  blockedDomains: string[];
  allowedExternalDomains: string[];
  sensitivePathPatterns: string[];
}

export const DEFAULT_POLICY: EnginePolicy = Object.freeze({
  sensitiveExternalAction: "deny",
  untrustedPrivateAccess: "require_approval",
  untrustedCodeExecution: "deny",
  untrustedLocalMutation: "require_approval",
  credentialAccessAfterUntrusted: "deny",
  sensitivePathRead: "require_approval",
  sensitivePathMutation: "deny",
  destructiveOperation: "require_approval",
  remoteScriptExecution: "deny",
  unlistedExternalAction: "require_approval",
  unknownTool: "require_approval",
  internalDomains: [],
  blockedDomains: [],
  allowedExternalDomains: [],
  sensitivePathPatterns: [],
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
  field: string;
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
  remediation?: string;
}

interface ExtendedToolSecurityContext extends ToolSecurityContext {
  policy: EnginePolicy;
  analysis: {
    commandRisks: CommandRiskFinding[];
    sensitivePaths: SensitivePathFinding[];
    destinations: NetworkDestination[];
    externalDestinations: NetworkDestination[];
  };
}

type Rule = (ctx: ExtendedToolSecurityContext, view: Record<string, ArgumentView>) => RuleResult | null;

function normalizeFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function buildView(ctx: ToolSecurityContext): Record<string, ArgumentView> {
  const view: Record<string, ArgumentView> = Object.create(null) as Record<string, ArgumentView>;
  for (const leaf of argumentLeaves(ctx.args)) {
    view[leaf.path] = {
      field: leaf.field,
      value: leaf.value,
      source: Object.hasOwn(ctx.provenance, leaf.path) ? ctx.provenance[leaf.path] : [],
      taints: Object.hasOwn(ctx.taints, leaf.path) ? ctx.taints[leaf.path] : [],
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

function sawOrderedIngestionThenPrivateAccess(ctx: ToolSecurityContext): boolean {
  const explicit = ctx.toolchain.sawIngestionThenPrivateAccess;
  if (typeof explicit === "boolean") return explicit;
  const ingestion = ctx.toolchain.path.indexOf("external_ingestion");
  const privateAccess = ctx.toolchain.path.indexOf("private_access");
  return ingestion >= 0 && privateAccess > ingestion;
}

function sensitiveArgs(view: Record<string, ArgumentView>): string[] {
  return Object.entries(view)
    .filter(([, argument]) =>
      !SINK_FIELD_ALIASES.has(normalizeFieldName(argument.field)) &&
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
    if (!SINK_FIELD_ALIASES.has(normalizeFieldName(argument.field))) continue;
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
    remediation: "Use an approved service endpoint instead of a metadata or link-local address.",
  };
};

/** Operator denylist: applies even when no sensitive data is present. */
const ruleBlockedDestination: Rule = (ctx) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION") || ctx.policy.blockedDomains.length === 0) return null;
  const blocked = ctx.analysis.destinations.filter((destination) =>
    ctx.policy.blockedDomains.some((pattern) => matchesDomainPattern(destination.target, pattern)));
  if (blocked.length === 0) return null;
  const targets = [...new Set(blocked.map((destination) => destination.target))];
  return {
    id: "blocked_destination",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: [...new Set(blocked.map((destination) => destination.field))],
    evidence: [`destination matches policy.blockedDomains: ${targets.join(", ")}`],
    reason: `external action targets an operator-blocked destination (${targets.join(", ")})`,
    remediation: "Choose an approved destination or review the blockedDomains entry outside the agent session.",
  };
};

/** Optional egress allowlist: only active when at least one domain is listed. */
const ruleUnlistedExternalDestination: Rule = (ctx) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION") || ctx.policy.allowedExternalDomains.length === 0) return null;
  const unlisted = ctx.analysis.externalDestinations.filter((destination) =>
    !ctx.policy.allowedExternalDomains.some((pattern) => matchesDomainPattern(destination.target, pattern)));
  if (unlisted.length === 0) return null;
  const targets = [...new Set(unlisted.map((destination) => destination.target))];
  return {
    id: "unlisted_external_destination",
    decision: ctx.policy.unlistedExternalAction,
    riskLevel: "high",
    triggeredArgs: [...new Set(unlisted.map((destination) => destination.field))],
    evidence: [`external destination is not allowlisted: ${targets.join(", ")}`],
    reason: `external action targets a destination outside policy.allowedExternalDomains (${targets.join(", ")})`,
    remediation: "Use an allowlisted destination or have an operator add the domain after verification.",
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
    remediation: "Remove the credential value and pass a vault reference or server-side credential binding instead.",
  };
};

/** Network-capable shell commands carrying credentials are outbound sinks too. */
const ruleCredentialNetworkCommand: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "CODE_EXECUTION")) return null;
  const network = ctx.analysis.commandRisks.filter((finding) => finding.kind === "network_egress");
  const credentials = credentialArgs(view);
  if (network.length === 0 || credentials.length === 0) return null;
  const fields = [...new Set([...network.map((finding) => finding.field), ...credentials])];
  return {
    id: "credential_network_command",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: fields,
    evidence: [
      ...network.map((finding) => `arg '${finding.field}' contains a network-capable command`),
      ...credentials.map((field) => `arg '${field}' carries SECRET/API_KEY`),
    ],
    reason: "a network-capable command is carrying credential material",
    remediation: "Remove inline credentials and use an approved credential helper with a constrained destination.",
  };
};

/** Sensitive data flowing to a confirmed external destination. */
const ruleSensitiveExternalAction: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const destinations = ctx.analysis.externalDestinations;
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
    remediation: "Remove or redact sensitive fields, or route the action to a configured internal domain.",
  };
};

/** Catastrophic operations are hard invariants and cannot be relaxed. */
const ruleCatastrophicOperation: Rule = (ctx) => {
  if (!hasCapability(ctx, "CODE_EXECUTION")) return null;
  const findings = ctx.analysis.commandRisks.filter((finding) => finding.kind === "catastrophic_operation");
  if (findings.length === 0) return null;
  return {
    id: "catastrophic_system_operation",
    decision: "deny",
    riskLevel: "critical",
    triggeredArgs: [...new Set(findings.map((finding) => finding.field))],
    evidence: findings.map((finding) => `arg '${finding.field}' matches ${finding.category}`),
    reason: "command contains a high-confidence irreversible system operation",
    remediation: "Replace the operation with a narrowly scoped, recoverable command and verify its explicit target.",
  };
};

/** Download-and-execute pipelines bypass review of the executed artifact. */
const ruleRemoteScriptExecution: Rule = (ctx) => {
  if (!hasCapability(ctx, "CODE_EXECUTION")) return null;
  const findings = ctx.analysis.commandRisks.filter((finding) => finding.kind === "remote_script_execution");
  if (findings.length === 0) return null;
  return {
    id: "remote_script_execution",
    decision: ctx.policy.remoteScriptExecution,
    riskLevel: "critical",
    triggeredArgs: [...new Set(findings.map((finding) => finding.field))],
    evidence: findings.map((finding) => `arg '${finding.field}' contains a ${finding.category}`),
    reason: "remote content is piped directly into an interpreter without review",
    remediation: "Download to a file, verify its source and contents, then execute the reviewed artifact separately.",
  };
};

/** Recoverable but destructive commands use the configured approval posture. */
const ruleDestructiveOperation: Rule = (ctx) => {
  if (!hasCapability(ctx, "CODE_EXECUTION")) return null;
  const findings = ctx.analysis.commandRisks.filter((finding) => finding.kind === "destructive_operation");
  if (findings.length === 0) return null;
  return {
    id: "destructive_operation",
    decision: ctx.policy.destructiveOperation,
    riskLevel: "high",
    triggeredArgs: [...new Set(findings.map((finding) => finding.field))],
    evidence: findings.map((finding) => `arg '${finding.field}' matches ${finding.category}`),
    reason: "command can irreversibly modify local or remote state",
    remediation: "Create a checkpoint or backup and replace forced or recursive flags with the narrowest viable operation.",
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
    remediation: "Remove untrusted-derived command text and reconstruct the command from trusted constants.",
  };
};

/** Untrusted content influencing a local write can persist an attack. */
const ruleUntrustedLocalMutation: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "LOCAL_MUTATION")) return null;
  const args = untrustedArgs(view);
  if (args.length === 0) return null;
  return {
    id: "untrusted_local_mutation",
    decision: ctx.policy.untrustedLocalMutation,
    riskLevel: "high",
    triggeredArgs: args,
    evidence: args.map((field) => `arg '${field}' carries untrusted content into a local mutation`),
    reason: "untrusted content is being persisted to local state",
    remediation: "Review and sanitize the untrusted-derived fields before writing them.",
  };
};

/** Credential reads after external ingestion are a common prompt-injection step. */
const ruleCredentialAccessAfterUntrusted: Rule = (ctx) => {
  if (!hasCapability(ctx, "CREDENTIAL_ACCESS") || !ctx.toolchain.sawIngestion) return null;
  return {
    id: "credential_access_after_untrusted",
    decision: ctx.policy.credentialAccessAfterUntrusted,
    riskLevel: "critical",
    triggeredArgs: [],
    evidence: ["observed capability transition: external_ingestion -> credential_access"],
    reason: "credential access follows untrusted external ingestion",
    remediation: "Start a clean task without untrusted context or obtain the credential through a non-model server-side binding.",
  };
};

/** Sensitive path reads/writes are gated before file content reaches the model. */
const ruleSensitivePathAccess: Rule = (ctx) => {
  const reads = hasCapability(ctx, "PRIVATE_ACCESS") || hasCapability(ctx, "CREDENTIAL_ACCESS");
  const mutates = hasCapability(ctx, "LOCAL_MUTATION");
  if (!reads && !mutates) return null;
  const findings = ctx.analysis.sensitivePaths;
  if (findings.length === 0) return null;
  return {
    id: mutates ? "sensitive_path_mutation" : "sensitive_path_read",
    decision: mutates ? ctx.policy.sensitivePathMutation : ctx.policy.sensitivePathRead,
    riskLevel: mutates ? "critical" : "high",
    triggeredArgs: [...new Set(findings.map((finding) => finding.field))],
    evidence: findings.map((finding) => `arg '${finding.field}' references ${finding.category}`),
    reason: mutates
      ? "a local mutation targets a path likely to contain credential material"
      : "a private read targets a path likely to contain credential material",
    remediation: mutates
      ? "Write a template or non-secret configuration file instead of modifying the credential-bearing path."
      : "Use a metadata-only inspection or a credential helper that does not expose the raw value to the model.",
  };
};

/** Full EIT → PAT → NAT chain with sensitive data actually in the outbound args. */
const rulePrivateDataExfiltrationChain: Rule = (ctx, view) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const state = ctx.toolchain;
  if (!sawOrderedIngestionThenPrivateAccess(ctx)) return null;
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
    remediation: "Remove the private-derived fields and restart from a trusted context before any external action.",
  };
};

/** EIT → PAT → NAT chain without confirmed sensitive data in the outbound args. */
const ruleSuspiciousDisclosureChain: Rule = (ctx) => {
  if (!hasCapability(ctx, "EXTERNAL_ACTION")) return null;
  const state = ctx.toolchain;
  if (!sawOrderedIngestionThenPrivateAccess(ctx)) return null;
  return {
    id: "suspicious_disclosure_chain",
    decision: "require_approval",
    riskLevel: "high",
    triggeredArgs: [],
    evidence: [`observed capability path: ${state.path.join(" -> ")} -> external_action`],
    reason: "external action follows external ingestion and private access, forming a potential exfiltration chain",
    remediation: "Review the outbound payload and destination, or restart the action in a clean trusted task.",
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
    remediation: "Confirm the access is user-requested or perform it in a clean task without untrusted context.",
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
    remediation: "Add an explicit classification.overrides entry for this tool after reviewing its behavior.",
  };
};

const RULES: readonly Rule[] = [
  ruleCloudMetadataLinkLocal,
  ruleBlockedDestination,
  ruleCatastrophicOperation,
  ruleCredentialExternalAction,
  ruleCredentialNetworkCommand,
  ruleCredentialAccessAfterUntrusted,
  ruleSensitiveExternalAction,
  ruleSensitivePathAccess,
  ruleRemoteScriptExecution,
  ruleUntrustedCodeExecution,
  ruleUntrustedLocalMutation,
  ruleDestructiveOperation,
  rulePrivateDataExfiltrationChain,
  ruleSuspiciousDisclosureChain,
  ruleUntrustedPrivateAccess,
  ruleUnlistedExternalDestination,
  ruleUnknownTool,
];

// ── Evaluation ────────────────────────────────────────────────────────────────

export function evaluate(
  context: ToolSecurityContext,
  policy: EnginePolicy = DEFAULT_POLICY,
  referenceTime?: string,
): SecurityDecision {
  const view = buildView(context);
  const hasCodeExecution = context.tool.capabilities.includes("CODE_EXECUTION");
  const hasPathAccess = context.tool.capabilities.some((capability) =>
    capability === "PRIVATE_ACCESS" || capability === "CREDENTIAL_ACCESS" || capability === "LOCAL_MUTATION");
  const hasExternalAction = context.tool.capabilities.includes("EXTERNAL_ACTION");
  const destinations = hasExternalAction ? findDestinations(context.args) : [];
  const ctx: ExtendedToolSecurityContext = {
    ...context,
    policy,
    analysis: {
      commandRisks: hasCodeExecution ? analyzeCommandRisks(context.args) : [],
      sensitivePaths: hasPathAccess ? findSensitivePaths(context.args, policy.sensitivePathPatterns) : [],
      destinations,
      externalDestinations: destinations.filter((destination) =>
        isExternalDomain(destination.target, context.internalDomains ?? policy.internalDomains)),
    },
  };
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
    remediation: result.remediation,
  }));

  const evidence = matchedRules.flatMap((rule) => rule.evidence);
  const reasons = matchedRules.map((rule) => rule.reason).filter(Boolean);
  const remediations = [...new Set(matchedRules
    .map((rule) => rule.remediation)
    .filter((value): value is string => typeof value === "string" && value.length > 0))];
  const reason = reasons.length > 0
    ? reasons.join("; ")
    : "no security policy matched; execution allowed";

  return {
    decision,
    riskLevel,
    matchedRules,
    reason,
    evidence,
    remediations,
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
