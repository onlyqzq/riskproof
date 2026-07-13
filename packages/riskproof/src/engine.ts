// ============================================================================
// RiskProof — Policy Engine (v3 merged)
// ============================================================================
// Single entry point: evaluate(input) → output
// Merges: provenance collection + taint analysis + 17 policy rules + adapter
//
// Policy decisions are deterministic. Proof time/IDs include trusted clock and
// random uniqueness metadata. No IO. No LLM.
// ============================================================================

import { randomUUID } from "node:crypto";
import { RE2JS } from "re2js";
import { validateConfig } from "./config.js";
import { InputValidationError, parseEngineInput } from "./validation.js";
import type {
  ToolName, TaintLabel, Decision, RiskLevel,
  EngineInput, EngineOutput, EngineOptions,
  ArgumentEvidence, MatchedPolicy, AuditProof,
  Capability, SafetyInvariant, TraceContext,
} from "./types.js";
import type { RiskProofConfig, CustomRule } from "./config.js";

// ═══════════════════════════════════════════════════════════════════════════════
// Part 1: Provenance Collection (was provenance.ts)
// ═══════════════════════════════════════════════════════════════════════════════

function buildArguments(
  args: Record<string, unknown>,
  provenance?: Record<string, string[]>,
  taints?: Record<string, TaintLabel[]>,
): Record<string, ArgumentEvidence> {
  const result: Record<string, ArgumentEvidence> = {};
  for (const key of Object.keys(args)) {
    result[key] = {
      value: args[key],
      source: provenance?.[key] ? [...provenance[key]] : [],
      taints: taints?.[key] ? [...taints[key]] : [],
    };
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part 2: Taint Analysis (was taint.ts)
// ═══════════════════════════════════════════════════════════════════════════════

const SOURCE_KIND_TO_TAINT: Record<string, TaintLabel> = {
  webpage: "UNTRUSTED_WEB",
  email: "UNTRUSTED_EMAIL",
  tool_schema: "UNTRUSTED_TOOL_SCHEMA",
};

function inferTaintsFromSource(sourceId: string): TaintLabel[] {
  const result: TaintLabel[] = [];
  for (const [keyword, label] of Object.entries(SOURCE_KIND_TO_TAINT)) {
    if (sourceId.toLowerCase().includes(keyword)) {
      result.push(label);
    }
  }
  return result;
}

// Value-based sensitive data detection patterns
const SENSITIVE_PATTERNS: Array<{ label: TaintLabel; patterns: RegExp[] }> = [
  { label: "API_KEY", patterns: [/sk-[a-zA-Z0-9_-]{20,}/i, /Bearer\s+[a-zA-Z0-9._\-]{20,}/i] },
  {
    label: "SECRET",
    patterns: [
      /\bapi[_-]?key["']?\s*[=:]\s*["']?[^\s"',}\]]+/i,
      /\bsecret["']?\s*[=:]\s*["']?[^\s"',}\]]+/i,
      /\btoken["']?\s*[=:]\s*["']?[^\s"',}\]]+/i,
      /\bpassword["']?\s*[=:]\s*["']?[^\s"',}\]]+/i,
    ],
  },
  { label: "CUSTOMER_DATA", patterns: [/\bcustomer\b/i, /\bclient\b/i, /客户/] },
  { label: "PII", patterns: [/\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/, /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/] },
];

function detectValueTaints(value: unknown): TaintLabel[] {
  const searchable = valueToSearchText(value);
  if (!searchable) return [];
  const result: TaintLabel[] = [];
  for (const { label, patterns } of SENSITIVE_PATTERNS) {
    if (patterns.some((p) => p.test(searchable))) result.push(label);
  }
  return result;
}

function valueToSearchText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  // parseEngineInput already applies a deterministic 2 MiB character / 10k
  // node budget. Scanning only the first 1 MiB here would let a secret placed
  // near the end of an otherwise valid nested object evade taint detection.
  return serializeArgumentValue(value);
}

function serializeArgumentValue(value: unknown): string {
  try {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      throw new InputValidationError("args contain a value that cannot be serialized as JSON");
    }
    return serialized;
  } catch (error) {
    if (error instanceof InputValidationError) throw error;
    throw new InputValidationError("args contain a value that cannot be serialized deterministically");
  }
}

function enrichTaints(
  args: Record<string, ArgumentEvidence>,
  inputTaints?: Record<string, TaintLabel[]>,
): Record<string, ArgumentEvidence> {
  const result: Record<string, ArgumentEvidence> = {};
  for (const key of Object.keys(args)) {
    const arg = args[key];
    const allTaints = new Set<TaintLabel>(inputTaints?.[key] ?? arg.taints);

    // Source-based inference
    for (const src of arg.source) {
      for (const t of inferTaintsFromSource(src)) allTaints.add(t);
    }

    // Value-based detection
    for (const t of detectValueTaints(arg.value)) allTaints.add(t);

    result[key] = { ...arg, taints: [...allTaints] };
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part 3: Policy Rules (16 deterministic rules)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Helpers ────────────────────────────────────────────────────────────────────

function hasTaint(arg: ArgumentEvidence | undefined, taint: TaintLabel): boolean {
  return arg?.taints?.includes(taint) ?? false;
}

function hasAnyTaint(arg: ArgumentEvidence | undefined, taints: TaintLabel[]): boolean {
  return taints.some((t) => hasTaint(arg, t));
}

function getTaints(arg: ArgumentEvidence | undefined): TaintLabel[] {
  return arg?.taints ?? [];
}

const UNTRUSTED_TAINTS: TaintLabel[] = ["UNTRUSTED_WEB", "UNTRUSTED_EMAIL", "UNTRUSTED_TOOL_SCHEMA"];

function extractEmailDomains(value: unknown): string[] {
  const text = valueToSearchText(value);
  if (!text) return [];
  const domains = new Set<string>();
  const email = /@[\s]*([a-zA-Z0-9.-]+|\[[0-9a-fA-F:.]+\])/g;
  for (const match of text.matchAll(email)) {
    const domain = match[1].replace(/^\[|\]$/g, "").replace(/\.+$/, "").toLowerCase();
    if (domain.includes(".") || domain === "localhost") domains.add(domain);
  }
  return [...domains];
}

function extractUrlHosts(value: unknown): string[] {
  const text = valueToSearchText(value);
  if (!text) return [];
  const hosts = new Set<string>();
  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  for (const raw of urls) {
    try { hosts.add(new URL(raw.replace(/[),.;}\]]+$/, "")).hostname.toLowerCase()); }
    catch { /* invalid URL: ignored here and left to the caller's schema validation */ }
  }
  return [...hosts];
}

function isExternalDomain(host: string, internalDomains?: string[]): boolean {
  const lower = host.toLowerCase().trim();
  if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(lower)) return false;
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(lower)) return false;
  if (!internalDomains) return true;
  return !internalDomains.some((d) => {
    const dl = d.toLowerCase();
    return lower === dl || lower.endsWith("." + dl) || (dl.startsWith("*.") && (lower.endsWith(dl.slice(1)) || lower === dl.slice(2)));
  });
}

function hasUntrustedProvenance(arg: ArgumentEvidence | undefined): string[] {
  const sources = new Set(arg?.source ?? []);
  const untrusted = ["webpage", "email", "tool_output", "mcp_schema", "untrusted"];
  return [...sources].filter((s) => untrusted.some((k) => s.toLowerCase().includes(k)));
}

// ── Dangerous Shell Patterns ───────────────────────────────────────────────────

const DANGEROUS_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bcurl\b[^|\n]*\|\s*(?:\/\S*\/)?(?:ba|da|z)?sh\b/i, label: "curl … | shell" },
  { re: /\bwget\b[^|\n]*\|\s*(?:\/\S*\/)?(?:ba|da|z)?sh\b/i, label: "wget … | shell" },
  { re: /\brm\s+(?:(?:-[^\s]*[rR][^\s]*[fF][^\s]*)|(?:-[^\s]*[fF][^\s]*[rR][^\s]*)|(?:--recursive\s+--force)|(?:--force\s+--recursive))\b/i, label: "recursive forced rm" },
  { re: /\bchmod\s+777\b/i, label: "chmod 777" },
  { re: /\beval\s+\S/i, label: "eval" },
  { re: />\s*\/dev\/(?:tcp|udp|sd[a-z]\d*|vd[a-z]\d*|xvd[a-z]\d*|nvme\d+n\d+|mem|kmem)\b/i, label: "redirect to a device or network socket" },
  { re: /\bmkfifo\b/i, label: "mkfifo" },
  { re: /\bnc\s+-[lL]/i, label: "netcat listen mode" },
];

// ── Rule Definitions ───────────────────────────────────────────────────────────

interface RuleContext {
  tool: ToolName;
  args: Record<string, ArgumentEvidence>;
  options: EngineOptions;
  provenance?: Record<string, string[]>;
  capability?: Capability;
  invariants?: SafetyInvariant[];
}

type RuleFn = (ctx: RuleContext) => MatchedPolicy | null;

const EMAIL_RECIPIENT_FIELDS = ["to", "cc", "bcc"] as const;
const SENSITIVE_DATA_TAINTS: TaintLabel[] = [
  "CUSTOMER_DATA",
  "PII",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
];

function externalEmailDestinations(ctx: RuleContext): Array<{ field: string; domain: string }> {
  const destinations: Array<{ field: string; domain: string }> = [];
  for (const field of EMAIL_RECIPIENT_FIELDS) {
    for (const domain of extractEmailDomains(ctx.args[field]?.value)) {
      if (isExternalDomain(domain, ctx.options.internalDomains)) destinations.push({ field, domain });
    }
  }
  return destinations;
}

// R1: Sensitive business/personal data → external email
const ruleCustomerDataExternal: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  const destinations = externalEmailDestinations(ctx);
  if (destinations.length === 0) return null;

  const sensitiveArgs: string[] = [];
  const evidence: string[] = [];
  for (const [key, arg] of Object.entries(ctx.args)) {
    if ((EMAIL_RECIPIENT_FIELDS as readonly string[]).includes(key)) continue;
    const hits = getTaints(arg).filter((taint) => SENSITIVE_DATA_TAINTS.includes(taint));
    if (hits.length > 0) {
      sensitiveArgs.push(key);
      evidence.push(`arg '${key}' has sensitive taints: ${hits.join(", ")}`);
    }
  }
  if (sensitiveArgs.length === 0) return null;

  const externalDomains = [...new Set(destinations.map(({ domain }) => domain))];
  evidence.push(`recipient has external domain(s): ${externalDomains.join(", ")}`);
  return {
    id: "customer_data_external_send",
    triggeredArgs: [...sensitiveArgs, ...new Set(destinations.map(({ field }) => field))],
    evidence,
    reason: `邮件参数包含敏感业务/个人数据且收件人为外部地址 (${externalDomains.join(", ")})，存在数据外泄风险`,
  };
};

// R2: Secret/API Key → external email
const ruleSecretExternalEmail: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  const destinations = externalEmailDestinations(ctx);
  if (destinations.length === 0) return null;
  const externalDomains = [...new Set(destinations.map(({ domain }) => domain))];

  for (const key of Object.keys(ctx.args)) {
    const arg = ctx.args[key];
    if (hasAnyTaint(arg, ["SECRET", "API_KEY"])) {
      return {
        id: "secret_external_send",
        triggeredArgs: [key],
        evidence: [`arg '${key}' has SECRET/API_KEY`, `external recipient domain(s): ${externalDomains.join(", ")}`],
        reason: `参数包含密钥/凭证且收件人为外部地址 (${externalDomains.join(", ")})，存在凭据泄露风险`,
      };
    }
  }
  return null;
};

// R3: Secret/API Key → external HTTP
const ruleSecretExternalHttp: RuleFn = (ctx) => {
  if (ctx.tool !== "http_request") return null;
  const externalHosts = extractUrlHosts(ctx.args["url"]?.value)
    .filter((host) => isExternalDomain(host, ctx.options.internalDomains));
  if (externalHosts.length === 0) return null;

  for (const key of Object.keys(ctx.args)) {
    const arg = ctx.args[key];
    if (hasAnyTaint(arg, ["SECRET", "API_KEY"])) {
      return {
        id: "secret_external_http",
        triggeredArgs: [key],
        evidence: [`arg '${key}' has SECRET/API_KEY`, `external URL host(s): ${externalHosts.join(", ")}`],
        reason: `参数包含密钥/凭证且目标为外部地址 (${externalHosts.join(", ")})，存在凭据泄露风险`,
      };
    }
  }
  return null;
};

// Sensitive business/personal data → external HTTP
const ruleSensitiveExternalHttp: RuleFn = (ctx) => {
  if (ctx.tool !== "http_request") return null;
  const externalHosts = extractUrlHosts(ctx.args["url"]?.value)
    .filter((host) => isExternalDomain(host, ctx.options.internalDomains));
  if (externalHosts.length === 0) return null;

  const triggeredArgs: string[] = [];
  const evidence: string[] = [];
  for (const [key, arg] of Object.entries(ctx.args)) {
    if (key === "url") continue;
    const hits = getTaints(arg).filter((taint) => SENSITIVE_DATA_TAINTS.includes(taint));
    if (hits.length > 0) {
      triggeredArgs.push(key);
      evidence.push(`arg '${key}' has sensitive taints: ${hits.join(", ")}`);
    }
  }
  if (triggeredArgs.length === 0) return null;

  const hosts = [...new Set(externalHosts)];
  evidence.push(`external URL host(s): ${hosts.join(", ")}`);
  return {
    id: "sensitive_data_external_http",
    triggeredArgs: [...triggeredArgs, "url"],
    evidence,
    reason: `敏感业务/个人数据将发送到外部 HTTP 地址 (${hosts.join(", ")})，存在数据外泄风险`,
  };
};

// R4: Untrusted source → shell command
const ruleUntrustedShell: RuleFn = (ctx) => {
  if (ctx.tool !== "shell_exec") return null;
  const cmd = ctx.args["command"];
  if (!cmd) return null;
  const untrustedTaints = getTaints(cmd).filter((t) => UNTRUSTED_TAINTS.includes(t));
  const untrustedProv = hasUntrustedProvenance(cmd);
  if (untrustedTaints.length === 0 && untrustedProv.length === 0) return null;

  const evidence: string[] = [];
  if (untrustedTaints.length > 0) evidence.push(`arg 'command' has untrusted taints: ${untrustedTaints.join(", ")}`);
  if (untrustedProv.length > 0) evidence.push(`arg 'command' has untrusted provenance: ${untrustedProv.join(", ")}`);

  return {
    id: "untrusted_influenced_shell",
    triggeredArgs: ["command"],
    evidence,
    reason: "Shell 命令受不可信来源影响，存在间接注入或恶意指令风险",
  };
};

// R5: Dangerous shell pattern
const ruleDangerousShell: RuleFn = (ctx) => {
  if (ctx.tool !== "shell_exec") return null;
  for (const argName of Object.keys(ctx.args)) {
    const val = typeof ctx.args[argName]?.value === "string" ? ctx.args[argName].value as string : "";
    for (const { re, label } of DANGEROUS_PATTERNS) {
      if (re.test(val)) {
        return {
          id: "dangerous_shell_pattern",
          triggeredArgs: [argName],
          evidence: [`arg '${argName}' matches dangerous pattern: ${label}`],
          reason: `参数包含危险模式 (${label})，可能导致系统破坏或恶意代码执行`,
        };
      }
    }
  }
  return null;
};

// R6: Untrusted provenance → email recipient
const ruleUntrustedEmailTo: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  const triggeredArgs: string[] = [];
  const untrustedSources = new Set<string>();
  const externalDomains = new Set<string>();
  for (const field of EMAIL_RECIPIENT_FIELDS) {
    const untrusted = hasUntrustedProvenance(ctx.args[field]);
    const external = extractEmailDomains(ctx.args[field]?.value)
      .filter((domain) => isExternalDomain(domain, ctx.options.internalDomains));
    if (untrusted.length > 0 && external.length > 0) {
      triggeredArgs.push(field);
      untrusted.forEach((source) => untrustedSources.add(source));
      external.forEach((domain) => externalDomains.add(domain));
    }
  }
  if (triggeredArgs.length === 0) return null;
  return {
    id: "untrusted_provenance_email_to",
    triggeredArgs,
    evidence: [
      `recipient argument has untrusted provenance: ${[...untrustedSources].join(", ")}`,
      `external domain(s): ${[...externalDomains].join(", ")}`,
    ],
    reason: `收件人地址来源于不可信来源 (${[...untrustedSources].join(", ")}) 且为外部域名，可能是间接 prompt injection`,
  };
};

// R7: Untrusted provenance → shell command
const ruleUntrustedProvShell: RuleFn = (ctx) => {
  if (ctx.tool !== "shell_exec") return null;
  const cmd = ctx.args["command"];
  const untrusted = hasUntrustedProvenance(cmd);
  if (untrusted.length === 0) return null;
  return {
    id: "untrusted_provenance_shell",
    triggeredArgs: ["command"],
    evidence: [`arg 'command' has untrusted provenance: ${untrusted.join(", ")}`],
    reason: `Shell 命令参数来源于不可信来源 (${untrusted.join(", ")})，存在代码执行风险`,
  };
};

// R8: High-risk tool without capability
const HIGH_RISK_TOOLS: Set<string> = new Set(["send_email", "http_request", "shell_exec"]);

const ruleNoCapability: RuleFn = (ctx) => {
  if (!HIGH_RISK_TOOLS.has(ctx.tool)) return null;
  if (ctx.capability) return null;
  return {
    id: "high_risk_tool_requires_capability",
    triggeredArgs: [],
    evidence: [`tool '${ctx.tool}' is high-risk but no capability provided`],
    reason: `高风险工具 ${ctx.tool} 缺少能力授权声明，需人工审批`,
  };
};

// R9: Capability tool mismatch
const ruleCapabilityMismatch: RuleFn = (ctx) => {
  if (!ctx.capability) return null;
  if (ctx.capability.tool === ctx.tool) return null;
  return {
    id: "capability_tool_mismatch",
    triggeredArgs: [],
    evidence: [`capability authorizes '${ctx.capability.tool}' but tool call is '${ctx.tool}'`],
    reason: `能力授权工具 (${ctx.capability.tool}) 与当前调用 (${ctx.tool}) 不匹配`,
  };
};

// R10: Capability expired
const ruleCapabilityExpired: RuleFn = (ctx) => {
  if (!ctx.capability?.expiresAt) return null;
  const ref = ctx.options.referenceTime ?? new Date().toISOString();
  if (new Date(ctx.capability.expiresAt).getTime() >= new Date(ref).getTime()) return null;
  return {
    id: "capability_expired",
    triggeredArgs: [],
    evidence: [`capability expired at ${ctx.capability.expiresAt} (ref: ${ref})`],
    reason: `能力授权已于 ${ctx.capability.expiresAt} 过期`,
  };
};

// R11: Forbidden taints in capability
const ruleForbiddenTaint: RuleFn = (ctx) => {
  if (!ctx.capability?.forbiddenTaints?.length) return null;
  const triggered: string[] = [];
  const evidence: string[] = [];
  for (const key of Object.keys(ctx.args)) {
    const hits = getTaints(ctx.args[key]).filter((t) => ctx.capability!.forbiddenTaints!.includes(t));
    if (hits.length > 0) {
      triggered.push(key);
      evidence.push(`arg '${key}' has forbidden taints: ${hits.join(", ")}`);
    }
  }
  if (triggered.length === 0) return null;
  return {
    id: "capability_forbidden_taint",
    triggeredArgs: triggered,
    evidence,
    reason: `参数包含 capability 禁止的污点标签: ${ctx.capability.forbiddenTaints.join(", ")}`,
  };
};

// R12: Recipient domain not in allowed list
const ruleRecipientDomain: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  if (!ctx.capability?.allowedRecipientDomains?.length) return null;
  const domainsByField = EMAIL_RECIPIENT_FIELDS.flatMap((field) =>
    extractEmailDomains(ctx.args[field]?.value).map((domain) => ({ field, domain })),
  );
  if (domainsByField.length === 0) {
    return {
      id: "capability_recipient_domain_not_allowed",
      triggeredArgs: ["to"],
      evidence: ["capability restricts recipient domains but no valid recipient domain was provided"],
      reason: "能力授权要求受限收件人域名，但调用未提供可验证的收件人地址",
    };
  }
  const allowed = ctx.capability.allowedRecipientDomains.map((d) => d.toLowerCase());
  const disallowed = domainsByField.filter(({ domain }) =>
    !allowed.some((d) => domain === d || domain.endsWith("." + d)),
  );
  if (disallowed.length === 0) return null;
  const disallowedDomains = [...new Set(disallowed.map(({ domain }) => domain))];
  return {
    id: "capability_recipient_domain_not_allowed",
    triggeredArgs: [...new Set(disallowed.map(({ field }) => field))],
    evidence: [`recipient domain(s) '${disallowedDomains.join(", ")}' not in allowed list: ${allowed.join(", ")}`],
    reason: `收件人域名 ${disallowedDomains.join(", ")} 不在授权范围内 (${allowed.join(", ")})`,
  };
};

// R13: Provenance not in allowlist
const ruleProvenanceNotAllowed: RuleFn = (ctx) => {
  if (!ctx.capability?.allowedProvenance?.length) return null;
  const triggered: string[] = [];
  const evidence: string[] = [];
  for (const key of Object.keys(ctx.args)) {
    const sources = new Set([...(ctx.args[key]?.source ?? []), ...(ctx.provenance?.[key] ?? [])]);
    const bad = sources.size === 0
      ? ["<missing>"]
      : [...sources].filter((s) => !ctx.capability!.allowedProvenance!.includes(s));
    if (bad.length > 0) {
      triggered.push(key);
      evidence.push(`arg '${key}' provenance not allowed: ${bad.join(", ")}`);
    }
  }
  if (triggered.length === 0) return null;
  return {
    id: "capability_provenance_not_allowed",
    triggeredArgs: triggered,
    evidence,
    reason: `参数来源不在 capability 允许的白名单中，需人工审批`,
  };
};

// R14: Safety invariant — forbidden tools
const ruleInvariantForbiddenTool: RuleFn = (ctx) => {
  if (!ctx.invariants?.length) return null;
  const hits = ctx.invariants.filter((inv) => inv.forbiddenTools?.includes(ctx.tool));
  if (hits.length === 0) return null;
  const names = hits.map((i) => i.name).join(", ");
  return {
    id: "invariant_forbidden_tool",
    triggeredArgs: [],
    evidence: [`tool '${ctx.tool}' is forbidden by invariants: ${names}`],
    reason: `工具 ${ctx.tool} 被安全不变式 (${names}) 禁止调用`,
  };
};

// R15: Safety invariant — protected taints modified
const MUTATIVE_SINKS = new Set(["file_write", "http_request", "send_email", "shell_exec"]);

const ruleInvariantProtectedTaint: RuleFn = (ctx) => {
  if (!MUTATIVE_SINKS.has(ctx.tool)) return null;
  if (!ctx.invariants?.length) return null;
  const allProtected = new Set<TaintLabel>();
  for (const inv of ctx.invariants) {
    inv.protectedTaints?.forEach((t) => allProtected.add(t));
  }
  if (allProtected.size === 0) return null;

  const triggered: string[] = [];
  const evidence: string[] = [];
  for (const key of Object.keys(ctx.args)) {
    const hits = getTaints(ctx.args[key]).filter((t) => allProtected.has(t));
    if (hits.length > 0) {
      triggered.push(key);
      evidence.push(`arg '${key}' has protected taints: ${hits.join(", ")}`);
    }
  }
  if (triggered.length === 0) return null;
  return {
    id: "invariant_protected_taint_modified",
    triggeredArgs: triggered,
    evidence,
    reason: `参数包含受安全不变式保护的污点标签 (${[...allProtected].join(", ")})，不可外发/写入/执行`,
  };
};

// R16: Safety invariant — numeric range
const ruleInvariantNumeric: RuleFn = (ctx) => {
  if (!ctx.invariants?.length) return null;
  const triggered: string[] = [];
  const evidence: string[] = [];
  for (const inv of ctx.invariants) {
    for (const [argName, maxVal] of Object.entries(inv.maxValues ?? {})) {
      const val = Number(ctx.args[argName]?.value);
      if (!isNaN(val) && val > maxVal) {
        triggered.push(argName);
        evidence.push(`arg '${argName}' value ${val} exceeds max ${maxVal} (invariant: ${inv.name})`);
      }
    }
    for (const [argName, minVal] of Object.entries(inv.minValues ?? {})) {
      const val = Number(ctx.args[argName]?.value);
      if (!isNaN(val) && val < minVal) {
        triggered.push(argName);
        evidence.push(`arg '${argName}' value ${val} below min ${minVal} (invariant: ${inv.name})`);
      }
    }
  }
  if (triggered.length === 0) return null;
  return {
    id: "invariant_numeric_range_violation",
    triggeredArgs: [...new Set(triggered)],
    evidence,
    reason: "参数数值违反安全不变式中定义的范围约束",
  };
};

// ── Rule Registry (priority-ordered) ───────────────────────────────────────────

const ALL_RULES: RuleFn[] = [
  // Invariants (always first — absolute constraints)
  ruleInvariantForbiddenTool,
  ruleInvariantProtectedTaint,
  ruleInvariantNumeric,
  // Capability rules
  ruleCapabilityMismatch,
  ruleCapabilityExpired,
  ruleForbiddenTaint,
  ruleRecipientDomain,
  // Deny rules
  ruleSecretExternalEmail,
  ruleSecretExternalHttp,
  ruleDangerousShell,
  // Require-approval rules
  ruleNoCapability,
  ruleProvenanceNotAllowed,
  ruleCustomerDataExternal,
  ruleSensitiveExternalHttp,
  ruleUntrustedShell,
  ruleUntrustedEmailTo,
  ruleUntrustedProvShell,
];

// ── Decision/Risk Mapping per Rule ──────────────────────────────────────────────

function ruleDecision(id: string, customRules?: CustomRule[]): Decision {
  const denyRules = [
    "invariant_forbidden_tool", "invariant_protected_taint_modified",
    "invariant_numeric_range_violation", "capability_tool_mismatch",
    "capability_expired", "capability_forbidden_taint",
    "capability_recipient_domain_not_allowed",
    "secret_external_send", "secret_external_http", "dangerous_shell_pattern",
  ];
  const reviewRules = [
    "high_risk_tool_requires_capability", "capability_provenance_not_allowed",
    "customer_data_external_send", "sensitive_data_external_http", "untrusted_influenced_shell",
    "untrusted_provenance_email_to", "untrusted_provenance_shell",
  ];
  if (denyRules.includes(id)) return "deny";
  if (reviewRules.includes(id)) return "require_approval";
  const customRule = customRules?.find((r) => r.enabled !== false && r.id === id);
  if (customRule) return customRule.decision;
  return "allow";
}

function ruleRisk(id: string, customRules?: CustomRule[]): RiskLevel {
  const critical = ["invariant_protected_taint_modified", "capability_tool_mismatch",
    "capability_forbidden_taint", "secret_external_send", "secret_external_http", "dangerous_shell_pattern"];
  if (critical.includes(id)) return "critical";
  const builtInHigh = [
    "invariant_forbidden_tool", "invariant_numeric_range_violation", "capability_expired",
    "capability_recipient_domain_not_allowed", "high_risk_tool_requires_capability",
    "capability_provenance_not_allowed", "customer_data_external_send",
    "sensitive_data_external_http", "untrusted_influenced_shell",
    "untrusted_provenance_email_to", "untrusted_provenance_shell",
  ];
  if (builtInHigh.includes(id)) return "high";
  const customRule = customRules?.find((r) => r.enabled !== false && r.id === id);
  if (customRule) return customRule.risk;
  return "high";
}

// ── Custom Rule Evaluation ──────────────────────────────────────────────────────

/**
 * Evaluate a user-defined custom rule against the engine context.
 * Returns a MatchedPolicy if the rule matches, or null.
 */
function evaluateCustomRule(rule: CustomRule, ctx: RuleContext): MatchedPolicy | null {
  // Tool filter: must match rule.tool or rule.tool === "*"
  if (rule.tool && rule.tool !== "*" && rule.tool !== ctx.tool) return null;

  const triggeredArgs: string[] = [];
  const evidence: string[] = [];
  let pattern: RE2JS | undefined;
  if (rule.pattern) {
    try {
      pattern = RE2JS.compile(rule.pattern);
    } catch (error) {
      throw new Error(
        `Validated custom rule '${rule.id}' failed RE2 compilation: ` +
        `${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  if (rule.field) {
    // Check a specific argument field
    const arg = ctx.args[rule.field];
    if (!arg) return null;
    const val = typeof arg.value === "string" ? arg.value : serializeArgumentValue(arg.value);
    if (pattern && !pattern.test(val)) {
      return null;
    }
    triggeredArgs.push(rule.field);
    evidence.push(`arg '${rule.field}' matches custom rule '${rule.id}'`);
  } else if (pattern) {
    // Check all argument values for the pattern
    for (const key of Object.keys(ctx.args)) {
      const arg = ctx.args[key];
      const val = typeof arg.value === "string" ? arg.value : serializeArgumentValue(arg.value);
      if (pattern.test(val)) {
        triggeredArgs.push(key);
        evidence.push(`arg '${key}' matches pattern of custom rule '${rule.id}'`);
      }
    }
    if (triggeredArgs.length === 0) return null;
  } else {
    // No field and no pattern — match always (tool-level rule)
    evidence.push(`tool '${ctx.tool}' matches custom rule '${rule.id}'`);
  }

  return {
    id: rule.id,
    triggeredArgs,
    evidence,
    reason: rule.consequence,
  };
}

// ── Proof Generation ───────────────────────────────────────────────────────────

function generateProof(
  tool: string, decision: Decision, riskLevel: RiskLevel,
  matched: MatchedPolicy[], timestamp: string, trace?: TraceContext,
): AuditProof {
  const evidence = matched.flatMap((p) => p.evidence);
  const reasons = matched.map((p) => p.reason).filter(Boolean) as string[];
  const reason = reasons.length > 0 ? reasons.join("; ") : "未命中任何安全策略，允许执行";

  const idParts: string[] = [];
  if (trace?.traceId) idParts.push(trace.traceId.slice(0, 8));
  if (trace?.stepId) idParts.push(trace.stepId);
  idParts.push(tool, decision);
  idParts.push(matched.length > 0 ? matched.map((p) => p.id).sort().join("+") : "no_match");
  idParts.push(timestamp.replace(/\D/g, ""));
  idParts.push(randomUUID().slice(0, 8));

  return {
    proofId: `rp_${idParts.join("_")}`,
    tool: tool as ToolName,
    traceId: trace?.traceId,
    stepId: trace?.stepId,
    decision,
    riskLevel,
    matchedRules: matched,
    evidence,
    reason,
    timestamp,
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part 4: Main Entry Point
// ═══════════════════════════════════════════════════════════════════════════════

const DECISION_ORDER: Record<Decision, number> = { deny: 3, require_approval: 2, allow: 1 };
const RISK_ORDER: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const DECISION_TO_ACTION: Record<Decision, EngineOutput["action"]> = {
  allow: "allow",
  require_approval: "ask_approval",
  deny: "block",
};

/**
 * Main entry point. Takes an EngineInput, runs the full pipeline, returns EngineOutput.
 * The policy decision is deterministic for the same input/config. Proof IDs
 * and default timestamps are intentionally unique per evaluation.
 *
 * @param input  The tool call to evaluate.
 * @param config Optional RiskProof config with custom rules, internal domains, and risk overrides.
 */
export function evaluate(rawInput: EngineInput, config?: RiskProofConfig): EngineOutput {
  // Protect JavaScript callers as well as typed TypeScript callers. JSON-facing
  // adapters also validate early so they can return protocol-specific errors.
  const input = parseEngineInput(rawInput);
  const activeConfig = config === undefined ? undefined : validateConfig(config);
  // Step 0: Merge internal domains from config into options
  const mergedOptions: EngineOptions = { ...input.options };
  if (activeConfig?.internalDomains?.length) {
    const existing = mergedOptions.internalDomains ?? [];
    mergedOptions.internalDomains = [...new Set([...existing, ...activeConfig.internalDomains])];
  }

  // Step 1: Build argument evidence from raw args
  const args = buildArguments(input.args, input.provenance, input.taints);

  // Step 2: Enrich taints (source inference + value detection)
  const enrichedArgs = enrichTaints(args, input.taints);

  // Step 3: Mark sink arguments
  const sinks: Record<ToolName, string[]> = {
    send_email: ["to", "cc", "bcc"],
    http_request: ["url"],
    shell_exec: ["command"],
  };
  for (const argName of sinks[input.tool]) {
    if (enrichedArgs[argName]) {
      enrichedArgs[argName] = { ...enrichedArgs[argName], isSink: true };
    }
  }

  // Step 4: Build rule context
  const ctx: RuleContext = {
    tool: input.tool,
    args: enrichedArgs,
    options: mergedOptions,
    provenance: input.provenance,
    capability: input.capability,
    invariants: input.invariants,
  };

  // Step 5: Run built-in rules
  const matchedPolicies: MatchedPolicy[] = [];
  for (const rule of ALL_RULES) {
    const result = rule(ctx);
    if (result) matchedPolicies.push(result);
  }

  // Step 6: Run custom rules from config
  if (activeConfig?.rules?.length) {
    const enabledRules = activeConfig.rules.filter((r) => r.enabled !== false);
    for (const cr of enabledRules) {
      const result = evaluateCustomRule(cr, ctx);
      if (result) matchedPolicies.push(result);
    }
  }

  const timestamp = input.options?.referenceTime ?? new Date().toISOString();

  // Step 7: No matches — apply default decision from config
  if (matchedPolicies.length === 0) {
    const defaultDecision: Decision = activeConfig?.options?.defaultDecision ?? "allow";
    const defaultRisk: RiskLevel = activeConfig?.toolRisk?.[input.tool] ?? "low";

    const noMatchPolicy: MatchedPolicy[] = defaultDecision === "deny"
      ? [{ id: "default_deny_config", triggeredArgs: [], evidence: ["Config defaultDecision is 'deny'"], reason: "配置默认策略为 deny，未命中任何允许规则" }]
      : [];

    const proof = generateProof(input.tool, defaultDecision, defaultRisk, noMatchPolicy, timestamp, input.trace);
    return {
      action: DECISION_TO_ACTION[defaultDecision],
      decision: defaultDecision,
      riskLevel: defaultRisk,
      matchedPolicies: noMatchPolicy,
      arguments: enrichedArgs,
      proof,
    };
  }

  // Step 8: Aggregate: strictest decision + highest risk
  let finalDecision: Decision = "allow";
  let finalRisk: RiskLevel = "low";
  for (const p of matchedPolicies) {
    const d = ruleDecision(p.id, activeConfig?.rules);
    const r = ruleRisk(p.id, activeConfig?.rules);
    if (DECISION_ORDER[d] > DECISION_ORDER[finalDecision]) finalDecision = d;
    if (RISK_ORDER[r] > RISK_ORDER[finalRisk]) finalRisk = r;
  }

  // Apply toolRisk as a floor for the risk level
  if (activeConfig?.toolRisk?.[input.tool]) {
    const toolRiskFloor = activeConfig.toolRisk[input.tool];
    if (RISK_ORDER[toolRiskFloor] > RISK_ORDER[finalRisk]) {
      finalRisk = toolRiskFloor;
    }
  }

  const proof = generateProof(input.tool, finalDecision, finalRisk, matchedPolicies, timestamp, input.trace);

  return {
    action: DECISION_TO_ACTION[finalDecision],
    decision: finalDecision,
    riskLevel: finalRisk,
    matchedPolicies,
    arguments: enrichedArgs,
    proof,
  };
}

// Re-export for convenience
export { hasTaint, hasAnyTaint, getTaints, hasUntrustedProvenance };
