// ============================================================================
// dsh-riskproof — taint inference (source inference + value detection)
// ============================================================================
// Taint is "what security attribute does this data carry". It is strictly
// distinct from provenance ("where did this data come from"). Taint is
// additive: ordinary tool output can never remove a label; trusted
// declassification is explicitly out of scope for v0.1.
//
// Deterministic only. No LLM, no network lookup.
// ============================================================================

import type { SecurityCapability, TaintLabel } from "./types.js";
import { SENSITIVE_TAINTS } from "./types.js";

/** Context entry kind (how a tool result was classified for tracking). */
export type ContextKind =
  | "untrusted_web"
  | "untrusted_email"
  | "tool_output"
  | "pii"
  | "customer_data"
  | "secret"
  | "source_code"
  | "financial_data"
  | "patient_data"
  | "internal_data";

/** Taint labels carried by each context kind. */
export const TAINT_BY_KIND: Record<ContextKind, TaintLabel[]> = {
  untrusted_web: ["UNTRUSTED_WEB"],
  untrusted_email: ["UNTRUSTED_EMAIL"],
  tool_output: [],
  pii: ["PII"],
  customer_data: ["CUSTOMER_DATA"],
  secret: ["SECRET"],
  source_code: ["SOURCE_CODE"],
  financial_data: ["FINANCIAL_DATA"],
  patient_data: ["PATIENT_DATA"],
  internal_data: ["INTERNAL_DATA"],
};

/**
 * Infer a context kind from tool name + capabilities. Used by the result
 * observer to tag a successful result before provenance/taint tracking.
 */
export function inferKindFromTool(
  toolName: string,
  capabilities: readonly SecurityCapability[],
): ContextKind {
  const name = toolName.toLowerCase().replace(/[_-]+/g, " ");
  const has = (capability: SecurityCapability): boolean =>
    capabilities.includes(capability);

  if (has("CREDENTIAL_ACCESS") || /\b(credential|secret|vault|password|api[_-]?key|token)\b/.test(name)) {
    return "secret";
  }
  if (/\b(web|browser|search|crawl|scrape|fetch|url|webpage|rss|feed|news)\b/.test(name) && has("EXTERNAL_INGESTION")) {
    return "untrusted_web";
  }
  if (/\b(email|mail|inbox|message)\b/.test(name) && has("EXTERNAL_INGESTION")) {
    return "untrusted_email";
  }
  if (/\b(patient|medical|clinical|health|diagnosis|prescription)\b/.test(name)) return "patient_data";
  if (/\b(finance|financial|invoice|payment|bank|accounting)\b/.test(name)) return "financial_data";
  if (/\b(customer|client|crm|salesforce)\b/.test(name)) return "customer_data";
  if (/\b(repo|source|github|gitlab|source code)\b/.test(name)) return "source_code";
  if (/\b(internal|document|knowledge|wiki|confidential)\b/.test(name)) return "internal_data";
  if (/\b(pii|personal|profile|identity)\b/.test(name)) return "pii";
  return "tool_output";
}

// ── Source-id inference ──────────────────────────────────────────────────────

const SOURCE_KEYWORD_TAINTS: Array<{ keywords: string[]; label: TaintLabel }> = [
  { keywords: ["webpage", "browser_result", "web_result", "untrusted_web", "web_fetch", "web_search"], label: "UNTRUSTED_WEB" },
  { keywords: ["email", "mailbox", "inbox_message", "untrusted_email"], label: "UNTRUSTED_EMAIL" },
  { keywords: ["tool_schema", "mcp_schema", "untrusted_tool"], label: "UNTRUSTED_TOOL" },
  { keywords: ["customer_data", "customer_record", "crm_record", "client_record"], label: "CUSTOMER_DATA" },
  { keywords: ["pii_record", "personal_data", "pii"], label: "PII" },
  { keywords: ["secret_store", "credential", "vault_secret", "secret"], label: "SECRET" },
  { keywords: ["api_key"], label: "API_KEY" },
  { keywords: ["source_code", "repository_file", "source"], label: "SOURCE_CODE" },
  { keywords: ["financial_data", "financial_record", "bank_record", "financial"], label: "FINANCIAL_DATA" },
  { keywords: ["patient_data", "patient_record", "medical_record", "clinical_record", "patient"], label: "PATIENT_DATA" },
  { keywords: ["internal_doc", "internal_document", "knowledge_base", "company_wiki", "internal"], label: "INTERNAL_DATA" },
];

export function inferTaintsFromSource(sourceId: string): TaintLabel[] {
  const result: TaintLabel[] = [];
  const lower = sourceId.toLowerCase();
  for (const { keywords, label } of SOURCE_KEYWORD_TAINTS) {
    if (keywords.some((keyword) => lower.includes(keyword))) result.push(label);
  }
  return result;
}

// ── Value-based detection ────────────────────────────────────────────────────

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
  {
    label: "CUSTOMER_DATA",
    patterns: [/\bcustomer\b/i, /\bclient\b/i, /客户/, /\bCUST[_-]?\d+\b/i, /\bclient[_-]?\d+\b/i],
  },
  {
    label: "PII",
    patterns: [
      /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/,
      /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
      /\b\d{3}-\d{2}-\d{4}\b/,
      /\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b/,
    ],
  },
  {
    label: "INTERNAL_DATA",
    patterns: [
      /\b(?:company|internal)\s+(?:confidential|use only)\b/i,
      /\bconfidential\s*[-:]\s*internal\b/i,
      /内部(?:资料|文档|机密)|仅限内部/,
    ],
  },
  {
    label: "SOURCE_CODE",
    patterns: [
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
      /\b(?:function|class|interface)\s+[A-Za-z_$][\w$]*\s*(?:\(|\{|extends\b)/,
      /\b(?:import|export)\s+(?:[\w*{]|default\b).+\bfrom\s+["'][^"']+["']/,
      /\b(?:def|class)\s+[A-Za-z_]\w*\s*(?:\(|:)/,
    ],
  },
  {
    label: "FINANCIAL_DATA",
    patterns: [
      /\b(?:bank\s+account|routing\s+number|iban|swift\/bic|credit\s+card)\b/i,
      /\b(?:invoice|revenue|balance)\s*(?:id|number|amount)?\s*[#:=]\s*[^\s,;]+/i,
      /银行账(?:号|户)|财务数据|发票(?:号|金额)/,
    ],
  },
  {
    label: "PATIENT_DATA",
    patterns: [
      /\b(?:patient|medical\s+record|diagnosis|prescription)\s*(?:id|number|name)?\s*[#:=]\s*[^\s,;]+/i,
      /\b(?:hipaa|protected health information|clinical trial subject)\b/i,
      /患者(?:编号|姓名|病历)|诊断结果|处方信息/,
    ],
  },
];

/** Detect value-based taints (secrets, PII, financial data, ...). */
export function detectValueTaints(value: unknown): TaintLabel[] {
  const searchable = valueToSearchText(value);
  if (!searchable) return [];
  const result: TaintLabel[] = [];
  for (const { label, patterns } of SENSITIVE_PATTERNS) {
    if (patterns.some((pattern) => pattern.test(searchable))) result.push(label);
  }
  return result;
}

/** Whether a taint is a sensitive-data label (exfiltration-protected). */
export function isSensitiveTaint(taint: TaintLabel): boolean {
  return (SENSITIVE_TAINTS as readonly string[]).includes(taint);
}

/**
 * Additively enrich per-argument taints: start from matched provenance taints,
 * add source-id inference, then value-based detection. Taint only ever grows.
 */
export function enrichArgumentTaints(
  args: Record<string, unknown>,
  provenance: Record<string, string[]>,
  baseTaints: Record<string, TaintLabel[]>,
): Record<string, TaintLabel[]> {
  const result: Record<string, TaintLabel[]> = {};
  for (const name of Object.keys(args)) {
    const taints = new Set<TaintLabel>(baseTaints[name] ?? []);
    for (const source of provenance[name] ?? []) {
      for (const taint of inferTaintsFromSource(source)) taints.add(taint);
    }
    for (const taint of detectValueTaints(args[name])) taints.add(taint);
    result[name] = [...taints];
  }
  return result;
}

/** Turn an arbitrary value into a bounded search text for pattern matching. */
export function valueToSearchText(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return serializeArgumentValue(value);
}

function serializeArgumentValue(value: unknown): string {
  try {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      throw new TypeError("argument value cannot be serialized as JSON");
    }
    return serialized;
  } catch {
    throw new TypeError("argument value cannot be serialized deterministically");
  }
}
