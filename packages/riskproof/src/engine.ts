// ============================================================================
// RiskProof — Policy Engine (v3 merged)
// ============================================================================
// Single entry point: evaluate(input) → output
// Merges: provenance collection + taint analysis + 21 policy rules + adapter
//
// Policy decisions are deterministic. Proof time/IDs include trusted clock and
// random uniqueness metadata. No IO. No LLM.
// ============================================================================

import { randomUUID } from "node:crypto";
import { posix as posixPath } from "node:path";
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

const SOURCE_KIND_TO_TAINT: Array<{ keywords: string[]; label: TaintLabel }> = [
  { keywords: ["webpage", "browser_result", "web_result"], label: "UNTRUSTED_WEB" },
  { keywords: ["email", "mailbox", "inbox_message"], label: "UNTRUSTED_EMAIL" },
  { keywords: ["tool_schema", "mcp_schema"], label: "UNTRUSTED_TOOL_SCHEMA" },
  { keywords: ["internal_doc", "internal_document", "knowledge_base", "company_wiki"], label: "INTERNAL_DOC" },
  { keywords: ["customer_data", "customer_record", "crm_record", "client_record"], label: "CUSTOMER_DATA" },
  { keywords: ["pii_record", "personal_data"], label: "PII" },
  { keywords: ["secret_store", "credential", "vault_secret"], label: "SECRET" },
  { keywords: ["api_key"], label: "API_KEY" },
  { keywords: ["source_code", "repository_file"], label: "SOURCE_CODE" },
  { keywords: ["financial_data", "financial_record", "bank_record"], label: "FINANCIAL_DATA" },
  { keywords: ["patient_data", "patient_record", "medical_record", "clinical_record"], label: "PATIENT_DATA" },
];

function inferTaintsFromSource(sourceId: string): TaintLabel[] {
  const result: TaintLabel[] = [];
  for (const { keywords, label } of SOURCE_KIND_TO_TAINT) {
    if (keywords.some((keyword) => sourceId.toLowerCase().includes(keyword))) {
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
    label: "INTERNAL_DOC",
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

/**
 * Additively propagates provenance and taints across explicit transformation
 * edges. A bounded fixed-point handles chains and cycles without recursion.
 */
function propagateFlows(
  args: Record<string, ArgumentEvidence>,
  flows: EngineInput["flows"],
): Record<string, ArgumentEvidence> {
  if (!flows?.length) return args;
  const result = Object.fromEntries(
    Object.entries(args).map(([name, arg]) => [name, {
      ...arg,
      source: [...arg.source],
      taints: [...arg.taints],
    }]),
  );
  for (let pass = 0; pass < Object.keys(result).length; pass += 1) {
    let changed = false;
    for (const flow of flows) {
      const source = result[flow.from];
      const destination = result[flow.to];
      if (!source || !destination) continue;
      const sources = new Set(destination.source);
      if (source.source.some((item) => item !== "agent_generated")) sources.delete("agent_generated");
      const beforeSources = sources.size;
      source.source.forEach((item) => sources.add(item));
      const taints = new Set(destination.taints);
      const beforeTaints = taints.size;
      source.taints.forEach((item) => taints.add(item));
      if (sources.size !== beforeSources || taints.size !== beforeTaints) {
        result[flow.to] = { ...destination, source: [...sources], taints: [...taints] };
        changed = true;
      }
    }
    if (!changed) break;
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Part 3: Policy Rules (19 deterministic rules)
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

function normalizeArgumentFieldName(field: string): string {
  return field.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function matchingArgumentFields(
  args: Record<string, ArgumentEvidence>,
  aliases: ReadonlySet<string>,
): string[] {
  return Object.keys(args)
    .filter((field) => aliases.has(normalizeArgumentFieldName(field)))
    .sort();
}

function normalizeHost(host: string): string {
  return host.toLowerCase().trim().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
}

function extractUrlHosts(value: unknown): string[] {
  const text = valueToSearchText(value);
  if (!text) return [];
  const hosts = new Set<string>();
  const urls = text.match(/https?:\/\/[^\s"'<>]+/gi) ?? [];
  for (const raw of urls) {
    try { hosts.add(normalizeHost(new URL(raw.replace(/[),.;}\]]+$/, "")).hostname)); }
    catch { /* invalid URL: ignored here and left to the caller's schema validation */ }
  }
  return [...hosts];
}

/**
 * HTTP adapters do not agree on whether a target is a full URL, a URI, or a
 * bare host. Only values from recognized target fields reach this helper, so a
 * URL mentioned in a request body cannot be mistaken for the actual sink.
 */
function extractNetworkTargetHosts(value: unknown): string[] {
  const hosts = new Set(extractUrlHosts(value));
  const directValues = typeof value === "string"
    ? [value]
    : Array.isArray(value)
      ? value.filter((item): item is string => typeof item === "string")
      : [];

  for (const raw of directValues) {
    const candidate = raw.trim().replace(/^["']|["']$/g, "");
    if (!candidate || /\s/.test(candidate)) continue;
    try {
      const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)
        ? candidate
        : `http://${candidate}`);
      hosts.add(normalizeHost(parsed.hostname));
    } catch {
      // Invalid targets are left to the downstream tool's own schema checks.
    }
  }
  return [...hosts];
}

function isExternalDomain(host: string, internalDomains?: string[]): boolean {
  const lower = normalizeHost(host);
  if (["localhost", "127.0.0.1", "::1", "0.0.0.0"].includes(lower)) return false;
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(lower)) return false;
  if (!internalDomains) return true;
  return !internalDomains.some((d) => {
    const dl = d.toLowerCase();
    return lower === dl || lower.endsWith("." + dl) || (dl.startsWith("*.") && (lower.endsWith(dl.slice(1)) || lower === dl.slice(2)));
  });
}

function isCloudMetadataOrLinkLocalHost(host: string): boolean {
  const lower = normalizeHost(host).replace(/%25[^:]+$/i, "");
  const ipv4 = lower.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.every((octet) => octet <= 255)) {
      if (octets[0] === 169 && octets[1] === 254) return true;
      if ([
        "100.100.100.200", // Alibaba Cloud metadata
        "192.0.0.192", // Oracle Cloud metadata
        "168.63.129.16", // Azure platform virtual IP
      ].includes(lower)) return true;
    }
  }

  if (/^fe[89ab][0-9a-f]:/i.test(lower)) return true; // IPv6 fe80::/10 link-local
  if (lower === "fd00:ec2::254") return true; // AWS IMDS IPv6 endpoint
  if (lower.startsWith("::ffff:")) {
    return isCloudMetadataOrLinkLocalHost(lower.slice("::ffff:".length));
  }

  return [
    "metadata.google.internal",
    "metadata.goog",
    "instance-data.ec2.internal",
    "metadata.azure.internal",
  ].some((metadataHost) => lower === metadataHost || lower.endsWith(`.${metadataHost}`));
}

function hasUntrustedProvenance(arg: ArgumentEvidence | undefined): string[] {
  const sources = new Set(arg?.source ?? []);
  const untrusted = ["webpage", "email", "tool_output", "mcp_prompt", "mcp_schema", "resource", "untrusted"];
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

const DANGEROUS_DATABASE_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\b(?:drop|truncate)\s+(?:table|database|schema)\b/i, label: "destructive DDL" },
  { re: /\balter\s+(?:table|database|role|user)\b/i, label: "privileged ALTER" },
  { re: /\b(?:grant|revoke)\s+\S+/i, label: "permission change" },
  { re: /\bdelete\s+from\s+[^;]+(?:;|$)/i, label: "DELETE statement" },
  { re: /\bupdate\s+\S+\s+set\s+[^;]+(?:;|$)/i, label: "UPDATE statement" },
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

// MCP tools frequently expose semantically identical sinks under different
// schema field names. Match exact normalized aliases (rather than substrings)
// so aliases are covered without treating URLs/emails in ordinary body text as
// destinations.
const EMAIL_RECIPIENT_FIELD_ALIASES = new Set([
  "to", "cc", "bcc", "mailto",
  "recipient", "recipients", "recipientlist",
  "email", "emails", "address", "addresses", "target", "targets",
  "recipientemail", "recipientemails", "recipientaddress", "recipientaddresses",
  "emailaddress", "emailaddresses", "targetemail", "targetemails",
  "targetaddress", "targetaddresses", "toemail", "toemails", "toaddress", "toaddresses",
]);

const HTTP_TARGET_FIELD_ALIASES = new Set([
  "url", "uri", "endpoint", "targeturl", "targeturi", "targetendpoint",
  "webhook", "webhookurl", "webhookuri", "requesturl", "requesturi",
  "destination", "destinationurl", "destinationuri", "callbackurl", "callbackuri",
  "baseurl", "apiendpoint", "host", "hostname", "origin",
]);

const SHELL_COMMAND_FIELD_ALIASES = new Set([
  "command", "cmd", "script", "code", "shellcommand", "shellcmd", "commandline",
]);

const FILE_WRITE_PATH_FIELD_ALIASES = new Set([
  "path", "filepath", "filename", "file", "destination", "dest", "target",
  "outputpath", "outputfile",
]);

const SINK_FIELD_ALIASES: Record<ToolName, ReadonlySet<string>> = {
  send_email: EMAIL_RECIPIENT_FIELD_ALIASES,
  http_request: HTTP_TARGET_FIELD_ALIASES,
  shell_exec: SHELL_COMMAND_FIELD_ALIASES,
  file_read: new Set(["path"]),
  file_write: new Set([...FILE_WRITE_PATH_FIELD_ALIASES, "content"]),
  database_query: new Set(["query", "sql", "statement"]),
  browser_action: new Set(["url", "selector", "text"]),
};

const SENSITIVE_DATA_TAINTS: TaintLabel[] = [
  "CUSTOMER_DATA",
  "PII",
  "SOURCE_CODE",
  "FINANCIAL_DATA",
  "PATIENT_DATA",
];

function emailRecipientFields(ctx: RuleContext): string[] {
  return matchingArgumentFields(ctx.args, EMAIL_RECIPIENT_FIELD_ALIASES);
}

function httpTargetFields(ctx: RuleContext): string[] {
  return matchingArgumentFields(ctx.args, HTTP_TARGET_FIELD_ALIASES);
}

function shellCommandFields(ctx: RuleContext): string[] {
  return matchingArgumentFields(ctx.args, SHELL_COMMAND_FIELD_ALIASES);
}

function externalEmailDestinations(ctx: RuleContext): Array<{ field: string; domain: string }> {
  const destinations: Array<{ field: string; domain: string }> = [];
  for (const field of emailRecipientFields(ctx)) {
    for (const domain of extractEmailDomains(ctx.args[field]?.value)) {
      if (isExternalDomain(domain, ctx.options.internalDomains)) destinations.push({ field, domain });
    }
  }
  return destinations;
}

function httpDestinations(ctx: RuleContext): Array<{ field: string; host: string }> {
  const destinations: Array<{ field: string; host: string }> = [];
  for (const field of httpTargetFields(ctx)) {
    for (const host of extractNetworkTargetHosts(ctx.args[field]?.value)) {
      destinations.push({ field, host });
    }
  }
  return destinations;
}

function normalizePotentialWritePath(raw: string): string {
  let candidate = raw.trim().split("\0", 1)[0];
  if ((candidate.startsWith("\"") && candidate.endsWith("\"")) ||
      (candidate.startsWith("'") && candidate.endsWith("'"))) {
    candidate = candidate.slice(1, -1);
  }
  candidate = candidate.replace(/^(?:\$HOME|\$\{HOME\})(?=\/)/, "~");
  if (/^file:\/\//i.test(candidate)) {
    try {
      const fileUrl = new URL(candidate);
      candidate = decodeURIComponent(fileUrl.pathname);
    } catch {
      candidate = candidate.replace(/^file:\/\/(?:localhost)?/i, "");
    }
  }
  return posixPath.normalize(candidate);
}

function protectedWritePathKind(raw: string): string | null {
  const path = normalizePotentialWritePath(raw).toLowerCase();
  const home = String.raw`(?:~|/root|/home/[^/]+|/users/[^/]+)`;

  if (/^\/(?:private\/)?etc(?:\/|$)/.test(path)) return "system configuration (/etc)";
  if (new RegExp(`^(?:${home}/)?\\.ssh(?:/|$)`).test(path)) return "SSH configuration";
  if (new RegExp(`^(?:${home}/)?\\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zlogin|zshenv)$`).test(path)) {
    return "shell startup configuration";
  }
  if (/^\/(?:var\/spool\/cron|var\/cron|var\/at\/tabs|usr\/lib\/cron)(?:\/|$)/.test(path)) {
    return "scheduled-task configuration";
  }
  if (/^\/(?:usr\/lib\/systemd|lib\/systemd|run\/systemd\/system)(?:\/|$)/.test(path) ||
      new RegExp(`^(?:${home}/)?\\.config/systemd(?:/|$)`).test(path)) {
    return "systemd persistence configuration";
  }
  if (/^\/(?:system\/)?library\/(?:launchagents|launchdaemons|startupitems)(?:\/|$)/.test(path) ||
      new RegExp(`^${home}/library/(?:launchagents|launchdaemons|startupitems)(?:/|$)`).test(path)) {
    return "macOS launch persistence configuration";
  }
  if (new RegExp(`^(?:${home}/)?\\.config/autostart(?:/|$)`).test(path)) {
    return "desktop autostart configuration";
  }
  return null;
}

function shellTokenCommandName(token: string): string {
  const cleaned = token.toLowerCase().replace(/^["']|["']$/g, "").replace(/[;&|]+$/g, "");
  return cleaned.split("/").pop() ?? cleaned;
}

function protectedShellWriteTargets(command: string, nestingDepth = 0): Array<{ target: string; kind: string }> {
  const persistentCommand = [
    { re: /(?:^|[;&|]\s*)crontab\s+(?!-l(?:\s|$))\S+/i, kind: "scheduled-task configuration" },
    { re: /\bsystemctl\s+(?:enable|reenable|link|preset)\b/i, kind: "systemd persistence configuration" },
    { re: /\blaunchctl\s+(?:load|bootstrap|enable|submit)\b/i, kind: "macOS launch persistence configuration" },
  ].find(({ re }) => re.test(command));
  if (persistentCommand) return [{ target: "<persistence command>", kind: persistentCommand.kind }];

  if (nestingDepth < 4) {
    const nestedShell = command.match(/\b(?:ba|da|z)?sh\s+-c\s+(["'])([\s\S]*?)\1/i);
    if (nestedShell) return protectedShellWriteTargets(nestedShell[2], nestingDepth + 1);
  }

  const alwaysMutating = new Set(["tee", "touch", "mkdir", "rm", "chmod", "chown", "chgrp", "truncate"]);
  const destinationMutating = new Set(["cp", "mv", "install", "ln"]);
  const matches: Array<{ target: string; kind: string }> = [];
  for (const segment of command.split(/\s*(?:&&|\|\||[;|])\s*/)) {
    const tokens = segment.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
    const commandNames = tokens.map(shellTokenCommandName);
    const hasAlwaysMutatingCommand = commandNames.some((name) => alwaysMutating.has(name));
    const hasDestinationMutatingCommand = commandNames.some((name) => destinationMutating.has(name));
    const hasInPlaceEdit = commandNames.some((name) => name === "sed" || name === "perl") &&
      tokens.some((token) => /^-[a-z]*i[a-z]*$/i.test(token));

    for (let index = 0; index < tokens.length; index += 1) {
      const rawToken = tokens[index];
      const redirected = /^\d*>>?/.test(rawToken) || /^\d*>>?$/.test(tokens[index - 1] ?? "");
      const outputAssignment = /^of=/i.test(rawToken);
      const cleaned = rawToken
        .replace(/^\d*>>?/, "")
        .replace(/^of=/i, "")
        .replace(/^["']|["']$/g, "")
        .replace(/[,)]+$/g, "");
      const kind = protectedWritePathKind(cleaned);
      if (!kind) continue;

      const isLastArgument = index === tokens.length - 1;
      if (redirected || outputAssignment || hasAlwaysMutatingCommand || hasInPlaceEdit ||
          (hasDestinationMutatingCommand && isLastArgument)) {
        matches.push({ target: normalizePotentialWritePath(cleaned), kind });
      }
    }
  }
  return matches;
}

// R1: Sensitive business/personal data → external email
const ruleCustomerDataExternal: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  const destinations = externalEmailDestinations(ctx);
  if (destinations.length === 0) return null;

  const sensitiveArgs: string[] = [];
  const evidence: string[] = [];
  const recipientFields = new Set(emailRecipientFields(ctx));
  for (const [key, arg] of Object.entries(ctx.args)) {
    if (recipientFields.has(key)) continue;
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

// Cloud instance metadata and link-local services must never be reachable via
// an agent-controlled HTTP tool, even when an operator lists a broad internal
// domain or when no sensitive taint is present on the request.
const ruleCloudMetadataLinkLocalHttp: RuleFn = (ctx) => {
  if (ctx.tool !== "http_request") return null;
  const restricted = httpDestinations(ctx)
    .filter(({ host }) => isCloudMetadataOrLinkLocalHost(host));
  if (restricted.length === 0) return null;

  const targets = [...new Set(restricted.map(({ host }) => host))];
  return {
    id: "cloud_metadata_link_local_http",
    triggeredArgs: [...new Set(restricted.map(({ field }) => field))],
    evidence: [`HTTP target resolves to a cloud metadata or link-local address: ${targets.join(", ")}`],
    reason: `HTTP 目标为云元数据或链路本地地址 (${targets.join(", ")})，可能泄露实例凭据或访问宿主控制面`,
  };
};

// R3: Secret/API Key → external HTTP
const ruleSecretExternalHttp: RuleFn = (ctx) => {
  if (ctx.tool !== "http_request") return null;
  const destinations = httpDestinations(ctx)
    .filter(({ host }) => isExternalDomain(host, ctx.options.internalDomains));
  if (destinations.length === 0) return null;
  const externalHosts = [...new Set(destinations.map(({ host }) => host))];

  for (const key of Object.keys(ctx.args)) {
    const arg = ctx.args[key];
    if (hasAnyTaint(arg, ["SECRET", "API_KEY"])) {
      return {
        id: "secret_external_http",
        triggeredArgs: [...new Set([key, ...destinations.map(({ field }) => field)])],
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
  const destinations = httpDestinations(ctx)
    .filter(({ host }) => isExternalDomain(host, ctx.options.internalDomains));
  if (destinations.length === 0) return null;
  const targetFields = new Set(httpTargetFields(ctx));

  const triggeredArgs: string[] = [];
  const evidence: string[] = [];
  for (const [key, arg] of Object.entries(ctx.args)) {
    if (targetFields.has(key)) continue;
    const hits = getTaints(arg).filter((taint) => SENSITIVE_DATA_TAINTS.includes(taint));
    if (hits.length > 0) {
      triggeredArgs.push(key);
      evidence.push(`arg '${key}' has sensitive taints: ${hits.join(", ")}`);
    }
  }
  if (triggeredArgs.length === 0) return null;

  const hosts = [...new Set(destinations.map(({ host }) => host))];
  evidence.push(`external URL host(s): ${hosts.join(", ")}`);
  return {
    id: "sensitive_data_external_http",
    triggeredArgs: [...new Set([...triggeredArgs, ...destinations.map(({ field }) => field)])],
    evidence,
    reason: `敏感业务/个人数据将发送到外部 HTTP 地址 (${hosts.join(", ")})，存在数据外泄风险`,
  };
};

// R4: Untrusted source → shell command
const ruleUntrustedShell: RuleFn = (ctx) => {
  if (ctx.tool !== "shell_exec") return null;
  const triggeredArgs: string[] = [];
  const evidence: string[] = [];
  for (const field of shellCommandFields(ctx)) {
    const command = ctx.args[field];
    const untrustedTaints = getTaints(command).filter((taint) => UNTRUSTED_TAINTS.includes(taint));
    const untrustedProv = hasUntrustedProvenance(command);
    if (untrustedTaints.length === 0 && untrustedProv.length === 0) continue;
    triggeredArgs.push(field);
    if (untrustedTaints.length > 0) {
      evidence.push(`arg '${field}' has untrusted taints: ${untrustedTaints.join(", ")}`);
    }
    if (untrustedProv.length > 0) {
      evidence.push(`arg '${field}' has untrusted provenance: ${untrustedProv.join(", ")}`);
    }
  }
  if (triggeredArgs.length === 0) return null;

  return {
    id: "untrusted_influenced_shell",
    triggeredArgs,
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

// Writes to host configuration and common persistence locations are blocked
// independently of taint. This covers direct file tools and obvious shell
// write/activation forms while preserving ordinary reads such as `cat /etc/hosts`.
const ruleProtectedSystemPathWrite: RuleFn = (ctx) => {
  const triggeredArgs: string[] = [];
  const evidence: string[] = [];

  if (ctx.tool === "file_write") {
    for (const field of matchingArgumentFields(ctx.args, FILE_WRITE_PATH_FIELD_ALIASES)) {
      const value = ctx.args[field]?.value;
      const paths = typeof value === "string"
        ? [value]
        : Array.isArray(value)
          ? value.filter((item): item is string => typeof item === "string")
          : [];
      for (const path of paths) {
        const kind = protectedWritePathKind(path);
        if (!kind) continue;
        triggeredArgs.push(field);
        evidence.push(`arg '${field}' writes protected ${kind}: ${normalizePotentialWritePath(path)}`);
      }
    }
  }

  if (ctx.tool === "shell_exec") {
    for (const field of shellCommandFields(ctx)) {
      const command = ctx.args[field]?.value;
      if (typeof command !== "string") continue;
      for (const { target, kind } of protectedShellWriteTargets(command)) {
        triggeredArgs.push(field);
        evidence.push(`arg '${field}' writes or activates protected ${kind}: ${target}`);
      }
    }
  }

  if (triggeredArgs.length === 0) return null;
  return {
    id: "protected_system_path_write",
    triggeredArgs: [...new Set(triggeredArgs)],
    evidence: [...new Set(evidence)],
    reason: "调用尝试写入系统配置、凭据或启动持久化位置，默认禁止以防止宿主篡改与持久化",
  };
};

// R6: Untrusted provenance → email recipient
const ruleUntrustedEmailTo: RuleFn = (ctx) => {
  if (ctx.tool !== "send_email") return null;
  const triggeredArgs: string[] = [];
  const untrustedSources = new Set<string>();
  const externalDomains = new Set<string>();
  for (const field of emailRecipientFields(ctx)) {
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
  const triggeredArgs: string[] = [];
  const evidence: string[] = [];
  const untrustedSources = new Set<string>();
  for (const field of shellCommandFields(ctx)) {
    const untrusted = hasUntrustedProvenance(ctx.args[field]);
    if (untrusted.length === 0) continue;
    triggeredArgs.push(field);
    untrusted.forEach((source) => untrustedSources.add(source));
    evidence.push(`arg '${field}' has untrusted provenance: ${untrusted.join(", ")}`);
  }
  if (triggeredArgs.length === 0) return null;
  return {
    id: "untrusted_provenance_shell",
    triggeredArgs,
    evidence,
    reason: `Shell 命令参数来源于不可信来源 (${[...untrustedSources].join(", ")})，存在代码执行风险`,
  };
};

// Destructive or mutating database statements require a dedicated capability
// model; until then they are denied instead of being treated as generic shell.
const ruleDangerousDatabase: RuleFn = (ctx) => {
  if (ctx.tool !== "database_query") return null;
  const query = ctx.args.query ?? ctx.args.sql ?? ctx.args.statement;
  const text = valueToSearchText(query?.value);
  const matches = DANGEROUS_DATABASE_PATTERNS.filter(({ re }) => re.test(text)).map(({ label }) => label);
  if (matches.length === 0) return null;
  return {
    id: "dangerous_database_query",
    triggeredArgs: [ctx.args.query ? "query" : ctx.args.sql ? "sql" : "statement"],
    evidence: [`database statement matches dangerous pattern(s): ${matches.join(", ")}`],
    reason: `数据库语句包含破坏性或变更操作 (${matches.join(", ")})，默认禁止执行`,
  };
};

const ruleUntrustedMutativeTool: RuleFn = (ctx) => {
  if (!["file_write", "database_query", "browser_action"].includes(ctx.tool)) return null;
  const triggeredArgs = Object.entries(ctx.args)
    .filter(([, argument]) =>
      hasAnyTaint(argument, UNTRUSTED_TAINTS) || hasUntrustedProvenance(argument).length > 0)
    .map(([name]) => name);
  if (triggeredArgs.length === 0) return null;
  return {
    id: "untrusted_mutative_tool",
    triggeredArgs,
    evidence: triggeredArgs.map((name) => `arg '${name}' is influenced by untrusted content`),
    reason: `可变更系统状态的工具 ${ctx.tool} 受到不可信内容影响，可能是间接 prompt injection`,
  };
};

// R8: High-risk tool without capability
const HIGH_RISK_TOOLS: Set<string> = new Set([
  "send_email", "http_request", "shell_exec", "file_read", "file_write", "database_query",
  "browser_action",
]);

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
  const recipientFields = emailRecipientFields(ctx);
  const domainsByField = recipientFields.flatMap((field) =>
    extractEmailDomains(ctx.args[field]?.value).map((domain) => ({ field, domain })),
  );
  if (domainsByField.length === 0) {
    return {
      id: "capability_recipient_domain_not_allowed",
      triggeredArgs: recipientFields.length > 0 ? recipientFields : ["to"],
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
const MUTATIVE_SINKS = new Set([
  "file_write", "http_request", "send_email", "shell_exec", "database_query", "browser_action",
]);

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
  ruleCloudMetadataLinkLocalHttp,
  ruleSecretExternalEmail,
  ruleSecretExternalHttp,
  ruleDangerousShell,
  ruleProtectedSystemPathWrite,
  ruleDangerousDatabase,
  // Require-approval rules
  ruleNoCapability,
  ruleProvenanceNotAllowed,
  ruleCustomerDataExternal,
  ruleSensitiveExternalHttp,
  ruleUntrustedShell,
  ruleUntrustedEmailTo,
  ruleUntrustedProvShell,
  ruleUntrustedMutativeTool,
];

// ── Decision/Risk Mapping per Rule ──────────────────────────────────────────────

function ruleDecision(id: string, customRules?: CustomRule[]): Decision {
  const denyRules = [
    "invariant_forbidden_tool", "invariant_protected_taint_modified",
    "invariant_numeric_range_violation", "capability_tool_mismatch",
    "capability_expired", "capability_forbidden_taint",
    "capability_recipient_domain_not_allowed",
    "cloud_metadata_link_local_http", "protected_system_path_write",
    "secret_external_send", "secret_external_http", "dangerous_shell_pattern",
    "dangerous_database_query",
  ];
  const reviewRules = [
    "high_risk_tool_requires_capability", "capability_provenance_not_allowed",
    "customer_data_external_send", "sensitive_data_external_http", "untrusted_influenced_shell",
    "untrusted_provenance_email_to", "untrusted_provenance_shell", "untrusted_mutative_tool",
  ];
  if (denyRules.includes(id)) return "deny";
  if (reviewRules.includes(id)) return "require_approval";
  const customRule = customRules?.find((r) => r.enabled !== false && r.id === id);
  if (customRule) return customRule.decision;
  return "allow";
}

function ruleRisk(id: string, customRules?: CustomRule[]): RiskLevel {
  const critical = ["invariant_protected_taint_modified", "capability_tool_mismatch",
    "capability_forbidden_taint", "secret_external_send", "secret_external_http",
    "dangerous_shell_pattern", "dangerous_database_query",
    "cloud_metadata_link_local_http", "protected_system_path_write"];
  if (critical.includes(id)) return "critical";
  const builtInHigh = [
    "invariant_forbidden_tool", "invariant_numeric_range_violation", "capability_expired",
    "capability_recipient_domain_not_allowed", "high_risk_tool_requires_capability",
    "capability_provenance_not_allowed", "customer_data_external_send",
    "sensitive_data_external_http", "untrusted_influenced_shell",
    "untrusted_provenance_email_to", "untrusted_provenance_shell", "untrusted_mutative_tool",
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

export interface AdditionalPolicyDecision {
  policy: MatchedPolicy;
  decision: Decision;
  riskLevel: RiskLevel;
}

/**
 * Monotonically merges policy-as-code results with the deterministic built-in
 * evaluation. Additional policy modules can make a result stricter, never less
 * strict, and a new internally consistent proof is generated for the aggregate.
 */
export function mergePolicyDecisions(
  output: EngineOutput,
  additional: readonly AdditionalPolicyDecision[],
): EngineOutput {
  if (additional.length === 0) return output;
  let decision = output.decision;
  let riskLevel = output.riskLevel;
  for (const match of additional) {
    if (DECISION_ORDER[match.decision] > DECISION_ORDER[decision]) decision = match.decision;
    if (RISK_ORDER[match.riskLevel] > RISK_ORDER[riskLevel]) riskLevel = match.riskLevel;
  }
  const matchedPolicies = [
    ...output.matchedPolicies,
    ...additional.map(({ policy }) => policy),
  ];
  const proof = generateProof(
    output.proof.tool,
    decision,
    riskLevel,
    matchedPolicies,
    output.proof.timestamp,
    { traceId: output.proof.traceId, stepId: output.proof.stepId },
  );
  return {
    ...output,
    action: DECISION_TO_ACTION[decision],
    decision,
    riskLevel,
    matchedPolicies,
    proof,
  };
}

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
  const enrichedArgs = propagateFlows(enrichTaints(args, input.taints), input.flows);

  // Step 3: Mark sink arguments
  for (const argName of matchingArgumentFields(enrichedArgs, SINK_FIELD_ALIASES[input.tool])) {
    enrichedArgs[argName] = { ...enrichedArgs[argName], isSink: true };
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
